const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const winston = require('winston');
const compress = require('compression');

// Cargar variables de entorno
dotenv.config();

// Configuración de logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Inicializar aplicación express
const app = express();

// Configuración de seguridad
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Limitar solicitudes para prevenir ataques de fuerza bruta
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Límite de 100 solicitudes por IP
  message: 'Demasiadas solicitudes, por favor intente más tarde'
});
app.use(limiter);

// Middleware de compresión
app.use(compress());

// Conexión a MongoDB
const mongoUri = `mongodb://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_HOST}:27017/dataBaseSegDev?authSource=admin`;
const client = new MongoClient(mongoUri, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
});

let db;

// Función para generar token seguro
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Función de hash de contraseña
function hashPassword(password) {
  return crypto
    .createHash('sha256')
    .update(password)
    .digest('hex');
}

// Configuración de transporte de correo
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware de sesión
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'fallback_secret_key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoUri,
    collectionName: 'sessions'
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 horas
    sameSite: 'strict'
  }
});

app.use(sessionMiddleware);

// Configuración de middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (path.extname(filePath) === '.html') {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// Función de autenticación centralizada
async function authenticateUser(username, password) {
  const user = await db.collection('users').findOne({ username });
  
  if (!user) return null;
  
  const hashedPassword = hashPassword(password);
  
  if (hashedPassword !== user.password) {
    // Incrementar intentos fallidos
    await db.collection('users').updateOne(
      { username },
      { 
        $inc: { failedAttempts: 1 },
        $set: { lastFailedAttempt: new Date() }
      }
    );
    return null;
  }

  // Restablecer intentos fallidos
  await db.collection('users').updateOne(
    { username },
    { 
      $set: { 
        failedAttempts: 0, 
        lastFailedAttempt: null 
      }
    }
  );

  return user;
}

// Middleware de autorización
function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.status(401).json({ message: 'No autorizado' });
}

function isAdmin(req, res, next) {
  if (req.session.authenticated && req.session.role === 'admin') {
    return next();
  }
  res.status(403).json({ message: 'Acceso denegado' });
}

// Rutas principales
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Ruta de inicio de sesión
app.post('/login', [
  body('username').trim().notEmpty().withMessage('Usuario requerido'),
  body('password').notEmpty().withMessage('Contraseña requerida')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    const user = await authenticateUser(username, password);

    if (!user) {
      logger.warn(`Intento de inicio de sesión fallido: ${username}`);
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    req.session.authenticated = true;
    req.session.username = user.username;
    req.session.role = user.role;

    logger.info(`Inicio de sesión exitoso: ${username}`);
    res.json({ 
      message: `Bienvenido, ${username}`, 
      role: user.role 
    });

  } catch (error) {
    logger.error('Error en inicio de sesión', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Ruta de cierre de sesión
app.post('/logout', isAuthenticated, (req, res) => {
  logger.info(`Cierre de sesión: ${req.session.username}`);
  req.session.destroy((err) => {
    if (err) {
      logger.error('Error al cerrar sesión', err);
      return res.status(500).json({ message: 'Error al cerrar sesión' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Sesión cerrada exitosamente' });
  });
});

// Ruta de solicitud de restablecimiento de contraseña
app.post('/request-password-reset', [
  body('email').isEmail().withMessage('Correo electrónico inválido')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;

  try {
    const user = await db.collection('users').findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const resetToken = generateSecureToken();
    const resetTokenExpiration = Date.now() + 15 * 60 * 1000; // 15 minutos

    await db.collection('users').updateOne(
      { email },
      { 
        $set: { 
          resetToken, 
          resetTokenExpiration 
        } 
      }
    );

    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    await transporter.sendMail({
      from: '"Sistema de Usuarios" <noreply@example.com>',
      to: email,
      subject: 'Restablecimiento de Contraseña',
      html: `
        <h2>Solicitud de Restablecimiento de Contraseña</h2>
        <p>Haga clic en el siguiente enlace para restablecer su contraseña:</p>
        <a href="${resetLink}">Restablecer Contraseña</a>
        <p>Este enlace caducará en 15 minutos.</p>
      `
    });

    logger.info(`Solicitud de restablecimiento de contraseña para ${email}`);
    res.status(200).json({ message: 'Correo de restablecimiento enviado' });

  } catch (error) {
    logger.error('Error en solicitud de restablecimiento', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Ruta de restablecimiento de contraseña
app.post('/reset-password', [
  body('token').notEmpty().withMessage('Token es requerido'),
  body('newPassword')
    .isLength({ min: 8 }).withMessage('Contraseña debe tener al menos 8 caracteres')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
    .withMessage('Contraseña debe contener mayúsculas, minúsculas, números y caracteres especiales')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { token, newPassword } = req.body;

  try {
    const user = await db.collection('users').findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Token inválido o expirado' });
    }

    const hashedPassword = hashPassword(newPassword);

    await db.collection('users').updateOne(
      { _id: user._id },
      { 
        $set: { password: hashedPassword },
        $unset: { 
          resetToken: '', 
          resetTokenExpiration: '' 
        }
      }
    );

    logger.info(`Contraseña restablecida para usuario: ${user.email}`);
    res.status(200).json({ message: 'Contraseña restablecida exitosamente' });

  } catch (error) {
    logger.error('Error en restablecimiento de contraseña', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Rutas de administración
app.post('/register', isAuthenticated, isAdmin, [
  body('username').trim().notEmpty().withMessage('Usuario requerido'),
  body('password').notEmpty().withMessage('Contraseña requerida'),
  body('role').isIn(['admin', 'supervisor', 'operador']).withMessage('Rol inválido')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, role } = req.body;

  try {
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Usuario ya existe' });
    }

    const hashedPassword = hashPassword(password);

    await db.collection('users').insertOne({
      username,
      password: hashedPassword,
      role,
      failedAttempts: 0,
      lastFailedAttempt: null
    });

    logger.info(`Usuario registrado: ${username}`);
    res.status(201).json({ message: 'Usuario registrado exitosamente' });

  } catch (error) {
    logger.error('Error en registro de usuario', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Ruta de manejo de errores global
app.use((err, req, res, next) => {
  logger.error('Error no manejado', err);
  res.status(500).json({ 
    message: 'Error interno del servidor',
    error: process.env.NODE_ENV === 'production' ? {} : err.message
  });
});

// Conexión a la base de datos y arranque del servidor
async function startServer() {
  try {
    await client.connect();
    db = client.db('dataBaseSegDev');
    logger.info('Conectado a MongoDB');

    // Verificar y crear usuario admin por defecto
    const adminExists = await db.collection('users').findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = hashPassword('admin123');
      await db.collection('users').insertOne({
        username: 'admin',
        password: hashedPassword,
        role: 'admin',
        email: 'admin@example.com',
        failedAttempts: 0,
        lastFailedAttempt: null
      });
      logger.info('Usuario admin creado');
    }

    const PORT = process.env.PORT || 3001;
    
    // En producción, usar HTTPS
    if (process.env.NODE_ENV === 'production') {
      const httpsOptions = {
        key: fs.readFileSync('path/to/private.key'),
        cert: fs.readFileSync('path/to/certificate.crt')
      };
      https.createServer(httpsOptions, app).listen(PORT, () => {
        logger.info(`Servidor HTTPS corriendo en puerto ${PORT}`);
      });
    } else {
      app.listen(PORT, () => {
        logger.info(`Servidor corriendo en puerto ${PORT}`);
      });
    }

  } catch (error) {
    logger.error('Error al iniciar el servidor', error);
    process.exit(1);
  }
}

startServer();

// Manejo de cierre del proceso
process.on('SIGINT', async () => {
  try {
    await client.close();
    logger.info('Conexión a MongoDB cerrada');
    process.exit(0);
  } catch (error) {
    logger.error('Error al cerrar la conexión a MongoDB', error);
    process.exit(1);
  }
});
