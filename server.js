const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const session = require('express-session');
const { MongoClient, ObjectId } = require('mongodb');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;

// Cargar variables de entorno
dotenv.config();

// Inicializar aplicación express
const app = express();
const PORT = process.env.PORT || 3001;

// Crear directorio de logs si no existe
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Flujo de escritura para logs
const accessLogStream = fs.createWriteStream(
  path.join(logsDir, 'access.log'),
  { flags: 'a' }
);

// Conexión a MongoDB
const mongoUri = `mongodb://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_HOST}:27017/dataBaseSegDev?authSource=admin`;
let db;
const client = new MongoClient(mongoUri);

// Middleware de registro personalizado
const customLogger = (req, res, next) => {
  const startTime = Date.now();
  const originalEnd = res.end;

  res.end = function (chunk, encoding) {
    originalEnd.call(this, chunk, encoding);
    const responseTime = Date.now() - startTime;
    const now = new Date();
    const days = ['Dom', 'Lun', 'Mar', 'Mie', 'Jue', 'Vie', 'Sab'];
    const day = days[now.getDay()];
    const date = `${now.getDate()}/${(now.getMonth() + 1).toString().padStart(2, '0')}/${now.getFullYear()}`;
    const method = req.method;
    const url = req.originalUrl || req.url;
    const status = res.statusCode;
    const username = req.session?.username || req.body?.username || 'anónimo';
    let hashedPassword = req.session?.passwordHash || 'contraseña-no-proporcionada';

    if (!req.session?.passwordHash && req.body?.password) {
      hashedPassword = crypto
        .createHash('sha256')
        .update(req.body.password)
        .digest('hex');
    }

    const logEntry = `${day} ${date} ${method} ${status} ${responseTime}ms ${username} ${hashedPassword} ${url}`;
    accessLogStream.write(logEntry + '\n');
    console.log(logEntry);
  };

  next();
};

// Configuración de middleware básico
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Configuración del middleware de sesión (IMPORTANTE: antes de passport)
app.use(session({
  secret: process.env.NODE_SECRET || 'secret-key-dev',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

// Configuración de Passport (DESPUÉS de express-session)
app.use(passport.initialize());
app.use(passport.session());

// Registrar el middleware de logging personalizado
app.use(customLogger);

// Configuración de Passport para serialización/deserialización
passport.serializeUser((user, done) => {
  done(null, user._id.toString());
});

passport.deserializeUser(async (id, done) => {
  try {
    let objectId;
    try {
      objectId = new ObjectId(id);
    } catch (err) {
      objectId = id;
    }

    const user = await db.collection('users').findOne({ _id: objectId });
    done(null, user);
  } catch (err) {
    console.error("Error deserializando usuario:", err);
    done(err, null);
  }
});

// Función para procesar el resultado de autenticación OAuth
async function handleOAuthLogin(profile, provider, done) {
  try {
    console.log(`Procesando login de ${provider} para perfil:`, JSON.stringify(profile, null, 2));

    // Extraer email del perfil
    const email = profile.emails && profile.emails.length > 0
      ? profile.emails[0].value
      : null;

    // Construir consulta para buscar usuario existente
    const query = { $or: [{ [`${provider}Id`]: profile.id }] };
    if (email) {
      query.$or.push({ email });
    }

    console.log("Buscando usuario con query:", JSON.stringify(query));

    // Buscar si el usuario ya existe
    let user = await db.collection('users').findOne(query);

    if (user) {
      console.log(`Usuario encontrado:`, user);
      // Si el usuario existe pero no tiene ID del proveedor, actualizar
      if (!user[`${provider}Id`]) {
        await db.collection('users').updateOne(
          { _id: user._id },
          { $set: { [`${provider}Id`]: profile.id } }
        );
      }
      return done(null, user);
    }

    // Si el usuario no existe, crearlo
    console.log(`Creando nuevo usuario con ${provider}`);
    const newUser = {
      username: profile.displayName || profile.username || `${provider}-user-${profile.id}`,
      email: email,
      [`${provider}Id`]: profile.id,
      role: 'operador', // Rol por defecto para usuarios OAuth
      createdAt: new Date(),
      failedAttempts: 0,
      lastFailedAttempt: null
    };

    const result = await db.collection('users').insertOne(newUser);
    newUser._id = result.insertedId;
    console.log(`Usuario creado con ID: ${newUser._id}`);

    return done(null, newUser);
  } catch (err) {
    console.error(`Error en autenticación ${provider}:`, err);
    return done(err, null);
  }
}

// Middleware para verificar si el usuario puede intentar iniciar sesión
const checkLoginAttempts = async (username) => {
  const user = await db.collection('users').findOne({ username });
  if (!user) return true; // Si el usuario no existe, permitir el intento

  if (user.failedAttempts >= 3) {
    // Si han pasado menos de 5 minutos desde el último intento fallido, bloquear
    if (user.lastFailedAttempt && (Date.now() - user.lastFailedAttempt) < 5 * 60 * 1000) {
      return false;
    } else {
      // Si han pasado más de 5 minutos, resetear los intentos fallidos
      await db.collection('users').updateOne(
        { username },
        { $set: { failedAttempts: 0, lastFailedAttempt: null } }
      );
      return true;
    }
  }

  return true;
};

// Conexión a MongoDB e inicialización del servidor
async function startServer() {
  try {
    await client.connect();
    db = client.db('dataBaseSegDev');
    console.log('Conectado a MongoDB');

    // Verificar si existe el usuario admin, si no, crearlo
    const adminExists = await db.collection('users').findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
      await db.collection('users').insertOne({
        username: 'admin',
        email: 'admin@example.com',
        password: hashedPassword,
        role: 'admin',
        failedAttempts: 0,
        lastFailedAttempt: null
      });
      console.log('Usuario admin creado');
    }

    // Configurar estrategias OAuth solo si las variables de entorno están definidas
    configureOAuthStrategies();

    // Iniciar el servidor HTTP
    const server = http.createServer(app);
    server.listen(PORT, () => {
      console.log(`Servidor ejecutándose en el puerto ${PORT}`);
    });

  } catch (err) {
    console.error('Error al iniciar el servidor:', err);
    process.exit(1);
  }
}

// Configuración de estrategias OAuth
function configureOAuthStrategies() {
  // Google OAuth (solo si están definidas las credenciales)
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.NGROK_URL || `http://localhost:${PORT}`}/auth/google/callback`,
      scope: ['profile', 'email']
    }, (accessToken, refreshToken, profile, done) => {
      handleOAuthLogin(profile, 'google', done);
    }));

    console.log("Estrategia de Google OAuth configurada");
  } else {
    console.log("Estrategia de Google OAuth no configurada: faltan credenciales");
  }

  // GitHub OAuth (solo si están definidas las credenciales)
  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    passport.use(new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.NGROK_URL || `http://localhost:${PORT}`}/auth/github/callback`,
      scope: ['user:email']
    }, (accessToken, refreshToken, profile, done) => {
      handleOAuthLogin(profile, 'github', done);
    }));

    console.log("Estrategia de GitHub OAuth configurada");
  } else {
    console.log("Estrategia de GitHub OAuth no configurada: faltan credenciales");
  }

  // Microsoft OAuth (solo si están definidas las credenciales)
  if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
    passport.use(new MicrosoftStrategy({
      clientID: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL: `${process.env.NGROK_URL || `http://localhost:${PORT}`}/auth/microsoft/callback`,
      scope: ['user.read']
    }, (accessToken, refreshToken, profile, done) => {
      handleOAuthLogin(profile, 'microsoft', done);
    }));

    console.log("Estrategia de Microsoft OAuth configurada");
  } else {
    console.log("Estrategia de Microsoft OAuth no configurada: faltan credenciales");
  }
}

//=========================================================
// RUTAS DE LA APLICACIÓN
//=========================================================

// Ruta raíz - sirve la página de inicio de sesión
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Ruta para obtener la página del panel de administración
app.get('/admin', (req, res) => {
  if (!req.session.authenticated || req.session.role !== 'admin') {
    return res.redirect('/?error=Acceso no autorizado');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Ruta para obtener la página del usuario
app.get('/user', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/?error=Acceso no autorizado');
  }
  res.sendFile(path.join(__dirname, 'public', 'users.html'));
});

// Endpoint de inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Usuario y contraseña son requeridos');
  }

  try {
    const user = await db.collection('users').findOne({ username });

    if (!user) {
      return res.status(401).send('Usuario no encontrado');
    }

    // Verificar si el usuario puede intentar iniciar sesión
    const canAttempt = await checkLoginAttempts(username);
    if (!canAttempt) {
      const logEntry = `Intento fallido: ${username} ha excedido el límite de intentos. Favor de reiniciar contraseña o espere 5 minutos.`;
      accessLogStream.write(logEntry + '\n');
      console.log(logEntry);
      return res.status(403).send('Demasiados intentos fallidos. Espere 5 minutos o reinicie su contraseña.');
    }

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    if (hashedPassword === user.password) {
      // Restablecer intentos fallidos
      await db.collection('users').updateOne(
        { username },
        { $set: { failedAttempts: 0, lastFailedAttempt: null } }
      );

      req.session.username = username;
      req.session.role = user.role;
      req.session.authenticated = true;

      // Redirigir según el rol
      if (user.role === 'admin') {
        return res.send({ success: true, message: `Bienvenido, ${username} (${user.role})`, redirectTo: '/admin' });
      } else {
        return res.send({ success: true, message: `Bienvenido, ${username} (${user.role})`, redirectTo: '/user' });
      }
    } else {
      // Incrementar intentos fallidos y registrar el tiempo
      await db.collection('users').updateOne(
        { username },
        {
          $inc: { failedAttempts: 1 },
          $set: { lastFailedAttempt: Date.now() }
        }
      );

      // Obtener el número actualizado de intentos fallidos
      const updatedUser = await db.collection('users').findOne({ username });

      if (updatedUser.failedAttempts >= 3) {
        const logEntry = `Intento fallido: ${username} ha excedido el límite de intentos. Favor de reiniciar contraseña o espere 5 minutos.`;
        accessLogStream.write(logEntry + '\n');
        console.log(logEntry);
        return res.status(403).send('Demasiados intentos fallidos. Espere 5 minutos o reinicie su contraseña.');
      }

      return res.status(401).send('Credenciales incorrectas');
    }
  } catch (err) {
    console.error('Error en el inicio de sesión:', err);
    res.status(500).send('Error en el servidor');
  }
});

// Ruta de cierre de sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Ruta para la página de restablecimiento de contraseña
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// Ruta para manejar el código de verificación en la URL
app.get('/reset-password/:verificationCode', async (req, res) => {
  const { verificationCode } = req.params;

  // Validar que el código tenga el formato correcto
  if (!verificationCode || verificationCode.length < 6) {
    return res.redirect('/reset-password?error=Código+de+verificación+inválido');
  }

  try {
    // Verificar si el código existe en la base de datos
    const user = await db.collection('users').findOne({
      passwordResetCode: verificationCode,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.redirect('/reset-password?error=Código+de+verificación+inválido+o+expirado');
    }

    // Redirigir a la página de restablecimiento con el código y correo pre-llenados
    res.redirect(`/reset-password?code=${verificationCode}&email=${encodeURIComponent(user.email)}`);
  } catch (error) {
    console.error("Error al verificar código:", error);
    res.redirect('/reset-password?error=Error+al+procesar+la+solicitud');
  }
});

// Ruta de solicitud de restablecimiento de contraseña
app.post('/request-password-reset', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Correo electrónico es requerido' });
  }

  try {
    // Verificar si el usuario existe
    const user = await db.collection('users').findOne({ email });

    if (!user) {
      // Por seguridad, no informar si el correo existe o no
      return res.status(200).json({
        message: "Si el correo existe en nuestra base de datos, recibirás un mensaje con instrucciones."
      });
    }

    // Generar código de verificación (6 caracteres alfanuméricos)
    const verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    const tokenLink = `${req.protocol}://${req.get('host')}/reset-password/${verificationCode}`;

    // Almacenar el código de verificación en la base de datos con una marca de tiempo
    await db.collection('users').updateOne(
      { email },
      {
        $set: {
          passwordResetCode: verificationCode,
          passwordResetExpires: Date.now() + 3 * 60 * 1000 // 3 minutos de validez
        }
      }
    );

    // Configuración del transporte de correo
    const transporter = nodemailer.createTransport({
      host: "smtp.titan.email",
      port: 465,
      secure: true,
      auth: {
        user: process.env.NODE_EMAIL,
        pass: process.env.NODE_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false
      },
    });

    // Correo simplificado con el código principal
    const mailOptions = {
      from: `"Sistema de Usuarios" <${process.env.NODE_EMAIL}>`,
      to: email,
      subject: "Código de Verificación para Restablecer Contraseña",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color: #f9f9f9;">
          <div style="text-align: center; padding: 10px; background-color: #3498db; color: white; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">Código de Verificación</h2>
          </div>
          <div style="padding: 20px; background-color: white; border-radius: 0 0 8px 8px;">
            <p style="font-size: 16px; color: #555; text-align: center; margin: 20px 0;">
              Tu código para restablecer contraseña es:
            </p>
            <div style="margin: 25px auto; text-align: center; background: #f0f8ff; padding: 15px; border-radius: 8px; border: 2px dashed #3498db; max-width: 300px;">
              <div style="font-size: 30px; font-weight: bold; letter-spacing: 5px; color: #3498db;">${verificationCode}</div>
            </div>
            <p style="color: #e74c3c; font-size: 15px; text-align: center;">
              Este código expira en <strong>3 minutos</strong>
            </p>
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #777; text-align: center;">
              Ingresa este código en la página de restablecimiento de contraseña.
            </div>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);

    // En desarrollo, devolver el código para fines de prueba
    const devResponse = process.env.NODE_ENV === 'development'
      ? { verificationCode }
      : {};

    res.status(200).json({
      message: "Se ha enviado un código de verificación a tu correo electrónico.",
      ...devResponse
    });
  } catch (error) {
    console.error("Error en la solicitud de restablecimiento de contraseña:", error);
    res.status(500).json({ message: "Error al procesar la solicitud. Por favor intenta más tarde." });
  }
});

// Ruta para verificar el código antes de restablecer la contraseña
app.post('/check-verification-code', async (req, res) => {
  const { email, verificationCode } = req.body;

  if (!email || !verificationCode) {
    return res.status(400).send('Correo electrónico y código de verificación son requeridos');
  }

  try {
    // Buscar el usuario y verificar el código
    const user = await db.collection('users').findOne({
      email,
      passwordResetCode: verificationCode,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).send('Código de verificación inválido o expirado');
    }

    // Si el código es válido, enviar respuesta exitosa
    res.status(200).send('Código verificado correctamente');
  } catch (error) {
    console.error("Error al verificar código:", error);
    res.status(500).send("Error al verificar el código. Por favor intenta más tarde.");
  }
});

// Ruta para verificar el código y restablecer la contraseña
app.post('/verify-reset-password', async (req, res) => {
  const { email, verificationCode, newPassword } = req.body;

  if (!email || !verificationCode || !newPassword) {
    return res.status(400).send('Todos los campos son requeridos');
  }

  try {
    // Buscar el usuario y verificar el código
    const user = await db.collection('users').findOne({
      email,
      passwordResetCode: verificationCode,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).send('Código de verificación inválido o expirado');
    }

    // Hash de la nueva contraseña
    const hashedPassword = crypto.createHash('sha256').update(newPassword).digest('hex');

    // Actualizar contraseña y limpiar campos de restablecimiento
    await db.collection('users').updateOne(
      { email },
      {
        $set: {
          password: hashedPassword,
          failedAttempts: 0,
          lastFailedAttempt: null
        },
        $unset: {
          passwordResetCode: "",
          passwordResetExpires: ""
        }
      }
    );

    // Registrar la acción en los logs
    const logEntry = `${new Date().toISOString()} - Contraseña restablecida para el usuario con correo: ${email}`;
    accessLogStream.write(logEntry + '\n');
    console.log(logEntry);

    res.status(200).send('Contraseña restablecida exitosamente');
  } catch (error) {
    console.error("Error al restablecer contraseña:", error);
    res.status(500).send("Error al restablecer la contraseña. Por favor intenta más tarde.");
  }
});

// Ruta para registrar usuarios (solo para administradores)
app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  if (!req.session || !req.session.authenticated || req.session.role !== 'admin') {
    return res.status(403).send('Solo el administrador puede registrar usuarios');
  }

  if (!username || !email || !password || !role) {
    return res.status(400).send('Todos los campos son requeridos');
  }

  // Verificar que el rol sea válido
  const validRoles = ['admin', 'supervisor', 'operador'];
  if (!validRoles.includes(role)) {
    return res.status(400).send('Rol no válido');
  }

  try {
    // Verificar si el usuario o email ya existe
    const existingUser = await db.collection('users').findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(400).send('El nombre de usuario o correo ya está en uso');
    }

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    await db.collection('users').insertOne({
      username,
      email,
      password: hashedPassword,
      role,
      failedAttempts: 0,
      lastFailedAttempt: null,
      createdAt: new Date()
    });

    res.send('Usuario registrado exitosamente');
  } catch (err) {
    console.error('Error al registrar usuario:', err);
    res.status(500).send('Error en el servidor');
  }
});

// Ruta para obtener información del usuario actual
app.get('/api/user-info', async (req, res) => {
  if (!req.session || !req.session.authenticated) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  try {
    // Buscar el usuario en la base de datos usando el nombre de usuario almacenado en la sesión
    const username = req.session.username;
    const user = await db.collection('users').findOne(
      { username },
      { projection: { password: 0 } } // Excluir la contraseña de la respuesta
    );

    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Devolver la información del usuario
    res.json({
      username: user.username,
      email: user.email || 'correo no disponible',
      role: user.role
    });
  } catch (err) {
    console.error('Error al obtener información del usuario:', err);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Ruta para obtener todos los usuarios (solo para administradores)
app.get('/users', async (req, res) => {
  if (!req.session || !req.session.authenticated || req.session.role !== 'admin') {
    return res.status(403).send('Solo el administrador puede ver la lista de usuarios');
  }

  try {
    // Obtener todos los usuarios excluyendo solo el campo password
    const users = await db.collection('users').find({}, {
      projection: {
        password: 0 // Solo excluimos la contraseña
      }
    }).toArray();

    // Asegurarse de que todos los usuarios tengan valores por defecto para los campos que podrían ser null
    const processedUsers = users.map(user => ({
      ...user,
      failedAttempts: user.failedAttempts || 0,
      email: user.email || 'No disponible'
    }));

    res.json(processedUsers);
  } catch (err) {
    console.error('Error al obtener usuarios:', err);
    res.status(500).send('Error en el servidor');
  }
});

//=========================================================
// RUTAS DE AUTENTICACIÓN OAUTH
//=========================================================

// Ruta para mostrar estado de autenticación (útil para depuración)
app.get('/auth/status', (req, res) => {
  res.json({
    isAuthenticated: req.isAuthenticated(),
    user: req.user ? {
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    } : null,
    session: {
      authenticated: req.session?.authenticated,
      username: req.session?.username,
      role: req.session?.role
    }
  });
});

// Rutas para autenticación de Google (solo si está configurada)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  app.get('/auth/google/callback',
    passport.authenticate('google', {
      failureRedirect: '/?oauth_error=Google+authentication+failed',
      failureMessage: true
    }),
    (req, res) => {
      // Establecer los valores de la sesión
      req.session.username = req.user.username;
      req.session.role = req.user.role;
      req.session.authenticated = true;

      // Redirigir según el rol del usuario
      if (req.user.role === 'admin') {
        res.redirect('/admin');
      } else {
        res.redirect('/user');
      }
    }
  );
}

// Rutas para autenticación de GitHub (solo si está configurada)
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
  app.get('/auth/github/callback',
    passport.authenticate('github', {
      failureRedirect: '/?oauth_error=GitHub+authentication+failed',
      failureMessage: true
    }),
    (req, res) => {
      // Establecer los valores de la sesión
      req.session.username = req.user.username;
      req.session.role = req.user.role;
      req.session.authenticated = true;

      // Redirigir según el rol del usuario
      if (req.user.role === 'admin') {
        res.redirect('/admin');
      } else {
        res.redirect('/user');
      }
    }
  );
}

// Rutas para autenticación de Microsoft (solo si está configurada)
if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
  app.get('/auth/microsoft', passport.authenticate('microsoft', { scope: ['user.read'] }));
  app.get('/auth/microsoft/callback',
    passport.authenticate('microsoft', {
      failureRedirect: '/?oauth_error=Microsoft+authentication+failed',
      failureMessage: true
    }),
    (req, res) => {
      // Establecer los valores de la sesión
      req.session.username = req.user.username;
      req.session.role = req.user.role;
      req.session.authenticated = true;

      // Redirigir según el rol del usuario
      if (req.user.role === 'admin') {
        res.redirect('/admin');
      } else {
        res.redirect('/user');
      }
    }
  );
}

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('¡Algo salió mal!');
});

// Iniciar el servidor
startServer();
