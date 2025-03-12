const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const session = require('express-session');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');

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
const client = new MongoClient(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });

let db;
client.connect()
  .then(async () => {
    db = client.db('dataBaseSegDev');
    console.log('Conectado a MongoDB');
    
    // Verificar si existe el usuario admin, si no, crearlo
    const adminExists = await db.collection('users').findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
      await db.collection('users').insertOne({
        username: 'admin',
        password: hashedPassword,
        role: 'admin',
        failedAttempts: 0,
        lastFailedAttempt: null
      });
      console.log('Usuario admin creado');
    }
  })
  .catch(err => {
    console.error('Error al conectar a MongoDB:', err);
  });

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

// Configuración de middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Configuración del middleware de sesión
app.use(session({
  secret: 'clave_secreta_para_firmar_cookies',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

app.use(customLogger);

// Middleware para verificar si el usuario puede intentar iniciar sesión después de 3 intentos fallidos
const checkLoginAttempts = async (username) => {
  const user = await db.collection('users').findOne({ username });
  if (!user) return true; // Si el usuario no existe, permitir el intento (la autenticación fallará de todos modos)
  
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

// Ruta de restablecimiento de contraseña
app.post('/reset-password', async (req, res) => {
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
    return res.status(400).send('Usuario y nueva contraseña son requeridos');
  }

  try {
    const user = await db.collection('users').findOne({ username });
    
    if (!user) {
      return res.status(404).send('Usuario no encontrado');
    }
    
    const hashedPassword = crypto.createHash('sha256').update(newPassword).digest('hex');

    await db.collection('users').updateOne(
      { username },
      { $set: { password: hashedPassword, failedAttempts: 0, lastFailedAttempt: null } }
    );

    res.send('Contraseña restablecida exitosamente');
  } catch (err) {
    console.error('Error al restablecer la contraseña:', err);
    res.status(500).send('Error en el servidor');
  }
});

// Ruta de registro de usuarios (solo para administradores)
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!req.session || !req.session.authenticated || req.session.role !== 'admin') {
    return res.status(403).send('Solo el administrador puede registrar usuarios');
  }

  if (!username || !password || !role) {
    return res.status(400).send('Todos los campos son requeridos');
  }

  // Verificar que el rol sea válido (admin, supervisor, operador)
  const validRoles = ['admin', 'supervisor', 'operador'];
  if (!validRoles.includes(role)) {
    return res.status(400).send('Rol no válido');
  }

  try {
    // Verificar si el usuario ya existe
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(400).send('El nombre de usuario ya está en uso');
    }

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    await db.collection('users').insertOne({
      username,
      password: hashedPassword,
      role,
      failedAttempts: 0,
      lastFailedAttempt: null
    });

    res.send('Usuario registrado exitosamente');
  } catch (err) {
    console.error('Error al registrar usuario:', err);
    res.status(500).send('Error en el servidor');
  }
});

// Ruta para obtener todos los usuarios (solo para administradores)
app.get('/users', async (req, res) => {
  if (!req.session || !req.session.authenticated || req.session.role !== 'admin') {
    return res.status(403).send('Solo el administrador puede ver la lista de usuarios');
  }

  try {
    const users = await db.collection('users').find({}, { projection: { password: 0 } }).toArray();
    res.json(users);
  } catch (err) {
    console.error('Error al obtener usuarios:', err);
    res.status(500).send('Error en el servidor');
  }
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('¡Algo salió mal!');
});

// Iniciar el servidor
const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});
