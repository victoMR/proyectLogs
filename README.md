# Sistema de Gestión de Usuarios con MongoDB en Google Cloud

Este proyecto implementa un **sistema de gestión de usuarios** conectado a una base de datos MongoDB hospedada en Google Cloud. Incluye un servidor Express.js completo con autenticación, restablecimiento de contraseñas, paneles de administración y usuario personalizados, todo configurado con seguridad avanzada.

![Node.js](https://img.shields.io/badge/Node.js-v14+-green.svg)
![Express](https://img.shields.io/badge/Express-v4.18+-blue.svg)
![MongoDB](https://img.shields.io/badge/MongoDB-v5+-yellow.svg)
![Google Cloud](https://img.shields.io/badge/Google_Cloud-Certified-red.svg)

---

## **Tabla de contenidos**

1. [Características](#características)
2. [Requisitos](#requisitos)
3. [Configuración inicial](#configuración-inicial)
4. [Estructura del proyecto](#estructura-del-proyecto)
5. [Despliegue de MongoDB en Google Cloud](#despliegue-de-mongodb-en-google-cloud)
6. [Configuración del servidor Express](#configuración-del-servidor-express)
7. [Características avanzadas](#características-avanzadas)
8. [API Endpoints](#api-endpoints)
9. [Contribuir](#contribuir)
10. [Licencia](#licencia)

---

## **Características**

### Sistema de autenticación
- Inicio de sesión seguro con hash de contraseñas
- Bloqueo automático después de 3 intentos fallidos (5 minutos)
- Sesiones persistentes con Express-session
- Niveles de acceso por rol (admin, supervisor, operador)

### Gestión de cuentas
- Restablecimiento de contraseña mediante correo electrónico
- Verificación con códigos temporales de 6 caracteres
- Interfaz intuitiva de tres pasos para restablecer contraseña
- Sistema de validación de seguridad para nuevas contraseñas

### Paneles de usuario
- Panel de Administración con gestión completa de usuarios
- Panel de Usuario con widgets personalizados (clima, tareas, calendario)
- Visualización de datos en tiempo real (sesión, fecha/hora)
- Diseño responsivo para todos los dispositivos

### Seguridad
- Protección contra inyección de SQL
- Registro detallado de actividades (login, intentos fallidos)
- Manejo seguro de headers y cookies
- Protección CSRF implementada

---

## **Requisitos**

Antes de comenzar, asegúrate de tener instalado lo siguiente:

1. **Node.js (v14+)** y **npm**: [Instalación de Node.js](https://nodejs.org/).
2. **MongoDB**: Local o en la nube.
3. **Terraform**: [Instalación de Terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli) (solo si despliegas en Google Cloud).
4. **Google Cloud SDK**: [Instalación de Google Cloud SDK](https://cloud.google.com/sdk/docs/install) (opcional).
5. **Editor de código**: VS Code, Sublime Text, etc.

---

## **Configuración inicial**

1. **Clona este repositorio**:
   ```bash
   git clone https://github.com/victoMR/proyectLogs
   cd proyectLogs
   ```

2. **Instala las dependencias**:
   ```bash
   npm install
   ```

3. **Configura las variables de entorno**:
   - Crea un archivo `.env` en la raíz del proyecto:
   ```
   MONGO_HOST=localhost
   MONGO_USER=admin
   MONGO_PASSWORD=tu_contraseña
   NODE_SECRET=tu_secreto_para_sesiones
   NODE_EMAIL=tu_correo@ejemplo.com
   NODE_PASSWORD=tu_contraseña_email
   PORT=3001
   ```

4. **Inicia el servidor**:
   ```bash
   npm start
   ```

---

## **Estructura del proyecto**

```
proyecto/
├── logs/                  # Archivos de registro de actividad
├── public/                # Archivos estáticos
│   ├── index.html        # Página de inicio de sesión
│   ├── admin.html        # Panel de administración
│   ├── users.html        # Panel de usuario
│   └── reset-password.html # Página de recuperación de contraseña
├── server.js              # Archivo principal del servidor
├── package.json           # Dependencias del proyecto
├── terraform/             # Archivos de configuración de Terraform
└── .env                   # Variables de entorno (no incluido en el repositorio)
```

---

## **Despliegue de MongoDB en Google Cloud**

### Utilizando Terraform

1. **Inicializa Terraform**:
   ```bash
   cd terraform
   terraform init
   ```

2. **Revisa el plan de despliegue**:
   ```bash
   terraform plan
   ```

3. **Aplica los cambios**:
   ```bash
   terraform apply
   ```

### Configurar MongoDB para el proyecto

1. **Habilitar el acceso remoto**:
   ```yaml
   # /etc/mongod.conf
   net:
     bindIp: 0.0.0.0
     port: 27017
   ```

2. **Crear la base de datos y colecciones**:
   ```javascript
   use dataBaseSegDev;
   db.createCollection("users");

   // Crear usuario administrador inicial
   db.users.insertOne({
     username: "admin",
     email: "admin@example.com",
     password: "hashed_password", // Usar crypto para generar el hash
     role: "admin",
     failedAttempts: 0,
     lastFailedAttempt: null
   });
   ```

---

## **Configuración del servidor Express**

El servidor implementa las siguientes características:

### Middleware principal
```javascript
// Configuración de middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Configuración del middleware de sesión
app.use(session({
  secret: process.env.NODE_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  },
}));
```

### Sistema de registro (Logs)
```javascript
// Flujo de escritura para logs
const accessLogStream = fs.createWriteStream(
  path.join(logsDir, 'access.log'),
  { flags: 'a' }
);

// Middleware de registro personalizado
app.use(customLogger);
```

### Autenticación de usuarios
```javascript
app.post('/login', async (req, res) => {
  // Verificar credenciales
  // Controlar intentos fallidos
  // Establecer sesión
});
```

---

## **Características avanzadas**

### Sistema de restablecimiento de contraseña

Hemos implementado un flujo de tres pasos para restablecimiento de contraseñas:

1. **Solicitud de restablecimiento**:
   - El usuario ingresa su correo electrónico
   - Se genera un código único de 6 caracteres
   - Se envía un correo con el código

2. **Verificación del código**:
   - El usuario ingresa el código recibido
   - El sistema verifica el código contra la base de datos
   - El código tiene una validez de 3 minutos

3. **Establecimiento de nueva contraseña**:
   - El usuario establece una nueva contraseña segura
   - Se actualiza la contraseña en la base de datos
   - Se reinician los intentos fallidos

### Endpoint de información del usuario

Añadimos un nuevo endpoint para obtener datos del usuario autenticado:

```javascript
app.get('/api/user-info', async (req, res) => {
  if (!req.session || !req.session.authenticated) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  try {
    const username = req.session.username;
    const user = await db.collection('users').findOne(
      { username },
      { projection: { password: 0 } }
    );

    res.json({
      username: user.username,
      email: user.email || 'correo no disponible',
      role: user.role
    });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});
```

### Panel de usuario interactivo

El panel de usuario incluye:

- **Información personalizada** del usuario (nombre, correo)
- **Widget de clima** basado en la ubicación geográfica
- **Calendario interactivo** con navegación entre meses
- **Sistema de tareas** con marcado de completadas
- **Estadísticas en tiempo real** (tiempo de sesión, etc.)

---

## **API Endpoints**

| Endpoint | Método | Descripción | Autenticación |
|----------|--------|-------------|---------------|
| `/login` | POST | Iniciar sesión | No |
| `/logout` | GET | Cerrar sesión | Sí |
| `/register` | POST | Registrar nuevo usuario | Sí (admin) |
| `/users` | GET | Obtener lista de usuarios | Sí (admin) |
| `/request-password-reset` | POST | Solicitar restablecimiento | No |
| `/check-verification-code` | POST | Verificar código | No |
| `/verify-reset-password` | POST | Actualizar contraseña | No |
| `/api/user-info` | GET | Obtener info del usuario | Sí |


---

## **Contribuir**

Si deseas contribuir a este proyecto, sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una rama para tu contribución (`git checkout -b feature/nueva-funcionalidad`).
3. Realiza tus cambios y haz commit (`git commit -m 'Añadir nueva funcionalidad'`).
4. Haz push a la rama (`git push origin feature/nueva-funcionalidad`).
5. Abre un Pull Request.

---

## **Licencia**

Este proyecto está bajo la licencia [MIT](LICENSE).

---

## **Gracias**

¡Gracias por usar este proyecto! Si tienes preguntas o sugerencias, no dudes en abrir un issue en el repositorio. 😊
