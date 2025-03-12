# MongoDB en Google Cloud con Terraform

Este proyecto despliega un clúster de MongoDB en Google Cloud utilizando **Terraform**. Incluye la configuración de instancias de Compute Engine, la instalación de MongoDB, y la habilitación de **sharding** y **balancing**.

---

## **Tabla de contenidos**

1. [Requisitos](#requisitos)
2. [Configuración inicial](#configuración-inicial)
3. [Desplegar la infraestructura con Terraform](#desplegar-la-infraestructura-con-terraform)
4. [Configurar MongoDB](#configurar-mongodb)
5. [Habilitar Sharding y Balancing](#habilitar-sharding-y-balancing)
6. [Próximos pasos](#próximos-pasos)
7. [Contribuir](#contribuir)
8. [Licencia](#licencia)

---

## **Requisitos**

Antes de comenzar, asegúrate de tener instalado lo siguiente:

1. **Terraform**: [Instalación de Terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli).
2. **Google Cloud SDK**: [Instalación de Google Cloud SDK](https://cloud.google.com/sdk/docs/install).
3. **Cuenta de Google Cloud**: Con un proyecto habilitado y facturación activa.
4. **Claves de servicio**: Un archivo JSON de credenciales de Google Cloud.

---

## **Configuración inicial**

1. **Clona este repositorio**:
   ```bash
   git clone https://github.com/victoMR/proyectLogs
   cd proyectLogs
   ```

2. **Configura las credenciales de Google Cloud**:
   - Descarga el archivo JSON de credenciales desde Google Cloud Console.
   - Coloca el archivo en la raíz del proyecto y renómbralo a `credentials.json`.

3. **Configura las variables de Terraform**:
   - Edita el archivo `variables.tf` para personalizar la configuración (por ejemplo, región, zona, tipo de máquina, etc.).

---

## **Desplegar la infraestructura con Terraform**

1. **Inicializa Terraform**:
   ```bash
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

   Esto creará las instancias de Compute Engine en Google Cloud y configurará la red.

---

## **Configurar MongoDB**

1. **Conéctate a las instancias**:
   - Usa SSH para conectarte a cada instancia creada por Terraform:
     ```bash
     gcloud compute ssh <NOMBRE_INSTANCIA> --zone=<ZONA>
     ```

2. **Instala MongoDB**:
   - En cada instancia, ejecuta:
     ```bash
     sudo apt update
     sudo apt install -y mongodb-org
     sudo systemctl start mongod
     sudo systemctl enable mongod
     ```

3. **Configura MongoDB para conexiones remotas**:
   - Edita el archivo `/etc/mongod.conf`:
     ```yaml
     net:
       bindIp: 0.0.0.0
       port: 27017
     ```

   - Reinicia MongoDB:
     ```bash
     sudo systemctl restart mongod
     ```

---

## **Habilitar Sharding y Balancing**

1. **Configura los Config Servers**:
   - Crea un replica set para los config servers:
     ```javascript
     rs.initiate({
       _id: "configReplSet",
       configsvr: true,
       members: [
         { _id: 0, host: "<IP_CONFIG1>:27019" },
         { _id: 1, host: "<IP_CONFIG2>:27019" },
         { _id: 2, host: "<IP_CONFIG3>:27019" }
       ]
     });
     ```

2. **Configura los Shards**:
   - Crea un replica set para cada shard:
     ```javascript
     rs.initiate({
       _id: "shardReplSet",
       members: [
         { _id: 0, host: "<IP_SHARD1>:27018" },
         { _id: 1, host: "<IP_SHARD2>:27018" },
         { _id: 2, host: "<IP_SHARD3>:27018" }
       ]
     });
     ```

3. **Configura el Mongos**:
   - Edita el archivo `/etc/mongod.conf`:
     ```yaml
     net:
       bindIp: 0.0.0.0
       port: 27017
     sharding:
       configDB: configReplSet/<IP_CONFIG1>:27019,<IP_CONFIG2>:27019,<IP_CONFIG3>:27019
     ```

4. **Habilita el sharding**:
   - Conéctate al mongos y habilita el sharding:
     ```javascript
     sh.enableSharding("dataBaseSegDev");
     sh.shardCollection("dataBaseSegDev.users", { username: 1 });
     ```

5. **Habilita el balancer**:
   - Verifica y habilita el balancer:
     ```javascript
     sh.getBalancerState();
     sh.setBalancerState(true);
     ```

---

## **Próximos pasos**

1. **Monitorear el clúster**:
   - Usa herramientas como **MongoDB Atlas** o **Prometheus** para monitorear el rendimiento.

2. **Optimizar el sharding**:
   - Ajusta la clave de sharding para mejorar el rendimiento.

3. **Escalar el clúster**:
   - Agrega más shards o instancias según sea necesario.

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

¡Gracias por usar este proyecto! Si tienes preguntas o sugerencias, no dudes en abrir un issue en el repositorio. 😊

---

### **Estructura del repositorio**

```
mongodb-google-cloud-terraform/
├── main.tf
├── variables.tf
├── outputs.tf
├── credentials.json
├── README.md
└── LICENSE
```

