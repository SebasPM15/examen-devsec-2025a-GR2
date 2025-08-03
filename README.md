# 🏦 Core Bancario API

Este proyecto es una API REST para un sistema bancario básico, desarrollada como parte de la evaluación de la asignatura **Desarrollo de Software Seguro**. La API permite realizar operaciones financieras fundamentales y está construida con un enfoque en la seguridad y las buenas prácticas de desarrollo.

El sistema está contenedorizado con Docker, lo que facilita su despliegue y ejecución en cualquier entorno compatible.

---

## 📚 Tabla de Contenido

- [🚀 Funcionalidades Principales](#-funcionalidades-principales)
- [🛠 Tecnologías Utilizadas](#-tecnologías-utilizadas)
- [⚙️ Requisitos Previos](#️-requisitos-previos)
- [🧪 Instalación y Ejecución](#-instalación-y-ejecución)
- [📑 Documentación de la API](#-documentación-de-la-api)
- [👤 Aportaciones al Proyecto](#-aportaciones-al-proyecto)
- [📎 Licencia](#-licencia)
- [📚 Referencias](#-referencias)

---

## 🚀 Funcionalidades Principales

- Autenticación de usuarios con roles de `cliente` y `cajero` [1].
- Gestión de cuentas bancarias.
- Operaciones de **Depósitos**, **Retiros** y **Transferencias** [2].
- Manejo de tarjetas de crédito, incluyendo pagos y consulta de saldos [3].
- Documentación de API interactiva a través de **Swagger UI**.
- Seguridad de datos sensibles mediante **encriptación**.

---

## 🛠 Tecnologías Utilizadas

- **Backend:** Python 3.10  
- **Framework:** Flask y Flask-RESTX  
- **Base de Datos:** PostgreSQL  
- **Servidor WSGI:** Gunicorn [4]  
- **Contenerización:** Docker y Docker Compose  
- **Librerías clave:**
  - [`psycopg2-binary`](https://pypi.org/project/psycopg2-binary/): Conexión a PostgreSQL  
  - [`cryptography`](https://pypi.org/project/cryptography/): Encriptación de datos sensibles [5]  

---

## ⚙️ Requisitos Previos

- Tener instalado [Docker](https://www.docker.com/get-started)
- Tener instalado [Docker Compose](https://docs.docker.com/compose/install/) (usualmente incluido en Docker Desktop)

---

## 🧪 Instalación y Ejecución

### 1. Clonar el Repositorio

```bash
git clone https://github.com/tu-usuario/tu-repositorio.git
cd tu-repositorio
````

### 2. Configurar la Clave de Encriptación (`FERNET_KEY`)

Este proyecto requiere una clave secreta para encriptar los datos de las tarjetas.

* Ejecuta el script para generar una clave:

```bash
# Instala la librería si no la tienes:
pip install cryptography

python generate_key.py
```

* El script imprimirá una clave en consola. Cópiala.
* Abre el archivo `docker-compose.yml` y pega la clave en la variable de entorno `FERNET_KEY`:

```yaml
services:
  app:
    # ...
    environment:
      # ...
      FERNET_KEY: "AQUI_PEGA_LA_CLAVE_GENERADA"
```

### 3. Levantar los Contenedores

Con la clave ya configurada, ejecuta:

```bash
docker-compose up --build
```

La API estará disponible en:
👉 `http://localhost:10090`

---

## 📑 Documentación de la API

La documentación interactiva está disponible mediante **Swagger UI**:
[http://localhost:10090/swagger](http://localhost:10090/swagger)

---

## 👤 Aportaciones al Proyecto

### Contribución de Mateo Pilco (Requisito TCE-04)

Como parte de los requisitos de seguridad del proyecto, implementé medidas robustas para el manejo y protección de los datos de tarjetas de crédito. Las mejoras incluyen:

#### 🔐 Encriptación de Datos Sensibles

Implementación de encriptación simétrica con **Fernet** (librería `cryptography`) para asegurar que los datos críticos —número de tarjeta, fecha de expiración y CVV— se almacenen cifrados en la base de datos \[6].

#### 🗂 Almacenamiento Seguro y Aislado

Para cumplir con los requisitos de segmentación de datos, se creó un nuevo **esquema PostgreSQL** llamado `bank_secure` con una tabla exclusiva (`encrypted_cards`) que almacena los datos sensibles, aislados del resto del sistema bancario \[7].

#### 🧮 Validación del Formato de Tarjetas

Se añadió validación con el **algoritmo de Luhn** en el endpoint de pago para asegurar que los números de tarjeta tengan una estructura válida antes de ser procesados, reduciendo el riesgo de errores \[8].

---

## 📎 Licencia

Este proyecto fue desarrollado como parte de un ejercicio académico. Su uso está destinado únicamente a fines educativos.

---

## 📚 Referencias

1. Implementación de autenticación por roles (`cliente` y `cajero`) en endpoints seguros.
2. Control de depósitos, retiros y transferencias implementado en el módulo `operaciones.py`.
3. Funcionalidades para pagos con tarjeta y consultas desarrolladas en `tarjetas.py`.
4. Gunicorn como servidor WSGI para producción segura y escalable.
5. Librería `cryptography` usada para encriptación simétrica con claves Fernet.
6. Mecanismo de cifrado para campos sensibles de tarjetas antes del almacenamiento.
7. Esquema `bank_secure` creado para aislamiento de datos críticos en la base de datos.
8. Validación de tarjetas mediante el algoritmo de Luhn en el backend.
