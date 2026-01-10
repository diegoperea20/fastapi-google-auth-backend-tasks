# FastAPI Google Auth Backend

[Spanish version](#spanish)

Backend built with **FastAPI**, implementing robust authentication via JWT and Google OAuth. It is designed to be secure, fast, and easy to integrate with modern frontends like Next.js.

## 🚀 Features

-   **FastAPI**: High performance and automatic data validation with Pydantic.
-   **Google OAuth 2.0**: Full integration with Google's flow using `Authlib`.
-   **JWT (JSON Web Tokens)**: Secure and stateless session management.
-   **Code Exchange System**: Secure callback implementation that generates temporary codes for the frontend.
-   **Rate Limiting**: Brute force protection using `slowapi`.
-   **SQLAlchemy**: Database management with ORM models.
-   **Pydantic Settings**: Professional configuration based on environment variables.

## 🛠️ Technologies

-   FastAPI
-   SQLAlchemy (SQLite by default)
-   Authlib & HTTPX
-   Bcrypt (Password hashing)
-   Python-Jose (JWT)
-   SlowAPI (Rate Limiting)

## 📋 Prerequisites

-   Python 3.10+
-   Google Cloud Console credentials (Client ID and Client Secret)

## 🔧 Installation

1.  Clone the repository or access the directory:
    ```bash
    cd c:\Users\user\Documents\fast-api-google
    ```

2.  Create a virtual environment and install dependencies:
    ```bash
    python -m venv venv
    .\venv\Scripts\activate  # On Windows
    pip install -r requirements.txt
    ```

3.  Configure environment variables in a `.env` file:
    ```env
    GOOGLE_CLIENT_ID=your_client_id
    GOOGLE_CLIENT_SECRET=your_client_secret
    SECRET_KEY=your_session_secret_key
    JWT_SECRET_KEY=your_jwt_secret_key
    DATABASE_URL=sqlite:///./app.db
    CORS_ORIGINS=http://localhost:3000
    ```

## 🚀 Running the Application

To start the server in development mode:

```bash
uvicorn main:app --reload
```

The server will be available at `http://localhost:8000`. You can access the interactive documentation at:
-   Swagger UI: `http://localhost:8000/docs`
-   Redoc: `http://localhost:8000/redoc`

## 🛣️ Main Endpoints

### Traditional Authentication
-   `POST /api/register`: Register new users.
-   `POST /api/login`: Log in with username/password.

### Google OAuth
-   `GET /api/login/google`: Starts the Google flow.
-   `GET /authorize/google`: Callback that processes Google's response.
-   `POST /api/auth/google/exchange`: Exchanges the temporary code for a JWT token.

### Protected (Require Bearer Token)
-   `GET /api/user/profile`: Returns the current user's profile.
-   `GET /api/protected`: Test endpoint to verify authorization.
-   `GET /api/stats`: Basic system statistics.

## 🛡️ Implemented Security
-   **Hashing**: Direct use of `bcrypt` to avoid compatibility issues.
-   **CORS**: Dynamically configured from `.env`.
-   **CSRF**: Protected via `SessionMiddleware` in the OAuth flow.
-   **Rate Limit**: Request limitation on sensitive endpoints.

---

# FastAPI REST API with JWT and Google OAuth

This is a REST API built with FastAPI that implements two authentication methods:
- **JWT Authentication**: Traditional login and registration with username/password
- **OAuth 2.0 Authentication**: Login with Google

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Google account with OAuth 2.0 configured

## 🚀 Installation

1. **Create a virtual environment (recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
or use miniconda:
```bash
conda create -n environment_name python=3.10
conda activate environment_name
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
# To save the list of packages:
# pip freeze > requirements.txt
```

3. **Configure environment variables**

Create a `.env` file in the project root with the following content:

```env
SECRET_KEY=your-secret-key-here-change-in-production
JWT_SECRET_KEY=your-jwt-secret-key-here-change-in-production
DATABASE_URL=sqlite:///app.db
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
CORS_ORIGINS=http://localhost:3000
```

### Configure Google OAuth 2.0

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API (or the Google People API for modern apps)
4. Go to "Credentials" > "Create credentials" > "OAuth 2.0 Client ID"
5. Configure:
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:8000/authorize/google`
6. Copy the Client ID and Client Secret to your `.env` file

Create Google Console Project and enable the API:

<p align="center">
  <img src="README-images/googleConsole.png" alt="Step3">
</p>

<p align="center">
  <img src="README-images/enableGoogleplus.png" alt="Step4">
</p>

4. If using Docker for MySQL or PostgreSQL:

Use Docker:
```bash
# Commands to use a MySQL Docker container
docker run --name mymysql -e MYSQL_ROOT_PASSWORD=mypassword -p 3306:3306 -d mysql:latest

docker exec -it mymysql bash

# Inside the MySQL container
mysql -u root -p

create database fastapimysql;
```
And your `.env` `DATABASE_URL` will be:

```python
# PostgreSQL example
DATABASE_URL=postgresql://postgres:mypassword@localhost:5432/fastapipostgresql

# MySQL example
DATABASE_URL=mysql+pymysql://root:mypassword@localhost:3306/fastapimysql
```

## 🏃 Running the Application

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## 📚 API Endpoints

### JWT Authentication

#### `POST /api/register`
Registers a new user.

**Request Body:**
```json
{
  "username": "user@example.com",
  "password": "password123"
}
```

**Response (201):**
```json
{
  "message": "User registered successfully",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "user@example.com"
  }
}
```

#### `POST /api/login`
Logs in with username and password.

**Request Body:**
```json
{
  "username": "user@example.com",
  "password": "password123"
}
```

**Response (200):**
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "user@example.com"
  }
}
```

### Google OAuth Authentication

#### `GET /api/login/google`
Starts the Google authentication process. Redirects the user to Google for authorization.

#### `GET /api/authorize/google`
Google OAuth callback. Redirects the frontend with a temporary authorization code.

### Protected Routes

#### `GET /api/protected`
Protected route that requires a valid JWT token.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "message": "Access authorized",
  "user": {
    "id": 1,
    "username": "user@example.com"
  }
}
```

#### `GET /api/user/profile`
Retrieves the profile of the authenticated user.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "user": {
    "id": 1,
    "username": "user@example.com"
  }
}
```

### Utilities

#### `GET /api/health`
Verifies that the API is working.

**Response (200):**
```json
{
  "status": "ok",
  "message": "FastAPI API working correctly"
}
```

## 🔒 JWT Token Usage

After authenticating (login or Google), you will receive an `access_token`. To access protected routes, include this token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

## 📝 Notes

- The database is created automatically when running the application.
- Users authenticated with Google do not have a password (`password_hash = None`).
- The JWT token is stored on the frontend (localStorage) and sent in every request.
- CORS is configured to allow requests from `http://localhost:3000` (Next.js).

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Diego Ivan Perea Montealegre**

- GitHub: [@diegoperea20](https://github.com/diegoperea20)

---

Created by [Diego Ivan Perea Montealegre](https://github.com/diegoperea20)


------

# Spanish

# FastAPI Google Auth Backend

Backend con **FastAPI**, implementando autenticación robusta mediante JWT y Google OAuth. Está diseñado para ser seguro, rápido y fácil de integrar con frontends modernos como Next.js.

## 🚀 Características

-   **FastAPI**: Alto rendimiento y validación automática de datos con Pydantic.
-   **Google OAuth 2.0**: Integración completa con el flujo de Google usando `Authlib`.
-   **JWT (JSON Web Tokens)**: Gestión de sesiones segura y sin estado.
-   **Sistema de Intercambio de Códigos**: Implementación segura de callback que genera códigos temporales para el frontend.
-   **Rate Limiting**: Protección contra fuerza bruta usando `slowapi`.
-   **SQLAlchemy**: Gestión de base de datos con modelos ORM.
-   **Pydantic Settings**: Configuración profesional basada en variables de entorno.

## 🛠️ Tecnologías

-   FastAPI
-   SQLAlchemy (SQLite por defecto)
-   Authlib & HTTPX
-   Bcrypt (Hashing de contraseñas)
-   Python-Jose (JWT)
-   SlowAPI (Rate Limiting)

## 📋 Requisitos Previos

-   Python 3.10+
-   Credenciales de Google Cloud Console (Client ID y Client Secret)

## 🔧 Instalación

1.  Clona el repositorio o accede al directorio:
    ```bash
    cd c:\Users\user\Documents\fast-api-google
    ```

2.  Crea un entorno virtual e instálalo:
    ```bash
    python -m venv venv
    .\venv\Scripts\activate  # En Windows
    pip install -r requirements.txt
    ```

3.  Configura las variables de entorno en un archivo `.env`:
    ```env
    GOOGLE_CLIENT_ID=tu_client_id
    GOOGLE_CLIENT_SECRET=tu_client_secret
    SECRET_KEY=tu_secret_key_pro_sesiones
    JWT_SECRET_KEY=tu_secret_key_pro_jwt
    DATABASE_URL=sqlite:///./app.db
    CORS_ORIGINS=http://localhost:3000
    ```

## 🚀 Ejecución

Para iniciar el servidor en modo desarrollo:

```bash
uvicorn main:app --reload
```

El servidor estará disponible en `http://localhost:8000`. Puedes acceder a la documentación interactiva en:
-   Swagger UI: `http://localhost:8000/docs`
-   Redoc: `http://localhost:8000/redoc`

## 🛣️ Endpoints Principales

### Autenticación Tradicional
-   `POST /api/register`: Registro de nuevos usuarios.
-   `POST /api/login`: Inicio de sesión con username/password.

### Google OAuth
-   `GET /api/login/google`: Inicia el flujo de Google.
-   `GET /authorize/google`: Callback que procesa la respuesta de Google.
-   `POST /api/auth/google/exchange`: Intercambia el código temporal por un token JWT.

### Protegidos (Requieren Bearer Token)
-   `GET /api/user/profile`: Retorna el perfil del usuario actual.
-   `GET /api/protected`: Endpoint de prueba para verificar autorización.
-   `GET /api/stats`: Estadísticas básicas del sistema.

## 🛡️ Seguridad Implementada
-   **Hashing**: Uso directo de `bcrypt` para evitar problemas de compatibilidad.
-   **CORS**: Configurado dinámicamente desde el `.env`.
-   **CSRF**: Protegido mediante `SessionMiddleware` en el flujo OAuth.
-   **Rate Limit**: Limitación de peticiones en endpoints sensibles.



# API REST FastAPI con JWT y OAuth de Google

Esta es una API REST construida con FastAPI que implementa dos métodos de autenticación:
- **Autenticación JWT**: Login y registro tradicional con username/password
- **Autenticación OAuth 2.0**: Login con Google

## 📋 Requisitos Previos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)
- Cuenta de Google con OAuth 2.0 configurado

## 🚀 Instalación



1. **Crear un entorno virtual (recomendado)**
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```
o usar miniconda

   
```python
conda create -n environment_name python=3.10
```

```python
pip install -r requirements.txt
# for save list of packages
# pip freeze > requirements.txt
```


1. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

1. **Configurar variables de entorno**

Crea un archivo `.env` en la raíz del proyecto con el siguiente contenido:

```env
SECRET_KEY=tu-clave-secreta-aqui-cambiar-en-produccion
JWT_SECRET_KEY=tu-jwt-secreta-aqui-cambiar-en-produccion
DATABASE_URL=sqlite:///app.db
GOOGLE_CLIENT_ID=tu-google-client-id
GOOGLE_CLIENT_SECRET=tu-google-client-secret
CORS_ORIGINS=http://localhost:3000
```

### Configurar Google OAuth 2.0

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Crea un nuevo proyecto o selecciona uno existente
3. Habilita la API de Google+
4. Ve a "Credenciales" > "Crear credenciales" > "ID de cliente OAuth 2.0"
5. Configura:
   - Tipo de aplicación: Aplicación web
   - URI de redirección autorizados: `http://localhost:8000/authorize/google`
6. Copia el Client ID y Client Secret a tu archivo `.env`

Create Google Console Project and enable Google+ API

<p align="center">
  <img src="README-images/googleConsole.png" alt="Step3">
</p>

<p align="center">
  <img src="README-images/enableGoogleplus.png" alt="Step4">
</p>

4. if only use docker for db mysql or postgresql

Use Docker 
```python
#Comands for use docker container mysql
docker run --name mymysql -e MYSQL_ROOT_PASSWORD=mypassword -p 3306:3306 -d mysql:latest

docker exec -it mymysql bash

#Inside of the container mysql
mysql -u root -p

create database flaskmysql;

```
And your .env in DATABASE_URL wiil be 

```python
# posgresql example

DATABASE_URL= postgresql://postgres:mypassword@localhost:5432/fastapipostgresql

# mysql example
DATABASE_URL=mysql+pymysql://root:mypassword@localhost:3306/fastapimysql

```


## 🏃 Ejecutar la aplicación

```bash
uvicorn main:app --reload
```

La API estará disponible en `http://localhost:8000`

## 📚 Endpoints de la API

### Autenticación JWT

#### `POST /api/register`
Registra un nuevo usuario.

**Request Body:**
```json
{
  "username": "usuario@ejemplo.com",
  "password": "contraseña123"
}
```

**Response (201):**
```json
{
  "message": "Usuario registrado exitosamente",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "usuario@ejemplo.com"
  }
}
```

#### `POST /api/login`
Inicia sesión con username y password.

**Request Body:**
```json
{
  "username": "usuario@ejemplo.com",
  "password": "contraseña123"
}
```

**Response (200):**
```json
{
  "message": "Login exitoso",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "usuario@ejemplo.com"
  }
}
```

### Autenticación Google OAuth

#### `GET /api/login/google`
Inicia el proceso de autenticación con Google. Redirige al usuario a Google para autorización.

#### `GET /api/authorize/google`
Callback de Google OAuth. Redirige al frontend con el token JWT.

### Rutas Protegidas

#### `GET /api/protected`
Ruta protegida que requiere un token JWT válido.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "message": "Acceso autorizado",
  "user": {
    "id": 1,
    "username": "usuario@ejemplo.com"
  }
}
```

#### `GET /api/user/profile`
Obtiene el perfil del usuario autenticado.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "user": {
    "id": 1,
    "username": "usuario@ejemplo.com"
  }
}
```

### Utilidades

#### `GET /api/health`
Verifica que la API está funcionando.

**Response (200):**
```json
{
  "status": "ok",
  "message": "API Flask funcionando correctamente"
}
```

## 🔒 Uso del Token JWT

Después de autenticarte (login o Google), recibirás un `access_token`. Para acceder a rutas protegidas, incluye este token en el header `Authorization`:

```
Authorization: Bearer <access_token>
```




## 📝 Notas

- La base de datos se crea automáticamente al ejecutar la aplicación
- Los usuarios autenticados con Google no tienen contraseña (`password_hash = None`)
- El token JWT se almacena en el frontend (localStorage) y se envía en cada petición
- CORS está configurado para permitir peticiones desde `http://localhost:3000` (Next.js)





### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author / Autor

**Diego Ivan Perea Montealegre**

- GitHub: [@diegoperea20](https://github.com/diegoperea20)

---

Created by [Diego Ivan Perea Montealegre](https://github.com/diegoperea20)