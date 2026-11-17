# 🌿 Mente en Calma — Plataforma de diagnóstico y bienestar

Plataforma web de acompañamiento en bienestar emocional. Permite a las personas responder cuestionarios (incluido el **WHO-5**), jugar mini-juegos de atención y calma, recibir un informe orientativo y conversar con un asistente de ejemplo. Incluye un panel de administración con datos **agregados** y herramientas de control de cuentas por terminal.

> ⚠️ **Aviso:** esta plataforma es orientativa y **no reemplaza** la valoración de un profesional de salud mental.

---

## ✨ Características

- **Cuestionarios:** WHO-5 y "Calma y carga diaria" (10 preguntas).
- **Juegos:** *Atrapa la estrella*, *Mi planta* y otros, con medición de tiempos de reacción.
- **Informe personal** con nivel tipo semáforo (basado en WHO-5).
- **Chat de ejemplo "Conversar con Calma"** (demo en el navegador, sin envío al servidor).
- **Modo invitado:** los datos viven solo en memoria y se borran al salir.
- **Panel de administración** con datos agregados y, solo con permiso expreso de cada persona, resultados individuales.
- **Derechos del usuario:** descargar o borrar sus datos en cualquier momento.

## 🛠️ Tecnologías

- Node.js **22.13 o superior** (usa `node:sqlite`, **sin dependencias externas**)
- SQLite
- HTML / CSS / JavaScript (frontend en `public/index.html`)

## 📁 Estructura

```
mente-en-calma/
├── public/
│   └── index.html      # Interfaz de usuario
├── server.js           # Servidor y API
├── admin.js            # Control de cuentas por terminal
├── package.json
├── render.yaml         # Blueprint de despliegue en Render
├── .gitignore          # Excluye datos, copias y claves
└── README.md
```

Las carpetas `data/` y `backups/` se generan solas al arrancar y **no se suben a Git**.

## 🚀 Instalación y uso local

```bash
# 1. Clonar el repositorio
git clone https://github.com/1019992028-cmd/Plataforma-de-diagnostico.git
cd Plataforma-de-diagnostico

# 2. Verificar Node.js (debe ser >= 22.13)
node -v

# 3. Arrancar el servidor
npm start
```

Abre **http://localhost:3000**.

En el primer arranque se crea el usuario `admin` y su clave se imprime **una sola vez** en la consola. También puedes fijarla con la variable `ADMIN_PASSWORD` (mínimo 10 caracteres).

## ⚙️ Variables de entorno

| Variable | Descripción |
|---|---|
| `PORT` | Puerto del servidor (por defecto `3000`). |
| `COOKIE_SECURE=1` | Marca la cookie de sesión como *Secure* (usar detrás de HTTPS). |
| `ADMIN_PASSWORD` | Fija o restablece la clave del usuario `admin` al arrancar. |
| `DATA_KEY` | Clave AES-256 en hexadecimal (64 caracteres). Si no existe, se genera `data/secret.key`. |
| `DATA_DIR` | Carpeta donde se guardan la base de datos y las copias. |

Generar una `DATA_KEY`:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 🔒 Seguridad

- Respuestas y resultados cifrados con **AES-256-GCM**; contraseñas con **scrypt**.
- Sesiones con cookie `HttpOnly` + `SameSite=Strict`, límite de intentos de login y cabeceras CSP.
- El administrador ve datos agregados; los resultados individuales solo son visibles si la persona los autorizó (y puede retirar el permiso cuando quiera).
- Cada consulta del administrador queda en la **auditoría** y es visible para la persona.
- Los invitados nunca se escriben en disco.

> 🚫 **Nunca subas a GitHub** `data/`, `backups/`, `*.db` ni `secret.key`. El `.gitignore` ya los excluye. Sin `secret.key` (o `DATA_KEY`) los datos cifrados **no se pueden recuperar**: guárdala en un gestor de contraseñas.

## 👤 Administración por terminal

Ejecutar dentro de la carpeta del proyecto, desde una terminal real:

```bash
node admin.js list [admin|user|blocked]   # listar cuentas
node admin.js promote <alias>             # convertir en administrador
node admin.js demote <alias>              # volver participante
node admin.js create-admin <alias>        # crear administrador
node admin.js block <alias>               # suspender cuenta
node admin.js unblock <alias>             # reactivar cuenta
node admin.js passwd <alias>              # restablecer clave
node admin.js logout <alias>|--all        # cerrar sesiones
node admin.js delete <alias>              # borrar participante y sus datos
node admin.js audit [N] [alias]           # ver auditoría
node admin.js check                       # diagnóstico de acceso
node admin.js reset-admin [--generate]    # restablecer clave del admin principal
```

Siempre debe quedar al menos **un administrador activo**.

## 💾 Copias de seguridad

- Automáticas al arrancar y cada 24 h en `backups/` (se conservan 14).
- Restaurar: detén el servidor, copia la copia elegida sobre `data/mente.db` y borra `mente.db-wal` y `mente.db-shm`.

## ☁️ Despliegue en Render

> Requiere un **plan de pago**: el plan gratuito no tiene disco persistente y los datos se perderían.

1. Genera la `DATA_KEY` y guárdala fuera de Render.
2. Sube el proyecto a un repositorio **privado** de GitHub.
3. En Render: **New → Blueprint** y selecciona el repositorio (usa `render.yaml`).
4. Configura las variables: `NODE_VERSION=22`, `DATA_DIR=/var/data`, `DATA_KEY`, `ADMIN_PASSWORD`.
5. Entra a la URL pública → "Acceso de administrador" → usuario `admin`.
6. Una vez dentro, **elimina `ADMIN_PASSWORD`** de las variables (si no, cada reinicio restablece la clave).

## 📜 Cumplimiento y datos personales

Antes de usarla con personas reales, define una política de tratamiento de datos y un plazo de conservación (Ley 1581 de 2012, Colombia), y pide a un profesional de salud mental revisar los textos del informe y a un abogado la política de datos.

## 📄 Licencia

Proyecto privado. Todos los derechos reservados.
