<div align="center">

<pre>
 ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗████████╗██╗ █████╗ ██╗
██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║██╔══██╗██║
██║     ██████╔╝█████╗  ██║  ██║█████╗  ██╔██╗ ██║   ██║   ██║███████║██║
██║     ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██║██╔══██║██║
    ╚██████╗██║  ██║███████╗██████╔╝███████╗██║ ╚████║   ██║   ██║██║  ██║███████╗
  ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═╝╚══════╝
</pre>

**Credential Leak Monitor**

Bot de Discord para detección de credenciales comprometidas.

</div>

<br/>

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Discord.py](https://img.shields.io/badge/discord.py-2.3%2B-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discordpy.readthedocs.io)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![APIs](https://img.shields.io/badge/Fuentes-7%20APIs-ef4444?style=for-the-badge&logo=databricks&logoColor=white)]()
[![k-Anonymity](https://img.shields.io/badge/k--Anonymity-SHA--1%20%2B%20SHA3-f59e0b?style=for-the-badge&logo=hackthebox&logoColor=white)]()

<br/>

> Consulta **HaveIBeenPwned · XposedOrNot · LeakCheck · BreachDirectory**  
> **DeHashed · Snusbase · BreachSense** — todo desde un solo comando de Discord

</div>

---

## 📸 Vista previa

```
!clm email test@ejemplo.com

📧 Escaneo Multi-Fuente
Email: t**t@ejemplo.com
Resultado: 🚨 COMPROMETIDO (4/7 fuentes positivas)

1️⃣ HaveIBeenPwned   → 🚨 3 brechas: Adobe · LinkedIn · Dropbox
2️⃣ XposedOrNot      → 🚨 2 brechas | Risk score: 8/10 (High)
3️⃣ LeakCheck        → 🚨 5 fuentes [FREE]
4️⃣ BreachDirectory  → ✅ No encontrado
5️⃣ DeHashed         → ⚙️  Sin key configurada
6️⃣ Snusbase         → ⚙️  Sin key configurada
7️⃣ BreachSense      → ⚙️  Sin key configurada

📂 Datos expuestos: Email · Passwords · IP addresses · Usernames
```

---

## ✨ Características

| Característica | Descripción |
|---|---|
| 🔍 **Multi-fuente** | 7 APIs consultadas en paralelo con `asyncio.gather()` |
| 🔑 **5 fuentes de passwords** | HIBP · XposedOrNot · Snusbase · DeHashed · BreachDirectory |
| 🔒 **k-Anonymity** | SHA-1 + SHA3-Keccak-512 — la contraseña nunca sale de tu equipo |
| 🗑️ **Auto-borrado** | Mensajes con contraseñas eliminados automáticamente del canal |
| 📊 **Informes ejecutivos** | Nivel de riesgo, cronología de brechas y recomendaciones RGPD |
| 🌐 **Dominios corporativos** | Auditoría de filtraciones por dominio empresarial |
| 🎨 **Logging en color** | Consola con colores ANSI + archivo rotativo `bot.log` (5MB × 3) |
| ⏱️ **Cooldowns** | Protección anti-spam por usuario |

---

## 🗂️ Fuentes integradas

### Para emails — 7 fuentes

```
✅ Gratis          ⚠️ Key gratis       💳 De pago
```

| # | Fuente | Tier | Rate limit | Obtener key |
|---|--------|------|-----------|-------------|
| 1️⃣ | **HIBP Email + Pastes** | ⚠️ Key test gratis | 1 req/1.5s | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| 2️⃣ | **XposedOrNot** | ✅ Sin key | 1 req/s | [xposedornot.com/api_management](https://xposedornot.com/api_management) |
| 3️⃣ | **LeakCheck** | ✅ Sin key / Pro | 1 req/s | [leakcheck.io/account](https://leakcheck.io) |
| 4️⃣ | **BreachDirectory** | ⚠️ 10/mes gratis | RapidAPI | [rapidapi.com](https://rapidapi.com/rohan-patra/api/breachdirectory) |
| 5️⃣ | **DeHashed** | 💳 Pay-per-query | Sin límite fijo | [dehashed.com](https://dehashed.com) |
| 6️⃣ | **Snusbase** | 💳 Suscripción | 2048 req/12h | [snusbase.com](https://snusbase.com) |
| 7️⃣ | **BreachSense** | 💳 Suscripción | Plan-based | [breachsense.com](https://breachsense.com) |

### Para contraseñas — 5 fuentes con k-Anonymity

| # | Fuente | Método | Key |
|---|--------|--------|-----|
| 1️⃣ | **HIBP Passwords** | SHA-1 k-anon → prefijo 5 chars | ❌ No necesita |
| 2️⃣ | **XposedOrNot** | SHA3-Keccak-512 → prefijo 10 chars | ❌ No necesita |
| 3️⃣ | **Snusbase** | combo-lookup directo | 💳 `SNUSBASE_KEY` |
| 4️⃣ | **DeHashed** | query `password:X` | 💳 `DEHASHED_KEY` |
| 5️⃣ | **BreachDirectory** | `func=auto&term=X` | ⚠️ `BREACHDIRECTORY_KEY` |

---

## 🤖 Comandos

```
Prefijo: !clm
```

| Comando | Alias | Descripción | Cooldown |
|---------|-------|-------------|----------|
| `!clm password <pass>` | `pass` `pwd` `p` | Contraseña en 5 fuentes — mensaje se auto-elimina | 5s |
| `!clm email <email>` | `e` `scan` | Email en 7 fuentes simultáneas | 10s |
| `!clm domain <dominio>` | `d` | Filtraciones de un dominio corporativo | 15s |
| `!clm report <dominio>` | `r` | Informe ejecutivo completo con riesgo + recomendaciones | 30s |
| `!clm setup` | — | Estado de todas las APIs y keys configuradas | — |
| `!clm help` | `h` | Menú de ayuda | — |

---

## 🚀 Instalación

### Prerrequisitos

- **Python 3.10+**
- **Token de bot de Discord**

### 1 — Clonar

```bash
git clone https://github.com/Borde00/credential-leak-monitor.git
cd credential-leak-monitor
```

### 2 — Instalar dependencias

```bash
pip install -r requirements.txt
```

> Si usas entorno virtual (recomendado):
> ```bash
> python -m venv venv
> venv\Scripts\activate       # Windows
> source venv/bin/activate    # Linux / macOS
> pip install -r requirements.txt
> ```

### 3 — Crear el bot en Discord

1. Ve a **[discord.com/developers/applications](https://discord.com/developers/applications)**
2. `New Application` → asigna un nombre
3. Sección **Bot** → `Reset Token` → copia el token
4. Activa los intents:
   - ✅ `MESSAGE CONTENT INTENT`
   - ✅ `SERVER MEMBERS INTENT`
5. `OAuth2` → `URL Generator`:
   - Scope: ✅ `bot`
   - Permisos: ✅ `Send Messages` · `Read Messages` · `Manage Messages` · `Embed Links`
6. Abre la URL generada → invita el bot a tu servidor

### 4 — Configurar `.env`

```bash
cp .env.example .env
# Edita .env con tu editor favorito
```

### 5 — Arrancar

```bash
python bot.py
```

Deberías ver en consola:

```
=======================================================
  🔐 Credential Leak Monitor v4
  Bot: CredLeakMonitor#3607 | Servidores: 1
─────────────────────────────────────────────────────
  HIBP Password:   ✅ Gratis (k-anon)
  HIBP Email:      ✅
  XposedOrNot:     ✅ Gratis
  LeakCheck:       ✅ Free
  BreachDirectory: ⚙️  Sin key
  DeHashed:        ⚙️  Sin key
  Snusbase:        ⚙️  Sin key
  BreachSense:     ⚙️  Sin key
=======================================================
```

---

## ⚙️ Configuración del `.env`

```ini
# ════════════════════════════════════════════════════
#   CREDENTIAL LEAK MONITOR — Variables de entorno
# ════════════════════════════════════════════════════

# ── OBLIGATORIO ──────────────────────────────────────
DISCORD_TOKEN=tu_token_aqui

# ── GRATIS (sin registro) ────────────────────────────
# HIBP Passwords, XposedOrNot y LeakCheck public
# funcionan automáticamente sin ninguna key

# ── GRATIS CON KEY ───────────────────────────────────
# Key test gratis ya incluida (funciona al instante):
HIBP_API_KEY=

# Registro gratis → https://xposedornot.com/api_management
XPOSEDORNOT_KEY=

# Registro gratis → https://leakcheck.io/account
LEAKCHECK_KEY=

# RapidAPI plan free (10/mes) → https://rapidapi.com/rohan-patra/api/breachdirectory
BREACHDIRECTORY_KEY=

# ── DE PAGO ──────────────────────────────────────────
# DeHashed → https://dehashed.com (pay-per-query)
DEHASHED_EMAIL=
DEHASHED_KEY=

# Snusbase → https://snusbase.com (suscripción)
SNUSBASE_KEY=

# BreachSense → https://breachsense.com (suscripción)
BREACHSENSE_KEY=

# SpyCloud → https://spycloud.com (enterprise)
SPYCLOUD_KEY=

# ── OPCIONES ─────────────────────────────────────────
# DEBUG | INFO | WARNING | ERROR  (por defecto: INFO)
LOG_LEVEL=INFO
```

> **💡 Mínimo para empezar gratis:**
> Solo necesitas `DISCORD_TOKEN`. Los demás son opcionales — HIBP Passwords, XposedOrNot y LeakCheck funcionan sin key.

---

## 🐳 Docker

```bash
# Arrancar en background
docker compose up -d

# Logs en tiempo real
docker compose logs -f

# Parar
docker compose down

# Rebuildar tras cambios
docker compose up -d --build
```

---

## 🔒 Seguridad por diseño

### ¿Cómo funciona k-Anonymity?

Tu contraseña **nunca abandona tu equipo**. El proceso completo:

```
Tu contraseña: "mipassword123"
       │
       ▼
SHA-1 local: "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3"
       │
       ▼ Solo los primeros 5 chars
HIBP recibe: "A94A8"
       │
       ▼ Devuelve ~500 hashes que empiezan por A94A8
Comparación: hecha LOCALMENTE en tu equipo
       │
       ▼
Resultado: encontrada / no encontrada (sin exponer la pass)
```

Lo mismo aplica con **SHA3-Keccak-512** (primeros 10 chars) para XposedOrNot.

### Otras medidas de seguridad

- 🗑️ Mensajes con contraseñas **eliminados automáticamente** del canal
- 👁️ Emails mostrados **enmascarados** en las respuestas (`******n@gmail.com`)
- ⏱️ **Cooldowns por usuario** para evitar abuso de rate limits
- 🔄 Todas las consultas en **paralelo** — sin guardar histórico de búsquedas

---

## 📊 Cómo se calcula el nivel de riesgo

```
!clm report dominio.com

Filtraciones:   0          → ✅ BAJO
Filtraciones:   1-2        → ⚠️  MEDIO
Filtraciones:   3-5        → 🔶 ALTO
Filtraciones:   6+         → 🚨 CRÍTICO
```

El informe incluye:
- Cronología de brechas ordenada por fecha
- Tipos de datos expuestos (emails, passwords, IPs, tarjetas...)
- Recomendaciones según normativa **RGPD** (notificación en 72h si aplica)

---

## 📁 Estructura del proyecto

```
credential-leak-monitor/
│
├── 📄 bot.py               # Bot principal (~1200 líneas)
├── 📄 requirements.txt     # discord.py · aiohttp · python-dotenv
├── 📄 .env.example         # Plantilla de variables de entorno
├── 📄 .env                 # Tu configuración local (⚠️ no subir a Git)
├── 📄 docker-compose.yml   # Despliegue con Docker
├── 📄 Dockerfile
├── 📄 bot.log              # Logs rotativos (generado automáticamente)
└── 📄 README.md
```

---

## 🐛 Solución de problemas

| Error | Causa | Solución |
|-------|-------|----------|
| `ModuleNotFoundError: discord` | Dependencias no instaladas | `pip install -r requirements.txt` |
| `LoginFailure` | Token de Discord inválido | Regenera el token en el portal |
| Bot no responde a comandos | Falta `MESSAGE CONTENT INTENT` | Actívalo en [discord.com/developers](https://discord.com/developers) |
| `Forbidden` al borrar mensajes | Sin permiso | Añade `Manage Messages` al bot |
| `HIBP 401` | Key caducada | Actualiza `HIBP_API_KEY` en `.env` |
| `BreachDirectory 429` | Límite mensual alcanzado | Espera al próximo mes o sube de plan |

### Ver logs en tiempo real

```bash
# Linux / macOS
tail -f bot.log

# Windows PowerShell
Get-Content bot.log -Wait

# Activar modo DEBUG para máximo detalle
# Añade en .env: LOG_LEVEL=DEBUG
```

---

## 🗺️ Roadmap

- [ ] Soporte completo para SpyCloud Enterprise
- [ ] Exportación de informes en PDF
- [ ] Dashboard web con historial de consultas
- [ ] Notificaciones programadas para dominios corporativos
- [ ] Integración con Flare.io (dark web monitoring)

---

## 📄 Licencia

Distribuido bajo licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

<div align="center">
</div>
