"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║         CREDENTIAL LEAK MONITOR — Discord Bot                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

import discord
from discord.ext import commands
import aiohttp
import hashlib
import os
import asyncio
import re
import logging
import sys
from datetime import datetime
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler

load_dotenv()

# ──────────────────────────────────────────────────────────────
# Logging — Consola en tiempo real + archivo rotativo
# ──────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

class ColorFormatter(logging.Formatter):
    """Colores ANSI para la consola."""
    COLORS = {
        "DEBUG":    "\033[94m",  # Azul
        "INFO":     "\033[92m",  # Verde
        "WARNING":  "\033[93m",  # Amarillo
        "ERROR":    "\033[91m",  # Rojo
        "CRITICAL": "\033[95m",  # Magenta
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    FMT   = "%(asctime)s %(levelname)-8s %(name)s » %(message)s"

    def format(self, record):
        color     = self.COLORS.get(record.levelname, "")
        formatter = logging.Formatter(
            f"{color}{self.BOLD}{self.FMT}{self.RESET}",
            datefmt="%H:%M:%S"
        )
        return formatter.format(record)

class PlainFormatter(logging.Formatter):
    """Sin colores para el archivo de log."""
    def __init__(self):
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s %(name)s » %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

def setup_logging():
    root = logging.getLogger()
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # Handler consola con colores
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG)
    console.setFormatter(ColorFormatter())

    # Handler archivo rotativo (5 MB x 3 archivos)
    file_handler = RotatingFileHandler(
        "bot.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(PlainFormatter())

    root.addHandler(console)
    root.addHandler(file_handler)

    # Silenciar loggers ruidosos de librerías externas
    logging.getLogger("discord").setLevel(logging.WARNING)
    logging.getLogger("discord.http").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)

    return logging.getLogger("CLM")

setup_logging()
log = logging.getLogger("CLM")

DISCORD_TOKEN      = os.getenv("DISCORD_TOKEN", "")
HIBP_API_KEY       = os.getenv("HIBP_API_KEY", "")
BREACHDIRECTORY_KEY = os.getenv("BREACHDIRECTORY_KEY", "")
LEAKCHECK_KEY      = os.getenv("LEAKCHECK_KEY", "")
XPOSEDORNOT_KEY    = os.getenv("XPOSEDORNOT_KEY", "")
DEHASHED_EMAIL     = os.getenv("DEHASHED_EMAIL", "")
DEHASHED_KEY       = os.getenv("DEHASHED_KEY", "")
SNUSBASE_KEY       = os.getenv("SNUSBASE_KEY", "")
BREACHSENSE_KEY    = os.getenv("BREACHSENSE_KEY", "")
SPYCLOUD_KEY       = os.getenv("SPYCLOUD_KEY", "")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!clm ", intents=intents, help_command=None)

# ──────────────────────────────────────────────────────────────
# Colores
# ──────────────────────────────────────────────────────────────
BRAND_COLOR  = discord.Color.from_str("#01696f")
SAFE_COLOR   = discord.Color.from_str("#437a22")
WARN_COLOR   = discord.Color.from_str("#da7101")
DANGER_COLOR = discord.Color.from_str("#a12c7b")
CRIT_COLOR   = discord.Color.from_str("#a13544")

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
def is_valid_email(e):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e))

def is_valid_domain(d):
    return bool(re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", d))

def mask_email(email):
    try:
        local, domain = email.split("@")
        masked = local[0] + "*" * (len(local) - 2) + local[-1] if len(local) > 2 else local[0] + "*"
        return f"{masked}@{domain}"
    except Exception:
        return email

def risk_info(count):
    if count == 0:       return SAFE_COLOR,   "✅", "SEGURO"
    if count < 100:      return WARN_COLOR,   "⚠️", "RIESGO BAJO"
    if count < 10_000:   return DANGER_COLOR, "🔶", "RIESGO MEDIO"
    return CRIT_COLOR, "🚨", "RIESGO ALTO"

# ──────────────────────────────────────────────────────────────
# API 1 — HIBP Pwned Passwords (k-anonymity SHA-1, GRATIS)
# ──────────────────────────────────────────────────────────────
async def check_password_pwned(password: str) -> int:
    sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    log.debug(f"[HIBP-PASS] Consultando rango {prefix}…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status != 200:
                    log.warning(f"[HIBP-PASS] Status inesperado: {r.status}")
                    return -1
                for line in (await r.text()).splitlines():
                    h, cnt = line.strip().split(":")
                    if h == suffix:
                        count = int(cnt)
                        log.info(f"[HIBP-PASS] Contraseña encontrada {count:,} veces")
                        return count
                log.info("[HIBP-PASS] Contraseña NO encontrada")
        except Exception as e:
            log.error(f"[HIBP-PASS] Error: {e}")
            return -1
    return 0

# ──────────────────────────────────────────────────────────────
# API 2 — HIBP Email + Pastes
# ──────────────────────────────────────────────────────────────
async def check_hibp_email(email: str) -> dict:
    out = {"breaches": [], "pastes": [], "error": None}
    if not HIBP_API_KEY:
        log.warning("[HIBP-EMAIL] Sin API key configurada")
        out["error"] = "NO_KEY"
        return out
    headers = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "CredLeakMonitor/3.0"}
    log.debug(f"[HIBP-EMAIL] Consultando {email}…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                headers=headers, timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    out["breaches"] = await r.json()
                    log.info(f"[HIBP-EMAIL] {len(out['breaches'])} brecha(s) para {email}")
                elif r.status == 404:
                    out["breaches"] = []
                    log.info(f"[HIBP-EMAIL] Email limpio: {email}")
                elif r.status == 401:
                    log.error("[HIBP-EMAIL] API Key inválida (401)")
                    out["error"] = "UNAUTHORIZED"; return out
                elif r.status == 429:
                    log.warning("[HIBP-EMAIL] Rate limit alcanzado (429)")
                    out["error"] = "RATE_LIMIT"; return out
        except Exception as e:
            log.error(f"[HIBP-EMAIL] Excepción: {e}")
            out["error"] = str(e); return out
        try:
            async with s.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status == 200: out["pastes"] = await r.json()
                elif r.status == 404: out["pastes"] = []
        except Exception:
            pass
    return out

# ──────────────────────────────────────────────────────────────
# API 3 — HIBP Domain
# ──────────────────────────────────────────────────────────────
async def check_hibp_domain(domain: str):
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                return await r.json() if r.status == 200 else []
        except Exception:
            return None

# ──────────────────────────────────────────────────────────────
# API 4 — XposedOrNot Email (GRATIS, sin key)
# ──────────────────────────────────────────────────────────────
async def check_xposedornot(email: str) -> dict:
    headers = {"x-api-key": XPOSEDORNOT_KEY} if XPOSEDORNOT_KEY else {}
    log.debug(f"[XON] Consultando {email}… (key: {'sí' if XPOSEDORNOT_KEY else 'no'})")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    # ✅ FIX: usar "or {}" para proteger contra valores null en el JSON
                    breaches = (data.get("BreachesSummary") or {}).get("site", "")
                    count = len([x for x in breaches.split(";") if x]) if breaches else 0
                    log.info(f"[XON] {count} brecha(s) para {email}")
                    return {"ok": True, "data": data}
                elif r.status == 404:
                    log.info(f"[XON] Email limpio: {email}")
                    return {"ok": True, "data": None}
                elif r.status == 429:
                    log.warning("[XON] Rate limit (429)")
                    return {"ok": False, "error": "RATE_LIMIT"}
        except Exception as e:
            log.error(f"[XON] Excepción: {e}")
            return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "UNKNOWN"}

# ──────────────────────────────────────────────────────────────
# API 5 — XposedOrNot Password (k-anonymity SHA3-Keccak-512)
# ──────────────────────────────────────────────────────────────
async def check_xon_password(password: str) -> dict:
    try:
        h      = hashlib.new("sha3_512", password.encode("utf-8")).hexdigest()
        prefix = h[:10]
    except Exception:
        return {"error": "HASH_ERROR"}

    headers = {"x-api-key": XPOSEDORNOT_KEY} if XPOSEDORNOT_KEY else {}
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://passwords.xposedornot.com/v1/pass/anon/{prefix}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status == 200:   return await r.json()
                elif r.status == 404: return {"not_found": True}
                elif r.status == 429: return {"error": "RATE_LIMIT"}
        except Exception as e:
            return {"error": str(e)}
    return {"error": "UNKNOWN"}

# ──────────────────────────────────────────────────────────────
# API 6 — LeakCheck (GRATIS sin key, PRO con key)
# ──────────────────────────────────────────────────────────────
async def check_leakcheck(email: str) -> dict:
    plan = "PRO" if LEAKCHECK_KEY else "FREE"
    log.debug(f"[LEAKCHECK] Consultando {email}… (plan: {plan})")
    async with aiohttp.ClientSession() as s:
        try:
            if LEAKCHECK_KEY:
                async with s.get(
                    f"https://leakcheck.io/api/v2/query/{email}",
                    headers={"X-API-Key": LEAKCHECK_KEY},
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as r:
                    if r.status == 200:
                        d = await r.json()
                        d["_plan"] = "pro"
                        log.info(f"[LEAKCHECK-PRO] found={d.get('found', 0)} para {email}")
                        return d
            async with s.get(
                f"https://leakcheck.io/api/public?check={email}",
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    d = await r.json()
                    d["_plan"] = "free"
                    log.info(f"[LEAKCHECK-FREE] found={d.get('found', 0)} para {email}")
                    return d
                elif r.status == 429:
                    log.warning("[LEAKCHECK] Rate limit (429)")
                    return {"error": "RATE_LIMIT"}
        except Exception as e:
            log.error(f"[LEAKCHECK] Excepción: {e}")
            return {"error": str(e)}
    return {"error": "UNKNOWN"}

# ──────────────────────────────────────────────────────────────
# API 7 — BreachDirectory (RapidAPI, 10/mes gratis)
# ──────────────────────────────────────────────────────────────
async def check_breachdirectory(email: str) -> dict:
    if not BREACHDIRECTORY_KEY:
        log.warning("[BREACHDIR] Sin API key — configura BREACHDIRECTORY_KEY")
        return {"error": "NO_KEY"}
    log.debug(f"[BREACHDIR] Consultando {email}…")
    headers = {
        "X-RapidAPI-Key":  BREACHDIRECTORY_KEY,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                "https://breachdirectory.p.rapidapi.com/",
                headers=headers,
                params={"func": "auto", "term": email},
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:           return await r.json()
                elif r.status in (401, 403):  return {"error": "UNAUTHORIZED"}
                elif r.status == 429:         return {"error": "RATE_LIMIT"}
                elif r.status == 404:         return {"result": False, "found": 0}
        except Exception as e:
            return {"error": str(e)}
    return {"error": "UNKNOWN"}

# ──────────────────────────────────────────────────────────────
# API 8 — DeHashed (Basic Auth)
# ──────────────────────────────────────────────────────────────
async def check_dehashed(email: str) -> dict:
    if not DEHASHED_EMAIL or not DEHASHED_KEY:
        log.warning("[DEHASHED] Sin credenciales — configura DEHASHED_EMAIL y DEHASHED_KEY")
        return {"error": "NO_KEY"}
    import base64
    creds   = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_KEY}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}
    log.debug(f"[DEHASHED] Consultando {email}…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://api.dehashed.com/search?query=email:{email}&size=10",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    log.info(f"[DEHASHED] {data.get('total', 0)} resultado(s) para {email}")
                    return data
                elif r.status == 401:
                    log.error("[DEHASHED] Credenciales inválidas (401)")
                    return {"error": "UNAUTHORIZED"}
                elif r.status == 429:
                    log.warning("[DEHASHED] Rate limit (429)")
                    return {"error": "RATE_LIMIT"}
                elif r.status == 400:
                    return {"error": "BAD_REQUEST"}
                else:
                    return {"error": f"HTTP_{r.status}"}
        except Exception as e:
            log.error(f"[DEHASHED] Excepción: {e}")
            return {"error": str(e)}

# ──────────────────────────────────────────────────────────────
# API 9 — Snusbase (requiere suscripción)
# ──────────────────────────────────────────────────────────────
async def check_snusbase_email(email: str) -> dict:
    if not SNUSBASE_KEY:
        log.warning("[SNUSBASE] Sin API key — configura SNUSBASE_KEY")
        return {"error": "NO_KEY"}
    headers = {"Auth": SNUSBASE_KEY, "Content-Type": "application/json"}
    payload = {"terms": [email], "types": ["email"]}
    log.debug(f"[SNUSBASE] Consultando {email}…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.post(
                "https://api.snusbase.com/data/search",
                headers=headers, json=payload,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    log.info(f"[SNUSBASE] {data.get('size', 0)} resultado(s) para {email}")
                    return data
                elif r.status == 401:
                    log.error("[SNUSBASE] API Key inválida (401)")
                    return {"error": "UNAUTHORIZED"}
                elif r.status == 429:
                    log.warning("[SNUSBASE] Rate limit (429)")
                    return {"error": "RATE_LIMIT"}
                else:
                    return {"error": f"HTTP_{r.status}"}
        except Exception as e:
            log.error(f"[SNUSBASE] Excepción: {e}")
            return {"error": str(e)}

async def check_snusbase_password(password: str) -> dict:
    if not SNUSBASE_KEY:
        return {"error": "NO_KEY"}
    headers = {"Auth": SNUSBASE_KEY, "Content-Type": "application/json"}
    payload = {"terms": [password], "types": ["password"]}
    log.debug("[SNUSBASE] Combo-lookup de contraseña…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.post(
                "https://api.snusbase.com/tools/combo-lookup",
                headers=headers, json=payload,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    log.info(f"[SNUSBASE-COMBO] size={data.get('size', 0)}")
                    return data
                elif r.status == 401: return {"error": "UNAUTHORIZED"}
                elif r.status == 429: return {"error": "RATE_LIMIT"}
                else:                 return {"error": f"HTTP_{r.status}"}
        except Exception as e:
            return {"error": str(e)}

# ──────────────────────────────────────────────────────────────
# API 10 — BreachSense (Bearer token)
# ──────────────────────────────────────────────────────────────
async def check_breachsense(email: str) -> dict:
    if not BREACHSENSE_KEY:
        log.warning("[BREACHSENSE] Sin API key — configura BREACHSENSE_KEY")
        return {"error": "NO_KEY"}
    headers = {"Authorization": f"Bearer {BREACHSENSE_KEY}", "Accept": "application/json"}
    log.debug(f"[BREACHSENSE] Consultando {email}…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://api.breachsense.com/v1/email/{email}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    log.info(f"[BREACHSENSE] {data.get('cnt', 0)} resultado(s) para {email}")
                    return data
                elif r.status in (401, 403):
                    log.error("[BREACHSENSE] API Key inválida")
                    return {"error": "UNAUTHORIZED"}
                elif r.status == 429:
                    log.warning("[BREACHSENSE] Rate limit")
                    return {"error": "RATE_LIMIT"}
                elif r.status == 404:
                    return {"cnt": 0, "results": []}
                else:
                    return {"error": f"HTTP_{r.status}"}
        except Exception as e:
            log.error(f"[BREACHSENSE] Excepción: {e}")
            return {"error": str(e)}

# ──────────────────────────────────────────────────────────────
# API 11 — DeHashed por contraseña
# ──────────────────────────────────────────────────────────────
async def check_dehashed_password(password: str) -> dict:
    if not DEHASHED_EMAIL or not DEHASHED_KEY:
        return {"error": "NO_KEY"}
    import base64
    creds   = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_KEY}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}
    log.debug("[DEHASHED-PASS] Consultando por contraseña…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://api.dehashed.com/search?query=password:{password}&size=10",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    log.info(f"[DEHASHED-PASS] total={data.get('total', 0)}")
                    return data
                elif r.status == 401: return {"error": "UNAUTHORIZED"}
                elif r.status == 429: return {"error": "RATE_LIMIT"}
                else:                 return {"error": f"HTTP_{r.status}"}
        except Exception as e:
            log.error(f"[DEHASHED-PASS] {e}")
            return {"error": str(e)}

# ──────────────────────────────────────────────────────────────
# API 12 — BreachDirectory por contraseña
# ──────────────────────────────────────────────────────────────
async def check_breachdirectory_password(password: str) -> dict:
    if not BREACHDIRECTORY_KEY:
        return {"error": "NO_KEY"}
    headers = {
        "X-RapidAPI-Key":  BREACHDIRECTORY_KEY,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }
    log.debug("[BREACHDIR-PASS] Consultando por contraseña…")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                "https://breachdirectory.p.rapidapi.com/",
                headers=headers,
                params={"func": "auto", "term": password},
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    log.info(f"[BREACHDIR-PASS] found={data.get('found', 0)}")
                    return data
                elif r.status in (401, 403): return {"error": "UNAUTHORIZED"}
                elif r.status == 429:        return {"error": "RATE_LIMIT"}
                elif r.status == 404:        return {"result": False, "found": 0}
                else:                        return {"error": f"HTTP_{r.status}"}
        except Exception as e:
            log.error(f"[BREACHDIR-PASS] {e}")
            return {"error": str(e)}

# ══════════════════════════════════════════════════════════════
# FORMATEADORES
# ══════════════════════════════════════════════════════════════

def fmt_hibp(res: dict):
    if res.get("error") == "NO_KEY":
        return "⚙️ `HIBP_API_KEY` no configurada\nUsa key test: `00000000000000000000000000000000`", False
    if res.get("error") == "UNAUTHORIZED": return "❌ HIBP Key inválida", False
    if res.get("error") == "RATE_LIMIT":   return "⏳ Rate limit HIBP", False
    if res.get("error"):                   return f"❌ Error: `{res['error']}`", False

    breaches = res.get("breaches", [])
    pastes   = res.get("pastes", [])
    if not breaches and not pastes:
        return "✅ No encontrado en HIBP", False

    lines = []
    if breaches:
        names = [f"`{b.get('Name','?')}`" for b in breaches[:5]]
        suf   = f" _(+{len(breaches)-5} más)_" if len(breaches) > 5 else ""
        lines.append(f"🚨 **{len(breaches)} brecha(s):** {' · '.join(names)}{suf}")
    if pastes:
        lines.append(f"📋 **{len(pastes)} paste(s)** públicos")
    return "\n".join(lines), True


def fmt_xon(res: dict):
    if not res.get("ok"):
        err = res.get("error", "UNKNOWN")
        if err == "RATE_LIMIT": return "⏳ Rate limit XposedOrNot (1 req/s)", False
        return f"❌ Error XposedOrNot: `{err}`", False

    data = res.get("data")
    if not data:
        return "✅ No encontrado en XposedOrNot", False

    # ✅ FIX: "or {}" protege contra valores null en el JSON de la API
    summary = data.get("BreachesSummary") or {}
    metrics = data.get("BreachMetrics")   or {}
    details = (data.get("ExposedBreaches") or {}).get("breaches_details", [])
    pastes  = data.get("PastesSummary")   or {}

    site_raw = summary.get("site", "")
    sites    = [s.strip() for s in site_raw.split(";")] if site_raw else []
    num      = len(sites)

    lines = [f"🚨 **{num} brecha(s) detectada(s)**"]
    for d in details[:4]:
        yr   = d.get("xposed_date", "?")
        rec  = d.get("xposed_records", 0)
        risk = d.get("password_risk", "?")
        lines.append(f"• **{d.get('breach','?')}** ({yr}) — `{rec:,}` registros | riesgo pass: `{risk}`")
    if num > 4:
        lines.append(f"_... y {num-4} más_")

    # Risk score de métricas
    risk_data = metrics.get("risk") or []
    if risk_data:
        score = risk_data[0].get("risk_score", "?")
        label = risk_data[0].get("risk_label", "?")
        lines.append(f"📊 **Risk score:** `{score}/10` ({label})")

    paste_cnt = pastes.get("cnt", 0)
    if paste_cnt:
        lines.append(f"📋 **{paste_cnt} paste(s)** detectados")

    return "\n".join(lines), True


def fmt_leakcheck(res: dict):
    if res.get("error") == "RATE_LIMIT": return "⏳ Rate limit LeakCheck", False
    if res.get("error"):                 return f"❌ Error LeakCheck: `{res.get('error')}`", False

    found   = res.get("found", 0)
    sources = res.get("sources", [])
    plan    = res.get("_plan", "free")

    if not found:
        return "✅ No encontrado en LeakCheck", False

    lines = [f"🚨 **{found} fuente(s)** [{plan.upper()}]"]
    for s in sources[:5]:
        name = s if isinstance(s, str) else s.get("name", str(s))
        lines.append(f"• `{name}`")
    if len(sources) > 5:
        lines.append(f"_... y {len(sources)-5} más_")
    if plan == "free":
        lines.append("_⚠️ Contraseñas ocultas en plan free_")
    return "\n".join(lines), True


def fmt_breachdirectory(res: dict):
    if res.get("error") == "NO_KEY":
        return "⚙️ `BREACHDIRECTORY_KEY` no configurada\nObtener gratis (10/mes): [RapidAPI](https://rapidapi.com/rohan-patra/api/breachdirectory)", False
    if res.get("error") == "UNAUTHORIZED": return "❌ RapidAPI Key inválida", False
    if res.get("error") == "RATE_LIMIT":   return "⏳ Límite mensual alcanzado (10/mes plan free)", False
    if res.get("error"):                   return f"❌ Error BreachDirectory: `{res.get('error')}`", False

    found   = res.get("found", 0)
    sources = res.get("sources", [])
    if not res.get("result") or not found:
        return "✅ No encontrado en BreachDirectory", False

    lines = [f"🚨 **{found} registro(s) encontrados**"]
    for s in sources[:4]:
        line = f"• `{s.get('name','?')}`"
        if s.get("password"): line += f" | Pass: `{s['password']}`"
        elif s.get("sha1"):   line += f" | SHA1: `{str(s['sha1'])[:20]}…`"
        elif s.get("hash"):   line += f" | Hash: `{str(s['hash'])[:20]}…`"
        lines.append(line)
    if found > 4:
        lines.append(f"_... y {found-4} más_")
    return "\n".join(lines), True


def fmt_dehashed(res: dict):
    if res.get("error") == "NO_KEY":
        return "⚙️ Configura `DEHASHED_EMAIL` + `DEHASHED_KEY`\n🔗 [dehashed.com](https://dehashed.com) — Pay-per-query", False
    if res.get("error") == "UNAUTHORIZED": return "❌ Credenciales DeHashed inválidas", False
    if res.get("error") == "RATE_LIMIT":   return "⏳ Rate limit DeHashed", False
    if res.get("error"):                   return f"❌ Error: `{res.get('error')}`", False

    total   = res.get("total", 0)
    entries = res.get("entries", [])
    if not total:
        return "✅ No encontrado en DeHashed", False

    lines = [f"🚨 **{total:,} registro(s)**"]
    for e in entries[:4]:
        src   = e.get("database_name", "?")
        pwd   = e.get("password", "")
        hash_ = e.get("hashed_password", "")
        user  = e.get("username", "")
        line  = f"• **{src}**"
        if user:  line += f" | user: `{user}`"
        if pwd:   line += f" | pass: `{pwd}`"
        elif hash_: line += f" | hash: `{hash_[:20]}…`"
        lines.append(line)
    if total > 4:
        lines.append(f"_... y {total - 4} más_")
    return "\n".join(lines), True


def fmt_snusbase(res: dict):
    if res.get("error") == "NO_KEY":
        return "⚙️ Configura `SNUSBASE_KEY`\n🔗 [snusbase.com](https://snusbase.com) — requiere suscripción", False
    if res.get("error") == "UNAUTHORIZED": return "❌ Snusbase Key inválida", False
    if res.get("error") == "RATE_LIMIT":   return "⏳ Rate limit Snusbase (2048 req/12h)", False
    if res.get("error"):                   return f"❌ Error: `{res.get('error')}`", False

    size    = res.get("size", 0)
    results = res.get("results", {})
    if not size:
        return "✅ No encontrado en Snusbase", False

    lines = [f"🚨 **{size:,} registro(s)** en `{len(results)}` DB(s)"]
    count = 0
    for db_name, records in results.items():
        if count >= 4: break
        short_db = db_name.split("_")[0] + "…" if len(db_name) > 30 else db_name
        for rec in records[:2]:
            if count >= 4: break
            pwd   = rec.get("password", "")
            hash_ = rec.get("hash", "")
            user  = rec.get("username", "")
            ip    = rec.get("lastip", "")
            line  = f"• **{short_db}**"
            if user:  line += f" | `{user}`"
            if pwd:   line += f" | pass: `{pwd}`"
            elif hash_: line += f" | hash: `{hash_[:20]}…`"
            if ip:    line += f" | IP: `{ip}`"
            lines.append(line)
            count += 1
    if size > count:
        lines.append(f"_... y {size - count} más_")
    return "\n".join(lines), True


def fmt_breachsense(res: dict):
    if res.get("error") == "NO_KEY":
        return "⚙️ Configura `BREACHSENSE_KEY`\n🔗 [breachsense.com](https://breachsense.com)", False
    if res.get("error") == "UNAUTHORIZED": return "❌ BreachSense Key inválida", False
    if res.get("error") == "RATE_LIMIT":   return "⏳ Rate limit BreachSense", False
    if res.get("error"):                   return f"❌ Error: `{res.get('error')}`", False

    cnt     = res.get("cnt", 0)
    results = res.get("results", []) if isinstance(res.get("results"), list) else []
    if not cnt:
        return "✅ No encontrado en BreachSense", False

    lines = [f"🚨 **{cnt:,} registro(s)**"]
    for r in results[:4]:
        src  = r.get("src", "?")
        pwd  = r.get("pwd", "")
        line = f"• **{src}**"
        if pwd: line += f" | pass: `{pwd}`"
        lines.append(line)
    if cnt > 4:
        lines.append(f"_... y {cnt - 4} más_")
    return "\n".join(lines), True

# ══════════════════════════════════════════════════════════════
# EVENTOS
# ══════════════════════════════════════════════════════════════

@bot.event
async def on_ready():
    log.info(f"Bot conectado como {bot.user} (ID: {bot.user.id})")
    log.info(f"Servidores: {len(bot.guilds)}")
    log.info(f"Nivel de log activo: {LOG_LEVEL}")
    status = {
        "HIBP Password":   "✅ Gratis (k-anon)",
        "HIBP Email":      "✅" if HIBP_API_KEY      else "⚠️ Sin key",
        "XposedOrNot":     "✅ Key configurada" if XPOSEDORNOT_KEY else "✅ Gratis",
        "LeakCheck":       "✅ PRO" if LEAKCHECK_KEY else "✅ Free",
        "BreachDirectory": "✅" if BREACHDIRECTORY_KEY else "⚙️ Sin key",
        "DeHashed":        "✅" if DEHASHED_KEY       else "⚙️ Sin key",
        "Snusbase":        "✅" if SNUSBASE_KEY        else "⚙️ Sin key",
        "BreachSense":     "✅" if BREACHSENSE_KEY     else "⚙️ Sin key",
    }
    print(f"\n{'═'*55}")
    print(f"  🔐 Credential Leak Monitor v4")
    print(f"  Bot: {bot.user} | Servidores: {len(bot.guilds)}")
    print(f"{'─'*55}")
    for k, v in status.items():
        print(f"  {k:<20} {v}")
    print(f"{'═'*55}\n")
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="leaks 🔍 | 7 fuentes | !clm help"
        )
    )

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        log.debug(f"[COOLDOWN] {ctx.author} intentó !clm {ctx.invoked_with} — retry en {error.retry_after:.1f}s")
        await ctx.send(f"⏳ Cooldown: reintenta en `{error.retry_after:.1f}s`", delete_after=6)
    elif isinstance(error, commands.CommandNotFound):
        log.debug(f"[CMD:unknown] {ctx.author} usó: {ctx.message.content[:50]}")
        await ctx.send("❓ Comando no reconocido. Usa `!clm help`", delete_after=5)
    else:
        log.error(f"[ERROR] {type(error).__name__} en {ctx.command}: {error}")
        await ctx.send(f"❌ Error: `{type(error).__name__}: {error}`")

# ══════════════════════════════════════════════════════════════
# COMANDOS
# ══════════════════════════════════════════════════════════════

@bot.command(name="help", aliases=["h"])
async def help_cmd(ctx):
    embed = discord.Embed(
        title="🔐 Credential Leak Monitor v4",
        description=(
            "Escanea **7 fuentes simultáneas** de credenciales filtradas:\n"
            "HIBP · XposedOrNot · LeakCheck · BreachDirectory · DeHashed · Snusbase · BreachSense"
        ),
        color=BRAND_COLOR,
        timestamp=datetime.utcnow()
    )
    cmds = [
        ("📧 `!clm email <email>`",      "Escanea el email en las 7 fuentes a la vez"),
        ("🔑 `!clm password <pass>`",    "Verifica contraseña con k-anonymity SHA-1 + SHA3"),
        ("🌐 `!clm domain <dominio>`",   "Filtraciones de un dominio corporativo (HIBP)"),
        ("📊 `!clm report <dominio>`",   "Informe ejecutivo completo con nivel de riesgo"),
        ("⚙️ `!clm setup`",              "Estado de todas las APIs y keys configuradas"),
    ]
    for name, desc in cmds:
        embed.add_field(name=name, value=desc, inline=False)
    embed.set_footer(text="🔒 Contraseñas nunca salen de tu equipo · SHA-1 k-anonymity")
    await ctx.send(embed=embed)


@bot.command(name="setup")
async def setup_cmd(ctx):
    embed = discord.Embed(
        title="⚙️ Estado de APIs — Credential Leak Monitor v4",
        description="**7 fuentes** integradas · ✅ Gratis · ⚠️ Free+Key · 💳 Pago",
        color=BRAND_COLOR,
        timestamp=datetime.utcnow()
    )
    apis = [
        ("✅ HIBP Passwords",    "Gratis · k-anonymity SHA-1 · sin límite",        "api.pwnedpasswords.com",                         "Sin key necesaria"),
        ("✅ XposedOrNot",       "Gratis sin key · key gratis disponible",          "xposedornot.com/api_management",                 f"{'🔑 Key configurada' if XPOSEDORNOT_KEY else '⚠️ Sin key (funciona igual)'}"),
        ("✅ LeakCheck",         "Gratis sin key · PRO con key ($9.99/mes)",        "leakcheck.io",                                   f"{'🔑 PRO configurada' if LEAKCHECK_KEY else '⚠️ Free (funciona igual)'}"),
        ("⚠️ HIBP Email",        "Key test gratis o ~3.50 USD/mes real",            "haveibeenpwned.com/API/Key",                     f"{'✅ Configurada' if HIBP_API_KEY else '❌ Falta HIBP_API_KEY'}"),
        ("⚠️ BreachDirectory",   "10 búsquedas/mes gratis — RapidAPI",             "rapidapi.com/rohan-patra/api/breachdirectory",   f"{'✅ Configurada' if BREACHDIRECTORY_KEY else '❌ Falta BREACHDIRECTORY_KEY'}"),
        ("💳 DeHashed",          "Pay-per-query · Basic Auth",                     "dehashed.com",                                   f"{'✅ Configurada' if DEHASHED_KEY else '❌ Falta DEHASHED_EMAIL + KEY'}"),
        ("💳 Snusbase",          "Suscripción · 2048 req/12h",                     "snusbase.com",                                   f"{'✅ Configurada' if SNUSBASE_KEY else '❌ Falta SNUSBASE_KEY'}"),
        ("💳 BreachSense",       "Suscripción · Bearer token",                     "breachsense.com",                                f"{'✅ Configurada' if BREACHSENSE_KEY else '❌ Falta BREACHSENSE_KEY'}"),
    ]
    for name, note, url, estado in apis:
        embed.add_field(
            name=f"{name}",
            value=f"📌 **Estado:** {estado}\n📝 {note}\n🔗 `{url}`",
            inline=False
        )
    activas = sum([bool(HIBP_API_KEY), bool(XPOSEDORNOT_KEY), bool(LEAKCHECK_KEY),
                   bool(BREACHDIRECTORY_KEY), bool(DEHASHED_KEY), bool(SNUSBASE_KEY),
                   bool(BREACHSENSE_KEY)])
    embed.add_field(
        name="📊 Resumen",
        value=(
            f"**Keys configuradas:** {activas}/7\n"
            f"**Fuentes activas en !clm email:** 7\n"
            f"**Log level:** `{LOG_LEVEL}`"
        ),
        inline=False
    )
    embed.add_field(
        name="📝 .env mínimo para empezar GRATIS",
        value=(
            "```ini\n"
            "DISCORD_TOKEN=tu_token\n"
            "HIBP_API_KEY=00000000000000000000000000000000\n"
            "# LeakCheck y XposedOrNot funcionan sin key automáticamente\n"
            "```"
        ),
        inline=False
    )
    embed.set_footer(text="CLM v4 · !clm help para ver comandos")
    await ctx.send(embed=embed)


@bot.command(name="password", aliases=["pass", "pwd", "p"])
@commands.cooldown(1, 5, commands.BucketType.user)
async def cmd_password(ctx, *, password: str = None):
    if not password:
        await ctx.send("❌ Uso: `!clm password <contraseña>`"); return
    try:
        await ctx.message.delete()
    except discord.Forbidden:
        pass

    log.info(f"[CMD:password] Solicitado por {ctx.author} ({ctx.author.id}) en #{ctx.channel}")
    thinking = await ctx.send("🔍 Comprobando contraseña en 5 fuentes simultáneas…")

    (hibp_count, xon_res,
     sns_pass, dh_pass, bd_pass) = await asyncio.gather(
        check_password_pwned(password),
        check_xon_password(password),
        check_snusbase_password(password),
        check_dehashed_password(password),
        check_breachdirectory_password(password),
    )

    hits = 0
    if isinstance(hibp_count, int) and hibp_count > 0: hits += 1
    xon_data  = xon_res.get("SearchPassAnon", {}) if not xon_res.get("not_found") and not xon_res.get("error") else {}
    xon_count = int(xon_data.get("count", 0))
    if xon_count > 0:               hits += 1
    if sns_pass.get("size", 0) > 0: hits += 1
    if dh_pass.get("total", 0) > 0: hits += 1
    if bd_pass.get("found", 0) > 0: hits += 1

    color = CRIT_COLOR if hits >= 3 else (DANGER_COLOR if hits >= 1 else SAFE_COLOR)

    embed = discord.Embed(
        title="🔑 Comprobación de Contraseña",
        description=(
            f"**Resultado:** {'🚨 COMPROMETIDA' if hits > 0 else '✅ LIMPIA'} "
            f"(**{hits}/5** fuentes positivas)"
        ),
        color=color,
        timestamp=datetime.utcnow()
    )

    # 1. HIBP Pwned Passwords
    if hibp_count == -1:
        embed.add_field(name="1️⃣ HIBP Pwned Passwords", value="❌ Error de conexión", inline=False)
    else:
        _, emoji, label = risk_info(hibp_count)
        embed.add_field(
            name="1️⃣ HIBP Pwned Passwords",
            value=f"{emoji} **{label}** — encontrada `{hibp_count:,}` veces",
            inline=False
        )

    # 2. XposedOrNot
    if xon_res.get("not_found"):
        embed.add_field(name="2️⃣ XposedOrNot", value="✅ No encontrada", inline=False)
    elif xon_res.get("error"):
        embed.add_field(name="2️⃣ XposedOrNot", value=f"⚠️ `{xon_res['error']}`", inline=False)
    elif xon_count > 0:
        xon_char = xon_data.get("char", "?")
        embed.add_field(
            name="2️⃣ XposedOrNot",
            value=f"🚨 Encontrada **{xon_count:,} veces** | Características: `{xon_char}`",
            inline=False
        )
    else:
        embed.add_field(name="2️⃣ XposedOrNot", value="✅ No encontrada", inline=False)

    # 3. Snusbase
    if sns_pass.get("error") == "NO_KEY":
        embed.add_field(name="3️⃣ Snusbase", value="⚙️ Sin key — configura `SNUSBASE_KEY`", inline=False)
    elif sns_pass.get("error") == "UNAUTHORIZED":
        embed.add_field(name="3️⃣ Snusbase", value="❌ Key inválida", inline=False)
    elif sns_pass.get("error"):
        embed.add_field(name="3️⃣ Snusbase", value=f"❌ `{sns_pass['error']}`", inline=False)
    elif sns_pass.get("size", 0) > 0:
        embed.add_field(name="3️⃣ Snusbase", value=f"🚨 Encontrada en **{sns_pass['size']:,}** combo(s)", inline=False)
    else:
        embed.add_field(name="3️⃣ Snusbase", value="✅ No encontrada", inline=False)

    # 4. DeHashed
    if dh_pass.get("error") == "NO_KEY":
        embed.add_field(name="4️⃣ DeHashed", value="⚙️ Sin key — configura `DEHASHED_EMAIL` + `DEHASHED_KEY`", inline=False)
    elif dh_pass.get("error") == "UNAUTHORIZED":
        embed.add_field(name="4️⃣ DeHashed", value="❌ Credenciales inválidas", inline=False)
    elif dh_pass.get("error"):
        embed.add_field(name="4️⃣ DeHashed", value=f"❌ `{dh_pass['error']}`", inline=False)
    elif dh_pass.get("total", 0) > 0:
        total   = dh_pass["total"]
        entries = dh_pass.get("entries", [])
        emails_found = list({e.get("email","") for e in entries if e.get("email")})[:3]
        val = f"🚨 **{total:,} registro(s)**"
        if emails_found:
            val += "\nEmails asociados: " + " · ".join(f"`{mask_email(em)}`" for em in emails_found)
        embed.add_field(name="4️⃣ DeHashed", value=val, inline=False)
    else:
        embed.add_field(name="4️⃣ DeHashed", value="✅ No encontrada", inline=False)

    # 5. BreachDirectory
    if bd_pass.get("error") == "NO_KEY":
        embed.add_field(name="5️⃣ BreachDirectory", value="⚙️ Sin key — configura `BREACHDIRECTORY_KEY`", inline=False)
    elif bd_pass.get("error") == "UNAUTHORIZED":
        embed.add_field(name="5️⃣ BreachDirectory", value="❌ Key inválida", inline=False)
    elif bd_pass.get("error") == "RATE_LIMIT":
        embed.add_field(name="5️⃣ BreachDirectory", value="⏳ Límite mensual alcanzado (10/mes)", inline=False)
    elif bd_pass.get("error"):
        embed.add_field(name="5️⃣ BreachDirectory", value=f"❌ `{bd_pass['error']}`", inline=False)
    elif bd_pass.get("found", 0) > 0:
        found   = bd_pass["found"]
        sources = bd_pass.get("sources", [])
        lines   = [f"🚨 **{found} registro(s)**"]
        for src in sources[:3]:
            name = src.get("name", "?")
            pwd  = src.get("password", "")
            lines.append(f"• `{name}`" + (f" | `{pwd}`" if pwd else ""))
        embed.add_field(name="5️⃣ BreachDirectory", value="\n".join(lines), inline=False)
    else:
        embed.add_field(name="5️⃣ BreachDirectory", value="✅ No encontrada", inline=False)

    # Recomendación final
    if hits > 0:
        embed.add_field(
            name="🚨 Acción recomendada",
            value=(
                "Esta contraseña está comprometida en filtraciones conocidas.\n"
                "**1.** Cámbiala inmediatamente en todos los servicios donde la uses\n"
                "**2.** Activa **2FA/MFA** en esas cuentas\n"
                "**3.** Usa un gestor de contraseñas (Bitwarden, 1Password)"
            ),
            inline=False
        )
    else:
        embed.add_field(
            name="✅ Contraseña no comprometida",
            value="No encontrada en filtraciones conocidas. Recuerda usar contraseñas únicas por servicio.",
            inline=False
        )

    embed.set_footer(text="🔒 k-anonymity SHA-1 + SHA3 · la contraseña NUNCA salió de tu equipo")
    await thinking.edit(content="", embed=embed)


@bot.command(name="email", aliases=["e", "scan"])
@commands.cooldown(1, 10, commands.BucketType.user)
async def cmd_email(ctx, email: str = None):
    if not email:
        await ctx.send("❌ Uso: `!clm email <email>`"); return
    if not is_valid_email(email):
        await ctx.send("❌ Formato de email inválido."); return

    log.info(f"[CMD:email] {mask_email(email)} solicitado por {ctx.author} ({ctx.author.id})")
    thinking = await ctx.send(f"🔍 Escaneando `{mask_email(email)}` en 7 fuentes simultáneas…")

    (hibp_res, xon_res, lc_res, bd_res,
     dh_res, sns_res, bs_res) = await asyncio.gather(
        check_hibp_email(email),
        check_xposedornot(email),
        check_leakcheck(email),
        check_breachdirectory(email),
        check_dehashed(email),
        check_snusbase_email(email),
        check_breachsense(email),
    )

    hibp_txt, hibp_hit = fmt_hibp(hibp_res)
    xon_txt,  xon_hit  = fmt_xon(xon_res)
    lc_txt,   lc_hit   = fmt_leakcheck(lc_res)
    bd_txt,   bd_hit   = fmt_breachdirectory(bd_res)
    dh_txt,   dh_hit   = fmt_dehashed(dh_res)
    sns_txt,  sns_hit  = fmt_snusbase(sns_res)
    bs_txt,   bs_hit   = fmt_breachsense(bs_res)

    any_hit = any([hibp_hit, xon_hit, lc_hit, bd_hit, dh_hit, sns_hit, bs_hit])
    hits    = sum([hibp_hit, xon_hit, lc_hit, bd_hit, dh_hit, sns_hit, bs_hit])
    total   = 7
    color   = CRIT_COLOR if hits >= 3 else (DANGER_COLOR if any_hit else SAFE_COLOR)

    embed = discord.Embed(
        title="📧 Escaneo Multi-Fuente",
        description=(
            f"**Email:** `{mask_email(email)}`\n"
            f"**Resultado:** {'🚨 COMPROMETIDO' if any_hit else '✅ LIMPIO'} "
            f"(**{hits}/{total}** fuentes positivas)"
        ),
        color=color,
        timestamp=datetime.utcnow()
    )
    embed.add_field(name="1️⃣ HaveIBeenPwned",  value=hibp_txt, inline=False)
    embed.add_field(name="2️⃣ XposedOrNot",     value=xon_txt,  inline=False)
    embed.add_field(name="3️⃣ LeakCheck",        value=lc_txt,   inline=False)
    embed.add_field(name="4️⃣ BreachDirectory",  value=bd_txt,   inline=False)
    embed.add_field(name="5️⃣ DeHashed",         value=dh_txt,   inline=False)
    embed.add_field(name="6️⃣ Snusbase",         value=sns_txt,  inline=False)
    embed.add_field(name="7️⃣ BreachSense",      value=bs_txt,   inline=False)

    # Datos expuestos (HIBP)
    if isinstance(hibp_res.get("breaches"), list) and hibp_res["breaches"]:
        all_data = set()
        for b in hibp_res["breaches"]:
            all_data.update(b.get("DataClasses", []))
        if all_data:
            embed.add_field(
                name="📂 Datos expuestos (HIBP)",
                value=", ".join(sorted(all_data)[:10]),
                inline=False
            )

    embed.set_footer(text="CLM v4 — 7 fuentes · !clm report <dominio>")
    await thinking.edit(content="", embed=embed)


@bot.command(name="domain", aliases=["d"])
@commands.cooldown(1, 15, commands.BucketType.user)
async def cmd_domain(ctx, domain: str = None):
    if not domain:
        await ctx.send("❌ Uso: `!clm domain <dominio.com>`"); return
    if not is_valid_domain(domain):
        await ctx.send("❌ Dominio inválido."); return

    log.info(f"[CMD:domain] {domain} solicitado por {ctx.author} ({ctx.author.id})")
    thinking = await ctx.send(f"🔍 Analizando `{domain}`…")
    breaches = await check_hibp_domain(domain)
    num      = len(breaches) if isinstance(breaches, list) else 0

    embed = discord.Embed(
        title=f"🌐 Análisis de Dominio — {domain}",
        color=CRIT_COLOR if num > 0 else SAFE_COLOR,
        timestamp=datetime.utcnow()
    )

    if breaches is None:
        embed.add_field(name="Estado", value="❌ Error de conexión con HIBP", inline=False)
    elif num == 0:
        embed.add_field(name="Estado", value=f"✅ Sin filtraciones para `{domain}`", inline=False)
    else:
        lines = []
        for b in sorted(breaches, key=lambda x: x.get("BreachDate",""), reverse=True)[:6]:
            lines.append(f"• **{b.get('Name')}** ({b.get('BreachDate','?')}) — `{b.get('PwnCount',0):,}` cuentas")
        embed.add_field(name=f"🚨 {num} filtración(es)", value="\n".join(lines), inline=False)

    embed.set_footer(text=f"!clm report {domain} para informe ejecutivo")
    await thinking.edit(content="", embed=embed)


@bot.command(name="report", aliases=["r"])
@commands.cooldown(1, 30, commands.BucketType.user)
async def cmd_report(ctx, domain: str = None):
    if not domain:
        await ctx.send("❌ Uso: `!clm report <dominio.com>`"); return
    if not is_valid_domain(domain):
        await ctx.send("❌ Dominio inválido."); return

    log.info(f"[CMD:report] {domain} solicitado por {ctx.author} ({ctx.author.id})")
    thinking = await ctx.send(f"📊 Generando informe para `{domain}`…")
    breaches    = await check_hibp_domain(domain)
    blist       = breaches if isinstance(breaches, list) else []
    total_accts = sum(b.get("PwnCount", 0) for b in blist)
    num         = len(blist)

    if num == 0:                                       risk_level, rc = "✅ BAJO",     SAFE_COLOR
    elif num <= 2 or total_accts < 50_000:             risk_level, rc = "⚠️ MEDIO",   WARN_COLOR
    elif num <= 5 or total_accts < 500_000:            risk_level, rc = "🔶 ALTO",    DANGER_COLOR
    else:                                              risk_level, rc = "🚨 CRÍTICO", CRIT_COLOR

    embed = discord.Embed(
        title="📊 Informe Ejecutivo de Seguridad",
        description=f"**Dominio:** `{domain}` | **Fecha:** {datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC",
        color=rc,
        timestamp=datetime.utcnow()
    )
    embed.add_field(name="📁 Filtraciones", value=f"```{num}```",            inline=True)
    embed.add_field(name="👥 Cuentas",      value=f"```{total_accts:,}```",  inline=True)
    embed.add_field(name="🎯 Riesgo",       value=risk_level,                inline=True)

    if blist:
        sorted_b = sorted(blist, key=lambda x: x.get("BreachDate",""), reverse=True)
        lines    = []
        for b in sorted_b[:5]:
            s = "🔴" if b.get("IsSensitive") else "🔵"
            lines.append(f"{s} **{b.get('Name')}** — {b.get('BreachDate','?')} · `{b.get('PwnCount',0):,}` cuentas")
        embed.add_field(name="🕒 Cronología (más recientes)", value="\n".join(lines), inline=False)

        all_data = set()
        for b in blist:
            all_data.update(b.get("DataClasses", []))
        if all_data:
            high     = {"Passwords","Credit cards","Bank account numbers","Social security numbers","Health records"}
            crit     = sorted(all_data & high)
            rest     = sorted(all_data - high)
            data_str = ""
            if crit: data_str += "🔴 **Críticos:** " + ", ".join(crit) + "\n"
            if rest: data_str += "🔵 **Otros:** "    + ", ".join(rest[:8])
            embed.add_field(name="📂 Datos expuestos", value=data_str, inline=False)

    recs = (
        ["🔁 Forzar reset de contraseñas en usuarios afectados",
         "🔐 Activar MFA en todos los accesos corporativos",
         "📣 Notificar a usuarios según RGPD (máx 72h)"]
        if num > 0 else
        ["✅ Mantener monitoreo periódico",
         "🔑 Política de contraseñas robusta + MFA obligatorio"]
    )
    embed.add_field(name="📋 Recomendaciones", value="\n".join(recs), inline=False)
    embed.set_footer(text="CLM v4 · leyenda: 🔵 activa 🔴 sensible")
    await thinking.edit(content="", embed=embed)


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("[!] ERROR: DISCORD_TOKEN no configurado en .env")
        exit(1)
    print("[*] Iniciando Credential Leak Monitor v4...")
    bot.run(DISCORD_TOKEN)
