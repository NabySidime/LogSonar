"""
main.py — Point d'entrée LogSonar
Lecture Docker avec retry exponentiel + re-détection des nouveaux conteneurs.
Auth JWT + OTP + RBAC (superuser/user)
"""
import asyncio
import re
import os
import json
import secrets
import hashlib
import time as _time_module
import unicodedata
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from urllib.parse import unquote_plus, unquote

import docker
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Query, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
try:
    import jwt
    from jwt import ExpiredSignatureError as JWTError
except ImportError:
    jwt = None
    JWTError = Exception

# ---------------------------------------------------------------------------
# PASSLIB (hash mots de passe)
# ---------------------------------------------------------------------------
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except ImportError:
    pwd_context = None

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
from db import (
    init_db, close_db,
    save_critical_event, get_setting, update_setting,
    get_events_for_date, get_stats_today, get_dashboard_data,
    get_user_by_username, get_user_by_id, create_user, count_users,
    has_superuser, delete_user, store_otp, verify_otp,
    _OTP_STORE, get_db,
)
from mailer import send_critical_alert, send_otp_email
from reporter import generate_daily_report

# ---------------------------------------------------------------------------
# CONFIG JWT
# ---------------------------------------------------------------------------
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h

def _get_or_create_jwt_secret() -> str:
    """
    Clé JWT persistante :
    1. Variable d'environnement LOGSONAR_JWT_SECRET (priorité)
    2. Fichier data/.jwt_secret (persiste entre les redémarrages)
    3. Génération aléatoire (dernier recours)
    """
    env_key = os.environ.get("LOGSONAR_JWT_SECRET")
    if env_key:
        return env_key
    key_path = "data/.jwt_secret"
    if os.path.exists(key_path):
        with open(key_path, "r") as f:
            return f.read().strip()
    key = secrets.token_urlsafe(32)
    os.makedirs("data", exist_ok=True)
    with open(key_path, "w") as f:
        f.write(key)
    os.chmod(key_path, 0o600)
    print("LogSonar: Clé JWT générée dans data/.jwt_secret")
    return key

SECRET_KEY = _get_or_create_jwt_secret()

security = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# MOTEUR D'ANALYSE — v3
# ---------------------------------------------------------------------------

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*\[(?P<timestamp>[^\]]+)\]\s'
    r'"(?P<method>[A-Z]+)\s(?P<path>.+?)\sHTTP/[^"]+"\s(?P<status>\d{3})'
    r'(?:\s+(?P<size>\d+))?(?:\s+"(?P<referer>[^"]*?)")?(?:\s+"(?P<ua>[^"]*?)")?'
)

APP_LOG_PATTERN = re.compile(
    r'(?:ERROR|WARNING|CRITICAL|WARN).*?(?P<msg>.+)',
    re.IGNORECASE
)

ATTACK_SIGNATURES: dict[str, str] = {
    "Tentative d'Injection SQL": (
        r"(?i)("
        r"union[\s\+%20\*/]+select"
        r"|or[\s%20\*/]+1[\s%20]*=[\s%20]*1"
        r"|and[\s%20\*/]+1[\s%20]*=[\s%20]*1"
        r"|drop[\s%20]+(?:table|database|index)"
        r"|select[\s%20]+.{0,50}[\s%20]+from"
        r"|insert[\s%20]+into"
        r"|delete[\s%20]+from"
        r"|update[\s%20]+.{0,50}[\s%20]+set"
        r"|'[\s]*(?:--|#|/\*)"
        r"|;[\s]*(?:drop|select|insert|delete|update|exec)"
        r"|xp_cmdshell|sp_executesql"
        r"|information_schema|pg_sleep|sleep\s*\("
        r"|benchmark\s*\(|waitfor[\s%20]+delay"
        r"|0x[0-9a-f]{4,}"
        r"|char\s*\(\s*\d+\s*\)"
        r"|convert\s*\(|cast\s*\(.*as"
        r"|load_file\s*\(|into\s+outfile"
        r")"
    ),
    "Tentative de Cross-Site Scripting (XSS)": (
        r"(?i)("
        r"<script[\s\/>]"
        r"|<\/script>"
        r"|javascript\s*:"
        r"|vbscript\s*:"
        r"|on(?:error|load|click|mouseover|focus|keyup|submit|change|blur|input"
        r"|mouseenter|mouseleave|dblclick|drag|drop|paste|copy|cut|reset"
        r"|invalid|search|select|contextmenu|wheel|touchstart|touchend)\s*="
        r"|alert\s*\(|prompt\s*\(|confirm\s*\("
        r"|document\.(?:cookie|write|location|domain|referrer)"
        r"|window\.(?:location|open|eval)"
        r"|<iframe[\s\/>]|<frame[\s\/>]|<embed[\s\/>]|<object[\s\/>]"
        r"|<svg[\s\/>].*?(?:on\w+|href)"
        r"|<img[^>]+(?:onerror|onload)\s*="
        r"|expression\s*\("
        r"|&#(?:x[0-9a-f]+|\d+);"
        r"|data:text/html"
        r"|<math[\s\/>]"
        r")"
    ),
    "Tentative de Path Traversal": (
        r"(?i)("
        r"\.\.[\\/]"
        r"|%2e%2e[\\/]"
        r"|%252e%252e"
        r"|\.\.%2f|\.\.%5c"
        r"|%c0%ae%c0%ae"
        r"|%c1%9c"
        r"|\.\.[/\\](?:etc|proc|var|tmp|usr|home|root)"
        r"|/etc/(?:passwd|shadow|hosts|crontab|sudoers)"
        r"|/proc/(?:self|version|cmdline|environ)"
        r"|C:\\\\(?:Windows|Users|Program)"
        r")"
    ),
    "Tentative d'Injection de Commande": (
        r"(?i)("
        r"[;&|`]\s*(?:ls|cat|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|php)"
        r"|\$\((?:ls|cat|id|whoami|uname|curl|wget)"
        r"|\|\s*(?:bash|sh|cmd|powershell|python|perl|ruby|nc|ncat)"
        r"|`[^`]*`"
        r"|;\s*(?:sleep|ping|nslookup|dig|curl|wget)\s"
        r"|(?:&&|\|\|)\s*(?:ls|cat|id|curl|wget|ping)"
        r"|\bexec\s*\("
        r"|system\s*\(|passthru\s*\(|shell_exec\s*\("
        r"|__import__\s*\(|eval\s*\(|exec\s*\("
        r"|\bRCE\b|remote.?code.?exec"
        r")"
    ),
    "Tentative Log4Shell (Log4J)": (
        r"(?i)("
        r"\$\{jndi:"
        r"|\$\{(?:lower|upper|:-|:-).*jndi"
        r"|\$\{(?:\$\{lower:j\}|\$\{::-j\})"
        r"|jndi:(?:ldap|rmi|dns|iiop|corba|nds|ldaps)://"
        r"|\$\{(?:env|sys|java|main|marker|date|ctx):.*\}"
        r")"
    ),
    "Tentative de SSRF (Falsification de Requête Côté Serveur)": (
        r"(?i)("
        r"(?:url|redirect|uri|path|dest|destination|continue|return|returnTo"
        r"|next|data|reference|site|html|val|validate|domain|callback|return_url"
        r"|feed|host|port|to|out|view|dir|show|navigation|open)="
        r"(?:https?://(?:169\.254\.169\.254|127\.|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)|file://)"
        r"|169\.254\.169\.254"
        r"|metadata\.google\.internal"
        r"|100\.100\.100\.200"
        r"|file:///(?:etc|proc|var|tmp)"
        r"|dict://|gopher://|ftp://127"
        r"|@127\.\d+\.\d+\.\d+"
        r")"
    ),
    "Tentative XXE (Injection d'Entité XML)": (
        r"(?i)("
        r"<!(?:DOCTYPE|ENTITY)"
        r'''|SYSTEM\s+["'](?:file|http|ftp|php|expect|data):'''
        r'''|PUBLIC\s+["'][^"']*["']\s+["']'''
        r"|\&(?:xxe|file|data|system);"
        r"|%(?:xxe|file|data|payload);"
        r")"
    ),
    "Tentative de Redirection Ouverte": (
        r"(?i)(?:redirect|return|next|url|goto|dest|destination|continue|returnTo|r|u|link|ref)="
        r"(?:https?://(?!(?:tikipay|localhost|127\.0\.0\.1)))"
    ),
    "Scan de vulnérabilités (Bot)": (
        r"(?i)("
        r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster"
        r"|nuclei|acunetix|burpsuite|zgrab|wfuzz|ffuf"
        r"|hydra|metasploit|openvas|nessus|w3af|skipfish"
        r"|appscan|webinspect|qualysguard|vega|zaproxy|zap"
        r"|python-requests|go-http-client/1\.1$"
        r"|curl/[0-9]|wget/[0-9]"
        r"|masscan|zgrab|shodan|censys"
        r")"
    ),
    "Recherche de fichiers sensibles": (
        r"(?i)("
        r"\.env(?:\.|$|/)"
        r"|\.env\.(?:local|production|prod|dev|development|docker|bak|old|backup)"
        r"|wp-(?:admin|login|config|includes|content)"
        r"|/etc/(?:passwd|shadow|hosts|crontab|sudoers|group|gshadow)"
        r"|phpmyadmin|pma/|myadmin"
        r"|\.git/(?:HEAD|config|logs|index|refs|objects|packed)"
        r"|\.htaccess|\.htpasswd"
        r"|backup\.|\.sql$|\.sql\.gz|\.dump$|\.bak$|\.old$|\.orig$"
        r"|web\.config|app\.config|appsettings\.json"
        r"|/proc/self|/proc/version"
        r"|id_rsa|authorized_keys|known_hosts"
        r"|\.aws/credentials|\.ssh/"
        r"|config\.php|config\.yml|config\.yaml|settings\.py"
        r"|database\.yml|secrets\.yml|credentials\.yml"
        r"|/manager/html|/admin/console|/solr/|/jenkins/"
        r"|actuator/|/swagger-ui|/api-docs$"
        r")"
    ),
    "Alerte interne de l'application": (
        r"(?i)("
        r"SuspiciousOperation|BadRequest|DisallowedHost"
        r"|LOGSONAR_POST_ATTACK"
        r"|PermissionDenied|IntegrityError"
        r"|ImproperlyConfigured"
        r"|OperationalError.*denied"
        r"|CSRF.*(?:failed|invalid|missing|mismatch|verification)"
        r"|Invalid HTTP_HOST header"
        r")"
    ),
    "Tentative de falsification (CSRF)": (
        r"(?i)(csrf[\s_-]*(?:failed|invalid|missing|mismatch|verification|token))"
    ),
    "Tentative d'Injection de Template (SSTI)": (
        r"(?i)("
        r"\{\{.*\}\}"
        r"|\$\{.*\}"
        r"|<%.*%>"
        r"|\{\%.*\%\}"
        r"|\#\{.*\}"
        r"|\{\{7\*7\}\}|\{\{config\}\}"
        r"|\$\{7\*7\}|\$\{T\(java"
        r")"
    ),
    "Tentative de Désérialisation Malveillante": (
        r"(?i)("
        r"rO0AB"
        r"|O:[0-9]+:\"[a-zA-Z]"
        r"|__reduce__|__import__|pickle"
        r"|YTozO|TzM6|YTo"
        r"|aced0005"
        r")"
    ),
}

_BRUTE_THRESHOLD = 10
_BRUTE_WINDOW    = 60
_FLOOD_THRESHOLD = 30
_FLOOD_WINDOW    = 30
_ip_windows: dict = defaultdict(list)

_ANSI_RE      = re.compile(r'\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])')
_LOGSONAR_TAG = "logsonar"
_REPORT_DIR   = Path("data/reports")


# ===========================================================================
# AUTHENTIFICATION — JWT + OTP + RBAC
# ===========================================================================

def _hash_password(password: str) -> str:
    if pwd_context:
        return pwd_context.hash(password)
    return hashlib.sha256(password.encode()).hexdigest()


def _verify_password(plain: str, hashed: str) -> bool:
    if pwd_context:
        return pwd_context.verify(plain, hashed)
    return hashlib.sha256(plain.encode()).hexdigest() == hashed


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    if jwt is None:
        raise RuntimeError("PyJWT n'est pas installé. pip install PyJWT")
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if jwt is None:
        raise HTTPException(status_code=500, detail="JWT non configuré")

    token = credentials.credentials if credentials else None
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token invalide")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        # InvalidSignatureError ou autre erreur JWT inattendue
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await get_user_by_id(int(user_id))
    if user is None:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return user


async def require_superuser(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "superuser":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé au superuser",
        )
    return user


# ===========================================================================
# MOTEUR D'ANALYSE
# ===========================================================================

def _normalize_payload(raw: str) -> str:
    seen, s = set(), raw
    for _ in range(5):
        try:
            decoded = unquote_plus(unquote(s))
        except Exception:
            break
        if decoded in seen or decoded == s:
            break
        seen.add(decoded)
        s = decoded
    try:
        s = unicodedata.normalize("NFKC", s)
    except Exception:
        pass
    s = s.replace("\x00", "").replace("%00", "")
    s = re.sub(r'/\*.*?\*/', ' ', s)
    return s


def _check_behavioral(ip: str, path: str) -> tuple[bool, str | None]:
    now = _time_module.monotonic()
    key_brute = f"{ip}::{path}"
    key_flood  = f"{ip}::*"

    _ip_windows[key_brute] = [t for t in _ip_windows[key_brute] if now - t < _BRUTE_WINDOW]
    _ip_windows[key_flood]  = [t for t in _ip_windows[key_flood]  if now - t < _FLOOD_WINDOW]
    _ip_windows[key_brute].append(now)
    _ip_windows[key_flood].append(now)

    if len(_ip_windows[key_brute]) >= _BRUTE_THRESHOLD:
        cnt = len(_ip_windows[key_brute])
        return True, f"Bruteforce ({cnt} req/{_BRUTE_WINDOW}s sur {path})"
    if len(_ip_windows[key_flood]) >= _FLOOD_THRESHOLD:
        cnt = len(_ip_windows[key_flood])
        return True, f"Flood ({cnt} req/{_FLOOD_WINDOW}s depuis {ip})"
    return False, None


_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')
_EMAIL_RE    = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _validate_settings(form: dict) -> list[str]:
    errors = []
    email = form.get("alert_email", "")
    if email and not _EMAIL_RE.match(email):
        errors.append("alert_email invalide")
    smtp_host = form.get("smtp_host", "")
    if smtp_host and not _HOSTNAME_RE.match(smtp_host):
        errors.append("smtp_host invalide (caractères non autorisés)")
    smtp_port = form.get("smtp_port", "")
    if smtp_port:
        try:
            port = int(smtp_port)
            if not (1 <= port <= 65535):
                errors.append("smtp_port hors plage (1-65535)")
        except ValueError:
            errors.append("smtp_port doit être un entier")
    smtp_user = form.get("smtp_user", "")
    if smtp_user and not _EMAIL_RE.match(smtp_user):
        errors.append("smtp_user invalide (doit être une adresse email)")
    return errors


def _safe_report_path(filename: str) -> Path | None:
    if not re.fullmatch(r'rapport_\d{4}-\d{2}-\d{2}\.html', filename):
        return None
    resolved = (_REPORT_DIR / filename).resolve()
    try:
        resolved.relative_to(_REPORT_DIR.resolve())
    except ValueError:
        return None
    return resolved


def analyze_log(raw_log: str) -> dict:
    result = {
        "is_web": False, "ip": "N/A", "method": "", "path": "",
        "status": "", "timestamp": "", "is_attack": False,
        "attack_type": None, "raw": raw_log, "ua": "", "referer": "",
    }
    clean = _ANSI_RE.sub("", raw_log)
    match = LOG_PATTERN.search(clean)

    if not match:
        normalized_raw = _normalize_payload(clean)
        for name, pattern in ATTACK_SIGNATURES.items():
            if re.search(pattern, normalized_raw):
                result.update({"is_attack": True, "attack_type": name})
                break
        return result

    raw_ts = match.group("timestamp").split(" ")[0]
    try:
        ts = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = raw_ts

    ip      = match.group("ip")
    method  = match.group("method")
    path_qs = match.group("path")
    status  = match.group("status")
    ua      = match.group("ua")      or ""
    referer = match.group("referer") or ""
    path_only = path_qs.split("?")[0]

    result.update({
        "is_web": True, "ip": ip, "method": method,
        "path": path_only, "status": status, "timestamp": ts,
        "ua": ua, "referer": referer,
    })

    norm_path    = _normalize_payload(path_qs)
    norm_ua      = _normalize_payload(ua)
    norm_referer = _normalize_payload(referer)
    norm_raw     = _normalize_payload(clean)

    surfaces = [path_only, norm_path, ua, norm_ua, referer, norm_referer, norm_raw]
    for name, pattern in ATTACK_SIGNATURES.items():
        if any(re.search(pattern, s) for s in surfaces if s):
            result.update({"is_attack": True, "attack_type": name})
            return result

    is_behavioral, btype = _check_behavioral(ip, path_only)
    if is_behavioral:
        result.update({"is_attack": True, "attack_type": btype})

    return result


# ---------------------------------------------------------------------------
# DOCKER
# ---------------------------------------------------------------------------
_DOCKER_URLS = (
    "unix:///var/run/docker.sock",
    "tcp://host.docker.internal:2375",
)
_RETRY_DELAYS = (1, 2, 4, 8, 16, 30)


def _connect_docker() -> docker.DockerClient:
    for url in _DOCKER_URLS:
        try:
            client = docker.DockerClient(base_url=url)
            client.ping()
            print(f"LogSonar: Connecté à Docker via {url}")
            return client
        except Exception:
            continue
    raise ConnectionError("Impossible de joindre le démon Docker.")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)


def _is_logsonar_container(name: str) -> bool:
    return _LOGSONAR_TAG in name.lower()


def _read_one_container(container_name: str, client: docker.DockerClient, queue: asyncio.Queue) -> None:
    try:
        container = client.containers.get(container_name)
        print(f"LogSonar: Écoute {container_name}")
        for line in container.logs(stream=True, follow=True, tail=50):
            clean = _strip_ansi(line.decode("utf-8", errors="replace").strip())
            if not clean:
                continue
            data = analyze_log(clean)
            data["container"] = container_name
            queue.put_nowait(data)
    except docker.errors.NotFound:
        print(f"LogSonar: Conteneur {container_name} introuvable ou arrêté.")
    except Exception as e:
        print(f"LogSonar: Erreur lecture {container_name}: {type(e).__name__}: {e}")


async def docker_supervisor(queue: asyncio.Queue) -> None:
    retry_idx   = 0
    client      = None
    watched: set[str] = set()
    reader_tasks: dict[str, asyncio.Task] = {}

    while True:
        try:
            client = await asyncio.to_thread(_connect_docker)
            retry_idx = 0
        except ConnectionError as e:
            delay = _RETRY_DELAYS[min(retry_idx, len(_RETRY_DELAYS) - 1)]
            print(f"LogSonar: Docker indisponible ({e}). Nouvel essai dans {delay}s...")
            retry_idx += 1
            await asyncio.sleep(delay)
            continue

        try:
            while True:
                try:
                    active = {
                        c.name for c in client.containers.list()
                        if not _is_logsonar_container(c.name)
                    }
                except Exception as e:
                    print(f"LogSonar: Perte de connexion Docker ({e}). Reconnexion...")
                    break

                new_containers = active - watched
                for name in new_containers:
                    print(f"LogSonar: Nouveau conteneur détecté → {name}")
                    task = asyncio.create_task(
                        asyncio.to_thread(_read_one_container, name, client, queue)
                    )
                    reader_tasks[name] = task
                    watched.add(name)

                stopped = watched - active
                for name in stopped:
                    print(f"LogSonar: Conteneur arrêté → {name}")
                    task = reader_tasks.pop(name, None)
                    if task and not task.done():
                        task.cancel()
                    watched.discard(name)

                await asyncio.sleep(30)

        except asyncio.CancelledError:
            print("LogSonar: Arrêt du superviseur Docker.")
            for task in reader_tasks.values():
                task.cancel()
            raise


# ---------------------------------------------------------------------------
# RATE-LIMITING ALERTES EMAIL
# ---------------------------------------------------------------------------
_alert_cooldowns: dict[str, float] = {}
_ALERT_COOLDOWN_SECONDS = 60


def _is_successful_attack(status: str) -> bool:
    try:
        code = int(status)
        return 200 <= code <= 299
    except (ValueError, TypeError):
        return False


def _should_send_alert(ip: str, attack_type: str, status: str) -> bool:
    if not _is_successful_attack(status):
        return False
    key = f"{ip}::{attack_type}"
    now = _time_module.monotonic()
    if key in _alert_cooldowns and now - _alert_cooldowns[key] < _ALERT_COOLDOWN_SECONDS:
        return False
    _alert_cooldowns[key] = now
    return True


# ---------------------------------------------------------------------------
# LIFESPAN
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("LogSonar: Démarrage...")
    await init_db()
    scheduler   = asyncio.create_task(daily_report_scheduler())
    print("LogSonar: Planificateur de rapports démarré.")
    yield
    print("LogSonar: Arrêt en cours...")
    scheduler.cancel()
    await close_db()
    print("LogSonar: Arrêt complet.")

app = FastAPI(title="LogSonar", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ###########################################################################
# ROUTES AUTHENTIFICATION
# ###########################################################################

@app.get("/api/auth/check-setup")
async def api_check_setup():
    """Vérifie si un superuser existe déjà."""
    needs_setup = not await has_superuser()
    return JSONResponse(content={"needs_setup": needs_setup})


@app.post("/api/auth/setup")
async def api_setup(request: Request):
    """Crée le premier superuser (uniquement si aucun n'existe)."""
    if await has_superuser():
        raise HTTPException(status_code=403, detail="Un superuser existe déjà")

    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    email = form.get("email", "").strip()

    if not username or not password or not email:
        return JSONResponse(status_code=422, content={"status": "error", "message": "Tous les champs sont requis"})
    if len(password) < 8:
        return JSONResponse(status_code=422, content={"status": "error", "message": "Le mot de passe doit faire au moins 8 caractères"})

    try:
        password_hash = _hash_password(password)
        new_user = await create_user(username, password_hash, email, "superuser")
        return JSONResponse(content={"status": "success", "user_id": new_user["id"]})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@app.post("/api/auth/login")
async def api_login(request: Request):
    """Étape 1 : Authentification par username/password. Retourne OTP requis."""
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username et password requis")

    user = await get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    if not _verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    # Générer un code OTP numérique à 6 chiffres
    otp_code = ''.join(secrets.choice('0123456789') for _ in range(6))
    store_otp(username, otp_code, ttl_seconds=300)

    # Tentative d'envoi par email
    email_sent = False
    smtp_host = await get_setting('smtp_host')
    smtp_user = await get_setting('smtp_user')
    smtp_password = await get_setting('smtp_password')

    if smtp_host and smtp_user and smtp_password and smtp_password != "********":
        try:
            await send_otp_email(user["email"], otp_code, username)
            email_sent = True
            print(f"LogSonar: OTP envoyé par email à {user['email']}")
        except Exception as e:
            print(f"LogSonar: Erreur envoi OTP email -> {e}")

    # Fallback console si email non envoyé
    if not email_sent:
        print("=" * 60)
        print(f"LogSonar: SMTP non configuré — CODE OTP pour {username}")
        print(f"  Code: {otp_code}")
        print(f"  Email: {user['email']}")
        print("=" * 60)

    return JSONResponse(content={
        "status": "otp_required",
        "username": username,
        "email_sent": email_sent,
    })


@app.post("/api/auth/verify-otp")
async def api_verify_otp(request: Request):
    """Étape 2 : Vérification OTP. Retourne le JWT d'accès."""
    form = await request.form()
    username = form.get("username", "").strip()
    code = form.get("code", "").strip()  # Le form login.html envoie "code", pas "otp"

    if not username or not code:
        raise HTTPException(status_code=400, detail="Username et code OTP requis")

    if not verify_otp(username, code):
        raise HTTPException(status_code=401, detail="OTP invalide ou expiré")

    user = await get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")

    access_token = create_access_token(data={"sub": str(user["id"]), "role": user["role"]})
    return JSONResponse(content={
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "role": user["role"],
    })


@app.get("/api/auth/me")
async def api_auth_me(user: dict = Depends(get_current_user)):
    """Retourne les infos de l'utilisateur connecté."""
    return JSONResponse(content={
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    })


@app.post("/api/auth/logout")
async def api_auth_logout():
    """Déconnexion côté serveur."""
    return JSONResponse(content={"status": "logged_out"})


@app.post("/api/auth/create-user")
async def api_create_user(request: Request, current_user: dict = Depends(require_superuser)):
    """Crée un nouvel utilisateur (superuser uniquement)."""
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    email = form.get("email", "").strip()
    role = form.get("role", "user")

    if not username or not password or not email:
        return JSONResponse(status_code=422, content={"status": "error", "message": "Tous les champs sont requis"})
    if len(password) < 8:
        return JSONResponse(status_code=422, content={"status": "error", "message": "Le mot de passe doit faire au moins 8 caractères"})
    if role not in ("user", "superuser"):
        return JSONResponse(status_code=422, content={"status": "error", "message": "Rôle invalide"})

    try:
        password_hash = _hash_password(password)
        new_user = await create_user(username, password_hash, email, role)
        return JSONResponse(content={"status": "success", "user_id": new_user["id"]})
    except ValueError as e:
        return JSONResponse(status_code=422, content={"status": "error", "message": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


# ###########################################################################
# ROUTES USERS
# ###########################################################################

@app.get("/api/users")
async def api_list_users(current_user: dict = Depends(require_superuser)):
    """Liste tous les utilisateurs actifs."""
    import aiosqlite
    db = await get_db()
    db.row_factory = aiosqlite.Row
    async with db.execute(
        "SELECT id, username, email, role, created_at FROM users WHERE is_active = 1"
    ) as cursor:
        rows = await cursor.fetchall()
    return JSONResponse(content=[dict(r) for r in rows])


@app.post("/api/users/update")
async def api_update_user(request: Request, current_user: dict = Depends(require_superuser)):
    """Met à jour un utilisateur (email, password)."""
    form = await request.form()
    user_id = form.get("user_id")
    email = form.get("email", "").strip()
    password = form.get("password", "")

    if not user_id:
        return JSONResponse(status_code=422, content={"status": "error", "message": "ID requis"})

    db = await get_db()
    updates = []
    params = []
    if email:
        updates.append("email = ?")
        params.append(email)
    if password and len(password) >= 8:
        updates.append("password_hash = ?")
        params.append(_hash_password(password))

    if not updates:
        return JSONResponse(content={"status": "success"})

    params.append(int(user_id))
    await db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
    await db.commit()
    return JSONResponse(content={"status": "success"})


@app.delete("/api/users/{user_id}")
async def api_delete_user(user_id: int, current_user: dict = Depends(require_superuser)):
    """Supprime (désactive) un utilisateur."""
    if user_id == current_user["id"]:
        return JSONResponse(status_code=422, content={
            "status": "error", "message": "Vous ne pouvez pas supprimer votre propre compte"
        })
    await delete_user(user_id)
    return JSONResponse(content={"status": "success"})


# ###########################################################################
# ROUTES API — SETTINGS
# ###########################################################################

@app.get("/api/settings")
async def api_get_settings(user: dict = Depends(require_superuser)):
    pwd = await get_setting("smtp_password")
    return {
        "alert_email":   await get_setting("alert_email"),
        "smtp_host":     await get_setting("smtp_host"),
        "smtp_port":     await get_setting("smtp_port"),
        "smtp_user":     await get_setting("smtp_user"),
        "smtp_password": "********" if pwd else "",
    }


@app.post("/api/settings")
async def api_save_settings(request: Request, user: dict = Depends(require_superuser)):
    form      = await request.form()
    form_dict = dict(form)
    errors    = _validate_settings(form_dict)
    if errors:
        return JSONResponse(status_code=422, content={"status": "error", "errors": errors})
    await update_setting("alert_email", form_dict.get("alert_email", ""))
    await update_setting("smtp_host",   form_dict.get("smtp_host", ""))
    await update_setting("smtp_port",   form_dict.get("smtp_port", ""))
    await update_setting("smtp_user",   form_dict.get("smtp_user", ""))
    new_pwd = form_dict.get("smtp_password", "")
    if new_pwd and new_pwd != "********":
        await update_setting("smtp_password", new_pwd)
    return JSONResponse(content={"status": "success"})


@app.post("/api/settings/test")
async def api_test_email(user: dict = Depends(require_superuser)):
    test_data = {
        "attack_type": "Test de configuration",
        "ip": "127.0.0.1", "container": "Système",
        "method": "TEST", "path": "/", "status": "200",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "raw": "Si vous lisez ceci, la configuration SMTP de LogSonar est parfaite !",
    }
    await send_critical_alert(test_data)
    return JSONResponse(content={"status": "test_sent"})


# ###########################################################################
# ROUTES API — RAPPORTS
# ###########################################################################

@app.get("/api/reports/generate")
async def api_generate_report(user: dict = Depends(require_superuser)):
    filename = await generate_daily_report()
    if filename:
        return JSONResponse(content={"status": "success", "filename": filename})
    return JSONResponse(content={"status": "no_events"})


@app.get("/api/reports")
async def api_list_reports(user: dict = Depends(get_current_user)):
    if not _REPORT_DIR.exists():
        return []
    files = sorted(
        [f for f in _REPORT_DIR.iterdir() if f.suffix == ".html"],
        key=lambda p: p.name, reverse=True,
    )
    return [{"filename": f.name} for f in files]


@app.get("/api/reports/view/{filename}")
async def api_view_report(filename: str, user: dict = Depends(get_current_user)):
    fp = _safe_report_path(filename)
    if fp is None or not fp.exists():
        return JSONResponse(status_code=404, content={"error": "Rapport non trouvé"})
    return FileResponse(fp, media_type="text/html")


@app.delete("/api/reports/{filename}")
async def api_delete_report(filename: str, user: dict = Depends(require_superuser)):
    fp = _safe_report_path(filename)
    if fp is None or not fp.exists():
        return JSONResponse(status_code=404, content={"error": "Rapport non trouvé"})
    fp.unlink()
    return JSONResponse(content={"status": "deleted"})


# ###########################################################################
# ROUTES API — STATS
# ###########################################################################

@app.get("/api/stats")
async def api_get_stats(user: dict = Depends(get_current_user)):
    today = datetime.now().strftime("%Y-%m-%d")
    return await get_stats_today(today)


@app.get("/api/dashboard")
async def api_get_dashboard(user: dict = Depends(get_current_user)):
    today = datetime.now()
    today_str = today.strftime("%Y-%m-%d")
    since_str = (today - timedelta(days=6)).strftime("%Y-%m-%d")
    return await get_dashboard_data(today_str, since_str)


# ###########################################################################
# ROUTES API — ANALYSE DÉPENDANCES CONTENEURS
# ###########################################################################

async def _get_container_pip_packages(container_name: str) -> list[dict]:
    def _run():
        try:
            client = _connect_docker()
            container = client.containers.get(container_name)
            result = container.exec_run("pip list --format=json", stdout=True, stderr=False)
            if result.exit_code == 0:
                raw = result.output.decode("utf-8", errors="replace").strip()
                return json.loads(raw)
        except Exception as e:
            print(f"LogSonar: Deps scan {container_name}: {e}")
        return []
    return await asyncio.to_thread(_run)


async def _check_pypi_latest(package_name: str) -> str | None:
    import urllib.request
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LogSonar/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data["info"]["version"]
    except Exception:
        return None


@app.get("/api/containers/deps")
async def api_containers_deps(user: dict = Depends(require_superuser)):
    try:
        client = _connect_docker()
        containers = [c for c in client.containers.list() if not _is_logsonar_container(c.name)]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": f"Docker indisponible: {e}"})

    results = []
    for container in containers:
        packages = await _get_container_pip_packages(container.name)
        if not packages:
            results.append({"container": container.name, "status": "no_python", "packages": []})
            continue

        PRIORITY_PACKAGES = {
            "django", "flask", "fastapi", "requests", "urllib3", "pillow",
            "cryptography", "pyjwt", "sqlalchemy", "celery", "redis",
            "gunicorn", "uvicorn", "aiohttp", "boto3", "paramiko",
            "pyyaml", "jinja2", "werkzeug", "setuptools", "pip",
        }
        checked, outdated = [], []
        for pkg in packages:
            name, current = pkg.get("name", ""), pkg.get("version", "")
            if name.lower() not in PRIORITY_PACKAGES:
                checked.append({"name": name, "current": current, "latest": None, "status": "skipped"})
                continue
            latest = await _check_pypi_latest(name)
            status = "unknown" if latest is None else ("up_to_date" if latest == current else "outdated")
            if status == "outdated":
                outdated.append(name)
            checked.append({"name": name, "current": current, "latest": latest, "status": status})

        results.append({
            "container": container.name,
            "status": "scanned",
            "total": len(packages),
            "checked": len([p for p in checked if p["status"] != "skipped"]),
            "outdated": len(outdated),
            "packages": sorted(checked, key=lambda p: (p["status"] != "outdated", p["name"])),
        })
    return results


# ###########################################################################
# PLANIFICATEUR DE RAPPORT
# ###########################################################################

async def daily_report_scheduler():
    while True:
        now = datetime.now()
        if now.hour == 0 and now.minute == 0:
            print("LogSonar: Minuit — génération du rapport quotidien...")
            await generate_daily_report()
            await asyncio.sleep(120)
        else:
            await asyncio.sleep(30)


# ###########################################################################
# WEBSOCKET
# ###########################################################################

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(default="")):
    expected = await get_setting("ws_token")
    if not expected or token != expected:
        await websocket.close(code=4401)
        print(f"LogSonar: WebSocket refusé — token invalide")
        return

    await websocket.accept()
    log_queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
    supervisor_task = asyncio.create_task(docker_supervisor(log_queue))

    try:
        while True:
            log_data = await log_queue.get()
            if log_data.get("is_attack"):
                asyncio.create_task(save_critical_event(log_data))
                if _should_send_alert(log_data.get("ip", ""), log_data.get("attack_type", ""), log_data.get("status", "")):
                    asyncio.create_task(send_critical_alert(log_data))
            try:
                await websocket.send_json(log_data)
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        supervisor_task.cancel()
        try:
            await supervisor_task
        except asyncio.CancelledError:
            pass


# ###########################################################################
# ROUTE API — TOKEN WebSocket
# ###########################################################################

@app.get("/api/ws-token")
async def api_get_ws_token():
    token = await get_setting("ws_token")
    return JSONResponse(content={"token": token})


# ###########################################################################
# INTERFACE — LOGIN PAGE
# ###########################################################################

@app.get("/login", response_class=HTMLResponse)
async def get_login_page():
    with open("static/login.html", "r", encoding="utf-8") as f:
        content = f.read()
    return Response(content=content, media_type="text/html")


# ###########################################################################
# INTERFACE — MAIN APP (protégé par auth)
# ###########################################################################

@app.get("/", response_class=HTMLResponse)
async def get_interface():
    with open("static/index.html", "r", encoding="utf-8") as f:
        content = f.read()
    return Response(
        content=content,
        media_type="text/html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )