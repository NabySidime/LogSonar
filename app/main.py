"""
main.py — Point d'entrée LogSonar
Lecture Docker avec retry exponentiel + re-détection des nouveaux conteneurs.
Auth JWT + OTP + RBAC (superuser/user)

=== CORRECTIFS v2.0 (voir audit) ===
- LogBroadcaster : fan-out WebSocket (fin du partage de logs entre clients/reconnexions)
- Rejeu d'historique (tail) limité au 1er démarrage, marqué historical=True,
  exclu du scoring comportemental et des alertes (fin des rafales de faux positifs)
- Coupe-circuit global anti-rafale sur les emails d'alerte
- Scheduler de rapport quotidien blindé contre les exceptions silencieuses
- Fallback Docker TCP non authentifié désactivé par défaut
- Plus aucune valeur spécifique à un client (whitelist IP, domaines de redirection,
  logs à ignorer) codée en dur : tout passe par des variables d'environnement
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
from typing import Optional, Dict, List, Tuple

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
    purge_old_events,
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
# CONFIGURATION SPÉCIFIQUE AU DÉPLOIEMENT
# ---------------------------------------------------------------------------
# CORRECTIF : plus aucune valeur propre à un client (IP, domaine, motif de log à
# ignorer) codée en dur dans le moteur de détection. Tout se règle par variables
# d'environnement, propres à chaque installation. Voir .env.example.
def _parse_csv_env(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]

WHITELIST_IPS: set[str] = set(_parse_csv_env("LOGSONAR_WHITELIST_IPS"))
ALLOWED_REDIRECT_DOMAINS: list[str] = [
    d.lower() for d in _parse_csv_env("LOGSONAR_ALLOWED_REDIRECT_DOMAINS", "localhost,127.0.0.1")
]
IGNORE_LOG_SUBSTRINGS: list[str] = _parse_csv_env("LOGSONAR_IGNORE_LOG_SUBSTRINGS", "PostgreSQL,checkpoint")

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
    # CORRECTIF : la "Redirection Ouverte" a été retirée d'ici. Elle référençait un
    # domaine ("tikipay") propre à un client précédent, en dur dans une regex censée
    # être générique. Elle est désormais gérée dynamiquement par _check_open_redirect(),
    # configurable via LOGSONAR_ALLOWED_REDIRECT_DOMAINS (voir .env.example).
    "Scan de vulnérabilités (Bot)": (
        r"(?i)("
        r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster"
        r"|nuclei|acunetix|burpsuite|zgrab|wfuzz|ffuf"
        r"|hydra|metasploit|openvas|nessus|w3af|skipfish"
        r"|appscan|webinspect|qualysguard|vega|zaproxy|zap"
        r"|masscan|zgrab|shodan|censys"
        r"|/(?:storage|apply|hndUnblock|tmUnblock|JNAP|HNAP1|cgi-bin|goform|boaform)/"
        r"|\.cgi$"
        r"|/device\.rsp"
        r"|/cgi-bin/luci/"
        r"|/cgi-bin/webproc"
        r")"
    ),
    "Recherche de fichiers sensibles": (
        r"(?i)("
        r"\.env(?:\.|$|/)"
        r"|\.env\.(?:local|production|prod|dev|development|docker|bak|old|backup)"
        r"|wp-(?:admin|login|config|includes|content)"
        r"|wp-json/gravitysmtpv1/tests/mock-data"
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
        r"\{\{7\*7\}\}|\{\{config\}\}"
        r"|\$\{7\*7\}|\$\{T\(java"
        r"|<%.*%>"
        r")"
    ),
    "Tentative de Désérialisation Malveillante": (
        r"(?i)("
        r"rO0AB"
        r"|O:[0-9]+:\"[a-zA-Z]"
        r"|__reduce__|__import__|pickle"
        r"|aced0005"
        r")"
    ),
}
# NOTE SSTI : le pattern générique `\{\{.*\}\}` a été retiré (voir audit §0.3) : il
# matchait n'importe quel gabarit Vue/Angular/JSON présent dans des logs légitimes.
# On ne garde que des charges utiles d'exploitation avérées (payloads de preuve de
# concept type {{7*7}}), beaucoup plus spécifiques. Si vous avez besoin d'une détection
# plus large, ajoutez-la avec un score de confiance réduit plutôt qu'un flag binaire
# (voir section "Scoring" de l'audit).

_BRUTE_THRESHOLD = 200
_BRUTE_WINDOW    = 120
_FLOOD_THRESHOLD = 250
_FLOOD_WINDOW    = 60
_ALERT_COOLDOWN_SECONDS = 600
_ALERT_TYPE_COOLDOWN_HOURS = 1
_ip_windows: dict = defaultdict(list)

# CORRECTIF : coupe-circuit global anti-rafale. Même si chaque (IP, type) individuel
# respecte son propre cooldown, une rafale multi-IP/multi-type (ex. rejeu de logs
# après un hoquet Docker, ou une nouvelle règle trop large) ne doit jamais générer
# des dizaines d'emails d'un coup. Voir audit §0.4.
_GLOBAL_ALERT_WINDOW_SECONDS = 600
_GLOBAL_ALERT_MAX = 20
_global_alert_timestamps: list[float] = []

def _global_alert_budget_available() -> bool:
    now = _time_module.monotonic()
    while _global_alert_timestamps and now - _global_alert_timestamps[0] > _GLOBAL_ALERT_WINDOW_SECONDS:
        _global_alert_timestamps.pop(0)
    if len(_global_alert_timestamps) >= _GLOBAL_ALERT_MAX:
        return False
    _global_alert_timestamps.append(now)
    return True


_ANSI_RE      = re.compile(r'\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])')
_LOGSONAR_TAG = "logsonar"
_REPORT_DIR   = Path("data/reports")
_MUTED_CONTAINERS: set[str] = set()  # Conteneurs dont l'écoute est coupée


# ===========================================================================
# AUTHENTIFICATION — JWT + OTP + RBAC
# ===========================================================================
# NOTE : ceci est la SEULE implémentation d'authentification du projet.
# Le fichier auth.py (ancien doublon, jamais importé, avec un flux différent
# basé sur des cookies) doit être supprimé — voir audit §1 et §4.

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


_REDIRECT_PARAM_RE = re.compile(
    r'(?i)(?:redirect|return|next|url|goto|dest|destination|continue|returnTo|r|u|link|ref)='
    r'(https?%3A%2F%2F[^&\s"\']+|https?://[^&\s"\']+)'
)

def _check_open_redirect(path_qs: str) -> bool:
    """
    Détecte une redirection vers un domaine externe non autorisé.
    CORRECTIF : les domaines autorisés se configurent via
    LOGSONAR_ALLOWED_REDIRECT_DOMAINS (jamais en dur dans le code — voir audit §0.3).
    """
    for match in _REDIRECT_PARAM_RE.finditer(path_qs):
        target = unquote_plus(unquote(match.group(1))).lower()
        if not any(domain in target for domain in ALLOWED_REDIRECT_DOMAINS):
            return True
    return False


def _check_behavioral(ip: str, path: str) -> tuple[bool, str | None]:
    """
    Détecte bruteforce (même IP + même path) et flood (même IP toutes cibles).
    Retourne (is_attack, description).
    """
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
    sender = form.get("brevo_sender_email", "")
    if sender and not _EMAIL_RE.match(sender):
        errors.append("brevo_sender_email invalide")
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


def analyze_log(raw_log: str, historical: bool = False) -> dict:
    """
    Analyse une ligne de log brute.
    Surfaces inspectées : path, query string (décodé), User-Agent, Referer, log complet.
    Complété par la détection comportementale (bruteforce / flood).

    CORRECTIF : le paramètre `historical` marque les lignes rejouées depuis l'historique
    d'un conteneur (tail au démarrage). Ces lignes ne participent JAMAIS au scoring
    comportemental (sinon un simple redémarrage produit un faux "flood" instantané —
    voir audit §0.2) et ne déclenchent jamais d'alerte email (voir websocket_endpoint).
    """
    result = {
        "is_web": False, "ip": "N/A", "method": "", "path": "",
        "status": "", "timestamp": "", "is_attack": False,
        "attack_type": None, "raw": raw_log, "ua": "", "referer": "",
        "historical": historical,
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

    norm_ua      = _normalize_payload(ua)
    norm_referer = _normalize_payload(referer)

    # --- WHITELIST / IGNORE : configurable par déploiement, jamais en dur ---
    if ip in WHITELIST_IPS:
        pass
    elif any(s in raw_log for s in IGNORE_LOG_SUBSTRINGS):
        pass
    else:
        if _check_open_redirect(path_qs):
            result.update({"is_attack": True, "attack_type": "Tentative de Redirection Ouverte"})
            return result

        surfaces = [path_only, norm_ua, norm_referer]
        for name, pattern in ATTACK_SIGNATURES.items():
            if any(re.search(pattern, s) for s in surfaces if s):
                result.update({"is_attack": True, "attack_type": name})
                return result

    # CORRECTIF : jamais de scoring comportemental sur du rejeu d'historique.
    if not historical:
        is_behavioral, btype = _check_behavioral(ip, path_only)
        if is_behavioral:
            result.update({"is_attack": True, "attack_type": btype})

    return result


# ---------------------------------------------------------------------------
# DOCKER
# ---------------------------------------------------------------------------
# CORRECTIF SÉCURITÉ CRITIQUE : le fallback TCP non authentifié n'est plus actif
# par défaut. Un socket Docker exposé en clair sur le réseau, sans TLS ni
# authentification, équivaut à un accès root non protégé sur l'hôte. Ne
# l'activer qu'en connaissance de cause, en développement local uniquement.
_DOCKER_URLS: tuple[str, ...] = ("unix:///var/run/docker.sock",)
if os.environ.get("LOGSONAR_ALLOW_TCP_DOCKER") == "1":
    _tcp_url = os.environ.get("LOGSONAR_DOCKER_TCP_URL", "tcp://host.docker.internal:2375")
    _DOCKER_URLS = _DOCKER_URLS + (_tcp_url,)
    print(
        f"LogSonar: ATTENTION — fallback Docker TCP non authentifié activé ({_tcp_url}). "
        f"À réserver strictement au développement local."
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


_api_docker_client: docker.DockerClient | None = None
_api_docker_lock = asyncio.Lock()


async def get_shared_docker_client() -> docker.DockerClient:
    global _api_docker_client
    async with _api_docker_lock:
        if _api_docker_client is not None:
            try:
                await asyncio.to_thread(_api_docker_client.ping)
                return _api_docker_client
            except Exception:
                _api_docker_client = None  # mort, on en recrée un ci-dessous

        _api_docker_client = await asyncio.to_thread(_connect_docker)
        return _api_docker_client
    

def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)


def _is_logsonar_container(name: str) -> bool:
    return _LOGSONAR_TAG in name.lower()


# ---------------------------------------------------------------------------
# DIFFUSION DES LOGS — CORRECTIF FAN-OUT (voir audit §0.1)
# ---------------------------------------------------------------------------
class LogBroadcaster:
    """
    Diffuse chaque événement à TOUS les clients WebSocket abonnés (affichage),
    ET exécute des "ingest handlers" indépendants de tout client connecté
    (persistance DB, alertes). CORRECTIF CRITIQUE : avant, la sauvegarde des
    attaques et l'envoi d'alertes ne se déclenchaient QUE si un client WebSocket
    était connecté au dashboard — sans personne connecté, LogSonar ne
    détectait plus rien du tout.
    """
    def __init__(self, maxsize: int = 500):
        self._subscribers: set[asyncio.Queue] = set()
        self._maxsize = maxsize
        self._ingest_handlers: list = []

    def add_ingest_handler(self, handler) -> None:
        self._ingest_handlers.append(handler)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._maxsize)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, item: dict) -> None:
        # Ingestion : tourne TOUJOURS, qu'il y ait ou non un client connecté.
        for handler in self._ingest_handlers:
            try:
                handler(item)
            except Exception as e:
                print(f"LogSonar: Erreur ingest handler: {e}")

        # Affichage live : uniquement pour les clients réellement abonnés.
        for q in list(self._subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(item)
                except asyncio.QueueFull:
                    pass


log_broadcaster = LogBroadcaster()


def _read_one_container(container_name: str, client: docker.DockerClient, loop: asyncio.AbstractEventLoop, tail: int = 0) -> None:
    """
    CORRECTIF : publication planifiée sur la boucle d'événements principale via
    call_soon_threadsafe, au lieu d'un appel direct depuis ce thread — évite
    toute manipulation non thread-safe de la queue asyncio, et garantit que
    les ingest handlers (sauvegarde DB, alertes) s'exécutent bien sur le loop.
    """
    try:
        container = client.containers.get(container_name)

        if tail > 0:
            try:
                historical_raw = container.logs(stream=False, tail=tail)
                for line in historical_raw.decode("utf-8", errors="replace").splitlines():
                    clean = _strip_ansi(line.strip())
                    if not clean:
                        continue
                    data = analyze_log(clean, historical=True)
                    data["container"] = container_name
                    loop.call_soon_threadsafe(log_broadcaster.publish, data)
            except Exception as e:
                print(f"LogSonar: Erreur lecture historique {container_name}: {e}")

        print(f"LogSonar: Écoute {container_name}")
        for line in container.logs(stream=True, follow=True, tail=0):
            if container_name in _MUTED_CONTAINERS:
                print(f"LogSonar: Arrêt de l'écoute de {container_name} (sourdine)")
                break
            clean = _strip_ansi(line.decode("utf-8", errors="replace").strip())
            if not clean:
                continue
            data = analyze_log(clean, historical=False)
            data["container"] = container_name
            loop.call_soon_threadsafe(log_broadcaster.publish, data)
    except docker.errors.NotFound:
        print(f"LogSonar: Conteneur {container_name} introuvable ou arrêté.")
    except Exception as e:
        print(f"LogSonar: Erreur lecture {container_name}: {type(e).__name__}: {e}")


async def docker_supervisor() -> None:
    retry_idx   = 0
    client      = None
    watched: set[str] = set()
    reader_tasks: dict[str, asyncio.Task] = {}
    first_pass = True
    loop = asyncio.get_running_loop()  # capturé une fois, transmis aux threads workers

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
                    containers = await asyncio.to_thread(client.containers.list)
                    active = {
                        c.name for c in containers
                        if not _is_logsonar_container(c.name)
                    }
                except Exception as e:
                    print(f"LogSonar: Perte de connexion Docker ({e}). Reconnexion...")
                    break

                new_containers = active - watched - _MUTED_CONTAINERS
                for name in new_containers:
                    tail = 900 if first_pass else 20
                    print(f"LogSonar: Nouveau conteneur détecté → {name} (tail={tail})")
                    task = asyncio.create_task(
                        asyncio.to_thread(_read_one_container, name, client, loop, tail)
                    )
                    reader_tasks[name] = task
                    watched.add(name)
                first_pass = False

                stopped = watched - active
                for name in stopped:
                    print(f"LogSonar: Conteneur arrêté → {name}")
                    task = reader_tasks.pop(name, None)
                    if task and not task.done():
                        task.cancel()
                    watched.discard(name)

                newly_muted = watched & _MUTED_CONTAINERS
                for name in newly_muted:
                    print(f"LogSonar: Conteneur mis en sourdine → {name}")
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
_alert_type_cooldowns: dict[str, float] = {}

def _is_successful_attack(status: str) -> bool:
    try:
        code = int(status)
        return 200 <= code <= 299
    except (ValueError, TypeError):
        return False


def _should_send_alert(ip: str, attack_type: str, status: str) -> bool:
    if ip in WHITELIST_IPS:
        return False

    if attack_type.startswith("Bruteforce") or attack_type.startswith("Flood"):
        return False

    if not _is_successful_attack(status):
        return False

    now = _time_module.monotonic()

    type_key = attack_type
    if type_key in _alert_type_cooldowns and now - _alert_type_cooldowns[type_key] < (_ALERT_TYPE_COOLDOWN_HOURS * 3600):
        return False

    key = f"{ip}::{attack_type}"
    if key in _alert_cooldowns and now - _alert_cooldowns[key] < _ALERT_COOLDOWN_SECONDS:
        return False

    _alert_cooldowns[key] = now
    _alert_type_cooldowns[type_key] = now
    return True


def _handle_ingest(log_data: dict) -> None:
    """
    S'exécute pour CHAQUE ligne de log analysée, qu'un client WebSocket soit
    connecté ou non. C'est ici — et seulement ici — que la persistance et les
    alertes se décident désormais.
    """
    if log_data.get("historical"):
        return
    if not log_data.get("is_attack"):
        return

    asyncio.create_task(save_critical_event(log_data))

    if _should_send_alert(
        log_data.get("ip", ""),
        log_data.get("attack_type", ""),
        log_data.get("status", ""),
    ) and _global_alert_budget_available():
        asyncio.create_task(send_critical_alert(log_data))


log_broadcaster.add_ingest_handler(_handle_ingest)


# ---------------------------------------------------------------------------
# RATE-LIMITING AUTH — anti-bruteforce login + OTP
# ---------------------------------------------------------------------------
class LoginRateLimiter:
    """
    Throttling anti-bruteforce sur /api/auth/login et /api/auth/verify-otp.
    Clé = IP + identifiant ciblé, pour ne pas bloquer tout un NAT partagé contre
    un seul compte, ni laisser un attaquant contourner le blocage en changeant d'IP
    contre un compte donné. Verrouillage progressif : plus l'attaquant insiste,
    plus le blocage s'allonge (5min -> 15min -> 45min ... plafonné à 6h).
    """
    MAX_ATTEMPTS = 5
    WINDOW_SECONDS = 300
    BASE_LOCKOUT_SECONDS = 300
    LOCKOUT_MULTIPLIER = 3
    MAX_LOCKOUT_SECONDS = 3600 * 6

    def __init__(self):
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._lockout_until: dict[str, float] = {}
        self._lockout_strikes: dict[str, int] = defaultdict(int)

    def _key(self, ip: str, identifier: str) -> str:
        return f"{ip}::{identifier.lower()}"

    def is_locked(self, ip: str, identifier: str) -> tuple[bool, int]:
        key = self._key(ip, identifier)
        now = _time_module.monotonic()
        until = self._lockout_until.get(key)
        if until and now < until:
            return True, int(until - now)
        return False, 0

    def record_failure(self, ip: str, identifier: str) -> None:
        key = self._key(ip, identifier)
        now = _time_module.monotonic()
        self._failures[key] = [t for t in self._failures[key] if now - t < self.WINDOW_SECONDS]
        self._failures[key].append(now)

        if len(self._failures[key]) >= self.MAX_ATTEMPTS:
            strikes = self._lockout_strikes[key]
            lockout_duration = min(
                self.BASE_LOCKOUT_SECONDS * (self.LOCKOUT_MULTIPLIER ** strikes),
                self.MAX_LOCKOUT_SECONDS,
            )
            self._lockout_until[key] = now + lockout_duration
            self._lockout_strikes[key] += 1
            self._failures[key] = []
            print(f"LogSonar: Verrouillage anti-bruteforce ({identifier} depuis {ip}) — {lockout_duration}s")

    def record_success(self, ip: str, identifier: str) -> None:
        key = self._key(ip, identifier)
        self._failures.pop(key, None)
        self._lockout_until.pop(key, None)
        self._lockout_strikes[key] = 0


_login_rate_limiter = LoginRateLimiter()


def _get_client_ip(request: Request) -> str:
    """Respecte X-Forwarded-For si LogSonar est derrière un reverse proxy."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _catch_up_missed_report():
    """
    CORRECTIF : si le process était arrêté pendant toute la fenêtre de minuit
    (crash, redémarrage, mise à jour de version), le rapport de la veille
    n'est jamais généré. Au démarrage, on vérifie s'il manque et on le génère
    immédiatement s'il y a eu des événements ce jour-là.
    """
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    expected_file = _REPORT_DIR / f"rapport_{yesterday}.html"
    if not expected_file.exists():
        try:
            filename = await generate_daily_report(yesterday)
            if filename:
                print(f"LogSonar: Rapport manqué détecté au démarrage — {filename} généré rétroactivement.")
        except Exception as e:
            print(f"LogSonar: Impossible de générer le rapport rattrapé du {yesterday}: {e}")

# ---------------------------------------------------------------------------
# LIFESPAN
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("LogSonar: Démarrage...")
    await init_db()

    await start_global_supervisor()
    await _catch_up_missed_report()

    scheduler = asyncio.create_task(daily_report_scheduler())
    print("LogSonar: Planificateur de rapports démarré.")

    yield

    print("LogSonar: Arrêt en cours...")
    await stop_global_supervisor()
    scheduler.cancel()
    await close_db()
    print("LogSonar: Arrêt complet.")

app = FastAPI(title="LogSonar", lifespan=lifespan, websocket_max_message_size=10_000_000)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ###########################################################################
# ROUTES AUTHENTIFICATION
# ###########################################################################

@app.get("/api/auth/check-setup")
async def api_check_setup():
    needs_setup = not await has_superuser()
    return JSONResponse(content={"needs_setup": needs_setup})


@app.post("/api/auth/setup")
async def api_setup(request: Request):
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

    client_ip = _get_client_ip(request)
    locked, retry_after = _login_rate_limiter.is_locked(client_ip, username)
    if locked:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives. Réessayez dans {retry_after // 60 + 1} minute(s).",
            headers={"Retry-After": str(retry_after)},
        )

    user = await get_user_by_username(username)
    if user is None or not _verify_password(password, user["password_hash"]):
        _login_rate_limiter.record_failure(client_ip, username)
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    _login_rate_limiter.record_success(client_ip, username)

    otp_code = ''.join(secrets.choice('0123456789') for _ in range(6))
    store_otp(username, otp_code, ttl_seconds=300)

    email_sent = await send_otp_email(user["email"], otp_code, username)
    if email_sent:
        print(f"LogSonar: OTP envoyé par Brevo à {user['email']}")
    else:
        print("=" * 60)
        print(f"LogSonar: Brevo non configuré — CODE OTP pour {username}")
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
    code = form.get("code", "").strip()

    if not username or not code:
        raise HTTPException(status_code=400, detail="Username et code OTP requis")

    client_ip = _get_client_ip(request)
    otp_identifier = f"otp:{username}"
    locked, retry_after = _login_rate_limiter.is_locked(client_ip, otp_identifier)
    if locked:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives. Réessayez dans {retry_after // 60 + 1} minute(s).",
            headers={"Retry-After": str(retry_after)},
        )

    if not verify_otp(username, code):
        _login_rate_limiter.record_failure(client_ip, otp_identifier)
        raise HTTPException(status_code=401, detail="OTP invalide ou expiré")

    _login_rate_limiter.record_success(client_ip, otp_identifier)

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
    return JSONResponse(content={
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    })


@app.post("/api/auth/logout")
async def api_auth_logout():
    return JSONResponse(content={"status": "logged_out"})


@app.post("/api/auth/create-user")
async def api_create_user(request: Request, current_user: dict = Depends(require_superuser)):
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
    return {
        "alert_email":          await get_setting("alert_email"),
        "brevo_api_key":        await get_setting("brevo_api_key"),
        "brevo_sender_email":   await get_setting("brevo_sender_email"),
    }


@app.post("/api/settings")
async def api_save_settings(request: Request, user: dict = Depends(require_superuser)):
    form = await request.form()
    form_dict = dict(form)
    errors = _validate_settings(form_dict)
    if errors:
        return JSONResponse(status_code=422, content={"status": "error", "errors": errors})

    await update_setting("alert_email", form_dict.get("alert_email", ""))
    await update_setting("brevo_api_key", form_dict.get("brevo_api_key", ""))
    await update_setting("brevo_sender_email", form_dict.get("brevo_sender_email", ""))
    return JSONResponse(content={"status": "success"})


@app.post("/api/settings/test")
async def api_test_email(user: dict = Depends(require_superuser)):
    test_data = {
        "attack_type": "Test de configuration Brevo",
        "ip": "127.0.0.1",
        "container": "Système",
        "method": "TEST",
        "path": "/",
        "status": "200",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "raw": "Ceci est un email de test depuis LogSonar via Brevo.",
    }
    await send_critical_alert(test_data)
    return JSONResponse(content={"status": "test_sent"})


# ###########################################################################
# ROUTES API — RAPPORTS
# ###########################################################################

@app.get("/api/reports/generate")
async def api_generate_report(
    date: str | None = Query(default=None, description="Format YYYY-MM-DD, par défaut aujourd'hui"),
    user: dict = Depends(require_superuser),
):
    if date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        return JSONResponse(status_code=422, content={"status": "error", "message": "Format de date invalide (YYYY-MM-DD)"})
    filename = await generate_daily_report(date)
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

CRITICAL_SERVICES = {
    "nginx": {"name": "Nginx", "category": "Reverse Proxy / Serveur Web", "url": "https://nginx.org/en/download.html", "docker_image": "nginx"},
    "apache2": {"name": "Apache HTTP Server", "category": "Serveur Web", "url": "https://httpd.apache.org/download.cgi", "docker_image": "httpd"},
    "openssl": {"name": "OpenSSL", "category": "Cryptographie / TLS", "url": "https://www.openssl.org/source/", "docker_image": None},
    "postgresql": {"name": "PostgreSQL", "category": "Base de données", "url": "https://www.postgresql.org/download/", "docker_image": "postgres"},
    "mysql": {"name": "MySQL", "category": "Base de données", "url": "https://dev.mysql.com/downloads/", "docker_image": "mysql"},
    "redis": {"name": "Redis", "category": "Cache / Base de données", "url": "https://redis.io/download/", "docker_image": "redis"},
    "node": {"name": "Node.js", "category": "Runtime JavaScript", "url": "https://nodejs.org/en/download/", "docker_image": "node"},
    "python": {"name": "Python", "category": "Runtime Python", "url": "https://www.python.org/downloads/", "docker_image": "python"},
}


_LAST_VERSION_CACHE = {}
_CACHE_TTL = 3600


async def _get_container_pip_packages(container_name: str) -> list[dict]:
    client = await get_shared_docker_client()

    def _run():
        try:
            container = client.containers.get(container_name)
            result = container.exec_run("pip list --format=json", stdout=True, stderr=False)
            if result.exit_code == 0:
                raw = result.output.decode("utf-8", errors="replace").strip()
                return json.loads(raw)
        except Exception as e:
            print(f"LogSonar: Deps scan {container_name}: {e}")
        return []
    return await asyncio.to_thread(_run)


async def _get_container_system_packages(container_name: str) -> List[Dict]:
    client = await get_shared_docker_client()

    def _run():
        try:
            container = client.containers.get(container_name)
            packages = []

            result = container.exec_run("which apk", stdout=True, stderr=True)
            if result.exit_code == 0:
                pkgs_output = container.exec_run("apk list -I", stdout=True).output.decode("utf-8", errors="replace")
                for line in pkgs_output.splitlines():
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg_name_ver = parts[0]
                        if '-' in pkg_name_ver:
                            name_parts = pkg_name_ver.split('-')
                            name = '-'.join(name_parts[:-1]) if len(name_parts) > 1 else pkg_name_ver
                            version = name_parts[-1] if len(name_parts) > 1 else ""
                            is_critical = name in CRITICAL_SERVICES
                            packages.append({
                                "name": name, "version": version, "is_critical": is_critical,
                                "category": CRITICAL_SERVICES.get(name, {}).get("category", "Paquet système"),
                                "display_name": CRITICAL_SERVICES.get(name, {}).get("name", name),
                            })
                return packages

            result = container.exec_run("which apt", stdout=True, stderr=True)
            if result.exit_code == 0:
                pkgs_output = container.exec_run("apt list --installed", stdout=True).output.decode("utf-8", errors="replace")
                for line in pkgs_output.splitlines():
                    if not line.strip() or line.startswith("Listing..."):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg_name = parts[0].split('/')[0]
                        version = parts[1].split(',')[0]
                        is_critical = pkg_name in CRITICAL_SERVICES
                        packages.append({
                            "name": pkg_name, "version": version, "is_critical": is_critical,
                            "category": CRITICAL_SERVICES.get(pkg_name, {}).get("category", "Paquet système"),
                            "display_name": CRITICAL_SERVICES.get(pkg_name, {}).get("name", pkg_name),
                        })
                return packages

            result = container.exec_run("which yum", stdout=True, stderr=True)
            if result.exit_code == 0:
                pkgs_output = container.exec_run("yum list installed", stdout=True).output.decode("utf-8", errors="replace")
                for line in pkgs_output.splitlines():
                    if not line.strip() or line.startswith("Installed Packages"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg_name_ver = parts[0]
                        version = parts[1]
                        pkg_name = pkg_name_ver.split('.')[0] if '.' in pkg_name_ver else pkg_name_ver
                        is_critical = pkg_name in CRITICAL_SERVICES
                        packages.append({
                            "name": pkg_name, "version": version, "is_critical": is_critical,
                            "category": CRITICAL_SERVICES.get(pkg_name, {}).get("category", "Paquet système"),
                            "display_name": CRITICAL_SERVICES.get(pkg_name, {}).get("name", pkg_name),
                        })
                return packages

            return []
        except Exception as e:
            print(f"LogSonar: Erreur scan système {container_name}: {e}")
            return []
    return await asyncio.to_thread(_run)

async def _get_latest_version(service_name: str) -> Optional[str]:
    import time
    from urllib.request import urlopen, Request
    import json

    now = time.time()
    if service_name in _LAST_VERSION_CACHE:
        cached_version, cached_time = _LAST_VERSION_CACHE[service_name]
        if now - cached_time < _CACHE_TTL:
            return cached_version

    try:
        if service_name in CRITICAL_SERVICES and CRITICAL_SERVICES[service_name]["docker_image"]:
            image = CRITICAL_SERVICES[service_name]["docker_image"]
            url = f"https://hub.docker.com/v2/repositories/library/{image}/tags?page_size=1&page=1&ordering=last_updated"
            req = Request(url, headers={"User-Agent": "LogSonar/1.0"})
            with urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if data.get("results") and len(data["results"]) > 0:
                    latest_tag = data["results"][0]["name"]
                    if latest_tag.lower() in ["latest", "stable", "main"]:
                        if len(data["results"]) > 1:
                            latest_tag = data["results"][1]["name"]
                        else:
                            latest_tag = None
                    if latest_tag:
                        _LAST_VERSION_CACHE[service_name] = (latest_tag, now)
                        return latest_tag
    except Exception as e:
        print(f"LogSonar: Erreur récupération version {service_name}: {e}")

    return None

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
async def api_containers_deps(user: dict = Depends(get_current_user)):
    try:
        client = await get_shared_docker_client()
        all_containers = await asyncio.to_thread(client.containers.list)
        containers = [c for c in all_containers if not _is_logsonar_container(c.name)]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": f"Docker indisponible: {e}"})

    results = []
    for container in containers:
        packages = await _get_container_pip_packages(container.name)
        if not packages:
            results.append({"container": container.name, "status": "no_python", "packages": []})
            continue

        PRIORITY_PACKAGES = {
            "django", "flask", "fastapi", "starlette", "tornado", "aiohttp", "sanction",
            "djangorestframework", "drf-yasg", "drf-spectacular", "flask-restx",
            "django-allauth", "python-jose", "pyjwt", "cryptography", "bcrypt", "passlib",
            "authlib", "oauthlib", "pyotp", "qrcode",
            "sqlalchemy", "psycopg2-binary", "mysqlclient", "pymongo", "redis", "aioredis",
            "celery", "rq", "dramatiq", "kombu", "billiard",
            "gunicorn", "uvicorn", "waitress", "hypercorn", "daphne",
            "requests", "httpx", "urllib3",
            "pillow", "openpyxl", "xlrd", "reportlab", "weasyprint",
            "python-decouple", "python-dotenv", "django-environ",
            "django-cors-headers", "whitenoise", "django-debug-toolbar", "django-extensions",
            "boto3", "botocore", "google-cloud-storage", "azure-storage-blob",
            "paramiko", "fabric",
            "pydantic", "marshmallow", "attrs", "cerberus",
            "jinja2", "mako",
            "setuptools", "pip", "wheel",
            "sentry-sdk", "prometheus-client", "structlog",
            "mkdocs", "mkdocs-material", "pymdown-extensions",
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
# ROUTES API — CONTENEURS MONITORES
# ###########################################################################

@app.get("/api/containers/monitored")
async def api_get_monitored_containers(user: dict = Depends(require_superuser)):
    try:
        client = await get_shared_docker_client()
        raw_containers = await asyncio.to_thread(client.containers.list)
        all_containers = [
            {"name": c.name, "status": c.status}
            for c in raw_containers
            if not _is_logsonar_container(c.name)
        ]
        return [
            {**c, "is_muted": c["name"] in _MUTED_CONTAINERS}
            for c in all_containers
        ]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})

@app.post("/api/containers/toggle")
async def api_toggle_container(request: Request, user: dict = Depends(require_superuser)):
    form = await request.form()
    container_name = form.get("name", "").strip()
    if not container_name:
        return JSONResponse(status_code=400, content={"error": "Nom requis"})

    if container_name in _MUTED_CONTAINERS:
        _MUTED_CONTAINERS.discard(container_name)
        return JSONResponse(content={"status": "unmuted"})
    else:
        _MUTED_CONTAINERS.add(container_name)
        return JSONResponse(content={"status": "muted"})


@app.get("/api/containers/system-scan")
async def api_containers_system_scan(user: dict = Depends(require_superuser)):
    try:
        client = await get_shared_docker_client()
        all_containers = await asyncio.to_thread(client.containers.list)
        containers = [c for c in all_containers if not _is_logsonar_container(c.name)]
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": f"Docker indisponible: {e}"})

    results = []
    for container in containers:
        packages = await _get_container_system_packages(container.name)
        if not packages:
            results.append({"container": container.name, "status": "no_system_info", "packages": []})
            continue

        critical_pkgs = [p for p in packages if p["is_critical"]]

        if not critical_pkgs:
            results.append({"container": container.name, "status": "no_critical_services", "packages": packages})
            continue

        checked = []
        for pkg in critical_pkgs:
            latest = await _get_latest_version(pkg["name"])
            status = "unknown"
            if latest:
                if latest.lower() == pkg["version"].lower():
                    status = "up_to_date"
                else:
                    status = "outdated"
            else:
                status = "unknown"

            checked.append({
                "name": pkg["name"], "display_name": pkg["display_name"],
                "current": pkg["version"], "latest": latest, "status": status,
                "category": pkg["category"],
            })

        results.append({
            "container": container.name,
            "status": "scanned",
            "total": len(checked),
            "outdated": len([p for p in checked if p["status"] == "outdated"]),
            "packages": sorted(checked, key=lambda p: (p["status"] != "outdated", p["name"])),
        })

    return results

# ###########################################################################
# PLANIFICATEUR DE RAPPORT
# ###########################################################################

async def daily_report_scheduler():
    """
    CORRECTIF : plus aucune exception (ex. VACUUM en conflit avec une écriture
    concurrente) ne peut tuer cette tâche de fond silencieusement. `last_run_date`
    remplace la fenêtre fragile "minute == 0", qui pouvait être ratée après un
    redémarrage du process pile à cet instant.
    """
    last_run_date: str | None = None
    while True:
        try:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            if now.hour == 0 and today != last_run_date:
                print(f"LogSonar: Minuit — génération du rapport du {today}...")
                await generate_daily_report()
                await purge_old_events()
                last_run_date = today
                print(f"LogSonar: Rapport et purge du {today} terminés.")
        except Exception as e:
            print(f"LogSonar: ERREUR dans le planificateur de rapport quotidien "
                  f"({type(e).__name__}: {e}) — la boucle continue, on réessaiera au prochain cycle.")
        await asyncio.sleep(30)


# ###########################################################################
# WEBSOCKET
# ###########################################################################

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    """
    Le WebSocket ne sert plus qu'à l'affichage live. La persistance (DB) et les
    alertes sont gérées indépendamment par log_broadcaster (voir _handle_ingest),
    qu'un client soit connecté ou non.
    """
    await websocket.accept()

    try:
        first_message = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4401)
        print("LogSonar: WebSocket refusé — token manquant ou délai dépassé")
        return

    try:
        payload = json.loads(first_message)
        token = payload.get("token", "")
    except Exception:
        token = first_message.strip()

    expected = await get_setting("ws_token")
    if not expected or token != expected:
        await websocket.close(code=4401)
        print("LogSonar: WebSocket refusé — token invalide")
        return

    await websocket.send_json({"type": "auth_ok"})
    client_queue = log_broadcaster.subscribe()

    async def sender():
        while True:
            try:
                log_data = await asyncio.wait_for(client_queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            await websocket.send_json(log_data)

    async def receiver():
        while True:
            await websocket.receive_text()

    sender_task = asyncio.create_task(sender())
    receiver_task = asyncio.create_task(receiver())

    try:
        done, pending = await asyncio.wait(
            {sender_task, receiver_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in done:
            exc = task.exception() if not task.cancelled() else None
            if exc and not isinstance(exc, (WebSocketDisconnect, asyncio.CancelledError)):
                print(f"LogSonar: Erreur WebSocket: {exc}")
    except WebSocketDisconnect:
        print("LogSonar: Client WebSocket déconnecté par le client")
    finally:
        log_broadcaster.unsubscribe(client_queue)
        print("LogSonar: Client WebSocket déconnecté (superviseur toujours actif)")


# ---------------------------------------------------------------------------
# SUPERVISEUR GLOBAL
# ---------------------------------------------------------------------------
_supervisor_task: asyncio.Task | None = None


async def start_global_supervisor():
    """Démarre le superviseur Docker global (une seule fois)."""
    global _supervisor_task
    if _supervisor_task is None or _supervisor_task.done():
        _supervisor_task = asyncio.create_task(docker_supervisor())
        print("LogSonar: Superviseur Docker global démarré.")


async def stop_global_supervisor():
    """Arrête proprement le superviseur."""
    global _supervisor_task
    if _supervisor_task and not _supervisor_task.done():
        _supervisor_task.cancel()
        try:
            await asyncio.wait_for(_supervisor_task, timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        print("LogSonar: Superviseur Docker global arrêté.")


# ###########################################################################
# ROUTE API — TOKEN WebSocket
# ###########################################################################

@app.get("/api/ws-token")
async def api_get_ws_token(user: dict = Depends(get_current_user)):
    """CORRECTIF : cette route n'était protégée par aucune authentification —
    n'importe qui pouvait récupérer le token WebSocket sans être connecté."""
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