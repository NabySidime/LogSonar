"""
Authentification : bcrypt, session JWT en cookie HttpOnly, 2FA TOTP (application
d'authentification), limitation des tentatives, contrôle d'accès par rôle.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
import time
from collections import defaultdict, deque
from typing import Optional

import bcrypt
import jwt
import pyotp
from fastapi import Depends, HTTPException, Request, WebSocket, status

from . import config, db

ALGORITHM = "HS256"
SESSION_COOKIE = "ls_session"
CSRF_HEADER = "x-logsonar"
MIN_PASSWORD_LENGTH = 10


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
def _load_jwt_secret() -> str:
    if config.JWT_SECRET_ENV:
        return config.JWT_SECRET_ENV
    config.ensure_dirs()
    path = config.DATA_DIR / ".jwt_secret"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    path.write_text(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


_JWT_SECRET: str | None = None


def jwt_secret() -> str:
    global _JWT_SECRET
    if _JWT_SECRET is None:
        _JWT_SECRET = _load_jwt_secret()
    return _JWT_SECRET


# Code d'installation : imprimé dans les logs tant qu'aucun compte n'existe.
# Seule une personne ayant accès au serveur (docker logs) peut créer l'admin.
SETUP_CODE = os.environ.get("LOGSONAR_SETUP_CODE") or secrets.token_hex(4).upper()


# ---------------------------------------------------------------------------
# Mots de passe
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed.encode())
    except ValueError:
        return False


# Hash factice : même temps de réponse que l'utilisateur existe ou non
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def validate_password(password: str) -> Optional[str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères."
    if password.lower() == password or not any(c.isdigit() for c in password):
        return "Le mot de passe doit contenir au moins une majuscule et un chiffre."
    return None


# ---------------------------------------------------------------------------
# Jetons
# ---------------------------------------------------------------------------
def make_token(payload: dict, ttl_seconds: int) -> str:
    now = int(time.time())
    data = {**payload, "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(data, jwt_secret(), algorithm=ALGORITHM)


def read_token(token: str, purpose: str) -> Optional[dict]:
    try:
        data = jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    if data.get("purpose") != purpose:
        return None
    return data


def session_token(user: dict) -> str:
    return make_token(
        {"purpose": "session", "sub": str(user["id"]), "ver": user["token_version"]},
        config.SESSION_HOURS * 3600,
    )


def challenge_token(user: dict, enroll: bool) -> str:
    """Jeton court entre l'étape mot de passe et l'étape 2FA."""
    return make_token(
        {"purpose": "2fa", "sub": str(user["id"]), "enroll": enroll, "jti": secrets.token_hex(8)},
        300,
    )


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
_last_totp_step: dict[int, int] = {}


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=config.INSTANCE_NAME)


def verify_totp(user_id: int, secret: str, code: str) -> bool:
    """Accepte ±30 s de décalage d'horloge et refuse la réutilisation d'un code."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6) or not secret:
        return False
    totp = pyotp.TOTP(secret)
    now = time.time()
    for offset in (-1, 0, 1):
        at = now + offset * 30
        if secrets.compare_digest(totp.at(at), code):
            step = int(at // 30)
            if step <= _last_totp_step.get(user_id, -1):
                return False
            _last_totp_step[user_id] = step
            return True
    return False


def qr_svg(data: str) -> str:
    import qrcode
    import qrcode.image.svg

    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return img.to_string(encoding="unicode")


# ---------------------------------------------------------------------------
# Limitation des tentatives
# ---------------------------------------------------------------------------
class AttemptLimiter:
    """
    Fenêtre glissante + verrouillage progressif.
    On limite à la fois par compte (indépendamment de l'IP : changer d'IP ne
    sert à rien) et par IP (pour freiner le test de nombreux comptes).
    """

    def __init__(self, max_failures: int, window: int, base_lockout: int, max_lockout: int = 6 * 3600):
        self.max_failures = max_failures
        self.window = window
        self.base_lockout = base_lockout
        self.max_lockout = max_lockout
        self._fail: dict[str, deque] = defaultdict(deque)
        self._until: dict[str, float] = {}
        self._strikes: dict[str, int] = defaultdict(int)

    def locked_for(self, key: str) -> int:
        until = self._until.get(key, 0)
        remaining = until - time.monotonic()
        return int(remaining) + 1 if remaining > 0 else 0

    def failure(self, key: str) -> None:
        now = time.monotonic()
        q = self._fail[key]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max_failures:
            duration = min(self.base_lockout * (3 ** self._strikes[key]), self.max_lockout)
            self._until[key] = now + duration
            self._strikes[key] += 1
            q.clear()

    def success(self, key: str) -> None:
        self._fail.pop(key, None)
        self._until.pop(key, None)
        self._strikes.pop(key, None)

    def cleanup(self) -> None:
        now = time.monotonic()
        for key in [k for k, q in self._fail.items() if not q or now - q[-1] > self.window]:
            self._fail.pop(key, None)
        for key in [k for k, t in self._until.items() if t < now - 86400]:
            self._until.pop(key, None)
            self._strikes.pop(key, None)


account_limiter = AttemptLimiter(max_failures=8, window=900, base_lockout=300)
ip_limiter = AttemptLimiter(max_failures=25, window=900, base_lockout=600)
_challenge_failures: dict[str, int] = {}


def check_limits(ip: str, account: str) -> None:
    wait = max(ip_limiter.locked_for(ip), account_limiter.locked_for(account.lower()))
    if wait:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives. Réessayez dans {wait // 60 + 1} minute(s).",
            headers={"Retry-After": str(wait)},
        )


def record_failure(ip: str, account: str) -> None:
    ip_limiter.failure(ip)
    account_limiter.failure(account.lower())


def record_success(ip: str, account: str) -> None:
    account_limiter.success(account.lower())


def challenge_failure(jti: str) -> bool:
    """Retourne True si le jeton 2FA est épuisé (5 essais max par connexion)."""
    _challenge_failures[jti] = _challenge_failures.get(jti, 0) + 1
    if len(_challenge_failures) > 10000:
        _challenge_failures.clear()
    return _challenge_failures[jti] >= 5


def challenge_burned(jti: str) -> bool:
    return _challenge_failures.get(jti, 0) >= 5


# ---------------------------------------------------------------------------
# IP cliente
# ---------------------------------------------------------------------------
def _is_trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in config.TRUSTED_PROXIES)


def client_ip(request: Request) -> str:
    """
    X-Forwarded-For n'est pris en compte que si la connexion vient d'un proxy
    déclaré dans LOGSONAR_TRUSTED_PROXIES. On remonte la chaîne depuis la droite
    jusqu'à la première IP non fiable (impossible à falsifier pour le client).
    """
    peer = request.client.host if request.client else "unknown"
    if not _is_trusted(peer):
        return peer
    xff = request.headers.get("x-forwarded-for", "")
    chain = [p.strip() for p in xff.split(",") if p.strip()]
    for hop in reversed(chain):
        if not _is_trusted(hop):
            return hop
    return chain[0] if chain else peer


def is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    peer = request.client.host if request.client else ""
    return _is_trusted(peer) and request.headers.get("x-forwarded-proto", "").lower() == "https"


def cookie_secure(request: Request) -> bool:
    if config.SECURE_COOKIES in ("1", "true", "yes"):
        return True
    if config.SECURE_COOKIES in ("0", "false", "no"):
        return False
    return is_https(request)


# ---------------------------------------------------------------------------
# Dépendances FastAPI
# ---------------------------------------------------------------------------
async def _user_from_token(token: str | None) -> Optional[dict]:
    if not token:
        return None
    data = read_token(token, "session")
    if not data:
        return None
    user = await db.fetchone("SELECT * FROM users WHERE id = ?", (int(data["sub"]),))
    if not user or user["token_version"] != data.get("ver") or not user["totp_enabled"]:
        return None
    return user


# ---------------------------------------------------------------------------
# Jetons d'accès en LECTURE SEULE (outils externes, assistant...)
# ---------------------------------------------------------------------------
READ_TOKEN_PREFIX = "lsr_"
READ_METHODS = ("GET", "HEAD")
# Seules ces pages de consultation sont accessibles avec un jeton de lecture.
# Jamais : paramètres, utilisateurs, compte, temps réel, envoi de données.
READ_ALLOWED_PREFIXES = (
    "/api/overview", "/api/host", "/api/containers", "/api/traffic", "/api/security/",
    "/api/alerts", "/api/system", "/api/vulns/", "/api/reports",
)
_token_touch: dict[int, float] = {}


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def _reader_from_token(token: str, request: Request) -> dict:
    ip = client_ip(request)
    key = "readtoken:" + ip
    wait = ip_limiter.locked_for(key)
    if wait:
        raise HTTPException(429, "Trop de tentatives.", headers={"Retry-After": str(wait)})
    # Lecture seule, vérifiée avant même de regarder le jeton : aucune route d'écriture n'est atteignable
    if request.method not in READ_METHODS:
        raise HTTPException(403, "Jeton en lecture seule : seules les requêtes GET sont autorisées.")
    path = request.url.path
    if not path.startswith(READ_ALLOWED_PREFIXES):
        raise HTTPException(403, "Cette page n'est pas accessible avec un jeton de lecture.")
    row = await db.fetchone(
        "SELECT * FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
        (hash_api_token(token), time.time()))
    if not row:
        ip_limiter.failure(key)
        raise HTTPException(401, "Jeton invalide, expiré ou révoqué.")
    now = time.time()
    if now - _token_touch.get(row["id"], 0) > 60:   # une écriture par minute au plus
        _token_touch[row["id"]] = now
        await db.execute("UPDATE api_tokens SET last_used_at = ?, last_used_ip = ?, use_count = use_count + 1 WHERE id = ?",
                         (now, ip, row["id"]))
    return {
        "id": -row["id"], "username": f"jeton:{row['name']}", "email": "", "role": "reader",
        "totp_enabled": 1, "token_version": 0, "created_at": row["created_at"], "last_login": now,
    }


def _token_from_request(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get(SESSION_COOKIE)


async def current_user(request: Request) -> dict:
    token = _token_from_request(request)
    if token and token.startswith(READ_TOKEN_PREFIX):
        return await _reader_from_token(token, request)
    user = await _user_from_token(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalide ou expirée")
    # Protection CSRF : un site tiers ne peut pas envoyer d'en-tête personnalisé
    # sans requête préalable CORS, que LogSonar refuse.
    if request.method not in ("GET", "HEAD", "OPTIONS") and not request.headers.get(CSRF_HEADER):
        if not request.headers.get("authorization"):
            raise HTTPException(status_code=403, detail="En-tête de sécurité manquant")
    return user


async def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs")
    return user


async def websocket_user(ws: WebSocket) -> Optional[dict]:
    # Contre le détournement de WebSocket depuis un autre site : l'origine doit correspondre à l'hôte.
    origin = ws.headers.get("origin")
    host = ws.headers.get("host")
    if origin and host and origin.split("://", 1)[-1] != host:
        return None
    return await _user_from_token(ws.cookies.get(SESSION_COOKIE))


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "totp_enabled": bool(user["totp_enabled"]),
        "created_at": user["created_at"],
        "last_login": user["last_login"],
    }
