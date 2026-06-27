"""
auth.py — Système d'authentification LogSonar
JWT + bcrypt + OTP par email
"""
import os
import secrets
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from fastapi import Request, HTTPException, Depends
from fastapi.responses import JSONResponse

from db import (
    get_user_by_username, get_user_by_id, create_user, count_users,
    has_superuser, store_otp, verify_otp, get_setting
)
from mailer import send_otp_email

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
JWT_SECRET = os.getenv("LOGSONAR_JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALGO = "HS256"
JWT_EXPIRY_HOURS = 24

# ---------------------------------------------------------------------------
# PASSWORD HASHING
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())

# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def create_jwt_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ---------------------------------------------------------------------------
# DEPENDENCIES
# ---------------------------------------------------------------------------
async def get_current_user(request: Request) -> dict:
    """Dependency FastAPI : vérifie le JWT et retourne l'utilisateur."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Non authentifié")
    
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    
    user = await get_user_by_id(int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    
    return user

async def require_superuser(request: Request) -> dict:
    """Dependency : superuser uniquement."""
    user = await get_current_user(request)
    if user["role"] != "superuser":
        raise HTTPException(status_code=403, detail="Accès réservé au superuser")
    return user

# ---------------------------------------------------------------------------
# OTP
# ---------------------------------------------------------------------------
def generate_otp_code() -> str:
    """Génère un code OTP à 6 chiffres."""
    return "".join(secrets.choice("0123456789") for _ in range(6))

async def send_otp_to_user(username: str) -> dict:
    """
    Génère et envoie un OTP.
    Retourne {"sent": True} si email envoyé, {"sent": False, "code": "123456"} sinon.
    """
    user = await get_user_by_username(username)
    if not user:
        raise ValueError("Utilisateur introuvable")
    
    code = generate_otp_code()
    store_otp(username, code, ttl_seconds=300)  # 5 min
    
    # Vérifier si SMTP est configuré
    smtp_host = await get_setting('smtp_host')
    smtp_user = await get_setting('smtp_user')
    smtp_password = await get_setting('smtp_password')
    
    if smtp_host and smtp_user and smtp_password and smtp_password != "********":
        # Envoi email
        try:
            await send_otp_email(user["email"], code, user["username"])
            return {"sent": True, "code": None}
        except Exception as e:
            print(f"LogSonar: Erreur envoi OTP email -> {e}")
            # Fallback : retourner le code pour affichage console
            print(f"=" * 60)
            print(f"LogSonar: CODE OTP pour {username}")
            print(f"  Code: {code}")
            print(f"  Email: {user['email']}")
            print(f"=" * 60)
            return {"sent": False, "code": code}
    else:
        # SMTP non configuré → code visible dans les logs
        print(f"=" * 60)
        print(f"LogSonar: SMTP non configuré — CODE OTP pour {username}")
        print(f"  Code: {code}")
        print(f"  Email: {user['email']}")
        print(f"  Configurez SMTP dans Paramètres pour activer l'envoi par email.")
        print(f"=" * 60)
        return {"sent": False, "code": code}

# ---------------------------------------------------------------------------
# INIT — Création du premier superuser si aucun utilisateur
# ---------------------------------------------------------------------------
async def init_first_user() -> None:
    """Si aucun utilisateur n'existe, crée un superuser par défaut."""
    count = await count_users()
    if count == 0:
        default_user = "admin"
        default_pass = "admin123"  # À changer immédiatement !
        default_email = "admin@localhost"
        
        await create_user(
            username=default_user,
            password_hash=hash_password(default_pass),
            email=default_email,
            role="superuser"
        )
        print(f"=" * 60)
        print(f"LogSonar: Premier utilisateur créé !")
        print(f"  Username: {default_user}")
        print(f"  Password: {default_pass}")
        print(f"  Email:    {default_email}")
        print(f"  Role:     superuser")
        print(f"=" * 60)
        print(f"CHANGEZ CE MOT DE PASSE IMMÉDIATEMENT !")
        print(f"=" * 60)