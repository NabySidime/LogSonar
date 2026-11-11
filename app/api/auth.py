# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
Authentification en deux étapes : mot de passe, puis code TOTP (application
d'authentification). La première connexion enrôle l'application via un QR code.
"""
from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import db, security as sec

router = APIRouter(prefix="/api/auth", tags=["auth"])
_setup_lock = asyncio.Lock()


class SetupIn(BaseModel):
    setup_code: str = Field(max_length=64)
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(default="", max_length=200)
    password: str = Field(max_length=256)


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class TwoFAIn(BaseModel):
    challenge: str = Field(max_length=2000)
    code: str = Field(max_length=12)


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


async def _needs_setup() -> bool:
    return not await db.scalar("SELECT COUNT(*) FROM users")


async def _enroll_payload(user: dict) -> dict:
    """Génère (si besoin) le secret TOTP et renvoie le QR code à scanner."""
    from ..settings_store import decrypt, encrypt

    secret = decrypt(user["totp_secret"]) if user["totp_secret"] else ""
    if not secret:
        secret = sec.new_totp_secret()
        await db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (encrypt(secret), user["id"]))
    uri = sec.totp_uri(secret, user["username"])
    return {
        "step": "enroll",
        "challenge": sec.challenge_token(user, enroll=True),
        "secret": secret,
        "qr_svg": sec.qr_svg(uri),
    }


@router.get("/status")
async def status(request: Request):
    user = None
    try:
        user = await sec.current_user(request)
    except HTTPException:
        pass
    return {
        "needs_setup": await _needs_setup(),
        "authenticated": user is not None,
        "user": sec.public_user(user) if user else None,
    }


@router.post("/setup")
async def setup(body: SetupIn, request: Request):
    ip = sec.client_ip(request)
    sec.check_limits(ip, "__setup__")
    async with _setup_lock:
        if not await _needs_setup():
            raise HTTPException(403, "LogSonar est déjà configuré.")
        if not sec.secrets.compare_digest(body.setup_code.strip().upper(), sec.SETUP_CODE):
            sec.record_failure(ip, "__setup__")
            raise HTTPException(403, "Code d'installation incorrect. Il s'affiche dans les logs : docker logs logsonar")
        err = sec.validate_password(body.password)
        if err:
            raise HTTPException(422, err)
        uid = await db.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
            (body.username.strip(), body.email.strip(), sec.hash_password(body.password), time.time()),
        )
    user = await db.fetchone("SELECT * FROM users WHERE id = ?", (uid,))
    return await _enroll_payload(user)


@router.post("/login")
async def login(body: LoginIn, request: Request):
    ip = sec.client_ip(request)
    username = body.username.strip()
    sec.check_limits(ip, username)
    user = await db.fetchone("SELECT * FROM users WHERE username = ?", (username,))
    ok = sec.verify_password(body.password, user["password_hash"] if user else sec._DUMMY_HASH)
    if not user or not ok:
        sec.record_failure(ip, username)
        raise HTTPException(401, "Identifiants invalides.")
    if not user["totp_enabled"]:
        return await _enroll_payload(user)
    return {"step": "totp", "challenge": sec.challenge_token(user, enroll=False)}


@router.post("/2fa")
async def verify_2fa(body: TwoFAIn, request: Request, response: Response):
    from ..settings_store import decrypt

    data = sec.read_token(body.challenge, "2fa")
    if not data or sec.challenge_burned(data["jti"]):
        raise HTTPException(401, "Session de connexion expirée, recommencez.")
    user = await db.fetchone("SELECT * FROM users WHERE id = ?", (int(data["sub"]),))
    if not user:
        raise HTTPException(401, "Utilisateur introuvable.")
    ip = sec.client_ip(request)
    sec.check_limits(ip, user["username"])

    if not sec.verify_totp(user["id"], decrypt(user["totp_secret"]), body.code):
        sec.record_failure(ip, user["username"])
        burned = sec.challenge_failure(data["jti"])
        raise HTTPException(401, "Trop d'essais, reconnectez-vous." if burned else "Code incorrect.")

    sec.record_success(ip, user["username"])
    if data.get("enroll") and not user["totp_enabled"]:
        await db.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user["id"],))
        user["totp_enabled"] = 1
    await db.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user["id"]))
    token = sec.session_token(user)
    response.set_cookie(
        sec.SESSION_COOKIE, token, httponly=True, samesite="strict", secure=sec.cookie_secure(request),
        max_age=sec.config.SESSION_HOURS * 3600, path="/",
    )
    return {"ok": True, "user": sec.public_user(user)}


@router.post("/logout")
async def logout(response: Response, user: dict = Depends(sec.current_user)):
    # Invalide toutes les sessions de l'utilisateur (jetons déjà émis compris)
    await db.execute("UPDATE users SET token_version = token_version + 1 WHERE id = ?", (user["id"],))
    response.delete_cookie(sec.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(user: dict = Depends(sec.current_user)):
    return sec.public_user(user)


@router.post("/password")
async def change_password(body: PasswordIn, request: Request, response: Response, user: dict = Depends(sec.current_user)):
    if not sec.verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(403, "Mot de passe actuel incorrect.")
    err = sec.validate_password(body.new_password)
    if err:
        raise HTTPException(422, err)
    await db.execute(
        "UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
        (sec.hash_password(body.new_password), user["id"]),
    )
    user = await db.fetchone("SELECT * FROM users WHERE id = ?", (user["id"],))
    response.set_cookie(
        sec.SESSION_COOKIE, sec.session_token(user), httponly=True, samesite="strict",
        secure=sec.cookie_secure(request), max_age=sec.config.SESSION_HOURS * 3600, path="/",
    )
    return {"ok": True}
