# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
Jetons d'accès en lecture seule.

Un jeton permet de CONSULTER les données (vue d'ensemble, alertes, menaces,
vulnérabilités, rapports) depuis un outil externe, sans pouvoir rien modifier :
requêtes GET uniquement, sur une liste fermée de pages (voir security.READ_ALLOWED_PREFIXES).
Seule l'empreinte du jeton est stockée : il n'est affiché qu'une fois, à sa création.
Créer, lister et révoquer les jetons demande une session administrateur (2FA).
"""
from __future__ import annotations

import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import db
from .. import security as sec

router = APIRouter(prefix="/api/tokens", tags=["tokens"])

MAX_ACTIVE = 5


class TokenIn(BaseModel):
    name: str = Field(min_length=2, max_length=40, pattern=r"^[\w .'-]+$")
    days: int = Field(default=30, ge=1, le=365)


def _admin_session(request: Request, user: dict) -> dict:
    # Un jeton ne peut jamais en gérer d'autres : session interactive obligatoire
    if user["role"] != "admin" or user["id"] < 0:
        raise HTTPException(403, "Réservé aux administrateurs connectés.")
    return user


@router.get("")
async def list_tokens(request: Request, user: dict = Depends(sec.require_admin)):
    _admin_session(request, user)
    rows = await db.fetchall(
        "SELECT id, name, prefix, created_by, created_at, expires_at, revoked_at, last_used_at, last_used_ip, use_count"
        " FROM api_tokens ORDER BY revoked_at IS NOT NULL, id DESC LIMIT 50")
    now = time.time()
    for r in rows:
        r["active"] = r["revoked_at"] is None and r["expires_at"] > now
    return {"items": rows, "max_active": MAX_ACTIVE, "allowed": list(sec.READ_ALLOWED_PREFIXES)}


@router.post("")
async def create_token(body: TokenIn, request: Request, user: dict = Depends(sec.require_admin)):
    _admin_session(request, user)
    now = time.time()
    active = await db.scalar("SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL AND expires_at > ?", (now,))
    if active >= MAX_ACTIVE:
        raise HTTPException(409, f"{MAX_ACTIVE} jetons actifs au maximum : révoquez-en un d'abord.")
    token = sec.READ_TOKEN_PREFIX + secrets.token_urlsafe(32)
    await db.execute(
        "INSERT INTO api_tokens (name, token_hash, prefix, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (body.name.strip(), sec.hash_api_token(token), token[:10], user["username"], now, now + body.days * 86400))
    print(f"LogSonar: jeton de lecture « {body.name.strip()} » créé par {user['username']} ({body.days} jours).")
    return {"token": token, "expires_at": now + body.days * 86400}


@router.delete("/{token_id}")
async def revoke_token(token_id: int, request: Request, user: dict = Depends(sec.require_admin)):
    _admin_session(request, user)
    row = await db.fetchone("SELECT name FROM api_tokens WHERE id = ? AND revoked_at IS NULL", (token_id,))
    if not row:
        raise HTTPException(404, "Jeton introuvable ou déjà révoqué.")
    await db.execute("UPDATE api_tokens SET revoked_at = ? WHERE id = ?", (time.time(), token_id))
    print(f"LogSonar: jeton de lecture « {row['name']} » révoqué par {user['username']}.")
    return {"ok": True}
