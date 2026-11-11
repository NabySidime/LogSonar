# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""Gestion des comptes (administrateurs uniquement)."""
from __future__ import annotations

import asyncio
import time
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import config, db, security as sec

router = APIRouter(prefix="/api/users", tags=["users"])
_create_lock = asyncio.Lock()


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(default="", max_length=200)
    password: str = Field(max_length=256)
    role: Literal["admin", "viewer"] = "viewer"


class UserPatch(BaseModel):
    email: Optional[str] = Field(default=None, max_length=200)
    password: Optional[str] = Field(default=None, max_length=256)
    role: Optional[Literal["admin", "viewer"]] = None
    reset_2fa: bool = False


@router.get("")
async def list_users(_: dict = Depends(sec.require_admin)):
    rows = await db.fetchall("SELECT * FROM users ORDER BY id")
    return {"items": [sec.public_user(r) for r in rows], "max": config.MAX_USERS}


@router.post("")
async def create_user(body: UserIn, _: dict = Depends(sec.require_admin)):
    err = sec.validate_password(body.password)
    if err:
        raise HTTPException(422, err)
    password_hash = sec.hash_password(body.password)
    async with _create_lock:
        if await db.scalar("SELECT COUNT(*) FROM users") >= config.MAX_USERS:
            raise HTTPException(409, f"Limite atteinte : {config.MAX_USERS} comptes maximum. Supprimez un compte pour en créer un autre.")
        if await db.fetchone("SELECT id FROM users WHERE username = ?", (body.username,)):
            raise HTTPException(409, "Ce nom d'utilisateur existe déjà.")
        uid = await db.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (body.username, body.email.strip(), password_hash, body.role, time.time()),
        )
    return sec.public_user(await db.fetchone("SELECT * FROM users WHERE id = ?", (uid,)))


async def _admins_left(excluding: int) -> int:
    return await db.scalar("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?", (excluding,))


@router.patch("/{user_id}")
async def update_user(user_id: int, body: UserPatch, admin: dict = Depends(sec.require_admin)):
    user = await db.fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
    if not user:
        raise HTTPException(404, "Utilisateur introuvable.")
    sets, params = [], []
    if body.email is not None:
        sets.append("email = ?")
        params.append(body.email.strip())
    if body.password:
        err = sec.validate_password(body.password)
        if err:
            raise HTTPException(422, err)
        sets += ["password_hash = ?", "token_version = token_version + 1"]
        params.append(sec.hash_password(body.password))
    if body.role and body.role != user["role"]:
        if user["role"] == "admin" and not await _admins_left(user_id):
            raise HTTPException(422, "Il doit rester au moins un administrateur.")
        sets += ["role = ?", "token_version = token_version + 1"]
        params.append(body.role)
    if body.reset_2fa:
        sets += ["totp_secret = ''", "totp_enabled = 0", "token_version = token_version + 1"]
    if sets:
        await db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", (*params, user_id))
    return sec.public_user(await db.fetchone("SELECT * FROM users WHERE id = ?", (user_id,)))


@router.delete("/{user_id}")
async def delete_user(user_id: int, admin: dict = Depends(sec.require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(422, "Vous ne pouvez pas supprimer votre propre compte.")
    user = await db.fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
    if not user:
        raise HTTPException(404, "Utilisateur introuvable.")
    if user["role"] == "admin" and not await _admins_left(user_id):
        raise HTTPException(422, "Il doit rester au moins un administrateur.")
    await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"ok": True}
