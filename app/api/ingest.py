# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
Réception des requêtes envoyées par le middleware des applications (Django, etc.).

Les logs d'accès ne contiennent pas le corps des requêtes POST : une injection SQL
envoyée dans un formulaire y est invisible. Le middleware transmet donc chaque
requête avec son corps, que LogSonar analyse en mémoire. Seul un court extrait
de l'attaque est conservé, jamais le corps complet ni la valeur d'un champ sensible.
"""
from __future__ import annotations

import json
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import security as sec
from .. import settings_store as S
from ..alerts import check_notification_setup
from ..monitor import monitor

router = APIRouter(tags=["ingest"])

MAX_PAYLOAD = 4 * 1024 * 1024
MAX_EVENTS = 200
_SOURCE_RE = re.compile(r"[^A-Za-z0-9_.-]")


def _check_token(request: Request) -> None:
    expected = S.get("ingest_token")
    # Limitation par IP uniquement : un verrou global permettrait à un tiers de bloquer le middleware.
    key = "ingest:" + sec.client_ip(request)
    wait = sec.ip_limiter.locked_for(key)
    if wait:
        raise HTTPException(429, "Trop de tentatives.", headers={"Retry-After": str(wait)})
    auth = request.headers.get("authorization", "")
    given = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not expected or not given or not secrets.compare_digest(given.encode(), expected.encode()):
        sec.ip_limiter.failure(key)
        raise HTTPException(401, "Jeton invalide.")


@router.post("/api/ingest")
async def ingest(request: Request):
    _check_token(request)
    if int(request.headers.get("content-length") or 0) > MAX_PAYLOAD:
        raise HTTPException(413, "Lot trop volumineux.")
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_PAYLOAD:
            raise HTTPException(413, "Lot trop volumineux.")
    try:
        payload = json.loads(data)
    except ValueError:
        raise HTTPException(400, "JSON invalide.")
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        raise HTTPException(400, "Format attendu : {\"source\": \"...\", \"events\": [...]}")
    source = _SOURCE_RE.sub("", str(payload.get("source") or "application"))[:64] or "application"
    events = payload["events"][:MAX_EVENTS]
    attacks = monitor.ingest_requests(source, events)
    return {"accepted": len(events), "attacks": attacks}


@router.get("/api/settings/ingest")
async def ingest_status(_: dict = Depends(sec.require_admin)):
    return {"token_set": bool(S.get("ingest_token")), "sources": monitor.ingest_sources}


@router.post("/api/settings/ingest/token")
async def new_token(_: dict = Depends(sec.require_admin)):
    """Génère un nouveau jeton. Il n'est affiché qu'une fois ; l'ancien cesse de fonctionner."""
    token = "lsi_" + secrets.token_urlsafe(32)
    await S.set_many({"ingest_token": token})
    await check_notification_setup()
    return {"token": token}


@router.delete("/api/settings/ingest/token")
async def delete_token(_: dict = Depends(sec.require_admin)):
    await S.set_many({"ingest_token": ""})
    await check_notification_setup()
    return {"ok": True}
