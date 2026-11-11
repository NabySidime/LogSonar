# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
LogSonar — point d'entrée FastAPI.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, config, db, security
from . import settings_store as S
from .alerts import alerts, check_notification_setup
from .api import admin, auth, ingest, monitoring, tokens, users, vulns
from .vuln.scanner import mark_interrupted_scans, slim_osv_cache
from .hub import hub
from .monitor import monitor


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"LogSonar {__version__} — démarrage")
    await db.init_db()
    await S.load()
    await alerts.load()
    await mark_interrupted_scans()
    await check_notification_setup()
    # En arrière-plan : jusqu'à ~30 s sur un gros cache, LogSonar répond pendant ce temps
    cleanup = asyncio.create_task(slim_osv_cache())
    cleanup.add_done_callback(lambda t: t.cancelled() or not t.exception() or print(f"LogSonar: nettoyage du cache en échec : {t.exception()}"))
    if not await db.scalar("SELECT COUNT(*) FROM users"):
        line = "=" * 64
        print(f"{line}\n  PREMIÈRE INSTALLATION — code d'installation : {security.SETUP_CODE}\n"
              f"  Ouvrez l'interface et saisissez ce code pour créer le compte administrateur.\n{line}", flush=True)
    await monitor.start()
    yield
    await monitor.stop()
    await db.close_db()
    print("LogSonar arrêté.")


app = FastAPI(title="LogSonar", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/reports/"):
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
    else:
        response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif request.url.path.startswith(("/static/js/", "/static/css/")):
        # Sans consigne, le navigateur garde sa copie plusieurs heures (cache heuristique) :
        # une mise à jour de LogSonar ne lui parvenait pas. « no-cache » le fait revalider
        # à chaque chargement (ETag : réponse 304 vide si rien n'a changé).
        response.headers["Cache-Control"] = "no-cache"
    if security.is_https(request):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    # Jamais de détail technique côté client ; le détail reste dans les logs.
    print(f"LogSonar: erreur sur {request.method} {request.url.path} : {type(exc).__name__}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Erreur interne."})


for r in (auth.router, users.router, monitoring.router, vulns.router, admin.router, ingest.router, tokens.router):
    app.include_router(r)

app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True, "version": __version__}


@app.get("/login", include_in_schema=False)
async def login_page():
    return FileResponse(config.STATIC_DIR / "login.html", headers={"Cache-Control": "no-cache"})


@app.get("/", include_in_schema=False)
async def index(request: Request):
    try:
        await security.current_user(request)
    except Exception:
        return RedirectResponse("/login", status_code=303)
    return FileResponse(config.STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.websocket("/ws")
async def websocket(ws: WebSocket):
    user = await security.websocket_user(ws)
    if user is None:
        await ws.close(code=4401)
        return
    await ws.accept()
    queue = hub.subscribe()
    paused_logs = False

    async def sender():
        while True:
            msg = await queue.get()
            if paused_logs and msg["type"] == "log":
                continue
            await ws.send_text(json.dumps(msg, default=str))

    async def receiver():
        nonlocal paused_logs
        while True:
            text = await ws.receive_text()
            try:
                cmd = json.loads(text)
            except ValueError:
                continue
            if cmd.get("type") == "logs":
                paused_logs = not cmd.get("enabled", True)

    async def session_check():
        # Une session révoquée (déconnexion, changement de mot de passe) coupe aussi le flux
        while True:
            await asyncio.sleep(60)
            if await security.websocket_user(ws) is None:
                await ws.close(code=4401)
                return

    tasks = [asyncio.create_task(t()) for t in (sender, receiver, session_check)]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    finally:
        for t in tasks:
            t.cancel()
        hub.unsubscribe(queue)
