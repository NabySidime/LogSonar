"""
main.py — Point d'entrée LogSonar
Lecture Docker avec retry exponentiel + re-détection des nouveaux conteneurs.
Auth JWT + OTP + RBAC (superuser/user)
"""
import asyncio
import re
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

import docker
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Query, Depends
from fastapi.responses import HTMLResponse, Response, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from db import (
    init_db, close_db,
    save_critical_event, get_setting, update_setting,
    get_events_for_date, get_stats_today, get_dashboard_data,
    get_user_by_username, create_user, count_users, has_superuser,
    store_otp, verify_otp
)
from mailer import send_critical_alert
from reporter import generate_daily_report
from auth import (
    hash_password, verify_password, create_jwt_token, decode_jwt_token,
    get_current_user, require_superuser, send_otp_to_user, init_first_user,
    generate_otp_code
)

# ---------------------------------------------------------------------------
# MOTEUR D'ANALYSE — v2
# ---------------------------------------------------------------------------
import time as _time_module
from collections import defaultdict
from urllib.parse import unquote_plus

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*\[(?P<timestamp>[^\]]+)\]\s'
    r'"(?P<method>[A-Z]+)\s(?P<path>.+?)\sHTTP/[^"]+"\s(?P<status>\d{3})'
    r'(?:\s+\d+)?(?:\s+"(?P<referer>[^"]*?)")?(?:\s+"(?P<ua>[^"]*?)")?'
)

ATTACK_SIGNATURES = {
    "Tentative d'Injection SQL": (
        r"(?i)(union[\s\+%20]+select"
        r"|or[\s%20]+1[\s%20]*=[\s%20]*1"
        r"|drop[\s%20]+table"
        r"|select[\s%20]+.{0,30}[\s%20]+from"
        r"|insert[\s%20]+into"
        r"|'[\s]*--"
        r"|;[\s]*drop"
        r"|xp_cmdshell"
        r"|information_schema)"
    ),
    "Tentative de Cross-Site Scripting (XSS)": (
        r"(?i)(<script[\s>]"
        r"|javascript\s*:"
        r"|on(?:error|load|click|mouseover|focus|keyup|submit)\s*="
        r"|alert\s*\("
        r"|document\.cookie"
        r"|<iframe"
        r"|<svg.*on)"
    ),
    "Tentative de Path Traversal": (
        r"(?i)(\.\.[\\/]"
        r"|%2e%2e[\\/]"
        r"|%252e"
        r"|\.\.%2f"
        r"|\.\.%5c)"
    ),
    "Scan de vulnérabilités (Bot)": (
        r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster"
        r"|nuclei|acunetix|burpsuite|zgrab|wfuzz|ffuf"
        r"|hydra|metasploit|openvas)"
    ),
    "Recherche de fichiers sensibles": (
        r"(?i)(\.env$"
        r"|wp-(?:admin|login|config)"
        r"|/etc/(?:passwd|shadow|hosts)"
        r"|phpmyadmin"
        r"|\.git/"
        r"|\.htaccess"
        r"|backup\."
        r"|\.sql$"
        r"|\.bak$"
        r"|web\.config"
        r"|/proc/self)"
    ),
    "Alerte interne de l'application": (
        r"(?i)(SuspiciousOperation|BadRequest|LOGSONAR_POST_ATTACK)"
    ),
    "Tentative de falsification (CSRF)": (
        r"(?i)(csrf[\s_-]*(failed|invalid|missing|mismatch))"
    ),
}

_BRUTE_THRESHOLD = 10
_BRUTE_WINDOW    = 60
_FLOOD_THRESHOLD = 30
_FLOOD_WINDOW    = 30
_ip_windows: dict = defaultdict(list)

_ANSI_RE      = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
_LOGSONAR_TAG = "logsonar"
_REPORT_DIR   = Path("data/reports")


def _decode_payload(raw: str) -> str:
    seen, s = set(), raw
    for _ in range(4):
        decoded = unquote_plus(s)
        if decoded in seen or decoded == s:
            break
        seen.add(decoded)
        s = decoded
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
        for name, pattern in ATTACK_SIGNATURES.items():
            if re.search(pattern, clean):
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

    path_only    = path_qs.split("?")[0]
    decoded_full = _decode_payload(path_qs)

    result.update({
        "is_web": True, "ip": ip, "method": method,
        "path": path_only, "status": status, "timestamp": ts,
        "ua": ua, "referer": referer,
    })

    surfaces = [path_only, decoded_full, ua, referer, clean]
    for name, pattern in ATTACK_SIGNATURES.items():
        if any(re.search(pattern, s) for s in surfaces if s):
            result.update({"is_attack": True, "attack_type": name})
            return result

    is_behavioral, btype = _check_behavioral(ip, path_only)
    if is_behavioral:
        result.update({"is_attack": True, "attack_type": btype})

    return result


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


_alert_cooldowns: dict[str, float] = {}
_ALERT_COOLDOWN_SECONDS = 60


def _should_send_alert(ip: str, attack_type: str) -> bool:
    key = f"{ip}::{attack_type}"
    now = _time.monotonic()
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
    await init_first_user()  # Crée le superuser par défaut si aucun user
    scheduler = asyncio.create_task(daily_report_scheduler())
    print("LogSonar: Planificateur de rapports démarré.")
    yield
    print("LogSonar: Arrêt en cours...")
    scheduler.cancel()
    await close_db()
    print("LogSonar: Arrêt complet.")

app = FastAPI(title="LogSonar", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------------------------------------------------------------------------
# AUTH ROUTES — Login / OTP / Setup
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
async def api_login(request: Request):
    """Étape 1 : Vérification username/password → envoi OTP."""
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")

    if not username or not password:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Champs requis"})

    user = await get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        await asyncio.sleep(0.5)
        return JSONResponse(status_code=401, content={"status": "error", "message": "Identifiants invalides"})

    # Envoi OTP
    try:
        result = await send_otp_to_user(username)
    except Exception as e:
        print(f"LogSonar: Erreur envoi OTP -> {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": "Erreur d'envoi OTP"})

    response_data = {
        "status": "otp_required",
        "username": username,
        "message": "Code de confirmation envoyé par email" if result["sent"] else "Code de confirmation (voir console/logs)",
        "email_sent": result["sent"],
    }
    
    # Si pas d'email envoyé, inclure le code dans la réponse (pour le dev/debug)
    # En production, tu peux retirer cette ligne pour ne pas exposer le code
    if not result["sent"] and result["code"]:
        response_data["code"] = result["code"]  # ⚠️ Retirer en production si tu veux
    
    return JSONResponse(content=response_data)


@app.post("/api/auth/verify-otp")
async def api_verify_otp(request: Request):
    """Étape 2 : Vérification OTP → création du JWT."""
    form = await request.form()
    username = form.get("username", "").strip()
    code = form.get("code", "").strip()

    if not username or not code:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Champs requis"})

    if not verify_otp(username, code):
        return JSONResponse(status_code=401, content={"status": "error", "message": "Code invalide ou expiré"})

    user = await get_user_by_username(username)
    if not user:
        return JSONResponse(status_code=401, content={"status": "error", "message": "Utilisateur introuvable"})

    token = create_jwt_token(user["id"], user["username"], user["role"])

    response = JSONResponse(content={
        "status": "success",
        "username": user["username"],
        "role": user["role"]
    })
    # Cookie HTTP-only, Secure, SameSite strict
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,  # Mettre True en production HTTPS
        samesite="lax",
        max_age=86400,  # 24h
        path="/"
    )
    return response


@app.post("/api/auth/logout")
async def api_logout():
    """Déconnexion — suppression du cookie."""
    response = JSONResponse(content={"status": "success"})
    response.delete_cookie(key="access_token", path="/")
    return response


@app.get("/api/auth/me")
async def api_me(user: dict = Depends(get_current_user)):
    """Retourne les infos de l'utilisateur connecté."""
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"]
    }


@app.post("/api/auth/setup")
async def api_setup(request: Request):
    """
    Setup initial — crée le premier superuser.
    Ne fonctionne que si aucun utilisateur n'existe.
    """
    count = await count_users()
    if count > 0:
        return JSONResponse(status_code=403, content={
            "status": "error",
            "message": "Setup déjà effectué. Utilisez /api/auth/login"
        })

    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    email = form.get("email", "").strip()

    if not username or not password or not email:
        return JSONResponse(status_code=400, content={
            "status": "error", "message": "Tous les champs sont requis"
        })

    if len(password) < 8:
        return JSONResponse(status_code=400, content={
            "status": "error", "message": "Mot de passe min. 8 caractères"
        })

    if not _EMAIL_RE.match(email):
        return JSONResponse(status_code=400, content={
            "status": "error", "message": "Email invalide"
        })

    try:
        user = await create_user(
            username=username,
            password_hash=hash_password(password),
            email=email,
            role="superuser"
        )
        return JSONResponse(content={
            "status": "success",
            "message": "Superuser créé",
            "username": user["username"]
        })
    except ValueError as e:
        return JSONResponse(status_code=400, content={"status": "error", "message": str(e)})


@app.post("/api/auth/create-user")
async def api_create_user(request: Request, current_user: dict = Depends(require_superuser)):
    """
    Création d'un utilisateur (superuser uniquement).
    Max 2 utilisateurs total. Max 1 superuser.
    """
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    email = form.get("email", "").strip()
    role = form.get("role", "user").strip()

    if not username or not password or not email:
        return JSONResponse(status_code=400, content={
            "status": "error", "message": "Tous les champs sont requis"
        })

    if len(password) < 8:
        return JSONResponse(status_code=400, content={
            "status": "error", "message": "Mot de passe min. 8 caractères"
        })

    if role not in ("superuser", "user"):
        return JSONResponse(status_code=400, content={
            "status": "error", "message": "Rôle invalide"
        })

    try:
        user = await create_user(
            username=username,
            password_hash=hash_password(password),
            email=email,
            role=role
        )
        return JSONResponse(content={
            "status": "success",
            "message": f"Utilisateur '{username}' créé",
            "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
        })
    except ValueError as e:
        return JSONResponse(status_code=400, content={"status": "error", "message": str(e)})


@app.get("/api/auth/check-setup")
async def api_check_setup():
    """Vérifie si le setup initial est nécessaire."""
    count = await count_users()
    return {"needs_setup": count == 0}


# ---------------------------------------------------------------------------
# ROUTES API — SETTINGS (protégées)
# ---------------------------------------------------------------------------
@app.get("/api/settings")
async def api_get_settings(user: dict = Depends(get_current_user)):
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

# ---------------------------------------------------------------------------
# ROUTES API — RAPPORTS (RBAC)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# ROUTES API — STATS (protégées)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# PLANIFICATEUR DE RAPPORT
# ---------------------------------------------------------------------------
async def daily_report_scheduler():
    while True:
        now = datetime.now()
        if now.hour == 0 and now.minute == 0:
            print("LogSonar: Minuit — génération du rapport quotidien...")
            await generate_daily_report()
            await asyncio.sleep(120)
        else:
            await asyncio.sleep(30)

# ---------------------------------------------------------------------------
# WEBSOCKET — AUTH PAR TOKEN JWT
# ---------------------------------------------------------------------------
@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(default="")):
    # Vérification du token JWT pour le WebSocket
    payload = decode_jwt_token(token)
    if not payload:
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
                if _should_send_alert(log_data.get("ip", ""), log_data.get("attack_type", "")):
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


@app.get("/api/ws-token")
async def api_get_ws_token(user: dict = Depends(get_current_user)):
    """Retourne un token JWT pour la connexion WebSocket."""
    token = create_jwt_token(user["id"], user["username"], user["role"])
    return JSONResponse(content={"token": token})

# ---------------------------------------------------------------------------
# INTERFACE — Redirection vers login si non auth
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def get_interface(request: Request):
    # Vérifier si l'utilisateur est authentifié
    token = request.cookies.get("access_token")
    if not token or not decode_jwt_token(token):
        # Rediriger vers la page de login
        with open("static/login.html", "r", encoding="utf-8") as f:
            content = f.read()
        return Response(
            content=content,
            media_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )
    
    with open("static/index.html", "r", encoding="utf-8") as f:
        content = f.read()
    return Response(
        content=content,
        media_type="text/html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )