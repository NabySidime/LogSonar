import docker
import asyncio
import re
import os
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, Response, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from db import init_db, save_critical_event, get_setting, update_setting
from mailer import send_critical_alert
from reporter import generate_daily_report

# --- LE CERVEAU ---
LOG_PATTERN = re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*\[(?P<timestamp>[^\]]+)\]\s"(?P<method>[A-Z]+)\s(?P<path>.+?)\sHTTP/[^"]+"\s(?P<status>\d{3})')
ATTACK_SIGNATURES = {
    "Tentative d'Injection SQL": r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|select\s+.*\s+from|insert\s+into|'.*--)",
    "Tentative de Cross-Site Scripting (XSS)": r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|alert\()",
    "Tentative de Path Traversal": r"(\.\.\/|\.\.\\|%2e%2e)",
    "Scan de vulnérabilités (Bot)": r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster)",
    "Recherche de fichiers sensibles": r"(?i)(/etc/passwd|/\.env|/wp-admin|/phpmyadmin|\.git|\.htaccess)",
    "Alerte interne de l'application": r"(?i)(SuspiciousOperation|BadRequest)",
    "Tentative de falsification (CSRF)": r"(?i)(csrf.*failed|csrf.*missing)"
}

def analyze_log(raw_log):
    result = {"is_web": False, "ip": "N/A", "method": "", "path": "", "status": "", "timestamp": "", "is_attack": False, "attack_type": None, "raw": raw_log}
    match = LOG_PATTERN.search(raw_log)
    if match:
        # On convertit "26/Jun/2026:20:21:22 +0000" en "2026-06-26 20:21:22"
        raw_ts = match.group("timestamp").split(" ")[0] # On enlève le fuseau horaire pour le parsing
        try:
            clean_ts = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            clean_ts = raw_ts # Au cas où le format changerait un jour

        result.update({
            "is_web": True, 
            "ip": match.group("ip"), 
            "method": match.group("method"), 
            "path": match.group("path").split("?")[0], 
            "status": match.group("status"), 
            "timestamp": clean_ts # NOUVEAU : On injecte la date formatée pour la BDD
        })
        
        for attack_name, pattern in ATTACK_SIGNATURES.items():
            if re.search(pattern, result["path"]) or re.search(pattern, raw_log):
                result.update({"is_attack": True, "attack_type": attack_name})
                break
    return result

# --- APPLICATION ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("LogSonar: Initialisation de la base de données...")
    await init_db()
    yield

app = FastAPI(title="LogSonar", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

def get_docker_client():
    try:
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock'); client.ping(); return client
    except: pass
    try:
        client = docker.DockerClient(base_url='tcp://host.docker.internal:2375'); client.ping(); return client
    except: pass
    raise Exception("LogSonar: Impossible de se connecter à Docker.")

def strip_ansi_codes(text): return re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('', text)

async def docker_log_reader(queue: asyncio.Queue):
    try:
        client = get_docker_client()
        containers = [c for c in client.containers.list() if 'logsonar' not in c.name.lower()]
        def read_container_logs(container_name):
            try:
                container = client.containers.get(container_name)
                for line in container.logs(stream=True, follow=True, tail=20):
                    clean_line = strip_ansi_codes(line.decode("utf-8").strip())
                    if clean_line:
                        analyzed_data = analyze_log(clean_line)
                        analyzed_data["container"] = container_name
                        queue.put_nowait(analyzed_data)
            except Exception as e: print(f"Erreur lecture {container_name}: {e}")
        tasks = [asyncio.to_thread(read_container_logs, c.name) for c in containers]
        await asyncio.gather(*tasks)
    except Exception as e: print(f"ERREUR CRITIQUE -> {e}")

# --- ROUTES API ---
@app.get("/api/settings")
async def api_get_settings():
    pwd = await get_setting('smtp_password')
    return {
        "alert_email": await get_setting('alert_email'), "smtp_host": await get_setting('smtp_host'),
        "smtp_port": await get_setting('smtp_port'), "smtp_user": await get_setting('smtp_user'),
        "smtp_password": "********" if pwd else ""
    }

@app.post("/api/settings")
async def api_save_settings(request: Request):
    form = await request.form()
    await update_setting('alert_email', form.get("alert_email"))
    await update_setting('smtp_host', form.get("smtp_host"))
    await update_setting('smtp_port', form.get("smtp_port"))
    await update_setting('smtp_user', form.get("smtp_user"))
    if form.get("smtp_password") and form.get("smtp_password") != "********":
        await update_setting('smtp_password', form.get("smtp_password"))
    return JSONResponse(content={"status": "success"})

@app.post("/api/settings/test")
async def api_test_email():
    test_data = {"attack_type": "Test de configuration", "ip": "127.0.0.1", "container": "Système", "method": "TEST", "path": "/", "status": "200", "timestamp": "Maintenant", "raw": "Si vous lisez ceci, la configuration SMTP de LogSonar est parfaite !"}
    await send_critical_alert(test_data)
    return JSONResponse(content={"status": "test_sent"})

# --- PLANIFICATEUR DE RAPPORT (Tâche de fond) ---
async def daily_report_scheduler():
    while True:
        now = datetime.now()
        # Si il est exactement 00h00 (avec une marge de 59 secondes)
        if now.hour == 0 and now.minute == 0:
            print("LogSonar: Il est minuit, génération du rapport quotidien...")
            await generate_daily_report()
            # On attend 2 minutes pour ne pas générer le rapport 60 fois pendant la minute 00
            await asyncio.sleep(120) 
        else:
            # On vérifie l'heure toutes les 30 secondes
            await asyncio.sleep(30)

@app.on_event("startup")
async def start_scheduler():
    asyncio.create_task(daily_report_scheduler())

# --- ROUTE POUR TESTER LE RAPPORT ---
@app.get("/api/reports/generate")
async def api_generate_report():
    filename = await generate_daily_report()
    if filename:
        return JSONResponse(content={"status": "success", "filename": filename})
    return JSONResponse(content={"status": "no_events"})


# --- GESTION DES RAPPORTS ---
REPORT_DIR = "data/reports"

@app.get("/api/reports")
async def api_list_reports():
    if not os.path.exists(REPORT_DIR):
        return []
    files = [f for f in os.listdir(REPORT_DIR) if f.endswith(".html")]
    # On trie par ordre décroissant (les plus récents en premier)
    files.sort(reverse=True)
    return [{"filename": f} for f in files]

@app.get("/api/reports/view/{filename}")
async def api_view_report(filename: str):
    filepath = os.path.join(REPORT_DIR, filename)
    if os.path.exists(filepath):
        return FileResponse(filepath, media_type='text/html')
    return JSONResponse(status_code=404, content={"error": "Rapport non trouvé"})

@app.delete("/api/reports/{filename}")
async def api_delete_report(filename: str):
    filepath = os.path.join(REPORT_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return JSONResponse(content={"status": "deleted"})
    return JSONResponse(status_code=404, content={"error": "Rapport non trouvé"})


# --- WEBSOCKET & INTERFACE ---
@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    log_queue = asyncio.Queue()
    stream_task = asyncio.create_task(docker_log_reader(log_queue))
    try:
        while True:
            log_data = await log_queue.get()
            if log_data.get("is_attack"):
                asyncio.create_task(save_critical_event(log_data))
                asyncio.create_task(send_critical_alert(log_data))
            try: await websocket.send_json(log_data)
            except: break 
    except WebSocketDisconnect: pass
    finally: stream_task.cancel()

@app.get("/", response_class=HTMLResponse)
async def get_interface():
    with open("static/index.html", "r", encoding="utf-8") as f: content = f.read()
    return Response(content=content, media_type="text/html", headers={"Cache-Control": "no-cache, no-store, must-revalidate"})