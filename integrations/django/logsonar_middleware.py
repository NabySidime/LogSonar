"""
LogSonar — middleware Django.

Les logs d'accès (Nginx, Gunicorn...) ne contiennent pas le corps des requêtes :
une injection SQL envoyée dans un formulaire POST y est invisible. Ce middleware
transmet chaque requête POST/PUT/PATCH/DELETE à LogSonar, qui y cherche des attaques.

- Aucun impact sur l'application : l'envoi se fait en arrière-plan, par lots. Si
  LogSonar est arrêté ou injoignable, les requêtes sont simplement ignorées.
- Données bancaires jamais transmises (numéro de carte, CVV, IBAN...) : leurs
  valeurs sont remplacées par "***" avant l'envoi.
- LogSonar ne stocke jamais le corps complet : seulement un court extrait de
  l'attaque détectée, et jamais la valeur d'un mot de passe ou d'un jeton.
- Fichiers envoyés (upload) : seuls leurs noms sont transmis, pas leur contenu.

Installation
------------
1. Copiez ce fichier dans votre projet, par exemple `monprojet/logsonar_middleware.py`.
2. Dans settings.py, ajoutez-le À LA FIN de MIDDLEWARE :
       MIDDLEWARE = [
           ...,
           "monprojet.logsonar_middleware.LogSonarMiddleware",
       ]
3. Variables d'environnement du conteneur de l'application :
       LOGSONAR_URL=http://logsonar:8000      # adresse de LogSonar sur le réseau Docker
       LOGSONAR_TOKEN=lsi_...                  # Paramètres > Analyse des requêtes POST
       LOGSONAR_SOURCE=tikipay                 # nom affiché dans LogSonar (facultatif)
       LOGSONAR_EXCLUDE_PATHS=/admin/,/webhook/ # préfixes d'URL non transmis (facultatif)
Sans LOGSONAR_URL ou LOGSONAR_TOKEN, le middleware ne fait rien.

Que exclure ? Les webhooks signés de prestataires (paiement...) et les espaces
d'administration où l'on saisit du HTML (articles, emails) : ce contenu légitime
ressemblerait à du XSS.
"""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
import urllib.request

LOGSONAR_URL = os.environ.get("LOGSONAR_URL", "").rstrip("/")
LOGSONAR_TOKEN = os.environ.get("LOGSONAR_TOKEN", "")
LOGSONAR_SOURCE = os.environ.get("LOGSONAR_SOURCE", "django")
EXCLUDE_PATHS = tuple(p.strip() for p in os.environ.get("LOGSONAR_EXCLUDE_PATHS", "").split(",") if p.strip())

METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_BODY = 64 * 1024          # au-delà, le corps n'est pas lu (gros envois, fichiers)
MAX_VALUE = 4096              # longueur maximale transmise par champ
BATCH_SIZE = 100
FLUSH_SECONDS = 2.0

# Données bancaires : jamais transmises, même à LogSonar (PCI DSS)
_NEVER_SEND = re.compile(r"card|cvv|cvc|cvn|iban|ccnum|exp_?(?:month|year)|(?<![a-z])(?:pan|bic|expiry)(?![a-z])", re.I)

_queue: "queue.Queue[dict]" = queue.Queue(maxsize=5000)
_worker_pid: int | None = None
_worker_lock = threading.Lock()


def _mask(value, key: str = ""):
    if key and _NEVER_SEND.search(key):
        return "***"
    if isinstance(value, dict):
        return {k: _mask(v, str(k)) for k, v in list(value.items())[:500]}
    if isinstance(value, list):
        return [_mask(v, key) for v in value[:200]]
    if isinstance(value, str):
        return value[:MAX_VALUE]
    return value


def _send(batch: list[dict]) -> None:
    data = json.dumps({"source": LOGSONAR_SOURCE, "events": batch}).encode()
    req = urllib.request.Request(
        LOGSONAR_URL + "/api/ingest", data=data, method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + LOGSONAR_TOKEN},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


def _worker() -> None:
    while True:
        batch = [_queue.get()]
        deadline = time.monotonic() + FLUSH_SECONDS
        while len(batch) < BATCH_SIZE:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(_queue.get(timeout=remaining))
            except queue.Empty:
                break
        try:
            _send(batch)
        except Exception:
            pass  # LogSonar indisponible : on n'affecte jamais l'application


def _ensure_worker() -> None:
    # Gunicorn crée ses workers par fork : chaque processus a besoin de son propre thread.
    global _worker_pid
    if _worker_pid == os.getpid():
        return
    with _worker_lock:
        if _worker_pid != os.getpid():
            threading.Thread(target=_worker, name="logsonar", daemon=True).start()
            _worker_pid = os.getpid()


def _read_body(request):
    ctype = (request.META.get("CONTENT_TYPE") or "").lower()
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if ctype.startswith("multipart/form-data"):
        # request.POST et request.FILES sont déjà analysés par Django : on n'envoie que
        # les champs texte et les noms des fichiers.
        fields = {k: request.POST.getlist(k) for k in request.POST}
        files = {k: [f.name for f in request.FILES.getlist(k)] for k in request.FILES}
        return {**fields, **{f"{k}(fichier)": v for k, v in files.items()}}
    if length > MAX_BODY:
        return None
    raw = request.body  # mis en cache par Django : la vue peut toujours le lire
    if not raw:
        return None
    text = raw[:MAX_BODY].decode("utf-8", "replace")
    if "json" in ctype:
        try:
            return json.loads(text)
        except ValueError:
            return text
    if ctype.startswith("application/x-www-form-urlencoded"):
        return {k: request.POST.getlist(k) for k in request.POST}
    return text


class LogSonarMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.enabled = bool(LOGSONAR_URL and LOGSONAR_TOKEN)

    def __call__(self, request):
        if not self.enabled or request.method not in METHODS or request.path.startswith(EXCLUDE_PATHS):
            return self.get_response(request)
        ctype = (request.META.get("CONTENT_TYPE") or "").lower()
        body = None
        if not ctype.startswith("multipart/form-data"):
            # Lu avant la vue : ensuite le flux peut avoir été consommé
            try:
                body = _read_body(request)
            except Exception:
                body = None
        response = self.get_response(request)
        try:
            if ctype.startswith("multipart/form-data"):
                body = _read_body(request)
            _ensure_worker()
            _queue.put_nowait({
                "method": request.method,
                "path": request.get_full_path()[:4096],
                "status": response.status_code,
                "ip": request.META.get("REMOTE_ADDR", ""),
                "xff": request.META.get("HTTP_X_FORWARDED_FOR", ""),
                "ua": request.META.get("HTTP_USER_AGENT", "")[:500],
                "referer": request.META.get("HTTP_REFERER", "")[:1000],
                "body": _mask(body),
            })
        except Exception:
            pass  # file pleine ou requête illisible : on ne bloque jamais la réponse
        return response
