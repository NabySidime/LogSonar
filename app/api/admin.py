"""Paramètres, notifications et rapports."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from .. import config, notify, reports
from .. import settings_store as S
from ..security import current_user, require_admin

router = APIRouter(prefix="/api", tags=["admin"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_FIELDS = {"discord_webhook", "slack_webhook", "webhook_url"}
_INT_RANGES = {
    "cpu_warn": (10, 100), "cpu_crit": (10, 100), "mem_warn": (10, 100), "mem_crit": (10, 100),
    "disk_warn": (10, 100), "disk_crit": (10, 100), "metric_duration_min": (1, 60),
    "traffic_rpm_threshold": (0, 10_000_000), "traffic_spike_factor": (2, 100), "traffic_min_rpm": (1, 1_000_000),
    "error_rate_threshold": (1, 100), "attack_campaign_threshold": (5, 10000), "tls_warn_days": (1, 90),
}


@router.get("/settings")
async def get_settings(_: dict = Depends(require_admin)):
    return {**S.public_view(), "channels": notify.configured_channels()}


@router.put("/settings")
async def put_settings(values: dict[str, Any], _: dict = Depends(require_admin)):
    clean: dict[str, Any] = {}
    errors = []
    for key, value in values.items():
        if key not in S.DEFAULTS or key in ("muted_containers", "ingest_token", "accepted_config"):
            continue
        if key in S.SECRET_KEYS and value in (None, "__keep__"):
            continue  # champ secret laissé vide dans le formulaire : on garde la valeur actuelle
        if key in _INT_RANGES:
            try:
                value = int(value)
            except (TypeError, ValueError):
                errors.append(f"{key} : nombre attendu")
                continue
            lo, hi = _INT_RANGES[key]
            if not lo <= value <= hi:
                errors.append(f"{key} : doit être entre {lo} et {hi}")
                continue
        if key in _URL_FIELDS and value and not str(value).startswith("https://"):
            errors.append(f"{key} : l'URL doit commencer par https://")
            continue
        if key in ("email_to",) and value:
            if not all(_EMAIL_RE.match(a.strip()) for a in str(value).split(",") if a.strip()):
                errors.append("email_to : adresse invalide")
                continue
        if key == "brevo_sender" and value and not _EMAIL_RE.match(str(value)):
            errors.append("brevo_sender : adresse invalide")
            continue
        if key == "notify_min_severity" and value not in ("info", "warning", "high", "critical"):
            continue
        clean[key] = value
    for a, b in (("cpu_warn", "cpu_crit"), ("mem_warn", "mem_crit"), ("disk_warn", "disk_crit")):
        warn, crit = clean.get(a, S.get(a)), clean.get(b, S.get(b))
        if int(warn) >= int(crit):
            errors.append(f"Le seuil d'avertissement ({a}) doit être inférieur au seuil critique ({b}).")
    if errors:
        raise HTTPException(422, " · ".join(errors))
    await S.set_many(clean)
    return {**S.public_view(), "channels": notify.configured_channels()}


@router.post("/settings/test/{channel}")
async def test_channel(channel: str, _: dict = Depends(require_admin)):
    if channel not in notify.CHANNELS:
        raise HTTPException(404, "Canal inconnu.")
    now = time.time()
    alert = {
        "id": 0, "category": "test", "severity": "info", "title": "Test de notification",
        "message": f"Si vous lisez ce message, le canal « {channel} » de {config.INSTANCE_NAME} fonctionne.",
        "source": "LogSonar", "first_ts": now, "last_ts": now, "count": 1,
    }
    result = await notify.send(alert, only=channel)
    if not result.get(channel):
        raise HTTPException(502, "Échec de l'envoi : vérifiez la configuration (détails dans les logs de LogSonar).")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Rapports
# ---------------------------------------------------------------------------
_REPORT_RE = re.compile(r"^rapport_\d{4}-\d{2}-\d{2}\.html$")


@router.get("/reports")
async def list_reports(_: dict = Depends(current_user)):
    if not config.REPORT_DIR.exists():
        return []
    files = sorted((f for f in config.REPORT_DIR.iterdir() if _REPORT_RE.match(f.name)), key=lambda f: f.name, reverse=True)
    out = []
    for f in files:
        item = {"filename": f.name, "date": f.name[8:18], "size": f.stat().st_size}
        try:
            item.update(json.loads(f.with_suffix(".json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
        out.append(item)
    return out


@router.post("/reports/generate")
async def generate_report(date: Optional[str] = None, send: bool = False, _: dict = Depends(require_admin)):
    if date:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(422, "Date invalide (AAAA-MM-JJ).")
    filename = await reports.generate(date, send=send)
    if not filename:
        raise HTTPException(404, "Aucune donnée pour cette date.")
    return {"filename": filename}


def _report_path(filename: str):
    if not _REPORT_RE.match(filename):
        raise HTTPException(404, "Rapport introuvable.")
    path = (config.REPORT_DIR / filename).resolve()
    if path.parent != config.REPORT_DIR.resolve() or not path.exists():
        raise HTTPException(404, "Rapport introuvable.")
    return path


@router.get("/reports/{filename}")
async def view_report(filename: str, download: bool = False, _: dict = Depends(current_user)):
    path = _report_path(filename)
    headers = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"}
    if download:
        return FileResponse(path, media_type="text/html", filename=filename, headers=headers)
    return FileResponse(path, media_type="text/html", headers=headers)


@router.delete("/reports/{filename}")
async def delete_report(filename: str, _: dict = Depends(require_admin)):
    path = _report_path(filename)
    path.unlink()
    path.with_suffix(".json").unlink(missing_ok=True)
    return {"ok": True}
