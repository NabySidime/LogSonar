"""Données de surveillance : vue d'ensemble, serveur, conteneurs, trafic, menaces, alertes."""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .. import db, notify, score
from .. import settings_store as S
from ..alerts import SECRET_LABELS, alerts
from ..collectors import docker_watch as D
from ..collectors.host import get_sampler
from ..detection.signatures import EXPLANATIONS
from ..monitor import monitor
from ..security import current_user, require_admin
from ..traffic import traffic
from ..vuln.scanner import config_counts, latest_scan, scan_state

router = APIRouter(prefix="/api", tags=["monitoring"])

RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "14d": 14 * 86400}


def _today_start() -> float:
    return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


@router.get("/overview")
async def overview(_: dict = Depends(current_user)):
    t0 = _today_start()
    scan = await latest_scan()
    open_alerts = alerts.open_alerts()
    cfg_counts = None
    if scan:
        cfg_counts = await config_counts(scan["id"])
    attacks_today = await db.scalar("SELECT COUNT(*) FROM security_events WHERE ts >= ?", (t0,))
    ips_today = await db.scalar("SELECT COUNT(DISTINCT ip) FROM security_events WHERE ts >= ? AND ip != ''", (t0,))
    top_types = await db.fetchall(
        "SELECT attack_type, COUNT(*) AS n FROM security_events WHERE ts >= ? GROUP BY attack_type ORDER BY n DESC LIMIT 6", (t0,))
    recent = await db.fetchall(
        "SELECT ts, container, ip, method, path, status, attack_type, severity FROM security_events ORDER BY id DESC LIMIT 8")
    containers = monitor.containers
    return {
        "score": score.compute(scan["summary"] if scan else None, open_alerts, monitor.host_now, monitor.tls, cfg_counts),
        "host": monitor.host_now,
        "host_info": get_sampler().info,
        "alerts": open_alerts[:10],
        "alerts_count": len(open_alerts),
        "attacks_today": attacks_today,
        "attacker_ips_today": ips_today,
        "top_attack_types": top_types,
        "recent_attacks": recent,
        "traffic": traffic.summary(60),
        "containers": {
            "total": len(containers),
            "running": sum(1 for c in containers if c["state"] == "running"),
            "unhealthy": sum(1 for c in containers if "unhealthy" in c.get("status", "")),
            "stopped": sum(1 for c in containers if c["state"] in ("exited", "dead")),
        },
        "docker": {"connected": D.state.connected, "error": D.state.last_error, "info": monitor.docker_info},
        "scan": {"last": {"id": scan["id"], "finished": scan["finished_ts"], **scan["summary"]} if scan else None,
                 "state": scan_state.as_dict()},
        "tls": monitor.tls,
        "notifications": {"channels": notify.configured_channels(), "unreadable": [SECRET_LABELS.get(k, k) for k in S.unreadable_secrets()]},
    }


@router.get("/host")
async def host(range: str = "1h", _: dict = Depends(current_user)):
    seconds = RANGES.get(range, 3600)
    since = time.time() - seconds
    rows = await db.fetchall("SELECT * FROM host_metrics WHERE ts >= ? ORDER BY ts", (since,))
    # Agrégation pour garder environ 300 points par graphique
    step = max(60, int(seconds / 300 // 60 * 60))
    if step > 60 and rows:
        buckets: dict[int, list[dict]] = {}
        for r in rows:
            buckets.setdefault(int(r["ts"] // step * step), []).append(r)
        agg = []
        for ts, items in sorted(buckets.items()):
            row = {"ts": ts}
            for key in ("cpu", "mem", "swap", "disk", "load1", "net_rx", "net_tx", "req_rate", "err_rate", "attack_rate"):
                vals = [i[key] for i in items if i[key] is not None]
                if key in ("req_rate", "err_rate", "attack_rate"):
                    row[key] = round(sum(vals) / len(vals), 1) if vals else 0
                    row[key + "_max"] = max(vals) if vals else 0
                else:
                    row[key] = round(sum(vals) / len(vals), 2) if vals else None
            agg.append(row)
        rows = agg
    return {"info": get_sampler().info, "now": monitor.host_now, "history": rows, "step": step,
            "docker_df": monitor.docker_df, "docker_info": monitor.docker_info}


@router.get("/host/processes")
async def processes(_: dict = Depends(current_user)):
    import asyncio
    return await asyncio.to_thread(get_sampler().top_processes, 10)


@router.get("/containers")
async def containers(_: dict = Depends(current_user)):
    return {"containers": monitor.containers, "connected": D.state.connected, "error": D.state.last_error,
            "traffic": {c["container"]: c for c in traffic.summary(60)["containers"]}}


@router.get("/containers/{name}/history")
async def container_history(name: str, range: str = "6h", _: dict = Depends(current_user)):
    since = time.time() - RANGES.get(range, 6 * 3600)
    return await db.fetchall(
        "SELECT ts, cpu, mem_bytes, mem_pct FROM container_metrics WHERE name = ? AND ts >= ? ORDER BY ts", (name, since))


class MuteIn(BaseModel):
    name: str
    muted: bool


@router.post("/containers/mute")
async def mute(body: MuteIn, _: dict = Depends(require_admin)):
    muted = set(S.get("muted_containers"))
    if body.muted:
        muted.add(body.name)
    else:
        muted.discard(body.name)
    await S.set_many({"muted_containers": sorted(muted)})
    monitor._sync_now.set()
    return {"muted": sorted(muted)}


@router.get("/traffic")
async def traffic_view(minutes: int = Query(60, ge=5, le=60), _: dict = Depends(current_user)):
    return traffic.summary(minutes)


# ---------------------------------------------------------------------------
# Menaces
# ---------------------------------------------------------------------------
def _event_filters(q: Optional[str], attack_type: Optional[str], ip: Optional[str], severity: Optional[str],
                   container: Optional[str], since: Optional[float], until: Optional[float]) -> tuple[str, list]:
    where, params = [], []
    if q:
        where.append("(path LIKE ? OR raw LIKE ? OR ip LIKE ? OR ua LIKE ?)")
        params += [f"%{q}%"] * 4
    for col, val in (("attack_type", attack_type), ("ip", ip), ("severity", severity), ("container", container)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    if since:
        where.append("ts >= ?")
        params.append(since)
    if until:
        where.append("ts < ?")
        params.append(until)
    return (" WHERE " + " AND ".join(where)) if where else "", params


@router.get("/security/events")
async def events(
    q: Optional[str] = None, attack_type: Optional[str] = None, ip: Optional[str] = None,
    severity: Optional[str] = None, container: Optional[str] = None,
    since: Optional[float] = None, until: Optional[float] = None,
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
    _: dict = Depends(current_user),
):
    where, params = _event_filters(q, attack_type, ip, severity, container, since, until)
    total = await db.scalar(f"SELECT COUNT(*) FROM security_events{where}", params)
    rows = await db.fetchall(
        f"SELECT * FROM security_events{where} ORDER BY id DESC LIMIT ? OFFSET ?", (*params, limit, offset))
    return {"total": total, "items": rows}


@router.get("/security/stats")
async def security_stats(days: int = Query(7, ge=1, le=90), _: dict = Depends(current_user)):
    since = (datetime.now() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    by_type = await db.fetchall(
        "SELECT attack_type, severity, COUNT(*) AS n FROM security_events WHERE ts >= ? GROUP BY attack_type ORDER BY n DESC", (since,))
    top_ips = await db.fetchall(
        "SELECT ip, COUNT(*) AS n, COUNT(DISTINCT attack_type) AS types, MAX(ts) AS last_ts,"
        " SUM(CASE WHEN status LIKE '2%' THEN 1 ELSE 0 END) AS success"
        " FROM security_events WHERE ts >= ? AND ip != '' GROUP BY ip ORDER BY n DESC LIMIT 15", (since,))
    rows = await db.fetchall("SELECT ts FROM security_events WHERE ts >= ?", (since,))
    days_count: dict[str, int] = {}
    for r in rows:
        d = datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d")
        days_count[d] = days_count.get(d, 0) + 1
    timeline = []
    for i in range(days):
        d = (datetime.now() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        timeline.append({"day": d, "count": days_count.get(d, 0)})
    by_container = await db.fetchall(
        "SELECT container, COUNT(*) AS n FROM security_events WHERE ts >= ? GROUP BY container ORDER BY n DESC LIMIT 10", (since,))
    return {"by_type": by_type, "top_ips": top_ips, "timeline": timeline, "by_container": by_container,
            "explanations": EXPLANATIONS}


# ---------------------------------------------------------------------------
# Alertes
# ---------------------------------------------------------------------------
@router.get("/alerts")
async def list_alerts(
    status: Literal["active", "resolved", "all"] = "active",
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
    _: dict = Depends(current_user),
):
    if status == "active":
        where = "WHERE status != 'resolved'"
    elif status == "resolved":
        where = "WHERE status = 'resolved'"
    else:
        where = ""
    total = await db.scalar(f"SELECT COUNT(*) FROM alerts {where}")
    rows = await db.fetchall(
        f"SELECT * FROM alerts {where} ORDER BY CASE status WHEN 'resolved' THEN 1 ELSE 0 END,"
        " CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, last_ts DESC"
        " LIMIT ? OFFSET ?", (limit, offset))
    return {"total": total, "items": rows}


class AlertStatusIn(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


@router.post("/alerts/{alert_id}/status")
async def alert_status(alert_id: int, body: AlertStatusIn, _: dict = Depends(current_user)):
    row = await alerts.set_status(alert_id, body.status)
    if not row:
        raise HTTPException(404, "Alerte introuvable.")
    return row


@router.get("/system")
async def system(_: dict = Depends(current_user)):
    from .. import __version__
    return {
        "version": __version__,
        "uptime": time.time() - monitor.started,
        "lines_processed": monitor.lines_total,
        "watched_containers": monitor.watcher.watched_names(),
        "docker_connected": D.state.connected,
        "host_mode": get_sampler().info.get("host_mode"),
        "rootfs_mode": get_sampler().info.get("rootfs_mode"),
    }
