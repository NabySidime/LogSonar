"""Vulnérabilités, audit de configuration et certificats TLS."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import db
from ..monitor import monitor
from ..security import current_user, require_admin
from ..vuln.osv import _natural_key
from ..vuln.scanner import latest_scan, scan_state, start_scan

router = APIRouter(prefix="/api/vulns", tags=["vulnerabilities"])

SEV_SQL = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"


@router.get("/summary")
async def summary(_: dict = Depends(current_user)):
    scan = await latest_scan()
    history = await db.fetchall(
        "SELECT id, started_ts, finished_ts, status, error FROM vuln_scans ORDER BY id DESC LIMIT 10")
    top = []
    if scan:
        top = await db.fetchall(
            f"SELECT package, ecosystem, version, MIN({SEV_SQL}) AS sev_rank, COUNT(*) AS n,"
            " GROUP_CONCAT(DISTINCT fixed_version) AS fixes, GROUP_CONCAT(DISTINCT target) AS targets"
            " FROM vuln_findings WHERE scan_id = ? GROUP BY ecosystem, package, version"
            " ORDER BY sev_rank, n DESC LIMIT 15", (scan["id"],))
        for row in top:
            # Pour corriger toutes les failles du paquet, il faut la plus haute version corrigée
            fixes = [f for f in (row.pop("fixes") or "").split(",") if f]
            row["fixed_version"] = max(fixes, key=_natural_key) if fixes else ""
    return {"scan": scan, "state": scan_state.as_dict(), "history": history, "top_packages": top}


@router.get("/findings")
async def findings(
    target: Optional[str] = None, severity: Optional[str] = None, q: Optional[str] = None,
    fixable: bool = False, ecosystem: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
    _: dict = Depends(current_user),
):
    scan = await latest_scan()
    if not scan:
        return {"total": 0, "items": []}
    where, params = ["scan_id = ?"], [scan["id"]]
    if target:
        where.append("target = ?")
        params.append(target)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if ecosystem:
        where.append("ecosystem LIKE ?")
        params.append(ecosystem + "%")
    if fixable:
        where.append("fixed_version != ''")
    if q:
        where.append("(package LIKE ? OR vuln_id LIKE ? OR aliases LIKE ? OR summary LIKE ?)")
        params += [f"%{q}%"] * 4
    clause = " WHERE " + " AND ".join(where)
    total = await db.scalar(f"SELECT COUNT(*) FROM vuln_findings{clause}", params)
    rows = await db.fetchall(
        f"SELECT * FROM vuln_findings{clause} ORDER BY {SEV_SQL}, score DESC, package LIMIT ? OFFSET ?",
        (*params, limit, offset))
    return {"total": total, "items": rows}


@router.get("/config")
async def config_findings(_: dict = Depends(current_user)):
    scan = await latest_scan()
    if not scan:
        return []
    return await db.fetchall(
        f"SELECT * FROM config_findings WHERE scan_id = ? ORDER BY {SEV_SQL}, target", (scan["id"],))


@router.post("/scan")
async def scan(_: dict = Depends(require_admin)):
    if not await start_scan():
        raise HTTPException(409, "Un scan est déjà en cours.")
    return {"ok": True, "state": scan_state.as_dict()}


@router.get("/tls")
async def tls(_: dict = Depends(current_user)):
    return monitor.tls


@router.post("/tls/check")
async def tls_check(_: dict = Depends(require_admin)):
    return await monitor.check_tls()
