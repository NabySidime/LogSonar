"""
Gestion des alertes : déduplication, escalade, résolution automatique, notifications.

Une alerte est identifiée par une « empreinte » (ex. "disk:/", "container:api:down").
Tant qu'elle est ouverte, une nouvelle occurrence incrémente son compteur au lieu
de créer un doublon ; on ne notifie qu'à l'ouverture ou si la gravité augmente.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Optional

from . import db, notify
from . import settings_store as S
from .hub import hub

LEVELS = {"info": 0, "warning": 1, "high": 2, "critical": 3}
# Gravité des détections (signatures) -> gravité d'alerte
FROM_DETECTION = {"low": "info", "medium": "warning", "high": "high", "critical": "critical"}

NOTIFY_BUDGET = 20          # notifications max ...
NOTIFY_WINDOW = 600         # ... par fenêtre de 10 min (anti-rafale)


class AlertManager:
    def __init__(self) -> None:
        self._open: dict[str, dict] = {}   # empreinte -> alerte ouverte (cache)
        self._sent: deque[float] = deque()
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task] = set()

    async def load(self) -> None:
        rows = await db.fetchall("SELECT * FROM alerts WHERE status != 'resolved'")
        self._open = {r["fingerprint"]: r for r in rows}

    def is_open(self, fingerprint: str) -> bool:
        return fingerprint in self._open

    def open_alerts(self) -> list[dict]:
        return sorted(self._open.values(), key=lambda a: (-LEVELS.get(a["severity"], 0), -a["last_ts"]))

    async def raise_alert(self, fingerprint: str, category: str, severity: str, title: str,
                          message: str = "", source: str = "") -> dict:
        now = time.time()
        async with self._lock:
            existing = self._open.get(fingerprint)
            if existing:
                escalated = LEVELS.get(severity, 0) > LEVELS.get(existing["severity"], 0)
                existing.update(
                    count=existing["count"] + 1, last_ts=now, message=message or existing["message"],
                    title=title, severity=severity if escalated else existing["severity"],
                )
                await db.execute(
                    "UPDATE alerts SET count = ?, last_ts = ?, message = ?, title = ?, severity = ? WHERE id = ?",
                    (existing["count"], now, existing["message"], title, existing["severity"], existing["id"]),
                )
                if escalated:
                    existing["status"] = "open"
                    await db.execute("UPDATE alerts SET status = 'open' WHERE id = ?", (existing["id"],))
                    self._notify(existing)
                hub.publish("alert", existing)
                return existing

            alert = {
                "fingerprint": fingerprint, "category": category, "severity": severity,
                "title": title, "message": message, "source": source, "status": "open",
                "count": 1, "first_ts": now, "last_ts": now, "resolved_ts": None, "notified": 0,
            }
            alert["id"] = await db.execute(
                "INSERT INTO alerts (fingerprint, category, severity, title, message, source, status, count,"
                " first_ts, last_ts) VALUES (?, ?, ?, ?, ?, ?, 'open', 1, ?, ?)",
                (fingerprint, category, severity, title, message, source, now, now),
            )
            self._open[fingerprint] = alert
        hub.publish("alert", alert)
        self._notify(alert)
        return alert

    async def resolve(self, fingerprint: str, note: str = "") -> None:
        async with self._lock:
            alert = self._open.pop(fingerprint, None)
            if not alert:
                return
            now = time.time()
            alert.update(status="resolved", resolved_ts=now)
            if note:
                alert["message"] = (alert["message"] + "\n\n" + note).strip()
            await db.execute(
                "UPDATE alerts SET status = 'resolved', resolved_ts = ?, message = ? WHERE id = ?",
                (now, alert["message"], alert["id"]),
            )
        hub.publish("alert", alert)
        if S.get("notify_resolved") and alert.get("notified"):
            self._spawn(notify.send(alert, resolved=True))

    async def resolve_prefix(self, prefix: str, keep: set[str]) -> None:
        """Résout les alertes d'une famille dont la condition a disparu."""
        for fp in [fp for fp in self._open if fp.startswith(prefix) and fp not in keep]:
            await self.resolve(fp)

    async def resolve_stale(self, category: str, older_than: float) -> None:
        cutoff = time.time() - older_than
        for fp, alert in list(self._open.items()):
            if alert["category"] == category and alert["last_ts"] < cutoff:
                await self.resolve(fp, "Résolue automatiquement : plus d'activité depuis 1 h.")

    async def set_status(self, alert_id: int, status: str) -> Optional[dict]:
        row = await db.fetchone("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if not row:
            return None
        if status == "resolved":
            await self.resolve(row["fingerprint"])
        else:
            await db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            if row["fingerprint"] in self._open:
                self._open[row["fingerprint"]]["status"] = status
        return await db.fetchone("SELECT * FROM alerts WHERE id = ?", (alert_id,))

    # -- notifications -----------------------------------------------------
    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _budget(self) -> bool:
        now = time.monotonic()
        while self._sent and now - self._sent[0] > NOTIFY_WINDOW:
            self._sent.popleft()
        if len(self._sent) >= NOTIFY_BUDGET:
            return False
        self._sent.append(now)
        return True

    def _notify(self, alert: dict) -> None:
        if LEVELS.get(alert["severity"], 0) < LEVELS.get(S.get("notify_min_severity"), 2):
            return
        if not notify.configured_channels():
            return
        if not self._budget():
            print("LogSonar: plafond de notifications atteint, alerte visible uniquement dans le dashboard.")
            return
        alert["notified"] = 1
        self._spawn(self._send_and_mark(alert))

    async def _send_and_mark(self, alert: dict) -> None:
        await notify.send(alert)
        await db.execute("UPDATE alerts SET notified = 1 WHERE id = ?", (alert["id"],))


alerts = AlertManager()
