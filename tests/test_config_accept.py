"""
Risques de configuration acceptés et scans interrompus.
"""
import asyncio
import time

from app import db
from app import settings_store as S
from app.alerts import alerts
from app.vuln import scanner


async def _setup() -> int:
    await db.init_db()
    await S.load()
    await alerts.load()
    await S.set_many({"accepted_config": []})
    scan_id = await db.execute(
        "INSERT INTO vuln_scans (started_ts, finished_ts, status, summary) VALUES (?, ?, 'done', '{}')", (time.time(), time.time()))
    await db.executemany(
        "INSERT INTO config_findings (scan_id, target, check_id, severity, title, detail, fix) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(scan_id, "netfilter", "privileged", "critical", "Conteneur en mode privilégié", "", ""),
         (scan_id, "dockerapi", "docker_socket", "high", "Socket Docker monté", "", ""),
         (scan_id, "web", "no_healthcheck", "low", "Pas de healthcheck", "", "")])
    return scan_id


def test_accepted_risk_leaves_score_and_alerts():
    async def run():
        scan_id = await _setup()
        await scanner.sync_config_alerts()
        assert alerts.is_open("config:netfilter:privileged")
        assert await scanner.config_counts(scan_id) == {"critical": 1, "high": 1, "low": 1}

        await S.set_many({"accepted_config": [scanner.config_key("netfilter", "privileged")]})
        await scanner.sync_config_alerts()
        assert not alerts.is_open("config:netfilter:privileged")
        assert await scanner.config_counts(scan_id) == {"high": 1, "low": 1}

        await S.set_many({"accepted_config": []})   # on revient en arrière
        await scanner.sync_config_alerts()
        assert alerts.is_open("config:netfilter:privileged")
        await db.close_db()
    asyncio.run(run())


def test_running_scans_marked_interrupted():
    async def run():
        await db.init_db()
        sid = await db.execute("INSERT INTO vuln_scans (started_ts, status) VALUES (?, 'running')", (time.time(),))
        await scanner.mark_interrupted_scans()
        row = await db.fetchone("SELECT status, finished_ts, error FROM vuln_scans WHERE id = ?", (sid,))
        assert row["status"] == "interrupted" and row["finished_ts"] and "redémarré" in row["error"]
        await db.close_db()
    asyncio.run(run())
