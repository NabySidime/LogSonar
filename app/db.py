# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
Base SQLite (mode WAL), connexion unique partagée.

Les horodatages sont stockés en secondes epoch (REAL) : comparaisons et index
fiables, et l'interface les affiche dans le fuseau du navigateur.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any, Iterable, Optional

import aiosqlite

from . import config

_db: Optional[aiosqlite.Connection] = None
_write_lock = asyncio.Lock()

SCHEMA_VERSION = 4

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email          TEXT NOT NULL DEFAULT '',
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
    totp_secret    TEXT NOT NULL DEFAULT '',
    totp_enabled   INTEGER NOT NULL DEFAULT 0,
    token_version  INTEGER NOT NULL DEFAULT 0,
    created_at     REAL NOT NULL,
    last_login     REAL
);

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    container   TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    attack_type TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'medium',
    ua          TEXT NOT NULL DEFAULT '',
    raw         TEXT NOT NULL DEFAULT '',
    neutral     TEXT NOT NULL DEFAULT ''  -- code 2xx qui ne prouve pas un succès : pourquoi
);
CREATE INDEX IF NOT EXISTS idx_sec_ts ON security_events (ts);
CREATE INDEX IF NOT EXISTS idx_sec_ip ON security_events (ip);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT NOT NULL,
    category     TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT NOT NULL,
    message      TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    count        INTEGER NOT NULL DEFAULT 1,
    first_ts     REAL NOT NULL,
    last_ts      REAL NOT NULL,
    resolved_ts  REAL,
    notified     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status, last_ts);
CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts (fingerprint, status);

CREATE TABLE IF NOT EXISTS host_metrics (
    ts         REAL PRIMARY KEY,
    cpu        REAL, mem REAL, swap REAL, disk REAL,
    load1      REAL,
    net_rx     REAL, net_tx REAL,
    req_rate   REAL, err_rate REAL, attack_rate REAL
);

CREATE TABLE IF NOT EXISTS container_metrics (
    ts        REAL NOT NULL,
    name      TEXT NOT NULL,
    cpu       REAL, mem_bytes REAL, mem_pct REAL,
    PRIMARY KEY (ts, name)
);

CREATE TABLE IF NOT EXISTS vuln_scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_ts  REAL NOT NULL,
    finished_ts REAL,
    status      TEXT NOT NULL DEFAULT 'running',
    summary     TEXT NOT NULL DEFAULT '{}',
    error       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES vuln_scans(id) ON DELETE CASCADE,
    target        TEXT NOT NULL,
    target_kind   TEXT NOT NULL,
    image         TEXT NOT NULL DEFAULT '',
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    version       TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    aliases       TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'unknown',
    score         REAL,
    summary       TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_vf_scan ON vuln_findings (scan_id, severity);

CREATE TABLE IF NOT EXISTS config_findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES vuln_scans(id) ON DELETE CASCADE,
    target    TEXT NOT NULL,
    check_id  TEXT NOT NULL,
    severity  TEXT NOT NULL,
    title     TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT '',
    fix       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cf_scan ON config_findings (scan_id);

CREATE TABLE IF NOT EXISTS osv_cache (
    vuln_id    TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_ts REAL NOT NULL
);

-- Jetons d'accès en lecture seule (seule l'empreinte SHA-256 est stockée)
CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    revoked_at   REAL,
    last_used_at REAL,
    last_used_ip TEXT NOT NULL DEFAULT '',
    use_count    INTEGER NOT NULL DEFAULT 0
);
"""


async def init_db() -> None:
    global _db
    config.ensure_dirs()
    _db = await aiosqlite.connect(config.DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA synchronous=NORMAL")
    await _db.execute("PRAGMA foreign_keys=ON")
    await _db.execute("PRAGMA busy_timeout=5000")
    await _migrate_from_v1()
    await _db.executescript(SCHEMA)
    await _add_missing_columns()
    await _db.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
    )
    await _db.commit()


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None


def conn() -> aiosqlite.Connection:
    if _db is None:
        raise RuntimeError("Base de données non initialisée")
    return _db


async def fetchall(sql: str, params: Iterable[Any] = ()) -> list[dict]:
    async with conn().execute(sql, tuple(params)) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def fetchone(sql: str, params: Iterable[Any] = ()) -> Optional[dict]:
    async with conn().execute(sql, tuple(params)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def scalar(sql: str, params: Iterable[Any] = ()) -> Any:
    async with conn().execute(sql, tuple(params)) as cur:
        row = await cur.fetchone()
    return row[0] if row else None


async def execute(sql: str, params: Iterable[Any] = ()) -> int:
    """Écriture unitaire. Retourne lastrowid."""
    async with _write_lock:
        cur = await conn().execute(sql, tuple(params))
        await conn().commit()
        return cur.lastrowid


async def execute_rowcount(sql: str, params: Iterable[Any] = ()) -> int:
    async with _write_lock:
        cur = await conn().execute(sql, tuple(params))
        await conn().commit()
        return cur.rowcount


async def executemany(sql: str, rows: list[tuple]) -> None:
    if not rows:
        return
    async with _write_lock:
        await conn().executemany(sql, rows)
        await conn().commit()


async def _add_missing_columns() -> None:
    """Colonnes ajoutées après coup : CREATE TABLE IF NOT EXISTS ne modifie pas une table existante."""
    cols = {r[1] for r in await (await conn().execute("PRAGMA table_info(security_events)")).fetchall()}
    if "neutral" not in cols:  # v4
        await conn().execute("ALTER TABLE security_events ADD COLUMN neutral TEXT NOT NULL DEFAULT ''")


# ---------------------------------------------------------------------------
# MIGRATION DEPUIS LA v1
# ---------------------------------------------------------------------------
async def _migrate_from_v1() -> None:
    """
    La v1 stockait les mots de passe en SHA-256 sans sel et n'avait pas de 2FA par
    application : ses comptes ne sont PAS repris (un nouvel assistant de création
    s'affiche). Les événements d'attaque, eux, sont importés.
    """
    db = conn()
    tables = {r[0] for r in await (await db.execute("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
    if "users" in tables:
        cols = {r[1] for r in await (await db.execute("PRAGMA table_info(users)")).fetchall()}
        if "totp_secret" not in cols:
            await db.execute("ALTER TABLE users RENAME TO legacy_users_v1")
            print("LogSonar: comptes v1 archivés (legacy_users_v1) — recréez un administrateur.")
    if "critical_events" in tables:
        await db.executescript(SCHEMA)
        rows = await (await db.execute(
            "SELECT timestamp, container, ip, method, path, status, attack_type, raw_log FROM critical_events"
        )).fetchall()
        imported = []
        for r in rows:
            try:
                ts = datetime.strptime(r[0], "%Y-%m-%d %H:%M:%S").timestamp()
            except (ValueError, TypeError):
                continue
            imported.append((ts, r[1], r[2], r[3], r[4], r[5], r[6], "medium", "", r[7]))
        await db.executemany(
            "INSERT INTO security_events (ts, container, ip, method, path, status, attack_type, severity, ua, raw)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", imported,
        )
        await db.execute("ALTER TABLE critical_events RENAME TO legacy_critical_events_v1")
        await db.commit()
        print(f"LogSonar: {len(imported)} événement(s) v1 importé(s).")


async def purge_old_data() -> None:
    now = time.time()
    ev_cut = now - config.RETENTION_EVENTS_DAYS * 86400
    m_cut = now - config.RETENTION_METRICS_DAYS * 86400
    await execute("DELETE FROM security_events WHERE ts < ?", (ev_cut,))
    await execute("DELETE FROM alerts WHERE status = 'resolved' AND last_ts < ?", (ev_cut,))
    await execute("DELETE FROM host_metrics WHERE ts < ?", (m_cut,))
    await execute("DELETE FROM container_metrics WHERE ts < ?", (now - 3 * 86400,))
    await execute("DELETE FROM osv_cache WHERE fetched_ts < ?", (now - 7 * 86400,))
    # On ne garde que les 10 derniers scans de vulnérabilités
    await execute(
        "DELETE FROM vuln_scans WHERE id NOT IN (SELECT id FROM vuln_scans ORDER BY id DESC LIMIT 10)"
    )
