"""
db.py — Gestionnaire de base de données LogSonar
Singleton de connexion persistante + chiffrement Fernet pour smtp_password.
"""
import asyncio
import os
import secrets
from typing import Optional

import aiosqlite
from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
DB_PATH         = "data/logsonar.db"
_CRYPTO_KEY_PATH = "data/.secret_key"
_ENCRYPTED_KEYS  = {"smtp_password"}
_RETENTION_DAYS  = 90  # ← Durée de rétention des attaques en jours

# ---------------------------------------------------------------------------
# CHIFFREMENT FERNET
# ---------------------------------------------------------------------------
def _get_or_create_key() -> bytes:
    """Charge ou génère la clé de chiffrement Fernet (persistée sur disque)."""
    if os.path.exists(_CRYPTO_KEY_PATH):
        with open(_CRYPTO_KEY_PATH, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    os.makedirs("data", exist_ok=True)
    with open(_CRYPTO_KEY_PATH, "wb") as f:
        f.write(key)
    os.chmod(_CRYPTO_KEY_PATH, 0o600)
    print("LogSonar: Clé de chiffrement générée dans data/.secret_key")
    return key

_fernet = Fernet(_get_or_create_key())

def encrypt_value(plain: str) -> str:
    if not plain:
        return ""
    return _fernet.encrypt(plain.encode()).decode()

def decrypt_value(encrypted: str) -> str:
    if not encrypted:
        return ""
    try:
        return _fernet.decrypt(encrypted.encode()).decode()
    except Exception:
        return encrypted  # rétrocompatibilité : valeur non chiffrée (ancienne version)

# ---------------------------------------------------------------------------
# SINGLETON — CONNEXION PERSISTANTE
# ---------------------------------------------------------------------------
_db: Optional[aiosqlite.Connection] = None
_db_lock = asyncio.Lock()

async def get_db() -> aiosqlite.Connection:
    """
    Retourne la connexion persistante unique.
    Thread-safe grâce au Lock asyncio.
    La connexion est créée une seule fois au démarrage par init_db().
    """
    global _db
    if _db is None:
        raise RuntimeError(
            "LogSonar: Base de données non initialisée. "
            "Appelez init_db() dans le lifespan avant toute requête."
        )
    return _db

async def init_db() -> None:
    """
    Ouvre la connexion persistante, crée le schéma et insère les valeurs par défaut.
    À appeler UNE SEULE FOIS dans le lifespan FastAPI.
    """
    global _db
    os.makedirs("data", exist_ok=True)
    _db = await aiosqlite.connect(DB_PATH, check_same_thread=False)

    # WAL : lectures et écritures peuvent se faire simultanément sans se bloquer.
    # Réduit drastiquement les erreurs "database is locked" sous charge.
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA synchronous=NORMAL")   # bon compromis perf/durabilité
    await _db.execute("PRAGMA cache_size=-8000")     # 8 Mo de cache en mémoire
    await _db.execute("PRAGMA foreign_keys=ON")

    await _db.execute("""
        CREATE TABLE IF NOT EXISTS critical_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            container   TEXT    NOT NULL DEFAULT '',
            ip          TEXT    NOT NULL DEFAULT '',
            method      TEXT    NOT NULL DEFAULT '',
            path        TEXT    NOT NULL DEFAULT '',
            status      TEXT    NOT NULL DEFAULT '',
            attack_type TEXT    NOT NULL DEFAULT '',
            raw_log     TEXT    NOT NULL DEFAULT ''
        )
    """)
    # Index composite : accélère les requêtes des rapports (WHERE timestamp LIKE 'YYYY-MM-DD%')
    # et les recherches par IP (futures)
    await _db.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON critical_events (timestamp)
    """)
    await _db.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_ip
        ON critical_events (ip)
    """)

    await _db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
    """)

    # -----------------------------------------------------------------------
    # TABLE USERS — Auth système
    # -----------------------------------------------------------------------
    await _db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            email         TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'user' CHECK(role IN ('superuser', 'user')),
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    defaults = [
        ("alert_email",          ""),                         # Destinataire des alertes
        ("brevo_api_key",        ""),                         # Clé API Brevo (xkeysib-...)
        ("brevo_sender_email",   ""),                         # Expéditeur vérifié chez Brevo
        ("ws_token",             secrets.token_urlsafe(32)),  # Token WebSocket (inchangé)
    ]
    for key, value in defaults:
        await _db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )

    await _db.commit()
    print("LogSonar: Base de données initialisée (connexion persistante + WAL).")

async def close_db() -> None:
    """Ferme proprement la connexion. À appeler dans le lifespan (shutdown)."""
    global _db
    if _db is not None:
        await _db.close()
        _db = None
        print("LogSonar: Connexion base de données fermée.")

# ---------------------------------------------------------------------------
# ÉCRITURE — ATTAQUES
# ---------------------------------------------------------------------------
async def save_critical_event(event_data: dict) -> None:
    """Insère un événement critique. Utilise la connexion persistante partagée."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            """INSERT INTO critical_events
               (timestamp, container, ip, method, path, status, attack_type, raw_log)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_data.get("timestamp", ""),
                event_data.get("container", ""),
                event_data.get("ip",        ""),
                event_data.get("method",    ""),
                event_data.get("path",      ""),
                event_data.get("status",    ""),
                event_data.get("attack_type", ""),
                event_data.get("raw",       ""),
            ),
        )
        await db.commit()

# ---------------------------------------------------------------------------
# PURGE — Suppression des vieilles attaques (rétention 90 jours)
# ---------------------------------------------------------------------------
async def purge_old_events() -> int:
    """
    Supprime les événements critiques datant de plus de _RETENTION_DAYS jours.
    Retourne le nombre de lignes supprimées.
    """
    from datetime import datetime, timedelta
    cutoff = (datetime.now() - timedelta(days=_RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    db = await get_db()
    async with _db_lock:
        cursor = await db.execute(
            "DELETE FROM critical_events WHERE timestamp < ?",
            (cutoff,)
        )
        await db.commit()
        deleted = cursor.rowcount
    if deleted > 0:
        # VACUUM pour récupérer l'espace disque
        await db.execute("VACUUM")
        await db.commit()
        print(f"LogSonar: {deleted} événement(s) supprimé(s) (rétention {_RETENTION_DAYS} jours).")
    return deleted

# ---------------------------------------------------------------------------
# LECTURE / ÉCRITURE — SETTINGS
# ---------------------------------------------------------------------------
async def get_setting(key: str) -> str:
    """Lit un paramètre. Déchiffre automatiquement si la clé est dans _ENCRYPTED_KEYS."""
    db = await get_db()
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cursor:
        row = await cursor.fetchone()
    if not row:
        return ""
    value = row[0]
    return decrypt_value(value) if key in _ENCRYPTED_KEYS else value

async def update_setting(key: str, value: str) -> None:
    """Sauvegarde un paramètre. Chiffre automatiquement si nécessaire."""
    stored = encrypt_value(value) if (key in _ENCRYPTED_KEYS and value) else (value or "")
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, stored),
        )
        await db.commit()

# ---------------------------------------------------------------------------
# USERS — AUTH SYSTEM
# ---------------------------------------------------------------------------
async def get_user_by_username(username: str) -> Optional[dict]:
    """Récupère un utilisateur par son nom d'utilisateur."""
    db = await get_db()
    db.row_factory = aiosqlite.Row
    async with db.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username,)
    ) as cursor:
        row = await cursor.fetchone()
    return dict(row) if row else None

async def get_user_by_id(user_id: int) -> Optional[dict]:
    """Récupère un utilisateur par son ID."""
    db = await get_db()
    db.row_factory = aiosqlite.Row
    async with db.execute(
        "SELECT * FROM users WHERE id = ? AND is_active = 1",
        (user_id,)
    ) as cursor:
        row = await cursor.fetchone()
    return dict(row) if row else None

async def create_user(username: str, password_hash: str, email: str, role: str = "user") -> dict:
    """Crée un nouvel utilisateur. Lève une exception si limite atteinte."""
    db = await get_db()

    # Vérifier la limite de 2 utilisateurs ACTIFS max
    async with db.execute("SELECT COUNT(*) FROM users WHERE is_active = 1") as cursor:
        count = (await cursor.fetchone())[0]
    if count >= 2:
        raise ValueError("Nombre maximum d'utilisateurs atteint (2).")

    # Vérifier qu'il n'y a pas déjà un superuser ACTIF
    if role == "superuser":
        async with db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'superuser' AND is_active = 1"
        ) as cursor:
            superuser_count = (await cursor.fetchone())[0]
        if superuser_count >= 1:
            raise ValueError("Un superuser existe déjà. Impossible d'en créer un second.")

    async with _db_lock:
        await db.execute(
            """INSERT INTO users (username, password_hash, email, role)
               VALUES (?, ?, ?, ?)""",
            (username, password_hash, email, role),
        )
        await db.commit()

    return await get_user_by_username(username)

async def count_users() -> int:
    """Retourne le nombre d'utilisateurs actifs."""
    db = await get_db()
    async with db.execute("SELECT COUNT(*) FROM users WHERE is_active = 1") as cursor:
        return (await cursor.fetchone())[0]

async def has_superuser() -> bool:
    """Vérifie si un superuser existe déjà."""
    db = await get_db()
    async with db.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'superuser'"
    ) as cursor:
        return (await cursor.fetchone())[0] > 0

async def delete_user(user_id: int) -> None:
    """Supprime physiquement un utilisateur."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "DELETE FROM users WHERE id = ?",
            (user_id,),
        )
        await db.commit()

# ---------------------------------------------------------------------------
# OTP — Codes temporaires (stockés en mémoire pour l'instant, ou en DB si tu préfères)
# -----------------------------------------------------------------------
_OTP_STORE: dict[str, tuple[str, float]] = {}  # username -> (code, expiry_timestamp)

def store_otp(username: str, code: str, ttl_seconds: int = 300) -> None:
    """Stocke un code OTP avec expiration (5 min par défaut)."""
    import time
    _OTP_STORE[username] = (code, time.time() + ttl_seconds)

def verify_otp(username: str, code: str) -> bool:
    """Vérifie un code OTP et le supprime après validation."""
    import time
    if username not in _OTP_STORE:
        return False
    stored_code, expiry = _OTP_STORE[username]
    if time.time() > expiry:
        del _OTP_STORE[username]
        return False
    if stored_code == code:
        del _OTP_STORE[username]
        return True
    return False

# ---------------------------------------------------------------------------
# LECTURE — RAPPORTS
# ---------------------------------------------------------------------------
async def get_events_for_date(date_str: str) -> list:
    """Récupère tous les événements d'une journée (format YYYY-MM-DD)."""
    db = await get_db()
    db.row_factory = aiosqlite.Row
    async with db.execute(
        "SELECT * FROM critical_events WHERE timestamp LIKE ? ORDER BY timestamp DESC",
        (f"{date_str}%",),
    ) as cursor:
        return await cursor.fetchall()

# ---------------------------------------------------------------------------
# LECTURE — STATS (pour le futur dashboard)
# ---------------------------------------------------------------------------
async def get_stats_today(date_str: str) -> dict:
    """Retourne les stats de la journée : total, top IPs, top types."""
    db = await get_db()
    async with db.execute(
        "SELECT COUNT(*) FROM critical_events WHERE timestamp LIKE ?",
        (f"{date_str}%",),
    ) as cursor:
        total = (await cursor.fetchone())[0]

    async with db.execute(
        """SELECT ip, COUNT(*) as cnt
           FROM critical_events WHERE timestamp LIKE ?
           GROUP BY ip ORDER BY cnt DESC LIMIT 5""",
        (f"{date_str}%",),
    ) as cursor:
        top_ips = [{"ip": r[0], "count": r[1]} for r in await cursor.fetchall()]

    async with db.execute(
        """SELECT attack_type, COUNT(*) as cnt
           FROM critical_events WHERE timestamp LIKE ?
           GROUP BY attack_type ORDER BY cnt DESC""",
        (f"{date_str}%",),
    ) as cursor:
        by_type = [{"type": r[0], "count": r[1]} for r in await cursor.fetchall()]

    return {"total": total, "top_ips": top_ips, "by_type": by_type}

# ---------------------------------------------------------------------------
# STATS ENRICHIES — DASHBOARD
# ---------------------------------------------------------------------------
async def get_dashboard_data(today_str: str, since_date_str: str) -> dict:
    """
    Retourne toutes les données nécessaires au dashboard en une seule fonction
    (évite les allers-retours multiples vers la BDD).

    today_str      : 'YYYY-MM-DD'  — filtre pour les stats du jour
    since_date_str : 'YYYY-MM-DD'  — date de début pour la tendance 7 jours
    """
    db = await get_db()

    # --- KPIs du jour ---
    async with db.execute(
        "SELECT COUNT(*) FROM critical_events WHERE timestamp LIKE ?",
        (f"{today_str}%",)
    ) as cur:
        attacks_today = (await cur.fetchone())[0]

    async with db.execute(
        "SELECT COUNT(DISTINCT ip) FROM critical_events WHERE timestamp LIKE ?",
        (f"{today_str}%",)
    ) as cur:
        unique_ips_today = (await cur.fetchone())[0]

    async with db.execute(
        """SELECT attack_type, COUNT(*) as cnt
           FROM critical_events WHERE timestamp LIKE ?
           GROUP BY attack_type ORDER BY cnt DESC LIMIT 1""",
        (f"{today_str}%",)
    ) as cur:
        row = await cur.fetchone()
        top_type_today = row[0] if row else "—"

    async with db.execute(
        """SELECT container, COUNT(*) as cnt
           FROM critical_events WHERE timestamp LIKE ?
           GROUP BY container ORDER BY cnt DESC LIMIT 1""",
        (f"{today_str}%",)
    ) as cur:
        row = await cur.fetchone()
        top_container_today = row[0] if row else "—"

    # --- Volume par heure (aujourd'hui, 0-23) ---
    async with db.execute(
        """SELECT CAST(substr(timestamp, 12, 2) AS INTEGER) as hour, COUNT(*) as cnt
           FROM critical_events WHERE timestamp LIKE ?
           GROUP BY hour ORDER BY hour""",
        (f"{today_str}%",)
    ) as cur:
        rows = await cur.fetchall()
    # Remplir les heures manquantes avec 0
    hours_map = {r[0]: r[1] for r in rows}
    by_hour = [{"hour": h, "count": hours_map.get(h, 0)} for h in range(24)]

    # --- Volume par jour (7 derniers jours) ---
    async with db.execute(
        """SELECT substr(timestamp, 1, 10) as day, COUNT(*) as cnt
           FROM critical_events WHERE timestamp >= ?
           GROUP BY day ORDER BY day""",
        (since_date_str,)
    ) as cur:
        rows = await cur.fetchall()
    by_day = [{"day": r[0], "count": r[1]} for r in rows]

    # --- Répartition par type (tous temps) ---
    async with db.execute(
        """SELECT attack_type, COUNT(*) as cnt
           FROM critical_events
           GROUP BY attack_type ORDER BY cnt DESC"""
    ) as cur:
        rows = await cur.fetchall()
    by_type = [{"type": r[0], "count": r[1]} for r in rows]

    # --- Top 5 IPs attaquantes (tous temps) ---
    async with db.execute(
        """SELECT ip, COUNT(*) as cnt
           FROM critical_events
           GROUP BY ip ORDER BY cnt DESC LIMIT 5"""
    ) as cur:
        rows = await cur.fetchall()
    top_ips = [{"ip": r[0], "count": r[1]} for r in rows]

    # --- Feed : 8 dernières attaques ---
    async with db.execute(
        """SELECT timestamp, ip, attack_type, container, path, status
           FROM critical_events ORDER BY id DESC LIMIT 8"""
    ) as cur:
        rows = await cur.fetchall()
    recent = [
        {"timestamp": r[0], "ip": r[1], "attack_type": r[2],
         "container": r[3], "path": r[4], "status": r[5]}
        for r in rows
    ]

    return {
        "kpis": {
            "attacks_today":     attacks_today,
            "unique_ips_today":  unique_ips_today,
            "top_type_today":    top_type_today,
            "top_container":     top_container_today,
        },
        "by_hour":  by_hour,
        "by_day":   by_day,
        "by_type":  by_type,
        "top_ips":  top_ips,
        "recent":   recent,
    }