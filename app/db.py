import aiosqlite

DB_PATH = "data/logsonar.db"

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS critical_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, container TEXT, ip TEXT, method TEXT, 
                path TEXT, status TEXT, attack_type TEXT, raw_log TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT
            )
        """)
        await db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_email', '')")
        await db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_host', 'smtp.gmail.com')")
        await db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_port', '587')")
        await db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_user', '')")
        await db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_password', '')")
        await db.commit()

async def save_critical_event(event_data):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO critical_events (timestamp, container, ip, method, path, status, attack_type, raw_log) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_data.get("timestamp", ""), event_data.get("container", ""), event_data.get("ip", ""), 
             event_data.get("method", ""), event_data.get("path", ""), event_data.get("status", ""), 
             event_data.get("attack_type", ""), event_data.get("raw", ""))
        )
        await db.commit()

async def get_setting(key):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else ""

# NOUVEAU : Pour sauvegarder les paramètres depuis l'interface
async def update_setting(key, value):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        await db.commit()