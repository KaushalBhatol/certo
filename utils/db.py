import sqlite3
import os

DB_PATH = "data/app.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT DEFAULT '',
        email TEXT DEFAULT ''
    )
    """)

    # Migrate existing databases that lack the new columns
    existing = {row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()}
    if "full_name" not in existing:
        cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''")
    if "email" not in existing:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
    if "mfa_secret" not in existing:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT NULL")
    if "mfa_enabled" not in existing:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")
    if "enabled" not in existing:
        cursor.execute("ALTER TABLE users ADD COLUMN enabled INTEGER DEFAULT 1")
    if "auto_logout" not in existing:
        cursor.execute("ALTER TABLE users ADD COLUMN auto_logout INTEGER DEFAULT 0")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        used INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS root_cas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        path TEXT NOT NULL
    )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ssl_certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            root_ca_name TEXT NOT NULL,
            path TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS branding (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        org_name TEXT DEFAULT '',
        logo_path TEXT DEFAULT '',
        primary_color TEXT DEFAULT '#6366f1',
        sidebar_color TEXT DEFAULT '#0f172a'
    )
    """)
    cursor.execute("INSERT OR IGNORE INTO branding (id, org_name, logo_path) VALUES (1, '', '')")
    try:
        cursor.execute("ALTER TABLE branding ADD COLUMN primary_color TEXT DEFAULT '#6366f1'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE branding ADD COLUMN sidebar_color TEXT DEFAULT '#0f172a'")
    except Exception:
        pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT DEFAULT '',
        details TEXT DEFAULT ''
    )
    """)

    conn.commit()
    conn.close()
