import os
from datetime import datetime, timedelta, timezone
import bcrypt
from utils.db import init_db, get_db

DATA_DIR = "data"

def precheckes():
    os.makedirs(os.path.join(DATA_DIR, "rootca"), exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, "ssl"), exist_ok=True)
    initialize_user_store()

def initialize_user_store():
    init_db()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        print("⚠️ No users found. Creating default admin user...")
        password = "certo"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       ("admin", hashed, "admin"))
        conn.commit()
        print("✅ Default admin user created: admin / certo")

    conn.close()

