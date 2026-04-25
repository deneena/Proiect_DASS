import sqlite3
from pathlib import Path
from flask import g, request
from datetime import datetime, timezone
#import database

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        db.executescript(f.read())
    db.commit()
    db.close()

def log_action(user_id, action, resource, resource_id):
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_logs (user_id, action, resource, resource_id, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            resource,
            str(resource_id),
            datetime.now(timezone.utc),
            request.remote_addr if request else "unknown"
        )
    )
    db.commit()