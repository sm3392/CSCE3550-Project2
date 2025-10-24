import sqlite3
from datetime import datetime
DB_FILE = "totally_not_my_privateKeys.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def insert_key(pem_str: str, exp: int):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_str, exp))
    conn.commit()
    conn.close()

def get_key_row(expired: bool = False):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    now = int(datetime.utcnow().timestamp())
    if expired:
        cur.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1", (now,))
    else:
        cur.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1", (now,))
    row = cur.fetchone()
    conn.close()
    return row

def get_all_valid_keys():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    now = int(datetime.utcnow().timestamp())
    cur.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid", (now,))
    rows = cur.fetchall()
    conn.close()
    return rows
