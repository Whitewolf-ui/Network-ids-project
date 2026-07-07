"""
database.py — SQLite persistence layer for the Network IDS dashboard.
"""
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "ids_data.db"

_lock = threading.Lock()


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            dest_port INTEGER,
            unique_ports INTEGER,
            details TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            stopped_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            iface TEXT NOT NULL DEFAULT 'lo',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def insert_alert(user_id, alert_type, source_ip, dest_port=None, unique_ports=None, details=""):
    with _lock:
        conn = get_connection()
        conn.execute(
            """INSERT INTO alerts (user_id, timestamp, alert_type, source_ip, dest_port, unique_ports, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, datetime.now().isoformat(), alert_type, source_ip, dest_port, unique_ports, details),
        )
        conn.commit()
        conn.close()


def get_recent_alerts(user_id, limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats(user_id):
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) c FROM alerts WHERE user_id = ?", (user_id,)).fetchone()["c"]
    unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) c FROM alerts WHERE user_id = ?", (user_id,)).fetchone()["c"]
    one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    last_hour = conn.execute(
        "SELECT COUNT(*) c FROM alerts WHERE timestamp >= ? AND user_id = ?", (one_hour_ago, user_id)
    ).fetchone()["c"]
    port_scans = conn.execute(
        "SELECT COUNT(*) c FROM alerts WHERE alert_type = 'port_scan' AND user_id = ?", (user_id,)
    ).fetchone()["c"]
    sensitive = conn.execute(
        "SELECT COUNT(*) c FROM alerts WHERE alert_type = 'sensitive_port' AND user_id = ?", (user_id,)
    ).fetchone()["c"]
    top_ips = conn.execute(
        """SELECT source_ip, COUNT(*) c FROM alerts WHERE user_id = ?
           GROUP BY source_ip ORDER BY c DESC LIMIT 5""", (user_id,)
    ).fetchall()
    conn.close()
    return {
        "total_alerts": total,
        "unique_ips": unique_ips,
        "alerts_last_hour": last_hour,
        "port_scans": port_scans,
        "sensitive_port_hits": sensitive,
        "top_ips": [dict(r) for r in top_ips],
    }


def get_chart_data(user_id, minutes=30):
    """Alert counts bucketed per minute for the last `minutes` minutes."""
    conn = get_connection()
    since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    rows = conn.execute(
        "SELECT timestamp FROM alerts WHERE timestamp >= ? AND user_id = ? ORDER BY timestamp",
        (since, user_id),
    ).fetchall()
    conn.close()

    buckets = {}
    now = datetime.now()
    for i in range(minutes, -1, -1):
        t = (now - timedelta(minutes=i)).strftime("%H:%M")
        buckets[t] = 0

    for r in rows:
        ts = datetime.fromisoformat(r["timestamp"])
        key = ts.strftime("%H:%M")
        if key in buckets:
            buckets[key] += 1

    return {"labels": list(buckets.keys()), "values": list(buckets.values())}


def start_session():
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO sessions (started_at) VALUES (?)", (datetime.now().isoformat(),)
    )
    conn.commit()
    session_id = cur.lastrowid
    conn.close()
    return session_id


def stop_session(session_id):
    conn = get_connection()
    conn.execute(
        "UPDATE sessions SET stopped_at = ? WHERE id = ?",
        (datetime.now().isoformat(), session_id),
    )
    conn.commit()
    conn.close()


def clear_alerts(user_id):
    with _lock:
        conn = get_connection()
        conn.execute("DELETE FROM alerts WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()


# ---------- users ----------

def any_users_exist():
    conn = get_connection()
    row = conn.execute("SELECT COUNT(*) c FROM users").fetchone()
    conn.close()
    return row["c"] > 0


def create_user(username, email, password_hash, salt):
    with _lock:
        conn = get_connection()
        cur = conn.execute(
            """INSERT INTO users (username, email, password_hash, salt, iface, created_at)
               VALUES (?, ?, ?, ?, 'lo', ?)""",
            (username, email, password_hash, salt, datetime.now().isoformat()),
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        return user_id


def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_profile(user_id, email, iface):
    with _lock:
        conn = get_connection()
        conn.execute(
            "UPDATE users SET email = ?, iface = ? WHERE id = ?",
            (email, iface, user_id),
        )
        conn.commit()
        conn.close()


def update_user_password(user_id, password_hash, salt):
    with _lock:
        conn = get_connection()
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
            (password_hash, salt, user_id),
        )
        conn.commit()
        conn.close()


# ---------- auth sessions ----------

def create_auth_session(session_id, user_id, created_at, expires_at):
    with _lock:
        conn = get_connection()
        conn.execute(
            "INSERT INTO auth_sessions (session_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (session_id, user_id, created_at, expires_at),
        )
        conn.commit()
        conn.close()


def get_auth_session_user(session_id):
    conn = get_connection()
    row = conn.execute(
        """SELECT u.* FROM auth_sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.session_id = ? AND s.expires_at > ?""",
        (session_id, datetime.now().isoformat()),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_auth_session(session_id):
    with _lock:
        conn = get_connection()
        conn.execute("DELETE FROM auth_sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        conn.close()
