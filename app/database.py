"""
database.py — Supabase-backed data layer for the Network IDS dashboard.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.supabase_client import supabase


# ── Initialization ─────────────────────────────────────────────────

def init_db() -> None:
    """
    No-op: Supabase tables are created/managed via the Supabase SQL Editor.
    This function exists only to satisfy the startup hook in main.py.
    """
    pass


# ── Alerts ─────────────────────────────────────────────────────────

def insert_alert(user_id, alert_type, source_ip, dest_port=None, unique_ports=None, details=""):
    supabase.table("alerts").insert({
        "user_id": user_id,
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": source_ip,
        "dest_port": dest_port,
        "unique_ports": unique_ports,
        "details": details,
    }).execute()


def get_recent_alerts(user_id, limit=50):
    result = supabase.table("alerts") \
        .select("*") \
        .eq("user_id", user_id) \
        .order("id", desc=True) \
        .limit(limit) \
        .execute()
    
    if result is None or not hasattr(result, "data") or result.data is None:
        return []
    return result.data


def clear_alerts(user_id):
    supabase.table("alerts") \
        .delete() \
        .eq("user_id", user_id) \
        .execute()


# ── Stats ──────────────────────────────────────────────────────────

def get_stats(user_id):
    # Total alerts
    total_result = supabase.table("alerts") \
        .select("id", count="exact") \
        .eq("user_id", user_id) \
        .execute()
    total = total_result.count if hasattr(total_result, "count") and total_result.count is not None else 0

    # Unique IPs
    unique_ips_result = supabase.rpc("count_distinct_source_ips", {"p_user_id": user_id}).execute()
    unique_ips = unique_ips_result.data if unique_ips_result.data is not None else 0

    # Alerts in last hour
    one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    last_hour_result = supabase.table("alerts") \
        .select("id", count="exact") \
        .gte("timestamp", one_hour_ago) \
        .eq("user_id", user_id) \
        .execute()
    last_hour = last_hour_result.count if hasattr(last_hour_result, "count") and last_hour_result.count is not None else 0

    # Port scans
    port_scans_result = supabase.table("alerts") \
        .select("id", count="exact") \
        .eq("alert_type", "port_scan") \
        .eq("user_id", user_id) \
        .execute()
    port_scans = port_scans_result.count if hasattr(port_scans_result, "count") and port_scans_result.count is not None else 0

    # Sensitive port hits
    sensitive_result = supabase.table("alerts") \
        .select("id", count="exact") \
        .eq("alert_type", "sensitive_port") \
        .eq("user_id", user_id) \
        .execute()
    sensitive = sensitive_result.count if hasattr(sensitive_result, "count") and sensitive_result.count is not None else 0

    # Top 5 IPs
    top_ips_result = supabase.rpc("get_top_ips", {"p_user_id": user_id, "p_limit": 5}).execute()
    top_ips = top_ips_result.data if top_ips_result.data is not None else []

    return {
        "total_alerts": total,
        "unique_ips": unique_ips,
        "alerts_last_hour": last_hour,
        "port_scans": port_scans,
        "sensitive_port_hits": sensitive,
        "top_ips": top_ips,
    }


# ── Chart Data ─────────────────────────────────────────────────────

def get_chart_data(user_id, minutes=30):
    since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    
    result = supabase.table("alerts") \
        .select("timestamp") \
        .gte("timestamp", since) \
        .eq("user_id", user_id) \
        .order("timestamp") \
        .execute()
    
    rows = result.data if result is not None and hasattr(result, "data") and result.data is not None else []

    buckets = {}
    now = datetime.now()
    for i in range(minutes, -1, -1):
        t = (now - timedelta(minutes=i)).strftime("%H:%M")
        buckets[t] = 0

    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        key = ts.strftime("%H:%M")
        if key in buckets:
            buckets[key] += 1

    return {"labels": list(buckets.keys()), "values": list(buckets.values())}


# ── Capture Sessions ───────────────────────────────────────────────

def start_session():
    result = supabase.table("sessions").insert({
        "started_at": datetime.now().isoformat(),
    }).execute()
    
    if result is None or not hasattr(result, "data") or not result.data:
        raise RuntimeError("Failed to start session")
    return result.data[0]["id"]


def stop_session(session_id):
    supabase.table("sessions") \
        .update({"stopped_at": datetime.now().isoformat()}) \
        .eq("id", session_id) \
        .execute()


# ── Users ──────────────────────────────────────────────────────────

def any_users_exist():
    result = supabase.table("users") \
        .select("id", count="exact") \
        .limit(1) \
        .execute()
    count = result.count if hasattr(result, "count") and result.count is not None else 0
    return count > 0


def create_user(username, email, password_hash, salt):
    result = supabase.table("users").insert({
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "salt": salt,
        "iface": "lo",
        "created_at": datetime.now().isoformat(),
    }).execute()
    
    if result is None or not hasattr(result, "data") or not result.data:
        raise RuntimeError("Failed to create user")
    return result.data[0]["id"]


def get_user_by_username(username):
    try:
        result = supabase.table("users") \
            .select("*") \
            .eq("username", username) \
            .maybe_single() \
            .execute()
    except Exception:
        return None
    
    if result is None or not hasattr(result, "data"):
        return None
    return result.data


def get_user_by_email(email: str) -> dict | None:
    try:
        result = supabase.table("users") \
            .select("*") \
            .eq("email", email) \
            .maybe_single() \
            .execute()
    except Exception:
        return None
    
    if result is None or not hasattr(result, "data"):
        return None
    return result.data


def get_user_by_id(user_id):
    try:
        result = supabase.table("users") \
            .select("*") \
            .eq("id", user_id) \
            .maybe_single() \
            .execute()
    except Exception:
        return None
    
    if result is None or not hasattr(result, "data"):
        return None
    return result.data


def update_user_profile(user_id, email, iface):
    supabase.table("users") \
        .update({"email": email, "iface": iface}) \
        .eq("id", user_id) \
        .execute()


def update_user_password(user_id, password_hash, salt):
    supabase.table("users") \
        .update({"password_hash": password_hash, "salt": salt}) \
        .eq("id", user_id) \
        .execute()


# ── Auth Sessions ──────────────────────────────────────────────────

def create_auth_session(session_id, user_id, created_at, expires_at):
    supabase.table("auth_sessions").insert({
        "session_id": session_id,
        "user_id": user_id,
        "created_at": created_at,
        "expires_at": expires_at,
    }).execute()


def get_auth_session_user(session_id):
    try:
        result = supabase.table("auth_sessions") \
            .select("*, users(*)") \
            .eq("session_id", session_id) \
            .gt("expires_at", datetime.now().isoformat()) \
            .maybe_single() \
            .execute()
    except Exception:
        return None
    
    if result is None or not hasattr(result, "data") or result.data is None:
        return None
    
    return result.data.get("users")


def delete_auth_session(session_id):
    supabase.table("auth_sessions") \
        .delete() \
        .eq("session_id", session_id) \
        .execute()
    
def create_user_from_auth(email: str, password_hash: str, salt: str) -> dict:
    """Wrapper for auth.py compatibility — uses email as username."""
    user_id = create_user(email, email, password_hash, salt)
    return {"id": user_id, "email": email}