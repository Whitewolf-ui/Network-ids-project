"""
auth.py — Authentication for the Whitewolf Security dashboard.

Single-admin-account model: PBKDF2-HMAC-SHA256 password hashing with a random
salt per user, and opaque session tokens stored server-side (Supabase) and
handed to the browser as an HTTP-only cookie.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import Request, Response

from app import database

PBKDF2_ITERATIONS = 200_000
SESSION_COOKIE_NAME = "whitewolf_session"
SESSION_DURATION_DAYS = 7


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password with PBKDF2-HMAC-SHA256. Returns (hash, salt)."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    )
    return digest.hex(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Verify a password against its stored hash."""
    computed, _ = hash_password(password, salt)
    return secrets.compare_digest(computed, expected_hash)


def create_session(user_id: int) -> tuple[str, datetime]:
    """Create a new session for a user. Returns (session_id, expires_at)."""
    session_id = secrets.token_urlsafe(32)
    now = datetime.now()
    expires = now + timedelta(days=SESSION_DURATION_DAYS)
    database.create_auth_session(
        session_id=session_id,
        user_id=user_id,
        created_at=now.isoformat(),
        expires_at=expires.isoformat(),
    )
    return session_id, expires


def get_user_from_request(request: Request) -> dict | None:
    """Extract session cookie and return the associated user, or None."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    return database.get_auth_session_user(session_id)


def logout(request: Request) -> None:
    """Invalidate the current session."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        database.delete_auth_session(session_id)


def set_session_cookie(response: Response, session_id: str, expires: datetime) -> None:
    """Attach the session cookie to a response."""
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        expires=int(expires.timestamp()),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Remove the session cookie from the client."""
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
