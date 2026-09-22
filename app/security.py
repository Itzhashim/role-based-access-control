"""Authentication primitives: password hashing, JWT sessions and revocation.

This module answers only one question — *who is making this request?* The
separate question of *what may they do?* is answered by :mod:`app.authz`.
Keeping the two apart is the whole point of the project: authentication alone
never grants permission.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, Request
from fastapi.exceptions import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import RevokedToken, User

# Generic, non-enumerable failure message. It must never reveal whether the
# username exists, the password was wrong, or the session simply expired.
AUTH_FAILED_MESSAGE = "Authentication required"


# --- Password hashing ------------------------------------------------------


def _prepare(password: str) -> bytes:
    """Pre-hash the password so bcrypt's 72-byte input limit cannot silently
    truncate a long passphrase."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prepare(password), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(password), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


# A pre-computed hash used to keep the timing of a login attempt against an
# unknown username similar to one against a real account.
DUMMY_PASSWORD_HASH = hash_password("not-a-real-password")


# --- Brute-force resistance ------------------------------------------------


def is_locked_out(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:  # SQLite returns naive datetimes
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def register_failed_login(db: Session, user: User) -> bool:
    """Count a failed attempt and lock the account once the threshold is hit.

    Returns ``True`` if this attempt triggered a lockout. The caller still
    returns the same generic error either way, so the lock itself is not
    observable from the response.
    """
    user.failed_login_count += 1
    triggered = False
    if user.failed_login_count >= settings.max_failed_logins:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.lockout_window_minutes
        )
        user.failed_login_count = 0
        triggered = True
    db.commit()
    return triggered


def reset_failed_logins(db: Session, user: User) -> None:
    if user.failed_login_count or user.locked_until:
        user.failed_login_count = 0
        user.locked_until = None
        db.commit()


# --- JWT sessions ----------------------------------------------------------


def create_access_token(user: User) -> tuple[str, datetime]:
    """Issue a signed session token for ``user`` and return it with its expiry."""
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(minutes=settings.access_token_ttl_minutes)
    payload: dict[str, Any] = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role.value,
        "jti": uuid.uuid4().hex,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, expires_at


def decode_access_token(token: str) -> dict[str, Any] | None:
    """Return the token claims, or ``None`` if the token is invalid or expired."""
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub", "jti"]},
        )
    except jwt.PyJWTError:
        return None


def revoke_token(db: Session, claims: dict[str, Any]) -> None:
    """Add a token's ``jti`` to the blocklist so logout takes effect immediately."""
    jti = claims.get("jti")
    if not jti or db.get(RevokedToken, jti):
        return
    db.add(
        RevokedToken(
            jti=jti,
            user_id=int(claims["sub"]),
            expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
        )
    )
    db.commit()


def is_token_revoked(db: Session, jti: str) -> bool:
    return db.get(RevokedToken, jti) is not None


# --- Request authentication ------------------------------------------------


def extract_token(request: Request) -> str | None:
    """Accept a session cookie (browser portal) or a Bearer token (API client).

    Both paths converge on the same verification code, so the browser UI cannot
    be an easier target than the API.
    """
    header = request.headers.get("Authorization")
    if header and header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return request.cookies.get(settings.session_cookie_name)


def _unauthenticated() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=AUTH_FAILED_MESSAGE,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Resolve the caller's identity, or fail with a generic 401.

    Every failure mode — missing, malformed, expired, revoked token, or a
    deactivated account — returns exactly the same response.
    """
    token = extract_token(request)
    if not token:
        raise _unauthenticated()

    claims = decode_access_token(token)
    if claims is None or is_token_revoked(db, claims["jti"]):
        raise _unauthenticated()

    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise _unauthenticated()

    # The role is re-read from the database on every request: a role changed or
    # revoked by an administrator takes effect immediately, and a tampered token
    # claim cannot grant anything.
    request.state.token_claims = claims
    return user
