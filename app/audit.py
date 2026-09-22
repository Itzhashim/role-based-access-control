"""Audit logging for sensitive operations and refused access attempts.

Authorization decisions are only half of accountability: the other half is being
able to say afterwards who did what, and who *tried*. Denials are recorded
centrally (see :mod:`app.errors`) so a new route cannot forget to log them.
"""

from __future__ import annotations

import enum

from fastapi import Request, Response
from fastapi.exception_handlers import http_exception_handler
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import AuditLog, User

#: Endpoints that write their own, richer audit entry; the generic denial
#: handler stays quiet for them so failures are not recorded twice.
SELF_AUDITING_PATHS = frozenset({"/api/auth/login"})


class AuditAction(str, enum.Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    ACCOUNT_LOCKED = "account_locked"
    LOGOUT = "logout"
    GRADE_WRITE = "grade_write"
    ANNOUNCEMENT_PUBLISH = "announcement_publish"
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    ROLE_ASSIGN = "role_assign"
    COURSE_CREATE = "course_create"
    COURSE_ASSIGN = "course_assign"
    ENROLLMENT_CREATE = "enrollment_create"
    ACCESS_DENIED = "access_denied"
    AUTH_REQUIRED = "auth_required"


ALLOWED = "allowed"
DENIED = "denied"


def client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


def record_audit(
    db: Session,
    *,
    action: AuditAction,
    outcome: str = ALLOWED,
    actor: User | None = None,
    actor_id: int | None = None,
    actor_username: str | None = None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    detail: str | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Write one audit entry. Never raises into the caller's happy path."""
    entry = AuditLog(
        actor_id=actor.id if actor else actor_id,
        actor_username=actor.username if actor else actor_username,
        actor_role=actor.role.value if actor else actor_role,
        action=action.value,
        outcome=outcome,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        detail=detail,
        method=request.method if request else None,
        path=request.url.path if request else None,
        ip_address=client_ip(request),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def record_audit_isolated(**kwargs) -> None:
    """Record an entry on a private session.

    Exception handlers run after the request's session has been torn down (and
    possibly rolled back), so denial logging opens its own short-lived session.
    A failure to log is swallowed: it must never turn a clean 403 into a 500.
    """
    db = SessionLocal()
    try:
        record_audit(db, **kwargs)
    except Exception:  # pragma: no cover - defensive
        db.rollback()
    finally:
        db.close()


def actor_from_request(request: Request) -> tuple[int | None, str | None, str | None]:
    """Best-effort identity for a request that was refused.

    The session may be missing or invalid — that is exactly the case worth
    logging — so every field is optional.
    """
    claims = getattr(request.state, "token_claims", None)
    if not claims:
        from app.security import decode_access_token, extract_token

        token = extract_token(request)
        claims = decode_access_token(token) if token else None
    if not claims:
        return None, None, None

    actor_id = int(claims["sub"]) if str(claims.get("sub", "")).isdigit() else None
    return actor_id, claims.get("username"), claims.get("role")


async def audit_denied_request(request: Request, exc) -> Response:
    """Exception handler that records every refused request.

    Logging here rather than in each route means a new endpoint cannot forget
    to audit its denials, and both 401s (no valid session) and 403s (session
    fine, permission or ownership missing) are captured.
    """
    if exc.status_code in (401, 403) and request.url.path not in SELF_AUDITING_PATHS:
        actor_id, username, role = actor_from_request(request)
        required = getattr(request.state, "denied_permission", None)
        record_audit_isolated(
            action=AuditAction.ACCESS_DENIED if exc.status_code == 403 else AuditAction.AUTH_REQUIRED,
            outcome=DENIED,
            actor_id=actor_id,
            actor_username=username,
            actor_role=role,
            target_type="endpoint",
            target_id=request.url.path,
            detail=f"status={exc.status_code}"
            + (f" required={required}" if required else ""),
            request=request,
        )
    return await http_exception_handler(request, exc)


def recent_entries(db: Session, limit: int = 100, **filters) -> list[AuditLog]:
    statement = select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
    for field, value in filters.items():
        if value is not None:
            statement = statement.where(getattr(AuditLog, field) == value)
    return list(db.scalars(statement.limit(limit)).all())
