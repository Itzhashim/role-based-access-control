"""Authentication endpoints: login, logout and session introspection."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import DENIED, AuditAction, record_audit
from app.config import settings
from app.database import get_db
from app.models import User
from app.schemas import LoginRequest, MessageResponse, TokenResponse, UserOut
from app.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    get_current_user,
    revoke_token,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

INVALID_CREDENTIALS = "Invalid username or password"


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.access_token_ttl_minutes * 60,
        path="/",
    )


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Verify credentials and issue a session token.

    The same message and status are returned for an unknown username, a wrong
    password and a deactivated account, so the endpoint cannot be used to
    enumerate valid accounts.
    """
    user = db.scalar(select(User).where(User.username == payload.username))

    if user is None:
        # Spend comparable time on unknown accounts to blunt timing analysis.
        verify_password(payload.password, DUMMY_PASSWORD_HASH)
        record_audit(
            db,
            action=AuditAction.LOGIN_FAILURE,
            outcome=DENIED,
            actor_username=payload.username,
            detail="unknown account",
            request=request,
        )
        raise HTTPException(status_code=401, detail=INVALID_CREDENTIALS)

    if not user.is_active or not verify_password(payload.password, user.password_hash):
        record_audit(
            db,
            action=AuditAction.LOGIN_FAILURE,
            outcome=DENIED,
            actor=user,
            detail="inactive account" if not user.is_active else "bad password",
            request=request,
        )
        raise HTTPException(status_code=401, detail=INVALID_CREDENTIALS)

    token, expires_at = create_access_token(user)
    set_session_cookie(response, token)
    record_audit(db, action=AuditAction.LOGIN_SUCCESS, actor=user, request=request)
    return TokenResponse(access_token=token, expires_at=expires_at, role=user.role)


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Revoke the presented token so it cannot be replayed after logout."""
    revoke_token(db, request.state.token_claims)
    response.delete_cookie(settings.session_cookie_name, path="/")
    record_audit(db, action=AuditAction.LOGOUT, actor=current_user, request=request)
    return MessageResponse(detail="Logged out")


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    """Return the authenticated caller's own account record."""
    return current_user
