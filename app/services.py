"""Operations shared by the JSON API and the server-rendered portal.

Both front doors call the same functions, so the browser path can never be a
softer target than the API: the assignment check, the roster check and the audit
entry happen here, once.
"""

from __future__ import annotations

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from sqlalchemy import select

from app.audit import DENIED, AuditAction, record_audit
from app.authz import get_assigned_course, get_enrollment_in_course
from app.models import Enrollment, Grade, Role, User
from app.security import (
    DUMMY_PASSWORD_HASH,
    is_locked_out,
    register_failed_login,
    reset_failed_logins,
    verify_password,
)


def authenticate(
    db: Session, *, username: str, password: str, request: Request | None = None
) -> User | None:
    """Verify credentials, audit the attempt and apply lockout.

    Returns ``None`` for every failure — unknown account, wrong password,
    deactivated account, locked account — so callers cannot accidentally build
    a response that distinguishes them.
    """
    user = db.scalar(select(User).where(User.username == username))

    if user is None:
        # Spend comparable time on unknown accounts to blunt timing analysis.
        verify_password(password, DUMMY_PASSWORD_HASH)
        record_audit(
            db,
            action=AuditAction.LOGIN_FAILURE,
            outcome=DENIED,
            actor_username=username,
            detail="unknown account",
            request=request,
        )
        return None

    if is_locked_out(user):
        record_audit(
            db,
            action=AuditAction.LOGIN_FAILURE,
            outcome=DENIED,
            actor=user,
            detail="account temporarily locked",
            request=request,
        )
        return None

    if not user.is_active or not verify_password(password, user.password_hash):
        locked = user.is_active and register_failed_login(db, user)
        record_audit(
            db,
            action=AuditAction.ACCOUNT_LOCKED if locked else AuditAction.LOGIN_FAILURE,
            outcome=DENIED,
            actor=user,
            detail="inactive account" if not user.is_active else "bad password",
            request=request,
        )
        return None

    reset_failed_logins(db, user)
    record_audit(db, action=AuditAction.LOGIN_SUCCESS, actor=user, request=request)
    return user


def upsert_grade(
    db: Session,
    *,
    faculty: User,
    course_id: int,
    student_id: int,
    score: float,
    comment: str | None,
    request: Request | None = None,
) -> tuple[Grade, Enrollment]:
    """Record a grade, but only on a course the caller teaches, for a student
    who is actually on that roster."""
    course = get_assigned_course(db, faculty, course_id)
    enrollment = get_enrollment_in_course(db, course_id, student_id)

    grade = enrollment.grade
    previous = grade.score if grade else None
    if grade is None:
        grade = Grade(enrollment_id=enrollment.id, score=score, letter="F")
        db.add(grade)

    grade.score = score
    grade.letter = Grade.letter_for(score)
    grade.comment = comment
    grade.updated_by_id = faculty.id
    db.commit()
    db.refresh(grade)

    record_audit(
        db,
        action=AuditAction.GRADE_WRITE,
        actor=faculty,
        target_type="grade",
        target_id=grade.id,
        detail=(
            f"{course.code} student={student_id} "
            f"{'created' if previous is None else f'{previous} ->'} {grade.score}"
        ),
        request=request,
    )
    return grade, enrollment


def assign_role(
    db: Session,
    *,
    administrator: User,
    target_user: User,
    new_role: Role,
    request: Request | None = None,
) -> User:
    """Change a user's role, refusing self-service changes."""
    if target_user.id == administrator.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    previous_role = target_user.role
    target_user.role = new_role
    db.commit()
    db.refresh(target_user)

    record_audit(
        db,
        action=AuditAction.ROLE_ASSIGN,
        actor=administrator,
        target_type="user",
        target_id=target_user.id,
        detail=f"{previous_role.value} -> {target_user.role.value}",
        request=request,
    )
    return target_user


def set_account_active(
    db: Session,
    *,
    administrator: User,
    target_user: User,
    is_active: bool,
    request: Request | None = None,
) -> User:
    if not is_active and target_user.id == administrator.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    target_user.is_active = is_active
    db.commit()
    db.refresh(target_user)

    record_audit(
        db,
        action=AuditAction.USER_UPDATE,
        actor=administrator,
        target_type="user",
        target_id=target_user.id,
        detail=f"is_active={is_active}",
        request=request,
    )
    return target_user
