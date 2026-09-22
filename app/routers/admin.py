"""Administrator endpoints: accounts, roles, courses and enrollments.

Administration is the most privileged role, so it is also the most narrowly
defined: it can manage *who* exists and *what* they may teach or take, but it
holds no permission to read or write academic records. Separating the two keeps
a compromised administrator account from silently altering grades.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import AuditAction, record_audit, recent_entries
from app.authz import require_permission
from app.database import get_db
from app.models import Announcement, Course, Enrollment, Role, User
from app.permissions import Permission
from app.schemas import (
    AnnouncementCreate,
    AnnouncementOut,
    AuditLogOut,
    CourseAssign,
    CourseCreate,
    CourseOut,
    EnrollmentCreate,
    EnrollmentOut,
    RoleUpdate,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.security import hash_password
from app.serializers import announcement_out, course_out

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _get_user_or_404(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    return user


# --- Accounts --------------------------------------------------------------


@router.get("/users", response_model=list[UserOut])
def list_users(
    role: Role | None = None,
    current_user: User = Depends(require_permission(Permission.USERS_READ_ANY)),
    db: Session = Depends(get_db),
) -> list[User]:
    statement = select(User).order_by(User.username)
    if role is not None:
        statement = statement.where(User.role == role)
    return list(db.scalars(statement).all())


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> User:
    existing = db.scalar(
        select(User).where((User.username == payload.username) | (User.email == payload.email))
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="Account already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        department=payload.department,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_audit(
        db,
        action=AuditAction.USER_CREATE,
        actor=current_user,
        target_type="user",
        target_id=user.id,
        detail=f"username={user.username} role={user.role.value}",
        request=request,
    )
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> User:
    user = _get_user_or_404(db, user_id)

    if payload.is_active is False and user.id == current_user.id:
        # Refuse the change that would lock the last operator out of the portal.
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(user, field, value)
    db.commit()
    db.refresh(user)
    record_audit(
        db,
        action=AuditAction.USER_UPDATE,
        actor=current_user,
        target_type="user",
        target_id=user.id,
        detail=", ".join(f"{k}={v}" for k, v in changes.items()) or "no change",
        request=request,
    )
    return user


@router.put("/users/{user_id}/role", response_model=UserOut)
def assign_role(
    user_id: int,
    payload: RoleUpdate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.ROLES_ASSIGN)),
    db: Session = Depends(get_db),
) -> User:
    """Change a user's role.

    Self-service role changes are refused: an administrator cannot quietly move
    themselves into a role to reach data their own role forbids, and cannot
    accidentally remove the last administrator.
    """
    user = _get_user_or_404(db, user_id)
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    previous_role = user.role
    user.role = payload.role
    db.commit()
    db.refresh(user)
    record_audit(
        db,
        action=AuditAction.ROLE_ASSIGN,
        actor=current_user,
        target_type="user",
        target_id=user.id,
        detail=f"{previous_role.value} -> {user.role.value}",
        request=request,
    )
    return user


# --- Courses and enrollments -----------------------------------------------


@router.get("/courses", response_model=list[CourseOut])
def list_courses(
    current_user: User = Depends(require_permission(Permission.COURSES_MANAGE)),
    db: Session = Depends(get_db),
) -> list[CourseOut]:
    return [course_out(c) for c in db.scalars(select(Course).order_by(Course.code)).all()]


@router.post("/courses", response_model=CourseOut, status_code=status.HTTP_201_CREATED)
def create_course(
    payload: CourseCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.COURSES_MANAGE)),
    db: Session = Depends(get_db),
) -> CourseOut:
    if db.scalar(select(Course).where(Course.code == payload.code)) is not None:
        raise HTTPException(status_code=409, detail="Course already exists")
    if payload.faculty_id is not None:
        _require_faculty(db, payload.faculty_id)

    course = Course(**payload.model_dump())
    db.add(course)
    db.commit()
    db.refresh(course)
    record_audit(
        db,
        action=AuditAction.COURSE_CREATE,
        actor=current_user,
        target_type="course",
        target_id=course.id,
        detail=f"code={course.code} faculty={course.faculty_id}",
        request=request,
    )
    return course_out(course)


@router.put("/courses/{course_id}/faculty", response_model=CourseOut)
def assign_course_faculty(
    course_id: int,
    payload: CourseAssign,
    request: Request,
    current_user: User = Depends(require_permission(Permission.COURSES_MANAGE)),
    db: Session = Depends(get_db),
) -> CourseOut:
    course = db.get(Course, course_id)
    if course is None:
        raise HTTPException(status_code=404, detail="Not found")
    _require_faculty(db, payload.faculty_id)

    previous_faculty_id = course.faculty_id
    course.faculty_id = payload.faculty_id
    db.commit()
    db.refresh(course)
    record_audit(
        db,
        action=AuditAction.COURSE_ASSIGN,
        actor=current_user,
        target_type="course",
        target_id=course.id,
        detail=f"faculty {previous_faculty_id} -> {course.faculty_id}",
        request=request,
    )
    return course_out(course)


@router.post("/enrollments", response_model=EnrollmentOut, status_code=status.HTTP_201_CREATED)
def create_enrollment(
    payload: EnrollmentCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.ENROLLMENTS_MANAGE)),
    db: Session = Depends(get_db),
) -> Enrollment:
    student = _get_user_or_404(db, payload.student_id)
    if student.role is not Role.STUDENT:
        raise HTTPException(status_code=400, detail="Only students can be enrolled")
    if db.get(Course, payload.course_id) is None:
        raise HTTPException(status_code=404, detail="Not found")
    if db.scalar(
        select(Enrollment).where(
            Enrollment.student_id == payload.student_id,
            Enrollment.course_id == payload.course_id,
        )
    ):
        raise HTTPException(status_code=409, detail="Already enrolled")

    enrollment = Enrollment(student_id=payload.student_id, course_id=payload.course_id)
    db.add(enrollment)
    db.commit()
    db.refresh(enrollment)
    record_audit(
        db,
        action=AuditAction.ENROLLMENT_CREATE,
        actor=current_user,
        target_type="enrollment",
        target_id=enrollment.id,
        detail=f"student={enrollment.student_id} course={enrollment.course_id}",
        request=request,
    )
    return enrollment


@router.post(
    "/announcements", response_model=AnnouncementOut, status_code=status.HTTP_201_CREATED
)
def publish_campus_announcement(
    payload: AnnouncementCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.ANNOUNCEMENTS_WRITE_GLOBAL)),
    db: Session = Depends(get_db),
) -> AnnouncementOut:
    announcement = Announcement(
        title=payload.title,
        body=payload.body,
        course_id=None,  # campus-wide
        author_id=current_user.id,
    )
    db.add(announcement)
    db.commit()
    db.refresh(announcement)
    record_audit(
        db,
        action=AuditAction.ANNOUNCEMENT_PUBLISH,
        actor=current_user,
        target_type="announcement",
        target_id=announcement.id,
        detail="campus-wide",
        request=request,
    )
    return announcement_out(announcement)


# --- Oversight -------------------------------------------------------------


@router.get("/audit", response_model=list[AuditLogOut])
def read_audit_log(
    action: str | None = None,
    outcome: str | None = None,
    actor_id: int | None = None,
    limit: int = 100,
    current_user: User = Depends(require_permission(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> list[AuditLogOut]:
    """The audit trail, newest first. Readable only by administrators."""
    entries = recent_entries(
        db,
        limit=max(1, min(limit, 500)),
        action=action,
        outcome=outcome,
        actor_id=actor_id,
    )
    return [AuditLogOut.model_validate(entry) for entry in entries]


def _require_faculty(db: Session, faculty_id: int) -> User:
    faculty = _get_user_or_404(db, faculty_id)
    if faculty.role is not Role.FACULTY:
        raise HTTPException(status_code=400, detail="Assigned user is not faculty")
    return faculty
