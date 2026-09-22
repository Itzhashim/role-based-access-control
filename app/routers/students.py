"""Student endpoints.

Every route here is scoped twice: by permission (only the student role holds
``grades:read_own``) and by ownership (the record must belong to the caller).
Paths take an explicit ``student_id`` rather than only ``/me`` precisely so the
ownership check is exercised — this is where an insecure direct object
reference would show up.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.authz import ensure_self, get_own_enrollment, require_permission
from app.database import get_db
from app.models import Announcement, Course, Enrollment, User
from app.permissions import Permission
from app.schemas import AnnouncementOut, CourseOut, GradeOut, UserOut
from app.serializers import announcement_out, course_out, grade_out

router = APIRouter(prefix="/api/students", tags=["student"])


@router.get("/{student_id}/profile", response_model=UserOut)
def read_profile(
    student_id: int,
    current_user: User = Depends(require_permission(Permission.PROFILE_READ_OWN)),
) -> User:
    ensure_self(current_user, student_id)
    return current_user


@router.get("/{student_id}/courses", response_model=list[CourseOut])
def list_enrolled_courses(
    student_id: int,
    current_user: User = Depends(require_permission(Permission.COURSES_READ_ENROLLED)),
    db: Session = Depends(get_db),
) -> list[CourseOut]:
    ensure_self(current_user, student_id)
    courses = db.scalars(
        select(Course).join(Enrollment).where(Enrollment.student_id == current_user.id)
    ).all()
    return [course_out(course) for course in courses]


@router.get("/{student_id}/grades", response_model=list[GradeOut])
def list_own_grades(
    student_id: int,
    current_user: User = Depends(require_permission(Permission.GRADES_READ_OWN)),
    db: Session = Depends(get_db),
) -> list[GradeOut]:
    """All of the caller's grades. The query itself is scoped to the caller, so
    even a bug in the loop below could not return another student's row."""
    ensure_self(current_user, student_id)
    enrollments = db.scalars(
        select(Enrollment).where(Enrollment.student_id == current_user.id)
    ).all()
    return [grade_out(e.grade, e) for e in enrollments if e.grade is not None]


@router.get("/{student_id}/courses/{course_id}/grade", response_model=GradeOut)
def read_course_grade(
    student_id: int,
    course_id: int,
    current_user: User = Depends(require_permission(Permission.GRADES_READ_OWN)),
    db: Session = Depends(get_db),
) -> GradeOut:
    ensure_self(current_user, student_id)
    enrollment = get_own_enrollment(db, current_user, course_id)
    if enrollment.grade is None:
        # The caller is entitled to this course, the grade simply is not in yet.
        raise HTTPException(status_code=404, detail="Not found")
    return grade_out(enrollment.grade, enrollment)


@router.get("/{student_id}/announcements", response_model=list[AnnouncementOut])
def list_announcements(
    student_id: int,
    current_user: User = Depends(require_permission(Permission.COURSES_READ_ENROLLED)),
    db: Session = Depends(get_db),
) -> list[AnnouncementOut]:
    """Campus-wide announcements plus those of the caller's own courses."""
    ensure_self(current_user, student_id)
    enrolled_course_ids = select(Enrollment.course_id).where(
        Enrollment.student_id == current_user.id
    )
    announcements = db.scalars(
        select(Announcement)
        .where(
            or_(
                Announcement.course_id.is_(None),
                Announcement.course_id.in_(enrolled_course_ids),
            )
        )
        .order_by(Announcement.created_at.desc())
    ).all()
    return [announcement_out(a) for a in announcements]
