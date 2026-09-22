"""Faculty endpoints, scoped to the courses the caller is assigned to teach.

Faculty hold course-wide permissions (``grades:write_course``), so the object
check here is *assignment* rather than ownership of a single record: the course
must name the caller as its instructor, and the student must be on its roster.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authz import (
    ensure_self,
    get_assigned_course,
    get_enrollment_in_course,
    require_permission,
)
from app.database import get_db
from app.models import Announcement, Course, Grade, User
from app.permissions import Permission
from app.schemas import (
    AnnouncementCreate,
    AnnouncementOut,
    CourseOut,
    GradeOut,
    GradeUpsert,
    RosterEntry,
)
from app.serializers import announcement_out, course_out, grade_out

router = APIRouter(prefix="/api/faculty", tags=["faculty"])


@router.get("/{faculty_id}/courses", response_model=list[CourseOut])
def list_assigned_courses(
    faculty_id: int,
    current_user: User = Depends(require_permission(Permission.COURSES_READ_ASSIGNED)),
    db: Session = Depends(get_db),
) -> list[CourseOut]:
    ensure_self(current_user, faculty_id)
    courses = db.scalars(select(Course).where(Course.faculty_id == current_user.id)).all()
    return [course_out(course) for course in courses]


@router.get("/courses/{course_id}/roster", response_model=list[RosterEntry])
def read_roster(
    course_id: int,
    current_user: User = Depends(require_permission(Permission.ROSTER_READ_ASSIGNED)),
    db: Session = Depends(get_db),
) -> list[RosterEntry]:
    course = get_assigned_course(db, current_user, course_id)
    return [
        RosterEntry(
            enrollment_id=enrollment.id,
            student_id=enrollment.student_id,
            student_name=enrollment.student.full_name,
            score=enrollment.grade.score if enrollment.grade else None,
            letter=enrollment.grade.letter if enrollment.grade else None,
        )
        for enrollment in course.enrollments
    ]


@router.get("/courses/{course_id}/grades", response_model=list[GradeOut])
def list_course_grades(
    course_id: int,
    current_user: User = Depends(require_permission(Permission.GRADES_READ_COURSE)),
    db: Session = Depends(get_db),
) -> list[GradeOut]:
    course = get_assigned_course(db, current_user, course_id)
    return [
        grade_out(enrollment.grade, enrollment)
        for enrollment in course.enrollments
        if enrollment.grade is not None
    ]


@router.put("/courses/{course_id}/grades", response_model=GradeOut)
def upsert_grade(
    course_id: int,
    payload: GradeUpsert,
    current_user: User = Depends(require_permission(Permission.GRADES_WRITE_COURSE)),
    db: Session = Depends(get_db),
) -> GradeOut:
    """Record or update a grade for a student on the caller's own course."""
    get_assigned_course(db, current_user, course_id)
    enrollment = get_enrollment_in_course(db, course_id, payload.student_id)

    grade = enrollment.grade
    if grade is None:
        grade = Grade(enrollment_id=enrollment.id, score=payload.score, letter="F")
        db.add(grade)

    grade.score = payload.score
    grade.letter = Grade.letter_for(payload.score)
    grade.comment = payload.comment
    grade.updated_by_id = current_user.id
    db.commit()
    db.refresh(grade)
    return grade_out(grade, enrollment)


@router.post(
    "/courses/{course_id}/announcements",
    response_model=AnnouncementOut,
    status_code=status.HTTP_201_CREATED,
)
def publish_course_announcement(
    course_id: int,
    payload: AnnouncementCreate,
    current_user: User = Depends(require_permission(Permission.ANNOUNCEMENTS_WRITE_COURSE)),
    db: Session = Depends(get_db),
) -> AnnouncementOut:
    """Publish to one of the caller's own courses.

    ``course_id`` comes from the path and the body's ``course_id`` is ignored,
    so the request cannot be redirected to another instructor's course.
    """
    get_assigned_course(db, current_user, course_id)
    announcement = Announcement(
        title=payload.title,
        body=payload.body,
        course_id=course_id,
        author_id=current_user.id,
    )
    db.add(announcement)
    db.commit()
    db.refresh(announcement)
    return announcement_out(announcement)
