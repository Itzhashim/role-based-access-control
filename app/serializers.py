"""Helpers that turn ORM objects into response schemas.

Building responses explicitly keeps related data (course code, student name)
in the payload without ever handing a raw model to the serialiser.
"""

from __future__ import annotations

from app.models import Announcement, Course, Enrollment, Grade
from app.schemas import AnnouncementOut, CourseOut, GradeOut


def course_out(course: Course) -> CourseOut:
    return CourseOut(
        id=course.id,
        code=course.code,
        title=course.title,
        term=course.term,
        credits=course.credits,
        faculty_id=course.faculty_id,
        faculty_name=course.faculty.full_name if course.faculty else None,
    )


def grade_out(grade: Grade, enrollment: Enrollment) -> GradeOut:
    return GradeOut(
        id=grade.id,
        enrollment_id=enrollment.id,
        student_id=enrollment.student_id,
        course_id=enrollment.course_id,
        course_code=enrollment.course.code,
        course_title=enrollment.course.title,
        score=grade.score,
        letter=grade.letter,
        comment=grade.comment,
        updated_at=grade.updated_at,
    )


def announcement_out(announcement: Announcement) -> AnnouncementOut:
    return AnnouncementOut(
        id=announcement.id,
        title=announcement.title,
        body=announcement.body,
        course_id=announcement.course_id,
        course_code=announcement.course.code if announcement.course else None,
        author_name=announcement.author.full_name if announcement.author else None,
        created_at=announcement.created_at,
    )
