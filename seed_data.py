"""Populate the portal with synthetic demo data.

Run ``python seed_data.py`` for a ready-to-explore campus, or
``python seed_data.py --reset`` to drop everything first.

The data is deliberately shaped so that access control is visible:

* two instructors teach different courses, so faculty-to-faculty boundaries
  can be probed;
* students are enrolled in overlapping but not identical course sets, so
  student-to-student boundaries can be probed;
* one student shares a course with another, proving that "same course" still
  does not mean "same records".

All passwords here are demo values and are safe only because this database is
disposable.
"""

from __future__ import annotations

import argparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, init_db
from app.models import Announcement, Course, Enrollment, Grade, Role, User
from app.security import hash_password

STUDENT_PASSWORD = "Student#2026"
FACULTY_PASSWORD = "Faculty#2026"
ADMIN_PASSWORD = "Admin#2026"

USERS = [
    ("admin.root", "Rita Advani", Role.ADMIN, ADMIN_PASSWORD, "Registrar"),
    ("faculty.brown", "Dr. Alan Brown", Role.FACULTY, FACULTY_PASSWORD, "Computer Science"),
    ("faculty.davis", "Dr. Mira Davis", Role.FACULTY, FACULTY_PASSWORD, "Mathematics"),
    ("student.alice", "Alice Nair", Role.STUDENT, STUDENT_PASSWORD, "Computer Science"),
    ("student.bob", "Bob Mathew", Role.STUDENT, STUDENT_PASSWORD, "Computer Science"),
    ("student.carol", "Carol Dsouza", Role.STUDENT, STUDENT_PASSWORD, "Mathematics"),
    ("student.dan", "Dan Iyer", Role.STUDENT, STUDENT_PASSWORD, "Physics"),
]

COURSES = [
    ("CS101", "Introduction to Computing", "2026-FALL", 4, "faculty.brown"),
    ("CS204", "Secure Web Development", "2026-FALL", 3, "faculty.brown"),
    ("MA201", "Linear Algebra", "2026-FALL", 3, "faculty.davis"),
    ("MA310", "Probability and Statistics", "2026-FALL", 3, "faculty.davis"),
]

# (student, course, score or None for "not graded yet")
ENROLLMENTS = [
    ("student.alice", "CS101", 91.5),
    ("student.alice", "CS204", 88.0),
    ("student.alice", "MA201", 79.0),
    ("student.bob", "CS101", 64.0),
    ("student.bob", "MA201", 72.5),
    ("student.carol", "MA201", 95.0),
    ("student.carol", "MA310", None),
    ("student.dan", "CS101", 55.0),
    ("student.dan", "MA310", 81.0),
]

ANNOUNCEMENTS = [
    (None, "admin.root", "Semester fee deadline", "Fees are due by 30 November."),
    (
        "CS101",
        "faculty.brown",
        "Lab session moved",
        "Friday's lab now meets in Room 204.",
    ),
    (
        "MA201",
        "faculty.davis",
        "Quiz 2 scheduled",
        "Quiz 2 covers eigenvalues and takes place next Monday.",
    ),
]


def seed(db: Session) -> None:
    users: dict[str, User] = {}
    for username, full_name, role, password, department in USERS:
        user = db.scalar(select(User).where(User.username == username))
        if user is None:
            user = User(
                username=username,
                email=f"{username.split('.')[-1]}@college.edu",
                full_name=full_name,
                role=role,
                department=department,
                password_hash=hash_password(password),
            )
            db.add(user)
        users[username] = user
    db.commit()

    courses: dict[str, Course] = {}
    for code, title, term, credits, faculty_username in COURSES:
        course = db.scalar(select(Course).where(Course.code == code))
        if course is None:
            course = Course(code=code, title=title, term=term, credits=credits)
            db.add(course)
        course.faculty_id = users[faculty_username].id
        courses[code] = course
    db.commit()

    for student_username, course_code, score in ENROLLMENTS:
        student, course = users[student_username], courses[course_code]
        enrollment = db.scalar(
            select(Enrollment).where(
                Enrollment.student_id == student.id, Enrollment.course_id == course.id
            )
        )
        if enrollment is None:
            enrollment = Enrollment(student_id=student.id, course_id=course.id)
            db.add(enrollment)
            db.commit()
            db.refresh(enrollment)

        if score is None or enrollment.grade is not None:
            continue
        db.add(
            Grade(
                enrollment_id=enrollment.id,
                score=score,
                letter=Grade.letter_for(score),
                updated_by_id=course.faculty_id,
            )
        )
    db.commit()

    for course_code, author_username, title, body in ANNOUNCEMENTS:
        if db.scalar(select(Announcement).where(Announcement.title == title)):
            continue
        db.add(
            Announcement(
                title=title,
                body=body,
                course_id=courses[course_code].id if course_code else None,
                author_id=users[author_username].id,
            )
        )
    db.commit()


def summary() -> str:
    lines = [
        "Demo accounts (username / password):",
        f"  admin.root     / {ADMIN_PASSWORD}",
        f"  faculty.brown  / {FACULTY_PASSWORD}   teaches CS101, CS204",
        f"  faculty.davis  / {FACULTY_PASSWORD}   teaches MA201, MA310",
        f"  student.alice  / {STUDENT_PASSWORD}  enrolled in CS101, CS204, MA201",
        f"  student.bob    / {STUDENT_PASSWORD}  enrolled in CS101, MA201",
        f"  student.carol  / {STUDENT_PASSWORD}  enrolled in MA201, MA310",
        f"  student.dan    / {STUDENT_PASSWORD}  enrolled in CS101, MA310",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the RBAC college portal database.")
    parser.add_argument(
        "--reset", action="store_true", help="drop all tables before seeding (destructive)"
    )
    args = parser.parse_args()

    if args.reset:
        Base.metadata.drop_all(bind=engine)
    init_db()

    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()

    print("Seed data ready.")
    print(summary())


if __name__ == "__main__":
    main()
