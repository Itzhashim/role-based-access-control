"""Student routes: own-data access works, cross-student access does not."""

from __future__ import annotations

from tests.conftest import auth_header, login


def test_student_reads_own_profile(client, portal):
    alice = portal["alice"]
    headers = auth_header(login(client, "student.alice"))
    response = client.get(f"/api/students/{alice.id}/profile", headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == "student.alice"


def test_student_reads_own_grades(client, portal):
    alice = portal["alice"]
    headers = auth_header(login(client, "student.alice"))
    response = client.get(f"/api/students/{alice.id}/grades", headers=headers)
    assert response.status_code == 200
    grades = response.json()
    assert len(grades) == 1
    assert grades[0]["course_code"] == "CS101"
    assert grades[0]["student_id"] == alice.id


def test_student_reads_own_enrolled_courses(client, portal):
    alice = portal["alice"]
    headers = auth_header(login(client, "student.alice"))
    response = client.get(f"/api/students/{alice.id}/courses", headers=headers)
    assert response.status_code == 200
    assert [c["code"] for c in response.json()] == ["CS101"]


def test_student_reads_grade_for_an_enrolled_course(client, portal):
    alice, cs101 = portal["alice"], portal["cs101"]
    headers = auth_header(login(client, "student.alice"))
    response = client.get(
        f"/api/students/{alice.id}/courses/{cs101.id}/grade", headers=headers
    )
    assert response.status_code == 200
    assert response.json()["letter"] == "A"


# --- Horizontal privilege escalation ---------------------------------------


def test_student_cannot_read_another_students_grades(client, portal):
    bob = portal["bob"]
    headers = auth_header(login(client, "student.alice"))
    response = client.get(f"/api/students/{bob.id}/grades", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied"}


def test_student_cannot_read_another_students_profile(client, portal):
    bob = portal["bob"]
    headers = auth_header(login(client, "student.alice"))
    assert client.get(f"/api/students/{bob.id}/profile", headers=headers).status_code == 403


def test_student_cannot_read_another_students_courses(client, portal):
    bob = portal["bob"]
    headers = auth_header(login(client, "student.alice"))
    assert client.get(f"/api/students/{bob.id}/courses", headers=headers).status_code == 403


def test_student_cannot_read_a_course_they_are_not_enrolled_in(client, portal):
    alice, ma201 = portal["alice"], portal["ma201"]
    headers = auth_header(login(client, "student.alice"))
    response = client.get(
        f"/api/students/{alice.id}/courses/{ma201.id}/grade", headers=headers
    )
    assert response.status_code == 403


def test_non_existent_course_is_indistinguishable_from_an_unenrolled_one(client, portal):
    alice, ma201 = portal["alice"], portal["ma201"]
    headers = auth_header(login(client, "student.alice"))
    unenrolled = client.get(f"/api/students/{alice.id}/courses/{ma201.id}/grade", headers=headers)
    missing = client.get(f"/api/students/{alice.id}/courses/999999/grade", headers=headers)
    assert unenrolled.status_code == missing.status_code == 403
    assert unenrolled.json() == missing.json()


def test_announcements_are_limited_to_enrolled_courses(client, portal, db):
    from app.models import Announcement

    alice, cs101, ma201 = portal["alice"], portal["cs101"], portal["ma201"]
    db.add_all(
        [
            Announcement(title="Campus closed", body="Public holiday", course_id=None),
            Announcement(title="CS101 quiz", body="Friday", course_id=cs101.id),
            Announcement(title="MA201 quiz", body="Monday", course_id=ma201.id),
        ]
    )
    db.commit()

    headers = auth_header(login(client, "student.alice"))
    response = client.get(f"/api/students/{alice.id}/announcements", headers=headers)
    assert response.status_code == 200
    titles = {a["title"] for a in response.json()}
    assert titles == {"Campus closed", "CS101 quiz"}


# --- Vertical privilege escalation -----------------------------------------


def test_faculty_cannot_use_student_grade_routes(client, portal):
    alice = portal["alice"]
    headers = auth_header(login(client, "faculty.brown"))
    assert client.get(f"/api/students/{alice.id}/grades", headers=headers).status_code == 403


def test_admin_cannot_read_a_students_grades_through_student_routes(client, portal):
    """Administrators manage the system; they do not hold ``grades:read_own``."""
    alice = portal["alice"]
    headers = auth_header(login(client, "admin.root"))
    assert client.get(f"/api/students/{alice.id}/grades", headers=headers).status_code == 403


def test_student_routes_reject_anonymous_callers(client, portal):
    alice = portal["alice"]
    assert client.get(f"/api/students/{alice.id}/grades").status_code == 401
