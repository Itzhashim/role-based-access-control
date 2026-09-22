"""Faculty routes: assigned courses work, other instructors' courses do not."""

from __future__ import annotations

from tests.conftest import auth_header, login


def test_faculty_lists_own_assigned_courses(client, portal):
    brown = portal["brown"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.get(f"/api/faculty/{brown.id}/courses", headers=headers)
    assert response.status_code == 200
    assert [c["code"] for c in response.json()] == ["CS101"]


def test_faculty_reads_roster_of_assigned_course(client, portal):
    cs101 = portal["cs101"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.get(f"/api/faculty/courses/{cs101.id}/roster", headers=headers)
    assert response.status_code == 200
    roster = response.json()
    assert [entry["student_id"] for entry in roster] == [portal["alice"].id]


def test_faculty_updates_grade_on_assigned_course(client, portal):
    cs101, alice = portal["cs101"], portal["alice"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.put(
        f"/api/faculty/courses/{cs101.id}/grades",
        headers=headers,
        json={"student_id": alice.id, "score": 84.0, "comment": "Strong project work"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["score"] == 84.0
    assert body["letter"] == "B"

    # The student sees the new value on their own record.
    student_headers = auth_header(login(client, "student.alice"))
    grades = client.get(f"/api/students/{alice.id}/grades", headers=student_headers).json()
    assert grades[0]["score"] == 84.0


def test_faculty_publishes_announcement_to_assigned_course(client, portal):
    cs101 = portal["cs101"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.post(
        f"/api/faculty/courses/{cs101.id}/announcements",
        headers=headers,
        json={"title": "Lab moved", "body": "Room 204", "course_id": cs101.id},
    )
    assert response.status_code == 201
    assert response.json()["course_code"] == "CS101"


# --- Horizontal escalation between faculty ---------------------------------


def test_faculty_cannot_read_another_instructors_roster(client, portal):
    ma201 = portal["ma201"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.get(f"/api/faculty/courses/{ma201.id}/roster", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied"}


def test_faculty_cannot_grade_another_instructors_course(client, portal):
    ma201, bob = portal["ma201"], portal["bob"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.put(
        f"/api/faculty/courses/{ma201.id}/grades",
        headers=headers,
        json={"student_id": bob.id, "score": 100.0},
    )
    assert response.status_code == 403


def test_faculty_cannot_grade_a_student_not_on_the_roster(client, portal):
    cs101, bob = portal["cs101"], portal["bob"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.put(
        f"/api/faculty/courses/{cs101.id}/grades",
        headers=headers,
        json={"student_id": bob.id, "score": 100.0},
    )
    assert response.status_code == 403


def test_faculty_cannot_list_another_faculty_members_courses(client, portal):
    davis = portal["davis"]
    headers = auth_header(login(client, "faculty.brown"))
    assert client.get(f"/api/faculty/{davis.id}/courses", headers=headers).status_code == 403


def test_announcement_body_cannot_redirect_to_another_course(client, portal):
    """The path decides the target course; a forged body field is ignored."""
    cs101, ma201 = portal["cs101"], portal["ma201"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.post(
        f"/api/faculty/courses/{cs101.id}/announcements",
        headers=headers,
        json={"title": "Injected", "body": "...", "course_id": ma201.id},
    )
    assert response.status_code == 201
    assert response.json()["course_id"] == cs101.id


# --- Vertical escalation ---------------------------------------------------


def test_student_cannot_write_grades(client, portal):
    cs101, alice = portal["cs101"], portal["alice"]
    headers = auth_header(login(client, "student.alice"))
    response = client.put(
        f"/api/faculty/courses/{cs101.id}/grades",
        headers=headers,
        json={"student_id": alice.id, "score": 100.0},
    )
    assert response.status_code == 403


def test_student_cannot_read_a_course_roster(client, portal):
    cs101 = portal["cs101"]
    headers = auth_header(login(client, "student.alice"))
    assert client.get(f"/api/faculty/courses/{cs101.id}/roster", headers=headers).status_code == 403


def test_admin_cannot_write_grades(client, portal):
    cs101, alice = portal["cs101"], portal["alice"]
    headers = auth_header(login(client, "admin.root"))
    response = client.put(
        f"/api/faculty/courses/{cs101.id}/grades",
        headers=headers,
        json={"student_id": alice.id, "score": 100.0},
    )
    assert response.status_code == 403


def test_faculty_routes_reject_anonymous_callers(client, portal):
    cs101 = portal["cs101"]
    assert client.get(f"/api/faculty/courses/{cs101.id}/roster").status_code == 401
