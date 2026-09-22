"""The browser portal is guarded by the same server-side rules as the API."""

from __future__ import annotations

import pytest

from tests.conftest import PASSWORD


def portal_login(client, username: str, password: str = PASSWORD):
    client.cookies.clear()
    return client.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )


HTML = {"accept": "text/html"}


def test_login_page_is_public(client, portal):
    response = client.get("/login", headers=HTML)
    assert response.status_code == 200
    assert "Sign in" in response.text


def test_login_sets_a_session_cookie_and_redirects(client, portal):
    response = portal_login(client, "student.alice")
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert "portal_session" in client.cookies


def test_failed_portal_login_shows_one_generic_message(client, portal):
    response = client.post(
        "/login", data={"username": "student.alice", "password": "wrong"}, follow_redirects=False
    )
    assert response.status_code == 200
    assert "Invalid username or password" in response.text
    assert "portal_session" not in client.cookies


def test_each_role_gets_its_own_dashboard(client, portal):
    portal_login(client, "student.alice")
    student_page = client.get("/dashboard", headers=HTML).text
    assert "My courses" in student_page and "Audit log" not in student_page

    portal_login(client, "faculty.brown")
    faculty_page = client.get("/dashboard", headers=HTML).text
    assert "Open roster" in faculty_page and "Audit log" not in faculty_page

    portal_login(client, "admin.root")
    admin_page = client.get("/dashboard", headers=HTML).text
    assert "accounts" in admin_page and "Audit log" in admin_page


def test_anonymous_visitor_is_redirected_to_the_login_page(client, portal):
    client.cookies.clear()
    response = client.get("/dashboard", headers=HTML, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?expired=1"


def test_revoked_session_cannot_browse_the_portal(client, portal):
    portal_login(client, "student.alice")
    assert client.get("/portal/grades", headers=HTML).status_code == 200

    client.get("/logout", headers=HTML, follow_redirects=False)
    response = client.get("/portal/grades", headers=HTML, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?expired=1"


@pytest.mark.parametrize(
    "username,path",
    [
        ("student.alice", "/portal/admin/users"),
        ("student.alice", "/portal/admin/audit"),
        ("faculty.brown", "/portal/admin/users"),
        ("faculty.brown", "/portal/grades"),
        ("admin.root", "/portal/grades"),
    ],
)
def test_pages_outside_a_role_render_the_access_denied_page(client, portal, username, path):
    portal_login(client, username)
    response = client.get(path, headers=HTML)
    assert response.status_code == 403
    assert "Access denied" in response.text


def test_faculty_cannot_open_another_instructors_roster(client, portal):
    portal_login(client, "faculty.brown")
    response = client.get(f"/portal/courses/{portal['ma201'].id}", headers=HTML)
    assert response.status_code == 403
    assert "Access denied" in response.text


def test_faculty_saves_a_grade_from_the_roster_page(client, portal):
    cs101, alice = portal["cs101"], portal["alice"]
    portal_login(client, "faculty.brown")
    response = client.post(
        f"/portal/courses/{cs101.id}/grades",
        data={"student_id": alice.id, "score": "77", "comment": "Improved"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    page = client.get(f"/portal/courses/{cs101.id}", headers=HTML).text
    assert "77" in page

    portal_login(client, "student.alice")
    assert "77" in client.get("/portal/grades", headers=HTML).text


def test_grade_form_posted_by_the_wrong_instructor_is_refused(client, portal):
    """Hiding a form is not a control: posting it directly must still fail."""
    ma201, bob = portal["ma201"], portal["bob"]
    portal_login(client, "faculty.brown")
    response = client.post(
        f"/portal/courses/{ma201.id}/grades",
        data={"student_id": bob.id, "score": "100"},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_student_cannot_post_the_grade_form_at_all(client, portal):
    cs101, alice = portal["cs101"], portal["alice"]
    portal_login(client, "student.alice")
    response = client.post(
        f"/portal/courses/{cs101.id}/grades",
        data={"student_id": alice.id, "score": "100"},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_admin_changes_a_role_from_the_portal(client, portal):
    alice = portal["alice"]
    portal_login(client, "admin.root")
    response = client.post(
        f"/portal/admin/users/{alice.id}/role", data={"role": "faculty"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "faculty" in client.get("/portal/admin/users", headers=HTML).text

    entries = client.get("/portal/admin/audit", headers=HTML).text
    assert "role_assign" in entries


def test_denied_portal_attempt_appears_in_the_audit_page(client, portal):
    portal_login(client, "student.alice")
    client.get("/portal/admin/users", headers=HTML)

    portal_login(client, "admin.root")
    page = client.get("/portal/admin/audit?outcome=denied", headers=HTML).text
    assert "access_denied" in page
    assert "student.alice" in page


def test_session_cookie_is_http_only(client, portal):
    response = portal_login(client, "student.alice")
    cookie_header = response.headers["set-cookie"].lower()
    assert "httponly" in cookie_header
    assert "samesite=lax" in cookie_header
