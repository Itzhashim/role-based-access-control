"""Administrator routes and the vertical escalation attempts against them."""

from __future__ import annotations

import pytest

from tests.conftest import PASSWORD, auth_header, login

ADMIN_ROUTES = [
    ("GET", "/api/admin/users", None),
    ("GET", "/api/admin/courses", None),
    (
        "POST",
        "/api/admin/users",
        {
            "username": "mallory",
            "email": "mallory@college.edu",
            "full_name": "Mallory",
            "password": "Passw0rd!123",
            "role": "admin",
        },
    ),
    ("POST", "/api/admin/enrollments", {"student_id": 1, "course_id": 1}),
    ("POST", "/api/admin/announcements", {"title": "x", "body": "y"}),
]


def _call(client, method, path, body, headers):
    return client.request(method, path, json=body, headers=headers)


def test_admin_lists_users(client, portal):
    headers = auth_header(login(client, "admin.root"))
    response = client.get("/api/admin/users", headers=headers)
    assert response.status_code == 200
    usernames = {u["username"] for u in response.json()}
    assert {"student.alice", "faculty.brown", "admin.root"} <= usernames
    assert all("password_hash" not in u for u in response.json())


def test_admin_filters_users_by_role(client, portal):
    headers = auth_header(login(client, "admin.root"))
    response = client.get("/api/admin/users", params={"role": "faculty"}, headers=headers)
    assert response.status_code == 200
    assert {u["username"] for u in response.json()} == {"faculty.brown", "faculty.davis"}


def test_admin_creates_a_user_who_can_then_log_in(client, portal):
    headers = auth_header(login(client, "admin.root"))
    response = client.post(
        "/api/admin/users",
        headers=headers,
        json={
            "username": "student.carol",
            "email": "carol@college.edu",
            "full_name": "Carol Diaz",
            "password": PASSWORD,
            "role": "student",
        },
    )
    assert response.status_code == 201
    assert response.json()["role"] == "student"
    assert login(client, "student.carol")


def test_admin_assigns_a_role_and_the_change_takes_effect_immediately(client, portal, db):
    admin_headers = auth_header(login(client, "admin.root"))
    alice = portal["alice"]

    # As a student, Alice cannot read the audit-free admin user list.
    alice_headers = auth_header(login(client, "student.alice"))
    assert client.get("/api/admin/users", headers=alice_headers).status_code == 403

    response = client.put(
        f"/api/admin/users/{alice.id}/role", headers=admin_headers, json={"role": "faculty"}
    )
    assert response.status_code == 200
    assert response.json()["role"] == "faculty"

    # The role is re-read from the database per request, so her existing token
    # now carries faculty privileges and no longer carries student ones.
    assert client.get(f"/api/students/{alice.id}/grades", headers=alice_headers).status_code == 403
    assert client.get(f"/api/faculty/{alice.id}/courses", headers=alice_headers).status_code == 200


def test_admin_cannot_change_their_own_role(client, portal):
    admin = portal["admin"]
    headers = auth_header(login(client, "admin.root"))
    response = client.put(
        f"/api/admin/users/{admin.id}/role", headers=headers, json={"role": "student"}
    )
    assert response.status_code == 400


def test_deactivated_user_loses_access_immediately(client, portal):
    alice_headers = auth_header(login(client, "student.alice"))
    admin_headers = auth_header(login(client, "admin.root"))
    alice = portal["alice"]

    assert client.get("/api/auth/me", headers=alice_headers).status_code == 200
    response = client.patch(
        f"/api/admin/users/{alice.id}", headers=admin_headers, json={"is_active": False}
    )
    assert response.status_code == 200
    assert client.get("/api/auth/me", headers=alice_headers).status_code == 401


def test_admin_creates_and_assigns_a_course(client, portal):
    headers = auth_header(login(client, "admin.root"))
    davis = portal["davis"]

    created = client.post(
        "/api/admin/courses",
        headers=headers,
        json={"code": "PH110", "title": "Mechanics", "term": "2026-FALL"},
    )
    assert created.status_code == 201
    course_id = created.json()["id"]

    assigned = client.put(
        f"/api/admin/courses/{course_id}/faculty", headers=headers, json={"faculty_id": davis.id}
    )
    assert assigned.status_code == 200
    assert assigned.json()["faculty_name"] == davis.full_name

    # The newly assigned instructor can now reach it; the other one cannot.
    davis_headers = auth_header(login(client, "faculty.davis"))
    assert (
        client.get(f"/api/faculty/courses/{course_id}/roster", headers=davis_headers).status_code
        == 200
    )
    brown_headers = auth_header(login(client, "faculty.brown"))
    assert (
        client.get(f"/api/faculty/courses/{course_id}/roster", headers=brown_headers).status_code
        == 403
    )


def test_admin_cannot_assign_a_course_to_a_student(client, portal):
    headers = auth_header(login(client, "admin.root"))
    cs101, alice = portal["cs101"], portal["alice"]
    response = client.put(
        f"/api/admin/courses/{cs101.id}/faculty", headers=headers, json={"faculty_id": alice.id}
    )
    assert response.status_code == 400


def test_admin_enrolls_a_student_and_only_students(client, portal):
    headers = auth_header(login(client, "admin.root"))
    bob, cs101, brown = portal["bob"], portal["cs101"], portal["brown"]

    ok = client.post(
        "/api/admin/enrollments", headers=headers, json={"student_id": bob.id, "course_id": cs101.id}
    )
    assert ok.status_code == 201

    duplicate = client.post(
        "/api/admin/enrollments", headers=headers, json={"student_id": bob.id, "course_id": cs101.id}
    )
    assert duplicate.status_code == 409

    faculty_enrollment = client.post(
        "/api/admin/enrollments",
        headers=headers,
        json={"student_id": brown.id, "course_id": cs101.id},
    )
    assert faculty_enrollment.status_code == 400


# --- Vertical privilege escalation -----------------------------------------


@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_student_cannot_reach_admin_routes(client, portal, method, path, body):
    headers = auth_header(login(client, "student.alice"))
    response = _call(client, method, path, body, headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied"}


@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_faculty_cannot_reach_admin_routes(client, portal, method, path, body):
    headers = auth_header(login(client, "faculty.brown"))
    assert _call(client, method, path, body, headers).status_code == 403


@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_anonymous_cannot_reach_admin_routes(client, portal, method, path, body):
    assert _call(client, method, path, body, None).status_code == 401


def test_student_cannot_promote_themselves(client, portal):
    """The classic vertical escalation: editing your own role through the API."""
    alice = portal["alice"]
    headers = auth_header(login(client, "student.alice"))
    response = client.put(
        f"/api/admin/users/{alice.id}/role", headers=headers, json={"role": "admin"}
    )
    assert response.status_code == 403
