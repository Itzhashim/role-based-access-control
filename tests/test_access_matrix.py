"""The full access-control matrix: every role against every kind of endpoint.

Each row states the expected HTTP status. The suite therefore doubles as the
evidence table for the report: 200 where access is legitimate, 403 where the
role or the ownership check refuses, 401 where there is no valid session.
"""

from __future__ import annotations

import pytest

from tests.conftest import auth_header, login

STUDENT, FACULTY, ADMIN, ANON = "student.alice", "faculty.brown", "admin.root", None

# (label, method, path template, body, {role: expected status})
MATRIX = [
    (
        "read own grades",
        "GET",
        "/api/students/{alice}/grades",
        None,
        {STUDENT: 200, FACULTY: 403, ADMIN: 403, ANON: 401},
    ),
    (
        "read another student's grades",
        "GET",
        "/api/students/{bob}/grades",
        None,
        {STUDENT: 403, FACULTY: 403, ADMIN: 403, ANON: 401},
    ),
    (
        "read own enrolled courses",
        "GET",
        "/api/students/{alice}/courses",
        None,
        {STUDENT: 200, FACULTY: 403, ADMIN: 403, ANON: 401},
    ),
    (
        "read roster of an assigned course",
        "GET",
        "/api/faculty/courses/{cs101}/roster",
        None,
        {STUDENT: 403, FACULTY: 200, ADMIN: 403, ANON: 401},
    ),
    (
        "read roster of another instructor's course",
        "GET",
        "/api/faculty/courses/{ma201}/roster",
        None,
        {STUDENT: 403, FACULTY: 403, ADMIN: 403, ANON: 401},
    ),
    (
        "write a grade on an assigned course",
        "PUT",
        "/api/faculty/courses/{cs101}/grades",
        {"student_id": "{alice}", "score": 70},
        {STUDENT: 403, FACULTY: 200, ADMIN: 403, ANON: 401},
    ),
    (
        "write a grade on another instructor's course",
        "PUT",
        "/api/faculty/courses/{ma201}/grades",
        {"student_id": "{bob}", "score": 100},
        {STUDENT: 403, FACULTY: 403, ADMIN: 403, ANON: 401},
    ),
    (
        "list all accounts",
        "GET",
        "/api/admin/users",
        None,
        {STUDENT: 403, FACULTY: 403, ADMIN: 200, ANON: 401},
    ),
    (
        "change a user's role",
        "PUT",
        "/api/admin/users/{bob}/role",
        {"role": "faculty"},
        {STUDENT: 403, FACULTY: 403, ADMIN: 200, ANON: 401},
    ),
    (
        "read the audit log",
        "GET",
        "/api/admin/audit",
        None,
        {STUDENT: 403, FACULTY: 403, ADMIN: 200, ANON: 401},
    ),
    (
        "read the permission matrix",
        "GET",
        "/api/meta/permissions",
        None,
        {STUDENT: 200, FACULTY: 200, ADMIN: 200, ANON: 401},
    ),
]

CASES = [
    pytest.param(label, method, path, body, role, expected, id=f"{role or 'anonymous'}: {label}")
    for label, method, path, body, expectations in MATRIX
    for role, expected in expectations.items()
]


def resolve(value, ids: dict[str, int]):
    if isinstance(value, str):
        return value.format(**ids)
    if isinstance(value, dict):
        return {k: resolve(v, ids) for k, v in value.items()}
    return value


@pytest.mark.parametrize("label,method,path,body,username,expected", CASES)
def test_access_matrix(client, portal, label, method, path, body, username, expected):
    ids = {
        "alice": portal["alice"].id,
        "bob": portal["bob"].id,
        "cs101": portal["cs101"].id,
        "ma201": portal["ma201"].id,
    }
    headers = auth_header(login(client, username)) if username else None
    payload = resolve(body, ids)
    if isinstance(payload, dict) and "student_id" in payload:
        payload["student_id"] = int(payload["student_id"])

    response = client.request(method, resolve(path, ids), json=payload, headers=headers)
    assert response.status_code == expected, (
        f"{username or 'anonymous'} -> {label}: expected {expected}, got {response.status_code}"
    )


def test_no_endpoint_returns_data_to_an_anonymous_caller(client, portal):
    """A sweep of every API route: without a session, nothing but 401."""
    from app.authz import PUBLIC_PATHS, iter_api_routes
    from app.main import app as fastapi_app

    client.cookies.clear()
    checked = 0
    for route in iter_api_routes(fastapi_app):
        if route.path in PUBLIC_PATHS or not route.path.startswith("/api/"):
            continue
        path = route.path.format(**{name: 1 for name in ("student_id", "course_id", "user_id", "faculty_id")})
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            response = client.request(method, path, json={})
            assert response.status_code == 401, f"{method} {path} returned {response.status_code}"
            checked += 1
    assert checked > 10
