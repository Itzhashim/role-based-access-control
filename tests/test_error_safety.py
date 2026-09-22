"""Error responses must be uniform, uninformative and free of internals."""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.authz import require_permission
from app.config import settings
from app.errors import install_exception_handlers
from app.permissions import Permission
from tests.conftest import PASSWORD, auth_header, login


def test_denials_are_identical_across_causes(client, portal):
    """Wrong role, wrong owner and a non-existent object look the same."""
    alice, bob, ma201 = portal["alice"], portal["bob"], portal["ma201"]
    headers = auth_header(login(client, "student.alice"))

    wrong_role = client.get("/api/admin/users", headers=headers)
    wrong_owner = client.get(f"/api/students/{bob.id}/grades", headers=headers)
    not_enrolled = client.get(
        f"/api/students/{alice.id}/courses/{ma201.id}/grade", headers=headers
    )
    missing_object = client.get(
        f"/api/students/{alice.id}/courses/424242/grade", headers=headers
    )

    bodies = {r.json()["detail"] for r in (wrong_role, wrong_owner, not_enrolled, missing_object)}
    assert bodies == {"Access denied"}
    assert {r.status_code for r in (wrong_role, wrong_owner, not_enrolled, missing_object)} == {403}


def test_unauthenticated_response_is_generic(client, portal):
    response = client.get("/api/admin/users")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_validation_errors_do_not_echo_the_submitted_values(client, portal):
    cs101 = portal["cs101"]
    headers = auth_header(login(client, "faculty.brown"))
    response = client.put(
        f"/api/faculty/courses/{cs101.id}/grades",
        headers=headers,
        json={"student_id": "<script>alert(1)</script>", "score": 9000},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert "script" not in response.text


def test_unhandled_exceptions_return_a_generic_500_without_a_traceback():
    app = FastAPI()
    router = APIRouter()

    @router.get("/api/boom")
    def boom(user=Depends(require_permission(Permission.AUDIT_READ))) -> None:
        raise RuntimeError("database password is hunter2")

    app.include_router(router)
    install_exception_handlers(app)

    with TestClient(app, raise_server_exceptions=False) as test_client:
        response = test_client.get("/api/boom")

    assert response.status_code in (401, 500)
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text


def test_http_exception_details_are_sanitised():
    app = FastAPI()
    router = APIRouter()

    @router.get("/api/leaky")
    def leaky() -> None:
        raise HTTPException(status_code=404, detail="user 7 has no grade in CS101")

    app.include_router(router)
    install_exception_handlers(app)

    with TestClient(app) as test_client:
        response = test_client.get("/api/leaky")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_repeated_failures_lock_the_account_without_saying_so(client, portal):
    body = {"username": "student.alice", "password": "wrong"}
    for _ in range(settings.max_failed_logins):
        assert client.post("/api/auth/login", json=body).status_code == 401

    # The correct password now fails too, with the very same message.
    locked = client.post("/api/auth/login", json={"username": "student.alice", "password": PASSWORD})
    assert locked.status_code == 401
    assert locked.json() == {"detail": "Invalid username or password"}

    # The lockout itself is visible to administrators in the audit trail.
    admin_headers = auth_header(login(client, "admin.root"))
    entries = client.get(
        "/api/admin/audit", params={"action": "account_locked"}, headers=admin_headers
    ).json()
    assert entries and entries[0]["actor_username"] == "student.alice"


def test_successful_login_clears_the_failure_counter(client, portal, db):
    client.post("/api/auth/login", json={"username": "student.alice", "password": "wrong"})
    db.refresh(portal["alice"])
    assert portal["alice"].failed_login_count == 1

    login(client, "student.alice")
    db.refresh(portal["alice"])
    assert portal["alice"].failed_login_count == 0
    assert portal["alice"].locked_until is None
