"""Structural tests for deny-by-default authorization."""

from __future__ import annotations

import pytest
from fastapi import APIRouter, Depends, FastAPI

from app.authz import (
    PUBLIC_PATHS,
    require_permission,
    unprotected_routes,
    verify_deny_by_default,
)
from app.main import app as fastapi_app
from app.models import Role
from app.permissions import Permission, has_permission, permissions_for
from tests.conftest import auth_header, login


def test_every_route_is_public_by_allowlist_or_permission_guarded():
    assert unprotected_routes(fastapi_app) == []


def test_startup_rejects_a_route_without_a_permission():
    """A forgotten guard must break the build, not quietly expose data."""
    app = FastAPI()
    router = APIRouter()

    @router.get("/api/oops")
    def unguarded() -> dict[str, str]:
        return {"secret": "everything"}

    app.include_router(router)

    with pytest.raises(RuntimeError, match="Deny-by-default violation"):
        verify_deny_by_default(app)


def test_guarded_route_passes_the_startup_audit():
    app = FastAPI()
    router = APIRouter()

    @router.get("/api/fine")
    def guarded(user=Depends(require_permission(Permission.AUDIT_READ))) -> dict[str, str]:
        return {"ok": "yes"}

    app.include_router(router)
    verify_deny_by_default(app)  # must not raise


def test_public_allowlist_is_small_and_explicit():
    # Anything beyond authentication, health and the API docs would be a finding.
    assert PUBLIC_PATHS == frozenset(
        {
            "/health",
            "/login",
            "/api/auth/login",
            "/openapi.json",
            "/docs",
            "/docs/oauth2-redirect",
            "/redoc",
        }
    )


def test_roles_hold_disjoint_privileged_permissions():
    student = permissions_for(Role.STUDENT)
    faculty = permissions_for(Role.FACULTY)
    admin = permissions_for(Role.ADMIN)

    assert Permission.GRADES_WRITE_COURSE not in student
    assert Permission.USERS_MANAGE not in student and Permission.USERS_MANAGE not in faculty
    assert Permission.AUDIT_READ not in student and Permission.AUDIT_READ not in faculty
    # Administrators manage accounts; they are not a superset of every role.
    assert Permission.GRADES_WRITE_COURSE not in admin


def test_unknown_role_holds_no_permissions():
    assert permissions_for("not-a-role") == frozenset()  # type: ignore[arg-type]
    assert not has_permission("not-a-role", Permission.META_READ)  # type: ignore[arg-type]


def test_permission_matrix_endpoint_requires_authentication(client, portal):
    assert client.get("/api/meta/permissions").status_code == 401


def test_permission_matrix_endpoint_reports_the_callers_permissions(client, portal):
    token = login(client, "student.alice")
    response = client.get("/api/meta/permissions", headers=auth_header(token))
    assert response.status_code == 200
    body = response.json()
    assert body["your_role"] == "student"
    assert "grades:read_own" in body["your_permissions"]
    assert "users:manage" not in body["your_permissions"]
