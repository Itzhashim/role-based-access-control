"""The audit trail records sensitive operations and refused attempts."""

from __future__ import annotations

from tests.conftest import PASSWORD, auth_header, login


def read_audit(client, **params):
    headers = auth_header(login(client, "admin.root"))
    response = client.get("/api/admin/audit", params=params, headers=headers)
    assert response.status_code == 200
    return response.json()


def test_successful_login_is_recorded(client, portal):
    login(client, "student.alice")
    entries = read_audit(client, action="login_success")
    assert any(e["actor_username"] == "student.alice" for e in entries)


def test_failed_login_is_recorded_without_the_password(client, portal):
    client.post("/api/auth/login", json={"username": "student.alice", "password": "wrong"})
    entries = read_audit(client, action="login_failure")
    entry = next(e for e in entries if e["actor_username"] == "student.alice")
    assert entry["outcome"] == "denied"
    assert "wrong" not in (entry["detail"] or "")


def test_login_attempt_on_unknown_account_is_recorded(client, portal):
    client.post("/api/auth/login", json={"username": "ghost", "password": PASSWORD})
    entries = read_audit(client, action="login_failure")
    assert any(e["actor_username"] == "ghost" for e in entries)


def test_logout_is_recorded(client, portal):
    headers = auth_header(login(client, "student.alice"))
    client.post("/api/auth/logout", headers=headers)
    assert any(e["actor_username"] == "student.alice" for e in read_audit(client, action="logout"))


def test_grade_change_is_recorded_with_before_and_after(client, portal):
    cs101, alice = portal["cs101"], portal["alice"]
    headers = auth_header(login(client, "faculty.brown"))
    client.put(
        f"/api/faculty/courses/{cs101.id}/grades",
        headers=headers,
        json={"student_id": alice.id, "score": 55.0},
    )
    entry = read_audit(client, action="grade_write")[0]
    assert entry["actor_username"] == "faculty.brown"
    assert "91.0 -> 55.0" in entry["detail"]


def test_role_assignment_is_recorded(client, portal):
    admin_headers = auth_header(login(client, "admin.root"))
    alice = portal["alice"]
    client.put(
        f"/api/admin/users/{alice.id}/role", headers=admin_headers, json={"role": "faculty"}
    )
    entry = read_audit(client, action="role_assign")[0]
    assert entry["target_id"] == str(alice.id)
    assert entry["detail"] == "student -> faculty"


def test_horizontal_escalation_attempt_is_recorded(client, portal):
    bob = portal["bob"]
    headers = auth_header(login(client, "student.alice"))
    client.get(f"/api/students/{bob.id}/grades", headers=headers)

    entry = read_audit(client, action="access_denied")[0]
    assert entry["actor_username"] == "student.alice"
    assert entry["outcome"] == "denied"
    assert entry["target_id"] == f"/api/students/{bob.id}/grades"


def test_vertical_escalation_attempt_is_recorded_with_the_missing_permission(client, portal):
    headers = auth_header(login(client, "student.alice"))
    client.get("/api/admin/users", headers=headers)

    entry = read_audit(client, action="access_denied")[0]
    assert entry["actor_username"] == "student.alice"
    assert entry["actor_role"] == "student"
    assert "users:read_any" in entry["detail"]


def test_unauthenticated_attempt_is_recorded(client, portal):
    client.get("/api/admin/users")
    entries = read_audit(client, action="auth_required")
    assert entries and entries[0]["target_id"] == "/api/admin/users"
    assert entries[0]["actor_username"] is None


def test_audit_log_is_not_readable_by_students_or_faculty(client, portal):
    for username in ("student.alice", "faculty.brown"):
        headers = auth_header(login(client, username))
        assert client.get("/api/admin/audit", headers=headers).status_code == 403


def test_audit_entries_can_be_filtered_by_outcome(client, portal):
    headers = auth_header(login(client, "student.alice"))
    client.get("/api/admin/users", headers=headers)
    denied = read_audit(client, outcome="denied")
    assert denied and all(e["outcome"] == "denied" for e in denied)
