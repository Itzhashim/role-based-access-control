"""Authentication tests: credentials, session tokens, expiry and logout."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings
from tests.conftest import PASSWORD, auth_header, login


def test_login_succeeds_with_valid_credentials(client, portal):
    response = client.post(
        "/api/auth/login", json={"username": "student.alice", "password": PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "student"
    # The browser portal receives an HttpOnly session cookie.
    assert settings.session_cookie_name in response.cookies


def test_login_fails_with_wrong_password(client, portal):
    response = client.post(
        "/api/auth/login", json={"username": "student.alice", "password": "wrong-password"}
    )
    assert response.status_code == 401


def test_login_does_not_reveal_whether_the_account_exists(client, portal):
    unknown = client.post(
        "/api/auth/login", json={"username": "nobody.here", "password": "wrong-password"}
    )
    wrong_password = client.post(
        "/api/auth/login", json={"username": "student.alice", "password": "wrong-password"}
    )
    assert unknown.status_code == wrong_password.status_code == 401
    assert unknown.json() == wrong_password.json()


def test_deactivated_account_cannot_log_in(client, portal, db):
    alice = portal["alice"]
    alice.is_active = False
    db.commit()

    response = client.post(
        "/api/auth/login", json={"username": "student.alice", "password": PASSWORD}
    )
    assert response.status_code == 401


def test_me_requires_a_token(client, portal):
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_the_caller_and_never_the_password_hash(client, portal):
    token = login(client, "student.alice")
    response = client.get("/api/auth/me", headers=auth_header(token))
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "student.alice"
    assert "password_hash" not in body


def test_malformed_token_is_rejected(client, portal):
    response = client.get("/api/auth/me", headers=auth_header("not.a.jwt"))
    assert response.status_code == 401


def test_token_signed_with_another_key_is_rejected(client, portal):
    forged = jwt.encode(
        {
            "sub": str(portal["admin"].id),
            "role": "admin",
            "jti": "forged",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        },
        "attacker-controlled-key-that-is-long-enough",
        algorithm="HS256",
    )
    assert client.get("/api/auth/me", headers=auth_header(forged)).status_code == 401


def test_expired_token_is_rejected(client, portal):
    expired = jwt.encode(
        {
            "sub": str(portal["alice"].id),
            "role": "student",
            "jti": "expired",
            "exp": int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp()),
        },
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    assert client.get("/api/auth/me", headers=auth_header(expired)).status_code == 401


def test_token_cannot_be_replayed_after_logout(client, portal):
    token = login(client, "student.alice")
    headers = auth_header(token)
    assert client.get("/api/auth/me", headers=headers).status_code == 200

    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    # Same token, now revoked.
    assert client.get("/api/auth/me", headers=headers).status_code == 401
