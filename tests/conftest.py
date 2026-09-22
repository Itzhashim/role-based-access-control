"""Shared pytest fixtures.

The test suite runs against its own throwaway SQLite database. The environment
variable is set before ``app.config`` is imported so the application's engine
points at the test database rather than the development one.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

TEST_DB = Path(tempfile.gettempdir()) / "rbac_portal_test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-for-the-rbac-portal-suite"

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models import Course, Enrollment, Grade, Role, User  # noqa: E402
from app.security import hash_password  # noqa: E402

PASSWORD = "Passw0rd!123"


@pytest.fixture()
def db():
    """A clean database for each test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db):
    with TestClient(fastapi_app) as test_client:
        yield test_client


def make_user(db, username: str, role: Role, **kwargs) -> User:
    user = User(
        username=username,
        email=f"{username}@college.edu",
        full_name=kwargs.pop("full_name", username.replace(".", " ").title()),
        role=role,
        password_hash=hash_password(kwargs.pop("password", PASSWORD)),
        **kwargs,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def portal(db):
    """A miniature campus used by the access-control tests.

    * ``student.alice`` is enrolled in CS101 (taught by ``faculty.brown``) and
      has a grade.
    * ``student.bob`` is enrolled in MA201 (taught by ``faculty.davis``).
    * The two students therefore share no data at all, which makes horizontal
      access attempts unambiguous.
    """
    alice = make_user(db, "student.alice", Role.STUDENT)
    bob = make_user(db, "student.bob", Role.STUDENT)
    brown = make_user(db, "faculty.brown", Role.FACULTY, department="Computer Science")
    davis = make_user(db, "faculty.davis", Role.FACULTY, department="Mathematics")
    admin = make_user(db, "admin.root", Role.ADMIN)

    cs101 = Course(code="CS101", title="Intro to Computing", term="2026-FALL", faculty_id=brown.id)
    ma201 = Course(code="MA201", title="Linear Algebra", term="2026-FALL", faculty_id=davis.id)
    db.add_all([cs101, ma201])
    db.commit()

    alice_cs101 = Enrollment(student_id=alice.id, course_id=cs101.id)
    bob_ma201 = Enrollment(student_id=bob.id, course_id=ma201.id)
    db.add_all([alice_cs101, bob_ma201])
    db.commit()

    db.add(Grade(enrollment_id=alice_cs101.id, score=91.0, letter="A", updated_by_id=brown.id))
    db.add(Grade(enrollment_id=bob_ma201.id, score=74.5, letter="C", updated_by_id=davis.id))
    db.commit()

    return {
        "alice": alice,
        "bob": bob,
        "brown": brown,
        "davis": davis,
        "admin": admin,
        "cs101": cs101,
        "ma201": ma201,
        "alice_cs101": alice_cs101,
        "bob_ma201": bob_ma201,
    }


def login(client: TestClient, username: str, password: str = PASSWORD) -> str:
    """Log in and return the bearer token (the cookie is set on the client too)."""
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def as_role(client, portal):
    """Return a helper that yields request headers for a given username."""

    def _as(username: str) -> dict[str, str]:
        client.cookies.clear()
        return auth_header(login(client, username))

    return _as
