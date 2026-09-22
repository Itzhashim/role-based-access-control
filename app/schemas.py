"""Pydantic schemas.

Response schemas are the second line of defence against data leakage: a model is
never serialised directly, so fields such as ``password_hash`` cannot escape even
if a route accidentally returns a full ORM object.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models import Role


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Authentication --------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    role: Role


class MessageResponse(BaseModel):
    detail: str


# --- Users -----------------------------------------------------------------


class UserPublic(ORMModel):
    """The minimal projection safe to show to any authenticated user."""

    id: int
    full_name: str
    role: Role


class UserOut(ORMModel):
    id: int
    username: str
    email: str
    full_name: str
    role: Role
    department: str | None = None
    is_active: bool
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9._-]+$")
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=128)
    role: Role
    department: str | None = Field(default=None, max_length=80)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=120)
    email: EmailStr | None = None
    department: str | None = Field(default=None, max_length=80)
    is_active: bool | None = None


class RoleUpdate(BaseModel):
    role: Role


# --- Courses ---------------------------------------------------------------


class CourseOut(ORMModel):
    id: int
    code: str
    title: str
    term: str
    credits: int
    faculty_id: int | None = None
    faculty_name: str | None = None


class CourseCreate(BaseModel):
    code: str = Field(min_length=2, max_length=20)
    title: str = Field(min_length=1, max_length=120)
    term: str = Field(min_length=1, max_length=20)
    credits: int = Field(default=3, ge=1, le=12)
    faculty_id: int | None = None


class CourseAssign(BaseModel):
    faculty_id: int


# --- Enrollments and grades ------------------------------------------------


class EnrollmentOut(ORMModel):
    id: int
    student_id: int
    course_id: int
    enrolled_at: datetime


class EnrollmentCreate(BaseModel):
    student_id: int
    course_id: int


class GradeOut(ORMModel):
    id: int
    enrollment_id: int
    student_id: int
    course_id: int
    course_code: str
    course_title: str
    score: float
    letter: str
    comment: str | None = None
    updated_at: datetime


class GradeUpsert(BaseModel):
    student_id: int
    score: float = Field(ge=0, le=100)
    comment: str | None = Field(default=None, max_length=500)


class RosterEntry(ORMModel):
    enrollment_id: int
    student_id: int
    student_name: str
    score: float | None = None
    letter: str | None = None


# --- Announcements ---------------------------------------------------------


class AnnouncementOut(ORMModel):
    id: int
    title: str
    body: str
    course_id: int | None = None
    course_code: str | None = None
    author_name: str | None = None
    created_at: datetime


class AuditLogOut(ORMModel):
    id: int
    timestamp: datetime
    actor_id: int | None = None
    actor_username: str | None = None
    actor_role: str | None = None
    action: str
    outcome: str
    target_type: str | None = None
    target_id: str | None = None
    detail: str | None = None
    method: str | None = None
    path: str | None = None
    ip_address: str | None = None


class AnnouncementCreate(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    body: str = Field(min_length=1, max_length=4000)
    course_id: int | None = None
