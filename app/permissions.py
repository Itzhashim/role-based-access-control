"""The role-permission matrix.

Roles exist so that permissions can be managed in one place instead of being
scattered across route handlers. Every protected endpoint names the permission
it needs; this module is the only place that decides which role holds it.
"""

from __future__ import annotations

import enum

from app.models import Role


class Permission(str, enum.Enum):
    """Fine-grained capabilities. The suffix states the scope:

    ``_own``       the caller's own records only
    ``_enrolled``  courses the caller is enrolled in
    ``_assigned``  courses the caller is assigned to teach
    ``_any``       across the whole institution
    """

    # Shared
    META_READ = "meta:read"

    # Student
    PROFILE_READ_OWN = "profile:read_own"
    GRADES_READ_OWN = "grades:read_own"
    COURSES_READ_ENROLLED = "courses:read_enrolled"

    # Faculty
    COURSES_READ_ASSIGNED = "courses:read_assigned"
    ROSTER_READ_ASSIGNED = "roster:read_assigned"
    GRADES_READ_COURSE = "grades:read_course"
    GRADES_WRITE_COURSE = "grades:write_course"
    ANNOUNCEMENTS_WRITE_COURSE = "announcements:write_course"

    # Administrator
    USERS_READ_ANY = "users:read_any"
    USERS_MANAGE = "users:manage"
    ROLES_ASSIGN = "roles:assign"
    COURSES_MANAGE = "courses:manage"
    ENROLLMENTS_MANAGE = "enrollments:manage"
    ANNOUNCEMENTS_WRITE_GLOBAL = "announcements:write_global"
    AUDIT_READ = "audit:read"


STUDENT_PERMISSIONS = frozenset(
    {
        Permission.META_READ,
        Permission.PROFILE_READ_OWN,
        Permission.GRADES_READ_OWN,
        Permission.COURSES_READ_ENROLLED,
    }
)

FACULTY_PERMISSIONS = frozenset(
    {
        Permission.META_READ,
        Permission.PROFILE_READ_OWN,
        Permission.COURSES_READ_ASSIGNED,
        Permission.ROSTER_READ_ASSIGNED,
        Permission.GRADES_READ_COURSE,
        Permission.GRADES_WRITE_COURSE,
        Permission.ANNOUNCEMENTS_WRITE_COURSE,
    }
)

ADMIN_PERMISSIONS = frozenset(
    {
        Permission.META_READ,
        Permission.PROFILE_READ_OWN,
        Permission.USERS_READ_ANY,
        Permission.USERS_MANAGE,
        Permission.ROLES_ASSIGN,
        Permission.COURSES_MANAGE,
        Permission.ENROLLMENTS_MANAGE,
        Permission.ANNOUNCEMENTS_WRITE_GLOBAL,
        Permission.AUDIT_READ,
    }
)

#: The single source of truth for "which role may do what".
#:
#: Note what an administrator deliberately does *not* hold: no
#: ``grades:write_course`` and no ``grades:read_own`` for other people's
#: records. Administration is about managing accounts, courses and oversight,
#: not about silently editing academic results.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.STUDENT: STUDENT_PERMISSIONS,
    Role.FACULTY: FACULTY_PERMISSIONS,
    Role.ADMIN: ADMIN_PERMISSIONS,
}


def permissions_for(role: Role) -> frozenset[Permission]:
    """Permissions held by ``role`` — an unknown role holds none (deny by default)."""
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in permissions_for(role)


def matrix_as_dict() -> dict[str, list[str]]:
    """The matrix in a serialisable form, used by the API and the documentation."""
    return {
        role.value: sorted(p.value for p in permissions_for(role))
        for role in (Role.STUDENT, Role.FACULTY, Role.ADMIN)
    }
