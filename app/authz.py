"""Authorization: the layer that turns an identity into an allowed action.

Three rules are enforced here:

1. **Deny by default** — a route is unreachable unless it declares the
   permission it needs. :func:`verify_deny_by_default` proves this at startup by
   walking the route table, so a forgotten guard is a crash, not a hole.
2. **Role check** — the caller's role must hold the declared permission.
3. **Object-level check** — holding ``grades:read_own`` does not say *whose*
   grades; the ownership helpers below decide that from server-side state.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request
from fastapi.routing import APIRoute
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Course, Enrollment, User
from app.permissions import Permission, has_permission
from app.security import get_current_user

#: Every authorization failure returns this message and nothing else: no
#: resource names, no "you are not the owner", no hint that the object exists.
ACCESS_DENIED_MESSAGE = "Access denied"

#: The only endpoints reachable without authentication. Anything not listed
#: here must declare a permission or the application refuses to start.
PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/",  # redirects to the dashboard, shows nothing itself
        "/health",
        "/login",
        "/api/auth/login",
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
    }
)

#: Routes that need a logged-in user but no further permission (they act purely
#: on the caller's own session). The dashboard is here because it renders a
#: different view per role rather than exposing one privileged resource.
SESSION_ONLY_PATHS: frozenset[str] = frozenset(
    {"/api/auth/logout", "/api/auth/me", "/logout", "/dashboard"}
)


def access_denied() -> HTTPException:
    return HTTPException(status_code=403, detail=ACCESS_DENIED_MESSAGE)


def require_permission(*required: Permission):
    """Build a dependency that admits only roles holding **all** ``required``
    permissions, and returns the authenticated user.

    The permissions are attached to the dependency so the startup audit can see
    which routes are protected.
    """
    if not required:  # pragma: no cover - programming error
        raise ValueError("require_permission() needs at least one permission")

    def dependency(request: Request, current_user: User = Depends(get_current_user)) -> User:
        if not all(has_permission(current_user.role, permission) for permission in required):
            request.state.denied_permission = ",".join(p.value for p in required)
            raise access_denied()
        return current_user

    dependency.rbac_permissions = frozenset(required)  # type: ignore[attr-defined]
    dependency.__name__ = "require_" + "_".join(p.name.lower() for p in required)
    return dependency


# --- Object-level (ownership) checks ---------------------------------------
#
# A role check answers "may this kind of user read grades?"; these answer
# "may this particular user read *this* record?". Both must pass.


def ensure_self(current_user: User, target_user_id: int) -> None:
    """Reject any attempt to act on another user's records (horizontal escalation).

    The caller's id comes from the verified session, never from the request
    body, so a manipulated client cannot claim to be someone else.
    """
    if current_user.id != target_user_id:
        raise access_denied()


def get_own_enrollment(db: Session, student: User, course_id: int) -> Enrollment:
    """Return the caller's enrollment in ``course_id`` or deny access.

    An unenrolled student and a non-existent course are indistinguishable in the
    response, so the endpoint cannot be used to discover which courses exist.
    """
    enrollment = db.scalar(
        select(Enrollment).where(
            Enrollment.student_id == student.id, Enrollment.course_id == course_id
        )
    )
    if enrollment is None:
        raise access_denied()
    return enrollment


def get_assigned_course(db: Session, faculty: User, course_id: int) -> Course:
    """Return a course only if ``faculty`` is the assigned instructor.

    Assignment lives on the course row, which only an administrator can change;
    a faculty member cannot reach a colleague's course by editing an id.
    """
    course = db.get(Course, course_id)
    if course is None or course.faculty_id != faculty.id:
        raise access_denied()
    return course


def get_enrollment_in_course(db: Session, course_id: int, student_id: int) -> Enrollment:
    """Return the enrollment linking ``student_id`` to ``course_id``, or deny.

    Used before writing a grade so an instructor cannot grade a student who is
    not on their roster.
    """
    enrollment = db.scalar(
        select(Enrollment).where(
            Enrollment.course_id == course_id, Enrollment.student_id == student_id
        )
    )
    if enrollment is None:
        raise access_denied()
    return enrollment


# --- Startup audit of the route table --------------------------------------


def _iter_dependants(dependant) -> Iterator:
    yield dependant
    for sub_dependant in dependant.dependencies:
        yield from _iter_dependants(sub_dependant)


def _expand_route(route) -> Iterator:
    """Yield every endpoint behind ``route``.

    FastAPI keeps included routers nested and composes their effective paths
    lazily, so the route table has to be walked rather than simply iterated.
    """
    if isinstance(route, APIRoute):
        yield route
        return

    candidates = getattr(route, "effective_candidates", None)
    if callable(candidates):
        for nested in candidates():
            yield from _expand_route(nested)
        low_priority = getattr(route, "effective_low_priority_routes", None)
        if callable(low_priority):
            for nested in low_priority():
                yield from _expand_route(nested)
        return

    # A composed endpoint context: it carries the final path and dependency tree.
    if hasattr(route, "dependant") and hasattr(route, "path"):
        yield route


def iter_api_routes(app) -> Iterator:
    """Every API endpoint of ``app``, with included routers flattened."""
    for route in app.routes:
        yield from _expand_route(route)


def route_permissions(route) -> frozenset[Permission]:
    """The permissions a route requires, gathered from its dependency tree."""
    found: set[Permission] = set()
    for dependant in _iter_dependants(route.dependant):
        found |= getattr(dependant.call, "rbac_permissions", frozenset())
    return frozenset(found)


def route_requires_authentication(route) -> bool:
    return any(
        getattr(dependant.call, "__name__", "") == "get_current_user"
        or getattr(dependant.call, "rbac_permissions", None)
        for dependant in _iter_dependants(route.dependant)
    )


def unprotected_routes(app) -> list[str]:
    """Routes that are neither public nor guarded — this list must stay empty."""
    offenders: list[str] = []
    for route in iter_api_routes(app):
        if route.path in PUBLIC_PATHS:
            continue
        if route.path in SESSION_ONLY_PATHS:
            if not route_requires_authentication(route):
                offenders.append(f"{route.path} (no authentication)")
            continue
        if not route_permissions(route):
            offenders.append(f"{route.path} (no permission requirement)")
    return offenders


def verify_deny_by_default(app) -> None:
    """Abort startup if any route escaped the authorization layer."""
    offenders = unprotected_routes(app)
    if offenders:
        raise RuntimeError(
            "Deny-by-default violation — unprotected routes: " + ", ".join(sorted(offenders))
        )
