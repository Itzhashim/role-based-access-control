"""The server-rendered portal.

These pages are a *view* over the same authorization layer the API uses: the
identical ``require_permission`` dependencies and ownership helpers guard them,
and the write actions go through :mod:`app.services`. Hiding a link in a
template is presentation, not protection — removing the link changes nothing
about what the server will accept.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit import AuditAction, record_audit, recent_entries
from app.authz import get_assigned_course, require_permission
from app.config import settings
from app.database import get_db
from app.models import Announcement, Course, Enrollment, Role, User
from app.permissions import Permission, permissions_for
from app.routers.auth import set_session_cookie
from app.security import create_access_token, get_current_user, revoke_token
from app.services import assign_role, authenticate, set_account_active, upsert_grade

router = APIRouter(tags=["portal"])
templates = Jinja2Templates(directory="app/templates")


def render(request: Request, template: str, user: User | None = None, **context) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template,
        context={
            "user": user,
            "permissions": sorted(p.value for p in permissions_for(user.role)) if user else [],
            **context,
        },
    )


# --- Session ---------------------------------------------------------------


@router.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request, expired: int = 0) -> HTMLResponse:
    message = "Your session ended. Please sign in again." if expired else None
    return render(request, "login.html", notice=message)


@router.post("/login", response_class=HTMLResponse, response_model=None, include_in_schema=False)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    user = authenticate(db, username=username, password=password, request=request)
    if user is None:
        # One message for every failure, exactly as in the API.
        return render(request, "login.html", error="Invalid username or password")

    token, _ = create_access_token(user)
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, token)
    return response


@router.get("/logout", include_in_schema=False)
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    revoke_token(db, request.state.token_claims)
    record_audit(db, action=AuditAction.LOGOUT, actor=current_user, request=request)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie_name, path="/")
    return response


# --- Dashboard -------------------------------------------------------------


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """One entry point, three very different views — chosen by the server."""
    if current_user.role is Role.STUDENT:
        enrollments = db.scalars(
            select(Enrollment).where(Enrollment.student_id == current_user.id)
        ).all()
        return render(
            request,
            "dashboard_student.html",
            user=current_user,
            enrollments=enrollments,
            announcements=_student_announcements(db, current_user),
        )

    if current_user.role is Role.FACULTY:
        courses = db.scalars(select(Course).where(Course.faculty_id == current_user.id)).all()
        return render(request, "dashboard_faculty.html", user=current_user, courses=courses)

    users = db.scalars(select(User).order_by(User.username)).all()
    return render(
        request,
        "dashboard_admin.html",
        user=current_user,
        users=users,
        courses=db.scalars(select(Course).order_by(Course.code)).all(),
        recent=recent_entries(db, limit=10),
    )


def _student_announcements(db: Session, student: User) -> list[Announcement]:
    enrolled_course_ids = select(Enrollment.course_id).where(Enrollment.student_id == student.id)
    return list(
        db.scalars(
            select(Announcement)
            .where(
                or_(
                    Announcement.course_id.is_(None),
                    Announcement.course_id.in_(enrolled_course_ids),
                )
            )
            .order_by(Announcement.created_at.desc())
        ).all()
    )


# --- Student pages ---------------------------------------------------------


@router.get("/portal/grades", response_class=HTMLResponse, include_in_schema=False)
def my_grades(
    request: Request,
    current_user: User = Depends(require_permission(Permission.GRADES_READ_OWN)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    enrollments = db.scalars(
        select(Enrollment).where(Enrollment.student_id == current_user.id)
    ).all()
    return render(request, "student_grades.html", user=current_user, enrollments=enrollments)


# --- Faculty pages ---------------------------------------------------------


@router.get("/portal/courses/{course_id}", response_class=HTMLResponse, include_in_schema=False)
def course_roster(
    course_id: int,
    request: Request,
    saved: int = 0,
    current_user: User = Depends(require_permission(Permission.ROSTER_READ_ASSIGNED)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    course = get_assigned_course(db, current_user, course_id)
    return render(
        request,
        "faculty_roster.html",
        user=current_user,
        course=course,
        saved=bool(saved),
    )


@router.post(
    "/portal/courses/{course_id}/grades", response_class=HTMLResponse, include_in_schema=False
)
def submit_grade(
    course_id: int,
    request: Request,
    student_id: int = Form(...),
    score: float = Form(...),
    comment: str = Form(""),
    current_user: User = Depends(require_permission(Permission.GRADES_WRITE_COURSE)),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Grade submission from the roster page.

    The session cookie is ``SameSite=Lax``, so a third-party site cannot make a
    browser post this form on the instructor's behalf.
    """
    if not 0 <= score <= 100:
        raise HTTPException(status_code=422, detail="Invalid request")

    upsert_grade(
        db,
        faculty=current_user,
        course_id=course_id,
        student_id=student_id,
        score=score,
        comment=comment or None,
        request=request,
    )
    return RedirectResponse(f"/portal/courses/{course_id}?saved=1", status_code=303)


# --- Administrator pages ---------------------------------------------------


@router.get("/portal/admin/users", response_class=HTMLResponse, include_in_schema=False)
def manage_users(
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_READ_ANY)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    users = db.scalars(select(User).order_by(User.username)).all()
    return render(
        request, "admin_users.html", user=current_user, users=users, roles=list(Role)
    )


@router.post("/portal/admin/users/{user_id}/role", include_in_schema=False)
def change_role(
    user_id: int,
    request: Request,
    role: Role = Form(...),
    current_user: User = Depends(require_permission(Permission.ROLES_ASSIGN)),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Not found")
    assign_role(
        db, administrator=current_user, target_user=target, new_role=role, request=request
    )
    return RedirectResponse("/portal/admin/users", status_code=303)


@router.post("/portal/admin/users/{user_id}/active", include_in_schema=False)
def change_account_state(
    user_id: int,
    request: Request,
    is_active: str = Form(...),
    current_user: User = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Not found")
    set_account_active(
        db,
        administrator=current_user,
        target_user=target,
        is_active=is_active == "true",
        request=request,
    )
    return RedirectResponse("/portal/admin/users", status_code=303)


@router.get("/portal/admin/audit", response_class=HTMLResponse, include_in_schema=False)
def audit_page(
    request: Request,
    outcome: str | None = None,
    current_user: User = Depends(require_permission(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    entries = recent_entries(db, limit=200, outcome=outcome)
    return render(
        request, "admin_audit.html", user=current_user, entries=entries, outcome=outcome or ""
    )
