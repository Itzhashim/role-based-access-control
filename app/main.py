"""FastAPI application entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.audit import audit_denied_request
from app.config import settings
from app.authz import verify_deny_by_default
from app.database import init_db
from app.routers import admin, auth, faculty, meta, students


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="A college portal demonstrating role-based access control.",
        lifespan=lifespan,
    )

    # Every refused request is audited in one place.
    app.add_exception_handler(StarletteHTTPException, audit_denied_request)

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(auth.router)
    app.include_router(meta.router)
    app.include_router(students.router)
    app.include_router(faculty.router)
    app.include_router(admin.router)

    # Fail fast if any route was added without an authorization requirement.
    verify_deny_by_default(app)

    return app


app = create_app()
