"""Global exception handling.

Error responses are part of the attack surface. A message such as "you are not
the owner of grade 42" confirms that grade 42 exists and hints at how to reach
it; a stack trace reveals file paths, library versions and query structure.
Every response leaving the application is therefore reduced to a fixed,
uninformative message, while the details go to the server log only.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.audit import audit_refusal

logger = logging.getLogger("app.errors")

#: Statuses whose message is replaced before the response is sent. Codes that
#: report a legitimate operational conflict (400, 409) keep their message: they
#: describe the caller's own request, not somebody else's data.
SAFE_DETAILS: dict[int, str] = {
    401: "Authentication required",
    403: "Access denied",
    404: "Not found",
    405: "Method not allowed",
    500: "Internal server error",
}

#: Messages that are already safe and are worth keeping for usability. The
#: login message is generic on purpose: it says nothing about whether the
#: account exists, is locked or is deactivated.
ALLOWED_DETAILS: dict[int, frozenset[str]] = {
    401: frozenset({"Invalid username or password"}),
}

INVALID_REQUEST = "Invalid request"


def _is_safe(status_code: int, detail: object) -> bool:
    return detail in ALLOWED_DETAILS.get(status_code, frozenset())


def wants_html(request: Request) -> bool:
    """True for a browser navigating the portal, false for API clients."""
    if request.url.path.startswith("/api/"):
        return False
    return "text/html" in request.headers.get("accept", "")


def html_response_for(request: Request, status_code: int) -> Response | None:
    """Turn a refusal into a page instead of a JSON body, where appropriate."""
    from app.routers.portal import render  # imported late to avoid a cycle

    if status_code == 401:
        # An expired or missing session sends the visitor back to sign in.
        return RedirectResponse("/login?expired=1", status_code=303)
    if status_code == 403:
        response = render(request, "access_denied.html")
        response.status_code = 403
        return response
    return None


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> Response:
    safe_detail = SAFE_DETAILS.get(exc.status_code)
    if safe_detail is not None and exc.detail != safe_detail and not _is_safe(
        exc.status_code, exc.detail
    ):
        logger.info(
            "sanitised %s response on %s: %r", exc.status_code, request.url.path, exc.detail
        )
        exc = HTTPException(
            status_code=exc.status_code,
            detail=safe_detail,
            headers=getattr(exc, "headers", None),
        )

    # Denials are audited centrally on the way out, whichever front door was used.
    audit_refusal(request, exc.status_code)

    if wants_html(request):
        page = html_response_for(request, exc.status_code)
        if page is not None:
            return page
    return await http_exception_handler(request, exc)


async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Reject malformed input without echoing it back.

    The default FastAPI body repeats the offending values, which is a tidy way
    to reflect injected content to whoever reads the response.
    """
    logger.info("validation error on %s: %s", request.url.path, exc.errors())
    return JSONResponse(status_code=422, content={"detail": INVALID_REQUEST})


async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Last line of defence: never let an exception reach the client."""
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": SAFE_DETAILS[500]})


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    app.add_exception_handler(Exception, handle_unexpected_error)
