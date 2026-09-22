"""Global exception handling.

Error responses are part of the attack surface. A message such as "you are not
the owner of grade 42" confirms that grade 42 exists and hints at how to reach
it; a stack trace reveals file paths, library versions and query structure.
Every response leaving the application is therefore reduced to a fixed,
uninformative message, while the details go to the server log only.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.audit import audit_denied_request

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


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
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
    # Denials are audited centrally on the way out.
    return await audit_denied_request(request, exc)


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
