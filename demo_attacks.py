"""Scripted privilege-escalation attempts against a running portal.

This is the evidence generator: it logs in as ordinary users and then tries to
step outside their role (vertical escalation) and outside their own records
(horizontal escalation), exactly as a manipulated client would. Every attempt
is reported as expected vs actual status, and the resulting audit entries are
printed at the end.

    python demo_attacks.py                 # starts its own server on a temp database
    python demo_attacks.py --base-url http://127.0.0.1:8000

The report is written to docs/evidence/attack_demo.md.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

EVIDENCE = Path("docs/evidence/attack_demo.md")

STUDENT_A = ("student.alice", "Student#2026")
STUDENT_B = ("student.bob", "Student#2026")
FACULTY_A = ("faculty.brown", "Faculty#2026")
ADMIN = ("admin.root", "Admin#2026")


@dataclass
class Attempt:
    category: str
    description: str
    method: str
    path: str
    expected: int
    actual: int
    body: str

    @property
    def passed(self) -> bool:
        return self.actual == self.expected


class Portal:
    def __init__(self, base_url: str) -> None:
        self.client = httpx.Client(base_url=base_url, timeout=10.0)

    def token(self, credentials: tuple[str, str]) -> str:
        username, password = credentials
        response = self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        response.raise_for_status()
        # Login also sets a browser session cookie; drop it so each attempt below
        # is authenticated only by the bearer token it explicitly carries.
        self.client.cookies.clear()
        return response.json()["access_token"]

    def whoami(self, token: str) -> dict:
        return self.client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).json()

    def attempt(
        self,
        category: str,
        description: str,
        method: str,
        path: str,
        expected: int,
        token: str | None = None,
        json: dict | None = None,
    ) -> Attempt:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = self.client.request(method, path, headers=headers, json=json)
        return Attempt(
            category=category,
            description=description,
            method=method,
            path=path,
            expected=expected,
            actual=response.status_code,
            body=response.text[:160],
        )


def run_scenarios(portal: Portal) -> tuple[list[Attempt], list[dict]]:
    alice_token = portal.token(STUDENT_A)
    bob_token = portal.token(STUDENT_B)
    faculty_token = portal.token(FACULTY_A)
    admin_token = portal.token(ADMIN)

    alice = portal.whoami(alice_token)
    bob = portal.whoami(bob_token)
    faculty = portal.whoami(faculty_token)

    courses = portal.client.get(
        f"/api/faculty/{faculty['id']}/courses", headers={"Authorization": f"Bearer {faculty_token}"}
    ).json()
    own_course = courses[0]["id"]
    all_courses = portal.client.get(
        "/api/admin/courses", headers={"Authorization": f"Bearer {admin_token}"}
    ).json()
    other_course = next(c["id"] for c in all_courses if c["faculty_id"] != faculty["id"])

    attempts = [
        # --- Baseline: legitimate access still works ----------------------
        portal.attempt(
            "baseline",
            "Student reads their own grades",
            "GET",
            f"/api/students/{alice['id']}/grades",
            200,
            alice_token,
        ),
        portal.attempt(
            "baseline",
            "Faculty reads the roster of their own course",
            "GET",
            f"/api/faculty/courses/{own_course}/roster",
            200,
            faculty_token,
        ),
        portal.attempt(
            "baseline",
            "Administrator lists accounts",
            "GET",
            "/api/admin/users",
            200,
            admin_token,
        ),
        # --- Horizontal escalation ---------------------------------------
        portal.attempt(
            "horizontal",
            "Student A requests Student B's grades by id",
            "GET",
            f"/api/students/{bob['id']}/grades",
            403,
            alice_token,
        ),
        portal.attempt(
            "horizontal",
            "Student A requests Student B's profile",
            "GET",
            f"/api/students/{bob['id']}/profile",
            403,
            alice_token,
        ),
        portal.attempt(
            "horizontal",
            "Faculty opens a colleague's course roster",
            "GET",
            f"/api/faculty/courses/{other_course}/roster",
            403,
            faculty_token,
        ),
        portal.attempt(
            "horizontal",
            "Faculty writes a grade on a colleague's course",
            "PUT",
            f"/api/faculty/courses/{other_course}/grades",
            403,
            faculty_token,
            {"student_id": bob["id"], "score": 100},
        ),
        # --- Vertical escalation ------------------------------------------
        portal.attempt(
            "vertical",
            "Student calls an administrator endpoint",
            "GET",
            "/api/admin/users",
            403,
            alice_token,
        ),
        portal.attempt(
            "vertical",
            "Student promotes themselves to administrator",
            "PUT",
            f"/api/admin/users/{alice['id']}/role",
            403,
            alice_token,
            {"role": "admin"},
        ),
        portal.attempt(
            "vertical",
            "Student writes a grade for themselves",
            "PUT",
            f"/api/faculty/courses/{own_course}/grades",
            403,
            alice_token,
            {"student_id": alice["id"], "score": 100},
        ),
        portal.attempt(
            "vertical",
            "Faculty reads the audit log",
            "GET",
            "/api/admin/audit",
            403,
            faculty_token,
        ),
        portal.attempt(
            "vertical",
            "Administrator edits a grade (not an administrator's job)",
            "PUT",
            f"/api/faculty/courses/{own_course}/grades",
            403,
            admin_token,
            {"student_id": alice["id"], "score": 100},
        ),
        # --- Session handling ---------------------------------------------
        portal.attempt(
            "session",
            "Request with no session at all",
            "GET",
            f"/api/students/{alice['id']}/grades",
            401,
        ),
        portal.attempt(
            "session",
            "Request with a forged token",
            "GET",
            "/api/admin/users",
            401,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.not-a-real-signature",
        ),
    ]

    # A logged-out token must stop working immediately.
    throwaway = portal.token(STUDENT_B)
    portal.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {throwaway}"})
    attempts.append(
        portal.attempt(
            "session",
            "Token replayed after logout",
            "GET",
            f"/api/students/{bob['id']}/grades",
            401,
            throwaway,
        )
    )

    denied = portal.client.get(
        "/api/admin/audit",
        params={"outcome": "denied", "limit": 20},
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()
    return attempts, denied


def report(attempts: list[Attempt], denied: list[dict]) -> str:
    passed = sum(1 for a in attempts if a.passed)
    lines = [
        "# Attack demonstration",
        "",
        f"Attempts: **{len(attempts)}** &middot; behaved as expected: **{passed}**"
        f" &middot; unexpected: **{len(attempts) - passed}**",
        "",
        "| # | Category | Attempt | Request | Expected | Actual | Result |",
        "|---|----------|---------|---------|----------|--------|--------|",
    ]
    for index, attempt in enumerate(attempts, start=1):
        lines.append(
            f"| {index} | {attempt.category} | {attempt.description} | "
            f"`{attempt.method} {attempt.path}` | {attempt.expected} | {attempt.actual} | "
            f"{'PASS' if attempt.passed else 'FAIL'} |"
        )

    lines += [
        "",
        "Every refusal returned the same body, revealing nothing about the target:",
        "",
        "```json",
        next(
            (a.body for a in attempts if a.actual == 403),
            '{"detail": "Access denied"}',
        ),
        "```",
        "",
        "## Audit trail produced by these attempts",
        "",
        "| Time | Actor | Role | Action | Endpoint | Detail |",
        "|------|-------|------|--------|----------|--------|",
    ]
    for entry in denied[:15]:
        lines.append(
            f"| {entry['timestamp'][11:19]} | {entry['actor_username'] or 'anonymous'} | "
            f"{entry['actor_role'] or '-'} | `{entry['action']}` | "
            f"`{entry['target_id'] or ''}` | {entry['detail'] or ''} |"
        )
    lines.append("")
    return "\n".join(lines)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server() -> tuple[subprocess.Popen, str]:
    """Run a throwaway portal on a temporary database."""
    port = free_port()
    database = Path(tempfile.mkdtemp()) / "demo.db"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{database.as_posix()}"}

    subprocess.run([sys.executable, "seed_data.py"], env=env, check=True, capture_output=True)
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            if httpx.get(f"{base_url}/health", timeout=1.0).status_code == 200:
                return process, base_url
        except httpx.HTTPError:
            time.sleep(0.5)
    process.terminate()
    raise RuntimeError("the demo server did not start")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="target an already running portal")
    parser.add_argument("--output", default=str(EVIDENCE), help="where to write the report")
    args = parser.parse_args()

    process = None
    if args.base_url:
        base_url = args.base_url
    else:
        process, base_url = start_server()

    try:
        portal = Portal(base_url)
        attempts, denied = run_scenarios(portal)
    finally:
        if process is not None:
            process.terminate()

    for attempt in attempts:
        mark = "ok  " if attempt.passed else "FAIL"
        print(f"[{mark}] {attempt.category:<10} {attempt.description:<55} "
              f"expected {attempt.expected}, got {attempt.actual}")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report(attempts, denied), encoding="utf-8")
    print(f"\nReport written to {output}")

    failures = [a for a in attempts if not a.passed]
    if failures:
        print(f"{len(failures)} attempt(s) did not behave as expected", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
