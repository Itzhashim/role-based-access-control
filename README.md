# RBAC College Portal

A college portal that separates **Student**, **Faculty** and **Administrator** functions and
data using server-side role-based access control. Built with FastAPI, SQLAlchemy and SQLite,
with a server-rendered web portal and a JSON API sharing the same authorization layer.

## Features

- Role-permission matrix with three roles and deny-by-default routing
- Object-level ownership and course-assignment checks (no cross-user data access)
- JWT sessions with expiry, logout revocation and an account lockout on repeated failures
- Audit log of sensitive operations and every refused request
- Uniform, non-revealing error responses
- Web portal (role-specific dashboards) plus a documented REST API
- 150 automated tests covering positive, vertical-escalation and horizontal-escalation cases

## Tech stack

| Layer | Choice |
|-------|--------|
| Language | Python 3.10+ |
| Framework | FastAPI |
| Database | SQLite via SQLAlchemy 2 |
| Templates | Jinja2 |
| Security | `bcrypt` (password hashing), `PyJWT` (sessions) |
| Tests | pytest + httpx |

## Requirements

- Python 3.10 or newer

## Setup

```bash
git clone https://github.com/Itzhashim/role-based-access-control.git
cd role-based-access-control

python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
```

### Windows: "running scripts is disabled on this system"

PowerShell's execution policy blocks `.venv\Scripts\Activate.ps1` by default. Either allow
local scripts for your own user (no admin rights required):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

use the batch activator instead:

```powershell
.\.venv\Scripts\activate.bat
```

or skip activation altogether and call the interpreter inside the virtual environment directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe seed_data.py
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
.\.venv\Scripts\python.exe -m pytest
```

### Configuration

The defaults work out of the box. To override them, create a `.env` file:

```ini
SECRET_KEY=replace-with-a-long-random-string
DATABASE_URL=sqlite:///./portal.db
ACCESS_TOKEN_TTL_MINUTES=30
MAX_FAILED_LOGINS=5
COOKIE_SECURE=false
```

## Seed the database

```bash
python seed_data.py            # create and populate portal.db
python seed_data.py --reset    # start from an empty database
```

### Demo accounts

| Username | Password | Role | Data |
|----------|----------|------|------|
| `admin.root` | `Admin#2026` | Administrator | all accounts and courses |
| `faculty.brown` | `Faculty#2026` | Faculty | teaches CS101, CS204 |
| `faculty.davis` | `Faculty#2026` | Faculty | teaches MA201, MA310 |
| `student.alice` | `Student#2026` | Student | CS101, CS204, MA201 |
| `student.bob` | `Student#2026` | Student | CS101, MA201 |
| `student.carol` | `Student#2026` | Student | MA201, MA310 |
| `student.dan` | `Student#2026` | Student | CS101, MA310 |

## Run

```bash
uvicorn app.main:app --reload
```

- Portal: <http://127.0.0.1:8000/login>
- API docs (Swagger UI): <http://127.0.0.1:8000/docs>

## API overview

| Method | Endpoint | Required permission |
|--------|----------|---------------------|
| `POST` | `/api/auth/login` | public |
| `POST` | `/api/auth/logout` | any session |
| `GET` | `/api/auth/me` | any session |
| `GET` | `/api/meta/permissions` | `meta:read` |
| `GET` | `/api/students/{id}/grades` | `grades:read_own` + ownership |
| `GET` | `/api/students/{id}/courses` | `courses:read_enrolled` + ownership |
| `GET` | `/api/faculty/courses/{id}/roster` | `roster:read_assigned` + assignment |
| `PUT` | `/api/faculty/courses/{id}/grades` | `grades:write_course` + assignment |
| `GET` | `/api/admin/users` | `users:read_any` |
| `PUT` | `/api/admin/users/{id}/role` | `roles:assign` |
| `GET` | `/api/admin/audit` | `audit:read` |

## Tests

```bash
pytest                                   # full suite
pytest tests/test_access_matrix.py -v    # the role/endpoint matrix
```

To reproduce the privilege-escalation demonstration (starts its own throwaway server and
writes `docs/evidence/attack_demo.md`):

```bash
python demo_attacks.py
python demo_attacks.py --base-url http://127.0.0.1:8000   # target a running portal
```

## Project structure

```
app/
  main.py          application setup, routers, exception handlers
  config.py        settings
  database.py      engine and session
  models.py        users, courses, enrollments, grades, announcements, audit log
  schemas.py       request/response models
  security.py      password hashing, JWT sessions, lockout
  permissions.py   role-permission matrix
  authz.py         permission dependencies and ownership checks
  services.py      operations shared by the API and the portal
  audit.py         audit logging
  errors.py        global exception handlers
  routers/         auth, students, faculty, admin, meta, portal (HTML)
  templates/       Jinja2 pages
  static/          stylesheet
seed_data.py       synthetic demo data
demo_attacks.py    scripted escalation attempts
tests/             pytest suite
docs/              security report and test evidence
```

## Documentation

- [Security report](docs/security_report.md) — architecture, threat model, controls and test evidence
- [Test results](docs/test_results.md) — expected vs actual status codes
- [Evidence](docs/evidence/) — captured test output and attack-demo report

## License

Released under the MIT License. See [LICENSE](LICENSE).
