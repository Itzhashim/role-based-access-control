# Test Results

Reproduce with:

```bash
pytest -v                 # full suite
python demo_attacks.py    # scripted escalation attempts
```

Captured evidence: [`evidence/pytest_output.txt`](evidence/pytest_output.txt) and
[`evidence/attack_demo.md`](evidence/attack_demo.md).

## Summary

| Suite | File | Tests | Result |
|-------|------|------:|--------|
| Authentication and sessions | `tests/test_auth.py` | 10 | pass |
| Deny-by-default and matrix invariants | `tests/test_deny_by_default.py` | 8 | pass |
| Student access and ownership | `tests/test_student_access.py` | 13 | pass |
| Faculty access and course assignment | `tests/test_faculty_access.py` | 13 | pass |
| Administration and vertical escalation | `tests/test_admin_access.py` | 25 | pass |
| Audit logging | `tests/test_audit.py` | 11 | pass |
| Error safety and lockout | `tests/test_error_safety.py` | 7 | pass |
| Browser portal | `tests/test_portal_ui.py` | 18 | pass |
| Role × endpoint access matrix | `tests/test_access_matrix.py` | 45 | pass |
| **Total** | | **150** | **pass** |

## Positive cases (expected 200/201/303)

| # | Case | Endpoint | Expected | Actual |
|---|------|----------|:--------:|:------:|
| 1 | Student logs in | `POST /api/auth/login` | 200 | 200 |
| 2 | Faculty logs in | `POST /api/auth/login` | 200 | 200 |
| 3 | Administrator logs in | `POST /api/auth/login` | 200 | 200 |
| 4 | Student reads own grades | `GET /api/students/{self}/grades` | 200 | 200 |
| 5 | Student reads own enrolled courses | `GET /api/students/{self}/courses` | 200 | 200 |
| 6 | Student reads grade for an enrolled course | `GET /api/students/{self}/courses/{id}/grade` | 200 | 200 |
| 7 | Student reads own + campus announcements | `GET /api/students/{self}/announcements` | 200 | 200 |
| 8 | Faculty lists assigned courses | `GET /api/faculty/{self}/courses` | 200 | 200 |
| 9 | Faculty reads assigned roster | `GET /api/faculty/courses/{own}/roster` | 200 | 200 |
| 10 | Faculty updates a grade on an assigned course | `PUT /api/faculty/courses/{own}/grades` | 200 | 200 |
| 11 | Faculty publishes a course announcement | `POST /api/faculty/courses/{own}/announcements` | 201 | 201 |
| 12 | Administrator lists accounts | `GET /api/admin/users` | 200 | 200 |
| 13 | Administrator creates an account | `POST /api/admin/users` | 201 | 201 |
| 14 | Administrator assigns a role | `PUT /api/admin/users/{id}/role` | 200 | 200 |
| 15 | Administrator creates and assigns a course | `POST /api/admin/courses` | 201 | 201 |
| 16 | Administrator enrolls a student | `POST /api/admin/enrollments` | 201 | 201 |
| 17 | Administrator reads the audit log | `GET /api/admin/audit` | 200 | 200 |
| 18 | Faculty saves a grade from the portal form | `POST /portal/courses/{own}/grades` | 303 | 303 |

## Negative cases — vertical escalation (expected 403)

| # | Case | Endpoint | Expected | Actual |
|---|------|----------|:--------:|:------:|
| 19 | Student calls an admin endpoint | `GET /api/admin/users` | 403 | 403 |
| 20 | Student promotes themselves | `PUT /api/admin/users/{self}/role` | 403 | 403 |
| 21 | Student creates an account | `POST /api/admin/users` | 403 | 403 |
| 22 | Student enrolls themselves | `POST /api/admin/enrollments` | 403 | 403 |
| 23 | Student writes a grade | `PUT /api/faculty/courses/{id}/grades` | 403 | 403 |
| 24 | Student reads a course roster | `GET /api/faculty/courses/{id}/roster` | 403 | 403 |
| 25 | Student reads the audit log | `GET /api/admin/audit` | 403 | 403 |
| 26 | Faculty calls an admin endpoint | `GET /api/admin/users` | 403 | 403 |
| 27 | Faculty reads the audit log | `GET /api/admin/audit` | 403 | 403 |
| 28 | Faculty reads a student's grade route | `GET /api/students/{id}/grades` | 403 | 403 |
| 29 | Administrator writes a grade | `PUT /api/faculty/courses/{id}/grades` | 403 | 403 |
| 30 | Administrator reads a student's grade route | `GET /api/students/{id}/grades` | 403 | 403 |
| 31 | Student opens the admin portal page | `GET /portal/admin/users` | 403 | 403 |
| 32 | Student posts the grade form directly | `POST /portal/courses/{id}/grades` | 403 | 403 |

## Negative cases — horizontal escalation (expected 403)

| # | Case | Endpoint | Expected | Actual |
|---|------|----------|:--------:|:------:|
| 33 | Student A reads Student B's grades | `GET /api/students/{other}/grades` | 403 | 403 |
| 34 | Student A reads Student B's profile | `GET /api/students/{other}/profile` | 403 | 403 |
| 35 | Student A lists Student B's courses | `GET /api/students/{other}/courses` | 403 | 403 |
| 36 | Student reads a course they are not enrolled in | `GET /api/students/{self}/courses/{other}/grade` | 403 | 403 |
| 37 | Student probes a non-existent course | `GET /api/students/{self}/courses/999999/grade` | 403 | 403 |
| 38 | Faculty reads a colleague's roster | `GET /api/faculty/courses/{other}/roster` | 403 | 403 |
| 39 | Faculty grades a colleague's course | `PUT /api/faculty/courses/{other}/grades` | 403 | 403 |
| 40 | Faculty grades a student not on the roster | `PUT /api/faculty/courses/{own}/grades` | 403 | 403 |
| 41 | Faculty lists another instructor's courses | `GET /api/faculty/{other}/courses` | 403 | 403 |
| 42 | Faculty opens a colleague's roster page | `GET /portal/courses/{other}` | 403 | 403 |

Cases 36 and 37 return byte-identical responses: an unenrolled course and a course that does
not exist are indistinguishable to the caller.

## Negative cases — sessions (expected 401)

| # | Case | Endpoint | Expected | Actual |
|---|------|----------|:--------:|:------:|
| 43 | No token | any protected API route | 401 | 401 |
| 44 | Malformed token | `GET /api/auth/me` | 401 | 401 |
| 45 | Token signed with another key | `GET /api/auth/me` | 401 | 401 |
| 46 | Expired token | `GET /api/auth/me` | 401 | 401 |
| 47 | Token replayed after logout | `GET /api/auth/me` | 401 | 401 |
| 48 | Session of a deactivated account | `GET /api/auth/me` | 401 | 401 |
| 49 | Wrong password | `POST /api/auth/login` | 401 | 401 |
| 50 | Unknown username | `POST /api/auth/login` | 401 | 401 |
| 51 | Correct password while locked out | `POST /api/auth/login` | 401 | 401 |
| 52 | Anonymous browser visit to the portal | `GET /dashboard` | 303 → `/login?expired=1` | 303 |

Cases 49–51 return the same status and the same body, so the endpoint cannot be used to
enumerate accounts or to detect the lockout.

## Other assertions

| Case | Expectation | Result |
|------|-------------|--------|
| Every non-public route declares a permission | startup audit finds 0 offenders | pass |
| Adding an unguarded route | application refuses to start | pass |
| Anonymous sweep of all API routes | every route returns 401 | pass |
| Invalid input (`score=9000`, script tag in a field) | 422 `{"detail": "Invalid request"}`, value not echoed | pass |
| Unhandled server exception | 500 generic body, no traceback, secret not leaked | pass |
| Sanitised 404 | `{"detail": "Not found"}` with no object description | pass |
| Session cookie flags | `HttpOnly`, `SameSite=Lax` | pass |
| Role change | takes effect on the next request, old token loses old rights | pass |
| Account deactivation | existing session rejected immediately | pass |
| Responses containing `password_hash` | none | pass |
