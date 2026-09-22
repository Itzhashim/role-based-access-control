# Attack demonstration

Attempts: **15** &middot; behaved as expected: **15** &middot; unexpected: **0**

| # | Category | Attempt | Request | Expected | Actual | Result |
|---|----------|---------|---------|----------|--------|--------|
| 1 | baseline | Student reads their own grades | `GET /api/students/4/grades` | 200 | 200 | PASS |
| 2 | baseline | Faculty reads the roster of their own course | `GET /api/faculty/courses/1/roster` | 200 | 200 | PASS |
| 3 | baseline | Administrator lists accounts | `GET /api/admin/users` | 200 | 200 | PASS |
| 4 | horizontal | Student A requests Student B's grades by id | `GET /api/students/5/grades` | 403 | 403 | PASS |
| 5 | horizontal | Student A requests Student B's profile | `GET /api/students/5/profile` | 403 | 403 | PASS |
| 6 | horizontal | Faculty opens a colleague's course roster | `GET /api/faculty/courses/3/roster` | 403 | 403 | PASS |
| 7 | horizontal | Faculty writes a grade on a colleague's course | `PUT /api/faculty/courses/3/grades` | 403 | 403 | PASS |
| 8 | vertical | Student calls an administrator endpoint | `GET /api/admin/users` | 403 | 403 | PASS |
| 9 | vertical | Student promotes themselves to administrator | `PUT /api/admin/users/4/role` | 403 | 403 | PASS |
| 10 | vertical | Student writes a grade for themselves | `PUT /api/faculty/courses/1/grades` | 403 | 403 | PASS |
| 11 | vertical | Faculty reads the audit log | `GET /api/admin/audit` | 403 | 403 | PASS |
| 12 | vertical | Administrator edits a grade (not an administrator's job) | `PUT /api/faculty/courses/1/grades` | 403 | 403 | PASS |
| 13 | session | Request with no session at all | `GET /api/students/4/grades` | 401 | 401 | PASS |
| 14 | session | Request with a forged token | `GET /api/admin/users` | 401 | 401 | PASS |
| 15 | session | Token replayed after logout | `GET /api/students/5/grades` | 401 | 401 | PASS |

Every refusal returned the same body, revealing nothing about the target:

```json
{"detail":"Access denied"}
```

## Audit trail produced by these attempts

| Time | Actor | Role | Action | Endpoint | Detail |
|------|-------|------|--------|----------|--------|
| 13:55:24 | student.bob | student | `auth_required` | `/api/students/5/grades` | status=401 |
| 13:55:24 | anonymous | - | `auth_required` | `/api/admin/users` | status=401 |
| 13:55:24 | anonymous | - | `auth_required` | `/api/students/4/grades` | status=401 |
| 13:55:24 | admin.root | admin | `access_denied` | `/api/faculty/courses/1/grades` | status=403 required=grades:write_course |
| 13:55:24 | faculty.brown | faculty | `access_denied` | `/api/admin/audit` | status=403 required=audit:read |
| 13:55:24 | student.alice | student | `access_denied` | `/api/faculty/courses/1/grades` | status=403 required=grades:write_course |
| 13:55:24 | student.alice | student | `access_denied` | `/api/admin/users/4/role` | status=403 required=roles:assign |
| 13:55:24 | student.alice | student | `access_denied` | `/api/admin/users` | status=403 required=users:read_any |
| 13:55:24 | faculty.brown | faculty | `access_denied` | `/api/faculty/courses/3/grades` | status=403 |
| 13:55:24 | faculty.brown | faculty | `access_denied` | `/api/faculty/courses/3/roster` | status=403 |
| 13:55:24 | student.alice | student | `access_denied` | `/api/students/5/profile` | status=403 |
| 13:55:24 | student.alice | student | `access_denied` | `/api/students/5/grades` | status=403 |
