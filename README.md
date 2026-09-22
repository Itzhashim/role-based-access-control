# RBAC College Portal

A college portal that separates Student, Faculty and Administrator functions and data using
server-side role-based access control. Built with FastAPI and SQLite.

## Requirements

- Python 3.10+

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --reload
```

The portal is served at http://127.0.0.1:8000 and the interactive API docs at
http://127.0.0.1:8000/docs.
