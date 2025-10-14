# To Do Backend (FastAPI)

Backend API for the To Do application providing health, auth, and tasks CRUD.

## Prerequisites

- Python 3.11+
- pip
- Recommended: virtualenv or similar

## Setup

1. Create a virtual environment and install dependencies:
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt

2. Create your environment file:
   cp .env.example .env
   # Edit ".env" and set values:
   # - SECRET_KEY: set a strong random value in production (do not commit)
   # - DATABASE_URL: default uses SQLite local file (sqlite:///./app.db)
   # - ACCESS_TOKEN_EXPIRE_MINUTES: token expiry time in minutes
   # - CORS_ALLOW_ORIGINS: frontend origin(s), e.g., http://localhost:3000
   # - ENVIRONMENT: development | staging | production

3. Run the server (port 3001):
   uvicorn src.api.main:app --reload --host 0.0.0.0 --port 3001

## Environment Variables

- DATABASE_URL (default: sqlite:///./app.db)
  - Local dev: SQLite file is fine and auto-creates tables on startup.
  - Production: Use a managed DB (e.g., Postgres) and run Alembic migrations (see below).
- SECRET_KEY (required in production; placeholder in example)
- ACCESS_TOKEN_EXPIRE_MINUTES (default: 60)
- ENVIRONMENT (default: development)
- CORS_ALLOW_ORIGINS (default: http://localhost:3000 or "*" if left blank in code)

Never hardcode or commit secrets. Always use environment variables.

## CORS and Logging

- CORS is configured via CORS_ALLOW_ORIGINS (comma-separated). Defaults to permissive in dev.
- Structured JSON logging is enabled with safe context only (no PII). Centralized exception handlers
  return safe messages for validation and server errors.

## Database options and behavior

- SQLite (local dev): When ENVIRONMENT=development or DATABASE_URL starts with sqlite,
  the app will create tables automatically on startup for convenience. SQLite is configured
  with pragmas (foreign_keys=ON, journal_mode=WAL, synchronous=NORMAL) and a shared StaticPool
  for in-memory usage to improve test/dev ergonomics.

- Networked DBs (e.g., PostgreSQL) in non-dev environments: The app initializes the engine
  but skips create_all. Use Alembic migrations to manage schema changes.

### Example DATABASE_URL values
- SQLite dev (default): sqlite:///./app.db
- PostgreSQL (psycopg2): postgresql+psycopg2://USER:PASSWORD@HOST:5432/DBNAME

## Indices and constraints

- users.email is unique and indexed.
- tasks.user_id has an explicit index to optimize user-scoped queries.

## Alembic migrations (guidance)

This project is migration-ready conceptually; if you introduce schema changes or deploy to production,
you should manage schema using Alembic.

Basic steps to add Alembic:

1. Install Alembic:
   pip install alembic

2. Initialize Alembic in this backend directory:
   alembic init alembic

3. Configure alembic.ini and env.py:
   - Set sqlalchemy.url to use ${DATABASE_URL} env var or fetch from settings.
   - In env.py, import Base from src.db.session and use:
       from src.db.session import Base
       target_metadata = Base.metadata

4. Generate and apply migrations:
   alembic revision --autogenerate -m "Initial schema"
   alembic upgrade head

Notes:
- Do not run create_all in production; rely on `alembic upgrade head`.
- Keep models authoritative; indices/constraints are defined in src/db/models.py.

## Smoke Test

1. Health:
   curl http://localhost:3001/

2. Register:
   curl -X POST http://localhost:3001/auth/register -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"password123"}'

3. Login and get token:
   TOKEN=$(curl -s -X POST http://localhost:3001/auth/login -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"password123"}' | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

4. Get current user:
   curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/auth/me

5. Create a task:
   curl -X POST http://localhost:3001/tasks -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"title":"My first task","description":"Test task"}'

## OpenAPI

- Interactive docs: http://localhost:3001/docs
- OpenAPI JSON: http://localhost:3001/openapi.json

To regenerate the interfaces/openapi.json file locally:
   python -m src.api.generate_openAPI

## Notes

- SQLite is convenient for local development. For production, use a managed database and update DATABASE_URL accordingly.
- Ensure CORS_ALLOW_ORIGINS includes your frontend origin to allow the browser to access the API.
