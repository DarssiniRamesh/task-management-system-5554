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

3. Run the server:
   uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

## Environment Variables

- DATABASE_URL (default: sqlite:///./app.db)
- SECRET_KEY (required in production; placeholder in example)
- ACCESS_TOKEN_EXPIRE_MINUTES (default: 60)
- ENVIRONMENT (default: development)
- CORS_ALLOW_ORIGINS (default: http://localhost:3000 or "*" if left blank in code)

Never hardcode or commit secrets. Always use environment variables.

## Smoke Test

1. Health:
   curl http://localhost:8000/

2. Register:
   curl -X POST http://localhost:8000/auth/register -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"password123"}'

3. Login and get token:
   TOKEN=$(curl -s -X POST http://localhost:8000/auth/login -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"password123"}' | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

4. Get current user:
   curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/me

5. Create a task:
   curl -X POST http://localhost:8000/tasks -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"title":"My first task","description":"Test task"}'

## OpenAPI

- Interactive docs: http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/openapi.json

To regenerate the interfaces/openapi.json file locally:
   python -m src.api.generate_openapi

## Notes

- SQLite is convenient for local development. For production, use a managed database and update DATABASE_URL accordingly.
- Ensure CORS_ALLOW_ORIGINS includes your frontend origin to allow the browser to access the API.
