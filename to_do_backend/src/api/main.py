from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import uvicorn

from src.api.routers.auth import router as auth_router
from src.api.routers.tasks import router as tasks_router
from src.core.config import get_settings
from src.db.session import Base, init_engine

# Configure module-level logger
logger = logging.getLogger("to_do_backend.api.main")
if not logger.handlers:
    # Basic configuration; in production, prefer structured JSON logging via a central config
    logging.basicConfig(level=logging.INFO)

# Initialize FastAPI app with metadata and OpenAPI tags
app = FastAPI(
    title="To Do Backend API",
    description="Backend API for the To Do application providing health, auth, and tasks CRUD.",
    version="0.1.0",
    openapi_tags=[
        {"name": "Health", "description": "Service health and readiness checks."},
        {"name": "Auth", "description": "Authentication and user management."},
        {"name": "Tasks", "description": "CRUD operations for tasks."},
    ],
)

# CORS configuration using environment settings with sane defaults
settings = get_settings()
cors_value = settings.cors_allow_origins or "*"
allow_origins = [o.strip() for o in str(cors_value).split(",") if o and o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    """
    Application startup hook to initialize the database engine and create tables.

    This function:
    - Initializes the SQLAlchemy engine and session factory.
    - Creates all tables if they do not exist (safe for local dev with SQLite).

    Errors are logged to aid diagnostics without exposing sensitive details.
    """
    try:
        engine = init_engine()
        # Create tables if not present; for dev convenience. In production, use migrations.
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized and tables ensured.")
    except Exception as exc:
        # Log a succinct message; avoid dumping secrets or connection strings
        logger.error("Failed to initialize database engine or create tables: %s", exc)
        # Re-raise to let the orchestrator surface a failing container health
        raise


@app.get("/", tags=["Health"], summary="Health Check", response_model=None)
# PUBLIC_INTERFACE
def health_check():
    """
    Health check endpoint.

    Returns:
        A simple JSON payload confirming service health.
    """
    return {"message": "Healthy"}


# Include routers
app.include_router(auth_router)
app.include_router(tasks_router)


if __name__ == "__main__":
    # Run the app for local development using port 3001 as requested.
    # In production, prefer starting via a process manager invoking:
    #   uvicorn src.api.main:app --host 0.0.0.0 --port 3001
    uvicorn.run(app, host="0.0.0.0", port=3001)
