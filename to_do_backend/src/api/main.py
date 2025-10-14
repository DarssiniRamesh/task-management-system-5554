from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routers.auth import router as auth_router
from src.api.routers.tasks import router as tasks_router
from src.core.config import get_settings
from src.db.session import Base, init_engine

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

# CORS configuration using environment settings
settings = get_settings()
allow_origins = [o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()]
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
    """
    engine = init_engine()
    # Create tables if not present; for dev convenience. In production, use migrations.
    Base.metadata.create_all(bind=engine)


@app.get("/", tags=["Health"], summary="Health Check")
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
