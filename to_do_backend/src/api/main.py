from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import json
import uvicorn

from src.api.routers.auth import router as auth_router
from src.api.routers.tasks import router as tasks_router
from src.core.config import get_settings
from src.db.session import Base, init_engine
from pydantic import ValidationError
from fastapi.exceptions import RequestValidationError

# Configure module-level logger with JSON formatting.
# Avoid logging PII; include only operation context.
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Optional extras
        for key in ("op", "user_id", "path", "method"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False)

logger = logging.getLogger("to_do_backend")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

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

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    # Lightweight access log without PII
    logger.info(
        "incoming_request",
        extra={"op": "http_request", "path": request.url.path, "method": request.method},
    )
    response = await call_next(request)
    logger.info(
        "request_completed",
        extra={"op": "http_response", "path": request.url.path, "method": request.method},
    )
    return response

# Centralized exception handlers returning safe messages
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(
        "request_validation_error",
        extra={"op": "validation_error", "path": request.url.path, "method": request.method},
    )
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request parameters or payload."},
    )

@app.exception_handler(ValidationError)
async def pydantic_validation_handler(request: Request, exc: ValidationError):
    logger.warning(
        "pydantic_validation_error",
        extra={"op": "validation_error", "path": request.url.path, "method": request.method},
    )
    return JSONResponse(
        status_code=400,
        content={"detail": "Validation failed."},
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Don't leak internals
    logger.error(
        "unhandled_exception",
        extra={"op": "unhandled", "path": request.url.path, "method": request.method},
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error."},
    )


@app.on_event("startup")
def on_startup():
    """
    Application startup hook to initialize the database engine and (optionally) create tables.

    This function:
    - Initializes the SQLAlchemy engine and session factory.
    - For development or SQLite usage, creates all tables if they do not exist (convenience for local dev).
      For production with networked databases, use Alembic migrations instead.

    Errors are logged to aid diagnostics without exposing sensitive details.
    """
    try:
        engine = init_engine()
        # Dev-only auto-creation of tables:
        from src.core.config import get_settings
        settings_local = get_settings()
        db_url = (settings_local.database_url or "").lower()
        is_dev = (settings_local.environment or "").lower() == "development"
        is_sqlite = db_url.startswith("sqlite")
        if is_dev or is_sqlite:
            Base.metadata.create_all(bind=engine)
            logger.info("db_initialized", extra={"op": "startup"})
        else:
            logger.info("db_engine_ready_no_create", extra={"op": "startup"})
    except Exception:
        # Log a succinct message; avoid dumping secrets or connection strings
        logger.error("db_init_failed", extra={"op": "startup"})
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
