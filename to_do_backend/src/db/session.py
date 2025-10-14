"""
Module: db.session
Purpose: Initialize SQLAlchemy engine, session factory, and declarative base.
         Provides a session dependency for FastAPI routes/services.

Design:
- Uses Pydantic settings to load database URL.
- Configures SQLite-specific connect args when applicable.
- Exposes get_db as a generator suitable for FastAPI dependency injection.
"""

from collections.abc import Generator
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

from src.core.config import get_settings

# SQLAlchemy Declarative Base for ORM models
Base = declarative_base()

# Session local factory; configured in init_engine()
SessionLocal: Optional[scoped_session] = None


def _create_engine_from_settings():
    """
    Create SQLAlchemy engine based on settings with SQLite handling.

    Special-case in-memory SQLite databases to use a StaticPool so the same
    connection is reused across the application. Without this, each new
    connection would get a fresh, empty in-memory database and tests would
    observe "no such table" errors after metadata creation.
    """
    settings = get_settings()
    database_url = settings.database_url

    # Base engine kwargs
    engine_kwargs = {"pool_pre_ping": True}

    # SQLite needs special connect args
    if database_url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
        # Detect in-memory SQLite URLs and pin to StaticPool for shared state
        if database_url in ("sqlite://", "sqlite:///:memory:") or database_url.endswith(":memory:"):
            engine_kwargs["poolclass"] = StaticPool

    engine = create_engine(database_url, **engine_kwargs)
    return engine


def init_engine():
    """
    Initialize engine and session factory.
    Should be called at startup before DB access.
    """
    global SessionLocal
    engine = _create_engine_from_settings()

    # sessionmaker configured with autocommit False and autoflush False for explicit control
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    # scoped_session ensures thread-local sessions in ASGI workers
    SessionLocal = scoped_session(session_factory)
    return engine


# PUBLIC_INTERFACE
def get_db() -> Generator:
    """
    Dependency generator that yields a SQLAlchemy Session.
    Ensures proper commit/rollback/close lifecycle.

    Yields:
        Session: SQLAlchemy ORM session.
    """
    if SessionLocal is None:
        # As a safe guard, initialize if not yet set.
        init_engine()
    assert SessionLocal is not None  # for type checkers
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        # On exception, rollback transaction before re-raising.
        db.rollback()
        raise
    finally:
        db.close()
