"""
Module: db.session
Purpose: Initialize SQLAlchemy engine, session factory, and declarative base.
         Provides a session dependency for FastAPI routes/services.

Design:
- Uses Pydantic settings to load database URL.
- Configures connection pooling and SQLite-specific pragmas/args when applicable.
- Exposes get_db as a generator suitable for FastAPI dependency injection.
- Provides helper to determine if current env is development for dev-only behaviors.
"""

from collections.abc import Generator
from typing import Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool, StaticPool
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

from src.core.config import get_settings

# SQLAlchemy Declarative Base for ORM models
Base = declarative_base()

# Session local factory; configured in init_engine()
SessionLocal: Optional[scoped_session] = None


def _is_sqlite(url: str) -> bool:
    """Return True if the SQLAlchemy URL points to SQLite."""
    return url.startswith("sqlite")


def _is_in_memory_sqlite(url: str) -> bool:
    """Detect in-memory SQLite variants."""
    return url in ("sqlite://", "sqlite:///:memory:") or url.endswith(":memory:")


def _is_development_env() -> bool:
    """Return True when ENVIRONMENT setting is development."""
    try:
        return (get_settings().environment or "").lower() == "development"
    except Exception:
        # Be safe: if settings not available, assume not production
        return False


def _create_engine_from_settings() -> Engine:
    """
    Create SQLAlchemy engine based on settings with pooling and SQLite handling.

    - Uses QueuePool defaults for networked DBs with sane pool sizes.
    - For in-memory SQLite, uses StaticPool so all sessions share the same DB.
    - Applies SQLite pragmas (foreign_keys = ON, journal_mode=WAL, synchronous=NORMAL) for dev ergonomics.
    """
    settings = get_settings()
    database_url = settings.database_url

    # Base engine kwargs with pre-ping for dead connection detection
    engine_kwargs: dict = {
        "pool_pre_ping": True,
    }

    # Configure pooling: QueuePool is default for most drivers; set modest dev-friendly sizes.
    # Note: StaticPool overrides poolclass for in-memory SQLite below.
    engine_kwargs.update(
        {
            "poolclass": QueuePool,
            "pool_size": 5,
            "max_overflow": 10,
        }
    )

    if _is_sqlite(database_url):
        # SQLite-specific connect args
        engine_kwargs["connect_args"] = {"check_same_thread": False}

        if _is_in_memory_sqlite(database_url):
            # Share same in-memory DB across threads
            engine_kwargs["poolclass"] = StaticPool

    engine = create_engine(database_url, **engine_kwargs)

    # Attach SQLite pragmas for reliability and FK enforcement (no-op for other DBs)
    if _is_sqlite(database_url):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: D401
            """
            On new SQLite connection, enable useful pragmas:
            - foreign_keys=ON for FK enforcement
            - journal_mode=WAL and synchronous=NORMAL for better concurrency in dev
            """
            try:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                # WAL/synchronous pragmas are safe no-ops on some SQLite builds, ignore failures
                try:
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA synchronous=NORMAL")
                except Exception:
                    pass
                cursor.close()
            except Exception:
                # Avoid raising from event hook; pragmas are best-effort
                pass

    return engine


def init_engine() -> Engine:
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
