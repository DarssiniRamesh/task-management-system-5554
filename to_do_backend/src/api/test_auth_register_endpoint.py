"""
Module: api.test_auth_register_endpoint
Purpose: Integration-style tests for /auth/register to validate that:
 - Normal 8–72 byte passwords return 201 Created.
 - <8 or >72 byte passwords return 400 with a clear message.
 - Duplicate email returns 409.
The tests run against the FastAPI app with an in-memory SQLite database.

Note:
We override DATABASE_URL for the app by setting environment variables and clearing the settings cache
before creating the TestClient to ensure the app uses the in-memory DB.
"""

import os
from contextlib import contextmanager

from fastapi.testclient import TestClient

from src.core.config import _get_cached_settings
from src.api.main import app
from src.db.session import Base, init_engine


@contextmanager
def using_inmemory_db():
    """
    Context manager to configure the app to use an in-memory SQLite DB during tests.
    Ensures the settings cache is cleared and the database tables are created.
    """
    # Set env for in-memory SQLite
    prev_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite://"
    try:
        # Clear cached settings so new env is picked up
        _get_cached_settings.cache_clear()
        # Initialize engine and create tables
        engine = init_engine()
        Base.metadata.create_all(bind=engine)
        yield
    finally:
        # Restore previous env and clear cache again
        if prev_db_url is not None:
            os.environ["DATABASE_URL"] = prev_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        _get_cached_settings.cache_clear()


def _client():
    # Helper to construct a fresh client
    return TestClient(app)


def _password_of_bytes(n: int) -> str:
    # ASCII to ensure 1 char == 1 byte
    return "a" * n


def test_register_with_valid_password_returns_201():
    with using_inmemory_db():
        client = _client()
        payload = {"email": "valid@example.com", "password": "Password123!"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["email"] == payload["email"]
        assert "id" in data


def test_register_with_7_bytes_returns_400():
    with using_inmemory_db():
        client = _client()
        payload = {"email": "short@example.com", "password": _password_of_bytes(7)}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 400
        assert "8" in resp.json().get("detail", "")


def test_register_with_73_bytes_returns_400():
    with using_inmemory_db():
        client = _client()
        payload = {"email": "long@example.com", "password": _password_of_bytes(73)}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 400
        assert "72" in resp.json().get("detail", "")


def test_register_duplicate_email_returns_409():
    with using_inmemory_db():
        client = _client()
        payload = {"email": "dup@example.com", "password": "Password123!"}
        first = client.post("/auth/register", json=payload)
        assert first.status_code == 201
        second = client.post("/auth/register", json=payload)
        assert second.status_code == 409
        assert "exists" in second.json().get("detail", "").lower()
