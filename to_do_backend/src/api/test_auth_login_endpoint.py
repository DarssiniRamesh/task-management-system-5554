"""
Module: api.test_auth_login_endpoint
Purpose: Integration-style tests for /auth/register and /auth/login to validate:
 - Normal registration returns 201 Created with required fields.
 - Duplicate email returns 409 Conflict.
 - Login returns 200 with access_token and token_type 'bearer'.
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
    Configure the app to use an in-memory SQLite DB during tests.
    Ensures the settings cache is cleared and the database tables are created.
    """
    prev_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite://"
    try:
        _get_cached_settings.cache_clear()
        engine = init_engine()
        Base.metadata.create_all(bind=engine)
        yield
    finally:
        if prev_db_url is not None:
            os.environ["DATABASE_URL"] = prev_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        _get_cached_settings.cache_clear()


def _client():
    # Construct a fresh client as a context manager so FastAPI startup/shutdown run.
    return TestClient(app)


def test_register_and_login_success_flow():
    email = "darssini@kavia.ai"
    password = "Password123!"
    with using_inmemory_db():
        with _client() as client:
            # Register
            reg_payload = {"email": email, "password": password}
            reg_resp = client.post("/auth/register", json=reg_payload)
            assert reg_resp.status_code == 201, reg_resp.text
            user = reg_resp.json()
            assert user["email"] == email
            assert "id" in user
            assert "created_at" in user and "updated_at" in user

            # Login
            login_resp = client.post("/auth/login", json=reg_payload)
            assert login_resp.status_code == 200, login_resp.text
            token_data = login_resp.json()
            assert "access_token" in token_data and isinstance(token_data["access_token"], str)
            assert token_data.get("token_type") == "bearer"

            # Optional: verify token works against /auth/me
            headers = {"Authorization": f"Bearer {token_data['access_token']}"}
            me_resp = client.get("/auth/me", headers=headers)
            assert me_resp.status_code == 200, me_resp.text
            me = me_resp.json()
            assert me["email"] == email
            assert me["id"] == user["id"]


def test_register_duplicate_email_returns_409():
    email = "darssini@kavia.ai"
    password = "Password123!"
    with using_inmemory_db():
        with _client() as client:
            payload = {"email": email, "password": password}
            first = client.post("/auth/register", json=payload)
            assert first.status_code == 201, first.text
            second = client.post("/auth/register", json=payload)
            assert second.status_code == 409, second.text
            assert "exists" in second.json().get("detail", "").lower()
