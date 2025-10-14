"""
Module: tests.conftest
Purpose: Shared pytest fixtures for in-memory SQLite (StaticPool) DB, FastAPI TestClient,
         user creation with token acquisition, and seeded tasks for Task-related tests.

Notes:
- Uses environment override for DATABASE_URL with sqlite:// (in-memory) and StaticPool.
- Ensures FastAPI startup runs so tables are created (app.on_event("startup") does create_all()).
- Provides AAA-friendly small factories for users and tasks.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Callable, Dict, Generator, Iterable, List, Tuple

import pytest
from fastapi.testclient import TestClient


from src.api.main import app
from src.core.config import _get_cached_settings
from src.db.session import Base, init_engine
from src.db.repositories import UserRepository, TaskRepository


@contextmanager
def _using_inmemory_db() -> Generator[None, None, None]:
    """
    Context to force the app to use in-memory SQLite with StaticPool.

    - Overrides DATABASE_URL to sqlite:// (triggers StaticPool in session.py).
    - Clears settings cache so new URL is picked up.
    - Initializes the engine and creates tables.
    """
    prev_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite://"
    try:
        _get_cached_settings.cache_clear()
        engine = init_engine()
        Base.metadata.drop_all(bind=engine)  # ensure clean schema per session
        Base.metadata.create_all(bind=engine)
        yield
    finally:
        if prev_db_url is not None:
            os.environ["DATABASE_URL"] = prev_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        _get_cached_settings.cache_clear()


@pytest.fixture(scope="session")
def inmemory_db_session_scope() -> Iterable[None]:
    """
    Session-scoped fixture to set up the in-memory DB for all tests in this session.
    """
    with _using_inmemory_db():
        yield


@pytest.fixture
def client(inmemory_db_session_scope) -> Generator[TestClient, None, None]:
    """
    Yields a TestClient ensuring startup/shutdown events execute, which creates tables.
    """
    with TestClient(app) as c:
        yield c


@pytest.fixture
def register_user_and_get_token(client: TestClient) -> Callable[[str, str], Tuple[int, str]]:
    """
    Factory fixture that:
    - Registers a user with given email/password
    - Logs in to obtain a JWT token
    Returns: (user_id, access_token)
    """
    def _register_and_login(email: str, password: str) -> Tuple[int, str]:
        reg_resp = client.post("/auth/register", json={"email": email, "password": password})
        assert reg_resp.status_code in (201, 409), reg_resp.text
        # If duplicate (409), still try login to get token for existing user
        login_resp = client.post("/auth/login", json={"email": email, "password": password})
        assert login_resp.status_code == 200, login_resp.text
        token = login_resp.json()["access_token"]
        me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_resp.status_code == 200, me_resp.text
        user_id = me_resp.json()["id"]
        return user_id, token
    return _register_and_login


@pytest.fixture
def auth_header(register_user_and_get_token: Callable[[str, str], Tuple[int, str]]) -> Callable[[str, str], Dict[str, str]]:
    """
    Factory fixture: returns headers with Authorization Bearer token for a given user.
    """
    def _hdr(email: str, password: str) -> Dict[str, str]:
        _, token = register_user_and_get_token(email, password)
        return {"Authorization": f"Bearer {token}"}
    return _hdr


@pytest.fixture
def seed_tasks(client: TestClient, register_user_and_get_token: Callable[[str, str], Tuple[int, str]]) -> Callable[[str, str, int], Tuple[int, List[dict]]]:
    """
    Factory fixture to create N tasks for a user via API, returning (user_id, tasks_json_list).
    """
    def _seed(email: str, password: str, n: int = 3) -> Tuple[int, List[dict]]:
        user_id, token = register_user_and_get_token(email, password)
        headers = {"Authorization": f"Bearer {token}"}
        created = []
        for i in range(n):
            payload = {"title": f"Task {i+1}", "description": f"Desc {i+1}"}
            resp = client.post("/tasks", json=payload, headers=headers)
            assert resp.status_code == 201, resp.text
            created.append(resp.json())
        return user_id, created
    return _seed


# Direct repository-level fixture helpers (if needed by unit tests)
@pytest.fixture
def user_repo() -> UserRepository:
    return UserRepository()


@pytest.fixture
def task_repo() -> TaskRepository:
    return TaskRepository()
