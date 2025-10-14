"""
Module: services.test_auth_password_policy_boundaries
Purpose: Boundary-focused tests for the password policy (8–72 UTF-8 bytes) covering 7/8/72/73 bytes,
         and ensuring typical inputs behave as expected on register and login.

These tests run against an in-memory SQLite database using the real repositories and AuthService.
"""

from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pytest

from src.db.session import Base
from src.services.auth_service import AuthService
from src.db.repositories import UserRepository


@pytest.fixture(scope="module")
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def _make_password_of_bytes(n: int) -> str:
    # Use pure ASCII 'a' to ensure bytes == chars for determinate length
    return "a" * n


def test_7_bytes_password_fails(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "seven@example.com"
    pwd = _make_password_of_bytes(7)
    with pytest.raises(ValueError) as excinfo:
        service.register_user(db, email=email, password=pwd)
    assert "8 and 72" in str(excinfo.value)


def test_8_bytes_password_passes(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "eight@example.com"
    pwd = _make_password_of_bytes(8)
    user = service.register_user(db, email=email, password=pwd)
    assert user.email == email
    user2, token = service.authenticate_user(db, email=email, password=pwd)
    assert user2.id == user.id
    assert isinstance(token, str) and len(token) > 10


def test_72_bytes_password_passes(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "seventytwo@example.com"
    pwd = _make_password_of_bytes(72)
    user = service.register_user(db, email=email, password=pwd)
    assert user.email == email
    user2, token = service.authenticate_user(db, email=email, password=pwd)
    assert user2.id == user.id
    assert isinstance(token, str) and len(token) > 10


def test_73_bytes_password_fails(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "seventythree@example.com"
    pwd = _make_password_of_bytes(73)
    with pytest.raises(ValueError) as excinfo:
        service.register_user(db, email=email, password=pwd)
    assert "8 and 72" in str(excinfo.value)


def test_string_6_chars_fails(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "sixchars@example.com"
    pwd = "string"  # 6 bytes
    with pytest.raises(ValueError) as excinfo:
        service.register_user(db, email=email, password=pwd)
    assert "8 and 72" in str(excinfo.value)


def test_password_12_chars_passes(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "pass12@example.com"
    pwd = "Password123!"  # 12 bytes ASCII
    user = service.register_user(db, email=email, password=pwd)
    assert user.email == email
    user2, token = service.authenticate_user(db, email=email, password=pwd)
    assert user2.id == user.id
    assert token and isinstance(token, str)
