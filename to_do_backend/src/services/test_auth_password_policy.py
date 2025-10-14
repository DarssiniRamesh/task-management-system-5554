"""
Module: services.test_auth_password_policy
Purpose: Inline, unit-style quick checks for the authentication password policy to guard against
         regressions that caused normal passwords to incorrectly trigger 72-byte bcrypt errors.

Note:
- These are simple tests runnable via pytest.
- They validate that:
  * A normal password (<=72 UTF-8 bytes) is accepted by service validation helpers.
  * An over-72-byte password is rejected with a ValueError.
  * Surrounding whitespace is stripped before validation.
"""
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pytest

from src.db.session import Base
from src.services.auth_service import AuthService
from src.db.repositories import UserRepository
from src.db.models import User


class _InMemoryUserRepo(UserRepository):
    """
    Minimal in-memory DB usage via SQLite for quick tests.
    """

    def __init__(self, db: Session):
        self._db = db

    def create_user(self, db: Session, *, email: str, password: str) -> User:
        # delegate to base implementation; using the provided db
        return super().create_user(db, email=email, password=password)


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


def test_normal_password_is_accepted(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "user@example.com"
    # Common strong password within bounds
    password = "Password123!"
    # Should not raise
    user = service.register_user(db, email=email, password=password)
    assert user.email == email
    # Can login with same password
    user2, token = service.authenticate_user(db, email=email, password=password)
    assert user2.id == user.id
    assert isinstance(token, str) and len(token) > 10


def test_surrounding_whitespace_stripped(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "spacey@example.com"
    password = "  pass with spaces  "  # surrounding spaces should be stripped
    user = service.register_user(db, email=email, password=password)
    assert user.email == email
    # Login should also strip
    user2, token = service.authenticate_user(db, email=email, password=password)
    assert user2.id == user.id
    assert token


def test_over_72_bytes_password_rejected(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "toolong@example.com"
    # Create a password that's >72 bytes in UTF-8. Use ASCII for determinism.
    long_password = "A" * 73
    with pytest.raises(ValueError) as exc:
        service.register_user(db, email=email, password=long_password)
    assert "8 and 72" in str(exc.value)
