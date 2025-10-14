"""
Module: services.test_auth_password_policy
Purpose: Inline, unit-style quick checks for the authentication password policy to guard against
         regressions. We ensure minimum length is enforced while allowing arbitrarily long passwords.

Note:
- These are simple tests runnable via pytest.
- They validate that:
  * A normal password (>=8 chars) is accepted by the service.
  * A very long password is accepted (no 72-byte cap).
  * <8 characters is rejected with ValueError.
  * Surrounding whitespace is stripped before validation.
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


def test_normal_password_is_accepted(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "user@example.com"
    # Common strong password with >=8 characters
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


def test_short_password_rejected(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "shorty@example.com"
    short_password = "short"  # 5 characters
    with pytest.raises(ValueError) as exc:
        service.register_user(db, email=email, password=short_password)
    # Policy message mentions the minimum length of 8
    assert "8" in str(exc.value)


def test_very_long_password_is_accepted(db: Session):
    service = AuthService(user_repository=UserRepository())
    email = "toolong@example.com"
    # Create a password that's very long (e.g., 5000 chars)
    long_password = "A" * 5000
    user = service.register_user(db, email=email, password=long_password)
    assert user.email == email
    # Login also works
    user2, token = service.authenticate_user(db, email=email, password=long_password)
    assert user2.id == user.id
    assert token
