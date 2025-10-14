"""
Module: services.auth_service
Purpose: Business logic for authentication including registration, login, and JWT handling.
Security: Uses HS256 JWT with secret from environment settings. Never logs secrets or raw passwords.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import jwt
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.db.repositories import UserRepository
from src.schemas.auth import TokenPayload
from src.db.models import User


class AuthServiceError(Exception):
    """Base class for authentication service errors."""


class InvalidCredentialsError(AuthServiceError):
    """Raised when user credentials are invalid."""


class TokenValidationError(AuthServiceError):
    """Raised when token validation fails."""


class AuthService:
    """
    AuthService encapsulates user registration, authentication, and JWT operations.
    """

    def __init__(self, user_repository: Optional[UserRepository] = None):
        self._user_repo = user_repository or UserRepository()
        self._settings = get_settings()

    # PUBLIC_INTERFACE
    def register_user(self, db: Session, *, email: str, password: str) -> User:
        """
        Register a new user with hashed password.

        Args:
            db: SQLAlchemy session.
            email: Email address for the new account.
            password: Plain text password.

        Returns:
            The created User entity.

        Raises:
            DuplicateEmailError: If the email is already registered.
            ValueError: On invalid input.
        """
        return self._user_repo.create_user(db, email=email, password=password)

    # PUBLIC_INTERFACE
    def authenticate_user(self, db: Session, *, email: str, password: str) -> Tuple[User, str]:
        """
        Authenticate user and return JWT access token.

        Args:
            db: SQLAlchemy session.
            email: Email address.
            password: Plain text password.

        Returns:
            Tuple of (User, jwt_token).

        Raises:
            InvalidCredentialsError: If authentication fails.
        """
        user = self._user_repo.authenticate(db, email=email, password=password)
        if not user:
            raise InvalidCredentialsError("Invalid email or password.")
        token = self._create_access_token(subject=str(user.id))
        return user, token

    def _create_access_token(self, *, subject: str) -> str:
        """
        Create a JWT access token for the given subject.

        Args:
            subject: Subject (user id as string).

        Returns:
            Encoded JWT token string.
        """
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=int(self._settings.access_token_expire_minutes))
        payload = {"sub": subject, "iat": int(now.timestamp()), "exp": int(expire.timestamp())}
        token = jwt.encode(payload, self._settings.secret_key, algorithm="HS256")
        return token

    # PUBLIC_INTERFACE
    def decode_token(self, token: str) -> TokenPayload:
        """
        Decode and validate a JWT token.

        Args:
            token: Encoded JWT token.

        Returns:
            TokenPayload with validated claims.

        Raises:
            TokenValidationError: If token is invalid or expired.
        """
        try:
            decoded = jwt.decode(token, self._settings.secret_key, algorithms=["HS256"])
            return TokenPayload(**decoded)
        except jwt.ExpiredSignatureError as exc:
            raise TokenValidationError("Token has expired.") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenValidationError("Invalid token.") from exc

    # PUBLIC_INTERFACE
    def get_user_by_id(self, db: Session, user_id: int) -> Optional[User]:
        """
        Retrieve a user by ID.

        Args:
            db: SQLAlchemy session.
            user_id: User identifier.

        Returns:
            User if found, else None.
        """
        # Utilizing repository method get_by_email isn't suitable; add a simple session get.
        return db.get(User, user_id)
