"""
Module: services.auth_service
Purpose: Business logic for authentication including registration, login, and JWT handling.
Security: Uses HS256 JWT with secret from environment settings. Never logs secrets or raw passwords.

Change:
- Remove enforcement of bcrypt's 72-byte limit. We now allow arbitrary-length passwords safely by
  pre-hashing with SHA-256 before bcrypt (see core.security). Maintain a minimum length of 8 characters.
- Update error messages and behavior to reject only passwords shorter than 8 characters or empty.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import jwt
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.db.repositories import UserRepository
from src.schemas.auth import TokenPayload
from src.db.models import User

# Single source of truth for password policy error text to ensure consistency across layers
POLICY_MESSAGE = "Password must be at least 8 characters."


class AuthServiceError(Exception):
    """Base class for authentication service errors."""


class InvalidCredentialsError(AuthServiceError):
    """Raised when user credentials are invalid."""


class TokenValidationError(AuthServiceError):
    """Raised when token validation fails."""


# PUBLIC_INTERFACE
def normalized_password(password: str) -> str:
    """
    Normalize password inputs safely.

    Notes:
        - Strips surrounding whitespace only (does not alter internal content).
        - Returns a string suitable for hashing/verification.
        - Does not perform Unicode normalization that could change byte-length.

    Args:
        password: Raw password input.

    Returns:
        The password with surrounding whitespace removed.

    Raises:
        ValueError: If input is not a string or normalization yields an empty string.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    normalized = password.strip()
    if normalized == "":
        # Ensure normalization doesn't produce empty values
        raise ValueError("Password cannot be empty.")
    return normalized


def _password_meets_minimum(password: str) -> bool:
    """
    Check if a password meets the minimum length requirement.

    Args:
        password: Candidate password string.

    Returns:
        True if length is >= 8 characters; else False.
    """
    if not isinstance(password, str):
        return False
    return len(password) >= 8


class AuthService:
    """
    AuthService encapsulates user registration, authentication, and JWT operations.
    """

    def __init__(self, user_repository: object | None = None):
        # Avoid exposing repository types in annotations to prevent FastAPI dependency analysis from
        # attempting to resolve non-Pydantic classes. Composition is done internally.
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
            ValueError: On invalid input (including >72-byte passwords).
        """
        # Normalize inputs
        email = (email or "").strip()
        normalized_pwd = normalized_password(password)

        # Enforce only minimum length; no 72-byte cap due to SHA-256 pre-hashing.
        if not _password_meets_minimum(normalized_pwd):
            raise ValueError(POLICY_MESSAGE)

        # Delegate hashing to repository; ensure repository does not mutate/truncate password.
        try:
            return self._user_repo.create_user(db, email=email, password=normalized_pwd)
        except ValueError as exc:
            # Preserve explicit validation messages (e.g., from repository or hashing)
            msg = str(exc) if str(exc) else "Invalid input."
            raise ValueError(msg) from exc
        # Do not catch-all here; let unexpected exceptions propagate to avoid masking valid inputs

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
            ValueError: If password violates byte-length policy or cannot be processed.
        """
        # Normalize inputs (mirror register path)
        email = (email or "").strip()
        normalized_pwd = normalized_password(password)

        # Enforce only minimum length for login as well.
        if not _password_meets_minimum(normalized_pwd):
            raise ValueError(POLICY_MESSAGE)

        try:
            user = self._user_repo.authenticate(db, email=email, password=normalized_pwd)
        except ValueError as exc:
            # Preserve validation messages (though repository authenticate shouldn't raise in normal flow)
            raise ValueError(str(exc) or "Invalid input.") from exc
        # Do not catch-all here; let unexpected exceptions propagate to avoid masking valid inputs

        if not user:
            # Standard invalid credentials without leaking whether email exists
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
