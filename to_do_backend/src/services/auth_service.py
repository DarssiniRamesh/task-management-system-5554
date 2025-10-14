"""
Module: services.auth_service
Purpose: Business logic for authentication including registration, login, and JWT handling.
Security: Uses HS256 JWT with secret from environment settings. Never logs secrets or raw passwords.
Enhancement: Enforce bcrypt UTF-8 byte-length constraints (8–72 bytes) defensively in service layer
             to prevent hashing/verification with invalid lengths.
Fix: Normalize inputs (strip surrounding whitespace), validate strictly by UTF-8 byte length (8–72),
     avoid truncation, and convert passlib/bcrypt exceptions into safe 400s only when truly exceeded.
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


def _normalized_password(password: str) -> str:
    """
    Normalize password inputs safely.

    - Strip surrounding whitespace only (do not transform internal content).
    - Ensure a string is returned for downstream processing.

    We explicitly do not perform any Unicode normalization that could expand bytes or change semantics.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    # Surrounding whitespace is often accidental (copy/paste); strip without altering internal content.
    normalized = password.strip()
    if normalized == "":
        # Ensure normalization doesn't produce empty values
        raise ValueError("Password cannot be empty.")
    return normalized


def _password_within_bcrypt_bounds(password: str) -> bool:
    """
    Return True if password is between 8 and 72 bytes (UTF-8), else False.
    """
    if not isinstance(password, str) or password == "":
        return False
    try:
        byte_len = len(password.encode("utf-8"))
        return 8 <= byte_len <= 72
    except Exception:
        # If encoding somehow fails, treat as invalid input.
        return False


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
        normalized_password = _normalized_password(password)

        # Defensive check: enforce bcrypt byte-length policy (8–72 bytes).
        if not _password_within_bcrypt_bounds(normalized_password):
            # Raise a ValueError so routers can consistently translate to HTTP 400
            raise ValueError("Password must be between 8 and 72 UTF-8 bytes.")

        # Delegate hashing to repository; ensure repository does not mutate/truncate password.
        try:
            return self._user_repo.create_user(db, email=email, password=normalized_password)
        except ValueError:
            # Bubble up validation errors consistently
            raise
        except Exception as exc:
            # Only map unexpected passlib/bcrypt issues; don't mask generic logic errors.
            raise ValueError("Unable to process password.") from exc

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
        normalized_password = _normalized_password(password)

        # Defensive check before verifying against bcrypt hash to avoid implicit truncation.
        if not _password_within_bcrypt_bounds(normalized_password):
            # Service-layer 400 via router; keep message generic and consistent.
            raise ValueError("Password must be between 8 and 72 UTF-8 bytes.")

        try:
            user = self._user_repo.authenticate(db, email=email, password=normalized_password)
        except Exception as exc:
            # Convert unexpected passlib/bcrypt errors to a safe 400
            raise ValueError("Unable to process password.") from exc

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
