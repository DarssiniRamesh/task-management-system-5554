"""
Module: security
Purpose: Security utilities including password hashing and verification with bcrypt via passlib.

Notes:
- This module intentionally avoids logging sensitive data.
- Only expected passlib/bcrypt exceptions are surfaced in a controlled way.
- CryptContext is configured with the 'bcrypt' scheme specifically (not bcrypt_sha256).
"""

from passlib.context import CryptContext
from passlib.exc import ExpectedStringError, InvalidHashError, UnknownHashError

# Configure passlib CryptContext for bcrypt hashing.
# Using bcrypt ensures 72-byte limit behavior is explicit and consistent.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# PUBLIC_INTERFACE
def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password using bcrypt.

    Args:
        plain_password: The raw password to hash.

    Returns:
        A secure bcrypt hash of the password.

    Raises:
        ValueError: If the provided password is empty or hashing fails.
    """
    if not isinstance(plain_password, str) or plain_password == "":
        raise ValueError("Password must be a non-empty string.")
    try:
        return _pwd_context.hash(plain_password)
    except (ExpectedStringError, ValueError) as exc:
        # Wrap and re-raise as generic ValueError for service/routers.
        raise ValueError("Password hashing failed.") from exc


# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a bcrypt hash.

    Args:
        plain_password: The raw password to verify.
        hashed_password: The stored bcrypt hash.

    Returns:
        True if the password matches the hash; otherwise False.
    """
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if plain_password == "" or hashed_password == "":
        return False
    try:
        return _pwd_context.verify(plain_password, hashed_password)
    except (InvalidHashError, UnknownHashError, ExpectedStringError, ValueError):
        # Treat invalid/unknown hash formats or bad input as non-match rather than raising
        return False
