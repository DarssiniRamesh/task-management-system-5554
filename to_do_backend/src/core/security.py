"""
Module: security
Purpose: Security utilities including password hashing and verification with bcrypt via passlib.

Notes:
- This module intentionally avoids logging sensitive data.
"""

from passlib.context import CryptContext

# Configure passlib CryptContext for bcrypt hashing.
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
        ValueError: If the provided password is empty.
    """
    if not isinstance(plain_password, str) or not plain_password:
        raise ValueError("Password must be a non-empty string.")
    return _pwd_context.hash(plain_password)


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
    if not plain_password or not hashed_password:
        return False
    return _pwd_context.verify(plain_password, hashed_password)
