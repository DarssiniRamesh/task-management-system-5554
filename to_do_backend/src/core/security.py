"""
Module: security
Purpose: Security utilities for password hashing and verification.

Implementation details:
- Prefer passlib's bcrypt_sha256 scheme which safely supports arbitrarily long passwords by
  applying SHA-256 before bcrypt internally. This avoids bcrypt's 72-byte limitation and
  removes the need for manual pre-hashing here.
- Narrow exception handling so we don't convert passlib's non-fatal warnings into failures.
- Ensure consistent return values and do not log sensitive data.
"""

from passlib.context import CryptContext

# Import passlib exceptions defensively; shapes may vary by environment.
try:  # pragma: no cover
    from passlib.exc import InvalidHashError, UnknownHashError  # type: ignore
except Exception:  # pragma: no cover
    InvalidHashError = Exception  # type: ignore
    UnknownHashError = Exception  # type: ignore

# Configure passlib CryptContext.
# Primary: bcrypt_sha256 (handles long passwords safely).
# Fallback: bcrypt for any legacy hashes that might already exist.
_pwd_context = CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")


# PUBLIC_INTERFACE
def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password.

    Args:
        plain_password: The raw password to hash (any length, min enforced upstream).

    Returns:
        A secure hash string using bcrypt_sha256 by default.

    Raises:
        ValueError: If the provided password is empty or hashing fails.
    """
    if not isinstance(plain_password, str) or plain_password == "":
        raise ValueError("Password must be a non-empty string.")
    try:
        hashed = _pwd_context.hash(plain_password)
        if not isinstance(hashed, str) or not hashed:
            raise ValueError("Password hashing failed.")
        return hashed
    except (AttributeError,):
        # Some environments produce AttributeError during bcrypt metadata checks.
        # Retry once; if still failing, raise a stable error without leaking details.
        try:
            hashed = _pwd_context.hash(plain_password)
            if not isinstance(hashed, str) or not hashed:
                raise ValueError("Password hashing failed.")
            return hashed
        except Exception as inner_exc:
            raise ValueError("Password hashing failed.") from inner_exc
    except Exception as exc:
        raise ValueError("Password hashing failed.") from exc


# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a stored hash.

    Args:
        plain_password: The raw password to verify.
        hashed_password: The stored hash (bcrypt_sha256 or bcrypt).

    Returns:
        True if the password matches the hash; otherwise False.
    """
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if plain_password == "" or hashed_password == "":
        return False
    try:
        return _pwd_context.verify(plain_password, hashed_password)
    except (InvalidHashError, UnknownHashError, ValueError, Exception):
        # Treat invalid/unknown hash formats or bad input as non-match rather than raising.
        return False
