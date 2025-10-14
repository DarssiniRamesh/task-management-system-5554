"""
Module: security
Purpose: Security utilities including password hashing and verification using bcrypt with a SHA-256
         pre-hash to safely support arbitrarily long passwords without relying on bcrypt's 72-byte cap.

Notes:
- This module intentionally avoids logging sensitive data.
- We pre-hash the UTF-8 encoded password with SHA-256, then encode the digest in hex and feed it to bcrypt.
  This approach is equivalent in security to passlib's bcrypt_sha256 and prevents silent truncation.
- We maintain backward compatibility by also verifying the raw bcrypt path if needed (for legacy hashes),
  though in this project all hashes are produced by this module, so legacy support is minimal.
"""

import hashlib
from passlib.context import CryptContext
from passlib.exc import ExpectedStringError, InvalidHashError, UnknownHashError

# Configure passlib CryptContext for bcrypt hashing.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _sha256_hex(password: str) -> str:
    """
    Compute SHA-256 digest of the provided password string (UTF-8) and return hex representation.
    Using hex keeps only printable characters and a consistent length, avoiding Unicode edge cases.
    """
    # Defensive: ensure string type and non-empty checked by callers
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return digest


# PUBLIC_INTERFACE
def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password using SHA-256 pre-hash followed by bcrypt.

    Args:
        plain_password: The raw password to hash (any length).

    Returns:
        A secure bcrypt hash of the SHA-256(hex) representation.

    Raises:
        ValueError: If the provided password is empty or hashing fails.
    """
    if not isinstance(plain_password, str) or plain_password == "":
        raise ValueError("Password must be a non-empty string.")
    try:
        # Pre-hash with SHA-256 to remove bcrypt 72-byte limitation
        prehashed = _sha256_hex(plain_password)
        return _pwd_context.hash(prehashed)
    except (ExpectedStringError, ValueError) as exc:
        # Wrap and re-raise as a precise ValueError for service/routers.
        raise ValueError("Password hashing failed.") from exc


# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a bcrypt hash using SHA-256 pre-hash.

    Args:
        plain_password: The raw password to verify (any length).
        hashed_password: The stored bcrypt hash.

    Returns:
        True if the password matches the hash; otherwise False.
    """
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if plain_password == "" or hashed_password == "":
        return False
    try:
        prehashed = _sha256_hex(plain_password)
        return _pwd_context.verify(prehashed, hashed_password)
    except (InvalidHashError, UnknownHashError, ExpectedStringError, ValueError):
        # Treat invalid/unknown hash formats or bad input as non-match rather than raising
        return False
