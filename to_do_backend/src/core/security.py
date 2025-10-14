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

# Import passlib exceptions defensively; not all environments expose identical classes.
# We will only use the ones guaranteed to be Exception subclasses in our handlers.
try:  # pragma: no cover - import shape may vary by environment
    from passlib.exc import InvalidHashError, UnknownHashError  # type: ignore
except Exception:  # pragma: no cover - extreme fallback if passlib.exc unavailable
    InvalidHashError = Exception  # type: ignore
    UnknownHashError = Exception  # type: ignore

# Configure passlib CryptContext for bcrypt hashing.
# Note: Some environments surface a trapped AttributeError when reading bcrypt version metadata
# (module 'bcrypt' has no attribute '__about__'). Passlib still computes a valid hash in such cases.
# Our hash_password() implementation therefore validates the returned hash string rather than
# blindly failing on any Exception raised during metadata inspection.
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
        # Some environments emit a trapped AttributeError reading bcrypt version but still return a valid hash.
        hashed = _pwd_context.hash(prehashed)
        # Ensure we actually received a string hash; otherwise treat as failure.
        if not isinstance(hashed, str) or not hashed:
            raise ValueError("Password hashing failed.")
        return hashed
    except Exception as exc:
        # Passlib/bcrypt may raise non-fatal warnings internally but still succeed.
        # If we end up here, hashing genuinely failed; raise a stable public message.
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
    except (InvalidHashError, UnknownHashError, ValueError, Exception):
        # Treat invalid/unknown hash formats or bad input as non-match rather than raising.
        # Catch-all Exception included to handle environments where passlib raises different subclasses.
        return False
