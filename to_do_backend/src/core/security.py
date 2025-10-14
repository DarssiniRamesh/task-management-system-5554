"""
Module: security
Purpose: Security utilities for password hashing and verification.

Implementation details:
- Use passlib's bcrypt_sha256 scheme which safely supports arbitrarily long passwords by
  applying SHA-256 before bcrypt internally. This avoids bcrypt's 72-byte limitation and
  removes the need for manual pre-hashing here.
- Narrow exception handling so only passlib-specific hashing errors are mapped to user-facing
  validation failures (HTTP 400). Unexpected errors are logged and propagated to avoid masking
  system faults.
- Add diagnostics to log the exact passlib exception without exposing sensitive data to assist
  in identifying misconfiguration or missing dependencies (e.g., bcrypt module).
"""

import logging
from passlib.context import CryptContext

# Set up module-level logger
logger = logging.getLogger("to_do_backend.core.security")
if not logger.handlers:  # ensure logs appear even if app-level config isn't set in tests
    logging.basicConfig(level=logging.INFO)

# Import passlib exceptions defensively; in some environments import paths may vary.
try:  # pragma: no cover
    from passlib.exc import PasslibError  # type: ignore
except Exception:  # pragma: no cover
    # Fallback to a generic base if passlib.exc isn't importable for any reason.
    class PasslibError(Exception):  # type: ignore
        """Fallback base class for passlib-related errors."""
        pass

# Best-effort import of bcrypt to log availability. Not strictly required at runtime for
# this module to import, but passlib's bcrypt-based schemes will fail without it.
try:
    import bcrypt as _bcrypt  # type: ignore  # noqa: F401

    _BCRYPT_AVAILABLE = True
except Exception as _bcrypt_exc:
    _BCRYPT_AVAILABLE = False
    # Warn early; hashing will fail later without a backend. Do not crash import/boot.
    logger.warning(
        "bcrypt package not available; ensure 'bcrypt' or 'passlib[bcrypt]' is installed. "
        "Module import error: %s",
        _bcrypt_exc.__class__.__name__,
    )

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
        ValueError: If the provided password is empty or hashing fails due to a passlib error.
        Other Exceptions: Propagated as-is to avoid masking unexpected system faults.
    """
    if not isinstance(plain_password, str) or plain_password == "":
        raise ValueError("Password must be a non-empty string.")

    try:
        hashed = _pwd_context.hash(plain_password)
        if not isinstance(hashed, str) or not hashed:
            # Very defensive; passlib should always return a non-empty string when successful.
            raise ValueError("Password hashing failed.")
        return hashed
    except PasslibError as exc:
        # Log exact exception for diagnostics without exposing sensitive data.
        # Typical cause: missing bcrypt backend or misconfigured environment.
        logger.exception(
            "Password hashing error (passlib). This typically indicates a missing or "
            "misconfigured bcrypt backend."
        )
        # Map to a user-visible validation error that routers translate to HTTP 400.
        raise ValueError("Password hashing failed.") from exc
    # Do NOT catch a broad Exception here; unexpected errors should propagate to 500 to
    # avoid masking real defects as client validation issues.


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
    except PasslibError:
        # Treat invalid/unknown hash formats or backend issues as non-match rather than raising.
        return False
