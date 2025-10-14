"""
Module: security
Purpose: Security utilities for password hashing and verification.

Implementation details:
- Primary scheme: Argon2 (via argon2-cffi) to be more robust across environments.
- Fallback schemes: bcrypt_sha256 then bcrypt (raw) within a single CryptContext.
- No manual low-level bcrypt pre-hashing: we rely entirely on passlib's implementations.
- Support arbitrarily long passwords by configuring generous max_password_size for argon2 and bcrypt_sha256.

Verification:
- verify_password() delegates to CryptContext.verify(), which auto-detects the scheme from the hash.
- On verify errors (e.g., unknown scheme/missing backend), verification returns False without raising.
"""

from __future__ import annotations

import logging
from typing import Final

from passlib.context import CryptContext

# Configure module-level logger. In production prefer centralized structured logging.
logger = logging.getLogger("to_do_backend.core.security")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# Detect availability of optional backends to help diagnose environment issues
try:  # pragma: no cover - diagnostic logging only
    import argon2 as _argon2  # type: ignore  # noqa: F401

    _ARGON2_AVAILABLE: Final[bool] = True
    logger.info(
        "Argon2 backend detected.",
        extra={"component": "security", "argon2_available": True},
    )
except Exception as _exc:  # pragma: no cover - diagnostic logging only
    _ARGON2_AVAILABLE = False
    logger.warning(
        "Argon2 backend NOT available. Ensure 'argon2-cffi' is installed.",
        extra={"component": "security", "argon2_available": False, "exc_type": _exc.__class__.__name__},
    )

try:  # pragma: no cover - diagnostic logging only
    import bcrypt as _bcrypt  # type: ignore  # noqa: F401

    _BCRYPT_AVAILABLE: Final[bool] = True
    logger.info(
        "bcrypt backend detected.",
        extra={"component": "security", "bcrypt_available": True},
    )
except Exception as _exc:  # pragma: no cover - diagnostic logging only
    _BCRYPT_AVAILABLE = False
    logger.warning(
        "bcrypt backend NOT available. Ensure 'bcrypt' or 'passlib[bcrypt]' is installed.",
        extra={"component": "security", "bcrypt_available": False, "exc_type": _exc.__class__.__name__},
    )

# Unified CryptContext configuration:
# - Prefer argon2 for new hashes.
# - Accept and verify bcrypt_sha256 and bcrypt for compatibility.
# - Set large max_password_size where applicable to accommodate long passwords.
PWD_CONTEXT: Final[CryptContext] = CryptContext(
    schemes=["argon2", "bcrypt_sha256", "bcrypt"],
    deprecated="auto",
    # Allow very long passwords; service layer enforces only minimum length
    argon2__max_password_size=10_000_000,
    bcrypt_sha256__max_password_size=10_000_000,
    # bcrypt raw has an inherent 72-byte limit; we still include it for legacy verification
    bcrypt__max_password_size=72,
)

# Import passlib exceptions defensively
try:  # pragma: no cover
    from passlib.exc import PasslibError  # type: ignore
except Exception:  # pragma: no cover
    class PasslibError(Exception):  # type: ignore
        """Fallback base for passlib-related errors."""
        pass


# PUBLIC_INTERFACE
def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password using a secure algorithm.

    Argon2 is used by default for new hashes. If Argon2 hashing fails due to a missing
    backend or runtime constraints, the function falls back to bcrypt_sha256 and then bcrypt.

    Args:
        plain_password: The raw password to hash (must be a non-empty string).

    Returns:
        A secure hash string.

    Raises:
        ValueError: If the provided password is invalid or hashing fails across all configured schemes.
    """
    if not isinstance(plain_password, str) or plain_password == "":
        raise ValueError("Password must be a non-empty string.")

    # Try default scheme (first in 'schemes' list: argon2)
    try:
        return PWD_CONTEXT.hash(plain_password)
    except PasslibError as exc1:
        # Log minimal diagnostics without PII
        logger.warning(
            "Primary password hashing failed; attempting fallbacks.",
            extra={
                "component": "security",
                "primary_scheme": "argon2",
                "argon2_available": _ARGON2_AVAILABLE,
                "bcrypt_available": _BCRYPT_AVAILABLE,
                "exc_type": exc1.__class__.__name__,
            },
        )
        # Fallback to bcrypt_sha256 then bcrypt (raw)
        for scheme in ("bcrypt_sha256", "bcrypt"):
            try:
                hashed = PWD_CONTEXT.hash(plain_password, scheme=scheme)
                logger.info(
                    "Password hashed using fallback scheme.",
                    extra={"component": "security", "fallback_scheme": scheme},
                )
                return hashed
            except PasslibError as exc_next:
                logger.warning(
                    "Fallback hashing failed.",
                    extra={
                        "component": "security",
                        "fallback_scheme": scheme,
                        "exc_type": exc_next.__class__.__name__,
                    },
                )
                continue

        # All attempts failed: surface a controlled validation error
        raise ValueError("Password hashing failed.") from exc1


# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a stored hash.

    This uses the unified CryptContext which auto-detects the hash's scheme.

    Args:
        plain_password: The raw password to verify.
        hashed_password: The stored hash (argon2, bcrypt_sha256, or bcrypt).

    Returns:
        True if the password matches; False otherwise.
    """
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if plain_password == "" or hashed_password == "":
        return False
    try:
        return PWD_CONTEXT.verify(plain_password, hashed_password)
    except PasslibError:
        # Unknown scheme or missing backend for the given hash -> treat as mismatch
        return False
