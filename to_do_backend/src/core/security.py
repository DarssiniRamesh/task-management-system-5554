"""
Module: security
Purpose: Security utilities for password hashing and verification.

Design:
- Prefer a single, verifiably available scheme to avoid intermittent failures:
  1) Try Argon2 (via argon2-cffi). If we can successfully hash a probe value at import time,
     we pin the context to argon2-only.
  2) Otherwise, fall back to bcrypt_sha256-only (supports arbitrarily long passwords safely).

Rationale:
- Using a single active scheme avoids ambiguity and backend/handler mis-selection inside Passlib
  that can lead to sporadic "Password hashing failed." errors on valid inputs.
- We proactively validate the backend by hashing a probe value during import; this ensures the
  chosen scheme truly works in the current environment.

Verification:
- verify_password() delegates to the single-scheme CryptContext.verify(), which auto-detects
  based on the configured scheme for the stored hash.
- Any handler/backend errors during verification are treated as a simple mismatch (False).

Security:
- Never log passwords or sensitive values. Only log the chosen scheme and high-level exceptions.
"""

from __future__ import annotations

import logging
from typing import Final

from passlib.context import CryptContext
from passlib import exc as passlib_exc

# Configure module-level logger (prefer centralized config in production)
logger = logging.getLogger("to_do_backend.core.security")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


def _build_pwd_context() -> tuple[CryptContext, str]:
    """
    Build a CryptContext with a single, verifiably available scheme.

    Tries argon2 first; if hashing a probe fails for any reason (missing backend, runtime
    constraints), falls back to bcrypt_sha256.

    Returns:
        Tuple of (CryptContext, active_scheme)

    Raises:
        RuntimeError: If neither argon2 nor bcrypt_sha256 can be verified.
    """
    # Attempt Argon2
    argon2_available = False
    try:  # pragma: no cover - import-time availability check
        import argon2  # noqa: F401
        argon2_available = True
    except Exception as _exc:  # pragma: no cover - diagnostic only
        logger.warning(
            "Argon2 backend not importable; considering fallback.",
            extra={"component": "security", "exc_type": _exc.__class__.__name__},
        )

    if argon2_available:
        try:
            ctx = CryptContext(schemes=["argon2"], deprecated="auto")
            # Probe-hash to ensure runtime backend is truly usable
            ctx.hash("kavia_probe_value")
            logger.info("Active password hashing scheme selected: argon2")
            return ctx, "argon2"
        except Exception as _exc:
            logger.warning(
                "Argon2 probe hashing failed; falling back to bcrypt_sha256.",
                extra={"component": "security", "exc_type": _exc.__class__.__name__},
            )

    # Fallback to bcrypt_sha256 (safe for long passwords via pre-hash)
    try:
        ctx = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
        ctx.hash("kavia_probe_value")
        logger.info("Active password hashing scheme selected: bcrypt_sha256")
        return ctx, "bcrypt_sha256"
    except Exception as _exc:
        logger.error(
            "Failed to initialize any password hashing backend.",
            extra={"component": "security", "exc_type": _exc.__class__.__name__},
        )
        raise RuntimeError("No usable password hashing backend found.") from _exc


# Initialize single-scheme context and scheme name at import time
PWD_CONTEXT: Final[CryptContext]
ACTIVE_SCHEME: Final[str]
PWD_CONTEXT, ACTIVE_SCHEME = _build_pwd_context()

# Construct a tuple of passlib exceptions we handle explicitly
_PASSLIB_ERRORS: tuple[type[BaseException], ...] = tuple(
    t
    for t in (
        getattr(passlib_exc, "PasswordSizeError", None),
        getattr(passlib_exc, "PasswordValueError", None),
        getattr(passlib_exc, "PasslibSecurityError", None),
        getattr(passlib_exc, "MissingBackendError", None),
        getattr(passlib_exc, "UnknownBackendError", None),
        getattr(passlib_exc, "CryptBackendError", None),
        getattr(passlib_exc, "InternalBackendError", None),
        getattr(passlib_exc, "InvalidHashError", None),
        getattr(passlib_exc, "MalformedHashError", None),
        getattr(passlib_exc, "NullPasswordError", None),
        getattr(passlib_exc, "PasswordTruncateError", None),
    )
    if t is not None
) + (ValueError, RuntimeError)


# PUBLIC_INTERFACE
def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password using the active scheme (argon2 or bcrypt_sha256).

    Args:
        plain_password: The raw password to hash (must be a non-empty string).

    Returns:
        A secure hash string.

    Raises:
        ValueError: If the password is invalid or hashing fails.
    """
    if not isinstance(plain_password, str) or plain_password == "":
        raise ValueError("Password must be a non-empty string.")

    try:
        # With a single configured scheme, Passlib uses that scheme directly.
        return PWD_CONTEXT.hash(plain_password)
    except _PASSLIB_ERRORS as exc:
        # Raise a controlled validation error without leaking backend details
        raise ValueError("Password hashing failed.") from exc


# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a stored hash using the active scheme.

    Args:
        plain_password: The raw password to verify.
        hashed_password: The stored hash (must have been produced by ACTIVE_SCHEME).

    Returns:
        True if the password matches; False otherwise.
    """
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if plain_password == "" or hashed_password == "":
        return False
    try:
        return PWD_CONTEXT.verify(plain_password, hashed_password)
    except _PASSLIB_ERRORS:
        # Unknown scheme, missing backend, or handler issues -> treat as mismatch
        return False
