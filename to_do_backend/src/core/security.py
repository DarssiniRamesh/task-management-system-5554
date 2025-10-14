"""
Module: security
Purpose: Security utilities for password hashing and verification.

Implementation details:
- Primary scheme: passlib's bcrypt_sha256 (no manual prehashing in the primary path).
  This safely supports arbitrarily long passwords by applying SHA-256 before bcrypt internally.
- Diagnostics:
  * Log availability and versions of bcrypt and argon2 backends at import time.
  * Log the exact PasslibError type/message when hashing fails (never log passwords).
- Fallbacks (activated only if the primary bcrypt_sha256 hashing fails at runtime):
  1) Try argon2 via passlib if argon2 backend is available.
  2) If argon2 unavailable and bcrypt C-extension is importable, use manual SHA-256 prehash
     combined with the low-level bcrypt library to produce a standard bcrypt hash.

Verification:
- verify_password() attempts passlib verify for bcrypt_sha256 first. Then:
  * Tries passlib argon2 verification (if hash looks like argon2 or passlib supports it).
  * Falls back to manual bcrypt verification with SHA-256 prehash.
  * As a last step, tries raw bcrypt verification (for legacy hashes without prehash).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

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

# Detect availability of bcrypt C-extension up front and record version for diagnostics.
try:
    import bcrypt as _bcrypt  # type: ignore  # noqa: F401

    _BCRYPT_AVAILABLE = True
    _BCRYPT_VERSION = getattr(_bcrypt, "__version__", "unknown")
    logger.info(
        "bcrypt backend available.",
        extra={"component": "security", "bcrypt_available": True, "bcrypt_version": _BCRYPT_VERSION},
    )
except Exception as _bcrypt_exc:
    _BCRYPT_AVAILABLE = False
    _BCRYPT_VERSION = None
    # Warn early; hashing will fail later without a backend for bcrypt-based schemes.
    logger.warning(
        "bcrypt backend NOT available; ensure 'bcrypt' or 'passlib[bcrypt]' is installed.",
        extra={
            "component": "security",
            "bcrypt_available": False,
            "exc_type": _bcrypt_exc.__class__.__name__,
            "exc_msg": str(_bcrypt_exc),
        },
    )

# Detect availability of argon2 backend (argon2-cffi).
try:
    import argon2 as _argon2  # type: ignore  # noqa: F401

    _ARGON2_AVAILABLE = True
    _ARGON2_VERSION = getattr(_argon2, "__version__", "unknown")
    logger.info(
        "argon2 backend available.",
        extra={"component": "security", "argon2_available": True, "argon2_version": _ARGON2_VERSION},
    )
except Exception as _argon2_exc:
    _ARGON2_AVAILABLE = False
    _ARGON2_VERSION = None
    logger.info(
        "argon2 backend not available.",
        extra={
            "component": "security",
            "argon2_available": False,
            "exc_type": _argon2_exc.__class__.__name__,
            "exc_msg": str(_argon2_exc),
        },
    )

# Configure passlib CryptContexts.
# Primary: bcrypt_sha256 (handles long passwords safely) - no manual prehashing here.
# Increase max_password_size to accept very long inputs (policy: only min length of 8 enforced at service layer).
# Note: passlib will still protect memory/transforms; we avoid 72-byte truncation by using bcrypt_sha256.
_PRIMARY_CONTEXT = CryptContext(
    schemes=["bcrypt_sha256"],
    deprecated="auto",
    # Accept passwords significantly longer than default (4096), covering our tests and typical needs.
    # Using a high integer to avoid None compatibility differences across passlib versions.
    bcrypt_sha256__max_password_size=10_000_000,
)

# Secondary contexts used only for verification / fallback hashing.
# Note: constructing these contexts does not guarantee runtime availability; Passlib will raise
# PasslibError when hashing/verifying if the respective backend is missing. We handle that below.
_ARGON2_CONTEXT: Optional[CryptContext] = CryptContext(schemes=["argon2"], deprecated="auto") if True else None


def _sha256_digest_bytes(value: str) -> bytes:
    """Return SHA-256 digest bytes of the provided unicode string encoded as UTF-8."""
    return hashlib.sha256(value.encode("utf-8")).digest()


def _hash_with_manual_bcrypt_sha256(plain_password: str) -> str:
    """
    Manual fallback: SHA-256 prehash the password bytes and hash with low-level bcrypt library.
    Returns a standard bcrypt modular crypt string.
    """
    if not _BCRYPT_AVAILABLE:
        raise RuntimeError("bcrypt backend not available for manual fallback.")
    digest = _sha256_digest_bytes(plain_password)
    # Use default cost or 12 rounds for a reasonable security baseline.
    salt = _bcrypt.gensalt(rounds=12)
    hashed_bytes = _bcrypt.hashpw(digest, salt)
    # bcrypt returns bytes; decode to str for storage.
    return hashed_bytes.decode("utf-8")


def _verify_with_manual_bcrypt_sha256(plain_password: str, hashed_password: str) -> bool:
    """
    Manual verification for hashes produced via _hash_with_manual_bcrypt_sha256().
    """
    if not _BCRYPT_AVAILABLE:
        return False
    try:
        digest = _sha256_digest_bytes(plain_password)
        return _bcrypt.checkpw(digest, hashed_password.encode("utf-8"))
    except Exception:
        return False


def _verify_with_manual_bcrypt_raw(plain_password: str, hashed_password: str) -> bool:
    """
    Manual verification against legacy raw-bcrypt hashes (no prehash).
    """
    if not _BCRYPT_AVAILABLE:
        return False
    try:
        return _bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# PUBLIC_INTERFACE
def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password.

    Args:
        plain_password: The raw password to hash (any length, min enforced upstream).

    Returns:
        A secure hash string using bcrypt_sha256 by default. If unavailable at runtime,
        attempts argon2 (if available) or manual SHA-256 + bcrypt as a last resort.

    Raises:
        ValueError: If the provided password is empty or hashing ultimately fails.
        Other Exceptions: Propagated for unexpected system faults during hashing attempts.
    """
    if not isinstance(plain_password, str) or plain_password == "":
        raise ValueError("Password must be a non-empty string.")

    # Primary attempt: passlib bcrypt_sha256
    try:
        hashed = _PRIMARY_CONTEXT.hash(plain_password)
        if not isinstance(hashed, str) or not hashed:
            # Very defensive; passlib should always return a non-empty string when successful.
            raise ValueError("Password hashing failed.")
        return hashed
    except PasslibError as exc:
        # Minimal, targeted diagnostics without exposing the password.
        logger.error(
            "Passlib hashing failed on primary scheme.",
            extra={
                "component": "security",
                "scheme": "bcrypt_sha256",
                "exc_type": exc.__class__.__name__,
                "exc_msg": str(exc),
                "bcrypt_available": _BCRYPT_AVAILABLE,
                "argon2_available": _ARGON2_AVAILABLE,
            },
        )
        # Fallback 1: argon2 (preferred if available)
        try:
            # Even if argon2 backend isn't available, constructing the context succeeded above;
            # hashing would raise PasslibError which we handle to attempt the next fallback.
            hashed_a2 = _ARGON2_CONTEXT.hash(plain_password)  # type: ignore[union-attr]
            logger.info(
                "Password hashed using argon2 fallback.",
                extra={"component": "security", "fallback": "argon2"},
            )
            return hashed_a2
        except PasslibError as exc2:
            logger.error(
                "Passlib hashing failed on argon2 fallback.",
                extra={"component": "security", "scheme": "argon2", "exc_type": exc2.__class__.__name__, "exc_msg": str(exc2)},
            )
        except Exception as exc2:
            # Unexpected system fault during argon2 attempt
            logger.exception(
                "Unexpected error during argon2 fallback hashing.",
                extra={
                    "component": "security",
                    "fallback": "argon2",
                    "exc_type": exc2.__class__.__name__,
                    "exc_msg": str(exc2),
                },
            )

        # Fallback 2: manual SHA-256 + bcrypt (only if bcrypt C-extension is importable)
        if _BCRYPT_AVAILABLE:
            try:
                hashed_manual = _hash_with_manual_bcrypt_sha256(plain_password)
                logger.info(
                    "Password hashed using manual bcrypt+sha256 fallback.",
                    extra={"component": "security", "fallback": "manual_bcrypt_sha256", "bcrypt_version": _BCRYPT_VERSION},
                )
                return hashed_manual
            except Exception as exc3:
                logger.error(
                    "Manual bcrypt+sha256 fallback hashing failed.",
                    extra={"component": "security", "fallback": "manual_bcrypt_sha256", "exc_type": exc3.__class__.__name__, "exc_msg": str(exc3)},
                )

        # All attempts failed -> present a controlled validation message
        raise ValueError("Password hashing failed.") from exc
    # Do NOT catch a broad Exception here; unexpected errors should propagate to 500 to
    # avoid masking real defects as client validation issues.


# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a stored hash.

    Args:
        plain_password: The raw password to verify.
        hashed_password: The stored hash (bcrypt_sha256 or fallback schemes).

    Returns:
        True if the password matches the hash; otherwise False.
    """
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if plain_password == "" or hashed_password == "":
        return False

    # 1) Try primary context (bcrypt_sha256)
    try:
        if _PRIMARY_CONTEXT.verify(plain_password, hashed_password):
            return True
    except PasslibError:
        # If the backend isn't available or hash isn't recognized, continue with fallbacks.
        pass

    # 2) Try argon2 via passlib if hash looks like argon2 or as a general fallback
    if hashed_password.startswith("$argon2"):
        try:
            if _ARGON2_CONTEXT.verify(plain_password, hashed_password):  # type: ignore[union-attr]
                return True
        except PasslibError:
            pass

    # 3) Manual bcrypt with SHA-256 prehash for hashes produced by our manual fallback
    if _BCRYPT_AVAILABLE and (hashed_password.startswith("$2a$") or hashed_password.startswith("$2b$") or hashed_password.startswith("$2y$")):
        if _verify_with_manual_bcrypt_sha256(plain_password, hashed_password):
            return True
        # 4) As a last attempt, verify against raw bcrypt (legacy hashes without prehash)
        if _verify_with_manual_bcrypt_raw(plain_password, hashed_password):
            return True

    return False
