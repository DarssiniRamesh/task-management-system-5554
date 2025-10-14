"""
Module: schemas.auth
Purpose: Pydantic models for authentication flows including registration, login, and token handling.
Security: Excludes sensitive fields (like passwords) from public response models where appropriate.
Enhancement: Enforce bcrypt-compatible UTF-8 byte-length policy (8–72 bytes) at the schema level.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


def _validate_password_byte_length(password: str) -> str:
    """
    Validate that the password respects bcrypt's 72-byte limit and a minimum of 8 bytes.

    Notes:
        - Bcrypt truncates input after 72 bytes; we proactively reject >72 bytes to avoid ambiguity.
        - We consider byte-length under UTF-8 encoding (not character count) to properly handle
          multi-byte characters.

    Raises:
        ValueError: If the password is shorter than 8 bytes or longer than 72 bytes.
    """
    if not isinstance(password, str):
        raise ValueError("Invalid password.")
    byte_len = len(password.encode("utf-8"))
    if byte_len < 8 or byte_len > 72:
        # Use a safe, generic message across register/login to avoid leaking policy nuances
        raise ValueError("Password must be between 8 and 72 bytes.")
    return password


class _BaseUser(BaseModel):
    """Shared user fields for composition."""
    email: EmailStr = Field(..., description="Unique email for the user account.")


class _PasswordMixin(BaseModel):
    """
    Internal mixin to capture password fields for inputs.

    We keep a human-friendly minimum of 8 characters at UI level via description, but the actual
    enforcement relevant to bcrypt is implemented via a field validator using UTF-8 byte length.
    """
    password: str = Field(
        ...,
        min_length=1,  # syntactic requirement; actual policy enforced in validator below
        description="User password (8–72 bytes, UTF-8).",
    )

    # Enforce bcrypt-safe boundaries using UTF-8 byte length
    @field_validator("password")
    @classmethod
    def _password_byte_bounds(cls, v: str) -> str:
        return _validate_password_byte_length(v)


# PUBLIC_INTERFACE
class RegisterRequest(_BaseUser, _PasswordMixin):
    """Request body for user registration."""


# PUBLIC_INTERFACE
class LoginRequest(_BaseUser, _PasswordMixin):
    """Request body for user login."""


# PUBLIC_INTERFACE
class UserResponse(_BaseUser):
    """Public user representation excluding credentials."""
    id: int = Field(..., description="User ID.")
    created_at: datetime = Field(..., description="User creation timestamp.")
    updated_at: datetime = Field(..., description="User last update timestamp.")

    class Config:
        from_attributes = True


# PUBLIC_INTERFACE
class TokenResponse(BaseModel):
    """JWT access token response."""
    access_token: str = Field(..., description="JWT access token.")
    token_type: str = Field(default="bearer", description="Token type (RFC 6750).")


# PUBLIC_INTERFACE
class TokenPayload(BaseModel):
    """Decoded JWT payload used internally for auth dependency."""
    sub: str = Field(..., description="Subject (user identifier, typically user id).")
    exp: int = Field(..., description="Expiration time (Unix epoch seconds).")
    iat: Optional[int] = Field(None, description="Issued at (Unix epoch seconds).")
