"""
Module: schemas.auth
Purpose: Pydantic models for authentication flows including registration, login, and token handling.
Security: Excludes sensitive fields (like passwords) from public response models where appropriate.
Enhancement: Allow typical user inputs at schema level. Service layer enforces minimum password length (>=8)
             while allowing arbitrary-length passwords via SHA-256 pre-hash before bcrypt.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


def _validate_password_utf8_bytes(v: str) -> str:
    """
    Validate that the provided password value is a string and normalize it.

    Notes:
        - We ensure the value is a string. The service layer enforces a minimum length of 8 characters.
        - We do not trim or transform the password content to avoid altering user intent.

    Raises:
        ValueError: If the password is not a string or is empty.
    """
    if not isinstance(v, str):
        raise ValueError("Password must be a string.")
    if v == "":
        # Keep schema requiring a non-empty string to avoid passing empties to service.
        raise ValueError("Password cannot be empty.")
    # Do not enforce byte-length limits here to prevent over-eager 422s.
    return v


class _BaseUser(BaseModel):
    """Shared user fields for composition."""
    email: EmailStr = Field(..., description="Unique email for the user account.")


class _PasswordMixin(BaseModel):
    """
    Internal mixin to capture password fields for inputs.

    We keep schema permissive but safe (non-empty string) while the service enforces 8–72 UTF-8 bytes.
    """
    password: str = Field(
        ...,
        min_length=1,  # syntactic requirement; actual minimum of 8 enforced in service
        description="User password (must be at least 8 characters).",
    )

    # Light validation: ensure string and non-empty; byte-length limits in service
    @field_validator("password")
    @classmethod
    def _password_basic_validation(cls, v: str) -> str:
        return _validate_password_utf8_bytes(v)


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
