"""
Module: schemas.auth
Purpose: Pydantic models for authentication flows including registration, login, and token handling.
Security: Excludes sensitive fields (like passwords) from public response models where appropriate.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class _BaseUser(BaseModel):
    """Shared user fields for composition."""
    email: EmailStr = Field(..., description="Unique email for the user account.")


class _PasswordMixin(BaseModel):
    """Internal mixin to capture password fields for inputs."""
    password: str = Field(..., min_length=8, description="User password (min 8 characters).")


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
