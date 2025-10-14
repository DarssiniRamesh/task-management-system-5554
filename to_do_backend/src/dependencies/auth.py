"""
Module: dependencies.auth
Purpose: FastAPI dependencies for authentication. Parses Bearer tokens and resolves current user.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.db.session import get_db
from src.services.auth_service import AuthService, TokenValidationError


# PUBLIC_INTERFACE
def get_current_user_id(
    request: Request, db: Annotated[Session, Depends(get_db)], auth_service: AuthService = Depends(AuthService)
) -> int:
    """
    Extract Bearer token from Authorization header, validate it, and return the user id.

    Args:
        request: FastAPI Request to access headers.
        db: SQLAlchemy session (unused here but retained for potential future lookups).
        auth_service: AuthService dependency.

    Returns:
        int: Current authenticated user's ID.

    Raises:
        HTTPException: 401 if token is missing/invalid.
    """
    auth_header = request.headers.get("Authorization") or ""
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = auth_service.decode_token(token)
        # Validate subject
        if not payload.sub.isdigit():
            raise ValueError("Invalid subject.")
        return int(payload.sub)
    except (TokenValidationError, ValueError):
        # Do not leak details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
