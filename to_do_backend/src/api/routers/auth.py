"""
Module: api.routers.auth
Purpose: Authentication routes for user registration, login, and profile retrieval.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.db.session import get_db
from src.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from src.services.auth_service import AuthService, InvalidCredentialsError, POLICY_MESSAGE
from src.db.repositories import DuplicateEmailError, RepositoryError
from src.dependencies.auth import get_current_user_id, get_auth_service

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a user with a hashed password. Returns basic user information. Password must be at least 8 characters; no upper byte-length limit.",
    responses={
        201: {"description": "User created."},
        400: {"description": "Validation error."},
        409: {"description": "Email already exists."},
    },
)
# PUBLIC_INTERFACE
def register_user(
    payload: RegisterRequest,
    db: Annotated[Session, Depends(get_db)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
):
    """
    Register a new user.

    Parameters:
        payload: RegisterRequest containing email and password.
        db: Injected SQLAlchemy session via Depends.
        auth_service: Injected AuthService via Depends.

    Returns:
        UserResponse with id, email, timestamps.

    Raises:
        HTTPException: 409 if email exists; 400 if validation fails.
    """
    try:
        # Delegate to service; transaction lifecycle is handled by get_db dependency.
        user = auth_service.register_user(db, email=payload.email, password=payload.password)
        return UserResponse.model_validate(user)
    except DuplicateEmailError as exc:
        # 409 Conflict for duplicate emails (unique constraint violation)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RepositoryError as exc:
        # Any repository-layer controlled error should be surfaced as a 400 to avoid 500s.
        detail = str(exc) or "Invalid input."
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except ValueError as exc:
        # Map service-layer policy violations and hashing/processing errors to 400 with precise detail.
        detail = str(exc) or POLICY_MESSAGE
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except Exception as exc:
        # Final safety net to prevent 500s on expected flow; redact details
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid input.") from exc


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
    description="Validates user credentials and returns a JWT access token (HS256). Password must be at least 8 characters.",
    responses={
        200: {"description": "Login successful."},
        400: {"description": "Validation error."},
        401: {"description": "Invalid credentials."},
    },
)
# PUBLIC_INTERFACE
def login(
    payload: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
):
    """
    Login user and get access token.

    Parameters:
        payload: LoginRequest containing email and password.
        db: Injected SQLAlchemy session via Depends.
        auth_service: Injected AuthService via Depends.

    Returns:
        TokenResponse with access_token and token_type bearer.

    Raises:
        HTTPException: 400 if validation fails; 401 if credentials are invalid.
    """
    try:
        _, token = auth_service.authenticate_user(db, email=payload.email, password=payload.password)
        return TokenResponse(access_token=token)
    except InvalidCredentialsError as exc:
        # 401 Unauthorized for bad credentials without leaking specifics
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except RepositoryError as exc:
        # Repository errors in login are treated as invalid inputs (do not leak internals)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc) or "Invalid input.") from exc
    except ValueError as exc:
        # Enforce consistent 400 behavior (service enforces >=8 characters policy)
        detail = str(exc) or POLICY_MESSAGE
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except Exception as exc:
        # Final safety net to avoid 500 for predictable flow issues
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid input.") from exc


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Returns current user details when provided a valid Bearer token.",
    responses={200: {"description": "User info returned."}, 401: {"description": "Unauthorized."}},
)
# PUBLIC_INTERFACE
def get_me(
    user_id: Annotated[int, Depends(get_current_user_id)],
    db: Annotated[Session, Depends(get_db)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
):
    """
    Get the current authenticated user's profile.

    Parameters:
        user_id: Injected current user id parsed from Bearer token via Depends(get_current_user_id).
        db: Injected SQLAlchemy session via Depends.
        auth_service: Injected AuthService via Depends.

    Returns:
        UserResponse for the current user.

    Raises:
        HTTPException: 401 if user not found or token invalid.
    """
    user = auth_service.get_user_by_id(db, user_id=user_id)
    if not user:
        # Token valid but user not found (deleted account)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")
    return UserResponse.model_validate(user)
