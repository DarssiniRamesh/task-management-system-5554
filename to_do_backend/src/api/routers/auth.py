"""
Module: api.routers.auth
Purpose: Authentication routes for user registration, login, and profile retrieval.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
import logging
from sqlalchemy.orm import Session

from src.db.session import get_db
from src.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from src.services.auth_service import AuthService, InvalidCredentialsError, POLICY_MESSAGE
from src.db.repositories import DuplicateEmailError, RepositoryError
from src.dependencies.auth import get_current_user_id, get_auth_service

router = APIRouter(prefix="/auth", tags=["Auth"])
logger = logging.getLogger("to_do_backend.api.routers.auth")


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
        # Controlled repository-layer error; surface details as provided without masking.
        detail = str(exc).strip() or "Repository error."
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except ValueError as exc:
        # Preserve the actual validation message from the service/repository.
        # If the message clearly indicates the password policy, keep it; otherwise pass through as-is.
        msg = (str(exc) or "").strip()
        if not msg:
            # If no message was provided, fall back to the policy message only for password-related issues.
            msg = POLICY_MESSAGE
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg) from exc
    except HTTPException:
        # Let already-formed HTTP exceptions bubble up unchanged.
        raise
    except Exception:
        # Unexpected error: log and re-raise to avoid masking root cause as a generic 400.
        logger.exception("Unexpected error during user registration for email=%s", payload.email)
        raise


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
        # Repository errors in login: surface the message (do not leak internals beyond controlled msg)
        detail = (str(exc) or "").strip() or "Repository error."
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except ValueError as exc:
        # Enforce consistent 400 behavior while preserving precise messages
        detail = (str(exc) or "").strip() or POLICY_MESSAGE
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except HTTPException:
        # Allow previously raised HTTP errors to propagate
        raise
    except Exception:
        # Unexpected error: log and re-raise to avoid masking root cause as a generic 400.
        logger.exception("Unexpected error during login for email=%s", payload.email)
        raise


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
