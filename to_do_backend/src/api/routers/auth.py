"""
Module: api.routers.auth
Purpose: Authentication routes for user registration, login, and profile retrieval.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.db.session import get_db
from src.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from src.services.auth_service import AuthService, InvalidCredentialsError
from src.db.repositories import DuplicateEmailError
from src.dependencies.auth import get_current_user_id

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a user with a hashed password. Returns basic user information.",
    responses={
        201: {"description": "User created."},
        400: {"description": "Validation error."},
        409: {"description": "Email already exists."},
    },
)
def register_user(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
):
    """
    Register a new user.

    Parameters:
        payload: RegisterRequest containing email and password.

    Returns:
        UserResponse with id, email, timestamps.
    """
    try:
        user = auth_service.register_user(db, email=payload.email, password=payload.password)
        # The session is committed in get_db dependency after returning
        return UserResponse.model_validate(user)
    except DuplicateEmailError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
    description="Validates user credentials and returns a JWT access token (HS256).",
    responses={
        200: {"description": "Login successful."},
        401: {"description": "Invalid credentials."},
    },
)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
):
    """
    Login user and get access token.

    Parameters:
        payload: LoginRequest containing email and password.

    Returns:
        TokenResponse with access_token and token_type bearer.
    """
    try:
        _, token = auth_service.authenticate_user(db, email=payload.email, password=payload.password)
        return TokenResponse(access_token=token)
    except InvalidCredentialsError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Returns current user details when provided a valid Bearer token.",
    responses={200: {"description": "User info returned."}, 401: {"description": "Unauthorized."}},
)
def get_me(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
):
    """
    Get the current authenticated user's profile.

    Returns:
        UserResponse for the current user.
    """
    user = auth_service.get_user_by_id(db, user_id=user_id)
    if not user:
        # Token valid but user not found (deleted account)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")
    return UserResponse.model_validate(user)
