"""
Module: db.repositories
Purpose: Repository layer encapsulating database CRUD operations for Users and Tasks.
         Provides a clean separation from business logic and enables future DB swaps.

Notes:
- All operations use SQLAlchemy ORM sessions passed as arguments.
- Input validation is performed for critical fields.
- Sensitive data (like raw passwords) must never be logged here.
"""

from typing import Optional, Sequence

from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.core.security import hash_password, verify_password
from src.db.models import Task, User


class RepositoryError(Exception):
    """Base repository exception for controlled error handling."""


class DuplicateEmailError(RepositoryError):
    """Raised when attempting to create a user with an email that already exists."""


class UserRepository:
    """Repository handling user-related persistence operations."""

    # PUBLIC_INTERFACE
    def create_user(self, db: Session, *, email: str, password: str) -> User:
        """
        Create a new user with hashed password.

        Args:
            db: Active SQLAlchemy session.
            email: Unique user email.
            password: Plain text password to be hashed.

        Returns:
            The created User instance.

        Raises:
            ValueError: If inputs are invalid.
            DuplicateEmailError: If the email already exists.
        """
        email = (email or "").strip().lower()
        if not email:
            raise ValueError("Email must be provided.")
        # Service layer enforces minimum length policy (>= 8 characters).
        # Here we only guard against an empty string as a final safety check.
        if not isinstance(password, str) or password == "":
            raise ValueError("Password must be provided.")

        user = User(email=email, hashed_password=hash_password(password))
        db.add(user)
        try:
            # Flush to execute INSERT, ensuring constraints checked and PK assigned.
            db.flush()
            # Refresh ensures server-side defaults (timestamps) are present on the instance.
            # Explicitly refresh key attributes to guarantee they are populated pre-commit (SQLite-safe).
            db.refresh(user, attribute_names=["id", "email", "created_at", "updated_at", "hashed_password"])
        except IntegrityError as exc:
            # Roll back the transaction before surfacing a conflict error.
            db.rollback()
            raise DuplicateEmailError("Email already exists.") from exc
        return user

    # PUBLIC_INTERFACE
    def get_by_email(self, db: Session, *, email: str) -> Optional[User]:
        """
        Retrieve a user by email.

        Args:
            db: Active SQLAlchemy session.
            email: User email.

        Returns:
            User if found; otherwise None.
        """
        if not email:
            return None
        stmt = select(User).where(User.email == email.strip().lower())
        return db.execute(stmt).scalar_one_or_none()

    # PUBLIC_INTERFACE
    def authenticate(self, db: Session, *, email: str, password: str) -> Optional[User]:
        """
        Authenticate a user with email and password.

        Args:
            db: Active SQLAlchemy session.
            email: User email.
            password: Plain text password.

        Returns:
            User if authentication succeeds; otherwise None.
        """
        user = self.get_by_email(db, email=email)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user


class TaskRepository:
    """Repository handling task-related persistence operations."""

    # PUBLIC_INTERFACE
    def create_task(
        self, db: Session, *, user_id: int, title: str, description: Optional[str] = None
    ) -> Task:
        """
        Create a new task for a user.

        Args:
            db: Active SQLAlchemy session.
            user_id: Owner user ID.
            title: Task title (required).
            description: Optional task details.

        Returns:
            The created Task.
        """
        title = (title or "").strip()
        if not user_id or not isinstance(user_id, int):
            raise ValueError("Valid user_id is required.")
        if not title:
            raise ValueError("Title is required.")

        task = Task(user_id=user_id, title=title, description=(description or "").strip() or None)
        db.add(task)
        db.flush()
        return task

    # PUBLIC_INTERFACE
    def list_tasks(self, db: Session, *, user_id: int) -> Sequence[Task]:
        """
        List tasks for a given user.

        Args:
            db: Active SQLAlchemy session.
            user_id: Owner user ID.

        Returns:
            Sequence of Task objects.
        """
        if not user_id or not isinstance(user_id, int):
            return []
        stmt = select(Task).where(Task.user_id == user_id).order_by(Task.created_at.desc())
        return list(db.execute(stmt).scalars().all())

    # PUBLIC_INTERFACE
    def get_task(self, db: Session, *, user_id: int, task_id: int) -> Optional[Task]:
        """
        Retrieve a task by ID ensuring it belongs to the given user.

        Args:
            db: Active SQLAlchemy session.
            user_id: Owner user ID.
            task_id: Task ID.

        Returns:
            Task if found; otherwise None.
        """
        if not task_id or not user_id:
            return None
        stmt = select(Task).where(Task.id == task_id, Task.user_id == user_id)
        return db.execute(stmt).scalar_one_or_none()

    # PUBLIC_INTERFACE
    def update_task(
        self,
        db: Session,
        *,
        user_id: int,
        task_id: int,
        title: Optional[str] = None,
        description: Optional[str] = None,
        is_completed: Optional[bool] = None,
    ) -> Optional[Task]:
        """
        Update task fields with safety checks (only owner can update).

        Args:
            db: Active SQLAlchemy session.
            user_id: Owner user ID.
            task_id: Task ID.
            title: Optional new title.
            description: Optional new description.
            is_completed: Optional completion flag.

        Returns:
            Updated Task if found; otherwise None.
        """
        task = self.get_task(db, user_id=user_id, task_id=task_id)
        if not task:
            return None

        if title is not None:
            new_title = title.strip()
            if not new_title:
                raise ValueError("Title cannot be empty.")
            task.title = new_title
        if description is not None:
            task.description = description.strip() or None
        if is_completed is not None:
            task.is_completed = bool(is_completed)

        db.flush()
        return task

    # PUBLIC_INTERFACE
    def delete_task(self, db: Session, *, user_id: int, task_id: int) -> bool:
        """
        Delete a task if it belongs to the given user.

        Args:
            db: Active SQLAlchemy session.
            user_id: Owner user ID.
            task_id: Task ID.

        Returns:
            True if a task was deleted; otherwise False.
        """
        if not task_id or not user_id:
            return False
        stmt = delete(Task).where(Task.id == task_id, Task.user_id == user_id)
        result = db.execute(stmt)
        # SQLAlchemy 2.0 returns CursorResult; rowcount indicates affected rows
        return (result.rowcount or 0) > 0
