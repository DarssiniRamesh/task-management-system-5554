"""
Module: services.task_service
Purpose: Business logic for Task operations ensuring authorization and validation.
"""

from typing import Optional, Sequence

from sqlalchemy.orm import Session

from src.db.models import Task
from src.db.repositories import TaskRepository


class TaskNotFoundError(Exception):
    """Raised when a task cannot be found or is not owned by the user."""


class TaskService:
    """Service layer for task operations with ownership enforcement."""

    def __init__(self, task_repository: object | None = None):
        # Avoid exposing repository types in annotations to FastAPI DI analysis
        self._task_repo = task_repository or TaskRepository()

    # PUBLIC_INTERFACE
    def create_task(self, db: Session, *, user_id: int, title: str, description: Optional[str]) -> Task:
        """Create a new task."""
        return self._task_repo.create_task(db, user_id=user_id, title=title, description=description)

    # PUBLIC_INTERFACE
    def list_tasks(self, db: Session, *, user_id: int, skip: int = 0, limit: int = 50) -> Sequence[Task]:
        """
        Return a paginated list of tasks for the user.

        For now, repository returns full list; we slice to keep repository simple.
        """
        tasks = self._task_repo.list_tasks(db, user_id=user_id)
        skip = max(0, int(skip))
        limit = max(1, min(int(limit), 100))
        return tasks[skip : skip + limit]

    # PUBLIC_INTERFACE
    def get_task(self, db: Session, *, user_id: int, task_id: int) -> Task:
        """Get a single task owned by the user."""
        task = self._task_repo.get_task(db, user_id=user_id, task_id=task_id)
        if not task:
            raise TaskNotFoundError("Task not found.")
        return task

    # PUBLIC_INTERFACE
    def update_task(
        self,
        db: Session,
        *,
        user_id: int,
        task_id: int,
        title: Optional[str],
        description: Optional[str],
        is_completed: Optional[bool],
    ) -> Task:
        """Update task fields; raises if task doesn't exist."""
        task = self._task_repo.update_task(
            db, user_id=user_id, task_id=task_id, title=title, description=description, is_completed=is_completed
        )
        if not task:
            raise TaskNotFoundError("Task not found.")
        return task

    # PUBLIC_INTERFACE
    def toggle_task(self, db: Session, *, user_id: int, task_id: int, explicit_state: Optional[bool]) -> Task:
        """Toggle task completion or set explicit state."""
        task = self._task_repo.get_task(db, user_id=user_id, task_id=task_id)
        if not task:
            raise TaskNotFoundError("Task not found.")
        new_state = (not task.is_completed) if explicit_state is None else bool(explicit_state)
        task = self._task_repo.update_task(
            db, user_id=user_id, task_id=task_id, is_completed=new_state, title=None, description=None
        )
        if not task:
            raise TaskNotFoundError("Task not found.")
        return task

    # PUBLIC_INTERFACE
    def delete_task(self, db: Session, *, user_id: int, task_id: int) -> None:
        """Delete a task; no-op if not found, but surface as not found per API semantics."""
        deleted = self._task_repo.delete_task(db, user_id=user_id, task_id=task_id)
        if not deleted:
            raise TaskNotFoundError("Task not found.")
