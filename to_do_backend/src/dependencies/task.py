"""
Module: dependencies.task
Purpose: FastAPI dependency providers for task-related services.
"""

from src.services.task_service import TaskService
from src.db.repositories import TaskRepository


# PUBLIC_INTERFACE
def get_task_service() -> TaskService:
    """
    Provide a TaskService instance without exposing repository types in the provider signature.

    Returns:
        TaskService: Concrete service instance composed with a repository.
    """
    # Compose repository internally to avoid leaking types to FastAPI dependency analysis
    return TaskService(task_repository=TaskRepository())
