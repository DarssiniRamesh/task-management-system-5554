"""
Module: api.routers.tasks
Purpose: Secured CRUD endpoints for tasks. Users can only access their own tasks.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.db.session import get_db
from src.dependencies.auth import get_current_user_id
from src.schemas.task import (
    TaskCreateRequest,
    TaskResponse,
    TaskToggleRequest,
    TaskUpdateRequest,
)
from src.services.task_service import TaskService, TaskNotFoundError

router = APIRouter(prefix="/tasks", tags=["Tasks"])


@router.get(
    "",
    response_model=List[TaskResponse],
    summary="List tasks (paginated)",
    description="Returns a paginated list of tasks belonging to the authenticated user.",
)
def list_tasks(
    skip: int = Query(0, ge=0, description="Number of items to skip."),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of items to return."),
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    task_service: TaskService = Depends(TaskService),
):
    """
    List tasks for the current user with pagination.
    """
    tasks = task_service.list_tasks(db, user_id=user_id, skip=skip, limit=limit)
    return [TaskResponse.model_validate(t) for t in tasks]


@router.get(
    "/{task_id}",
    response_model=TaskResponse,
    summary="Get a task",
    description="Gets a task by id for the authenticated user.",
    responses={404: {"description": "Task not found."}},
)
def get_task(
    task_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    task_service: TaskService = Depends(TaskService),
):
    """
    Retrieve a single task by ID.
    """
    try:
        task = task_service.get_task(db, user_id=user_id, task_id=task_id)
        return TaskResponse.model_validate(task)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "",
    response_model=TaskResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a task",
    description="Creates a new task for the authenticated user.",
)
def create_task(
    payload: TaskCreateRequest,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    task_service: TaskService = Depends(TaskService),
):
    """
    Create a new task.
    """
    task = task_service.create_task(db, user_id=user_id, title=payload.title, description=payload.description)
    return TaskResponse.model_validate(task)


@router.put(
    "/{task_id}",
    response_model=TaskResponse,
    summary="Update a task",
    description="Updates an existing task for the authenticated user.",
    responses={404: {"description": "Task not found."}, 400: {"description": "Validation error."}},
)
def update_task(
    task_id: int,
    payload: TaskUpdateRequest,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    task_service: TaskService = Depends(TaskService),
):
    """
    Full update of a task.
    """
    try:
        task = task_service.update_task(
            db,
            user_id=user_id,
            task_id=task_id,
            title=payload.title,
            description=payload.description,
            is_completed=payload.is_completed,
        )
        return TaskResponse.model_validate(task)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.patch(
    "/{task_id}/toggle",
    response_model=TaskResponse,
    summary="Toggle task completion",
    description="Toggles the completion status of a task or sets it explicitly if provided.",
    responses={404: {"description": "Task not found."}},
)
def toggle_task(
    task_id: int,
    payload: TaskToggleRequest | None = None,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    task_service: TaskService = Depends(TaskService),
):
    """
    Toggle completion or set explicit completion state.
    """
    explicit = None
    if payload is not None:
        explicit = payload.is_completed
    try:
        task = task_service.toggle_task(db, user_id=user_id, task_id=task_id, explicit_state=explicit)
        return TaskResponse.model_validate(task)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.delete(
    "/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a task",
    description="Deletes a task owned by the authenticated user.",
    responses={404: {"description": "Task not found."}, 204: {"description": "Deleted."}},
)
def delete_task(
    task_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    task_service: TaskService = Depends(TaskService),
):
    """
    Delete a task.
    """
    try:
        task_service.delete_task(db, user_id=user_id, task_id=task_id)
        return None
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
