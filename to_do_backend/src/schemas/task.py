"""
Module: schemas.task
Purpose: Pydantic models for Task entity inputs/outputs to ensure strict validation and clean API contracts.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class _BaseTask(BaseModel):
    """Shared base fields for task resources."""
    title: str = Field(..., min_length=1, max_length=255, description="Short title for the task.")
    description: Optional[str] = Field(
        default=None, max_length=10000, description="Optional detailed description for the task."
    )


# PUBLIC_INTERFACE
class TaskCreateRequest(_BaseTask):
    """Request body for creating a task."""


# PUBLIC_INTERFACE
class TaskUpdateRequest(BaseModel):
    """Request body for updating a task (full update)."""
    title: str = Field(..., min_length=1, max_length=255, description="Updated title for the task.")
    description: Optional[str] = Field(
        default=None, max_length=10000, description="Updated detailed description for the task."
    )
    is_completed: bool = Field(..., description="Completion status of the task.")


# PUBLIC_INTERFACE
class TaskToggleRequest(BaseModel):
    """Request body for toggling completion. Allows explicit set; if omitted router will flip."""
    is_completed: Optional[bool] = Field(
        default=None,
        description="Optional explicit desired state. If not provided, the server toggles the current state.",
    )


# PUBLIC_INTERFACE
class TaskResponse(_BaseTask):
    """Task representation returned by API."""
    id: int = Field(..., description="Unique task identifier.")
    user_id: int = Field(..., description="Owner user ID.")
    is_completed: bool = Field(..., description="Whether the task is completed.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")

    class Config:
        from_attributes = True
