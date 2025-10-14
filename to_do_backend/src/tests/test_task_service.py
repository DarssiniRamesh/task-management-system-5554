"""
Module: tests.test_task_service
Purpose: Unit tests for TaskService using real repositories and in-memory SQLite DB.

Coverage:
- create_task success
- list_tasks respects skip/limit bounds
- get_task raises TaskNotFoundError when not found or not owned
- update_task applies changes and validates title; not found -> TaskNotFoundError
- toggle_task flips/is explicit; not found -> TaskNotFoundError
- delete_task enforces ownership; not found -> TaskNotFoundError
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.db.session import Base
from src.db.repositories import UserRepository, TaskRepository
from src.services.task_service import TaskService, TaskNotFoundError


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    s = TestingSession()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture()
def service() -> TaskService:
    return TaskService(task_repository=TaskRepository())


@pytest.fixture()
def user_ids(db: Session) -> tuple[int, int]:
    ur = UserRepository()
    u1 = ur.create_user(db, email="svc1@example.com", password="Password123!")
    u2 = ur.create_user(db, email="svc2@example.com", password="Password123!")
    db.commit()
    return u1.id, u2.id


def test_create_and_get_task(db: Session, service: TaskService, user_ids: tuple[int, int]):
    u1, _ = user_ids
    t = service.create_task(db, user_id=u1, title="Svc Task", description="D")
    db.commit()
    assert t.id is not None
    got = service.get_task(db, user_id=u1, task_id=t.id)
    assert got.id == t.id

    # Cross-user get -> not found error
    with pytest.raises(TaskNotFoundError):
        service.get_task(db, user_id=9999, task_id=t.id)  # user id not owning


def test_list_pagination(db: Session, service: TaskService, user_ids: tuple[int, int]):
    u1, _ = user_ids
    # Create 5 tasks
    for i in range(5):
        service.create_task(db, user_id=u1, title=f"T{i+1}", description=None)
    db.commit()

    # limit 2
    page1 = service.list_tasks(db, user_id=u1, skip=0, limit=2)
    page2 = service.list_tasks(db, user_id=u1, skip=2, limit=2)
    page3 = service.list_tasks(db, user_id=u1, skip=4, limit=2)

    assert len(page1) == 2
    assert len(page2) == 2
    assert len(page3) == 1  # final item
    # Bounds enforcement
    assert len(service.list_tasks(db, user_id=u1, skip=-10, limit=1000)) == 5


def test_update_task_and_validation(db: Session, service: TaskService, user_ids: tuple[int, int]):
    u1, u2 = user_ids
    t = service.create_task(db, user_id=u1, title="Old", description="d")
    db.commit()

    # Update success
    updated = service.update_task(db, user_id=u1, task_id=t.id, title="New", description="x", is_completed=True)
    db.commit()
    assert updated.title == "New"
    assert updated.is_completed is True

    # Empty title -> ValueError
    with pytest.raises(ValueError):
        service.update_task(db, user_id=u1, task_id=t.id, title="   ", description=None, is_completed=None)

    # Cross-user update -> not found
    with pytest.raises(TaskNotFoundError):
        service.update_task(db, user_id=u2, task_id=t.id, title="Other", description=None, is_completed=None)

    # Non-existent -> not found
    with pytest.raises(TaskNotFoundError):
        service.update_task(db, user_id=u1, task_id=99999, title="X", description=None, is_completed=None)


def test_toggle_task(db: Session, service: TaskService, user_ids: tuple[int, int]):
    u1, u2 = user_ids
    t = service.create_task(db, user_id=u1, title="Toggle", description=None)
    db.commit()
    assert t.is_completed is False

    # Toggle without explicit -> True
    toggled = service.toggle_task(db, user_id=u1, task_id=t.id, explicit_state=None)
    db.commit()
    assert toggled.is_completed is True

    # Explicit False
    toggled2 = service.toggle_task(db, user_id=u1, task_id=t.id, explicit_state=False)
    db.commit()
    assert toggled2.is_completed is False

    # Cross-user -> not found
    with pytest.raises(TaskNotFoundError):
        service.toggle_task(db, user_id=u2, task_id=t.id, explicit_state=True)


def test_delete_task_enforces_ownership(db: Session, service: TaskService, user_ids: tuple[int, int]):
    u1, u2 = user_ids
    t = service.create_task(db, user_id=u1, title="DeleteMe", description=None)
    db.commit()

    # Cross-user delete -> not found
    with pytest.raises(TaskNotFoundError):
        service.delete_task(db, user_id=u2, task_id=t.id)

    # Owner delete -> no raise
    service.delete_task(db, user_id=u1, task_id=t.id)
    db.commit()

    # Subsequent delete -> not found
    with pytest.raises(TaskNotFoundError):
        service.delete_task(db, user_id=u1, task_id=t.id)
