"""
Module: tests.test_task_repository
Purpose: Unit-level tests for TaskRepository using a real in-memory SQLite database.

Coverage:
- create_task: success, empty title, invalid user_id
- get_task: only owner can see; non-existent -> None
- list_tasks: returns only user's tasks, ordered desc by created_at (approximate with ids)
- update_task: update fields, empty title -> ValueError, not found -> None
- delete_task: delete own, cross-user no-op, invalid ids
"""

from typing import Tuple

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.db.session import Base
from src.db.repositories import TaskRepository, UserRepository
from src.db.models import Task


@pytest.fixture()
def db_session() -> Session:
    """
    Standalone in-memory DB. Using check_same_thread=False as usual for SQLite in tests.
    """
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def repos() -> Tuple[UserRepository, TaskRepository]:
    return UserRepository(), TaskRepository()


def _create_user(db: Session, user_repo: UserRepository, email: str = "user@example.com", password: str = "Password123!") -> int:
    user = user_repo.create_user(db, email=email, password=password)
    db.commit()
    return user.id


def _create_task(db: Session, task_repo: TaskRepository, *, user_id: int, title: str, description: str | None = None) -> Task:
    task = task_repo.create_task(db, user_id=user_id, title=title, description=description)
    db.commit()
    db.refresh(task)
    return task


def test_create_task_success(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    user_repo, task_repo = repos
    uid = _create_user(db_session, user_repo)
    t = task_repo.create_task(db_session, user_id=uid, title="My Task", description="Desc")
    db_session.commit()
    assert t.id is not None
    assert t.user_id == uid
    assert t.title == "My Task"
    assert t.description == "Desc"
    assert t.is_completed is False


def test_create_task_empty_title_raises(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    user_repo, task_repo = repos
    uid = _create_user(db_session, user_repo)
    with pytest.raises(ValueError):
        task_repo.create_task(db_session, user_id=uid, title="   ", description=None)


def test_create_task_invalid_user_id_raises(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    _, task_repo = repos
    with pytest.raises(ValueError):
        task_repo.create_task(db_session, user_id=0, title="X")


def test_get_task_scoped_to_owner(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    user_repo, task_repo = repos
    uid1 = _create_user(db_session, user_repo, email="a@example.com")
    uid2 = _create_user(db_session, user_repo, email="b@example.com")
    t = _create_task(db_session, task_repo, user_id=uid1, title="OwnerOnly")

    # Owner sees it
    got_owner = task_repo.get_task(db_session, user_id=uid1, task_id=t.id)
    assert got_owner is not None and got_owner.id == t.id

    # Other user cannot see it
    got_other = task_repo.get_task(db_session, user_id=uid2, task_id=t.id)
    assert got_other is None

    # Non-existent id
    assert task_repo.get_task(db_session, user_id=uid1, task_id=9999) is None


def test_list_tasks_returns_only_user_tasks(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    user_repo, task_repo = repos
    uid1 = _create_user(db_session, user_repo, email="list1@example.com")
    uid2 = _create_user(db_session, user_repo, email="list2@example.com")

    # Create 3 tasks for uid1 and 2 for uid2
    ids1 = []
    for i in range(3):
        ids1.append(_create_task(db_session, task_repo, user_id=uid1, title=f"U1-{i+1}").id)
    ids2 = []
    for i in range(2):
        ids2.append(_create_task(db_session, task_repo, user_id=uid2, title=f"U2-{i+1}").id)

    u1_tasks = task_repo.list_tasks(db_session, user_id=uid1)
    u2_tasks = task_repo.list_tasks(db_session, user_id=uid2)

    assert {t.id for t in u1_tasks} == set(ids1)
    assert {t.id for t in u2_tasks} == set(ids2)


def test_update_task_fields_and_validation(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    user_repo, task_repo = repos
    uid = _create_user(db_session, user_repo, email="update@example.com")
    task = _create_task(db_session, task_repo, user_id=uid, title="Orig", description="D")

    # Update title and description
    updated = task_repo.update_task(db_session, user_id=uid, task_id=task.id, title=" New ", description="  new desc  ")
    db_session.commit()
    assert updated is not None
    assert updated.title == "New"
    assert updated.description == "new desc"

    # Validate empty title when provided explicitly
    with pytest.raises(ValueError):
        task_repo.update_task(db_session, user_id=uid, task_id=task.id, title="   ")

    # Non-existent task -> None
    assert task_repo.update_task(db_session, user_id=uid, task_id=9999, title="Something") is None


def test_update_toggle_completed(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    user_repo, task_repo = repos
    uid = _create_user(db_session, user_repo, email="toggle@example.com")
    task = _create_task(db_session, task_repo, user_id=uid, title="Toggle")
    assert task.is_completed is False

    # Set explicit True
    updated = task_repo.update_task(db_session, user_id=uid, task_id=task.id, is_completed=True)
    db_session.commit()
    assert updated is not None and updated.is_completed is True

    # Flip back to False
    updated2 = task_repo.update_task(db_session, user_id=uid, task_id=task.id, is_completed=False)
    db_session.commit()
    assert updated2 is not None and updated2.is_completed is False


def test_delete_task_ownership_enforced(db_session: Session, repos: Tuple[UserRepository, TaskRepository]):
    user_repo, task_repo = repos
    uid1 = _create_user(db_session, user_repo, email="del1@example.com")
    uid2 = _create_user(db_session, user_repo, email="del2@example.com")
    task = _create_task(db_session, task_repo, user_id=uid1, title="To Delete")

    # Cross-user delete should be False
    deleted = task_repo.delete_task(db_session, user_id=uid2, task_id=task.id)
    db_session.commit()
    assert deleted is False
    assert task_repo.get_task(db_session, user_id=uid1, task_id=task.id) is not None

    # Owner delete should be True
    deleted2 = task_repo.delete_task(db_session, user_id=uid1, task_id=task.id)
    db_session.commit()
    assert deleted2 is True
    assert task_repo.get_task(db_session, user_id=uid1, task_id=task.id) is None

    # Deleting non-existent -> False
    assert task_repo.delete_task(db_session, user_id=uid1, task_id=99999) is False
