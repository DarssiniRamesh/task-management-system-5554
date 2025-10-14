"""
Module: tests.test_tasks_api
Purpose: Integration tests for /tasks endpoints with real FastAPI app and in-memory SQLite via StaticPool.

Scenarios covered:
- All endpoints require auth (401 without token)
- POST /tasks creates task for current user; 422 on invalid payload (empty title)
- GET /tasks paginated and scoped to authenticated user
- GET /tasks/{id} 404 for other user's task or missing
- PUT /tasks/{id} full update; 400 on empty title; 404 for not found or cross-user
- PATCH /tasks/{id}/toggle toggles is_completed or sets explicit; 404 not found
- DELETE /tasks/{id} deletes only owner's; 404 when not found
"""

from fastapi.testclient import TestClient


def test_auth_required_on_all_routes(client: TestClient):
    # List
    assert client.get("/tasks").status_code == 401
    # Create
    assert client.post("/tasks", json={"title": "X"}).status_code == 401
    # Get
    assert client.get("/tasks/1").status_code == 401
    # Update
    assert client.put("/tasks/1", json={"title": "x", "description": None, "is_completed": False}).status_code == 401
    # Toggle
    assert client.patch("/tasks/1/toggle", json={"is_completed": True}).status_code == 401
    # Delete
    assert client.delete("/tasks/1").status_code == 401


def test_create_task_and_get_list_pagination(client: TestClient, auth_header, seed_tasks):
    headers_user1 = auth_header("owner1@example.com", "Password123!")
    # Invalid payload: empty title -> 422 by schema
    bad = client.post("/tasks", json={"title": ""}, headers=headers_user1)
    assert bad.status_code == 422

    # Create 5 tasks
    uid, created = seed_tasks("owner1@example.com", "Password123!", 5)
    assert len(created) == 5

    # Another user creates 2 tasks
    seed_tasks("owner2@example.com", "Password123!", 2)

    # List for user1, pagination
    resp1 = client.get("/tasks?skip=0&limit=2", headers=headers_user1)
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert isinstance(data1, list) and len(data1) == 2
    assert all(t["user_id"] == uid for t in data1)

    resp2 = client.get("/tasks?skip=2&limit=2", headers=headers_user1)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2) == 2
    assert all(t["user_id"] == uid for t in data2)

    resp3 = client.get("/tasks?skip=4&limit=2", headers=headers_user1)
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert len(data3) == 1  # remaining one
    assert all(t["user_id"] == uid for t in data3)


def test_get_task_and_ownership_enforced(client: TestClient, auth_header, seed_tasks):
    headers_user1 = auth_header("g1@example.com", "Password123!")
    uid, created = seed_tasks("g1@example.com", "Password123!", 1)
    tid = created[0]["id"]

    headers_user2 = auth_header("g2@example.com", "Password123!")

    # Owner can get
    r_ok = client.get(f"/tasks/{tid}", headers=headers_user1)
    assert r_ok.status_code == 200
    assert r_ok.json()["id"] == tid

    # Other user's access -> 404 (not found)
    r_forbidden = client.get(f"/tasks/{tid}", headers=headers_user2)
    assert r_forbidden.status_code == 404

    # Non-existent -> 404
    r_nf = client.get("/tasks/999999", headers=headers_user1)
    assert r_nf.status_code == 404


def test_put_update_task_and_validation(client: TestClient, auth_header, seed_tasks):
    headers_user1 = auth_header("u1@example.com", "Password123!")
    _, created = seed_tasks("u1@example.com", "Password123!", 1)
    tid = created[0]["id"]

    # Full update: valid
    payload = {"title": "Updated Title", "description": "Updated Desc", "is_completed": True}
    r = client.put(f"/tasks/{tid}", json=payload, headers=headers_user1)
    assert r.status_code == 200
    b = r.json()
    assert b["title"] == "Updated Title"
    assert b["description"] == "Updated Desc"
    assert b["is_completed"] is True

    # Empty title -> 400 from service/repo
    r2 = client.put(f"/tasks/{tid}", json={"title": "   ", "description": None, "is_completed": False}, headers=headers_user1)
    assert r2.status_code == 400

    # Cross-user update -> 404
    headers_user2 = auth_header("u2@example.com", "Password123!")
    r3 = client.put(f"/tasks/{tid}", json=payload, headers=headers_user2)
    assert r3.status_code == 404

    # Not found -> 404
    r4 = client.put("/tasks/999999", json=payload, headers=headers_user1)
    assert r4.status_code == 404


def test_toggle_task_completion(client: TestClient, auth_header, seed_tasks):
    headers_user1 = auth_header("t1@example.com", "Password123!")
    _, created = seed_tasks("t1@example.com", "Password123!", 1)
    tid = created[0]["id"]

    # Toggle without body flips the state
    r1 = client.patch(f"/tasks/{tid}/toggle", headers=headers_user1)
    assert r1.status_code == 200
    current = r1.json()
    first_state = current["is_completed"]

    # Explicit set to opposite
    r2 = client.patch(f"/tasks/{tid}/toggle", json={"is_completed": (not first_state)}, headers=headers_user1)
    assert r2.status_code == 200
    assert r2.json()["is_completed"] is (not first_state)

    # Other user -> 404
    headers_user2 = auth_header("t2@example.com", "Password123!")
    r3 = client.patch(f"/tasks/{tid}/toggle", headers=headers_user2)
    assert r3.status_code == 404

    # Not found
    r4 = client.patch("/tasks/999999/toggle", headers=headers_user1)
    assert r4.status_code == 404


def test_delete_task_only_owner(client: TestClient, auth_header, seed_tasks):
    headers_user1 = auth_header("d1@example.com", "Password123!")
    _, created = seed_tasks("d1@example.com", "Password123!", 1)
    tid = created[0]["id"]

    # Cross-user delete -> 404
    headers_user2 = auth_header("d2@example.com", "Password123!")
    r1 = client.delete(f"/tasks/{tid}", headers=headers_user2)
    assert r1.status_code == 404

    # Owner delete -> 204 no content
    r2 = client.delete(f"/tasks/{tid}", headers=headers_user1)
    assert r2.status_code == 204 or r2.status_code == 204

    # Subsequent delete -> 404
    r3 = client.delete(f"/tasks/{tid}", headers=headers_user1)
    assert r3.status_code == 404
