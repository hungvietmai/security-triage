from uuid import uuid4

import pytest


def test_create_list_and_get_project(client):
    response = client.post("/api/v1/projects", json={"name": "  Sample  ", "description": "Python"})
    assert response.status_code == 201
    project = response.json()
    assert project["name"] == "Sample"
    assert project["created_at"]
    assert client.get(f"/api/v1/projects/{project['id']}").json() == project
    page = client.get("/api/v1/projects").json()
    assert page["items"] == [project]
    assert page["total"] == 1


@pytest.mark.parametrize("name", ["", "   ", "x" * 121])
def test_reject_invalid_project_name(client, name):
    assert client.post("/api/v1/projects", json={"name": name}).status_code == 422
    assert client.get("/api/v1/projects").json()["total"] == 0


def test_unknown_and_invalid_project_id(client):
    assert client.get(f"/api/v1/projects/{uuid4()}").status_code == 404
    assert client.get("/api/v1/projects/not-a-uuid").status_code == 422


def test_paginated_projects_do_not_overlap(client):
    for name in ["First", "Second", "Third"]:
        assert client.post("/api/v1/projects", json={"name": name}).status_code == 201
    first = client.get("/api/v1/projects?limit=2&offset=0").json()
    second = client.get("/api/v1/projects?limit=2&offset=2").json()
    assert first["total"] == second["total"] == 3
    assert len(first["items"]) == 2
    assert len(second["items"]) == 1
    assert {p["id"] for p in first["items"]}.isdisjoint(p["id"] for p in second["items"])
    assert client.get("/api/v1/projects?limit=101").status_code == 422
    assert client.get("/api/v1/projects?offset=-1").status_code == 422


def test_extra_fields_are_not_silently_accepted(client):
    assert (
        client.post("/api/v1/projects", json={"name": "Demo", "id": str(uuid4())}).status_code
        == 422
    )
