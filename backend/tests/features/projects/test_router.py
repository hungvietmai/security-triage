from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import update

from app.features.projects.models import Project


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
    missing = client.get(f"/api/v1/projects/{uuid4()}")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Project not found"}
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


@pytest.mark.parametrize("description", ["", "   ", None])
def test_blank_description_is_stored_as_null(client, description):
    response = client.post("/api/v1/projects", json={"name": "Demo", "description": description})
    assert response.status_code == 201
    assert response.json()["description"] is None


def test_description_is_trimmed(client):
    response = client.post("/api/v1/projects", json={"name": "Demo", "description": "  CWE-78 "})
    assert response.json()["description"] == "CWE-78"


def create(client, name, description=None):
    response = client.post("/api/v1/projects", json={"name": name, "description": description})
    assert response.status_code == 201
    return response.json()


def names(client, query=""):
    response = client.get(f"/api/v1/projects{query}")
    assert response.status_code == 200, response.text
    return [project["name"] for project in response.json()["items"]]


def test_list_sorts_newest_first_by_default(client, session):
    for name in ["old", "middle", "new"]:
        create(client, name)
    # Timestamps may tie within one transaction clock tick; pin them explicitly.
    for offset, name in enumerate(["old", "middle", "new"]):
        session.execute(
            update(Project)
            .where(Project.name == name)
            .values(created_at=datetime(2026, 1, 1 + offset, tzinfo=UTC))
        )
    session.commit()
    assert names(client) == ["new", "middle", "old"]
    assert names(client, "?sort=created_at") == ["old", "middle", "new"]


def test_list_sorts_by_name(client):
    for name in ["beta", "Alpha", "gamma"]:
        create(client, name)
    ascending = names(client, "?sort=name")
    assert ascending == sorted(ascending)
    assert names(client, "?sort=-name") == list(reversed(ascending))


def test_list_rejects_unknown_sort_fields(client):
    assert client.get("/api/v1/projects?sort=description").status_code == 422
    assert client.get("/api/v1/projects?sort=id").status_code == 422


def test_list_searches_name_and_description(client):
    create(client, "Payment API", "Node.js service")
    create(client, "Python CLI", "uses subprocess")
    create(client, "Docs site")
    assert names(client, "?q=payment") == ["Payment API"]
    assert names(client, "?q=SUBPROCESS") == ["Python CLI"]
    assert sorted(names(client, "?q=p&sort=name")) == ["Payment API", "Python CLI"]
    page = client.get("/api/v1/projects?q=p&limit=1").json()
    assert (page["total"], len(page["items"])) == (2, 1)
    assert client.get("/api/v1/projects?q=").status_code == 422
