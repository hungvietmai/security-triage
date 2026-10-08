"""Scan API: named sources only, snapshot reuse, queue-ordered units and evidence detail."""

import hashlib
import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.features.scans.models import Scan
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment
from app.workflows.scans import task as scan_task
from tests.workflows.scans.fakes import (
    PYTHON_SOURCE,
    FakeStorage,
    fake_pipeline,
    fake_registry,
    make_archive,
)

COMMIT = "5d362353550a8baa42bba34edd26e5fb86d41b60"
PACKAGE_JSON = json.dumps({"name": "demo", "version": "1.0.0"})


@pytest.fixture
def queued(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    sent: list[str] = []
    monkeypatch.setattr(scan_task.run_scan, "delay", sent.append)
    return sent


@pytest.fixture
def project_id(client: TestClient) -> str:
    response = client.post("/api/v1/projects", json={"name": "Scans"})
    assert response.status_code == 201
    return str(response.json()["id"])


def _npm(package: str = "demo", version: str = "1.0.0") -> dict[str, Any]:
    return {"source": {"kind": "npm", "package": package, "version": version}}


def _run(engine: Engine, scan_id: str, fetch: Any, storage: FakeStorage | None = None) -> str:
    return scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage or FakeStorage(),  # type: ignore[arg-type]
        run_pipeline_fn=fake_pipeline(),
        fetch=fetch,
    )


@pytest.mark.parametrize(
    "body",
    [
        _npm("https://evil.example/x.tgz"),
        _npm("../etc"),
        _npm("demo", "latest"),
        {"source": {"kind": "npm", "package": "demo", "version": "1.0.0", "url": "https://x"}},
        {"source": {"kind": "url", "url": "https://registry.npmjs.org/demo"}},
        {"source": {"kind": "github", "owner": "-x", "repo": "r", "commit": COMMIT}},
        {"source": {"kind": "github", "owner": "o", "repo": "..", "commit": COMMIT}},
        {"source": {"kind": "github", "owner": "o", "repo": "r", "commit": "main" * 10}},
        {**_npm(), "profile": "other-profile"},
    ],
)
def test_only_validated_named_sources_are_accepted(client, project_id, queued, body):
    response = client.post(f"/api/v1/projects/{project_id}/scans", json=body)
    assert response.status_code == 422
    assert queued == []


def test_create_scan_needs_an_existing_project(client, queued):
    response = client.post(f"/api/v1/projects/{uuid.uuid4()}/scans", json=_npm())
    assert response.status_code == 404
    assert queued == []


def test_create_scan_queues_and_reuses_the_snapshot_of_a_named_source(
    client, engine, project_id, queued
):
    first = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm())
    second = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm())
    assert first.status_code == second.status_code == 202
    assert first.json()["status"] == "queued"
    assert first.json()["snapshot_id"] == second.json()["snapshot_id"]
    assert queued == [first.json()["scan_id"], second.json()["scan_id"]]
    with Session(engine) as session:
        snapshot = session.scalars(select(SourceSnapshot)).one()
        assert (snapshot.status, snapshot.source_coordinate) == ("validating", "npm:demo@1.0.0")
        assert snapshot.object_key == f"snapshots/{snapshot.id}.tgz"


def test_npm_scan_end_to_end_through_the_api(client, engine, project_id, queued):
    archive = make_archive({"package.json": PACKAGE_JSON, "app.py": PYTHON_SOURCE}, "package")
    registry = fake_registry("demo", "1.0.0", archive)
    storage = FakeStorage()
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()["scan_id"]

    assert _run(engine, scan_id, registry, storage) == "completed"
    assert registry.fetched == [
        "https://registry.npmjs.org/demo/1.0.0",
        "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
    ]

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "completed"
    assert scan["project_id"] == project_id
    assert scan["profile"] == "command-injection-v0.1"
    assert scan["snapshot"]["sha256"] == hashlib.sha256(archive).hexdigest()
    assert scan["snapshot"]["provenance_kind"] == "publisher_verified"
    assert [(r["tool"], r["status"]) for r in scan["tool_runs"]] == [
        ("codeql", "completed"),
        ("semgrep", "completed"),
    ]
    assert sum(scan["unit_counts"].values()) == 1

    units = client.get(f"/api/v1/scans/{scan_id}/units").json()
    assert units["total"] == 1
    unit = units["items"][0]
    assert (unit["path"], unit["argument_role"]) == ("app.py", "shell_command")
    assert sorted(unit["tools"]) == ["codeql", "semgrep"]
    detail = client.get(f"/api/v1/scans/{scan_id}/units/{unit['id']}").json()
    assert detail["unit_key"] == unit["unit_key"]
    assert detail["policy_sha256"] and detail["reason"]
    assert {f["rule_id"] for f in detail["findings"]} == {
        "dangerous-system-call",
        "py/command-line-injection",
    }
    assert {f["raw_id"] for f in detail["findings"]} == {"semgrep:0:0", "codeql:0:0"}

    # A second scan of the same coordinate reuses the stored bytes without downloading.
    again = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()
    offline = fake_registry("demo", "1.0.0", b"unused")
    assert _run(engine, again["scan_id"], offline, storage) == "completed"
    assert offline.fetched == []
    assert (
        client.get(f"/api/v1/scans/{again['scan_id']}/units").json()["items"][0]["unit_key"]
        == (unit["unit_key"])
    )


def test_github_scan_checks_the_archive_root(client, engine, project_id, queued):
    body = {"source": {"kind": "github", "owner": "o", "repo": "r", "commit": COMMIT}}
    good = make_archive({"app.py": PYTHON_SOURCE}, f"r-{COMMIT}")
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=body).json()["scan_id"]
    assert _run(engine, scan_id, lambda url, limit: good) == "completed"
    snapshot = client.get(f"/api/v1/scans/{scan_id}").json()["snapshot"]
    assert (snapshot["provenance_kind"], snapshot["source_coordinate"]) == (
        "tofu",
        f"github:o/r@{COMMIT}",
    )

    other = {"source": {"kind": "github", "owner": "o", "repo": "r", "commit": "a" * 40}}
    wrong_root = make_archive({"app.py": PYTHON_SOURCE}, "elsewhere")
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=other).json()["scan_id"]
    assert _run(engine, scan_id, lambda url, limit: wrong_root) == "failed"
    assert (
        "does not match the requested commit"
        in (client.get(f"/api/v1/scans/{scan_id}").json()["error_message"])
    )


def test_failed_acquisition_fails_the_scan_and_can_be_retried(client, engine, project_id, queued):
    archive = make_archive({"package.json": PACKAGE_JSON, "app.py": PYTHON_SOURCE}, "package")
    tampered = fake_registry("demo", "1.0.0", archive, integrity="sha512-AAAA")
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()["scan_id"]
    assert _run(engine, scan_id, tampered) == "failed"

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "failed" and "integrity" in scan["error_message"]
    assert scan["snapshot"]["status"] == "failed"
    assert scan["tool_runs"] == []

    retry = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()
    assert retry["snapshot_id"] == scan["snapshot"]["id"]
    assert _run(engine, retry["scan_id"], fake_registry("demo", "1.0.0", archive)) == "completed"


def test_npm_package_json_must_name_the_requested_version(client, engine, project_id, queued):
    archive = make_archive(
        {"package.json": json.dumps({"name": "demo", "version": "9.9.9"}), "app.py": "x = 1\n"},
        "package",
    )
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()["scan_id"]
    assert _run(engine, scan_id, fake_registry("demo", "1.0.0", archive)) == "failed"
    assert (
        "Package identity mismatch"
        in client.get(f"/api/v1/scans/{scan_id}").json()["error_message"]
    )


def _add_unit(session: Session, scan: Scan, key: str, priority: str) -> uuid.UUID:
    unit = LocationUnit(
        scan_id=scan.id,
        unit_key=key,
        path="extra.py",
        mapping_status="unmapped",
        reconciler_version=scan.reconciler_version or "",
        locator_version="sink-locator-v0",
    )
    session.add(unit)
    session.flush()
    session.add(
        UnitAssessment(
            unit_id=unit.id,
            evidence={"tools": ["semgrep"]},
            priority=priority,
            decision_id="D00",
            matched_conditions=[],
            reason="r",
            policy_id="p",
            policy_version=scan.policy_version or "",
            policy_sha256="a" * 64,
            spec_sha256="b" * 64,
            rule_claims_version="c",
            rule_claims_sha256="d" * 64,
        )
    )
    return unit.id


def test_units_follow_queue_order_and_filters(client, engine, project_id, queued):
    archive = make_archive({"package.json": PACKAGE_JSON, "app.py": PYTHON_SOURCE}, "package")
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()["scan_id"]
    assert _run(engine, scan_id, fake_registry("demo", "1.0.0", archive)) == "completed"
    with Session(engine) as session:
        scan = session.get_one(Scan, uuid.UUID(scan_id))
        _add_unit(session, scan, "k-p4", "P4")
        _add_unit(session, scan, "k-u", "U")
        _add_unit(session, scan, "a-p4", "P4")
        session.commit()

    items = client.get(f"/api/v1/scans/{scan_id}/units").json()["items"]
    order = [(item["priority"], item["unit_key"]) for item in items]
    real = next(item for item in items if item["path"] == "app.py")
    expected_first = [(real["priority"], real["unit_key"])] if real["priority"] < "U" else []
    assert order[: len(expected_first)] == expected_first
    assert [o for o in order if o[1] in {"k-u", "a-p4", "k-p4"}] == [
        ("U", "k-u"),
        ("P4", "a-p4"),
        ("P4", "k-p4"),
    ]
    tiers = ["P1", "P2", "U", "P3", "P4"]
    assert [tiers.index(p) for p, _ in order] == sorted(tiers.index(p) for p, _ in order)

    p4 = client.get(f"/api/v1/scans/{scan_id}/units", params={"tier": "P4"}).json()
    assert [item["unit_key"] for item in p4["items"]][:2] == ["a-p4", "k-p4"]
    codeql = client.get(f"/api/v1/scans/{scan_id}/units", params={"tool": "codeql"}).json()
    assert [item["path"] for item in codeql["items"]] == ["app.py"]
    page = client.get(f"/api/v1/scans/{scan_id}/units", params={"limit": 2, "offset": 2}).json()
    assert (page["total"], len(page["items"])) == (4, 2)
    assert client.get(f"/api/v1/scans/{scan_id}/units", params={"tier": "PX"}).status_code == 422


def test_unknown_scans_and_units_answer_404(client, engine, project_id, queued):
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}").status_code == 404
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}/units").status_code == 404
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()["scan_id"]
    response = client.get(f"/api/v1/scans/{scan_id}/units/{uuid.uuid4()}")
    assert response.status_code == 404
    assert response.json() == {"detail": "Location unit not found in this scan"}


def test_scan_requests_use_the_configured_celery_app_from_any_thread():
    # FastAPI runs sync endpoints in worker threads; Celery's current app is per thread.
    from threading import Thread

    from app.workers.celery_app import celery_app

    seen: list[str] = []
    thread = Thread(target=lambda: seen.append(scan_task.run_scan.app.main or ""))
    thread.start()
    thread.join()
    assert seen == [celery_app.main]
