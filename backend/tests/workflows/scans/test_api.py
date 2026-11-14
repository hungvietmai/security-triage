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
    PATH_SOURCE,
    PYTHON_SOURCE,
    FakeStorage,
    fake_evidence_pipeline,
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


def _run(
    engine: Engine,
    scan_id: str,
    fetch: Any,
    storage: FakeStorage | None = None,
    pipeline: Any = None,
) -> str:
    return scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage or FakeStorage(),  # type: ignore[arg-type]
        run_pipeline_fn=pipeline or fake_pipeline(),
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
    assert detail["shell_state"] == "absent"
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


def test_path_traversal_scan_ranks_baseline_alerts_by_safety_evidence(
    client, engine, project_id, queued
):
    body = {
        "source": {"kind": "github", "owner": "o", "repo": "r", "commit": COMMIT},
        "profile": "path-traversal-v0.2",
    }
    archive = make_archive({"app.py": PATH_SOURCE}, f"r-{COMMIT}")
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=body).json()["scan_id"]
    assert (
        _run(engine, scan_id, lambda url, limit: archive, pipeline=fake_evidence_pipeline())
        == "completed"
    )

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["profile"] == "path-traversal-v0.2"
    assert scan["policy_version"] == "0.2"
    assert [(r["tool"], r["status"]) for r in scan["tool_runs"]] == [("codeql", "completed")]
    assert {tier: n for tier, n in scan["unit_counts"].items() if n} == {"P1": 1, "P4": 1}
    assert scan["disposition_counts"] == {"review": 1, "filtered": 1}

    # Nothing is deleted: the alert the evidence removed is still listed, last.
    items = client.get(f"/api/v1/scans/{scan_id}/units").json()["items"]
    assert [(i["start_line"], i["priority"], i["decision_id"]) for i in items] == [
        (2, "P1", "EV_KEPT_NO_PROOF"),
        (3, "P4", "EV_HIDDEN_BY_EVIDENCE"),
    ]
    kept = client.get(f"/api/v1/scans/{scan_id}/units/{items[0]['id']}").json()
    assert kept["predicate_values"] == {"baseline_alert": True, "retained_by_evidence_query": True}
    assert {f["rule_id"] for f in kept["findings"]} == {"st/cwe-22/none", "st/cwe-22/all"}
    hidden = client.get(f"/api/v1/scans/{scan_id}/units/{items[1]['id']}").json()
    assert hidden["matched_conditions"] == ["baseline_alert", "removed_by_safety_evidence"]
    assert [f["rule_id"] for f in hidden["findings"]] == ["st/cwe-22/none"]
    assert hidden["policy_id"] == "cwe22-safety-evidence" and hidden["policy_sha256"]
    # The hidden alert is filtered on evidence and can be reopened with its original alert.
    assert (hidden["disposition"], hidden["filter_rule"]) == (
        "filtered",
        "G1_CODEQL_SAFETY_EVIDENCE",
    )
    assert hidden["adjudication"]["evidence"][0]["refuted_raw_ids"] == ["codeql:0:1"]
    assert kept["disposition"] == "review" and kept["adjudication"]["rule"] is None
    filtered = client.get(
        f"/api/v1/scans/{scan_id}/units", params={"disposition": "filtered"}
    ).json()
    assert [i["start_line"] for i in filtered["items"]] == [3]
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert (report["stages"]["main_list"], report["stages"]["filtered"]) == (1, 1)


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


V02 = {"profile": "command-injection-v0.2"}
# Semgrep's audit rule and Bandit report the call; CodeQL's flow is refuted by evidence.
REFUTED: dict[str, Any] = {"semgrep_rule": "subprocess-shell-true", "refuted": True}


def _scan_v02(client, engine, project_id, **pipeline: Any) -> str:
    archive = make_archive({"package.json": PACKAGE_JSON, "app.py": PYTHON_SOURCE}, "package")
    body = {**_npm(), **V02}
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=body).json()["scan_id"]
    registry = fake_registry("demo", "1.0.0", archive)
    assert _run(engine, scan_id, registry, pipeline=fake_pipeline(**pipeline)) == "completed"
    return str(scan_id)


def test_a_refuted_flow_leaves_the_main_list_but_stays_readable_with_its_reason(
    client, engine, project_id, queued
):
    # Semgrep's audit rule and Bandit report the call; CodeQL reports a flow that the safety
    # evidence query no longer reports.
    scan_id = _scan_v02(client, engine, project_id, **REFUTED)

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["disposition_counts"] == {"review": 0, "filtered": 1}
    assert ("codeql-evidence", "completed") in [(r["tool"], r["status"]) for r in scan["tool_runs"]]

    units = f"/api/v1/scans/{scan_id}/units"
    assert client.get(units, params={"disposition": "review"}).json()["total"] == 0
    (unit,) = client.get(units, params={"disposition": "filtered"}).json()["items"]
    assert (unit["disposition"], unit["filter_rule"]) == ("filtered", "G1_CODEQL_SAFETY_EVIDENCE")
    # The unit is still in the unfiltered listing, with every original alert.
    assert client.get(units).json()["total"] == 1
    detail = client.get(f"{units}/{unit['id']}").json()
    assert {f["raw_id"] for f in detail["findings"]} == {"semgrep:0:0", "codeql:0:0", "bandit:0:0"}
    assert detail["adjudication"]["evidence"][0]["refuted_raw_ids"] == ["codeql:0:0"]
    assert "st/cwe-78/all" in detail["adjudication"]["reason"]
    assert detail["candidate"]["tools"] == ["bandit", "codeql", "semgrep"]
    assert client.get(units, params={"disposition": "gone"}).status_code == 422


def test_report_counts_detection_merging_and_filtering(client, engine, project_id, queued):
    scan_id = _scan_v02(client, engine, project_id, **REFUTED)
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["profile"] == "command-injection-v0.2"
    assert len(report["profile_sha256"]) == 64
    assert report["raw_alerts"] == {"bandit": 1, "codeql": 1, "semgrep": 1}
    # Three alerts of one call: one unit, one candidate, filtered on evidence.
    assert report["stages"] == {
        "raw_alerts": 3,
        "units": 1,
        "candidates": 1,
        "main_list": 0,
        "filtered": 1,
        "demoted": 0,
    }
    assert report["filtered_by_rule"] == {"G1_CODEQL_SAFETY_EVIDENCE": 1}
    assert report["sources"]["codeql"] == {"candidates": 1, "only": 0}
    (candidate,) = report["candidates"]
    assert (candidate["basis"], candidate["raw_alerts"]) == ("same_call_site", 3)
    assert candidate["disposition"] == "filtered" and candidate["filter_rule"]
    assert report["steps"]["python"]["codeql-evidence"]["status"] == "completed"
    assert report["snapshot"]["sha256"]


@pytest.mark.parametrize(
    ("pipeline", "kept_because"),
    [
        # The evidence query still reports the flow.
        ({"semgrep_rule": "subprocess-shell-true"}, "evidence_query_still_reports_flow"),
        # Semgrep's taint rule claims the flow independently of CodeQL.
        ({"refuted": True}, "independent_flow_claim"),
    ],
)
def test_report_keeps_candidates_without_refuting_evidence(
    client, engine, project_id, queued, pipeline, kept_because
):
    scan_id = _scan_v02(client, engine, project_id, **pipeline)
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert (report["stages"]["main_list"], report["stages"]["filtered"]) == (1, 0)
    (unit,) = client.get(f"/api/v1/scans/{scan_id}/units").json()["items"]
    detail = client.get(f"/api/v1/scans/{scan_id}/units/{unit['id']}").json()
    assert detail["adjudication"]["kept_because"] == [kept_because]
    assert detail["disposition"] == "review"


def test_report_of_a_scan_only_one_tool_reported_keeps_that_candidate(
    client, engine, project_id, queued
):
    # The v0.1 profile's fake run: Semgrep and CodeQL at one call, no evidence step.
    archive = make_archive({"package.json": PACKAGE_JSON, "app.py": PYTHON_SOURCE}, "package")
    scan_id = client.post(f"/api/v1/projects/{project_id}/scans", json=_npm()).json()["scan_id"]
    assert _run(engine, scan_id, fake_registry("demo", "1.0.0", archive)) == "completed"
    with Session(engine) as session:
        scan = session.get_one(Scan, uuid.UUID(scan_id))
        _add_unit(session, scan, "legacy-unit", "P3")
        session.commit()
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["stages"]["candidates"] == 2 and report["stages"]["filtered"] == 0
    # A unit written before candidates existed, reported by Semgrep alone, is its own candidate.
    legacy = next(c for c in report["candidates"] if c["candidate_key"] == "legacy-unit")
    assert (legacy["tools"], legacy["disposition"], legacy["basis"]) == (
        ["semgrep"],
        "review",
        "single_unit",
    )
    assert report["sources"]["semgrep"] == {"candidates": 2, "only": 1}
    assert report["stages"]["demoted"] >= 1


def test_sarif_export_keeps_every_alert_and_suppresses_filtered_ones(
    client, engine, project_id, queued
):
    scan_id = _scan_v02(client, engine, project_id, **REFUTED)
    response = client.get(f"/api/v1/scans/{scan_id}/report.sarif")
    assert response.status_code == 200
    sarif = response.json()
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sorted(run["tool"]["driver"]["name"] for run in sarif["runs"]) == [
        "bandit",
        "codeql",
        "semgrep",
    ]
    results = [result for run in sarif["runs"] for result in run["results"]]
    assert len(results) == 3
    for result in results:
        triage = result["properties"]["securityTriage"]
        assert (triage["disposition"], triage["filterRule"]) == (
            "filtered",
            "G1_CODEQL_SAFETY_EVIDENCE",
        )
        assert result["suppressions"][0]["kind"] == "external"
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "app.py"
        assert "ruleIndex" not in result and result["ruleId"]
    assert len({r["properties"]["securityTriage"]["candidateKey"] for r in results}) == 1

    other = client.post("/api/v1/projects", json={"name": "Kept"}).json()["id"]
    kept_id = _scan_v02(client, engine, other)
    kept = client.get(f"/api/v1/scans/{kept_id}/report.sarif").json()
    assert all("suppressions" not in r for run in kept["runs"] for r in run["results"])
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}/report").status_code == 404


@pytest.mark.parametrize(
    ("pipeline", "rules"),
    [
        # Semgrep's dead-branch evidence alone: no tool claims a flow at the call.
        (
            {"semgrep_rule": "subprocess-shell-true", "codeql_alert": False, "dead_branch": True},
            ["G3_SEMGREP_DEAD_BRANCH"],
        ),
        # CodeQL's flow runs through the dead branch and its own evidence query agrees.
        (
            {"semgrep_rule": "subprocess-shell-true", "dead_branch": True, "refuted": True},
            ["G3_SEMGREP_DEAD_BRANCH", "G1_CODEQL_SAFETY_EVIDENCE"],
        ),
    ],
)
def test_semgrep_dead_branch_evidence_filters_and_is_reported_per_rule(
    client, engine, project_id, queued, pipeline, rules
):
    scan_id = _scan_v02(client, engine, project_id, **pipeline)
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert ("semgrep-evidence", "completed") in [
        (r["tool"], r["status"]) for r in scan["tool_runs"]
    ]
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    (candidate,) = report["candidates"]
    assert (candidate["disposition"], candidate["filter_rule"]) == ("filtered", rules[0])
    assert candidate["filter_rules"] == rules
    # One filtered candidate, counted once under every rule that filtered it.
    assert report["stages"]["filtered"] == 1
    assert report["filtered_by_rule"] == dict.fromkeys(rules, 1)
    assert report["steps"]["python"]["semgrep-evidence"]["status"] == "completed"
    (unit,) = client.get(f"/api/v1/scans/{scan_id}/units").json()["items"]
    detail = client.get(f"/api/v1/scans/{scan_id}/units/{unit['id']}").json()
    assert [item["rule"] for item in detail["adjudication"]["evidence"]] == rules
    assert detail["adjudication"]["evidence"][0]["tool"] == "semgrep"


def test_codeql_evidence_that_still_reports_the_flow_blocks_the_dead_branch_rule(
    client, engine, project_id, queued
):
    scan_id = _scan_v02(
        client, engine, project_id, semgrep_rule="subprocess-shell-true", dead_branch=True
    )
    (unit,) = client.get(f"/api/v1/scans/{scan_id}/units").json()["items"]
    detail = client.get(f"/api/v1/scans/{scan_id}/units/{unit['id']}").json()
    assert detail["disposition"] == "review"
    assert detail["adjudication"]["kept_because"] == ["evidence_query_still_reports_flow"]
