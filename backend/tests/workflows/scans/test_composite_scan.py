"""A composite (multi-CWE) scan through the worker, the database, the API and the exports.

Scanners are scripted and the source is synthetic test data (see test_families). Everything
after the scanners is real: routing, each member's assessment, persistence, the API, the
before/after report and the SARIF export. Scans with a single profile are read through the
same API to show that they answer as before, with their one family derived from the profile.
"""

import hashlib
import json
import uuid
from collections import Counter
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.features.findings.models import Finding
from app.features.projects.models import Project
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.workflows.scans import families, service
from app.workflows.scans import task as scan_task
from app.workflows.scans.families import COMPOSITION_VERSION
from tests.workflows.scans.fakes import (
    PATH_SOURCE,
    PYTHON_SOURCE,
    FakeStorage,
    fake_evidence_pipeline,
    fake_pipeline,
)
from tests.workflows.scans.test_families import COMMAND, PASS, PATH, SOURCE, Tools
from tests.workflows.scans.test_legacy_golden import fixed_archive

PROFILE = "multi-cwe-v0.1"
BOTH = ["command-injection", "path-traversal"]


def _never_invoked(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("No external process runs in these tests")


def _scan(engine: Engine, storage: FakeStorage, files: dict[str, str], profile: str) -> str:
    archive = fixed_archive(files)
    storage.objects[("sources", "snapshots/s.tgz")] = archive
    with Session(engine) as session:
        project = Project(name="Composite")
        session.add(project)
        session.flush()
        snapshot = SourceSnapshot(
            project_id=project.id,
            bucket="sources",
            object_key="snapshots/s.tgz",
            sha256=hashlib.sha256(archive).hexdigest(),
            status="ready",
        )
        session.add(snapshot)
        session.flush()
        scan = Scan(snapshot_id=snapshot.id, config={"profile": profile})
        session.add(scan)
        session.commit()
        return str(scan.id)


def _composite(engine: Engine, tools: Tools, **options: Any) -> tuple[str, str, FakeStorage]:
    storage = FakeStorage()
    scan_id = _scan(engine, storage, {"app.py": SOURCE}, PROFILE)
    status = scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=tools.pipeline,
        invoke_fn=_never_invoked,
        analyze_fn=tools.analyze,
        **options,
    )
    return scan_id, status, storage


def _single(engine: Engine, files: dict[str, str], profile: str, pipeline: Any) -> str:
    storage = FakeStorage()
    scan_id = _scan(engine, storage, files, profile)
    scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=pipeline,
    )
    return scan_id


def _detail(client: TestClient, scan_id: str, unit: dict[str, Any]) -> dict[str, Any]:
    response = client.get(f"/api/v1/scans/{scan_id}/units/{unit['id']}")
    assert response.status_code == 200, response.text
    return dict(response.json())


def _units(client: TestClient, scan_id: str, **params: Any) -> list[dict[str, Any]]:
    response = client.get(f"/api/v1/scans/{scan_id}/units", params={"limit": 100, **params})
    assert response.status_code == 200, response.text
    return list(response.json()["items"])


def test_the_api_accepts_the_composite_profile(client, monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(scan_task.run_scan, "delay", sent.append)
    project = client.post("/api/v1/projects", json={"name": "Multi"}).json()["id"]
    body = {
        "source": {"kind": "npm", "package": "demo", "version": "1.0.0"},
        "profile": PROFILE,
    }
    response = client.post(f"/api/v1/projects/{project}/scans", json=body)
    assert response.status_code == 202
    scan = client.get(f"/api/v1/scans/{response.json()['scan_id']}").json()
    # Queued: the profile is on record, and no family exists before the scan has run.
    assert (scan["profile"], scan["status"], scan["families"]) == (PROFILE, "queued", [])
    assert sent == [response.json()["scan_id"]]


def test_a_composite_scan_stores_both_families_with_their_provenance(engine):
    scan_id, status, storage = _composite(engine, Tools())
    assert status == "completed"

    settings = get_settings()
    command: Any = scan_task.load_scan_profile(settings, COMMAND)
    path: Any = scan_task.load_scan_profile(settings, PATH)
    composite: Any = scan_task.load_scan_profile(settings, PROFILE)
    with Session(engine) as session:
        scan = session.get_one(Scan, uuid.UUID(scan_id))
        assert (scan.status, scan.error_message) == ("completed", None)
        assert (scan.reconciler_version, scan.policy_version) == (
            COMPOSITION_VERSION,
            COMPOSITION_VERSION,
        )
        # The scan names its own manifest and every member's manifest by hash.
        assert scan.config["profile_id"] == PROFILE
        assert scan.config["profile_sha256"] == composite.manifest_sha256
        assert scan.config["composition"] == {
            "version": COMPOSITION_VERSION,
            "specification_sha256": composite.specification_sha256,
            "members": [
                {
                    "family": "command-injection",
                    "profile_id": COMMAND,
                    "profile_sha256": command.manifest_sha256,
                },
                {
                    "family": "path-traversal",
                    "profile_id": PATH,
                    "profile_sha256": path.manifest_sha256,
                },
            ],
        }
        recorded = scan.config["families"]["python"]
        assert [(f["family"], f["status"], f["units"], f["held_units"]) for f in recorded] == [
            ("command-injection", "completed", 2, 0),
            ("path-traversal", "completed", 4, 0),
        ]
        assert recorded[0]["unit_version"] == "reconcile-v0.1"
        assert recorded[1]["unit_version"] == "safety-evidence-units-v1"
        assert recorded[1]["evidence_steps"] == {PASS: "completed"}
        steps = scan.config["steps"]["python"]
        assert steps["codeql-create"]["serves"] == BOTH
        assert (steps[PASS]["kind"], steps[PASS]["seconds"]) == ("detection+evidence", 7.25)

        runs = {
            run.tool: run
            for run in session.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id))
        }
        assert sorted(runs) == [
            "bandit",
            "codeql",
            "codeql-evidence",
            PASS,
            "semgrep",
            "semgrep-evidence",
        ]
        # The pass on the shared database is its own run, with its own SARIF and version.
        assert runs[PASS].result_key == f"scans/{scan_id}/python/{PASS}.sarif"
        assert (runs[PASS].tool_version, runs[PASS].status) == ("2.27.1", "completed")
        assert runs[PASS].config["serves"] == ["path-traversal"]

        findings = session.scalars(
            select(Finding).where(Finding.tool_run_id.in_([run.id for run in runs.values()]))
        ).all()
        by_run = Counter(
            next(tool for tool, run in runs.items() if run.id == finding.tool_run_id)
            for finding in findings
        )
        assert by_run == {"semgrep": 2, "bandit": 2, "codeql": 2, PASS: 7}
        for finding in findings:
            classification = finding.evidence["classification"]
            # The tool's own labels stay as written; the classification sits next to them.
            assert finding.cwe_ids == classification["reported_cwes"]
            assert finding.classification_source == "pass_provenance"
            assert finding.evidence["raw_id"] == classification["raw_id"]
        labels = {tuple(finding.cwe_ids) for finding in findings}
        assert labels == {("CWE-78",), ("cwe-78",), ("cwe-078", "cwe-088"), ("cwe-022",)}
        mapped = {
            (
                f.evidence["classification"]["tool_pass"],
                tuple(f.evidence["classification"]["mapped_cwes"]),
            )
            for f in findings
        }
        assert mapped == {
            ("semgrep", ("CWE-78",)),
            ("bandit", ("CWE-78",)),
            ("codeql", ("CWE-78", "CWE-88")),
            (PASS, ("CWE-22",)),
        }

        units = session.scalars(select(LocationUnit).where(LocationUnit.scan_id == scan.id)).all()
        assert Counter(unit.analysis_family for unit in units) == {
            "command-injection": 2,
            "path-traversal": 4,
        }
        versions = {(unit.analysis_family, unit.reconciler_version) for unit in units}
        assert versions == {
            ("command-injection", "reconcile-v0.1"),
            ("path-traversal", "safety-evidence-units-v1"),
        }
        # Every finding is linked to exactly one unit, and to a unit of its own family.
        links = session.execute(
            select(UnitFinding.finding_id, LocationUnit.analysis_family).join(
                LocationUnit, LocationUnit.id == UnitFinding.unit_id
            )
        ).all()
        assert sorted(finding_id for finding_id, _ in links) == sorted(f.id for f in findings)
        family_of = {f.id: f.evidence["classification"]["analysis_family"] for f in findings}
        assert all(family_of[finding_id] == family for finding_id, family in links)
        # Each family keeps its own pinned policy on its assessments.
        policies = set(
            session.execute(
                select(
                    LocationUnit.analysis_family,
                    UnitAssessment.policy_id,
                    UnitAssessment.policy_sha256,
                ).join(UnitAssessment, UnitAssessment.unit_id == LocationUnit.id)
            ).all()
        )
        assert policies == {
            ("command-injection", "command-injection-priority", command.policy_sha256),
            ("path-traversal", "cwe22-safety-evidence", path.policy_sha256),
        }
        for name in ("run.json", "findings.json", "classification.json", "units.json"):
            artifact = scan.artifacts[f"python/{name}"]
            stored = storage.objects[(settings.s3_bucket, artifact["key"])]
            assert hashlib.sha256(stored).hexdigest() == artifact["sha256"]
        # Each member's own files stay in the work directory, so the stored record must
        # itself name the query files each member's CodeQL run was checked against.
        record = json.loads(
            storage.objects[(settings.s3_bucket, scan.artifacts["python/run.json"]["key"])]
        )
        assert {m["family"]: m["codeql_query_files"] for m in record["members"]} == {
            "command-injection": command.configs["python"]["codeql_query_sha256"],
            "path-traversal": path.configs["python"]["codeql_query_sha256"],
        }
        assert not [name for name in scan.artifacts if "/families/" in name]


def test_a_composite_scan_is_read_by_family_through_the_api(client, engine):
    scan_id, _, _ = _composite(engine, Tools())

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert (scan["status"], scan["profile"]) == ("completed", PROFILE)
    assert scan["disposition_counts"] == {"review": 5, "filtered": 1}
    command, path = scan["families"]
    assert command == {
        "family": "command-injection",
        "cwe": "CWE-78",
        "label": "Command injection",
        "profile_id": COMMAND,
        "profile_sha256": command["profile_sha256"],
        "runs": [
            {
                "language": "python",
                "status": "completed",
                "error": None,
                "raw_findings": 6,
                "evidence_steps": {
                    "semgrep-evidence": "completed",
                    "codeql-evidence": "completed",
                },
            }
        ],
        "units": 2,
        "review": 2,
        "filtered": 0,
        "held": 0,
    }
    assert (path["family"], path["cwe"], path["profile_id"]) == ("path-traversal", "CWE-22", PATH)
    assert (path["units"], path["review"], path["filtered"], path["held"]) == (4, 3, 1, 0)
    assert path["runs"][0]["evidence_steps"] == {PASS: "completed"}

    everything = _units(client, scan_id)
    assert Counter(unit["analysis_family"] for unit in everything) == {
        "command-injection": 2,
        "path-traversal": 4,
    }
    by_family = {name: _units(client, scan_id, family=name) for name in BOTH}
    assert [len(by_family[name]) for name in BOTH] == [2, 4]
    assert {unit["cwe"] for unit in by_family["command-injection"]} == {"CWE-78"}
    assert {unit["cwe"] for unit in by_family["path-traversal"]} == {"CWE-22"}
    assert _units(client, scan_id, family="unassigned") == []
    # Filters combine: the filtered path unit, and no filtered command unit.
    (hidden,) = _units(client, scan_id, family="path-traversal", disposition="filtered")
    assert (hidden["evidence_state"], hidden["filter_rule"], hidden["priority"]) == (
        "refuted",
        "G1_CODEQL_SAFETY_EVIDENCE",
        "P4",
    )
    assert _units(client, scan_id, family="command-injection", disposition="filtered") == []
    # The scan's status, the evidence state and the filter decision are three fields.
    kept = _units(client, scan_id, family="path-traversal", disposition="review")
    assert {(u["evidence_state"], tuple(u["kept_because"])) for u in kept} == {
        ("not_refuted", ("evidence_query_still_reports_flow",))
    }
    # A tool filter also finds alerts of that tool's pass on the shared database.
    assert len(_units(client, scan_id, tool="codeql")) == 6
    assert len(_units(client, scan_id, tool="bandit")) == 2
    assert client.get(f"/api/v1/scans/{scan_id}/units?family=sql-injection").status_code == 422

    detail = client.get(f"/api/v1/scans/{scan_id}/units/{hidden['id']}").json()
    assert (detail["analysis_family"], detail["cwe"], detail["disposition"]) == (
        "path-traversal",
        "CWE-22",
        "filtered",
    )
    assert detail["adjudication"]["evidence"][0]["evidence_rule"] == "st/cwe-22/all"
    (finding,) = detail["findings"]
    assert (finding["tool"], finding["tool_pass"], finding["rule_id"]) == (
        "codeql",
        PASS,
        "st/cwe-22/none",
    )
    assert (finding["cwe_ids"], finding["mapped_cwes"]) == (["cwe-022"], ["CWE-22"])
    assert (finding["analysis_family"], finding["family_status"], finding["family_basis"]) == (
        "path-traversal",
        "resolved",
        "pass_provenance",
    )
    command_unit = by_family["command-injection"][0]
    detail = client.get(f"/api/v1/scans/{scan_id}/units/{command_unit['id']}").json()
    assert detail["policy_id"] == "command-injection-priority"
    assert {f["analysis_family"] for f in detail["findings"]} == {"command-injection"}
    assert {tuple(f["mapped_cwes"]) for f in detail["findings"]} == {
        ("CWE-78",),
        ("CWE-78", "CWE-88"),
    }


def test_the_report_and_the_sarif_export_keep_every_alert_of_both_families(client, engine):
    scan_id, _, _ = _composite(engine, Tools())

    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["profile"] == PROFILE
    assert report["composition"]["version"] == COMPOSITION_VERSION
    assert [m["profile_id"] for m in report["composition"]["members"]] == [COMMAND, PATH]
    assert report["stages"] == {
        "raw_alerts": 13,
        # The path member stores its evidence query's three results with their units; they
        # are counted apart, so "before" is the ten alerts the detection queries reported.
        "evidence_results": 3,
        "detection_alerts": 10,
        "unranked_alerts": 0,
        "units": 6,
        "candidates": 6,
        "main_list": 5,
        "filtered": 1,
        "demoted": 0,
    }
    assert report["raw_alerts"] == {"semgrep": 2, "bandit": 2, "codeql": 2, PASS: 7}
    command, path = report["families"]
    assert (command["family"], command["cwe"], command["raw_alerts"]) == (
        "command-injection",
        "CWE-78",
        6,
    )
    assert (command["units"], command["candidates"], command["main_list"]) == (2, 2, 2)
    assert (command["filtered"], command["filtered_by_rule"]) == (0, {})
    assert (path["raw_alerts"], path["units"], path["main_list"], path["filtered"]) == (7, 4, 3, 1)
    assert (command["detection_alerts"], command["evidence_results"]) == (6, 0)
    # Four baseline locations; the three that stay in the main list each carry one evidence result.
    assert (path["detection_alerts"], path["evidence_results"]) == (4, 3)
    assert path["filtered_by_rule"] == {"G1_CODEQL_SAFETY_EVIDENCE": 1}
    assert path["evidence_states"] == {"refuted": 1, "not_refuted": 3}
    assert path["main_list_by_priority"]["P1"] == 3
    # The families' counts add up to the scan's; no candidate is counted in two families.
    for key in (
        "raw_alerts",
        "detection_alerts",
        "evidence_results",
        "units",
        "candidates",
        "main_list",
        "filtered",
    ):
        assert command[key] + path[key] == report["stages"][key]
    assert Counter(c["analysis_family"] for c in report["candidates"]) == {
        "command-injection": 2,
        "path-traversal": 4,
    }

    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    assert sarif["version"] == "2.1.0"
    runs = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
    assert sorted(runs) == ["bandit", "codeql", PASS, "semgrep"]
    assert {name: len(run["results"]) for name, run in runs.items()} == {
        "bandit": 2,
        "codeql": 2,
        PASS: 7,
        "semgrep": 2,
    }
    results = [result for run in sarif["runs"] for result in run["results"]]
    triage = [result["properties"]["securityTriage"] for result in results]
    assert Counter(item["analysisFamily"] for item in triage) == {
        "command-injection": 6,
        "path-traversal": 7,
    }
    for result in runs[PASS]["results"]:
        properties = result["properties"]["securityTriage"]
        assert (properties["cwe"], properties["mappedCwes"], properties["reportedCwes"]) == (
            "CWE-22",
            ["CWE-22"],
            ["cwe-022"],
        )
        assert properties["familyStatus"] == "resolved"
    # Every result is ranked, and an evidence-query result is told from a detection alert.
    assert all(item["ranked"] for item in triage)
    assert Counter(item["resultRole"] for item in triage) == {"detection": 10, "evidence_query": 3}
    assert {
        result["ruleId"]
        for result in results
        if result["properties"]["securityTriage"]["resultRole"] == "evidence_query"
    } == {"st/cwe-22/all"}
    suppressed = [r for r in results if "suppressions" in r]
    # Only the alert the path evidence refuted is suppressed, and it is still exported.
    assert [r["properties"]["securityTriage"]["evidenceState"] for r in suppressed] == ["refuted"]
    assert suppressed[0]["ruleId"] == "st/cwe-22/none"
    assert all(
        r["properties"]["securityTriage"]["disposition"] == "review"
        for r in results
        if r not in suppressed
    )


def test_an_incomplete_single_profile_run_holds_its_alerts_for_review(client, engine):
    # path-traversal-v0.2 alone ranks nothing when its run is partial. Its alerts are held as
    # units at priority U, as a composite scan holds them, so they reach the review list.
    scan_id = _single(engine, {"app.py": PATH_SOURCE}, PATH, fake_evidence_pipeline("partial"))
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "partial"
    assert scan["unit_counts"] == {"P1": 0, "P2": 0, "U": 2, "P3": 0, "P4": 0}
    assert scan["disposition_counts"] == {"review": 2, "filtered": 0}
    (family,) = scan["families"]
    assert (family["family"], family["units"], family["held"]) == ("path-traversal", 2, 2)

    units = _units(client, scan_id)
    # A held unit has no located call; its place is the place its alerts were reported at.
    assert [(unit["path"], unit["start_line"]) for unit in units] == [("app.py", None)] * 2
    lines = [
        {finding["start_line"] for finding in _detail(client, scan_id, unit)["findings"]}
        for unit in units
    ]
    assert sorted(lines, key=min) == [{2}, {3}]
    for unit in units:
        assert (unit["priority"], unit["disposition"]) == ("U", "review")
        assert unit["decision_id"] == families.NOT_RANKED_DECISION
        assert (unit["analysis_family"], unit["cwe"]) == ("path-traversal", "CWE-22")
        assert (unit["evidence_state"], unit["kept_because"]) == (
            "unavailable",
            [families.NOT_RANKED],
        )
        assert "chạy dở" in unit["reason"]
    details = [_detail(client, scan_id, unit) for unit in units]
    assert sorted(len(detail["findings"]) for detail in details) == [1, 2]
    assert {detail["reconciler_version"] for detail in details} == {COMPOSITION_VERSION}

    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    stages = report["stages"]
    assert (stages["raw_alerts"], stages["unranked_alerts"], stages["units"]) == (3, 0, 2)
    assert (stages["main_list"], stages["filtered"]) == (2, 0)
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    results = [result for run in sarif["runs"] for result in run["results"]]
    assert len(results) == 3
    for result in results:
        triage = result["properties"]["securityTriage"]
        assert (triage["ranked"], triage["priority"], triage["disposition"]) == (
            True,
            "U",
            "review",
        )
        # The profile ranked nothing, so no one recorded which query a result came from.
        assert triage["resultRole"] == "unknown"
        assert "suppressions" not in result


def test_a_completed_single_profile_run_is_not_held(client, engine):
    scan_id = _single(engine, {"app.py": PATH_SOURCE}, PATH, fake_evidence_pipeline())
    units = _units(client, scan_id)
    assert sorted(unit["decision_id"] for unit in units) == [
        "EV_HIDDEN_BY_EVIDENCE",
        "EV_KEPT_NO_PROOF",
    ]


def test_stored_alerts_without_a_unit_are_counted_and_exported(client, engine, monkeypatch):
    # Rows as they were written before unranked alerts were held: findings in no unit. The
    # report must still count them and the SARIF export must still carry them.
    monkeypatch.setattr(scan_task, "hold_unranked", lambda result, **_: result)
    scan_id = _single(engine, {"app.py": PATH_SOURCE}, PATH, fake_evidence_pipeline("partial"))
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "partial"
    assert _units(client, scan_id) == []

    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["stages"]["raw_alerts"] == 3
    assert report["stages"]["unranked_alerts"] == 3
    assert (report["stages"]["units"], report["stages"]["candidates"]) == (0, 0)
    assert report["families"] == []

    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    results = [result for run in sarif["runs"] for result in run["results"]]
    assert len(results) == 3
    for result in results:
        triage = result["properties"]["securityTriage"]
        assert (triage["ranked"], triage["unitKey"], triage["priority"]) == (False, None, None)
        assert (triage["disposition"], triage["evidenceState"]) == ("review", "unavailable")
        assert (triage["analysisFamily"], triage["cwe"]) == ("path-traversal", "CWE-22")
        assert triage["resultRole"] == "unknown"
        assert "suppressions" not in result
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"


def test_a_single_evidence_profile_counts_its_evidence_results_apart(client, engine):
    scan_id = _single(engine, {"app.py": PATH_SOURCE}, PATH, fake_evidence_pipeline())
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    # Two baseline alerts; the evidence query still reports one of them.
    stages = report["stages"]
    assert (stages["raw_alerts"], stages["detection_alerts"], stages["evidence_results"]) == (
        3,
        2,
        1,
    )
    assert (stages["unranked_alerts"], stages["main_list"], stages["filtered"]) == (0, 1, 1)
    (family,) = report["families"]
    assert (family["raw_alerts"], family["detection_alerts"], family["evidence_results"]) == (
        3,
        2,
        1,
    )
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    roles = Counter(
        result["properties"]["securityTriage"]["resultRole"]
        for run in sarif["runs"]
        for result in run["results"]
    )
    assert roles == {"detection": 2, "evidence_query": 1}


@pytest.mark.parametrize(
    ("tools", "status", "reason_part"),
    [
        (Tools(path_pass="partial"), "partial", "chạy dở"),
        (Tools(path_rule="st/cwe-22/other"), "partial", "Unexpected rule"),
    ],
)
def test_alerts_a_family_could_not_rank_are_held_for_review_and_never_hidden(
    client, engine, tools, status, reason_part
):
    scan_id, result, _ = _composite(engine, tools)
    assert result == status

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == status
    command, path = scan["families"]
    # The other family is untouched by the failure.
    assert (command["units"], command["held"], command["runs"][0]["status"]) == (2, 0, "completed")
    assert (path["units"], path["review"], path["filtered"], path["held"]) == (4, 4, 0, 4)
    held = _units(client, scan_id, family="path-traversal")
    assert len(held) == 4
    for unit in held:
        assert (unit["priority"], unit["disposition"], unit["decision_id"]) == (
            "U",
            "review",
            "F10_FAMILY_NOT_RANKED",
        )
        assert (unit["evidence_state"], unit["kept_because"]) == (
            "unavailable",
            ["family_not_ranked"],
        )
        assert unit["cwe"] == "CWE-22" and reason_part in unit["reason"]
    if tools.path_rule != "st/cwe-22/none":
        assert "python/path-traversal: ValueError" in scan["error_message"]
        assert path["runs"][0]["error"].startswith("ValueError")

    # All seven alerts of the family are in the export, none of them suppressed.
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    (pass_run,) = [run for run in sarif["runs"] if run["tool"]["driver"]["name"] == PASS]
    assert len(pass_run["results"]) == 7
    assert not any("suppressions" in result for result in pass_run["results"])
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["families"][1]["evidence_states"] == {"unavailable": 4}
    assert report["stages"]["raw_alerts"] == 13 and report["stages"]["filtered"] == 0
    with Session(engine) as session:
        versions = set(
            session.scalars(
                select(LocationUnit.reconciler_version).where(
                    LocationUnit.analysis_family == "path-traversal"
                )
            )
        )
        assert versions == {COMPOSITION_VERSION}


def test_a_failed_database_keeps_the_screening_alerts_and_filters_nothing(client, engine):
    scan_id, status, _ = _composite(engine, Tools(database="failed"))
    assert status == "partial"

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    command, path = scan["families"]
    assert (command["runs"][0]["status"], path["runs"][0]["status"]) == ("partial", "failed")
    assert (path["units"], path["runs"][0]["raw_findings"]) == (0, 0)
    assert "No CodeQL database" in scan["error_message"]
    units = _units(client, scan_id)
    assert len(units) == 2
    for unit in units:
        assert (unit["disposition"], unit["evidence_state"], unit["kept_because"]) == (
            "review",
            "unavailable",
            ["run_incomplete"],
        )
    statuses = {run["tool"]: run["status"] for run in scan["tool_runs"]}
    assert (statuses["codeql"], statuses[PASS], statuses["semgrep"]) == (
        "failed",
        "failed",
        "completed",
    )


def test_a_finding_without_a_family_is_stored_as_unassigned(client, engine, monkeypatch):
    unknown = (
        "tmp.rules.custom-audit",
        {"startLine": 3, "startColumn": 11, "endLine": 3, "endColumn": 14},
    )
    real = families.scan_language_families

    def shared_semgrep(language: str, **kwargs: Any) -> Any:
        # Semgrep is declared to serve both families, so its alerts are routed by pinned rule.
        return real(language, **kwargs, pass_members={"semgrep": BOTH})

    monkeypatch.setattr(scan_task, "scan_language_families", shared_semgrep)
    scan_id, status, _ = _composite(engine, Tools(extra_semgrep=(unknown,)))
    assert status == "completed"

    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert [family["family"] for family in scan["families"]] == [*BOTH, "unassigned"]
    unassigned = scan["families"][2]
    assert (unassigned["cwe"], unassigned["profile_id"], unassigned["label"]) == (
        None,
        None,
        "Chưa xác định nhóm",
    )
    assert (unassigned["units"], unassigned["review"], unassigned["held"]) == (1, 1, 1)
    (unit,) = _units(client, scan_id, family="unassigned")
    assert (unit["analysis_family"], unit["cwe"], unit["priority"], unit["disposition"]) == (
        "unassigned",
        None,
        "U",
        "review",
    )
    assert (unit["evidence_state"], unit["kept_because"]) == (
        "not_applicable",
        ["rule_not_claimed"],
    )
    detail = client.get(f"/api/v1/scans/{scan_id}/units/{unit['id']}").json()
    (finding,) = detail["findings"]
    # Nothing was invented for it and nothing it came with was dropped.
    assert (finding["cwe_ids"], finding["mapped_cwes"], finding["analysis_family"]) == (
        ["cwe-078"],
        [],
        None,
    )
    assert (finding["family_status"], finding["unresolved_reason"]) == (
        "unresolved",
        "rule_not_claimed",
    )
    assert len(_units(client, scan_id)) == 7
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["families"][2]["evidence_states"] == {"not_applicable": 1}
    assert sum(family["raw_alerts"] for family in report["families"]) == 14


def test_scans_with_a_single_profile_answer_as_before_with_their_family_derived(client, engine):
    command = _single(
        engine,
        {"app.py": PYTHON_SOURCE},
        "command-injection-v0.2",
        fake_pipeline(semgrep_rule="subprocess-shell-true", refuted=True),
    )
    path = _single(engine, {"app.py": PATH_SOURCE}, PATH, fake_evidence_pipeline())

    with Session(engine) as session:
        # Nothing new is written for a single-profile scan.
        assert set(session.scalars(select(LocationUnit.analysis_family))) == {None}
        assert set(session.scalars(select(Finding.classification_source))) == {None}
        scan = session.get_one(Scan, uuid.UUID(command))
        assert "composition" not in scan.config and "families" not in scan.config
        assert (scan.reconciler_version, scan.policy_version) == ("reconcile-v0.1", "0.2")

    (unit,) = _units(client, command)
    assert (unit["analysis_family"], unit["cwe"]) == ("command-injection", "CWE-78")
    assert (unit["disposition"], unit["evidence_state"], unit["filter_rule"]) == (
        "filtered",
        "refuted",
        "G1_CODEQL_SAFETY_EVIDENCE",
    )
    assert _units(client, command, family="command-injection") == [unit]
    assert _units(client, command, family="path-traversal") == []
    (family,) = client.get(f"/api/v1/scans/{command}").json()["families"]
    assert (family["family"], family["profile_id"], family["runs"]) == (
        "command-injection",
        "command-injection-v0.2",
        [],
    )
    assert (family["units"], family["filtered"], family["held"]) == (1, 1, 0)
    detail = client.get(f"/api/v1/scans/{command}/units/{unit['id']}").json()
    assert {f["mapped_cwes"] for f in detail["findings"]} == {None}
    assert {f["tool_pass"] for f in detail["findings"]} == {None}

    units = _units(client, path)
    assert {(u["analysis_family"], u["cwe"]) for u in units} == {("path-traversal", "CWE-22")}
    assert sorted((u["disposition"], u["evidence_state"]) for u in units) == [
        ("filtered", "refuted"),
        ("review", "not_refuted"),
    ]
    report = client.get(f"/api/v1/scans/{path}/report").json()
    assert report["composition"] is None
    (family_report,) = report["families"]
    assert (family_report["family"], family_report["units"], family_report["filtered"]) == (
        "path-traversal",
        2,
        1,
    )
    sarif = client.get(f"/api/v1/scans/{command}/report.sarif").json()
    properties = [
        result["properties"]["securityTriage"] for run in sarif["runs"] for result in run["results"]
    ]
    assert {item["analysisFamily"] for item in properties} == {"command-injection"}
    assert all("mappedCwes" not in item for item in properties)


def test_rows_written_before_filtering_existed_are_still_readable(client, engine):
    """A unit from before adjudication: no candidate, no adjudication record, no family."""
    with Session(engine) as session:
        project = Project(name="History")
        session.add(project)
        session.flush()
        snapshot = SourceSnapshot(project_id=project.id, bucket="b", object_key="k", status="ready")
        session.add(snapshot)
        session.flush()
        scan = Scan(
            snapshot_id=snapshot.id,
            status="completed",
            config={"profile_id": "command-injection-v0.1"},
            reconciler_version="reconcile-v0.1",
            policy_version="0.1",
        )
        session.add(scan)
        session.flush()
        run = ToolRun(scan_id=scan.id, tool="semgrep", language="python", status="completed")
        session.add(run)
        session.flush()
        finding = Finding(
            tool_run_id=run.id,
            result_index=0,
            rule_id="dangerous-system-call",
            message="m",
            cwe_ids=["CWE-78"],
            evidence={"raw_id": "semgrep:0:0", "raw_rule_id": "x.dangerous-system-call"},
        )
        unit = LocationUnit(
            scan_id=scan.id,
            unit_key="a" * 64,
            path="app.py",
            mapping_status="mapped",
            reconciler_version="reconcile-v0.1",
            locator_version="sink-locator-v0",
        )
        session.add_all([finding, unit])
        session.flush()
        session.add(
            UnitFinding(unit_id=unit.id, finding_id=finding.id, reconciler_version="reconcile-v0.1")
        )
        session.add(
            UnitAssessment(
                unit_id=unit.id,
                evidence={"tools": ["semgrep"], "finding_evidence": []},
                priority="P2",
                decision_id="D30_HIGH",
                matched_conditions=[],
                reason="r",
                policy_id="command-injection-priority",
                policy_version="0.1",
                policy_sha256="a" * 64,
                spec_sha256="b" * 64,
                rule_claims_version="rule-claims-v2",
                rule_claims_sha256="c" * 64,
            )
        )
        session.commit()
        scan_id = str(scan.id)

    (summary,) = _units(client, scan_id)
    assert (summary["analysis_family"], summary["cwe"], summary["disposition"]) == (
        "command-injection",
        "CWE-78",
        "review",
    )
    assert (summary["evidence_state"], summary["kept_because"]) == ("not_assessed", [])
    detail = client.get(f"/api/v1/scans/{scan_id}/units/{summary['id']}").json()
    assert (detail["candidate"], detail["adjudication"]) == (None, None)
    assert detail["findings"][0]["mapped_cwes"] is None
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["candidates"][0]["evidence_state"] == "not_assessed"
    assert report["families"][0]["evidence_states"] == {"not_assessed": 1}
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    assert sarif["runs"][0]["results"][0]["properties"]["securityTriage"]["cwe"] == "CWE-78"


@pytest.mark.parametrize(
    ("disposition", "decision", "adjudication", "state"),
    [
        ("review", "D30_HIGH", None, "not_assessed"),
        ("filtered", "D30_HIGH", {"kept_because": []}, "refuted"),
        ("review", "D30_HIGH", {"kept_because": ["run_incomplete"]}, "unavailable"),
        ("review", "D30_HIGH", {"kept_because": ["evidence_step_failed"]}, "unavailable"),
        ("review", "F10_FAMILY_NOT_RANKED", {"kept_because": ["family_not_ranked"]}, "unavailable"),
        ("review", "D30_HIGH", {"kept_because": ["no_refuting_evidence"]}, "insufficient"),
        (
            "review",
            "D10_LITERAL",
            {"kept_because": ["literal_proof_without_second_source"]},
            "insufficient",
        ),
        # No evidence about the alert exists: its rule has no evidence query, or the evidence
        # pack does not report it. Nothing was compared, so this is not "not refuted".
        (
            "review",
            "D20_STRONG",
            {"kept_because": ["flow_rule_without_evidence_query"]},
            "insufficient",
        ),
        (
            "review",
            "D20_STRONG",
            {"kept_because": ["evidence_baseline_does_not_report_this_alert"]},
            "insufficient",
        ),
        # Missing evidence next to a contradicting claim: the contradiction is what was examined.
        (
            "review",
            "D20_STRONG",
            {"kept_because": ["flow_rule_without_evidence_query", "independent_flow_claim"]},
            "not_refuted",
        ),
        ("review", "D30_HIGH", {"kept_because": ["independent_flow_claim"]}, "not_refuted"),
        (
            "review",
            "D30_HIGH",
            {"kept_because": ["evidence_query_still_reports_flow"]},
            "not_refuted",
        ),
        # Evidence that could not be examined outweighs evidence that was.
        (
            "review",
            "D30_HIGH",
            {"kept_because": ["evidence_step_failed", "independent_flow_claim"]},
            "unavailable",
        ),
        (
            "review",
            "F00_FAMILY_UNRESOLVED",
            {"kept_because": ["rule_not_claimed"]},
            "not_applicable",
        ),
    ],
)
def test_the_evidence_state_is_read_from_the_filter_record(
    disposition, decision, adjudication, state
):
    assert service.evidence_state(disposition, decision, adjudication) == state


def test_every_filter_reason_the_code_can_give_has_an_evidence_state():
    from app.triage import adjudicate

    reasons = {
        value
        for name, value in vars(adjudicate).items()
        if name.isupper() and isinstance(value, str) and value.islower() and "_" in value
    } - {"review", "filtered"}
    assert "run_incomplete" in reasons and len(reasons) >= 10
    for reason in reasons:
        state = service.evidence_state("review", "D30_HIGH", {"kept_because": [reason]})
        assert state in {"unavailable", "insufficient", "not_refuted"}


def test_counts_stay_consistent_across_the_scan_the_units_and_the_report(client, engine):
    scan_id, _, _ = _composite(engine, Tools(path_hidden=("a", "b")))
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    units = _units(client, scan_id)
    with Session(engine) as session:
        stored = session.scalar(
            select(func.count())
            .select_from(LocationUnit)
            .where(LocationUnit.scan_id == uuid.UUID(scan_id))
        )
    assert stored == len(units) == report["stages"]["units"] == sum(scan["unit_counts"].values())
    assert sum(f["units"] for f in scan["families"]) == len(units)
    assert sum(f["filtered"] for f in scan["families"]) == scan["disposition_counts"]["filtered"]
    assert scan["disposition_counts"]["filtered"] == 2 == report["stages"]["filtered"]
