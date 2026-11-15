"""Golden regression for the composite profiles multi-cwe-v0.1 and multi-cwe-v0.2.

Each scenario runs a composite scan through the worker with scripted scanner output and
compares what the scan stored and what the API, the report and the SARIF export say about it
with a committed JSON file under tests/golden/composite/. The `multi-cwe-v0.1` files were
generated before any analysis family was added to the composition; a difference means that
profile now behaves differently. The `multi-cwe-v0.2` files pin the three-family scan.

To regenerate after an intended, explained change: UPDATE_GOLDEN=1 uv run pytest <this file>.
Review the diff of every golden file and commit it with the change that caused it.
"""

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.features.scans.models import Scan
from tests.workflows.scans.fakes import FakeStorage
from tests.workflows.scans.test_composite_scan import _composite, _detail, _units
from tests.workflows.scans.test_families import Tools
from tests.workflows.scans.test_sql_family import SqlTools, _scan_v02, standard_pack  # noqa: F401

GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "composite"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"

V02_SCENARIOS: dict[str, Tools] = {
    "multi-cwe-v0.2-three-families": SqlTools(),
    "multi-cwe-v0.2-other-families-filter": SqlTools(command_refuted=True, path_hidden=()),
    "multi-cwe-v0.2-sql-pass-partial": SqlTools(sql_pass="partial"),
    "multi-cwe-v0.2-sql-pass-failed": SqlTools(sql_pass="failed"),
    "multi-cwe-v0.2-sql-pass-failed-with-results": SqlTools(
        sql_pass="failed", sql_results_when_failed=True
    ),
    "multi-cwe-v0.2-unexpected-sql-rule": SqlTools(sql_rule="py/nosql-injection"),
    "multi-cwe-v0.2-path-pass-partial": SqlTools(path_pass="partial"),
    "multi-cwe-v0.2-database-failed": SqlTools(database="failed"),
}
SCENARIOS: dict[str, Tools] = {
    "multi-cwe-v0.1-both-families": Tools(),
    "multi-cwe-v0.1-command-evidence-refutes": Tools(command_refuted=True),
    "multi-cwe-v0.1-path-evidence-removes-two": Tools(path_hidden=("a", "b")),
    "multi-cwe-v0.1-path-pass-partial": Tools(path_pass="partial"),
    "multi-cwe-v0.1-path-pass-failed": Tools(path_pass="failed"),
    "multi-cwe-v0.1-unexpected-path-rule": Tools(path_rule="st/cwe-22/other"),
    "multi-cwe-v0.1-command-evidence-step-failed": Tools(command_evidence_step="failed"),
    "multi-cwe-v0.1-database-failed": Tools(database="failed"),
}
# Keys of a unit detail that identify rows of one test database, not what the scan produced.
_ROW_IDS = ("id",)
_FINDING_KEYS = (
    "tool",
    "language",
    "raw_id",
    "rule_id",
    "raw_rule_id",
    "file_path",
    "start_line",
    "end_line",
    "start_column",
    "end_column",
    "cwe_ids",
    "mapped_cwes",
    "analysis_family",
    "family_status",
    "family_basis",
    "unresolved_reason",
    "tool_pass",
)


def _artifact(storage: FakeStorage, scan: Scan, name: str) -> Any:
    artifact = scan.artifacts.get(name)
    if artifact is None:
        return None
    return json.loads(storage.objects[(get_settings().s3_bucket, artifact["key"])])


def _produced(
    client: TestClient, engine: Engine, storage: FakeStorage, scan_id: str
) -> dict[str, Any]:
    """What a composite scan stored and reports, without row IDs, in a stable order."""
    with Session(engine) as session:
        scan = session.get_one(Scan, uuid.UUID(scan_id))
        run = _artifact(storage, scan, "python/run.json")
        stored = {
            "status": scan.status,
            "error_message": scan.error_message,
            "reconciler_version": scan.reconciler_version,
            "policy_version": scan.policy_version,
            "config": {
                key: scan.config.get(key)
                for key in ("profile_id", "profile_sha256", "languages", "composition", "families")
            },
            "artifacts": sorted(scan.artifacts),
            "run": {
                "composition_version": run["composition_version"],
                "status": run["status"],
                "members": run["members"],
                "steps": {
                    name: {key: step.get(key) for key in ("status", "kind", "serves")}
                    for name, step in run["steps"].items()
                },
                "conservation": run["conservation"],
            },
            "classification": _artifact(storage, scan, "python/classification.json"),
            "units_artifact": _artifact(storage, scan, "python/units.json"),
            "assessments_artifact": _artifact(storage, scan, "python/assessments.json"),
        }
    described = client.get(f"/api/v1/scans/{scan_id}").json()
    units = []
    for summary in _units(client, scan_id):
        detail = _detail(client, scan_id, summary)
        unit = {key: value for key, value in detail.items() if key not in (*_ROW_IDS, "findings")}
        unit["findings"] = sorted(
            ({key: finding[key] for key in _FINDING_KEYS} for finding in detail["findings"]),
            key=lambda finding: finding["raw_id"],
        )
        units.append(unit)
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    for candidate in report["candidates"]:
        candidate["unit_ids"] = len(candidate["unit_ids"])
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    return {
        "scan": stored,
        "described": {
            key: described[key]
            for key in (
                "status",
                "profile",
                "reconciler_version",
                "policy_version",
                "unit_counts",
                "disposition_counts",
                "families",
            )
        }
        | {
            "tool_runs": sorted(
                [run["language"], run["tool"], run["status"], run["tool_version"]]
                for run in described["tool_runs"]
            )
        },
        "units": sorted(units, key=lambda unit: unit["unit_key"]),
        "report": {
            key: report[key]
            for key in (
                "raw_alerts",
                "stages",
                "sources",
                "main_list_by_priority",
                "filtered_by_rule",
                "families",
                "composition",
                "candidates",
            )
        },
        "sarif": [
            {
                "tool": run["tool"]["driver"],
                "results": [
                    {
                        "ruleId": result["ruleId"],
                        "locations": result.get("locations"),
                        "suppressed": "suppressions" in result,
                        "securityTriage": result["properties"]["securityTriage"],
                    }
                    for result in run["results"]
                ],
            }
            for run in sarif["runs"]
        ],
    }


def _check(name: str, produced: dict[str, Any]) -> None:
    text = json.dumps(produced, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    path = GOLDEN / f"{name}.json"
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    assert path.is_file(), f"Missing golden file {path.name}; generate it with UPDATE_GOLDEN=1"
    assert json.loads(path.read_text(encoding="utf-8")) == json.loads(text)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_multi_cwe_v0_1_produces_its_recorded_result(client, engine, name):
    scan_id, _, storage = _composite(engine, SCENARIOS[name])
    _check(name, _produced(client, engine, storage, scan_id))


@pytest.mark.parametrize("name", sorted(V02_SCENARIOS))
def test_multi_cwe_v0_2_produces_its_recorded_result(client, engine, name):
    scan_id, _, storage = _scan_v02(engine, V02_SCENARIOS[name])
    _check(name, _produced(client, engine, storage, scan_id))


def test_every_golden_file_belongs_to_a_scenario():
    assert sorted(path.stem for path in GOLDEN.glob("*.json")) == sorted(
        [*SCENARIOS, *V02_SCENARIOS]
    )
