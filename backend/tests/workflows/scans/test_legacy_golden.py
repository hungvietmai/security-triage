"""Golden regression for the four existing scan profiles.

Each scenario runs `execute_scan` on a fixed synthetic source with scripted scanner output and
compares everything the scan produced (artifacts and database rows) with a committed JSON file
under tests/golden/legacy/. The files were generated from the code before any multi-CWE work;
a difference means an existing profile now behaves differently.

To regenerate after an intended, explained change: UPDATE_GOLDEN=1 uv run pytest <this file>.
Review the diff of every golden file and commit it with the change that caused it.
"""

import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.features.findings.models import Finding
from app.features.projects.models import Project
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.scanners import bandit, eslint
from app.scanners.pipeline import PipelineResult
from app.scanners.provenance import pinned_file
from app.scanners.semgrep import stage_rule
from app.triage.sinks_python import locate_python_sinks
from app.workflows.scans import task as scan_module
from tests.workflows.scans.fakes import (
    PATH_SOURCE,
    PYTHON_SOURCE,
    FakeStorage,
    fake_evidence_pipeline,
    fake_pipeline,
)

GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "legacy"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"

LITERAL_SOURCE = "import os\nos.system('ls -l')\n"
# Python 2 syntax: the sink locator cannot parse it, so the run is partial.
UNPARSABLE = "print 'python 2'\nf(a=1, 2)\n"
# Line 3: a constant command. Line 4: a command built from an argument.
JS_SOURCE = (
    "const cp = require('child_process');\n"
    "function run(name) {\n"
    "  cp.exec('ls -l');\n"
    "  cp.exec('rm ' + name);\n"
    "}\n"
)
JS_CONSTANT_CALL = "cp.exec('ls -l')"
JS_TAINTED_CALL = "cp.exec('rm ' + name)"
JS_TAINTED_ARGUMENT = "'rm ' + name"


def fixed_archive(files: dict[str, str], root: str = "src") -> bytes:
    """The same bytes on every run: no gzip timestamp, so the snapshot hash never changes."""
    buffer = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as bundle,
    ):
        for name, text in sorted(files.items()):
            data = text.encode()
            entry = tarfile.TarInfo(f"{root}/{name}")
            entry.size = len(data)
            bundle.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


def _position(offset: int) -> dict[str, int]:
    before = JS_SOURCE[:offset]
    return {
        "line": before.count("\n") + 1,
        "col": len(before.rsplit("\n", 1)[-1]) + 1,
        "offset": offset,
    }


def _js_span(text: str) -> dict[str, int]:
    start = _position(JS_SOURCE.index(text))
    end = _position(JS_SOURCE.index(text) + len(text))
    return {
        "startLine": start["line"],
        "startColumn": start["col"],
        "endLine": end["line"],
        "endColumn": end["col"],
    }


def _js_finding(raw_id: str, rule_id: str, region: Any, snapshot: str) -> Any:
    return {
        "raw_id": raw_id,
        "tool": raw_id.split(":")[0],
        "snapshot_sha256": snapshot,
        "rule_id": rule_id,
        "reported_path": "index.js",
        "reported_region": region,
        "reported_cwes": ["CWE-78"],
        "message": "command injection",
        "sink_identity": None,
        "mapping_status": "unresolved",
        "technical_verdict": "unresolved",
        "scope_verdict": "unresolved",
        "raw_result": {},
    }


def js_pipeline(**kwargs: Any) -> PipelineResult:
    """Scripted JavaScript scanners: a flow to the built command, pattern alerts on both calls.

    Semgrep and CodeQL report the argument of the tainted call. When the profile configures
    ESLint, it reports both calls; when it configures constant-command evidence, the evidence
    rule reports the constant call.
    """
    output: Path = kwargs["output"]
    snapshot: str = kwargs["snapshot_sha256"]
    root: Path = kwargs["repository_root"]
    for index, rule in enumerate(kwargs["semgrep_rules"]):
        stage_rule(rule, output / f"rule-{index}.yaml", repository_root=root)
    step = {"status": "completed", "exit_code": 0, "argv": ["tool"]}
    steps = {"semgrep": dict(step), "codeql": dict(step)}
    argument = _js_span(JS_TAINTED_ARGUMENT)
    findings = [
        _js_finding("semgrep:0:0", "tmp.detect-child-process", argument, snapshot),
        _js_finding("codeql:0:0", "js/command-line-injection", argument, snapshot),
    ]
    if kwargs.get("eslint") is not None:
        steps["eslint"] = dict(step)
        shutil.copyfile(
            pinned_file(kwargs["eslint"]["config"], root), output / eslint.STAGED_CONFIG
        )
        findings += [
            _js_finding(
                f"eslint:0:{index}", "security/detect-child-process", _js_span(call), snapshot
            )
            for index, call in enumerate((JS_CONSTANT_CALL, JS_TAINTED_CALL))
        ]
    evidence = []
    if kwargs.get("semgrep_evidence") is not None:
        steps["semgrep-evidence"] = dict(step)
        evidence.append(
            _js_finding(
                "semgrep-evidence:0:0",
                "tmp.semgrep-evidence.st-js-constant-command",
                _js_span(JS_CONSTANT_CALL),
                snapshot,
            )
        )
    return PipelineResult(
        status="completed",
        steps=steps,  # type: ignore[arg-type]
        findings=findings,
        codeql_query_files=kwargs["codeql_query_sha256"],
        codeql_pack_manifest="name: codeql/queries\n",
        evidence_findings=evidence,
    )


def js_locator(version: int) -> Callable[..., dict[str, Any]]:
    """The sink locator's Semgrep run: both calls, reported by a rule of the given version."""

    def invoke(argv: Any, cwd: Path, output: Path, name: str, timeout: float, env: Any = None):
        results = [
            {
                "check_id": f"rules.sink-locator-v{version}-child-process-namespace",
                "path": "index.js",
                "start": _position(JS_SOURCE.index(call)),
                "end": _position(JS_SOURCE.index(call) + len(call)),
            }
            for call in (JS_CONSTANT_CALL, JS_TAINTED_CALL)
        ]
        (output / "sink-locator-v0.json").write_text(
            json.dumps({"results": results}), encoding="utf-8"
        )
        return {"status": "completed", "exit_code": 0}

    return invoke


TWO_ROLES_SOURCE = "import subprocess\nsubprocess.run([tool, name])\n"


def two_roles_pipeline(**kwargs: Any) -> PipelineResult:
    """One call, alerts on different parts of it: three units that form one candidate.

    Semgrep reports the program of the argument list, CodeQL one of its arguments and Bandit
    the whole call. The units rank differently, so the candidate's priority is the best one.
    """
    output: Path = kwargs["output"]
    root: Path = kwargs["repository_root"]
    snapshot: str = kwargs["snapshot_sha256"]
    for index, rule in enumerate(kwargs["semgrep_rules"]):
        stage_rule(rule, output / f"rule-{index}.yaml", repository_root=root)
    shutil.copyfile(pinned_file(kwargs["bandit"]["config"], root), output / bandit.STAGED_CONFIG)
    sink = locate_python_sinks("app.py", TWO_ROLES_SOURCE)[0]
    program, argument = sink["args"][0]["sequence_items"]
    step = {"status": "completed", "exit_code": 0, "argv": ["tool"]}
    findings: list[Any] = [
        {
            **_js_finding("semgrep:0:0", "tmp.dangerous-subprocess-use", dict(program), snapshot),
            "reported_path": "app.py",
        },
        {
            **_js_finding("codeql:0:0", "py/command-line-injection", dict(argument), snapshot),
            "reported_path": "app.py",
        },
        {
            **_js_finding("bandit:0:0", "B603", dict(sink["span"]), snapshot),
            "reported_path": "app.py",
        },
    ]
    return PipelineResult(
        status="completed",
        steps={name: dict(step) for name in ("semgrep", "bandit", "codeql")},  # type: ignore[misc]
        findings=findings,
        codeql_query_files=kwargs["codeql_query_sha256"],
        codeql_pack_manifest="name: codeql/queries\n",
    )


def failed_evidence_step(**kwargs: Any) -> PipelineResult:
    """The CodeQL evidence queries did not finish; the scan itself completed."""
    result = fake_pipeline(semgrep_rule="subprocess-shell-true", refuted=True)(**kwargs)
    result.steps["codeql-evidence"] = {"status": "failed", "error": "evidence queries failed"}
    return result


AUDIT = "subprocess-shell-true"  # a Semgrep rule that claims no flow
# name -> (profile or None for the default, files, pipeline, sink-locator invoke, final status)
SCENARIOS: dict[str, tuple[str | None, dict[str, str], Any, Any, str]] = {
    "v0.1-python-flow": (None, {"app.py": PYTHON_SOURCE}, fake_pipeline(), None, "completed"),
    "v0.1-javascript-flow": (
        None,
        {"index.js": JS_SOURCE},
        js_pipeline,
        js_locator(0),
        "completed",
    ),
    "v0.1-python-scanners-failed": (
        None,
        {"app.py": PYTHON_SOURCE},
        fake_pipeline("failed"),
        None,
        "failed",
    ),
    "v0.2-python-flow-still-reported": (
        "command-injection-v0.2",
        {"app.py": PYTHON_SOURCE},
        fake_pipeline(),
        None,
        "completed",
    ),
    "v0.2-python-g1-codeql-evidence": (
        "command-injection-v0.2",
        {"app.py": PYTHON_SOURCE},
        fake_pipeline(semgrep_rule=AUDIT, refuted=True),
        None,
        "completed",
    ),
    "v0.2-python-g2-literal": (
        "command-injection-v0.2",
        {"app.py": LITERAL_SOURCE},
        fake_pipeline(semgrep_rule=AUDIT, codeql_alert=False, bandit_severity="LOW"),
        None,
        "completed",
    ),
    "v0.2-python-literal-without-second-source": (
        "command-injection-v0.2",
        {"app.py": LITERAL_SOURCE},
        fake_pipeline(semgrep_rule=AUDIT, codeql_alert=False, bandit_severity="HIGH"),
        None,
        "completed",
    ),
    "v0.2-python-g3-dead-branch": (
        "command-injection-v0.2",
        {"app.py": PYTHON_SOURCE},
        fake_pipeline(semgrep_rule=AUDIT, codeql_alert=False, dead_branch=True),
        None,
        "completed",
    ),
    "v0.2-python-evidence-step-failed": (
        "command-injection-v0.2",
        {"app.py": PYTHON_SOURCE},
        failed_evidence_step,
        None,
        "completed",
    ),
    "v0.2-python-partial-run": (
        "command-injection-v0.2",
        {"app.py": LITERAL_SOURCE, "legacy.py": UNPARSABLE},
        fake_pipeline(semgrep_rule=AUDIT, codeql_alert=False, bandit_severity="LOW"),
        None,
        "partial",
    ),
    "v0.2-python-two-roles-one-candidate": (
        "command-injection-v0.2",
        {"app.py": TWO_ROLES_SOURCE},
        two_roles_pipeline,
        None,
        "completed",
    ),
    "v0.3-python-flow": (
        "command-injection-v0.3",
        {"app.py": PYTHON_SOURCE},
        fake_pipeline(),
        None,
        "completed",
    ),
    "v0.3-javascript-g4-constant": (
        "command-injection-v0.3",
        {"index.js": JS_SOURCE},
        js_pipeline,
        js_locator(1),
        "completed",
    ),
    "path-traversal-v0.2-kept-and-hidden": (
        "path-traversal-v0.2",
        {"app.py": PATH_SOURCE},
        fake_evidence_pipeline(),
        None,
        "completed",
    ),
    "path-traversal-v0.2-partial-run": (
        "path-traversal-v0.2",
        {"app.py": PATH_SOURCE},
        fake_evidence_pipeline("partial"),
        None,
        "partial",
    ),
}


def _artifact(storage: FakeStorage, scan: Scan, name: str) -> Any:
    artifact = scan.artifacts.get(name)
    if artifact is None:
        return None
    return json.loads(storage.objects[(get_settings().s3_bucket, artifact["key"])])


def _produced(engine: Engine, storage: FakeStorage, scan_id: uuid.UUID) -> dict[str, Any]:
    """Everything a scan wrote that a user or a later reader depends on, in a stable order."""
    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        languages = {}
        for language in scan.config.get("languages", []):
            run = _artifact(storage, scan, f"{language}/run.json")
            languages[language] = {
                "run": {
                    key: run[key]
                    for key in ("status", "profile_id", "profile_sha256", "raw_findings")
                }
                | {"steps": {name: step["status"] for name, step in run["steps"].items()}},
                "findings": _artifact(storage, scan, f"{language}/findings.json"),
                "units": _artifact(storage, scan, f"{language}/units.json"),
                "assessments": _artifact(storage, scan, f"{language}/assessments.json"),
            }
        runs = {
            run.id: run
            for run in session.scalars(
                select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(ToolRun.id)
            )
        }
        findings = session.scalars(select(Finding).where(Finding.tool_run_id.in_(list(runs)))).all()
        raw_ids = {finding.id: finding.evidence["raw_id"] for finding in findings}
        units = session.scalars(
            select(LocationUnit)
            .where(LocationUnit.scan_id == scan_id)
            .order_by(LocationUnit.unit_key)
        ).all()
        keys = {unit.id: unit.unit_key for unit in units}
        links = session.scalars(
            select(UnitFinding).where(UnitFinding.unit_id.in_(list(keys)))
        ).all()
        assessments = session.scalars(
            select(UnitAssessment).where(UnitAssessment.unit_id.in_(list(keys)))
        ).all()
        return {
            "scan": {
                "status": scan.status,
                "reconciler_version": scan.reconciler_version,
                "policy_version": scan.policy_version,
                "profile_id": scan.config.get("profile_id"),
                "profile_sha256": scan.config.get("profile_sha256"),
            },
            "languages": languages,
            "tool_runs": sorted(
                [run.language, run.tool, run.status, run.tool_version] for run in runs.values()
            ),
            "finding_rows": sorted(
                (
                    {
                        "tool": runs[finding.tool_run_id].tool,
                        "language": runs[finding.tool_run_id].language,
                        "raw_id": finding.evidence["raw_id"],
                        "rule_id": finding.rule_id,
                        "raw_rule_id": finding.evidence["raw_rule_id"],
                        "file_path": finding.file_path,
                        "region": [
                            finding.start_line,
                            finding.start_column,
                            finding.end_line,
                            finding.end_column,
                        ],
                        "cwe_ids": finding.cwe_ids,
                        "mapping_version": finding.mapping_version,
                    }
                    for finding in findings
                ),
                key=lambda row: (row["language"], row["raw_id"]),
            ),
            "unit_rows": [
                {
                    "unit_key": unit.unit_key,
                    "candidate_key": unit.candidate_key,
                    "path": unit.path,
                    "region": [
                        unit.start_line,
                        unit.start_column,
                        unit.end_line,
                        unit.end_column,
                    ],
                    "sink_kind": unit.sink_kind,
                    "argument_role": unit.argument_role,
                    "mapping_status": unit.mapping_status,
                    "reconciler_version": unit.reconciler_version,
                    "locator_version": unit.locator_version,
                }
                for unit in units
            ],
            "unit_finding_rows": sorted(
                [keys[link.unit_id], raw_ids[link.finding_id], link.match_rule] for link in links
            ),
            "assessment_rows": sorted(
                (
                    {
                        "unit_key": keys[assessment.unit_id],
                        "priority": assessment.priority,
                        "disposition": assessment.disposition,
                        "decision_id": assessment.decision_id,
                        "matched_conditions": assessment.matched_conditions,
                        "reason": assessment.reason,
                        "policy_id": assessment.policy_id,
                        "policy_version": assessment.policy_version,
                        "policy_sha256": assessment.policy_sha256,
                        "spec_sha256": assessment.spec_sha256,
                        "rule_claims_version": assessment.rule_claims_version,
                        "rule_claims_sha256": assessment.rule_claims_sha256,
                    }
                    for assessment in assessments
                ),
                key=lambda row: row["unit_key"],
            ),
        }


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_existing_profile_produces_its_recorded_result(name: str, engine: Engine) -> None:
    profile, files, pipeline, invoke, expected_status = SCENARIOS[name]
    storage = FakeStorage()
    archive = fixed_archive(files)
    storage.objects[("sources", "snapshots/s.tgz")] = archive
    with Session(engine) as session:
        project = Project(name="Golden")
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
        scan = Scan(snapshot_id=snapshot.id, config={"profile": profile} if profile else {})
        session.add(scan)
        session.commit()
        scan_id = scan.id

    options: dict[str, Any] = {"invoke_fn": invoke} if invoke is not None else {}
    status = scan_module.execute_scan(
        scan_id,
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=pipeline,
        **options,
    )
    assert status == expected_status

    produced = json.loads(json.dumps(_produced(engine, storage, scan_id)))
    path = GOLDEN / f"{name}.json"
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(produced, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    assert path.is_file(), f"No golden file for {name}; see this module's docstring"
    assert produced == json.loads(path.read_text(encoding="utf-8"))


def test_every_golden_file_belongs_to_a_scenario() -> None:
    assert {path.stem for path in GOLDEN.glob("*.json")} == set(SCENARIOS)
