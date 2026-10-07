"""run_scan end to end with a fake pipeline: persistence, idempotency, atomicity and retries."""

import dataclasses
import hashlib
import subprocess
import sys
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.features.findings.models import Finding
from app.features.projects.models import Project
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.scanners.pipeline import PipelineResult
from app.scanners.profile import load_profile
from app.workers.celery_app import celery_app
from app.workflows.scans import task as scan_module
from app.workflows.scans.persist import _coordinates, persist_scan_result
from tests.workflows.scans.fakes import PYTHON_SOURCE, FakeStorage, fake_pipeline, make_archive


@pytest.fixture
def storage() -> FakeStorage:
    return FakeStorage()


@pytest.fixture
def make_scan(engine: Engine, storage: FakeStorage) -> Callable[..., uuid.UUID]:
    def make(files: dict[str, str] | None = None, *, sha256: str | None = None) -> uuid.UUID:
        archive = make_archive(files or {"app.py": PYTHON_SOURCE})
        storage.objects[("sources", "snapshots/s.tgz")] = archive
        with Session(engine) as session:
            project = Project(name="Scan test")
            session.add(project)
            session.flush()
            snapshot = SourceSnapshot(
                project_id=project.id,
                bucket="sources",
                object_key="snapshots/s.tgz",
                sha256=sha256 or hashlib.sha256(archive).hexdigest(),
                status="ready",
            )
            session.add(snapshot)
            session.flush()
            scan = Scan(snapshot_id=snapshot.id, config={"requested_by": "test"})
            session.add(scan)
            session.commit()
            return scan.id

    return make


def _execute(engine: Engine, storage: FakeStorage, scan_id: uuid.UUID, **kwargs: Any) -> str:
    return scan_module.execute_scan(
        scan_id,
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=kwargs.pop("run_pipeline_fn", fake_pipeline()),
        **kwargs,
    )


def _count(session: Session, model: type[Any]) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_execute_scan_persists_every_result_row_and_artifact(engine, storage, make_scan):
    outputs: list[Path] = []
    scan_id = make_scan()

    assert _execute(engine, storage, scan_id, run_pipeline_fn=fake_pipeline(outputs=outputs)) == (
        "completed"
    )

    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        assert scan.status == "completed"
        assert scan.started_at is not None and scan.finished_at is not None
        assert scan.error_message is None
        assert scan.config["requested_by"] == "test"
        assert scan.config["profile_id"] == "command-injection-v0.1"
        assert scan.config["languages"] == ["python"]
        runs = session.scalars(select(ToolRun).order_by(ToolRun.tool)).all()
        assert [(r.tool, r.language, r.status, r.tool_version) for r in runs] == [
            ("codeql", "python", "completed", "2.27.1"),
            ("semgrep", "python", "completed", "1.178.0"),
        ]
        semgrep = next(r for r in runs if r.tool == "semgrep")
        assert semgrep.result_key == f"scans/{scan_id}/python/semgrep.sarif"
        rule_ids = sorted(session.scalars(select(Finding.rule_id)))
        # The staging-path prefix is gone: findings store the pinned rule's ID.
        assert rule_ids == ["dangerous-system-call", "py/command-line-injection"]
        unit = session.scalars(select(LocationUnit)).one()
        assert (unit.path, unit.argument_role, unit.mapping_status) == (
            "app.py",
            "shell_command",
            "mapped",
        )
        assert _count(session, UnitFinding) == 2
        assessment = session.scalars(select(UnitAssessment)).one()
        profile = load_profile(get_settings().triage_root, get_settings().scan_profile)
        assert assessment.policy_sha256 == profile.policy_sha256
        assert assessment.priority in {"P1", "P2", "P3", "P4", "U"}
        assert assessment.evidence["predicate_values"]["agreement"] is True
        snapshot = session.get_one(SourceSnapshot, scan.snapshot_id)
        assert snapshot.provenance_verified_at is not None and snapshot.file_count == 1

        for name in ("python/run.json", "python/units.json", "python/assessments.json"):
            artifact = scan.artifacts[name]
            stored = storage.objects[(get_settings().s3_bucket, artifact["key"])]
            assert hashlib.sha256(stored).hexdigest() == artifact["sha256"]
    # The private work directory never outlives the scan.
    assert outputs and not outputs[0].parent.exists()


def test_persist_replaces_results_and_rolls_back_a_failed_write(engine, storage, make_scan):
    scan_id = make_scan()
    with Session(engine) as session:
        snapshot = session.get_one(SourceSnapshot, session.get_one(Scan, scan_id).snapshot_id)
        result = scan_module.scan_snapshot(
            scan_id,
            snapshot,
            settings=get_settings(),
            storage=storage,
            run_pipeline_fn=fake_pipeline(),
        )
        persist_scan_result(session, scan_id, result, now=scan_module._now())
        persist_scan_result(session, scan_id, result, now=scan_module._now())
        counts = [_count(session, m) for m in (ToolRun, Finding, LocationUnit, UnitFinding)]
        assert counts == [2, 2, 1, 2]
        assert _count(session, UnitAssessment) == 1

        # A row the schema rejects half-way through: nothing of the new write survives,
        # and the previous results stay exactly as they were.
        language = result.languages[0]
        bad_assessment = {**language.assessments[0], "priority": "PX"}
        bad = dataclasses.replace(
            result,
            status="partial",
            languages=[dataclasses.replace(language, assessments=[bad_assessment])],
        )
        with pytest.raises(IntegrityError):
            persist_scan_result(session, scan_id, bad, now=scan_module._now())
        assert [_count(session, m) for m in (ToolRun, Finding, LocationUnit, UnitFinding)] == counts
        assert session.get_one(Scan, scan_id).status == "completed"


def test_failed_persistence_marks_the_scan_failed(engine, storage, make_scan, monkeypatch):
    scan_id = make_scan()

    def broken(session: Session, *args: Any, **kwargs: Any) -> None:
        session.add(ToolRun(scan_id=scan_id, tool="semgrep", language="python"))
        session.flush()
        raise ValueError("write failed half-way")

    monkeypatch.setattr(scan_module, "persist_scan_result", broken)
    assert _execute(engine, storage, scan_id) == "failed"
    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        assert (scan.status, scan.error_message) == ("failed", "ValueError: write failed half-way")
        assert _count(session, ToolRun) == 0


def test_scanner_failure_is_final_without_triage(engine, storage, make_scan):
    scan_id = make_scan()
    assert _execute(engine, storage, scan_id, run_pipeline_fn=fake_pipeline("failed")) == "failed"
    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        assert scan.status == "failed"
        assert scan.error_message is not None and "python/semgrep: failed" in scan.error_message
        assert [r.status for r in session.scalars(select(ToolRun))] == ["failed", "failed"]
        assert _count(session, LocationUnit) == 0


def test_languages_combine_into_partial_and_javascript_uses_the_locator(engine, storage, make_scan):
    def pipeline(**kwargs: Any) -> PipelineResult:
        status = "failed" if kwargs["language"] == "python" else "completed"
        return fake_pipeline(status)(**kwargs)

    def invoke(argv: Any, cwd: Path, output: Path, name: str, timeout: float, env: Any = None):
        (output / "sink-locator-v0.json").write_text('{"results": []}', encoding="utf-8")
        return {"status": "completed", "exit_code": 0}

    scan_id = make_scan({"app.py": PYTHON_SOURCE, "index.js": "exec(cmd)\n"})
    assert _execute(engine, storage, scan_id, run_pipeline_fn=pipeline, invoke_fn=invoke) == (
        "partial"
    )
    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        assert scan.config["languages"] == ["javascript", "python"]
        assert "javascript/run.json" in scan.artifacts and "python/run.json" in scan.artifacts
        assert scan.error_message is not None and "python/codeql" in scan.error_message


@pytest.mark.parametrize(
    ("files", "sha256", "reason"),
    [
        (None, "0" * 64, "does not match its recorded SHA-256"),
        ({"README.md": "docs\n"}, None, "no source files in a profile language"),
    ],
)
def test_unusable_snapshots_fail_and_clean_up(engine, storage, make_scan, files, sha256, reason):
    scan_id = make_scan(files, sha256=sha256)
    assert _execute(engine, storage, scan_id) == "failed"
    with Session(engine) as session:
        message = session.get_one(Scan, scan_id).error_message
        assert message is not None and reason in message


def test_unexpected_errors_fail_the_scan_and_remove_the_work_directory(engine, storage, make_scan):
    outputs: list[Path] = []

    def crashing(**kwargs: Any) -> PipelineResult:
        outputs.append(kwargs["output"])
        raise RuntimeError("scanner crashed")

    scan_id = make_scan()
    assert _execute(engine, storage, scan_id, run_pipeline_fn=crashing) == "failed"
    assert not outputs[0].parent.exists()
    with Session(engine) as session:
        assert session.get_one(Scan, scan_id).error_message == "RuntimeError: scanner crashed"


def test_finished_scans_are_not_claimed_again(engine, storage, make_scan):
    scan_id = make_scan()
    assert _execute(engine, storage, scan_id) == "completed"
    assert _execute(engine, storage, scan_id) == "skipped"


@pytest.fixture
def eager(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    calls: list[str] = []
    monkeypatch.setattr(scan_module, "SessionLocal", lambda: Session(engine))
    celery_app.conf.task_always_eager = True
    try:
        yield calls
    finally:
        celery_app.conf.task_always_eager = False


def test_run_scan_does_not_retry_a_scanner_failure(engine, storage, make_scan, eager, monkeypatch):
    real = scan_module.execute_scan

    def counted(scan_id: uuid.UUID) -> str:
        eager.append("call")
        return real(
            scan_id,
            session_factory=lambda: Session(engine),
            storage=storage,
            run_pipeline_fn=fake_pipeline("failed"),
        )

    monkeypatch.setattr(scan_module, "execute_scan", counted)
    scan_id = make_scan()
    assert scan_module.run_scan.apply(args=(str(scan_id),)).get() == "failed"
    assert eager == ["call"]


def test_run_scan_retries_infrastructure_errors_then_fails(engine, make_scan, eager, monkeypatch):
    def down(scan_id: uuid.UUID) -> str:
        eager.append("call")
        raise OperationalError("SELECT 1", {}, Exception("database unavailable"))

    monkeypatch.setattr(scan_module, "execute_scan", down)
    scan_id = make_scan()
    result = scan_module.run_scan.apply(args=(str(scan_id),))
    assert isinstance(result.result, OperationalError)
    assert len(eager) == scan_module.MAX_RETRIES + 1
    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        assert scan.status == "failed"
        assert scan.error_message is not None and "after retries" in scan.error_message


def test_task_time_limits_cover_every_scanner_timeout_in_the_profile():
    profile = load_profile(get_settings().triage_root, get_settings().scan_profile)
    budget = sum(
        2 * 60 + scan_module.SCANNER_STEPS * config["timeout_seconds"]
        for config in profile.configs.values()
    )
    assert budget < scan_module.SOFT_TIME_LIMIT < scan_module.TIME_LIMIT
    visibility = celery_app.conf.broker_transport_options["visibility_timeout"]
    assert scan_module.TIME_LIMIT < visibility
    assert scan_module.run_scan.acks_late


@pytest.mark.parametrize(
    ("region", "expected"),
    [
        ({"startLine": 3}, (3, None, None, None)),
        ({"startLine": 3, "endLine": 2, "startColumn": 4, "endColumn": 1}, (3, None, 4, None)),
        ({"startLine": 0, "endLine": 2}, (None, None, None, None)),
        ({"startLine": 1, "endLine": 2, "startColumn": 9, "endColumn": 1}, (1, 2, 9, 1)),
    ],
)
def test_finding_coordinates_satisfy_the_schema_checks(region, expected):
    coordinates = _coordinates(region)
    assert tuple(coordinates.values()) == expected


def test_a_fresh_worker_process_registers_every_table():
    # conftest imports the model registry, which hides a worker that forgets to: run apart.
    code = (
        "import app.workers.celery_app\n"
        "from app.core.database import Base\n"
        "print(sorted(Base.metadata.tables))\n"
    )
    backend = Path(__file__).resolve().parents[3]
    output = subprocess.run(
        [sys.executable, "-c", code], cwd=backend, capture_output=True, text=True, check=True
    ).stdout
    for table in ("projects", "source_snapshots", "findings", "unit_assessments"):
        assert f"'{table}'" in output
