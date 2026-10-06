"""Cross-feature database constraints, exercised through the model registry."""

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import (
    Finding,
    LocationUnit,
    Project,
    Scan,
    SourceSnapshot,
    ToolRun,
    UnitAssessment,
    UnitFinding,
)


def add_chain(session):
    project = Project(name="Demo")
    session.add(project)
    session.flush()
    snapshot = SourceSnapshot(project_id=project.id, bucket="b", object_key="k")
    session.add(snapshot)
    session.flush()
    scan = Scan(snapshot_id=snapshot.id)
    session.add(scan)
    session.flush()
    run = ToolRun(scan_id=scan.id, tool="semgrep", language="python")
    session.add(run)
    session.flush()
    return project, run


def test_deleting_project_cascades_to_findings(session):
    project, run = add_chain(session)
    session.add(Finding(tool_run_id=run.id, result_index=0, rule_id="r", message="m"))
    session.commit()
    session.delete(project)
    session.commit()
    for model in [SourceSnapshot, Scan, ToolRun, Finding]:
        assert session.scalar(select(func.count()).select_from(model)) == 0


@pytest.mark.parametrize(
    ("start_line", "end_line", "start_column", "end_column", "valid"),
    [(3, 3, 5, 5, True), (3, 4, 9, 2, True), (3, 3, 9, 2, False), (None, None, None, None, True)],
)
def test_finding_column_order(session, start_line, end_line, start_column, end_column, valid):
    _, run = add_chain(session)
    session.add(
        Finding(
            tool_run_id=run.id,
            result_index=0,
            rule_id="r",
            message="m",
            start_line=start_line,
            end_line=end_line,
            start_column=start_column,
            end_column=end_column,
        )
    )
    if valid:
        session.commit()
    else:
        with pytest.raises(IntegrityError):
            session.commit()


def _add_triage_chain(session):
    project, run = add_chain(session)
    finding = Finding(tool_run_id=run.id, result_index=0, rule_id="r", message="m")
    session.add(finding)
    session.flush()
    scan = run.__class__.__table__.metadata.tables["scans"]
    scan_id = session.execute(
        select(scan.c.id).where(scan.c.id == run.scan_id)
    ).scalar_one()
    unit = LocationUnit(
        scan_id=scan_id,
        unit_key="reconcile-v0.1:" + "a" * 64,
        path="src/example.py",
        start_line=10,
        end_line=10,
        start_column=1,
        end_column=20,
        sink_kind="subprocess.run",
        argument_role="executable",
        mapping_status="mapped",
        reconciler_version="reconcile-v0.1",
        locator_version="sink-locator-v0",
    )
    session.add(unit)
    session.flush()
    link = UnitFinding(unit_id=unit.id, finding_id=finding.id, match_rule="containment")
    assessment = UnitAssessment(
        unit_id=unit.id,
        semgrep_flag=True,
        codeql_flag=True,
        rule_claims={"shell_semantics": False},
        evidence={"tools": ["semgrep", "codeql"]},
        priority="P2",
        reason="paired evidence",
        policy_version="priority-v0",
    )
    session.add_all([link, assessment])
    session.flush()
    return project, unit, finding


def test_triage_rows_cascade_with_project(session):
    project, _, _ = _add_triage_chain(session)
    session.commit()

    session.delete(project)
    session.commit()

    for model in [LocationUnit, UnitFinding, UnitAssessment]:
        assert session.scalar(select(func.count()).select_from(model)) == 0


def test_location_unit_key_is_unique_per_scan(session):
    _, run = add_chain(session)
    common = dict(
        scan_id=run.scan_id,
        unit_key="reconcile-v0.1:" + "b" * 64,
        mapping_status="mapped",
        reconciler_version="reconcile-v0.1",
        locator_version="sink-locator-v0",
    )
    session.add_all([LocationUnit(**common), LocationUnit(**common)])

    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("priority", ["P1", "P2", "U", "P3", "P4"])
def test_unit_assessment_accepts_frozen_priority_vocabulary(session, priority):
    _, unit, _ = _add_triage_chain(session)
    session.rollback()

    # Re-create a minimal committed chain after rollback.
    _, run = add_chain(session)
    unit = LocationUnit(
        scan_id=run.scan_id,
        unit_key=f"reconcile-v0.1:{priority}",
        mapping_status="mapped",
        reconciler_version="reconcile-v0.1",
        locator_version="sink-locator-v0",
    )
    session.add(unit)
    session.flush()
    session.add(
        UnitAssessment(
            unit_id=unit.id,
            semgrep_flag=False,
            codeql_flag=True,
            rule_claims={},
            evidence={},
            priority=priority,
            reason="test",
            policy_version="priority-v0",
        )
    )
    session.commit()


def test_unit_assessment_rejects_unknown_priority(session):
    _, run = add_chain(session)
    unit = LocationUnit(
        scan_id=run.scan_id,
        unit_key="reconcile-v0.1:bad-priority",
        mapping_status="mapped",
        reconciler_version="reconcile-v0.1",
        locator_version="sink-locator-v0",
    )
    session.add(unit)
    session.flush()
    session.add(
        UnitAssessment(
            unit_id=unit.id,
            semgrep_flag=False,
            codeql_flag=False,
            rule_claims={},
            evidence={},
            priority="PX",
            reason="test",
            policy_version="priority-v0",
        )
    )

    with pytest.raises(IntegrityError):
        session.commit()


def test_source_snapshot_provenance_round_trips(session):
    project = Project(name="Provenance")
    session.add(project)
    session.flush()
    snapshot = SourceSnapshot(
        project_id=project.id,
        bucket="b",
        object_key="k",
        source_kind="github",
        repository_url="https://example.invalid/repo.git",
        resolved_commit="abc123",
        ecosystem="npm",
        package_name="example",
        package_version="1.2.3",
        artifact_url="https://example.invalid/archive.tgz",
        source_subdirectory="packages/example",
        manifest_sha256="c" * 64,
    )
    session.add(snapshot)
    session.commit()
    session.refresh(snapshot)

    assert snapshot.source_kind == "github"
    assert snapshot.repository_url == "https://example.invalid/repo.git"
    assert snapshot.manifest_sha256 == "c" * 64
