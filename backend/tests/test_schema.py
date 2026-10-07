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

ASSESSMENT_PROVENANCE = {
    "decision_id": "D30_HIGH",
    "matched_conditions": ["agreement", "execution_candidate"],
    "policy_id": "command-injection-priority",
    "policy_version": "0.1",
    "policy_sha256": "a" * 64,
    "spec_sha256": "b" * 64,
    "rule_claims_version": "rule-claims-v2",
    "rule_claims_sha256": "c" * 64,
}


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
    unit = LocationUnit(
        scan_id=run.scan_id,
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
    link = UnitFinding(
        unit_id=unit.id,
        finding_id=finding.id,
        reconciler_version="reconcile-v0.1",
        match_rule="containment",
    )
    assessment = UnitAssessment(
        unit_id=unit.id,
        evidence={"tools": ["semgrep", "codeql"]},
        priority="P2",
        reason="paired evidence",
        **ASSESSMENT_PROVENANCE,
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


def test_location_unit_key_is_unique_per_scan_and_reconciler_version(session):
    _, run = add_chain(session)
    common = dict(
        scan_id=run.scan_id,
        unit_key="b" * 64,
        mapping_status="mapped",
        reconciler_version="reconcile-v0.1",
        locator_version="sink-locator-v0",
    )
    session.add_all([LocationUnit(**common), LocationUnit(**common)])

    with pytest.raises(IntegrityError):
        session.commit()


def test_location_unit_key_can_repeat_across_reconciler_versions(session):
    _, run = add_chain(session)
    common = dict(
        scan_id=run.scan_id,
        unit_key="c" * 64,
        mapping_status="mapped",
        locator_version="sink-locator-v0",
    )
    session.add_all(
        [
            LocationUnit(**common, reconciler_version="reconcile-v0.1"),
            LocationUnit(**common, reconciler_version="reconcile-v0.2"),
        ]
    )

    session.commit()
    assert session.scalar(select(func.count()).select_from(LocationUnit)) == 2


def _unit_for_version(session, scan_id, version, key):
    unit = LocationUnit(
        scan_id=scan_id,
        unit_key=key,
        mapping_status="mapped",
        reconciler_version=version,
        locator_version="sink-locator-v0",
    )
    session.add(unit)
    session.flush()
    return unit


def test_finding_maps_once_per_reconciler_version(session):
    _, run = add_chain(session)
    finding = Finding(tool_run_id=run.id, result_index=0, rule_id="r", message="m")
    session.add(finding)
    session.flush()
    first = _unit_for_version(session, run.scan_id, "reconcile-v0.1", "d" * 64)
    second = _unit_for_version(session, run.scan_id, "reconcile-v0.1", "e" * 64)
    session.add_all(
        [
            UnitFinding(
                unit_id=first.id,
                finding_id=finding.id,
                reconciler_version="reconcile-v0.1",
            ),
            UnitFinding(
                unit_id=second.id,
                finding_id=finding.id,
                reconciler_version="reconcile-v0.1",
            ),
        ]
    )

    with pytest.raises(IntegrityError):
        session.commit()


def test_finding_can_be_remapped_by_new_reconciler_version(session):
    _, run = add_chain(session)
    finding = Finding(tool_run_id=run.id, result_index=0, rule_id="r", message="m")
    session.add(finding)
    session.flush()
    old = _unit_for_version(session, run.scan_id, "reconcile-v0.1", "f" * 64)
    new = _unit_for_version(session, run.scan_id, "reconcile-v0.2", "f" * 64)
    session.add_all(
        [
            UnitFinding(
                unit_id=old.id,
                finding_id=finding.id,
                reconciler_version="reconcile-v0.1",
            ),
            UnitFinding(
                unit_id=new.id,
                finding_id=finding.id,
                reconciler_version="reconcile-v0.2",
            ),
        ]
    )

    session.commit()
    assert session.scalar(select(func.count()).select_from(UnitFinding)) == 2


def test_unit_finding_version_must_match_location_unit(session):
    _, run = add_chain(session)
    finding = Finding(tool_run_id=run.id, result_index=0, rule_id="r", message="m")
    session.add(finding)
    session.flush()
    unit = _unit_for_version(session, run.scan_id, "reconcile-v0.1", "1" * 64)
    session.add(
        UnitFinding(
            unit_id=unit.id,
            finding_id=finding.id,
            reconciler_version="reconcile-v0.2",
        )
    )

    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize(
    "mapping_status",
    ["mapped", "unmapped", "role_unresolved", "column_encoding_requires_review"],
)
def test_location_unit_accepts_frozen_mapping_status_vocabulary(session, mapping_status):
    _, run = add_chain(session)
    session.add(
        LocationUnit(
            scan_id=run.scan_id,
            unit_key=f"status-{mapping_status}",
            mapping_status=mapping_status,
            reconciler_version="reconcile-v0.1",
            locator_version="sink-locator-v0",
        )
    )
    session.commit()


def test_location_unit_rejects_unknown_mapping_status(session):
    _, run = add_chain(session)
    session.add(
        LocationUnit(
            scan_id=run.scan_id,
            unit_key="status-invalid",
            mapping_status="review_later",
            reconciler_version="reconcile-v0.1",
            locator_version="sink-locator-v0",
        )
    )

    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("argument_role", [None, "shell_command", "executable", "argument_list"])
def test_location_unit_accepts_frozen_argument_role_vocabulary(session, argument_role):
    _, run = add_chain(session)
    session.add(
        LocationUnit(
            scan_id=run.scan_id,
            unit_key=f"role-{argument_role}",
            argument_role=argument_role,
            mapping_status="mapped",
            reconciler_version="reconcile-v0.1",
            locator_version="sink-locator-v0",
        )
    )
    session.commit()


def test_location_unit_rejects_unknown_argument_role(session):
    _, run = add_chain(session)
    session.add(
        LocationUnit(
            scan_id=run.scan_id,
            unit_key="role-invalid",
            argument_role="command",
            mapping_status="mapped",
            reconciler_version="reconcile-v0.1",
            locator_version="sink-locator-v0",
        )
    )

    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("priority", ["P1", "P2", "U", "P3", "P4"])
def test_unit_assessment_accepts_frozen_priority_vocabulary(session, priority):
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
            evidence={},
            priority=priority,
            reason="test",
            **ASSESSMENT_PROVENANCE,
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
            evidence={},
            priority="PX",
            reason="test",
            **ASSESSMENT_PROVENANCE,
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
