"""Cross-feature database constraints, exercised through the model registry."""

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import Finding, Project, Scan, SourceSnapshot, ToolRun


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
