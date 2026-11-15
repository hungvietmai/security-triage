"""Composite scan: two analysis families on one tool run, compared with scanning each alone.

The source below is synthetic test data and the scanners are scripted. Everything between
the scanners' output and the units is the real code: classification, routing, each member's
own entry point, reconciliation, policy and adjudication.
"""

import dataclasses
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from app.core.config import get_settings
from app.scanners.bandit import STAGED_CONFIG
from app.scanners.pipeline import PipelineResult
from app.scanners.profile import EvidenceProfile, ScanProfile, load_any_profile
from app.scanners.provenance import pinned_file
from app.scanners.semgrep import stage_rule
from app.triage.reconcile import reconcile_findings
from app.triage.sinks_python import locate_python_sinks
from app.workflows.scans.analysis import scan_language, scan_language_evidence
from app.workflows.scans.families import (
    COMPOSITION_VERSION,
    UNRESOLVED_DECISION,
    CompositeResult,
    FamilyResult,
    check_conservation,
    compose,
    scan_language_families,
)
from app.workflows.scans.results import LanguageResult
from tests.workflows.scans.test_legacy_golden import JS_SOURCE, js_locator, js_pipeline

# Line 3: a command sink. Lines 4 and 5: path sinks. Line 6: a path sink inside a command call.
SOURCE = (
    "import os\n"
    "from flask import request\n"
    "os.system(cmd)\n"
    "open(request.args['a'])\n"
    "open(request.args['b'])\n"
    "os.system('cat ' + open(request.args['c']).read())\n"
)
SNAPSHOT = "5" * 64
COMMAND = "command-injection-v0.3"
PATH = "path-traversal-v0.2"
PASS = "codeql-path-traversal"
STEP: dict[str, Any] = {"status": "completed", "exit_code": 0, "argv": ["tool"], "seconds": 1.5}


def _profile(profile_id: str) -> Any:
    settings = get_settings()
    return load_any_profile(settings.triage_root, settings.scan_profiles[profile_id])


def _region(line: int, text: str) -> dict[str, Any]:
    column = SOURCE.splitlines()[line - 1].index(text) + 1
    return {
        "startLine": line,
        "startColumn": column,
        "endLine": line,
        "endColumn": column + len(text),
    }


COMMAND_SINKS = locate_python_sinks("app.py", SOURCE)
COMMAND_ARGUMENTS: list[dict[str, Any]] = [dict(sink["args"][0]["span"]) for sink in COMMAND_SINKS]
# Path alerts: two plain sinks, one nested in the command call of line 6, and one reported
# on exactly the region of line 3's command argument.
PATH_REGIONS: dict[str, dict[str, Any]] = {
    "a": _region(4, "request.args['a']"),
    "b": _region(5, "request.args['b']"),
    "nested": _region(6, "request.args['c']"),
    "same": COMMAND_ARGUMENTS[0],
}


def _finding(raw_id: str, tool: str, rule_id: str, region: dict[str, Any], cwes: list[str]) -> Any:
    return {
        "raw_id": raw_id,
        "tool": tool,
        "snapshot_sha256": SNAPSHOT,
        "rule_id": rule_id,
        "reported_path": "app.py",
        "reported_region": dict(region),
        "reported_cwes": cwes,
        "message": "alert",
        "sink_identity": None,
        "mapping_status": "unresolved",
        "technical_verdict": "unresolved",
        "scope_verdict": "unresolved",
        "raw_result": {},
    }


@dataclasses.dataclass
class Tools:
    """Scripted scanners for SOURCE; every option changes one tool's output only."""

    semgrep_rule: str = "dangerous-system-call"
    # Semgrep prefixes a rule ID with the dotted path of the folder its rule file is staged in.
    semgrep_prefix: str = "tmp"
    # CodeQL's command-evidence query no longer reports the flows of its default query.
    command_refuted: bool = False
    command_evidence_step: str = "completed"
    database: str = "completed"
    # Path alerts the CWE-22 evidence query removes.
    path_hidden: tuple[str, ...] = ("b",)
    path_pass: str = "completed"
    path_rule: str = "st/cwe-22/none"
    extra_semgrep: tuple[tuple[str, dict[str, Any]], ...] = ()

    def pipeline(self, **kwargs: Any) -> PipelineResult:
        """The command member's tools: Semgrep, Bandit, CodeQL and both evidence steps."""
        output: Path = kwargs["output"]
        root: Path = kwargs["repository_root"]
        for index, rule in enumerate(kwargs["semgrep_rules"]):
            stage_rule(rule, output / f"rule-{index}.yaml", repository_root=root)
        shutil.copyfile(pinned_file(kwargs["bandit"]["config"], root), output / STAGED_CONFIG)
        codeql = self.database == "completed"
        failed = {"status": "failed", "error": "CodeQL extraction failed"}
        steps: dict[str, Any] = {
            "codeql-version": dict(STEP),
            "semgrep": dict(STEP),
            "bandit": dict(STEP),
            "codeql-create": dict(STEP) if codeql else {"status": "failed", "exit_code": 2},
            "codeql": dict(STEP) if codeql else failed,
            "semgrep-evidence": dict(STEP),
        }
        findings: list[Any] = []
        evidence: list[Any] = []
        for index, (sink, argument) in enumerate(
            zip(COMMAND_SINKS, COMMAND_ARGUMENTS, strict=True)
        ):
            findings.append(
                _finding(
                    f"semgrep:0:{index}",
                    "semgrep",
                    f"{self.semgrep_prefix}.{self.semgrep_rule}",
                    argument,
                    ["CWE-78"],
                )
            )
            findings.append(
                _finding(f"bandit:0:{index}", "bandit", "B605", dict(sink["span"]), ["cwe-78"])
            )
            for rule in ("st-cmd-flow-none", "st-cmd-flow-all"):
                evidence.append(
                    _finding(
                        f"semgrep-evidence:0:{len(evidence)}",
                        "semgrep-evidence",
                        f"tmp.semgrep-evidence.{rule}",
                        argument,
                        [],
                    )
                )
            if codeql:
                findings.append(
                    _finding(
                        f"codeql:0:{index}",
                        "codeql",
                        "py/command-line-injection",
                        argument,
                        ["cwe-078", "cwe-088"],
                    )
                )
        for index, (rule, region) in enumerate(self.extra_semgrep, start=len(COMMAND_SINKS)):
            findings.append(_finding(f"semgrep:0:{index}", "semgrep", rule, region, ["cwe-078"]))
        if codeql:
            steps["codeql-evidence"] = {**STEP, "status": self.command_evidence_step}
            rules = ["st/cwe-78/none"] + ([] if self.command_refuted else ["st/cwe-78/all"])
            for rule in rules:
                for argument in COMMAND_ARGUMENTS:
                    evidence.append(
                        _finding(
                            f"codeql-evidence:0:{len(evidence)}",
                            "codeql-evidence",
                            rule,
                            argument,
                            [],
                        )
                    )
        return PipelineResult(
            status="completed" if codeql else "partial",
            steps=steps,
            findings=findings,
            codeql_query_files=kwargs["codeql_query_sha256"] if codeql else None,
            codeql_pack_manifest="name: codeql/python-queries\n" if codeql else None,
            evidence_findings=evidence,
        )

    def _path_alerts(self, name: str) -> list[Any]:
        alerts = [(self.path_rule, region) for region in PATH_REGIONS.values()]
        alerts += [
            ("st/cwe-22/all", region)
            for key, region in PATH_REGIONS.items()
            if key not in self.path_hidden
        ]
        return [
            _finding(f"{name}:0:{index}", name, rule, region, ["cwe-022"])
            for index, (rule, region) in enumerate(alerts)
        ]

    def analyze(self, **kwargs: Any) -> tuple[Any, list[Any], bool]:
        """The CWE-22 pack analyzed on the database the command member created."""
        assert kwargs["name"] == PASS
        assert kwargs["query_pack"].as_posix().endswith("rules/codeql/path-traversal-v0.2")
        assert sorted(kwargs["queries"]) == ["queries/cwe22_all.ql", "queries/cwe22_none.ql"]
        if self.database != "completed":
            raise RuntimeError("No CodeQL database to run evidence queries on")
        if self.path_pass == "failed":
            raise RuntimeError("Evidence queries produced no SARIF output")
        alerts = self._path_alerts(kwargs["name"])
        record = {**STEP, "status": self.path_pass, "seconds": 7.25, "raw_findings": len(alerts)}
        return record, alerts, self.path_pass == "completed"

    def evidence_pipeline(self, **kwargs: Any) -> PipelineResult:
        """The same CWE-22 alerts as a scan with the path-traversal profile alone reports them."""
        assert kwargs["scanners"] == ["codeql"]
        usable = self.database == "completed" and self.path_pass != "failed"
        status = self.path_pass if usable else "failed"
        findings = self._path_alerts("codeql") if usable else []
        return PipelineResult(
            status=status,  # type: ignore[arg-type]
            steps={
                "codeql-create": dict(STEP),  # type: ignore[dict-item]
                "codeql": {**STEP, "status": status},  # type: ignore[typeddict-item]
            },
            findings=findings,
            codeql_query_files=kwargs["codeql_query_sha256"] if usable else None,
            codeql_pack_manifest=None,
        )


def _never_invoked(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("No external process runs in these tests")


def _workspace(tmp_path: Path, name: str, files: dict[str, str]) -> tuple[Path, Path]:
    source = tmp_path / name / "source"
    source.mkdir(parents=True)
    for relative, text in files.items():
        (source / relative).write_text(text, encoding="utf-8", newline="")
    output = tmp_path / name / "output"
    output.mkdir()
    return source, output


def _composite(tmp_path: Path, tools: Tools, **options: Any) -> CompositeResult:
    source, output = _workspace(tmp_path, "composite", {"app.py": SOURCE})
    return scan_language_families(
        "python",
        members=compose([_profile(COMMAND), _profile(PATH)]),
        settings=get_settings(),
        source=source,
        files=["app.py"],
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=tools.pipeline,
        invoke_fn=_never_invoked,
        analyze_fn=tools.analyze,
        **options,
    )


def _command_alone(tmp_path: Path, tools: Tools) -> LanguageResult:
    source, output = _workspace(tmp_path, "command-alone", {"app.py": SOURCE})
    return scan_language(
        "python",
        profile=_profile(COMMAND),
        settings=get_settings(),
        source=source,
        files=["app.py"],
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=tools.pipeline,
        invoke_fn=_never_invoked,
    )


def _path_alone(tmp_path: Path, tools: Tools) -> LanguageResult:
    source, output = _workspace(tmp_path, "path-alone", {"app.py": SOURCE})
    return scan_language_evidence(
        "python",
        profile=_profile(PATH),
        settings=get_settings(),
        source=source,
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=tools.evidence_pipeline,
        invoke_fn=_never_invoked,
    )


def _same(value: Any) -> Any:
    """Units or assessments with the shared-database pass's raw-ID prefix written as CodeQL's.

    This prefix is the only difference a composite scan may show against a single-family scan.
    """
    return json.loads(json.dumps(value).replace(f'"{PASS}:', '"codeql:'))


def _family(result: CompositeResult, name: str) -> Any:
    return next(family for family in result.families if family.family == name)


def _assert_equals_single_family_scans(
    result: CompositeResult, command: LanguageResult, path: LanguageResult
) -> None:
    ours = _family(result, "command-injection")
    assert (ours.status, ours.units, ours.assessments) == (
        command.pipeline.status,
        command.units,
        command.assessments,
    )
    theirs = _family(result, "path-traversal")
    assert theirs.status == path.pipeline.status
    assert _same(theirs.units) == path.units
    assert _same(theirs.assessments) == path.assessments
    assert theirs.result is None or theirs.result.unit_version == path.unit_version


def test_each_family_equals_its_single_family_scan(tmp_path):
    tools = Tools()
    result = _composite(tmp_path, tools)

    _assert_equals_single_family_scans(
        result, _command_alone(tmp_path, tools), _path_alone(tmp_path, tools)
    )
    assert result.status == "completed"
    command, path = _family(result, "command-injection"), _family(result, "path-traversal")
    assert (len(command.units), len(path.units)) == (2, 4)
    # The command family's raw IDs are untouched; only the shared-database pass has a prefix.
    assert {raw_id.split(":")[0] for raw_id in command.raw_finding_ids} == {
        "semgrep",
        "bandit",
        "codeql",
    }
    assert {raw_id.split(":")[0] for raw_id in path.raw_finding_ids} == {PASS}
    assert {f["tool"] for f in result.findings} == {"semgrep", "bandit", "codeql"}
    # Evidence-only results of the command member never become findings.
    assert not any("evidence" in f["raw_id"] for f in result.findings)


def test_every_finding_is_kept_once_and_no_unit_mixes_families(tmp_path):
    result = _composite(tmp_path, Tools())

    assert result.conservation == {
        "raw_findings": 13,
        "families": {
            "command-injection": {"routed": 6, "in_units": 6, "unranked": 0, "units": 2},
            "path-traversal": {"routed": 7, "in_units": 7, "unranked": 0, "units": 4},
        },
        "unassigned": {"routed": 0, "in_units": 0, "unranked": 0, "units": 0},
    }
    family_of = {record["raw_id"]: record["analysis_family"] for record in result.classification}
    assert len(family_of) == len(result.findings) == 13
    seen: list[str] = []
    for family in result.families:
        for unit in family.units:
            assert {family_of[raw_id] for raw_id in unit["raw_finding_ids"]} == {family.family}
            seen += unit["raw_finding_ids"]
    assert sorted(seen) == sorted(family_of)
    candidates = {
        family.family: {a["candidate"]["key"] for a in family.assessments}
        for family in result.families
    }
    assert not candidates["command-injection"] & candidates["path-traversal"]


def test_a_path_alert_inside_a_command_call_stays_in_the_path_family(tmp_path):
    result = _composite(tmp_path, Tools())
    nested = PATH_REGIONS["nested"]
    path = _family(result, "path-traversal")
    unit = next(u for u in path.units if u["reported_region"] == nested)
    assert unit["sink_kind"] == "codeql-path-injection-sink"

    command = _family(result, "command-injection")
    call = next(u for u in command.units if u["sink_span"]["startLine"] == 6)
    assert sorted(call["tools"]) == ["bandit", "codeql", "semgrep"]
    assert all(not raw_id.startswith(PASS) for raw_id in call["raw_finding_ids"])

    # Why routing comes first: the command reconciler, given that alert, merges it into the
    # os.system call, because the call's argument contains the reported region.
    foreign = _finding("codeql:9:9", "codeql", "st/cwe-22/none", nested, ["cwe-022"])
    merged = reconcile_findings([foreign], COMMAND_SINKS, {"app.py": SOURCE})
    assert (merged[0]["sink_kind"], merged[0]["argument_role"]) == ("os.system", "shell_command")


def test_two_families_on_the_same_region_are_two_units_with_their_own_policy(tmp_path):
    result = _composite(tmp_path, Tools())
    same = PATH_REGIONS["same"]
    command, path = _family(result, "command-injection"), _family(result, "path-traversal")
    command_unit = next(u for u in command.units if u["sink_span"]["startLine"] == 3)
    path_unit = next(u for u in path.units if u["reported_region"] == same)
    assert command_unit["unit_id"] != path_unit["unit_id"]

    by_unit = {a["unit_id"]: a for family in result.families for a in family.assessments}
    ours, theirs = by_unit[command_unit["unit_id"]], by_unit[path_unit["unit_id"]]
    command_profile, path_profile = _profile(COMMAND), _profile(PATH)
    assert (ours["policy_id"], ours["policy_sha256"]) == (
        "command-injection-priority",
        command_profile.policy_sha256,
    )
    assert ours["decision_id"].startswith("D")
    assert (theirs["policy_id"], theirs["policy_sha256"]) == (
        "cwe22-safety-evidence",
        path_profile.policy_sha256,
    )
    assert theirs["decision_id"] == "EV_KEPT_NO_PROOF"
    assert ours["candidate"]["key"] != theirs["candidate"]["key"]
    assert {a["decision_id"] for a in path.assessments} == {
        "EV_KEPT_NO_PROOF",
        "EV_HIDDEN_BY_EVIDENCE",
    }


def test_evidence_of_one_family_never_changes_the_other(tmp_path):
    audit = "subprocess-shell-true"
    base = _composite(tmp_path / "base", Tools(semgrep_rule=audit))
    # The path evidence query removes every path alert.
    all_hidden = _composite(
        tmp_path / "hidden", Tools(semgrep_rule=audit, path_hidden=tuple(PATH_REGIONS))
    )
    # CodeQL's command evidence removes every command flow.
    refuted = _composite(tmp_path / "refuted", Tools(semgrep_rule=audit, command_refuted=True))

    def dispositions(result: CompositeResult, family: str) -> list[str]:
        return [a["disposition"] for a in _family(result, family).assessments]

    assert dispositions(base, "command-injection") == ["review", "review"]
    assert dispositions(base, "path-traversal").count("filtered") == 1
    assert dispositions(all_hidden, "path-traversal") == ["filtered"] * 4
    assert _family(all_hidden, "command-injection").assessments == (
        _family(base, "command-injection").assessments
    )
    assert dispositions(refuted, "command-injection") == ["filtered", "filtered"]
    assert _family(refuted, "path-traversal").assessments == (
        _family(base, "path-traversal").assessments
    )
    rules = {a["adjudication"]["rule"] for a in _family(refuted, "command-injection").assessments}
    assert rules == {"G1_CODEQL_SAFETY_EVIDENCE"}


def test_without_evidence_nothing_is_filtered(tmp_path):
    # Every evidence query still reports every flow: no rule has anything to act on.
    result = _composite(tmp_path, Tools(path_hidden=()))
    for family in result.families:
        assert [a["disposition"] for a in family.assessments] == ["review"] * len(family.units)
    kept = {
        code
        for family in result.families
        for a in family.assessments
        for code in a["adjudication"]["kept_because"]
    }
    assert kept == {"evidence_query_still_reports_flow"}


@pytest.mark.parametrize("path_pass", ["failed", "partial"])
def test_an_unusable_path_pass_ranks_no_path_alert_and_leaves_the_command_family_alone(
    tmp_path, path_pass
):
    tools = Tools(path_pass=path_pass)
    result = _composite(tmp_path, tools)

    _assert_equals_single_family_scans(
        result, _command_alone(tmp_path, tools), _path_alone(tmp_path, tools)
    )
    path = _family(result, "path-traversal")
    assert (path.status, path.units, path.error) == (path_pass, [], None)
    assert result.status == "partial"
    # A partial pass still reported alerts: they stay on record, unranked, never hidden.
    routed = 7 if path_pass == "partial" else 0
    assert result.conservation["families"]["path-traversal"] == {
        "routed": routed,
        "in_units": 0,
        "unranked": routed,
        "units": 0,
    }
    assert len(result.findings) == 6 + routed
    assert result.steps[PASS]["status"] == path_pass


def test_a_failed_database_keeps_screening_alerts_and_filters_nothing(tmp_path):
    tools = Tools(database="failed")
    result = _composite(tmp_path, tools)

    _assert_equals_single_family_scans(
        result, _command_alone(tmp_path, tools), _path_alone(tmp_path, tools)
    )
    command, path = _family(result, "command-injection"), _family(result, "path-traversal")
    assert (command.status, path.status, result.status) == ("partial", "failed", "partial")
    assert {f["tool"] for f in result.findings} == {"semgrep", "bandit"}
    assert len(result.findings) == 4 and len(command.units) == 2
    for assessment in command.assessments:
        assert assessment["disposition"] == "review"
        assert assessment["adjudication"]["kept_because"] == ["run_incomplete"]
    assert "No CodeQL database" in result.steps[PASS]["error"]


def test_a_failed_command_evidence_step_only_stops_the_rule_that_needs_it(tmp_path):
    audit = "subprocess-shell-true"
    tools = Tools(semgrep_rule=audit, command_refuted=True, command_evidence_step="failed")
    result = _composite(tmp_path, tools)

    _assert_equals_single_family_scans(
        result, _command_alone(tmp_path, tools), _path_alone(tmp_path, tools)
    )
    command = _family(result, "command-injection")
    for assessment in command.assessments:
        assert assessment["disposition"] == "review"
        assert "evidence_step_failed" in assessment["adjudication"]["kept_because"]
    untouched = _composite(tmp_path / "base", Tools(semgrep_rule=audit))
    assert _family(result, "path-traversal").assessments == (
        _family(untouched, "path-traversal").assessments
    )
    assert result.status == "completed"


def test_an_unexpected_rule_fails_its_family_only_and_its_alerts_stay_on_record(tmp_path):
    tools = Tools(path_rule="st/cwe-22/other")
    result = _composite(tmp_path, tools)

    with pytest.raises(ValueError, match="Unexpected rule"):
        _path_alone(tmp_path, tools)
    path = _family(result, "path-traversal")
    assert (path.status, path.result, path.units) == ("failed", None, [])
    assert path.error is not None and "Unexpected rule" in path.error
    command = _family(result, "command-injection")
    assert command.assessments == _command_alone(tmp_path, tools).assessments
    assert result.status == "partial"

    strange = [r for r in result.classification if r["rule_id"] == "st/cwe-22/other"]
    assert len(strange) == 4
    for record in strange:
        # The pass ran only the path member's pack, so the family is known; the rule is not
        # one the member pins, so nothing is mapped. The tool's label is untouched.
        assert (record["analysis_family"], record["family_basis"]) == (
            "path-traversal",
            "pass_provenance",
        )
        assert record["mapped_cwes"] == [] and record["reported_cwes"] == ["cwe-022"]
    assert result.conservation["families"]["path-traversal"]["unranked"] == 7


def test_a_finding_without_a_family_is_kept_alone_at_priority_u(tmp_path):
    # Semgrep is declared to serve both families, so its alerts are routed by pinned rule.
    # One alert has a rule no member pins; it sits inside the os.system call of line 3.
    unknown = ("tmp.rules.custom-audit", COMMAND_ARGUMENTS[0])
    tools = Tools(extra_semgrep=(unknown,))
    shared = {"semgrep": ["command-injection", "path-traversal"]}
    result = _composite(tmp_path, tools, pass_members=shared)

    by_raw_id = {record["raw_id"]: record for record in result.classification}
    record = by_raw_id["semgrep:0:2"]
    assert (record["analysis_family"], record["family_status"]) == (None, "unresolved")
    assert record["unresolved_reason"] == "rule_not_claimed"
    assert record["reported_cwes"] == ["cwe-078"] and record["mapped_cwes"] == []
    # The pinned Semgrep rule is still routed, now by its rule instead of by its pass.
    assert by_raw_id["semgrep:0:0"]["family_basis"] == "pinned_rule_set"
    assert by_raw_id["semgrep:0:0"]["mapped_cwes"] == ["CWE-78"]

    (unit,) = result.unassigned_units
    (assessment,) = result.unassigned_assessments
    assert unit["raw_finding_ids"] == ["semgrep:0:2"] and unit["mapping_status"] == "unmapped"
    assert (assessment["priority"], assessment["disposition"], assessment["decision_id"]) == (
        "U",
        "review",
        UNRESOLVED_DECISION,
    )
    assert assessment["adjudication"]["rules"] == []
    assert assessment["adjudication"]["kept_because"] == ["rule_not_claimed"]
    assert assessment["finding_evidence"] == [record]
    assert result.conservation["unassigned"] == {
        "routed": 1,
        "in_units": 1,
        "unranked": 0,
        "units": 1,
    }
    # It is not merged into the command call it sits in, and no family lost anything else.
    command = _family(result, "command-injection")
    assert all("semgrep:0:2" not in unit["raw_finding_ids"] for unit in command.units)
    assert command.assessments == _command_alone(tmp_path, Tools()).assessments
    assert _same(_family(result, "path-traversal").assessments) == (
        _path_alone(tmp_path, Tools()).assessments
    )


def test_a_composite_scan_writes_its_record_and_each_familys_own_files(tmp_path):
    result = _composite(tmp_path, Tools())
    output = tmp_path / "composite" / "output"

    run = json.loads((output / "run.json").read_text(encoding="utf-8"))
    assert run["composition_version"] == COMPOSITION_VERSION
    assert [(m["family"], m["profile_id"], m["status"], m["units"]) for m in run["members"]] == [
        ("command-injection", COMMAND, "completed", 2),
        ("path-traversal", PATH, "completed", 4),
    ]
    assert run["members"][0]["profile_sha256"] == _profile(COMMAND).manifest_sha256
    assert run["conservation"] == result.conservation
    # Cost per step: what it is, whom it serves and how long it took.
    steps = {name: (step["kind"], step["serves"]) for name, step in run["steps"].items()}
    both = ["command-injection", "path-traversal"]
    assert steps["codeql-create"] == ("shared", both)
    assert steps["codeql"] == ("detection", ["command-injection"])
    assert steps["codeql-evidence"] == ("evidence", ["command-injection"])
    assert steps["sink-locator"] == ("locator", ["command-injection"])
    assert steps[PASS] == ("detection+evidence", ["path-traversal"])
    assert (run["steps"][PASS]["seconds"], run["steps"][PASS]["raw_findings"]) == (7.25, 7)

    assert json.loads((output / "findings.json").read_text(encoding="utf-8")) == result.findings
    assert len(json.loads((output / "classification.json").read_text(encoding="utf-8"))) == 13
    for family in result.families:
        folder = output / "families" / family.family
        assert json.loads((folder / "units.json").read_text(encoding="utf-8")) == family.units
        member_run = json.loads((folder / "run.json").read_text(encoding="utf-8"))
        assert member_run["profile_id"] == family.profile_id
    # The path member sees the shared database's steps as its own.
    path_run = json.loads(
        (output / "families" / "path-traversal" / "run.json").read_text(encoding="utf-8")
    )
    assert sorted(path_run["steps"]) == ["codeql", "codeql-create", "codeql-version"]
    assert not (output / "families" / "unassigned").exists()
    assert not (output / "units.json").exists()


def test_a_language_only_one_member_configures_is_scanned_by_that_member(tmp_path):
    def scan(name: str, composite: bool) -> Any:
        source, output = _workspace(tmp_path, name, {"index.js": JS_SOURCE})
        common: dict[str, Any] = {
            "settings": get_settings(),
            "source": source,
            "files": ["index.js"],
            "output": output,
            "snapshot_sha256": SNAPSHOT,
            "run_pipeline_fn": js_pipeline,
            "invoke_fn": js_locator(1),
        }
        if composite:
            members = compose([_profile(COMMAND), _profile(PATH)])
            return scan_language_families("javascript", members=members, **common)
        return scan_language("javascript", profile=_profile(COMMAND), **common)

    result, alone = scan("composite", True), scan("alone", False)
    assert [family.family for family in result.families] == ["command-injection"]
    (command,) = result.families
    assert (command.units, command.assessments) == (alone.units, alone.assessments)
    assert [a["disposition"] for a in command.assessments].count("filtered") == 1


def test_members_must_fit_one_tool_run(tmp_path):
    command, path = _profile(COMMAND), _profile(PATH)
    assert isinstance(command, ScanProfile) and isinstance(path, EvidenceProfile)
    # The primary member comes first whatever the order given.
    assert [m.family for m in compose([path, command])] == ["command-injection", "path-traversal"]
    with pytest.raises(ValueError, match="exactly one member that runs the scanners"):
        compose([path])
    with pytest.raises(ValueError, match="one member per analysis family"):
        compose([command, _profile("command-injection-v0.2")])
    with pytest.raises(ValueError, match="no analysis family"):
        compose([dataclasses.replace(command, profile_id="sql-injection-v0.1")])

    other_version = {"python": {**path.configs["python"], "codeql_version": "9.9.9"}}
    members = compose([command, dataclasses.replace(path, configs=other_version)])
    source, output = _workspace(tmp_path, "versions", {"app.py": SOURCE})
    arguments: dict[str, Any] = {
        "settings": get_settings(),
        "source": source,
        "files": ["app.py"],
        "output": output,
        "snapshot_sha256": SNAPSHOT,
        "run_pipeline_fn": _never_invoked,
        "invoke_fn": _never_invoked,
    }
    with pytest.raises(ValueError, match="different CodeQL versions: 2.27.1 and 9.9.9"):
        scan_language_families("python", members=members, **arguments)
    with pytest.raises(ValueError, match="no ruby configuration"):
        scan_language_families("ruby", members=compose([command, path]), **arguments)
    without_codeql = {"python": {**command.configs["python"], "scanners": ["semgrep", "bandit"]}}
    members = compose([dataclasses.replace(command, configs=without_codeql), path])
    with pytest.raises(ValueError, match="creates no CodeQL database"):
        scan_language_families("python", members=members, **arguments)


def test_conservation_rejects_lost_duplicated_and_misplaced_findings():
    findings = [{"raw_id": "a:0:0"}, {"raw_id": "a:0:1"}]

    def record(raw_id: str, family: str | None) -> Any:
        return {"raw_id": raw_id, "analysis_family": family}

    def family(name: str, units: list[dict[str, Any]]) -> Any:
        result = LanguageResult("python", None, {}, units, [])  # type: ignore[arg-type]
        return FamilyResult(name, None, "completed", None, result, [])

    classified = [record("a:0:0", "x"), record("a:0:1", "x")]
    whole = family("x", [{"raw_finding_ids": ["a:0:0", "a:0:1"]}])
    assert check_conservation(findings, classified, [whole], [])["families"]["x"] == {
        "routed": 2,
        "in_units": 2,
        "unranked": 0,
        "units": 1,
    }
    with pytest.raises(RuntimeError, match="missing=\\['a:0:1'\\]"):
        check_conservation(
            findings, classified, [family("x", [{"raw_finding_ids": ["a:0:0"]}])], []
        )
    with pytest.raises(RuntimeError, match="foreign=\\['b:0:0'\\]"):
        misplaced = family("x", [{"raw_finding_ids": ["a:0:0", "a:0:1", "b:0:0"]}])
        check_conservation(findings, classified, [misplaced], [])
    with pytest.raises(RuntimeError, match="duplicate raw IDs"):
        check_conservation([*findings, findings[0]], classified, [whole], [])
    with pytest.raises(RuntimeError, match="classify every finding exactly once"):
        check_conservation(findings, classified[:1], [whole], [])
    with pytest.raises(RuntimeError, match="without a member: \\['y'\\]"):
        check_conservation(findings, [record("a:0:0", "x"), record("a:0:1", "y")], [whole], [])
