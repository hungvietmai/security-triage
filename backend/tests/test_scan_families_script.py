"""The development CLI that scans a source for several families and compares the two modes.

Scanners and source acquisition are scripted; the scan entry points and the comparison are real.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from app.scanners.acquisition import AcquiredSource
from scripts import scan_families
from tests.workflows.scans.test_families import COMMAND, PATH, SNAPSHOT, SOURCE, Tools

PROFILES = [COMMAND, PATH]
CASE = {"case_id": "synthetic-two-families"}


def _acquire(case: Any, folder: Path, *, source_archive: Any, limits: Any) -> AcquiredSource:
    source = folder / "source"
    source.mkdir()
    (source / "app.py").write_text(SOURCE, encoding="utf-8", newline="")
    (source / "notes.txt").write_text("not a source file\n", encoding="utf-8")
    (folder / "source.tgz").write_bytes(b"archive")
    return AcquiredSource(
        source_path=source,
        archive_path=folder / "source.tgz",
        snapshot_sha256=SNAPSHOT,
        source_files=["app.py", "notes.txt"],
        transport="test",
        seconds=0.0,
    )


def _never_invoked(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("No external process runs in these tests")


def _run(tmp_path: Path, mode: str, tools: Tools, name: str | None = None) -> Path:
    def pipeline(**kwargs: Any) -> Any:
        # Alone, the path member runs its own CodeQL pipeline; the command member the full one.
        alone = kwargs["scanners"] == ["codeql"]
        return tools.evidence_pipeline(**kwargs) if alone else tools.pipeline(**kwargs)

    output = tmp_path / (name or mode)
    scan_families.run(
        CASE,
        PROFILES,
        mode,
        output,
        acquire_fn=_acquire,
        run_pipeline_fn=pipeline,
        invoke_fn=_never_invoked,
        analyze_fn=tools.analyze,
    )
    return output


def test_both_modes_scan_the_same_source_and_compare_as_equivalent(tmp_path):
    composite = _run(tmp_path, "composite", Tools())
    separate = _run(tmp_path, "separate", Tools())

    summary = json.loads((composite / "scan.json").read_text(encoding="utf-8"))
    assert (summary["mode"], summary["case_id"], summary["snapshot_sha256"]) == (
        "composite",
        "synthetic-two-families",
        SNAPSHOT,
    )
    assert list(summary["profiles"]) == PROFILES
    (scan,) = summary["runs"]
    assert (scan["family"], scan["language"], scan["status"]) == (None, "python", "completed")
    assert scan["steps"]["codeql-path-traversal"] == {
        "status": "completed",
        "seconds": 7.25,
        "raw_findings": 7,
        "kind": "detection+evidence",
        "serves": ["path-traversal"],
    }
    alone = json.loads((separate / "scan.json").read_text(encoding="utf-8"))
    assert [(r["family"], r["language"], r["status"]) for r in alone["runs"]] == [
        ("command-injection", "python", "completed"),
        ("path-traversal", "python", "completed"),
    ]
    # The scanned source never stays with the results.
    for folder in (composite / "acquisition", separate / "command-injection" / "acquisition"):
        assert folder.is_dir() and not list(folder.iterdir())

    report = scan_families.compare(composite, separate)
    assert report["equivalent"] is True
    assert [(f["family"], f["equal"], f["units"]) for f in report["families"]] == [
        ("command-injection", True, {"composite": 2, "separate": 2}),
        ("path-traversal", True, {"composite": 4, "separate": 4}),
    ]
    path = report["families"][1]
    assert path["filtered"] == {"composite": 1, "separate": 1}
    assert path["filtered_without_evidence"] == {"composite": 0, "separate": 0}
    assert path["raw_results_equal"] and path["same_findings"]
    assert report["conservation"]["python"] == {
        "raw_findings": 13,
        "classified": 13,
        "by_family": {"command-injection": 6, "path-traversal": 7},
        "in_exactly_one_unit": 13,
        "in_several_units": 0,
        "in_no_unit": 0,
        "units_mixing_families": 0,
        "units_holding_another_familys_finding": 0,
        "unresolved": 0,
        "labels_kept": True,
        "evidence_only_results_as_findings": 0,
    }
    cost = report["cost"]["python"]
    assert (cost["composite"]["database_creations"], cost["separate"]["database_creations"]) == (
        1,
        2,
    )
    assert cost["composite"]["steps"]["codeql-path-traversal"] == 7.25
    assert "path-traversal/codeql" in cost["separate"]["steps"]


def test_alerts_are_matched_by_content_not_by_the_order_a_tool_printed_them(tmp_path):
    class Reordered(Tools):
        def _path_alerts(self, name: str) -> list[Any]:
            alerts = super()._path_alerts(name)
            if name != "codeql":
                return alerts
            # The single-family run prints its results in the opposite order.
            return [
                {**alert, "raw_id": f"codeql:0:{index}"}
                for index, alert in enumerate(reversed(alerts))
            ]

    composite = _run(tmp_path, "composite", Tools())
    separate = _run(tmp_path, "separate", Reordered())
    assert scan_families.compare(composite, separate)["equivalent"] is True


def test_details_of_where_a_tool_ran_are_not_differences(tmp_path):
    # Two output folders: Semgrep reports the same pinned rule under two prefixed IDs.
    composite = _run(tmp_path, "composite", Tools(semgrep_prefix="out.composite.python"))
    separate = _run(tmp_path, "separate", Tools(semgrep_prefix="out.separate.command.python"))
    # A SARIF artifact index is a position in one run's artifact table.
    findings_file = separate / "path-traversal" / "python" / "findings.json"
    findings = json.loads(findings_file.read_text(encoding="utf-8"))
    findings[0]["raw_result"] = {
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py", "index": 7}}}]
    }
    findings_file.write_text(json.dumps(findings), encoding="utf-8")
    mine_file = composite / "python" / "families" / "path-traversal" / "findings.json"
    mine = json.loads(mine_file.read_text(encoding="utf-8"))
    mine[0]["raw_result"] = {
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py", "index": 3}}}]
    }
    mine_file.write_text(json.dumps(mine), encoding="utf-8")

    report = scan_families.compare(composite, separate)
    assert report["equivalent"] is True
    command, path = report["families"]
    assert command["semgrep_rule_id_prefixes"] == {
        "composite": ["out.composite.python."],
        "separate": ["out.separate.command.python."],
    }
    assert (command["raw_results_equal"], command["raw_results_differing_as_written"]) == (True, 0)
    assert (path["raw_results_equal"], path["raw_results_differing_as_written"]) == (True, 1)

    # A different artifact path is a different alert, not a run detail.
    mine[0]["raw_result"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "b.py"
    mine_file.write_text(json.dumps(mine), encoding="utf-8")
    changed = scan_families.compare(composite, separate)["families"][1]
    assert changed["raw_results_equal"] is False


def test_a_family_that_differs_from_its_single_family_scan_is_reported(tmp_path, capsys):
    composite = _run(tmp_path, "composite", Tools())
    # The single-family run's evidence removes every path alert; the composite one's did not.
    separate = _run(tmp_path, "separate", Tools(path_hidden=("a", "b", "nested", "same")))

    report = scan_families.compare(composite, separate)
    assert report["equivalent"] is False
    command, path = report["families"]
    assert command["equal"] is True
    assert (path["equal"], path["units_equal"], path["assessments_equal"]) == (False, False, False)
    assert path["filtered"] == {"composite": 1, "separate": 4}
    assert path["same_findings"] is False

    target = tmp_path / "comparison.json"
    arguments = ["compare", "--composite", str(composite), "--separate", str(separate)]
    assert scan_families.main([*arguments, "--output", str(target)]) == 1
    assert json.loads(target.read_text(encoding="utf-8"))["equivalent"] is False
    assert json.loads(capsys.readouterr().out) == {"equivalent": False}
    with pytest.raises(ValueError, match="one composite run and one separate run"):
        scan_families.compare(separate, composite)


def test_a_finding_moved_to_another_familys_unit_is_not_equivalent(tmp_path):
    composite = _run(tmp_path, "composite", Tools())
    separate = _run(tmp_path, "separate", Tools())
    units_file = composite / "python" / "families" / "command-injection" / "units.json"
    units = json.loads(units_file.read_text(encoding="utf-8"))
    units[0]["raw_finding_ids"].append("codeql-path-traversal:0:0")
    units_file.write_text(json.dumps(units), encoding="utf-8")

    report = scan_families.compare(composite, separate)
    assert report["equivalent"] is False
    conservation = report["conservation"]["python"]
    assert conservation["units_mixing_families"] == 1
    assert conservation["in_several_units"] == 1


def test_a_member_that_fails_in_both_modes_is_equal_and_one_that_fails_in_one_is_not(tmp_path):
    failing = Tools(path_pass="failed")
    composite = _run(tmp_path, "composite", failing)
    separate = _run(tmp_path, "separate", failing)
    report = scan_families.compare(composite, separate)
    path = report["families"][1]
    assert (path["status"], path["equal"]) == (
        {"composite": "failed", "separate": "failed"},
        True,
    )
    assert report["equivalent"] is True

    working = _run(tmp_path, "separate", Tools(), name="separate-working")
    assert scan_families.compare(composite, working)["equivalent"] is False


def test_a_member_whose_handler_raised_leaves_no_files_and_is_compared_by_status(tmp_path):
    composite = _run(tmp_path, "composite", Tools(path_rule="st/cwe-22/other"))
    separate = _run(tmp_path, "separate", Tools())
    path = scan_families.compare(composite, separate)["families"][1]
    assert path["equal"] is False and path["note"] == "no result files on at least one side"
    assert path["status"] == {"composite": "failed", "separate": "completed"}


def test_run_refuses_unknown_modes_existing_output_and_differing_sources(tmp_path):
    with pytest.raises(ValueError, match="Unknown mode"):
        scan_families.run(CASE, PROFILES, "both", tmp_path / "x")
    (tmp_path / "taken").mkdir()
    with pytest.raises(FileExistsError):
        scan_families.run(CASE, PROFILES, "composite", tmp_path / "taken", acquire_fn=_acquire)

    hashes = iter(["1" * 64, "2" * 64])

    def changing(case: Any, folder: Path, **kwargs: Any) -> AcquiredSource:
        acquired = _acquire(case, folder, **kwargs)
        return AcquiredSource(
            acquired.source_path, acquired.archive_path, next(hashes), [], "test", 0.0
        )

    with pytest.raises(RuntimeError, match="same source bytes"):
        scan_families.run(CASE, PROFILES, "separate", tmp_path / "y", acquire_fn=changing)


def test_languages_can_be_limited_and_the_command_line_passes_its_options(
    tmp_path, monkeypatch, capsys
):
    output = tmp_path / "none"
    summary = scan_families.run(
        CASE, PROFILES, "composite", output, languages=["javascript"], acquire_fn=_acquire
    )
    assert summary["runs"] == []

    case = tmp_path / "case.json"
    case.write_text(json.dumps(CASE), encoding="utf-8")
    calls: list[Any] = []

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return {"runs": [{"language": "python", "family": None, "status": "completed"}]}

    monkeypatch.setattr(scan_families, "run", fake_run)
    arguments = ["run", "--case", str(case), "--profiles", ",".join(PROFILES)]
    arguments += ["--mode", "composite", "--output", str(tmp_path / "out")]
    arguments += ["--languages", "python", "--source-archive", str(tmp_path / "a.tgz")]
    assert scan_families.main(arguments) == 0
    ((args, kwargs),) = calls
    assert args[:3] == (CASE, PROFILES, "composite")
    assert args[3] == (tmp_path / "out").resolve()
    assert kwargs == {"source_archive": tmp_path / "a.tgz", "languages": ["python"]}
    assert json.loads(capsys.readouterr().out) == {"python/composite": "completed"}
