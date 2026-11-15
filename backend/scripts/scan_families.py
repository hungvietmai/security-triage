"""Development CLI: scan one pinned source for several analysis families, and compare.

Runs inside the scanner worker image, without the database, the object store or the API:

    python -m scripts.scan_families run --case CASE.json --mode composite \
        --profiles command-injection-v0.3,path-traversal-v0.2 --output OUT/composite
    python -m scripts.scan_families run --case CASE.json --mode separate \
        --profiles command-injection-v0.3,path-traversal-v0.2 --output OUT/separate
    python -m scripts.scan_families compare --composite OUT/composite \
        --separate OUT/separate --output OUT/comparison.json

"composite" runs the scanners once and creates one CodeQL database (app.workflows.scans.families).
"separate" scans with each profile alone, through the entry points the worker uses today.
"compare" checks that every family of the composite scan equals its single-family scan and that
no finding was lost, duplicated or moved to another family. It exits 1 when they differ.

CASE.json is a pinned source manifest (experiments/cases/*.json). The scanned source and the
CodeQL databases are removed when a run ends; scanner output stays in the output folder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from app.core.config import Settings, get_settings
from app.scanners.acquisition import (
    MAX_ARCHIVE,
    MAX_FILES,
    MAX_UNPACKED,
    SOURCE_EXTENSIONS,
    AcquiredSource,
    AcquisitionLimits,
    acquire_source,
)
from app.scanners.codeql import run_codeql_evidence
from app.scanners.pipeline import run_pipeline
from app.scanners.process import InvokeCallable, invoke
from app.scanners.profile import DetectionProfile, EvidenceProfile, load_member_profile
from app.workflows.scans.analysis import RunPipeline, scan_language, scan_language_evidence
from app.workflows.scans.detection import scan_language_detection
from app.workflows.scans.families import (
    FAMILY_OF_PROFILE,
    PASS_PREFIX,
    UNASSIGNED,
    AnalyzePass,
    compose,
    scan_language_families,
)

Acquire = Callable[..., AcquiredSource]
MEMBER_FILES = ("units.json", "assessments.json", "findings.json")


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _steps(steps: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """What a step cost and found; argv and logs stay in the step's own files."""
    keys = ("status", "seconds", "raw_findings", "kind", "serves", "error")
    return {name: {key: step[key] for key in keys if key in step} for name, step in steps.items()}


def _languages(configs: Mapping[str, Any], files: Sequence[str], only: Sequence[str]) -> list[str]:
    return [
        language
        for language in configs
        if (not only or language in only)
        and any(Path(name).suffix.lower() in SOURCE_EXTENSIONS[language] for name in files)
    ]


def run(
    case: Mapping[str, Any],
    profile_ids: Sequence[str],
    mode: str,
    output: Path,
    *,
    source_archive: Path | None = None,
    languages: Sequence[str] = (),
    settings: Settings | None = None,
    acquire_fn: Acquire = acquire_source,
    run_pipeline_fn: RunPipeline = run_pipeline,
    invoke_fn: InvokeCallable = invoke,
    analyze_fn: AnalyzePass = run_codeql_evidence,
) -> dict[str, Any]:
    """Scan the case's source in one mode and return (and write) the run's summary."""
    if mode not in {"composite", "separate"}:
        raise ValueError(f"Unknown mode: {mode}")
    settings = settings or get_settings()
    members = compose(
        [
            load_member_profile(settings.triage_root, settings.scan_profiles[profile_id])
            for profile_id in profile_ids
        ]
    )
    output.mkdir(parents=True, exist_ok=False)
    limits = AcquisitionLimits(MAX_ARCHIVE, MAX_UNPACKED, MAX_FILES)
    runs: list[dict[str, Any]] = []
    snapshots: set[str] = set()

    def acquire(name: str) -> tuple[AcquiredSource, Path]:
        folder = output / name
        folder.mkdir(parents=True)
        acquired = acquire_fn(case, folder, source_archive=source_archive, limits=limits)
        snapshots.add(acquired.snapshot_sha256)
        return acquired, folder

    def finish(folder: Path, databases: Sequence[Path]) -> None:
        # The scanned source and the databases never stay with the results.
        for path in (folder / "source", *databases):
            shutil.rmtree(path, ignore_errors=True)
        (folder / "source.tgz").unlink(missing_ok=True)

    def record(family: str | None, language: str, status: str, begin: float, steps: Any) -> None:
        runs.append(
            {
                "family": family,
                "language": language,
                "status": status,
                "wall_seconds": round(time.monotonic() - begin, 3),
                "steps": _steps(steps),
            }
        )

    if mode == "composite":
        acquired, folder = acquire("acquisition")
        configs = members[0].profile.configs
        scanned = _languages(configs, acquired.source_files, languages)
        for language in scanned:
            target = output / language
            target.mkdir()
            begin = time.monotonic()
            result = scan_language_families(
                language,
                members=members,
                settings=settings,
                source=acquired.source_path,
                files=acquired.source_files,
                output=target,
                snapshot_sha256=acquired.snapshot_sha256,
                run_pipeline_fn=run_pipeline_fn,
                invoke_fn=invoke_fn,
                analyze_fn=analyze_fn,
            )
            record(None, language, result.status, begin, result.steps)
        finish(folder, [output / language / "codeql-db" for language in scanned])
    else:
        for member in members:
            acquired, folder = acquire(f"{member.family}/acquisition")
            scanned = _languages(member.profile.configs, acquired.source_files, languages)
            for language in scanned:
                target = output / member.family / language
                target.mkdir()
                common: dict[str, Any] = {
                    "settings": settings,
                    "source": acquired.source_path,
                    "output": target,
                    "snapshot_sha256": acquired.snapshot_sha256,
                    "run_pipeline_fn": run_pipeline_fn,
                    "invoke_fn": invoke_fn,
                }
                begin = time.monotonic()
                if isinstance(member.profile, EvidenceProfile):
                    alone = scan_language_evidence(language, profile=member.profile, **common)
                elif isinstance(member.profile, DetectionProfile):
                    # Alone, the member creates its own database and runs the same queries.
                    alone = scan_language_detection(
                        language, profile=member.profile, family=member.family, **common
                    )
                else:
                    alone = scan_language(
                        language, profile=member.profile, files=acquired.source_files, **common
                    )
                record(member.family, language, alone.pipeline.status, begin, alone.pipeline.steps)
            finish(folder, [output / member.family / lang / "codeql-db" for lang in scanned])

    if len(snapshots) != 1:
        raise RuntimeError("Members were not scanned from the same source bytes")
    summary = {
        "mode": mode,
        "case_id": case.get("case_id"),
        "snapshot_sha256": snapshots.pop(),
        "profiles": {m.profile.profile_id: m.profile.manifest_sha256 for m in members},
        "scanner_workers": settings.scanner_workers,
        "runs": runs,
    }
    _write_json(output / "scan.json", summary)
    return summary


def _content_keys(findings: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """A raw ID's position-independent name: what was reported where, not in which order.

    Raw IDs number a tool's results in output order, which two runs need not share. Alerts
    that agree on tool, rule, location and message get a counter, so duplicates stay distinct.
    """
    described = sorted(
        (
            json.dumps(
                [
                    finding["tool"],
                    finding["rule_id"],
                    finding["reported_path"],
                    finding["reported_region"],
                    finding["message"],
                ],
                sort_keys=True,
                ensure_ascii=False,
            ),
            finding["raw_id"],
        )
        for finding in findings
    )
    seen: Counter[str] = Counter()
    keys = {}
    for content, raw_id in described:
        digest = hashlib.sha256(content.encode()).hexdigest()[:16]
        keys[raw_id] = f"finding:{digest}:{seen[content]}"
        seen[content] += 1
    return keys


def _canonical(value: Any, keys: Mapping[str, str]) -> Any:
    """`value` with raw IDs replaced by content keys and ID-ordered lists put in key order."""
    if isinstance(value, str):
        return keys.get(value, value)
    if isinstance(value, dict):
        return {name: _canonical(item, keys) for name, item in value.items()}
    if isinstance(value, list):
        items = [_canonical(item, keys) for item in value]
        if items and all(isinstance(item, dict) and "raw_id" in item for item in items):
            return sorted(items, key=lambda item: str(item["raw_id"]))
        if items and all(isinstance(item, str) and item.startswith("finding:") for item in items):
            return sorted(items)
        return items
    return value


def _staging_prefixes(assessments: Sequence[Mapping[str, Any]]) -> list[str]:
    """Rule-ID prefixes Semgrep made from the folder its staged rule files were in.

    Semgrep reports "<dotted path of the rule file's folder>.<rule ID>". Two scans write to two
    folders, so the same pinned rule has two reported IDs. The claim records hold both the
    reported and the pinned ID, which gives the prefix without knowing the folder.
    """
    prefixes = set()
    for assessment in assessments:
        for record in assessment.get("finding_evidence", []):
            reported, pinned = record.get("rule_id"), record.get("canonical_rule_id")
            if (
                isinstance(reported, str)
                and isinstance(pinned, str)
                and reported.endswith("." + pinned)
            ):
                prefixes.add(reported[: -len(pinned)])
    return sorted(prefixes, key=len, reverse=True)


def _without_run_details(value: Any, prefixes: Sequence[str]) -> Any:
    """`value` without what only records where and how a tool ran, never what it found.

    Removed: Semgrep's staging-folder prefix of a rule ID, and a SARIF artifact's index into
    the run's own artifact table (the artifact's path stays).
    """
    if isinstance(value, str):
        for prefix in prefixes:
            if value.startswith(prefix):
                return value[len(prefix) :]
        return value
    if isinstance(value, dict):
        return {
            name: _without_run_details(item, prefixes)
            for name, item in value.items()
            if not (name == "index" and "uri" in value)
        }
    if isinstance(value, list):
        return [_without_run_details(item, prefixes) for item in value]
    return value


def _raw_results(findings: Sequence[Mapping[str, Any]], keys: Mapping[str, str]) -> dict[str, str]:
    return {
        keys[finding["raw_id"]]: json.dumps(finding["raw_result"], sort_keys=True)
        for finding in findings
    }


def _compare_family(family: str, language: str, composite: Path, separate: Path) -> dict[str, Any]:
    ours, theirs = composite / language / "families" / family, separate / family / language
    report: dict[str, Any] = {"family": family, "language": language}
    statuses = []
    for folder in (ours, theirs):
        run_file = folder / "run.json"
        statuses.append(_read_json(run_file)["status"] if run_file.is_file() else "failed")
    report["status"] = {"composite": statuses[0], "separate": statuses[1]}
    loaded: list[dict[str, Any] | None] = []
    for folder in (ours, theirs):
        if not all((folder / name).is_file() for name in MEMBER_FILES):
            loaded.append(None)
            continue
        units, assessments, written = (_read_json(folder / name) for name in MEMBER_FILES)
        prefixes = _staging_prefixes(assessments)
        findings = _without_run_details(written, prefixes)
        units = _without_run_details(units, prefixes)
        assessments = _without_run_details(assessments, prefixes)
        keys = _content_keys(findings)
        loaded.append(
            {
                "units": _canonical(units, keys),
                "assessments": _canonical(assessments, keys),
                "raw_results": _raw_results(findings, keys),
                "raw_results_as_written": _raw_results(written, keys),
                "prefixes": prefixes,
                "findings": len(findings),
                "filtered": sum(a.get("disposition") == "filtered" for a in assessments),
                "priorities": dict(sorted(Counter(a["priority"] for a in assessments).items())),
                # A filtered assessment must name the rule and carry the evidence it rests on.
                "filtered_without_evidence": sum(
                    a.get("disposition") == "filtered"
                    and not (a["adjudication"]["rules"] and a["adjudication"]["evidence"])
                    for a in assessments
                ),
            }
        )
    mine, alone = loaded
    if mine is None or alone is None:
        # A member that failed wrote no result files; both sides must have failed alike.
        report["equal"] = mine is None and alone is None and statuses[0] == statuses[1]
        report["note"] = "no result files on at least one side"
        return report
    for name in ("findings", "filtered", "priorities", "filtered_without_evidence"):
        report[name] = {"composite": mine[name], "separate": alone[name]}
    report["units"] = {"composite": len(mine["units"]), "separate": len(alone["units"])}
    report["units_equal"] = mine["units"] == alone["units"]
    report["assessments_equal"] = mine["assessments"] == alone["assessments"]
    report["same_findings"] = sorted(mine["raw_results"]) == sorted(alone["raw_results"])
    report["raw_results_equal"] = mine["raw_results"] == alone["raw_results"]
    # How many alerts differ byte for byte before the run details are set aside, and why.
    as_written = (mine["raw_results_as_written"], alone["raw_results_as_written"])
    report["raw_results_differing_as_written"] = sum(
        as_written[0][key] != as_written[1].get(key) for key in as_written[0]
    )
    report["semgrep_rule_id_prefixes"] = {
        "composite": mine["prefixes"],
        "separate": alone["prefixes"],
    }
    their_units = {unit["unit_id"]: unit for unit in alone["units"]}
    our_units = {unit["unit_id"]: unit for unit in mine["units"]}
    report["unit_ids_only_in_composite"] = sorted(set(our_units) - set(their_units))
    report["unit_ids_only_in_separate"] = sorted(set(their_units) - set(our_units))
    report["equal"] = (
        statuses[0] == statuses[1]
        and report["units_equal"]
        and report["assessments_equal"]
        and report["same_findings"]
    )
    return report


def _conservation(folder: Path) -> dict[str, Any]:
    """Recount, from the composite scan's files alone, where every finding went."""
    findings = _read_json(folder / "findings.json")
    classification = _read_json(folder / "classification.json")
    family_of = {record["raw_id"]: record["analysis_family"] for record in classification}
    placed: Counter[str] = Counter()
    mixed = 0
    foreign = 0
    # A member's own units are under families/; units the composition made for findings no
    # member ranked are under held/, by the family they are held for.
    folders = [
        path
        for parent in ("families", "held")
        if (folder / parent).is_dir()
        for path in sorted((folder / parent).iterdir())
        if path.is_dir()
    ]
    for path in folders:
        units_file = path / "units.json"
        for unit in _read_json(units_file) if units_file.is_file() else []:
            owners = {family_of[raw_id] for raw_id in unit["raw_finding_ids"]}
            mixed += len(owners) > 1
            foreign += owners != {None if path.name == UNASSIGNED else path.name}
            placed.update(unit["raw_finding_ids"])
    raw_ids = [finding["raw_id"] for finding in findings]
    return {
        "raw_findings": len(raw_ids),
        "classified": len(family_of),
        "by_family": dict(Counter(str(family) for family in family_of.values())),
        "in_exactly_one_unit": sum(placed[raw_id] == 1 for raw_id in raw_ids),
        "in_several_units": sum(placed[raw_id] > 1 for raw_id in raw_ids),
        "in_no_unit": sum(placed[raw_id] == 0 for raw_id in raw_ids),
        "units_mixing_families": mixed,
        "units_holding_another_familys_finding": foreign,
        "unresolved": sum(record["family_status"] == "unresolved" for record in classification),
        "labels_kept": all(
            record["reported_cwes"] == finding["reported_cwes"]
            for record, finding in zip(classification, findings, strict=True)
        ),
        "evidence_only_results_as_findings": sum(
            raw_id.split(":")[0].endswith("-evidence") for raw_id in raw_ids
        ),
    }


def _seconds(runs: Sequence[Mapping[str, Any]], language: str) -> dict[str, Any]:
    steps: dict[str, float] = {}
    wall = 0.0
    for scan in runs:
        if scan["language"] != language:
            continue
        wall += scan["wall_seconds"]
        prefix = f"{scan['family']}/" if scan["family"] else ""
        for name, step in scan["steps"].items():
            if "seconds" in step:
                steps[prefix + name] = step["seconds"]
    creates = [seconds for name, seconds in steps.items() if name.endswith("codeql-create")]
    return {
        "wall_seconds": round(wall, 3),
        "step_seconds": round(sum(steps.values()), 3),
        "database_creations": len(creates),
        "database_seconds": round(sum(creates), 3),
        "steps": steps,
    }


def compare(composite: Path, separate: Path) -> dict[str, Any]:
    """Whether the composite scan equals the single-family scans, family by family."""
    ours, theirs = _read_json(composite / "scan.json"), _read_json(separate / "scan.json")
    if (ours["mode"], theirs["mode"]) != ("composite", "separate"):
        raise ValueError("compare needs one composite run and one separate run")
    families = [FAMILY_OF_PROFILE[profile_id] for profile_id in ours["profiles"]]
    report: dict[str, Any] = {
        "same_snapshot": ours["snapshot_sha256"] == theirs["snapshot_sha256"],
        "same_profiles": ours["profiles"] == theirs["profiles"],
        "snapshot_sha256": ours["snapshot_sha256"],
        "profiles": ours["profiles"],
        "allowed_differences": [
            f"raw IDs of a shared-database pass start with '{PASS_PREFIX}<family>' instead of "
            "'codeql'; findings are matched by tool, rule, location and message",
            "a shared-database member has no version or database step of its own",
            "Semgrep prefixes a rule ID with the folder of its staged rule file, which differs "
            "between two output folders; the prefix is removed before comparing",
            "a SARIF artifact's index into its run's artifact table is ignored; its path is not",
        ],
        "families": [],
        "conservation": {},
        "cost": {},
    }
    for scan in ours["runs"]:
        language = scan["language"]
        present = {r["family"] for r in theirs["runs"] if r["language"] == language}
        for family in families:
            if family in present or (composite / language / "families" / family).is_dir():
                report["families"].append(_compare_family(family, language, composite, separate))
        report["conservation"][language] = _conservation(composite / language)
        report["cost"][language] = {
            "composite": _seconds(ours["runs"], language),
            "separate": _seconds(theirs["runs"], language),
        }
    kept = report["conservation"].values()
    report["equivalent"] = bool(
        report["same_snapshot"]
        and report["same_profiles"]
        and report["families"]
        and all(family["equal"] for family in report["families"])
        and all(
            c["in_several_units"] == 0
            and c["units_mixing_families"] == 0
            and c["units_holding_another_familys_finding"] == 0
            and c["classified"] == c["raw_findings"]
            and c["labels_kept"]
            and c["evidence_only_results_as_findings"] == 0
            for c in kept
        )
    )
    return report


def _label(scan: Mapping[str, Any]) -> str:
    return f"{scan['language']}/{scan['family'] or 'composite'}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("run", help="scan one pinned source")
    scan.add_argument("--case", type=Path, required=True)
    scan.add_argument("--profiles", required=True, help="comma-separated profile IDs")
    scan.add_argument("--mode", choices=("composite", "separate"), required=True)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--source-archive", type=Path, help="reuse an archive with the pinned hash")
    scan.add_argument("--languages", default="", help="comma-separated; default: all")
    check = commands.add_parser("compare", help="compare a composite with a separate run")
    check.add_argument("--composite", type=Path, required=True)
    check.add_argument("--separate", type=Path, required=True)
    check.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    if args.command == "run":
        summary = run(
            _read_json(args.case),
            [name for name in args.profiles.split(",") if name],
            args.mode,
            args.output.resolve(),
            source_archive=args.source_archive,
            languages=[name for name in args.languages.split(",") if name],
        )
        print(json.dumps({_label(scan): scan["status"] for scan in summary["runs"]}))
        return 0
    report = compare(args.composite.resolve(), args.separate.resolve())
    if args.output is not None:
        _write_json(args.output, report)
    print(json.dumps({"equivalent": report["equivalent"]}))
    return 0 if report["equivalent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
