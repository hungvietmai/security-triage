"""Package completed development outputs without reinterpreting frozen Wave C results.

Run from repository root after both phases finish. Existing packaged directories
are rejected. Labels are joined after scanning and remain exploratory.
"""

import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import shutil
from datetime import datetime, timezone


def load(path):
    return json.loads(path.read_bytes())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--wave", required=True)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    fixture = (root / args.fixture).resolve()
    wave = (root / args.wave).resolve()
    if not all(path.is_relative_to(root / "artifacts/v021-normalization") for path in (fixture, wave)):
        parser.error("Inputs must be development runs under artifacts/v021-normalization")
    target = root / "experiments/v021-normalization/results/round-001"
    f_run, w_run = load(fixture / "run.json"), load(wave / "run.json")
    scored = load(fixture / "fixture-report.json")
    if f_run["status"] != "completed" or w_run["status"] != "completed" or not scored["passed"]:
        raise ValueError("Cannot package an incomplete or failed round as completed")
    if len(w_run["repositories"]) != 7 or not all(row["original_unchanged"] and not row["subset_violations"] for row in w_run["repositories"]):
        raise ValueError("Development DB comparison failed")
    file_mappings = []

    def copy(source, destination):
        if destination.exists():
            raise ValueError(f"Packaged output already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if sha(source) != sha(destination):
            raise ValueError("Copy checksum mismatch")
        file_mappings.append({"original": source.relative_to(root).as_posix(),
                              "packaged": destination.relative_to(root).as_posix(),
                              "sha256": sha(source)})

    for folder in ("fixture", "wave"):
        (target / folder).mkdir(exist_ok=False)
    for path in fixture.iterdir():
        if path.is_file() and (path.suffix in (".json", ".sarif", ".log")):
            copy(path, target / "fixture" / path.name)
    for path in wave.iterdir():
        if path.is_file() and path.suffix in (".json", ".log"):
            copy(path, target / "wave" / path.name)
    for row in w_run["repositories"]:
        rank = f"{row['rank']:02}"
        for name in ("candidate.sarif", "comparison.json"):
            copy(wave / rank / name, target / "wave" / rank / name)

    primary = load(root / "experiments/wave-c/results/study-001/evaluation/report.json")
    labels_path = root / "experiments/wave-c/closeout/self-review/labels.proposed.json"
    labels = {row["unit_id"]: row for row in load(labels_path)}
    sources = {row["repository"]: row for row in load(root / "experiments/wave-c/sources.lock.json")["records"]}
    units, additions = [], []
    for row in w_run["repositories"]:
        rank = f"{row['rank']:02}"
        sets = {mode: set() for mode in row["modes_run"]}
        sarif = load(wave / rank / "candidate.sarif")
        for run in sarif["runs"]:
            for result in run["results"]:
                mode = result["ruleId"].rsplit("/", 1)[-1]
                location = result["locations"][0]["physicalLocation"]
                key = (location["artifactLocation"]["uri"], location["region"]["startLine"], location["region"]["startColumn"])
                sets[mode].add(key)
        original = next(repo for repo in primary["repositories"] if repo["repository"] == row["repository"])
        for unit in original["rows"]:
            key = (unit["file"], unit["line"], unit["column"])
            label = labels[unit["unit_id"]]
            units.append({"unit_id": unit["unit_id"], "repository": row["repository"],
                          "sink": list(key), "old_retained": unit["retained"],
                          "candidate_retained": {mode: key in values for mode, values in sets.items()},
                          "proposed_label": label["technical_label"],
                          "label_confirmed": False,
                          "assumptions_confirmed": False})
        for recovered in row["recovered"]["v021"]:
            file, line, column = recovered
            source = sources[row["repository"]]
            path = root / f"artifacts/wave-c/study-001/{rank}/extracted" / source["archive_root"] / file
            additions.append({"repository": row["repository"], "file": file, "line": line,
                              "column": column, "source_line": path.read_text(encoding="utf-8").splitlines()[line - 1]})
    if len(units) != 8:
        raise ValueError("Expected all eight original sink units")
    dispositions = collections.Counter()
    for row in units:
        dispositions[("retained_" if row["candidate_retained"]["v021"] else "suppressed_") + row["proposed_label"]] += 1
    summary = {
        "classification": "exposed development regression; not an independent re-evaluation of Wave C",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "fixture_required_markers": sum(row["none"] == "must" for row in scored["markers"]),
        "fixture_marker_count": len(scored["markers"]),
        "fixture_not_exercised": [row["id"] for row in scored["markers"] if not row["reported"]["none"]],
        "fixture_failed_expectations": scored["failures"],
        "fixture_sink_counts": scored["sink_counts"],
        "legacy_case_count": len(scored["legacy_cases"]),
        "legacy_bad_case_count": sum(row["case"].endswith("_bad") for row in scored["legacy_cases"]),
        "legacy_bad_baseline_detected": sum(row["case"].endswith("_bad") and row["reported"]["none"] for row in scored["legacy_cases"]),
        "legacy_bad_baseline_absent": [row["case"] for row in scored["legacy_cases"] if row["case"].endswith("_bad") and not row["reported"]["none"]],
        "legacy_baseline_absent": [row["case"] for row in scored["legacy_cases"] if not row["reported"]["none"]],
        "candidate_repository_counts": {mode: sum(mode in row["modes_run"] for row in w_run["repositories"]) for mode in ("v021", "v031", "v031s")},
        "candidate_sink_totals_on_scanned_repositories": {mode: sum(row["counts"].get(mode, 0) for row in w_run["repositories"]) for mode in ("v021", "v031", "v031s")},
        "counts_include_only_measured_modes": True,
        "wave_recovered": additions,
        "candidate_dispositions_on_self_review_proposals": dict(dispositions),
        "old_suppressed_unknown_proposals": sum(row["proposed_label"] == "unknown" and not row["old_retained"]["all"] for row in units),
        "candidate_suppressed_unknown_proposals": dispositions["suppressed_unknown"],
        "candidate_retained_unknown_proposals": dispositions["retained_unknown"],
        "confirmed_fp_rate": None,
        "candidate_acceptance": "not independently adjudicated",
        "original_failed_acceptance_preserved": True,
        "all_original_databases_unchanged": True,
        "commands": len(f_run["commands"]) + len(w_run["commands"]),
        "command_wall_seconds": sum(command["wall_seconds"] for run in (f_run, w_run) for command in run["commands"]),
        "fixture_elapsed_seconds": (datetime.fromisoformat(f_run["finished_at"]) - datetime.fromisoformat(f_run["started_at"])).total_seconds(),
        "wave_elapsed_seconds_including_copy_and_hash": (datetime.fromisoformat(w_run["finished_at"]) - datetime.fromisoformat(w_run["started_at"])).total_seconds(),
        "no_additional_repository_acquisition": True,
    }
    write(target / "summary.json", summary)
    write(target / "sink_comparison.json", units)
    with (target / "repository_comparison.csv").open("x", encoding="utf-8", newline="") as stream:
        fields = ["rank", "repository", "none", "all", "v03", "v03s", "v021", "v031", "v031s", "original_unchanged"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in w_run["repositories"]:
            writer.writerow({"rank": row["rank"], "repository": row["repository"], **row["counts"], "original_unchanged": row["original_unchanged"]})
    write(target / "packaging.json", {
        "script": Path(__file__).resolve().relative_to(root).as_posix(),
        "script_sha256": sha(Path(__file__)),
        "input_lock_sha256": sha(root / "experiments/v021-normalization/INPUTS_LOCK.sha256"),
        "labels_joined_only_after_scans": True,
        "labels_sha256": sha(labels_path),
        "copied_files": file_mappings,
    })
    print(json.dumps({key: value for key, value in summary.items() if key != "fixture_sink_counts"}, indent=2))


if __name__ == "__main__":
    main()
