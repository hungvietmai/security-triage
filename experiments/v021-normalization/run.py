"""Run the isolated normalization correction as development, never as held-out validation.

Linux/WSL, repository-root cwd. Fresh output only; no application execution,
network access or installation. Expectations and method hashes must match the lock.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone

MODES = ("none", "all", "v03", "v03s", "v021", "v031", "v031s")


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def manifest(folder):
    result = {}
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Database symlink rejected: {path}")
        if path.is_file():
            result[path.relative_to(folder).as_posix()] = sha(path)
    return result


def alerts(path):
    result = {mode: set() for mode in MODES}
    for run in load(path)["runs"]:
        if any(item.get("executionSuccessful") is False for item in run.get("invocations", [])):
            raise ValueError("Unsuccessful SARIF invocation")
        for alert in run["results"]:
            mode = alert["ruleId"].rsplit("/", 1)[-1]
            if mode not in result:
                raise ValueError("Unknown result rule")
            physical = alert["locations"][0]["physicalLocation"]
            region = physical["region"]
            result[mode].add((physical["artifactLocation"]["uri"], region["startLine"], region["startColumn"]))
    return result


def check_sets(sets, modes):
    pairs = [("none", "v021"), ("v021", "all")]
    if "v031" in modes:
        pairs.extend([("v021", "v031"), ("v031", "v03"),
                      ("v031", "v031s"), ("v031s", "v03s")])
    issues = []
    for larger, smaller in pairs:
        issues.extend({"larger": larger, "smaller": smaller, "missing_or_extra": list(key)}
                      for key in sorted(sets[smaller] - sets[larger]))
    return issues


def score_fixture(folder, sarif, expectations):
    sets = alerts(sarif)
    markers = {}
    lines = (folder / "app.py").read_text(encoding="utf-8").splitlines()
    for line, text in enumerate(lines, 1):
        match = re.search(r"# sink: ([a-z_]+)$", text)
        if match:
            markers[match[1]] = line
    if set(markers) != {row["id"] for row in expectations["markers"]}:
        raise ValueError("Expectation markers differ from fixture")
    rows, failures = [], []
    for expected in expectations["markers"]:
        line = markers[expected["id"]]
        hit = {mode: any(file == "app.py" and number == line for file, number, _ in sets[mode]) for mode in MODES}
        problems = []
        if expected["none"] == "must" and not hit["none"]:
            problems.append("VACUOUS_REQUIRED_BASELINE")
        for mode in expectations["candidate_modes"]:
            decision = expected["candidate"]
            if decision in ("keep", "keep_if_reported") and hit["none"] and not hit[mode]:
                problems.append(f"{mode}:LOST_REQUIRED_ALERT")
            elif decision == "drop" and hit[mode]:
                problems.append(f"{mode}:POSITIVE_CONTROL_RETAINED")
            elif decision == "legacy" and hit[mode] != hit["all"]:
                problems.append(f"{mode}:LEXICAL_CONTROL_CHANGED")
        failures.extend({"marker": expected["id"], "problem": item} for item in problems)
        rows.append({**expected, "line": line, "reported": hit,
                     "coverage": "exercised" if hit["none"] else "not_exercised_baseline_absent",
                     "problems": problems})
    legacy = []
    for path in sorted(folder.glob("legacy_*.py")):
        for function in ast.parse(path.read_text(encoding="utf-8")).body:
            if not isinstance(function, ast.FunctionDef) or not function.name.endswith(("_bad", "_good")):
                continue
            hit = {mode: any(file == path.name and function.lineno <= number <= function.end_lineno
                             for file, number, _ in sets[mode]) for mode in MODES}
            lost = [mode for mode in expectations["candidate_modes"] if function.name.endswith("_bad")
                    and hit["none"] and not hit[mode]]
            failures.extend({"legacy_case": function.name, "problem": f"{mode}:LOST_BAD_CASE"} for mode in lost)
            legacy.append({"file": path.name, "case": function.name, "reported": hit,
                           "baseline_absent": not hit["none"], "lost_bad_case_modes": lost})
    subset = check_sets(sets, MODES)
    return {"markers": rows, "legacy_cases": legacy, "failures": failures,
            "subset_violations": subset, "sink_counts": {mode: len(values) for mode, values in sets.items()},
            "passed": not failures and not subset}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--phase", choices=("fixture", "wave"), required=True)
    parser.add_argument("--fixture-result", help="Successful fixture report required for wave phase")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Use Linux Python under WSL")
    root = Path.cwd().resolve()
    experiment = root / "experiments/v021-normalization"
    for line in (experiment / "INPUTS_LOCK.sha256").read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        path = root / name
        if not path.resolve().is_relative_to(root) or sha(path) != expected:
            raise ValueError(f"Changed locked input: {name}")
    output = (root / args.output).resolve()
    if not output.is_relative_to(root / "artifacts"):
        parser.error("Output must be a fresh directory under artifacts")
    if args.phase == "wave":
        if not args.fixture_result or not load(root / args.fixture_result)["passed"]:
            parser.error("Wave phase requires a successful fixture result")
    output.mkdir(parents=True, exist_ok=False)
    cli = root / "artifacts/toolchains/codeql-2.27.1/codeql/codeql"
    cache = root / "artifacts/toolchains/codeql-cache"
    old02 = root / "artifacts/wave-c/toolchain/v02"
    old03 = root / "artifacts/wave-c/toolchain/v03"
    candidate = experiment / "pack"
    packs = f"--additional-packs={old02}:{old03}:{candidate}"
    queries = {mode: (old02 if mode in ("none", "all") else old03 if mode in ("v03", "v03s") else candidate)
               / f"queries/cwe22_{mode}.ql" for mode in MODES}
    record = {"classification": "development after exposure, not independent evaluation",
              "phase": args.phase, "started_at": now(), "commands": [], "repositories": [],
              "input_lock_sha256": sha(experiment / "INPUTS_LOCK.sha256"),
              "application_source_executed": False}

    def execute(argv, name, timeout=1200):
        started = now()
        clock = time.monotonic()
        with (output / f"{name}.stdout.log").open("wb") as stdout, (output / f"{name}.stderr.log").open("wb") as stderr:
            proc = subprocess.Popen(list(map(str, argv)), stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = proc.wait(timeout=timeout)
                status = "ok" if code == 0 else "failed"
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                code = proc.wait()
                status = "timeout"
        command = {"argv": list(map(str, argv)), "started_at": started, "exit_code": code,
                   "status": status, "wall_seconds": time.monotonic() - clock, "timeout_seconds": timeout}
        record["commands"].append(command)
        save(output / "run.json", record)
        print(f"{name}: {status} ({command['wall_seconds']:.1f}s)", flush=True)
        if status != "ok":
            raise RuntimeError(f"Command failed: {name}")

    def analyze(db, modes, destination, name):
        execute([cli, "database", "analyze", db, *[queries[mode] for mode in modes], packs,
                 "--format=sarif-latest", f"--output={destination}", "--rerun", "--threads=2", "--ram=5000",
                 f"--common-caches={cache}"], name)

    try:
        if args.phase == "fixture":
            source = output / "source"
            source.mkdir()
            shutil.copyfile(root / "experiments/tests/fixtures/v021_normalization/app.py", source / "app.py")
            for name in ("paths", "values"):
                shutil.copyfile(root / f"experiments/owasp-bp-pilot/counterexamples/{name}.py", source / f"legacy_{name}.py")
            execute([cli, "database", "create", output / "database", "--language=python", "--build-mode=none",
                     f"--source-root={source}", "--threads=2", "--ram=5000", f"--common-caches={cache}"], "create-fixture", 1800)
            analyze(output / "database", MODES, output / "fixture.sarif", "analyze-fixture")
            scored = score_fixture(source, output / "fixture.sarif", load(experiment / "expectations.json"))
            save(output / "fixture-report.json", scored)
            print(f"Fixture passed={scored['passed']}; failures={scored['failures']}; subsets={scored['subset_violations']}", flush=True)
            if not scored["passed"]:
                raise ValueError("Locked fixture acceptance failed; preserve outputs and stop")
        else:
            study = load(root / "experiments/wave-c/results/study-001/original_run.json")
            for row in study["records"]:
                if row["status"] != "completed":
                    continue
                rank = f"{row['rank']:02}"
                original = root / f"artifacts/wave-c/study-001/{rank}/database"
                before = manifest(original)
                destination = output / rank
                destination.mkdir()
                print(f"Copying development DB {rank} ({len(before)} files)", flush=True)
                shutil.copytree(original, destination / "database")
                if manifest(destination / "database") != before:
                    raise ValueError("Database copy mismatch")
                modes = ("v021", "v031", "v031s") if rank in ("03", "08") else ("v021",)
                analyze(destination / "database", modes, destination / "candidate.sarif", f"analyze-{rank}")
                sets = alerts(destination / "candidate.sarif")
                for old in ("none", "all", "v03", "v03s"):
                    sets[old] = alerts(root / f"experiments/wave-c/results/study-001/inputs/{rank}/{old}.sarif")[old]
                issues = check_sets(sets, modes)
                after = manifest(original)
                compared = {"rank": row["rank"], "repository": row["repository"], "modes_run": modes,
                            "original_before": before, "original_after": after, "original_unchanged": before == after,
                            "subset_violations": issues,
                            "counts": {mode: len(sets[mode]) for mode in (*("none", "all", "v03", "v03s"), *modes)},
                            "recovered": {mode: [list(key) for key in sorted(sets[mode] - sets["all" if mode == "v021" else "v03" if mode == "v031" else "v03s"]) ] for mode in modes}}
                record["repositories"].append(compared)
                save(destination / "comparison.json", compared)
                save(output / "run.json", record)
                print(f"{rank} counts={compared['counts']}; recovered={compared['recovered']}", flush=True)
                if issues or before != after:
                    raise ValueError("Development comparison failed; preserve and stop")
        record["status"] = "completed"
    except Exception as error:
        record["status"] = "failed"
        record["error"] = repr(error)
        raise
    finally:
        record["finished_at"] = now()
        save(output / "run.json", record)


if __name__ == "__main__":
    main()
