"""Plan or execute wave C under a published freeze; synthetic smoke uses run_snapshot only."""

from __future__ import annotations

import argparse
import collections
import json
import os
import signal
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from evaluate import MODES, csv_rows, snapshot
from prepare_toolchain import check_toolchain
from source_support import (
    HEX40,
    HEX64,
    check_object,
    digest,
    extract_archive,
    fetch_bytes,
    file_digest,
    local,
    validate_repo,
    verify_sources,
    write_json,
)

DIAGNOSTICS = {
    "contracts": "V03Contracts",
    "evidence": "V03Evidence",
    "summaries": "V03Summaries",
    "resources": "V03Resources",
    "extracted": "ExtractedPythonFiles",
}


class CommandFailure(RuntimeError):
    pass


def invoke(
    argv: list[str],
    directory: Path,
    name: str,
    timeout: float,
    commands: list,
    *,
    cwd: Path | None = None,
) -> None:
    started = time.monotonic()
    record = {
        "argv": argv,
        "timeout_seconds": timeout,
        "started_at": datetime.now(UTC).isoformat(),
        "status": "running",
    }
    commands.append(record)
    with (directory / f"{name}.stdout.log").open("xb") as stdout:
        with (directory / f"{name}.stderr.log").open("xb") as stderr:
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=os.name == "posix",
                )
            except OSError as error:
                record.update(
                    status="launch_failed",
                    error=str(error),
                    wall_seconds=time.monotonic() - started,
                )
                write_json(directory / "commands.json", commands)
                raise CommandFailure(f"{name}: launch_failed") from error
            try:
                code = process.wait(timeout=timeout)
                record.update(status="ok" if code == 0 else "failed", exit_code=code)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # The process may have exited at the timeout boundary.
                else:
                    process.kill()
                process.wait()
                record.update(status="timed_out", exit_code=process.returncode)
            finally:
                record["wall_seconds"] = time.monotonic() - started
                write_json(directory / "commands.json", commands)
    if record["status"] != "ok":
        raise CommandFailure(f"{name}: {record['status']} (see preserved stdout/stderr)")


def commands_for(root: Path, source: dict, toolchain: dict, directory: Path) -> list[dict]:
    cli = str(local(root, toolchain["cli"]))
    cache = "--common-caches=" + str(local(root, toolchain["cache"]))
    packs = {key: local(root, value) for key, value in toolchain["packs"].items()}
    additional = "--additional-packs=" + os.pathsep.join(str(p) for p in packs.values())
    src = directory / "extracted" / source["archive_root"]
    database = directory / "database"
    plan = [
        {
            "name": "create",
            "timeout": 1800,
            "argv": [
                cli,
                "database",
                "create",
                str(database),
                "--language=python",
                f"--source-root={src}",
                "--threads=2",
                "--ram=5000",
                cache,
            ],
        }
    ]
    for mode in MODES:
        query = (
            (packs["v02"] if mode in {"none", "all"} else packs["v03"])
            / "queries"
            / f"cwe22_{mode}.ql"
        )
        plan.append(
            {
                "name": mode,
                "timeout": 1200,
                "argv": [
                    cli,
                    "database",
                    "analyze",
                    str(database),
                    str(query),
                    additional,
                    "--format=sarif-latest",
                    f"--output={directory / (mode + '.sarif')}",
                    "--rerun",
                    "--threads=2",
                    "--ram=5000",
                    cache,
                ],
            }
        )
    for key, name in DIAGNOSTICS.items():
        query = (
            (packs["diagnostics"] / f"{name}.ql")
            if key == "extracted"
            else packs["v03"] / "queries" / f"{name}.ql"
        )
        plan.append(
            {
                "name": key,
                "timeout": 1200,
                "diagnostic": key,
                "argv": [
                    cli,
                    "database",
                    "run-queries",
                    str(database),
                    str(query),
                    additional,
                    "--rerun",
                    "--threads=2",
                    "--ram=5000",
                    cache,
                ],
            }
        )
    return plan


def run_snapshot(
    root: Path, source: dict, toolchain: dict, directory: Path, deadline: float, *, execute=invoke
) -> dict:
    record = {key: source[key] for key in ("rank", "repository", "commit")}
    for key in ("group_id", "near_duplicate_review"):
        if key in source:
            record[key] = source[key]
    record.update(status="attempted", files={}, file_hashes={})
    directory.mkdir(parents=True, exist_ok=False)
    commands = []
    started = time.monotonic()
    try:
        archive = check_object(root, source["objects"]["archive"])
        extract_archive(archive, directory / "extracted", source["archive_root"])
        for task in commands_for(root, source, toolchain, directory):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                record["status"] = "budget_exhausted"
                return record
            execute(
                task["argv"], directory, task["name"], min(task["timeout"], remaining), commands
            )
            if "diagnostic" in task:
                key = task["diagnostic"]
                name = DIAGNOSTICS[key]
                matches = list((directory / "database/results").rglob(name + ".bqrs"))
                if len(matches) != 1:
                    raise ValueError(f"Missing/ambiguous BQRS result for {name}")
                csv_path = directory / f"{name}.csv"
                decode = [
                    str(local(root, toolchain["cli"])),
                    "bqrs",
                    "decode",
                    str(matches[0]),
                    "--format=csv",
                    f"--output={csv_path}",
                    "--common-caches=" + str(local(root, toolchain["cache"])),
                ]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record["status"] = "budget_exhausted"
                    return record
                execute(decode, directory, "decode_" + key, min(1200, remaining), commands)
                record["files"][key] = csv_path.relative_to(root).as_posix()
            elif task["name"] in MODES:
                record["files"][task["name"]] = (
                    (directory / (task["name"] + ".sarif")).relative_to(root).as_posix()
                )
        paths = {key: local(root, name) for key, name in record["files"].items()}
        observed = {row["file"] for row in csv_rows(paths["extracted"], {"file"})}
        expected = set(source["archive_inventory"]["python_files"])
        record["extraction"] = {
            "expected_python": len(expected),
            "observed_python": len(observed),
            "missing_python": sorted(expected - observed),
            "additional_modules": sorted(observed - expected),
        }
        result = snapshot(source["repository"], source["commit"], paths)
        write_json(directory / "machine_report.json", result)
        if result["status"] == "failed_acceptance":
            record["status"] = "failed_acceptance"
        else:
            record["status"] = "incomplete_extraction" if expected - observed else "completed"
            record["zero_alert"] = result["counts"]["none"] == 0
        record["file_hashes"] = {key: file_digest(path) for key, path in paths.items()}
    except (CommandFailure, OSError, ValueError, KeyError, TypeError) as error:
        record.update(status="run_failed", error=f"{type(error).__name__}: {error}")
    finally:
        record["wall_seconds"] = time.monotonic() - started
        write_json(directory / "snapshot.json", record)
    return record


def verify_publication(
    root: Path, publication: dict, execution_manifest: str, *, fetch=fetch_bytes
) -> dict:
    """Validate an actual service-recorded workflow and the exact Git tree, not a typed date."""
    commit = publication["commit"]
    repo = publication["repository"]
    workflow = publication["workflow_run_id"]
    if not isinstance(commit, str) or not isinstance(repo, str):
        raise ValueError("Published repository/commit fields are not filled in")
    validate_repo(repo)
    if not HEX40.fullmatch(commit) or type(workflow) is not int or workflow < 1:
        raise ValueError("Published commit and service-recorded workflow run ID are required")
    evidence = json.loads(
        fetch(f"https://api.github.com/repos/{repo}/actions/runs/{workflow}", 5 * 1024 * 1024)
    )
    if evidence["head_sha"] != commit or not evidence.get("created_at"):
        raise ValueError("Publication workflow does not prove the frozen commit")
    manifest_bytes = local(root, execution_manifest).read_bytes()
    if digest(manifest_bytes) != publication["execution_manifest_sha256"]:
        raise ValueError("Publication references a different execution manifest")
    entries = [(execution_manifest, digest(manifest_bytes))]
    seen = set()
    for line in manifest_bytes.decode().splitlines():
        expected, name = line.split("  ", 1)
        local(root, name)
        if not HEX64.fullmatch(expected) or name in seen:
            raise ValueError("Malformed/duplicate execution-manifest entry")
        seen.add(name)
        entries.append((name, expected))
    if not seen:
        raise ValueError("Empty execution manifest cannot authorize a study scan")
    for name, expected in entries:
        result = subprocess.run(
            ["git", "show", f"{commit}:{name}"],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode or digest(result.stdout) != expected:
            raise ValueError(f"Published Git tree does not contain frozen bytes: {name}")
        if file_digest(local(root, name)) != expected:
            raise ValueError(f"Workspace differs from publication: {name}")
    return {
        "commit": commit,
        "commit_url": f"https://github.com/{repo}/commit/{commit}",
        "workflow_url": evidence["html_url"],
        "service_created_at": evidence["created_at"],
        "verified_at": datetime.now(UTC).isoformat(),
        "workflow_response": evidence,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", required=True, help="New repository-relative directory")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="Plan only; no source extraction or scan")
    mode.add_argument("--execute", action="store_true", help="Requires a verified published freeze")
    parser.add_argument("--publication", default="experiments/wave-c/publication.json")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        inventory_path = local(root, "experiments/wave-c/inventory.json")
        sources_path = local(root, "experiments/wave-c/sources.lock.json")
        sources = json.loads(sources_path.read_bytes())
        inventory = json.loads(inventory_path.read_bytes())
        verify_sources(root, inventory, sources, file_digest(inventory_path))
        selected_count = sum(row["selection"] == "selected" for row in inventory["candidates"])
        if len(sources["records"]) != selected_count:
            raise ValueError("Source preparation is incomplete")
        if [r["rank"] for r in sources["records"]] != sorted(r["rank"] for r in sources["records"]):
            raise ValueError("Source records are not in the frozen rank order")
        toolchain = json.loads(local(root, "experiments/wave-c/toolchain.lock.json").read_bytes())
        check_toolchain(root, toolchain)
        publication = None
        if args.execute:
            publication = verify_publication(
                root,
                json.loads(local(root, args.publication).read_bytes()),
                "experiments/wave-c/EXECUTION_LOCK.sha256",
            )
            if os.name != "posix":
                raise ValueError("Execute this runner in the prepared Linux/WSL environment")
        output = local(root, args.output)
        output.mkdir(parents=True, exist_ok=False)
        plan = {
            "version": "wave-c-plan-v1",
            "executed": False,
            "sources_lock_sha256": file_digest(sources_path),
            "toolchain_lock_sha256": file_digest(
                local(root, "experiments/wave-c/toolchain.lock.json")
            ),
            "repositories": [
                {
                    "rank": row["rank"],
                    "repository": row["repository"],
                    "acquisition_status": row["status"],
                    "commands": commands_for(root, row, toolchain, output / f"{row['rank']:02d}")
                    if row["status"] == "prepared"
                    else [],
                }
                for row in sources["records"]
            ],
        }
        write_json(output / "plan.json", plan)
        if not args.execute:
            print(f"Planned {len(plan['repositories'])} repositories; no study database created")
            return
        run = {
            "version": "wave-c-run-v1",
            "records": [],
            "publication": publication,
            "sources_lock_sha256": plan["sources_lock_sha256"],
            "toolchain_lock_sha256": plan["toolchain_lock_sha256"],
        }
        write_json(output / "run.json", run)
        deadline, stopped = time.monotonic() + 24 * 3600, False
        for source in sources["records"]:
            if stopped or time.monotonic() >= deadline:
                record = {key: source[key] for key in ("rank", "repository", "commit")}
                record["status"] = "not_attempted_after_stop"
            elif source["status"] != "prepared":
                record = {key: source[key] for key in ("rank", "repository", "commit", "status")}
            else:
                record = run_snapshot(
                    root, source, toolchain, output / f"{source['rank']:02d}", deadline
                )
                stopped = record["status"] == "failed_acceptance"
            run["records"].append(record)
            write_json(output / "run.json", run)
            print(f"{record['rank']:02d} {record['repository']}: {record['status']}", flush=True)
        print(dict(collections.Counter(r["status"] for r in run["records"])))
        if stopped:
            parser.exit(2, "Failed acceptance; remaining repositories were not scanned\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Runner preflight failed: {error}\n")


if __name__ == "__main__":
    main()
