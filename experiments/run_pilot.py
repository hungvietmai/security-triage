"""Development-only, manifest-driven static scan runner (Python 3.12+).

No benchmark code/install hooks are executed. Scoring and automatic sink matching
are intentionally unavailable until the independent review ledger is implemented.
"""

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 50 * 1024 * 1024
MAX_UNPACKED = 200 * 1024 * 1024
MAX_FILES = 5000


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def fetch(url, target, expected_hash, max_bytes=MAX_ARCHIVE):
    if not url.startswith("https://") or not re.fullmatch(
        r"[a-f0-9]{64}", expected_hash
    ):
        raise ValueError("HTTPS URL and exact SHA-256 required")
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise ValueError("Insecure redirect")
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("Download size limit or checksum mismatch")
    target.write_bytes(data)


def stage_rule(rule, target):
    """Support committed local rules and pinned upstream downloads equally."""
    if ("path" in rule) == ("url" in rule):
        raise ValueError("Rule needs exactly one of path or url")
    if "url" in rule:
        fetch(rule["url"], target, rule["sha256"], 2 * 1024 * 1024)
        return
    relative = Path(rule["path"])
    source = (ROOT / relative).resolve()
    if relative.is_absolute() or not source.is_relative_to(ROOT):
        raise ValueError("Local rule must stay inside repository")
    if source.stat().st_size > 2 * 1024 * 1024 or digest(source) != rule["sha256"]:
        raise ValueError("Local rule size limit or checksum mismatch")
    shutil.copyfile(source, target)


def unpack(archive, destination, archive_root):
    """Extract only ordinary files/directories, without trusting archive metadata."""
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as bundle:
        members = []
        paths = set()
        total = 0
        for item in bundle:
            path = PurePosixPath(item.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in item.name
                or not path.parts
                or path.parts[0] != archive_root
                or not (item.isfile() or item.isdir())
            ):
                raise ValueError(f"Unsafe/unsupported archive entry: {item.name}")
            if path.as_posix() in paths:
                raise ValueError("Duplicate archive path")
            paths.add(path.as_posix())
            total += item.size
            if len(paths) > MAX_FILES or total > MAX_UNPACKED or item.size < 0:
                raise ValueError("Archive expansion limit exceeded")
            members.append((item, path))
        for item, path in members:
            out = destination.joinpath(*path.parts)
            if item.isdir():
                out.mkdir(parents=True, exist_ok=True)
            else:
                out.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(item) as src, out.open("xb") as dst:
                    while data := src.read(1024 * 1024):
                        dst.write(data)
    return destination / archive_root


def verify_source_identity(case, source):
    """Validate pinned source identity without importing or executing target code."""
    if case["source_kind"] == "npm_tarball":
        package = json.loads((source / "package.json").read_text())
        if (package["name"], package["version"]) != (
            case["package_name"], case["package_version"]
        ):
            raise ValueError("Package identity mismatch")
        return
    if case["source_kind"] != "github_tarball":
        raise ValueError("Unsupported source kind")
    commit, repository = case["source_commit"], case["repository"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        raise ValueError("GitHub repository and full source commit required")
    if case["artifact_url"] != f"https://codeload.github.com/{repository}/tar.gz/{commit}":
        raise ValueError("Archive URL must pin the source commit")
    if case["archive_root"] != f"{repository.split('/')[1]}-{commit}":
        raise ValueError("Archive root does not match pinned commit")
    identity_files = case.get("identity_files_sha256", {})
    if not identity_files:
        raise ValueError("Source identity file hashes required")
    for relative, expected in identity_files.items():
        path = (source / relative).resolve()
        if Path(relative).is_absolute() or not path.is_relative_to(source.resolve()):
            raise ValueError("Identity path escapes source root")
        if digest(path) != expected:
            raise ValueError(f"Source identity mismatch: {relative}")


def query_pack_for_language(args, language):
    pack = getattr(args, language + "_query_pack")
    if not pack:
        raise ValueError(f"--{language}-query-pack must point to bundled pinned queries")
    return pack.resolve()


def invoke(argv, cwd, output, name, timeout, env=None):
    if env is None:
        env = os.environ.copy()
    if name.startswith("semgrep"):
        env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
        env.pop("SEMGREP_APP_TOKEN", None)
    start = time.monotonic()
    record = {"argv": list(map(str, argv)), "status": "failed", "exit_code": None}
    with (
        (output / f"{name}.stdout.log").open("wb") as stdout,
        (output / f"{name}.stderr.log").open("wb") as stderr,
    ):
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                env=env,
                start_new_session=True,
            )
            try:
                record["exit_code"] = process.wait(timeout=timeout)
                record["status"] = "completed" if record["exit_code"] == 0 else "failed"
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                record["status"] = "timeout"
        except OSError as exc:
            record["error"] = str(exc)
    record["seconds"] = round(time.monotonic() - start, 4)
    return record


def tool_version(binary, expected, output, tool, steps):
    args = (
        [binary, "--version"]
        if tool == "semgrep"
        else [binary, "version", "--format=json"]
    )
    rec = invoke(args, ROOT, output, tool + "-version", 60)
    steps[tool + "-version"] = rec
    if rec["status"] != "completed":
        raise RuntimeError(f"{tool} unavailable; see version logs")
    actual = (output / f"{tool}-version.stdout.log").read_text()
    if tool == "codeql":
        actual = json.loads(actual)["version"]
    if actual.strip() != expected:
        raise ValueError(f"{tool} version mismatch: {actual.strip()} != {expected}")


def sarif_findings(path, tool, snapshot):
    """Preserve every result, including missing locations; do not infer sink IDs."""
    data = json.loads(path.read_text())
    records = []
    if data.get("version") != "2.1.0" or not isinstance(data.get("runs"), list):
        raise ValueError("Invalid SARIF 2.1.0 document")
    complete = True
    for run_index, run in enumerate(data["runs"]):
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                complete = False
            if any(
                note.get("level", "warning") not in {"none", "note"}
                for note in invocation.get("toolExecutionNotifications", [])
            ):
                complete = False
        rules = {
            r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result_index, result in enumerate(run.get("results", [])):
            physical = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            rule_id = result.get("ruleId")
            if not rule_id and isinstance(result.get("ruleIndex"), int):
                ordered = run.get("tool", {}).get("driver", {}).get("rules", [])
                idx = result["ruleIndex"]
                rule_id = ordered[idx]["id"] if 0 <= idx < len(ordered) else None
            rule = rules.get(rule_id, {})
            records.append(
                {
                    "raw_id": f"{tool}:{run_index}:{result_index}",
                    "tool": tool,
                    "snapshot_sha256": snapshot,
                    "rule_id": rule_id,
                    "reported_path": physical.get("artifactLocation", {}).get("uri"),
                    "reported_region": physical.get("region", {}),
                    "reported_cwes": sorted(
                        set(
                            re.findall(
                                r"CWE-\d+",
                                json.dumps(rule.get("properties", {})),
                                re.IGNORECASE,
                            )
                        )
                    ),
                    "message": result.get("message", {}).get("text", ""),
                    "sink_identity": None,
                    "mapping_status": "unresolved",
                    "technical_verdict": "unresolved",
                    "scope_verdict": "unresolved",
                    "raw_result": result,
                }
            )
    return records, complete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--configuration-commit", required=True)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--javascript-query-pack", type=Path)
    parser.add_argument("--python-query-pack", type=Path)
    parser.add_argument(
        "--source-archive", type=Path, help="Reuse an archive with the manifest hash"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.configuration_commit):
        parser.error("Exact configuration commit required")
    case_bytes, config_bytes = args.case.read_bytes(), args.config.read_bytes()
    case, config = json.loads(case_bytes), json.loads(config_bytes)
    if case["split"] != "development":
        parser.error(
            "Held-out execution is blocked: full freeze gate is not implemented"
        )
    if (case["source_kind"], case["language"]) not in {
        ("npm_tarball", "javascript"),
        ("github_tarball", "javascript"),
        ("github_tarball", "python"),
    }:
        parser.error("Supported sources: JavaScript npm, or pinned GitHub JS/Python archives")
    if config.get("language", "javascript") != case["language"]:
        parser.error("Case and scanner configuration languages must agree")
    if set(config["scanners"]) - {"semgrep", "codeql"}:
        parser.error("Unsupported scanner; ST/S1 are not implemented yet")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "case.json").write_bytes(case_bytes)
    (output / "config.json").write_bytes(config_bytes)
    protocol_path = ROOT / "experiments/EVALUATION_PROTOCOL.md"
    report = {
        "case_id": case["case_id"],
        "split": case["split"],
        "config_id": config["config_id"],
        "purpose": config["purpose"],
        "protocol_commit": config["protocol_commit"],
        "configuration_commit": args.configuration_commit,
        "protocol_sha256": digest(protocol_path),
        "case_manifest_sha256": digest(output / "case.json"),
        "configuration_sha256": digest(output / "config.json"),
        "runner_sha256": digest(Path(__file__)),
        "status": "running",
        "steps": {},
        "labels_commit": None,
        "mapping_version": "raw-ledger-v0",
        "metrics": None,
        "metrics_reason": "No reviewed common location/label ledger yet",
    }
    findings = []
    start = time.monotonic()
    try:
        begin = time.monotonic()
        archive = output / "source.tgz"
        if args.source_archive:
            if (
                args.source_archive.stat().st_size > MAX_ARCHIVE
                or digest(args.source_archive) != case["artifact_sha256"]
            ):
                raise ValueError("Cached source size limit or checksum mismatch")
            shutil.copyfile(args.source_archive, archive)
        else:
            fetch(case["artifact_url"], archive, case["artifact_sha256"])
        if case.get("registry_integrity"):
            integrity = (
                "sha512-"
                + base64.b64encode(
                    hashlib.sha512(archive.read_bytes()).digest()
                ).decode()
            )
            if integrity != case["registry_integrity"]:
                raise ValueError("Registry integrity mismatch")
        source = unpack(archive, output / "source", case["archive_root"])
        verify_source_identity(case, source)
        report["snapshot_sha256"] = digest(archive)
        report["source_files"] = [
            str(p.relative_to(source)) for p in sorted(source.rglob("*")) if p.is_file()
        ]
        report["steps"]["acquisition"] = {
            "status": "completed",
            "transport": "verified_local_archive" if args.source_archive else "https",
            "seconds": time.monotonic() - begin,
        }
        for tool in config["scanners"]:
            try:
                binary = args.semgrep if tool == "semgrep" else args.codeql
                tool_version(
                    binary, config[tool + "_version"], output, tool, report["steps"]
                )
                sarif = output / (tool + ".sarif")
                if tool == "semgrep":
                    argv = [
                        binary,
                        "scan",
                        "--metrics=off",
                        "--disable-version-check",
                        "--disable-nosem",
                        "--no-git-ignore",
                        "--jobs",
                        str(config["jobs"]),
                        "--sarif",
                        "--output",
                        str(sarif),
                    ]
                    for idx, rule in enumerate(config["semgrep_rules"]):
                        local = output / f"rule-{idx}.yaml"
                        stage_rule(rule, local)
                        argv += ["--config", str(local)]
                    argv += ["."]
                    rec = invoke(argv, source, output, tool, config["timeout_seconds"])
                else:
                    pack = query_pack_for_language(args, case["language"])
                    query_paths = [pack / x for x in config["codeql_queries"]]
                    if not all(q.is_file() for q in query_paths):
                        raise ValueError("Configured CodeQL query missing from pack")
                    report["codeql_query_files"] = {
                        str(q.relative_to(pack)): digest(q) for q in query_paths
                    }
                    report["codeql_pack_manifest"] = (pack / "qlpack.yml").read_text()
                    if report["codeql_query_files"] != config["codeql_query_sha256"]:
                        raise ValueError("CodeQL query digest mismatch")
                    database = output / "codeql-db"
                    rec = invoke(
                        [
                            binary,
                            "database",
                            "create",
                            str(database),
                            "--language=" + case["language"],
                            "--source-root",
                            str(source),
                            "--build-mode=none",
                            "--threads",
                            str(config["jobs"]),
                            "--ram=2048",
                        ],
                        source,
                        output,
                        "codeql-create",
                        config["timeout_seconds"],
                    )
                    report["steps"]["codeql-create"] = rec
                    if rec["status"] != "completed":
                        raise RuntimeError("CodeQL extraction failed")
                    rec = invoke(
                        [
                            binary,
                            "database",
                            "analyze",
                            str(database),
                            *map(str, query_paths),
                            "--format=sarif-latest",
                            "--output",
                            str(sarif),
                            "--threads",
                            str(config["jobs"]),
                            "--ram=2048",
                        ],
                        source,
                        output,
                        tool,
                        config["timeout_seconds"],
                    )
                report["steps"][tool] = rec
                if not sarif.exists():
                    raise RuntimeError("Scanner produced no SARIF output")
                if sarif.exists():
                    rows, complete = sarif_findings(
                        sarif, tool, case["artifact_sha256"]
                    )
                    findings.extend(rows)
                    rec["raw_findings"] = len(rows)
                    rec["sarif_sha256"] = digest(sarif)
                    if rec["status"] == "completed" and not complete:
                        rec["status"] = "partial"
            except (
                OSError,
                ValueError,
                RuntimeError,
                KeyError,
                tarfile.TarError,
            ) as exc:
                failure = report["steps"].setdefault(tool, {})
                failure["status"] = (
                    "timeout" if failure.get("status") == "timeout" else "failed"
                )
                failure["error"] = str(exc)
        report["status"] = (
            "completed"
            if all(
                report["steps"][t]["status"] == "completed" for t in config["scanners"]
            )
            else "partial"
        )
    except (OSError, ValueError, RuntimeError, KeyError, tarfile.TarError) as exc:
        report["status"], report["error"] = "failed", str(exc)
    report["wall_seconds"] = round(time.monotonic() - start, 4)
    report["raw_findings"] = len(findings)
    write_json(output / "findings.json", findings)
    fields = [
        "raw_id",
        "tool",
        "rule_id",
        "reported_path",
        "reported_region",
        "mapping_status",
        "message",
    ]
    with (output / "findings.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
    write_json(output / "run.json", report)
    print(
        json.dumps(
            {
                "status": report["status"],
                "raw_findings": len(findings),
                "output": str(output),
            }
        )
    )
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
