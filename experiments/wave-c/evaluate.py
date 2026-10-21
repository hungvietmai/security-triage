"""Evaluate wave C sink sets without inventing labels, approvals, or empty successful runs."""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import itertools
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

from source_support import encoded, file_digest, local, safe_relative, write_json

MODES = ("none", "all", "v03", "v03s")
LABELS = {"true_positive", "true_positive_conditional", "false_positive", "unknown"}
FINAL_REVIEWS = {"owner_reviewed", "independent_reviewed"}
SCOPED_ASSUMPTIONS = ("S-TEST", "S-TMP", "S-PURPOSE", "S-ENV")


def location(physical: dict) -> tuple[str, int, int]:
    uri = physical["artifactLocation"]["uri"]
    parsed = urlsplit(uri)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError(f"Sink URI must be relative to the source root: {uri}")
    name = safe_relative(unquote(parsed.path)).as_posix()
    line = physical["region"]["startLine"]
    col = physical["region"]["startColumn"]
    if type(line) is not int or type(col) is not int or line < 1 or col < 1:
        raise ValueError("Sink line/column must be positive integers")
    return name, line, col


def read_sarif(path: Path, mode: str) -> dict[tuple, list]:
    document = json.loads(path.read_bytes())
    if document.get("version") != "2.1.0" or not document.get("runs"):
        raise ValueError("Missing SARIF 2.1.0 runs")
    rows = collections.defaultdict(list)
    for run in document["runs"]:
        if any(i.get("executionSuccessful") is False for i in run.get("invocations", [])):
            raise ValueError("SARIF reports unsuccessful execution")
        for result in run["results"]:
            if result["ruleId"] != f"st/cwe-22/{mode}":
                raise ValueError(f"Unexpected rule in {mode} output: {result['ruleId']}")
            if len(result["locations"]) != 1:
                raise ValueError("Ambiguous primary sink location")
            rows[location(result["locations"][0]["physicalLocation"])].append(result)
    return dict(rows)


def csv_rows(path: Path, required: set[str]) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not required <= set(reader.fieldnames or []):
            raise ValueError(f"Missing diagnostic columns in {path.name}")
        return list(reader)


def diagnostic_location(row: dict) -> tuple[str, int, int]:
    return location(
        {
            "artifactLocation": {"uri": row["file"]},
            "region": {"startLine": int(row["line"]), "startColumn": int(row["col"])},
        }
    )


def unit_id(repository: str, commit: str, key: tuple) -> str:
    return hashlib.sha256(encoded([repository, commit, *key])).hexdigest()[:24]


def snapshot(
    repository: str, commit: str, paths: dict[str, Path], labels: dict | None = None
) -> dict:
    labels = labels or {}
    alerts = {mode: read_sarif(paths[mode], mode) for mode in MODES}
    sets = {mode: set(rows) for mode, rows in alerts.items()}
    violations = []
    for bigger, smaller in itertools.pairwise(MODES):
        violations.extend(
            {"larger": bigger, "smaller": smaller, "extra_sink": list(key)}
            for key in sorted(sets[smaller] - sets[bigger])
        )
    contracts = collections.defaultdict(list)
    for row in csv_rows(paths["contracts"], {"file", "line", "col", "kind", "root", "detail"}):
        if row["kind"] not in {"allowed", "contained"}:
            raise ValueError("Unknown diagnostic contract kind")
        contracts[diagnostic_location(row)].append(row)
    evidence = collections.defaultdict(list)
    for row in csv_rows(
        paths["evidence"], {"file", "line", "col", "root", "basis", "source", "level"}
    ):
        if row["level"] not in {"proved", "scoped"}:
            raise ValueError("Unknown evidence level")
        evidence[diagnostic_location(row)].append(row)
    rows, packet, template = [], [], []
    for key in sorted(set().union(*sets.values())):
        identity = unit_id(repository, commit, key)
        label = labels.get(identity, {})
        technical = label.get("technical_label")
        if technical is not None and technical not in LABELS:
            raise ValueError(f"Unknown technical label for {identity}")
        reviewed = technical is not None and label.get("review_status") in FINAL_REVIEWS
        if reviewed and not all(
            label.get(k) for k in ("reviewer", "reviewed_at", "scope", "root_cause_id")
        ):
            raise ValueError(f"Incomplete final review for {identity}")
        raw = {mode: key in sets["all"] and key not in sets[mode] for mode in ("v03", "v03s")}
        allowed = {r["root"] for r in contracts[key] if r["kind"] == "allowed"}
        contained = {r["root"] for r in contracts[key] if r["kind"] == "contained"}
        decisions = {}
        evidence_errors = []
        for mode in ("v03", "v03s"):
            if not raw[mode]:
                decisions[mode] = "kept"
                continue
            support = [r for r in evidence[key] if mode == "v03s" or r["level"] == "proved"]
            if not support or not any(r["root"] in allowed & contained for r in support):
                evidence_errors.append(
                    f"{mode}: missing matched containment/contract/suppression proof"
                )
            assumptions = set()
            if any(r["level"] == "scoped" for r in support):
                assumptions.update(SCOPED_ASSUMPTIONS)
            if any("lexical" in r["basis"] for r in support):
                assumptions.add("A-SYM")
            assumption_records = [label.get("assumptions", {}).get(a, {}) for a in assumptions]
            checks = [a.get("status", "unknown") for a in assumption_records]
            if any(c not in {"supported", "contradicted", "unknown"} for c in checks):
                raise ValueError(f"Invalid assumption status: {identity}")
            if "contradicted" in checks:
                decisions[mode] = "scope_rejected"
            elif "unknown" in checks or any(not a.get("evidence") for a in assumption_records):
                decisions[mode] = "scope_unknown"
            elif (
                reviewed
                and technical == "false_positive"
                and label.get("all_reported_flows_reviewed") is True
                and not evidence_errors
            ):
                decisions[mode] = "accepted_suppression"
            else:
                decisions[mode] = "review_pending"
        row = {
            "unit_id": identity,
            "repository": repository,
            "commit": commit,
            "file": key[0],
            "line": key[1],
            "column": key[2],
            "retained": {mode: key in sets[mode] for mode in MODES},
            "technical_label": technical or "unreviewed",
            "label_confirmed": reviewed,
            "review_status": label.get("review_status", "unreviewed"),
            "scope": label.get("scope") or "unresolved",
            "root_cause_id": label.get("root_cause_id"),
            "raw_suppressed": raw,
            "operational_decision": decisions,
            "contracts": contracts[key],
            "evidence": evidence[key],
            "evidence_errors": evidence_errors,
        }
        rows.append(row)
        reported = alerts["none"].get(key, [])
        packet.append(
            {
                "unit_id": identity,
                "repository": repository,
                "commit": commit,
                "file": key[0],
                "line": key[1],
                "column": key[2],
                "reported_sources": [p for r in reported for p in r.get("relatedLocations", [])],
                "code_flows": [p for r in reported for p in r.get("codeFlows", [])],
                "trace_available": any(r.get("codeFlows") for r in reported),
                "review_limitation": "Source locations do not enumerate complete execution paths",
            }
        )
        template.append(
            {
                "unit_id": identity,
                "technical_label": None,
                "scope": None,
                "root_cause_id": None,
                "review_status": "unreviewed",
                "reviewer": None,
                "reviewed_at": None,
                "all_reported_flows_reviewed": False,
                "assumptions": {
                    a: {"status": "unknown", "evidence": None}
                    for a in (*SCOPED_ASSUMPTIONS, "A-SYM")
                },
            }
        )
    modes = {}
    for mode in ("v03", "v03s"):
        base = [r for r in rows if r["retained"]["all"]]
        suppressed = [r for r in base if r["raw_suppressed"][mode]]
        confirmed_fp = [
            r for r in base if r["label_confirmed"] and r["technical_label"] == "false_positive"
        ]
        removed_fp = [r for r in confirmed_fp if r["raw_suppressed"][mode]]
        count_by_label = dict(collections.Counter(r["technical_label"] for r in suppressed))

        def eligible_allowed(row, current_mode=mode):
            return any(
                c["kind"] == "allowed" and (current_mode == "v03s" or c["detail"] != "resource")
                for c in row["contracts"]
            )

        modes[mode] = {
            "baseline_sinks": len(base),
            "raw_suppressed": len(suppressed),
            "suppressed_by_label": count_by_label,
            "accepted_suppression": sum(
                r["operational_decision"][mode] == "accepted_suppression" for r in suppressed
            ),
            "decision_counts": dict(
                collections.Counter(r["operational_decision"][mode] for r in suppressed)
            ),
            "contract_sinks": sum(eligible_allowed(r) for r in base),
            "contract_coverage": sum(eligible_allowed(r) for r in base) / len(base)
            if base
            else None,
            "confirmed_fp": len(confirmed_fp),
            "confirmed_fp_raw_removed": len(removed_fp),
            "fp_reduction_rate_reviewed_subset": len(removed_fp) / len(confirmed_fp)
            if confirmed_fp
            else None,
            "all_baseline_labels_confirmed": all(r["label_confirmed"] for r in base),
            "counts_by_scope": {
                scope: {
                    "baseline": sum(r["scope"] == scope for r in base),
                    "raw_suppressed": sum(r["scope"] == scope for r in suppressed),
                }
                for scope in sorted({r["scope"] for r in base})
            },
        }
        groups = collections.defaultdict(list)
        for row in base:
            if row["label_confirmed"]:
                groups[(row["scope"], row["root_cause_id"])].append(row)
        modes[mode]["root_causes_partly_suppressed"] = sum(
            any(r["raw_suppressed"][mode] for r in group) for group in groups.values()
        )
        modes[mode]["root_causes_fully_suppressed"] = sum(
            all(r["raw_suppressed"][mode] for r in group) for group in groups.values()
        )
    failed = bool(violations) or any(
        row["evidence_errors"]
        or any(
            row["raw_suppressed"][mode]
            and (
                row["technical_label"] in {"true_positive", "true_positive_conditional", "unknown"}
                or row["operational_decision"][mode] == "scope_rejected"
            )
            for mode in ("v03", "v03s")
        )
        or (
            row["retained"]["none"]
            and not row["retained"]["all"]
            and row["technical_label"] in {"true_positive", "true_positive_conditional", "unknown"}
        )
        for row in rows
    )
    pending = any(
        r["raw_suppressed"][m] and r["operational_decision"][m] != "accepted_suppression"
        for r in rows
        for m in ("v03", "v03s")
    )
    return {
        "repository": repository,
        "commit": commit,
        "status": "failed_acceptance"
        if failed
        else "review_pending"
        if pending
        else "no_observed_safety_failure",
        "counts": {m: len(sets[m]) for m in MODES},
        "v02_raw_suppressed": len(sets["none"] - sets["all"]),
        "scoped_incremental_raw_suppressed": len(sets["v03"] - sets["v03s"]),
        "subset_violations": violations,
        "modes": modes,
        "rows": rows,
        "review_packet": packet,
        "label_template": template,
        "labels_complete": all(r["label_confirmed"] for r in rows),
    }


def aggregate(results: list[dict]) -> dict:
    complete = [r for r in results if r.get("execution_status") == "completed"]
    incomplete = [r for r in results if r.get("execution_status") == "incomplete_extraction"]
    modes = {}
    for mode in ("v03", "v03s"):
        rows = [r["modes"][mode] for r in complete]
        total = {
            name: sum(r[name] for r in rows)
            for name in (
                "baseline_sinks",
                "raw_suppressed",
                "accepted_suppression",
                "contract_sinks",
                "confirmed_fp",
                "confirmed_fp_raw_removed",
                "root_causes_partly_suppressed",
                "root_causes_fully_suppressed",
            )
        }
        total["contract_coverage"] = (
            total["contract_sinks"] / total["baseline_sinks"] if total["baseline_sinks"] else None
        )
        total["fp_reduction_rate_reviewed_subset"] = (
            total["confirmed_fp_raw_removed"] / total["confirmed_fp"]
            if total["confirmed_fp"]
            else None
        )
        suppressed_labels = collections.Counter()
        decisions = collections.Counter()
        for row in rows:
            suppressed_labels.update(row["suppressed_by_label"])
            decisions.update(row["decision_counts"])
        total.update(suppressed_by_label=dict(suppressed_labels), decision_counts=dict(decisions))
        modes[mode] = total
    return {
        "repository_statuses": dict(
            collections.Counter(r.get("execution_status", r["status"]) for r in results)
        ),
        "complete_repositories": len(complete),
        "incomplete_extraction_repositories": len(incomplete),
        "zero_alert_complete_repositories": sum(r["counts"]["none"] == 0 for r in complete),
        "complete_counts": {mode: sum(r["counts"][mode] for r in complete) for mode in MODES},
        "scoped_incremental_raw_suppressed": sum(
            r["scoped_incremental_raw_suppressed"] for r in complete
        ),
        "modes_complete_repositories_only": modes,
        "incomplete_results_reported_separately": True,
        "safety_failure": any(r["status"] == "failed_acceptance" for r in results),
        "labels_complete_for_complete_repositories": (
            all(r["labels_complete"] for r in complete) if complete else None
        ),
        "all_sample_scans_complete": bool(results) and len(complete) == len(results),
        "independence_and_review_require_separate_confirmation": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--run", required=True, help="Repository-relative run.json")
    parser.add_argument(
        "--labels", help="Repository-relative JSON array of supplied review records"
    )
    parser.add_argument("--output", required=True, help="New repository-relative report directory")
    args = parser.parse_args()
    try:
        run = json.loads(local(args.root, args.run).read_bytes())
        labels_list = json.loads(local(args.root, args.labels).read_bytes()) if args.labels else []
        labels = {r["unit_id"]: r for r in labels_list}
        if len(labels) != len(labels_list):
            raise ValueError("Duplicate label unit_id")
        results, packet, template, review_priority = [], [], [], {}
        for record in run["records"]:
            if record["status"] not in {"completed", "incomplete_extraction", "failed_acceptance"}:
                results.append({k: record[k] for k in ("rank", "repository", "commit", "status")})
                continue
            paths = {k: local(args.root, value) for k, value in record["files"].items()}
            for key, path in paths.items():
                if file_digest(path) != record["file_hashes"][key]:
                    raise ValueError(f"Run artifact hash mismatch: {path}")
            result = snapshot(record["repository"], record["commit"], paths, labels)
            result["execution_status"] = record["status"]
            result["extraction"] = record.get("extraction")
            result["group_id"] = record.get("group_id")
            result["near_duplicate_review"] = record.get("near_duplicate_review", "pending")
            for row in result["rows"]:
                removed = any(row["raw_suppressed"].values()) or not row["retained"]["all"]
                key = (
                    f"security-triage/wave-c-v1/review/{row['repository']}@{row['commit']}/"
                    f"{row['file']}:{row['line']}:{row['column']}"
                )
                review_priority[row["unit_id"]] = (
                    not removed,
                    hashlib.sha256(key.encode()).hexdigest(),
                )
            packet.extend(result.pop("review_packet"))
            template.extend(result.pop("label_template"))
            results.append(result)
        if set(labels) - {r["unit_id"] for r in template}:
            raise ValueError("Labels contain unknown/unselected sink IDs")
        # Hidden policy decisions and original labels are absent from the first-pass packet.
        packet.sort(key=lambda r: review_priority[r["unit_id"]])
        output = local(args.root, args.output)
        output.mkdir(parents=True, exist_ok=False)
        write_json(
            output / "report.json",
            {
                "version": "wave-c-evaluation-v1",
                "repositories": results,
                "aggregate": aggregate(results),
                "run_sha256": file_digest(local(args.root, args.run)),
                "labels_sha256": file_digest(local(args.root, args.labels))
                if args.labels
                else None,
                "review_packet_not_fully_blind": "Prior exposure/source context may reveal tooling",
            },
        )
        write_json(output / "review_packet.json", packet)
        write_json(output / "labels.template.json", template)
        print(
            f"Reported {len(results)} repositories, {len(template)} review units; "
            "no labels invented"
        )
        if any(r["status"] == "failed_acceptance" for r in results):
            parser.exit(2, "Evaluation failed acceptance; preserve outputs and stop confirmation\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Evaluation incomplete: {error}\n")


if __name__ == "__main__":
    main()
