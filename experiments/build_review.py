"""Build an offline, unapproved review packet from preserved pilot evidence.

Run as python -m experiments.build_review. No scanner, label inference or scoring.
"""

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import tarfile
import tempfile
import sys
from pathlib import Path, PurePosixPath

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.scanners.sarif import sarif_findings
from experiments.run_pilot import write_json

VERSION = "sink-proposals-v1"
SUPPORTED_RULE = "js/shell-command-constructed-from-input"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(kind, value):
    return kind + ":" + sha(json.dumps(value, sort_keys=True).encode())


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return path.as_posix()


def load_evidence(path, attempt):
    """Verify original bytes before using the repository-owned evidence bundle."""
    envelope = json.loads(path.read_text())
    if envelope.get("format") != "gzip-base64-json-v1":
        raise ValueError("Unsupported evidence envelope")
    decoded = gzip.decompress(base64.b64decode(envelope["payload"], validate=True))
    if sha(decoded) != envelope["decoded_sha256"]:
        raise ValueError("Evidence payload checksum mismatch")
    bundle = json.loads(decoded)
    if bundle.get("format") != "pilot-evidence-v1":
        raise ValueError("Unsupported evidence format")
    files = {}
    for name, entry in bundle["attempts"][attempt].items():
        if entry["encoding"] == "base64":
            data = base64.b64decode(entry["content"], validate=True)
        elif entry["encoding"] == "utf-8":
            data = entry["content"].encode()
        else:
            raise ValueError("Unsupported artifact encoding")
        if sha(data) != entry["sha256"]:
            raise ValueError(f"Artifact checksum mismatch: {name}")
        files[name] = data
    return files


def source_texts(archive, root):
    texts = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        for member in bundle:
            name = relative_path(member.name)
            if not name or not name.startswith(root + "/") or not member.isfile():
                continue
            try:
                texts[name[len(root) + 1 :]] = (
                    bundle.extractfile(member).read().decode()
                )
            except UnicodeDecodeError:
                continue
    return texts


def propose(row, sources):
    """Narrow format adapter: message-linked shell-command location, not nearby lines.

    Source bounds are checked, but no AST/callee proof is claimed. Reviewer must
    confirm call span and argument role. Unsupported formats keep their fallback.
    """
    if row["tool"] != "codeql" or row["rule_id"] != SUPPORTED_RULE:
        return [], "unsupported_rule"
    result = row["raw_result"]
    refs = set(re.findall(r"\[shell command\]\((\d+)\)", row["message"]))
    if not refs:
        return [], "no_explicit_shell_link"
    proposals = {}
    for ref in sorted(refs):
        matches = [
            loc
            for loc in result.get("relatedLocations", [])
            if str(loc.get("id")) == ref
        ]
        if len(matches) != 1:
            return [], "ambiguous_or_missing_related_location"
        physical = matches[0].get("physicalLocation", {})
        path = relative_path(physical.get("artifactLocation", {}).get("uri"))
        region = physical.get("region", {})
        keys = ("startLine", "startColumn", "endLine", "endColumn")
        span = {key: region.get(key) for key in keys}
        if span["endLine"] is None:
            span["endLine"] = span["startLine"]
        if path not in sources or any(
            type(value) is not int or value < 1 for value in span.values()
        ):
            return [], "invalid_or_unresolved_source_span"
        lines = sources[path].splitlines()
        sl, sc, el, ec = (span[key] for key in keys)
        # SARIF defaults to UTF-16 columns. Keep non-ASCII spans for manual review.
        if not (sl <= el <= len(lines)) or (sl == el and ec <= sc):
            return [], "invalid_or_unresolved_source_span"
        if not all(line.isascii() for line in lines[sl - 1 : el]):
            return [], "column_encoding_requires_review"
        if sc > len(lines[sl - 1]) + 1 or ec > len(lines[el - 1]) + 1:
            return [], "invalid_or_unresolved_source_span"
        anchor = {
            "snapshot_sha256": row["snapshot_sha256"],
            "path": path,
            "sink_anchor": span,
            "argument_role": "shell_command",
        }
        unit_id = identity("sink", anchor)
        proposals[unit_id] = {
            "unit_id": unit_id,
            "identity": anchor,
            "evidence": {
                "related_location_id": int(ref),
                "message_link": f"[shell command]({ref})",
            },
            "source_context": "\n".join(
                lines[max(0, sl - 2) : min(len(lines), el + 1)]
            ),
            "status": "proposed_needs_review",
        }
    return list(proposals.values()), "explicit_sink_candidate"


def build_packet(files, evidence_sha, attempt):
    run, case = json.loads(files["run.json"]), json.loads(files["case.json"])
    if run["split"] != "development":
        raise ValueError("Only development evidence is supported")
    snapshot = sha(files["source.tgz"])
    if snapshot != run["snapshot_sha256"] or snapshot != case["artifact_sha256"]:
        raise ValueError("Source identity mismatch")
    sources = source_texts(files["source.tgz"], case["archive_root"])
    rows, scanner_status = [], {}
    with tempfile.TemporaryDirectory() as folder:
        for tool in ("semgrep", "codeql"):
            step = run["steps"].get(tool, {})
            scanner_status[tool] = {"recorded_status": step.get("status", "not_run")}
            name = tool + ".sarif"
            if name not in files:
                scanner_status[tool]["sarif_available"] = False
                continue
            if sha(files[name]) != step.get("sarif_sha256"):
                raise ValueError(f"Run/SARIF identity mismatch: {tool}")
            path = Path(folder) / name
            path.write_bytes(files[name])
            findings, complete = sarif_findings(path, tool, snapshot)
            scanner_status[tool].update(sarif_available=True, sarif_complete=complete)
            for row in findings:
                row["raw_reference"] = {
                    "sarif": name,
                    "sha256": sha(files[name]),
                    "raw_id": row["raw_id"],
                }
            rows.extend(findings)
    packet = {
        "schema_version": VERSION,
        "builder_sha256": sha(Path(__file__).read_bytes()),
        "case_id": case["case_id"],
        "evidence_sha256": evidence_sha,
        "attempt": attempt,
        "protocol_commit": run["protocol_commit"],
        "configuration_commit": run["configuration_commit"],
        "scanner_status": scanner_status,
        "review_status": "unreviewed",
        "blinded": False,
        "raw_findings": [],
        "candidate_groups": {},
        "labels": {},
        "metrics": None,
    }
    for row in rows:
        fallback = {
            "snapshot_sha256": snapshot,
            "reported_path": relative_path(row["reported_path"])
            or row["reported_path"],
            "reported_region": row["reported_region"],
            "discriminator": row["raw_reference"],
        }
        fallback_id = identity("fallback", fallback)
        candidates, reason = propose(row, sources)
        record = {key: value for key, value in row.items() if key != "raw_result"}
        record.update(
            fallback_unit_id=fallback_id,
            fallback_identity=fallback,
            candidates=candidates,
            proposal_reason=reason,
            mapping_review={
                "decision": "unresolved",
                "accepted_unit_ids": [],
                "reviewer": None,
                "reason": None,
            },
        )
        packet["raw_findings"].append(record)
        for unit_id in [fallback_id] + [
            candidate["unit_id"] for candidate in candidates
        ]:
            packet["labels"].setdefault(
                unit_id,
                {
                    "technical_verdict": "unresolved",
                    "scope_verdict": "unresolved",
                    "adjudicated_cwes": [],
                    "truth_set": "unresolved",
                    "evidence_references": [],
                    "assumptions": [],
                    "reviewer": None,
                    "reviewed_at": None,
                    "label_version": None,
                    "threat_model_version": None,
                    "second_review": None,
                },
            )
        for candidate in candidates:
            packet["candidate_groups"].setdefault(candidate["unit_id"], []).append(
                row["raw_reference"]
            )
    with_candidate = sum(bool(row["candidates"]) for row in packet["raw_findings"])
    count = len(rows)
    packet["summary"] = {
        "raw_findings": count,
        "fallback_records_retained": count,
        "raw_with_sink_proposal": with_candidate,
        "raw_without_sink_proposal": count - with_candidate,
        "unique_proposed_sinks": len(packet["candidate_groups"]),
        "accepted_sink_assignments": 0,
        "unresolved_mapping_records": count,
        "automatic_unmatched_rate": 1.0 if count else None,
        "note": (
            "Proposals are not assignments. Candidate and fallback labels are "
            "alternatives, not additive scoring units."
        ),
    }
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--attempt", default="002")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; preserve review history with a new path")
    packet = build_packet(
        load_evidence(args.evidence, args.attempt),
        sha(args.evidence.read_bytes()),
        args.attempt,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, packet)
    print(json.dumps(packet["summary"], indent=2))


if __name__ == "__main__":
    main()
