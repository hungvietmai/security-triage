"""Derive closeout tables and blank owner-review files from saved Wave C data.

No scanner, network request, source import, or label inference. Existing output
directories are rejected, so completed review files cannot be overwritten.
Run from the repository root.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
from datetime import datetime, timezone


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--review-output", required=True)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    output = (root / args.output).resolve()
    review = (root / args.review_output).resolve()
    for target in (output, review):
        if not target.is_relative_to(root / "experiments/wave-c") or target.exists():
            parser.error("Both outputs must be fresh directories under experiments/wave-c")
    if output == review or output.is_relative_to(review) or review.is_relative_to(output):
        parser.error("Outputs must be separate sibling directories")

    inputs = {}

    def read(name):
        path = root / name
        inputs[name] = sha(path)
        return load(path)

    sources = read("experiments/wave-c/sources.lock.json")
    exclusion_records = read("experiments/wave-c/exclusions.json")["repositories"]
    excluded = {row["repository"].lower() for row in exclusion_records}
    primary = "experiments/wave-c/results/study-001"
    report = read(f"{primary}/evaluation/report.json")
    run = read(f"{primary}/original_run.json")
    runtime = read(f"{primary}/runtime.json")
    packet = read(f"{primary}/evaluation/review_packet.json")
    paths = read("experiments/wave-c/results/paths-001/summary.json")
    overlap = read(f"{primary}/exact_file_overlap_screen.json")
    for name in (
        "experiments/wave-c/EXECUTION_LOCK.sha256",
        f"{primary}/RESULTS_LOCK.sha256",
        "experiments/wave-c/results/review-001/REVIEW_LOCK.sha256",
        "experiments/wave-c/results/paths-001/PATHS_LOCK.sha256",
    ):
        inputs[name] = sha(root / name)
    by_repo = {row["repository"]: row for row in report["repositories"]}
    run_by_repo = {row["repository"]: row for row in run["records"]}
    rows = []
    ledger = []
    for source in sources["records"]:
        repository = source["repository"]
        evaluated = by_repo[repository]
        executed = run_by_repo[repository]
        counts = evaluated.get("counts", {})
        rows.append({
            "rank": source["rank"], "repository": repository,
            "commit": source["commit"], "acquisition_status": source["status"],
            "execution_status": executed["status"],
            **{mode: counts.get(mode) for mode in ("none", "all", "v03", "v03s")},
            "labels_complete": evaluated.get("labels_complete"),
            "evaluator_status": evaluated["status"],
            "acquisition_error": source.get("error", ""),
        })
        metadata_ref = source["objects"]["repository_metadata"]
        metadata = read(metadata_ref["path"])
        if inputs[metadata_ref["path"]] != metadata_ref["sha256"]:
            raise ValueError("Repository metadata checksum mismatch")
        identities = {repository.lower(), metadata["full_name"].lower()}
        for field in ("parent", "source"):
            if metadata.get(field):
                identities.add(metadata[field]["full_name"].lower())
        ledger.append({
            "rank": source["rank"], "repository": repository,
            "commit": source["commit"], "repository_id": metadata["id"],
            "canonical_repository": metadata["full_name"],
            "description": metadata.get("description"),
            "acquisition_status": source["status"], "fork": metadata.get("fork"),
            "parent": (metadata.get("parent") or {}).get("full_name"),
            "source": (metadata.get("source") or {}).get("full_name"),
            "excluded_identity_matches": sorted(identities & excluded),
            "repository_metadata": metadata_ref,
            "semantic_near_duplicate_review": "pending" if source["status"] == "prepared" else "not_assessed_no_usable_snapshot",
            "independence_confirmed": False,
        })

    selections = {
        3: {
            "README.md": [(278, 284)],
            "SECURITY.md": [(25, 30)],
            "docs/spec/09-cost-observability.md": [(54, 56), (87, 89), (183, 191), (353, 355)],
            "docs/implementation/cost-dashboard.md": [(28, 28)],
            "atomic_agents/dashboard/serve.py": [(32, 43), (70, 84), (97, 116), (173, 190)],
            "atomic_agents/dashboard/__main__.py": [(30, 60)],
            "atomic_agents/_platform.py": [(17, 26)],
            "atomic_agents/_io.py": [(96, 120)],
        },
        8: {
            "src/pipecat/runner/run.py": [(212, 220), (260, 273), (298, 303), (972, 972), (1055, 1060)],
            "src/pipecat/runner/types.py": [(65, 82)],
        },
    }
    evidence = []
    for rank, selected in selections.items():
        source = next(row for row in sources["records"] if row["rank"] == rank)
        archive_ref = source["objects"]["archive"]
        archive = root / archive_ref["path"]
        if sha(archive) != archive_ref["sha256"]:
            raise ValueError("Archive checksum mismatch")
        inputs[archive_ref["path"]] = archive_ref["sha256"]
        with tarfile.open(archive, "r:gz") as tar:
            for relative, ranges in selected.items():
                path = root / "artifacts/wave-c/study-001" / f"{rank:02}" / "extracted" / source["archive_root"] / relative
                member = tar.getmember(source["archive_root"] + "/" + relative)
                if not member.isfile():
                    raise ValueError("Expected a regular source member")
                with tar.extractfile(member) as stream:
                    archive_bytes = stream.read()
                if path.read_bytes() != archive_bytes:
                    raise ValueError("Selected source differs from locked archive")
                inputs[path.relative_to(root).as_posix()] = sha(path)
                lines = archive_bytes.decode("utf-8").splitlines()
                evidence.append({
                    "repository": source["repository"], "commit": source["commit"],
                    "file": relative, "sha256": sha(path), "archive_sha256": archive_ref["sha256"],
                    "matches_locked_archive": True,
                    "source_url": f"https://github.com/{source['repository']}/blob/{source['commit']}/{relative}",
                    "excerpts": [{"start_line": start, "end_line": end,
                                  "lines": lines[start - 1:end]} for start, end in ranges],
                })
    for name, ranges in {
        "experiments/v03-interprocedural-guard/ql/IpgGuard.qll": [(72, 106), (840, 884)],
        "experiments/v03-interprocedural-guard/SPEC.md": [(112, 140)],
    }.items():
        path = root / name
        inputs[name] = sha(path)
        lines = path.read_text(encoding="utf-8").splitlines()
        evidence.append({"repository": "local frozen method", "file": name,
                         "sha256": sha(path),
                         "excerpts": [{"start_line": start, "end_line": end,
                                       "lines": lines[start - 1:end]} for start, end in ranges]})

    if len(rows) != 12 or len(packet) != 8:
        raise ValueError("Unexpected study/review population")
    if report["aggregate"]["complete_counts"] != {"none": 8, "all": 5, "v03": 5, "v03s": 5}:
        raise ValueError("Primary counts differ from closeout assumptions")
    output.mkdir(parents=True)
    review.mkdir(parents=True)
    with (output / "repositories.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    save(output / "relationships.json", {
        "records": ledger,
        "exact_byte_overlap_screen": overlap,
        "limitations": "Metadata is a screen, not semantic independence confirmation. No historical held-out source was opened for this closeout.",
    })
    save(output / "source_evidence.json", evidence)
    save(output / "metrics.json", {
        "classification": "descriptive closeout of saved Wave C outputs; human review pending",
        "primary_aggregate": report["aggregate"],
        "repositories_attempted": len(rows), "review_units": len(packet),
        "primary_command_count": sum(row["command_count"] for row in runtime),
        "primary_command_wall_seconds": sum(row["command_wall_seconds"] for row in runtime),
        "path_diagnostics": {key: paths[key] for key in (
            "total_units", "total_path_exemplars", "total_located_abstract_edge_rows", "diagnostic_command_wall_seconds")},
        "human_review_complete": False, "confirmed_fp_rate": None,
        "v03_incremental_effect_observed": 0,
        "independence_confirmed": False,
    })
    template_name = f"{primary}/evaluation/labels.template.json"
    template = root / template_name
    inputs[template_name] = sha(template)
    shutil.copyfile(template, review / "labels.owner-pass1.json")
    units = {unit["unit_id"]: unit for unit in packet}
    with (root / primary / "evaluation/review_queue.csv").open(encoding="utf-8", newline="") as stream:
        queue = list(csv.DictReader(stream))
    shutil.copyfile(root / primary / "evaluation/review_queue.csv", review / "review_queue.csv")
    save(review / "session.json", {
        "status": "not_started", "reviewer": None, "started_at": None,
        "finished_at": None, "active_review_seconds": None,
        "second_pass_earliest_at": None,
        "unit_activity": [{"unit_id": row["unit_id"], "active_review_seconds": None} for row in queue],
    })
    notes = ["# Ghi chú lượt rà đầu", "", "Tệp làm việc chưa có nhãn hoặc xác nhận của người rà.",
             "Không lấy ngày tạo tệp làm ngày bắt đầu rà. Ghi thời gian hoạt động thực tế trong session.json.", ""]
    for row in queue:
        unit = units[row["unit_id"]]
        notes.extend([f"## {unit['unit_id']}", "", f"Source: {row['source_url']}", "",
                      f"Đường đi: [thẻ sink](../../results/paths-001/units/{unit['unit_id']}.md).", "",
                      "- Nhãn kỹ thuật và phạm vi:", "- Bằng chứng tại source/caller/đường đi:",
                      "- Chính sách gốc và quyền truy cập:", "- Giả định áp dụng và căn cứ:",
                      "- Điểm chưa xác định / luồng chưa rà:", "- Root cause và các sink liên quan:", ""])
    (review / "notes.md").write_text("\n".join(notes), encoding="utf-8", newline="\n")
    save(output / "provenance.json", {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "script": str(Path(__file__).resolve().relative_to(root)),
        "script_sha256": sha(Path(__file__).resolve()),
        "argv": ["--output", args.output, "--review-output", args.review_output],
        "input_hashes": inputs,
        "owner_review_template_copied_exactly": sha(template) == sha(review / "labels.owner-pass1.json"),
        "source_files_checked_against_locked_archives": sum(row.get("matches_locked_archive", False) for row in evidence),
        "scanner_commands_run": 0, "source_imported_or_executed": False,
        "human_review_started": False, "new_model_pack_created": False,
    })
    print(f"Derived {len(rows)} repository rows, {len(ledger)} metadata screens, {len(evidence)} selected source/method records; 8 blank owner labels.")


if __name__ == "__main__":
    main()
