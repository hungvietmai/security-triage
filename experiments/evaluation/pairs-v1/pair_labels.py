"""Build a label file for one split of pairs-v1 from the locked manifests. Scans nothing.

The output has the format ../independent-secbench/configurations.py scores: one source per pair
(its vulnerable version) and one documented site per resolved known location. A pair whose
location is unresolved becomes a source without sites: its candidates are counted, never scored.
Each source carries the SHA-256 the source lock recorded, so that `--verify` can tell whether
an exported report was produced from the locked bytes.

    python experiments/evaluation/pairs-v1/pair_labels.py <development|held_out> [--pair ID] \
        [--json OUT]
    python experiments/evaluation/pairs-v1/pair_labels.py <split> --verify <inputs-dir>

Reading the manifests is not an evaluation. Do not scan a held-out pair before the owner has
decided to open that set and the protocol is committed; see README.md.
"""

import argparse
import json
from pathlib import Path

PAIRS = Path(__file__).resolve().parents[2] / "pairs"


def source_fields(source):
    if source["source_kind"] == "npm_tarball":
        return {
            "kind": "npm",
            "package": source["package_name"],
            "version": source["package_version"],
        }
    owner, _, repo = source["repository"].partition("/")
    return {"kind": "github", "owner": owner, "repo": repo, "commit": source["commit"]}


def build(split, pairs=PAIRS, only=None):
    lock = json.loads((pairs / "sources.lock.json").read_bytes())
    index = json.loads((pairs / "index.json").read_bytes())
    sources, not_acquired = [], []
    for pair_id in index["manifests"]:
        manifest = json.loads((pairs / f"{pair_id}.json").read_bytes())
        if manifest["split"] != split or (only and pair_id != only):
            continue
        locked = lock.get(pair_id, {}).get("vulnerable", {})
        if locked.get("status") != "locked":
            # The archive was never acquired (Ray exceeded the download bound): nothing to scan.
            not_acquired.append(pair_id)
            continue
        known_file = pairs / pair_id / "known-locations.json"
        known = json.loads(known_file.read_bytes())
        sources.append(
            {
                "id": pair_id,
                "language": manifest["language"],
                **source_fields(manifest["vulnerable_source"]),
                "vulnerability_id": manifest.get("vulnerability_id"),
                "prior_exposure": bool(manifest.get("prior_exposure")),
                "locked_sha256": locked["sha256"],
                "known_location_status": known["status"],
                "sites": [
                    {
                        "path": location["path"],
                        "line": location["span"]["startLine"],
                        "basis": location["provenance"]["kind"],
                    }
                    for location in known["locations"]
                    if location["status"] == "resolved"
                ],
            }
        )
    return {
        "description": f"pairs-v1, split {split}: vulnerable versions and resolved known locations",
        "split_id": index["split_id"],
        "sources": sources,
        "not_acquired": not_acquired,
    }


def verify(labels, inputs):
    """Per source: was the exported report produced from the bytes the lock recorded."""
    rows = []
    for source in labels["sources"]:
        report_file = Path(inputs) / source["id"] / "report.json"
        if not report_file.is_file():
            rows.append({"id": source["id"], "locked_bytes": None})
            continue
        scanned = json.loads(report_file.read_bytes())["snapshot"]["sha256"]
        rows.append({"id": source["id"], "locked_bytes": scanned == source["locked_sha256"]})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("split", choices=("development", "held_out"))
    parser.add_argument("--pair")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args(argv)
    labels = build(args.split, only=args.pair)
    if args.verify:
        rows = verify(labels, args.verify)
        for row in rows:
            print(
                row["id"],
                {True: "locked bytes", False: "DIFFERENT BYTES", None: "no report"}[
                    row["locked_bytes"]
                ],
            )
        return 0 if all(row["locked_bytes"] for row in rows) else 1
    data = (json.dumps(labels, indent=2, ensure_ascii=False) + "\n").encode()
    if args.json:
        args.json.write_bytes(data)
    sites = sum(len(source["sites"]) for source in labels["sources"])
    print(
        f"{args.split}: {len(labels['sources'])} sources, {sites} resolved sites, "
        f"{len(labels['not_acquired'])} never acquired"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
