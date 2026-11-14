"""Turn the copied SecBench.js metadata into the label file of this check, mechanically.

Every entry of secbench-metadata.json becomes one npm source with one documented site: the
`sink` position the dataset publishes. Nothing is chosen by hand. An entry is excluded, with
its reason kept, only when its published fields cannot name a source or a site.

    python experiments/evaluation/independent-secbench/build_labels.py [--check]
"""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SINK = re.compile(r"^(?P<path>.+):(?P<line>[1-9][0-9]*):(?P<column>[1-9][0-9]*)$")


def build(metadata):
    base = (
        f"https://github.com/{metadata['repository']}/blob/{metadata['commit']}/"
        f"{metadata['folder']}/"
    )
    sources, excluded = [], []
    for entry in metadata["entries"]:
        directory = entry["directory"]
        package, _, version = directory.rpartition("_")
        dependencies = entry.get("dependencies") or {}
        sink = SINK.match(entry.get("sink") or "")
        if dependencies.get(package) != version:
            # The folder names one package and version, the metadata installs another.
            reason = "published dependency does not match the folder's package and version"
        elif sink is None:
            reason = "published sink is not a path:line:column position"
        else:
            reason = None
        if reason:
            excluded.append({"directory": directory, "reason": reason})
            continue
        sources.append(
            {
                "id": directory,
                "language": "javascript",
                "kind": "npm",
                "package": package,
                "version": version,
                "vulnerability_id": entry.get("id") or None,
                "sites": [
                    {
                        "path": sink["path"],
                        "line": int(sink["line"]),
                        "column": int(sink["column"]),
                        "basis": "dataset_published_sink",
                        "evidence": base + directory + "/package.json",
                    }
                ],
            }
        )
    return {
        "description": (
            "Command-injection sinks published by SecBench.js for npm packages that the "
            "project's frozen pair inventory never contained. Positives only: no site is "
            "labeled safe."
        ),
        "dataset_commit": metadata["commit"],
        "sources": sources,
        "excluded": excluded,
    }


def main(argv=None):
    metadata = json.loads((HERE / "secbench-metadata.json").read_bytes())
    data = (json.dumps(build(metadata), indent=2, ensure_ascii=False) + "\n").encode()
    target = HERE / "labels.json"
    if "--check" in (argv if argv is not None else sys.argv[1:]):
        if target.read_bytes() != data:
            print("labels.json differs from the metadata")
            return 1
        return 0
    target.write_bytes(data)
    labels = json.loads(data)
    print(f"sources {len(labels['sources'])}, excluded {len(labels['excluded'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
