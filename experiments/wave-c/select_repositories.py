"""Select repository snapshots using pinned metadata only; never fetch or scan source."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

COMMIT_URL = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commit/([0-9a-fA-F]{40})"
)
REPOSITORY = re.compile(r"[a-z0-9_.-]+/[a-z0-9_.-]+")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def local_path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "\\" in name
        or ":" in name
        or not relative.parts
    ):
        raise ValueError(f"Unsafe repository-relative path: {name}")
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes repository: {name}")
    return path


def pinned_bytes(root: Path, entry: dict) -> bytes:
    data = local_path(root, entry["path"]).read_bytes()
    if digest(data) != entry["sha256"]:
        raise ValueError(f"Input hash mismatch: {entry['path']}")
    return data


def select(root: Path, config: dict) -> dict:
    """Keep a complete selection ledger; failures after selection never cause replacement."""
    if not isinstance(config["sample_size"], int) or config["sample_size"] < 1:
        raise ValueError("sample_size must be a positive integer")
    source = json.loads(pinned_bytes(root, config["advisories"]))
    exclusions = json.loads(pinned_bytes(root, config["exclusions"]))
    pinned_bytes(root, config["protocol"])
    for entry in exclusions["inputs"]:
        pinned_bytes(root, entry)
    excluded = {}
    for row in exclusions["repositories"]:
        repo = row["repository"]
        if not REPOSITORY.fullmatch(repo) or repo in excluded:
            raise ValueError(f"Noncanonical or duplicate excluded repository: {repo}")
        excluded[repo] = row["reasons"]
    seed = config["seed"]
    repositories: dict[str, list[dict]] = {}
    rejected = []
    for advisory in source:
        if advisory["decision"] != "candidate" or "CWE-22" not in advisory["cwes"]:
            continue
        for reference in advisory["fix_commits"]:
            match = COMMIT_URL.fullmatch(reference)
            if not match:
                rejected.append(
                    {
                        "advisory": advisory["ghsa_id"],
                        "reference": reference,
                        "reason": "requires_full_github_commit_url",
                    }
                )
                continue
            owner, name, commit = (value.lower() for value in match.groups())
            repo = f"{owner}/{name.removesuffix('.git')}"
            anchor = {
                "advisory": advisory["ghsa_id"],
                "commit": commit,
                "reference": reference,
                "anchor_key": digest(
                    f"{seed}anchor/{advisory['ghsa_id']}/{repo}/{commit}".encode()
                ),
            }
            if anchor not in repositories.setdefault(repo, []):
                repositories[repo].append(anchor)
    candidates, exclusions_ledger = [], []
    for repo, anchors in sorted(repositories.items()):
        if repo in excluded:
            exclusions_ledger.append({"repository": repo, "reasons": excluded[repo]})
            continue
        anchors.sort(key=lambda a: (a["anchor_key"], a["advisory"], repo, a["commit"]))
        candidates.append(
            {
                "repository": repo,
                "order_key": digest(f"{seed}repository/{repo}".encode()),
                "snapshot": anchors[0],
                "references": anchors,
            }
        )
    candidates.sort(key=lambda row: (row["order_key"], row["repository"]))
    for rank, row in enumerate(candidates, 1):
        row["rank"] = rank
        row["selection"] = "selected" if rank <= config["sample_size"] else "not_selected"
    return {
        "version": "wave-c-v1",
        "status": "metadata_selected_not_acquired_not_scanned",
        "seed": seed,
        "requested_repositories": config["sample_size"],
        "selected_repositories": min(config["sample_size"], len(candidates)),
        "configuration_sha256": digest(encode(config)),
        "inputs": {key: config[key] for key in ("advisories", "exclusions", "protocol")},
        "source_commit": config["source_commit"],
        "candidates": candidates,
        "excluded_repositories": exclusions_ledger,
        "rejected_references": sorted(
            rejected, key=lambda row: (row["advisory"], row["reference"])
        ),
    }


def encode(data: dict) -> bytes:
    return (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--config", default="experiments/wave-c/selection.json")
    parser.add_argument("--output", default="experiments/wave-c/inventory.json")
    parser.add_argument("--check", action="store_true", help="Reproduce without writing")
    args = parser.parse_args()
    try:
        config = json.loads(local_path(args.root, args.config).read_bytes())
        result = select(args.root, config)
        expected = encode(result)
        output = local_path(args.root, args.output)
        if args.check:
            if output.read_bytes() != expected:
                raise ValueError("Inventory differs from deterministic selection")
        else:
            with output.open("xb") as stream:
                stream.write(expected)
        print(
            f"{'Verified' if args.check else 'Selected'} "
            f"{result['selected_repositories']} repositories; "
            f"{len(result['excluded_repositories'])} excluded; no source fetched or scanned"
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Selection failed: {error}\n")


if __name__ == "__main__":
    main()
