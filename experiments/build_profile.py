"""Regenerate a scan profile's compiled policy JSON and pinned file hashes.

The manifest's hand-written keys (languages, policy, specification, rule_claims) choose
the files; this script derives everything else from those files. Run it after changing
any of them; CI runs `--check`, which fails while the committed profile is stale.

    python experiments/build_profile.py [--check]
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "profiles/command-injection-v0.1/profile.json"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def compile_policy(source_bytes):
    return (json.dumps(yaml.safe_load(source_bytes), indent=2, ensure_ascii=False) + "\n").encode()


def build(manifest_path=MANIFEST):
    """Return {repository-relative path: expected bytes} for every generated file."""
    manifest = json.loads((ROOT / manifest_path).read_bytes())
    policy = manifest["policy"]
    compiled = compile_policy((ROOT / policy["source"]).read_bytes())
    paths = {policy["source"], manifest["specification"], manifest["rule_claims"]}
    for entry in manifest["languages"].values():
        paths.add(entry["config"])
        if "sink_locator" in entry:
            paths.add(entry["sink_locator"])
        config = json.loads((ROOT / entry["config"]).read_bytes())
        # KeyError for a URL rule is deliberate: a profile only pins local rule files.
        paths.update(rule["path"] for rule in config["semgrep_rules"])
    files = {path: _sha256((ROOT / path).read_bytes()) for path in paths}
    files[policy["compiled"]] = _sha256(compiled)
    manifest["files"] = dict(sorted(files.items()))
    rendered = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()
    return {policy["compiled"]: compiled, manifest_path: rendered}


def stale(manifest_path=MANIFEST):
    expected = build(manifest_path)
    return sorted(
        path
        for path, data in expected.items()
        if not (ROOT / path).is_file() or (ROOT / path).read_bytes() != data
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the profile is stale")
    args = parser.parse_args(argv)
    if args.check:
        outdated = stale()
        for path in outdated:
            print("stale:", path)
        return 1 if outdated else 0
    for path, data in build().items():
        (ROOT / path).write_bytes(data)
        print("wrote", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
