"""Build vulnerable/safe labels from the rule tests of semgrep-rules, mechanically.

The upstream repository keeps, next to every rule, a test file whose comments say where the
rule must report (`ruleid: <id>`) and where it must not (`ok: <id>`). For rules that track
untrusted data into an OS command (taint mode, tagged CWE-78) these comments are the rule
author's statement that the next line of code is, or is not, a command injection.

Selection, with nothing chosen by hand:
- rule files under python/, javascript/ and typescript/ that contain `mode: taint` and `CWE-78`;
- their test files: same folder and name, extension .py, .js, .jsx, .ts or .tsx;
- every `ruleid:` / `ok:` comment naming one of those rules labels the next code line.
  `todoruleid:` and `todook:` (known wrong results of the rule) are not labels.

The archive is read in memory and never unpacked or executed.

    python experiments/evaluation/independent-labeled/build_labels.py <archive.tar.gz> [--check]
"""

import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
OWNER, REPO = "semgrep", "semgrep-rules"
# The commit the profile's own Semgrep rules were copied from.
COMMIT = "a84ff9cc2453ca91d581380de4b8b3f272f6f4be"
ROOTS = ("python", "javascript", "typescript")
TEST_EXTENSIONS = {".py": "python", ".js": "javascript", ".jsx": "javascript"}
TEST_EXTENSIONS |= {".ts": "javascript", ".tsx": "javascript"}
RULE_ID = re.compile(r"^\s*-\s+id:\s*(\S+)\s*$", re.MULTILINE)
ANNOTATION = re.compile(r"^\s*(?:#|//)\s*(ruleid|ok)\s*:\s*(.+?)\s*$")
COMMENT = re.compile(r"^\s*(?:#|//|/\*|\*)")


def profile_rule_paths(profile_root):
    """Upstream paths of the Semgrep rules the scan profile itself runs."""
    paths = set()
    for language in ("python", "javascript"):
        config = json.loads((profile_root / f"{language}.json").read_bytes())
        for rule in config["semgrep_rules"]:
            marker = f"/blob/{COMMIT}/"
            if marker in rule.get("upstream_url", ""):
                paths.add(rule["upstream_url"].split(marker, 1)[1])
    return paths


def label_lines(text, rule_ids):
    """(line number, label, rule ids) for each annotated code line of one test file."""
    pending = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = ANNOTATION.match(line)
        if match:
            named = {name.strip() for name in match.group(2).split(",")} & rule_ids
            for name in named:
                pending[name] = match.group(1)
            continue
        if not pending or not line.strip() or COMMENT.match(line):
            continue
        kinds = set(pending.values())
        # A line one rule must report is vulnerable even if another rule must stay silent.
        yield number, "vulnerable" if "ruleid" in kinds else "safe", sorted(pending)
        pending = {}


def build(archive_bytes, profile_rules):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            relative = PurePosixPath(*path.parts[1:])
            if not member.isfile() or not relative.parts or relative.parts[0] not in ROOTS:
                continue
            files[str(relative)] = archive.extractfile(member).read().decode("utf-8", "replace")
    sites, rules = [], []
    for path in sorted(files):
        if not path.endswith((".yaml", ".yml")):
            continue
        text = files[path]
        if "mode: taint" not in text or not re.search(r"CWE-78\b", text):
            continue
        rule_ids = set(RULE_ID.findall(text))
        stem = path.rsplit(".", 1)[0]
        tests = [stem + extension for extension in TEST_EXTENSIONS if stem + extension in files]
        rules.append({"rule_file": path, "rule_ids": sorted(rule_ids), "test_files": tests})
        for test in tests:
            for line, label, named in label_lines(files[test], rule_ids):
                sites.append(
                    {
                        "path": test,
                        "line": line,
                        "label": label,
                        "language": TEST_EXTENSIONS["." + test.rsplit(".", 1)[1]],
                        "rules": named,
                        # The profile runs this very rule: Semgrep alone is scored on its own
                        # expectations there.
                        "profile_rule": path in profile_rules,
                    }
                )
    return {
        "description": (
            "Vulnerable and safe lines stated by the rule authors of semgrep-rules for taint "
            "rules tagged CWE-78. Built mechanically; see build_labels.py."
        ),
        "source": {"kind": "github", "owner": OWNER, "repo": REPO, "commit": COMMIT},
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "rules": rules,
        "sites": sites,
    }


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    check = "--check" in arguments
    archive = Path(next(a for a in arguments if a != "--check"))
    profile = HERE.parents[2] / "profiles" / "command-injection-v0.2"
    labels = build(archive.read_bytes(), profile_rule_paths(profile))
    data = (json.dumps(labels, indent=2, ensure_ascii=False) + "\n").encode()
    target = HERE / "labels.json"
    if check:
        same = target.read_bytes() == data
        print("labels.json matches the archive" if same else "labels.json differs")
        return 0 if same else 1
    target.write_bytes(data)
    counts = {}
    for site in labels["sites"]:
        key = (site["language"], site["label"], site["profile_rule"])
        counts[key] = counts.get(key, 0) + 1
    print(f"rules {len(labels['rules'])}, sites {len(labels['sites'])}")
    for key in sorted(counts):
        print("  ", key, counts[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
