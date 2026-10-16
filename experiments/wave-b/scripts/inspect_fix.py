"""Review aid: verify a fix commit and print its Python diff (no scanners).

Usage: inspect_fix.py WORKDIR COMMIT_URL [MAX_CHARS]"""

import os
import re
import subprocess
import sys

work, url = sys.argv[1], sys.argv[2]
owner, repo, sha = re.match(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", url).groups()
d = os.path.join(work, f"{owner}__{repo}")


def run(*a):
    return subprocess.run(a, capture_output=True, text=True, cwd=d)


if not os.path.isdir(d):
    subprocess.run(
        [
            "git",
            "clone",
            "-q",
            "--filter=blob:none",
            "--no-checkout",
            f"https://github.com/{owner}/{repo}.git",
            d,
        ],
        check=False,
    )
if run("git", "cat-file", "-e", sha + "^{commit}").returncode:
    run("git", "fetch", "-q", "origin", sha)
full = run("git", "rev-parse", sha).stdout.strip()
if not full:
    print("FIX COMMIT NOT FOUND", url)
    sys.exit(0)
parent = run("git", "rev-parse", full + "^1").stdout.strip()
files = run("git", "diff", "--numstat", parent, full).stdout.strip().splitlines()
print(
    f"repo={owner}/{repo} fixed={full} vulnerable={parent} "
    f"date={run('git', 'show', '-s', '--format=%cs', full).stdout.strip()}"
)
print(
    "files:",
    "; ".join(f.split("\t")[2] + f"(+{f.split()[0]}/-{f.split()[1]})" for f in files)[:1500],
)
py = [
    f.split("\t")[2]
    for f in files
    if f.split("\t")[2].endswith(".py") and not re.search(r"(^|/)tests?/|test_", f.split("\t")[2])
]
diff = run("git", "diff", "-U2", parent, full, "--", *py).stdout if py else ""
print(diff[: int(sys.argv[3]) if len(sys.argv) > 3 else 4000])
