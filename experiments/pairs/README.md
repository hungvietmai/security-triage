# Frozen pair preparation — pairs-v1

`index.json` lists the **51 usable manifests** from `split_v0.2.json`: 35
development pairs (34 groups) and 16 held-out pairs (15 groups). Split-v0.2 is
split-v0.1 with its 11 JavaScript reserve groups reassigned to development by
[Amendment 05](../amendments/AMENDMENT_05_RESERVE_TO_DEVELOPMENT.md); held-out is
unchanged and no reserve remains. It also preserves all 32 excluded rows and their
reasons. The CSV `split` column is v0 metadata, never the effective assignment. Both
the frozen group assignment and each pair's `scope_verdict` are required.

`sources.lock.json` maps pair IDs to vulnerable/fixed archive hashes, provenance,
source references and acquisition timestamps. **50 pairs / 100 archives** are
locked. Both Ray archives exceeded the day-5 50 MiB download bound; their failures
remain recorded in the lock and `sources-report.json`. No replacement was
performed. The 11 reassigned pairs' locks were rebound only for their changed `split`
field (`--rebind-split`, recorded under `rebinds`); their archives are unchanged. Any later replacement must follow the already committed
group reserve ordering; this preparation CLI does not perform replacements.

Archive bytes live in the ignored local cache `artifacts/pair-sources/<sha256>.tgz`.
Keep/back up this cache with the lock. A successful lock is never refreshed:
missing cache bytes, checksum mismatches or changed manifests stop the workflow.
Mode B must consume `cache_archive()`/`load_pair()`; an upstream re-download is
not a substitute for missing locked bytes. Reusing the lock verifies the bytes
without contacting npm/GitHub. `--retry-failures` retries only failed/unattempted
versions and retains the earlier attempt records.

The `sha256` is the hash of the original archive bytes, not a normalized source
tree. npm acquisition uses the registry's SHA-512 integrity (`publisher_verified`);
GitHub acquisition uses the first commit-pinned codeload archive (`tofu`). Both
reuse `backend/app/scanners/sources.py` without redirects. Downloading a source
does not install its dependencies, extract it, or invoke a scanner.

Every locked pair (50: 34 development, 16 held-out) has `patch-hunks.json` and
`known-locations.json`, extracted **before any scanner output exists for the
held-out pairs**, so the chosen locations cannot depend on tool results. Ray has
no archive and therefore no artifacts.

| Split | Pairs | Resolved | `known_location_unresolved` |
| --- | ---: | ---: | ---: |
| development | 34 | 26 | 8 |
| held_out | 16 | 9 | 7 |

Unresolved development: Paddle `49bec1760535`, celery, pip, python-libnmap,
clamscan, git-parse, gry, local-devices. Unresolved held-out: both WeblateOrg pairs,
dcnnt-py, powerline-gitstatus, binderhub, mlflow, async-git. Reasons: no sink in the
deleted/modified lines and applicable function labels (10), a SecBench sink hint not
uniquely contained in a callee (4), a hint file missing (1). An unresolved pair keeps
no substituted location; it is not evidence that the pair is safe or out of scope.

The first three prepared pairs keep their hunks and locations byte-for-byte; only
their `generator_sha256` (and the dependent `patch_hunks_sha256`) changed with the
tools. Symlinks whose target stays inside the archive are listed under `ignored`
with reason `symlink` and are never read; see RESEARCH_LOG for this and the other
pre-scan preparation decisions.

The JavaScript helper parses ASTs with pinned Babel tooling; it never invokes
Semgrep/CodeQL or executes source. It supports direct child_process/shelljs
imports/requires and rejects unrecognized, reassigned or shadowed bindings.
It does not perform taint analysis. Python uses the existing stdlib AST locator.
Unmatched hints, unavailable syntax and unmatched function restrictions remain
`known_location_unresolved`; no nearest call is substituted.

`patch-hunks.json` uses exact paths, unique content hashes for unchanged renames,
and difflib line edits. Hunk context and insertions do not become vulnerable old
lines. Test/documentation/lockfile omissions are listed separately for each
snapshot; binary changes and ambiguous rename candidates are also retained.
Functions are narrowed only by exact normalized pre-patch function text and name
from the checksum-pinned PyVul metadata. These dataset records are not independent
vulnerability adjudication. The fixed side is not automatically a negative label.

See `MANUAL_REVIEW.md` for inspection of both source versions and the three diffs.
**No vulnerability scanner was run on any pair during this preparation.** Earlier
development exposure remains recorded in `prior_exposure` and RESEARCH_LOG.

## Reproduce without scanning

Run from the repository root with Node 24 and uv/Python 3.12:

```powershell
npm --prefix experiments/locators ci --ignore-scripts
uv run --project backend --with-requirements experiments/requirements-pairs.txt python experiments/make_pair_manifests.py --check
uv run --project backend --with-requirements experiments/requirements-pairs.txt python experiments/lock_pair_sources.py
uv run --project backend --with-requirements experiments/requirements-pairs.txt python experiments/patch_hunks.py --all-locked
uv run --project backend --with-requirements experiments/requirements-pairs.txt python experiments/known_locations.py --all-locked --pyvul-functions-file artifacts/pair-sources/pyvul-function-level-dataset.out
uv run --project backend --with-requirements experiments/requirements-pairs.txt python -m unittest discover -s experiments/tests -p 'test_*.py' -v
```

Omit `--check` only to regenerate manifests before source locking. A changed
manifest cannot silently rebind an existing lock. The PyVul function JSONL cache
was downloaded from the pinned URL recorded in `known-locations.json`, with
SHA-256 `73eb0e3cce41721345d3acca2169266db6888e46f9f33394dad3bed549711071`.
Copy those exact metadata bytes into the documented cache path to reproduce the
function restriction; a different checksum is rejected. If omitted, the output
explicitly records that the function metadata was unavailable.
