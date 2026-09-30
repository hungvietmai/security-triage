# Development review: platform scope and remaining alert

2026-09-30. [Review delta](scope-and-cap-review.json) records an unblinded
assistant first review, without independent human approval. Original scans and
drafts remain unchanged. The protocol, rules and evaluation unit are unchanged.

## Decisions

| Alert | Source evidence | Decision |
| --- | --- | --- |
| launch-editor 2.14.1, `index.js:167`, Semgrep `semgrep:0:0` | The `exec` invocation is enclosed by `process.platform === 'win32'` at line 123. Linux takes the distinct `spawn` call at line 172. | Scope **out_of_scope** for Linux/POSIX; technical verdict remains **unresolved**. This is not an FP. |
| launch-editor 2.14.1, `index.js:172` | Editor selection comes through `guessEditor`; `specifiedEditor` is parsed into executable and arguments at `guess.js:65–68`. | Retain the earlier unresolved verdict. A no-shell invocation alone does not establish safety. |
| gulp-shell 0.8.0, `lib/index.js:36`, Semgrep `semgrep:0:3` | `options.templateData` enters the context at line 31 and command interpolation at line 32; caller options override shell/env defaults. | Complete preliminary review of this formerly capped alert; retain unresolved labels. No constant-command R1 evidence. |

The Windows-only location is kept in the ledger, with an explicit scope label and
an unresolved technical label. It belongs in scope/coverage reporting. It receives
neither FP credit nor suppression credit. The scope filter must apply identically
to every evaluated configuration and cannot be attributed to ST's adjudication.
The guard conclusion assumes ordinary trusted Node platform state; no platform
spoofing or modified runtime is part of the chosen threat model.

## Bounded platform witness

[check-launch-platform.cjs](check-launch-platform.cjs) checks the pinned source hash
and loads the source with process creation replaced by collectors. It supplies an
existing-file result and a trusted editor, then models Linux and Windows in separate
contexts. [Recorded output](launch-platform-witness.json) shows one `spawn` call
for Linux and one `exec` call for Windows. No editor or shell is executed.

This witness corroborates the lexical branch review. It is not native Windows
testing, a check of Windows escaping, a test of editor guessing, or evidence that
every non-Windows use is safe. The source guard, not two finite inputs alone,
supports the out-of-scope decision.

Reproduce from the repository root:

```bash
python - <<'PY'
import base64, gzip, hashlib, json
from pathlib import Path
p = Path('experiments/reports/development-batch-02/npm-launch-editor-2.14.1-evidence.json')
e = json.loads(p.read_text())
b = gzip.decompress(base64.b64decode(e['payload']))
assert hashlib.sha256(b).hexdigest() == e['decoded_sha256']
entry = json.loads(b)['source_files']['index.js']
source = base64.b64decode(entry['content'])
assert hashlib.sha256(source).hexdigest() == entry['sha256']
target = Path('artifacts/launch-scope-review/index.js')
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(source)
PY
node experiments/reports/development-batch-02/check-launch-platform.cjs artifacts/launch-scope-review/index.js
```

## Review coverage and research decision

Batch 01 originally reviewed five of six raw alerts. Its fixed initial cap remains
recorded; this follow-up explicitly extends development review to the sole remaining
gulp-shell alert. Batch 02 already had notes for all five alerts. All **11 raw
alerts now have at least preliminary source notes**. That does not mean eleven
resolved labels, eleven vulnerabilities, or eleven independent evaluation units.

There are still **zero confirmed in-scope FP units** in these batches and no
reviewed negative example eligible for constant-command R1. The curling TP and
synthetic probes are separate datasets and do not fill that gap. The Windows
scope decision also does not fill it.

Do not implement an R1 suppressor from this evidence. The current collection has
mostly command-runner APIs and a dynamic sanitizer candidate whose shared helper
has a broader caller contract. Further package collection should include concrete
application/build-task callers with inspectable trust boundaries, rather than
assuming another generic command wrapper will supply negative labels.

For node-notifier, retain the shared-location verdict until all relevant caller
contracts are accounted for; a restricted NotifySend path assessment cannot silently
replace the existing sink unit. If no defensible negatives emerge, report that the
current pilot does not support the FP-reduction hypothesis and revisit the policy
with the supervisor. More infrastructure or permissive labels would not resolve it.
