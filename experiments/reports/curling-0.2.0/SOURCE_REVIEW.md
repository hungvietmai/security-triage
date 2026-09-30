# Curling 0.2.0: first resolved development location

Reviewed on 2026-09-30. [Machine-readable review](reviewed-units-v1.json)
records **one CWE-78 true-positive location, in scope**, with six reviewed CodeQL
aliases. This is an unblinded assistant first review; independent human review
and approval remain pending. It is not a held-out result or an FP-reduction claim.
The original [packet](review-packet-v1.json) remains unchanged as historical input.

## Independent evidence and source reasoning

The [pinned advisory](https://github.com/github/advisory-database/blob/5f020e75ceb39c5b24ae2350de254b8656caa01c/advisories/github-reviewed/2021/04/GHSA-xmxh-g7wj-8m4m/GHSA-xmxh-g7wj-8m4m.json)
identifies CVE-2019-10789 / CWE-78 and an affected range that includes 0.2.0.
The scanned npm archive is the source of all line numbers below; its checksum is
verified against the manifest and preserved evidence. The advisory-linked Git
revision differs from the npm source, so its line numbers are not substituted.

| Source location | Reviewed behavior |
| --- | --- |
| `index.js:1–2` | Exports `connect` and `run` publicly. |
| `lib/curl-transport.js:2` | `exec` is imported directly from `child_process`. |
| `lib/curl-transport.js:102–114` | `get(url, options)` adds the HTTP verb and passes an unescaped URL through `getCommand` to `run`. |
| `lib/curl-transport.js:75–99` | Option values are enclosed in double quotes; shell substitutions are not neutralized. |
| `lib/curl-transport.js:55–58` | `run` concatenates the command after `curl ` and passes it to `exec`. |

The scope assumption is attacker control of a URL or option value at the public
package API on Linux/POSIX, with a trusted installed executable/environment.
The URL and option APIs strengthen the decision beyond the low-level `run` API,
which the README intentionally exposes for flexible command construction. No
application-level remote entry point has been demonstrated.

The [upstream validation change](https://github.com/hgarcia/curling/commit/53867b9f29dc0f26046a0fb146e66959ebf631a6)
adds a metacharacter check before the same `exec` call. It supports the historical
mechanism; this review does not certify that patch as complete or label the
patched repository safe. The verdict is supported by the vulnerable source and
independent advisory, not by CodeQL's agreement with itself.

## Bounded API witness

[capture-command.cjs](capture-command.cjs) loads only the checksum-pinned source
with `child_process.exec` replaced by a capture stub. Three inputs reach the
constructed command unchanged: a direct command separator, a URL containing a
separator, and an option containing command substitution. [Recorded output](command-capture.json)
preserves those strings and the harness/source hashes.

No real shell, curl process, payload file write or network request is invoked.
These checks demonstrate transport of concrete inputs; they do not constitute a
full exploit execution, an exhaustive path test or proof about other packages.

Reproduce from the repository root without installing the package:

```bash
python - <<'PY'
from pathlib import Path
from experiments.build_review import load_evidence, source_texts
files = load_evidence(Path('experiments/reports/curling-0.2.0/execution-evidence.json'), '002')
sources = source_texts(files['source.tgz'], 'package')
target = Path('artifacts/curling-source-review/curl-transport.js')
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(sources['lib/curl-transport.js'])
PY
node experiments/reports/curling-0.2.0/capture-command.cjs artifacts/curling-source-review/curl-transport.js
```

## Mapping and use of the label

The six result regions (lines 56, 76, 108, 113, 123 and 128) all explicitly link
to the same reviewed `exec` invocation. Its anchor is `56:3–58:5` (end exclusive),
role `shell_command`; CWE is a label attribute, not part of the identity.
The reviewed ledger assigns all six raw references to that one unit. Original
fallback records remain in the input packet and are alternatives, not six extra
scoring units. This location verdict does not certify each individual taint trace.

Automatic matching remains a proposal-only implementation. Manual first-review
coverage for this packet is 6/6; independent human-review coverage is 0/1 units.
The review is explicitly single-reviewer under protocol section 4.

This is a development site supported by an independent reference, not a member
of a frozen held-out K set. Keep the site; it cannot qualify for constant-only
R1 suppression. No policy was executed and no suppression was measured.

The smoke run's zero Semgrep findings and six CodeQL findings are preserved.
The separate alias-rule diagnostic is an S1 development candidate, not a frozen
baseline. Neither result establishes precision/recall improvement. The eight-
package survey still has no confirmed FP; the next empirical task remains
reviewing caller context and possible FP candidates, with the same evidence bar.
