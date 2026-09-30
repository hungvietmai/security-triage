# R1 feasibility against the current upstream candidate set

2026-09-30. Synthetic development diagnostic, not an accuracy benchmark or new
real-world FP dataset. Ten authored modules are exported from one synthetic
package. Source and expectations were written before this run; configuration and
results are committed together afterwards, without a preregistration claim.

## Question and execution

Does the existing unchanged upstream Semgrep suite produce constant-command
candidates for the planned R1 evidence policy? Can constant executable names or
`{shell:false}` be used as shortcuts? Use the same four rules and two CodeQL
queries as batch 01. Semgrep 1.178.0 and CodeQL 2.27.1 both completed; Semgrep
scanned 11 JS files (ten modules and the export index) with approximately 100%
parsed lines. No fixture code or command in a fixture was executed.

The runner uses the existing `invoke`, version checks, rule verification and SARIF
parser. Source and support-file hashes are checked before scanning. Query hashes,
raw logs, SARIF and configuration are retained. This diagnostic does not change
S0, Q0, S1, the protocol, or a production suppression policy.

## Observed coverage

`DCP` = detect-child-process; `SHELL` = spawn-shell-true;
`INTERP` = dangerous-spawn-shell; `WRAP` = shelljs-exec-injection.
Every CodeQL alert below uses `js/shell-command-constructed-from-input`; the other
configured query emitted none. Counts are raw findings, not independent TP labels.

| Fixture | Source behavior under stated assumptions | Semgrep | CodeQL |
| --- | --- | --- | --- |
| 01 | Literal command to exec | 0 | 0 |
| 02 | Concatenation of constants to exec | 0 | 0 |
| 03 | Unquoted input appended to exec command | DCP | 1 |
| 04 | Fixed program and fixed arguments, shell:true | SHELL | 0 |
| 05 | Fixed program, attacker-controlled argument, shell:true | SHELL | 1 |
| 06 | /bin/sh with -c and attacker-controlled script, shell:false | INTERP | 0 |
| 07 | Attacker selects executable, shell:false | DCP | 0 |
| 08 | Fixed /usr/bin/printf and %s format, data argument, shell:false | 0 | 0 |
| 09 | Literal command through shelljs.exec | 0 | 0 |
| 10 | Unquoted input appended through shelljs.exec | WRAP | 1 |

Totals: **6 Semgrep alerts, 3 CodeQL alerts**, on ten authored call sites.
`comparison.json` stores exact file identities, source hashes and rule IDs.
The fixtures assume trusted POSIX executables/runtime/environment/import semantics
and attacker-controlled exported function inputs. ShellJS dependency source is not
installed; that portion probes scanner wrapper modeling. Numeric performance or
population precision/recall is not inferred from these deliberately chosen examples.

## Consequences for R1

1. **Much of the simplest work is already done by S0.** The upstream DCP rule
   explicitly excludes literal command forms and some literal assignments, and
   requires taint into the focused command expression. Fixtures 01/02 produce no
   candidates. Therefore R1 cannot remove their warnings in ST because none exist.
   This is evidence about the present rules and fixtures, not a theorem covering
   every constant propagation, alias or control-flow arrangement in real code.
2. **The remaining constant candidate is an audit warning.** Fixture 04 legitimately
   uses a shell. Its SHELL message is accurate as an API-use warning; interpreting
   it as a prediction of CWE-78 exploitability requires the rule-to-prediction
   mapping specified by the evaluation protocol. A reduction in audit workload
   must not be presented as improved vulnerability precision without that mapping.
   The original evidence implementation scope names Node exec/execSync; applying
   R1 to spawn would additionally require validated spawn command/argument modeling.
3. **Constant executable is insufficient.** Both fixtures 04 and 05 have a fixed
   program name, but 05 places input in shell-interpreted arguments. Fixture 06
   invokes an explicit interpreter. A filter based only on argument zero or
   shell:false would suppress important cases. The protocol already rejects those
   shortcuts; this run adds concrete controls for future implementations.
4. **CodeQL silence cannot reject a Semgrep warning.** Fixture 06 has a clear
   attacker-controlled shell-script argument and is reported only by Semgrep in
   this run. Fixture 07 also deserves review, with its executable-selection CWE
   classification kept separate. We have not isolated which query/model decision
   causes the misses, and make no general claim about all CodeQL configurations.
5. **Possible complementarity is demonstrable synthetically.** Fixture 06 shows a
   concrete mechanism worth seeking in real data. It is not evidence of improved
   real-project recall and cannot substitute for the independent K set.

## What to do next

Keep R1 narrow and prospective; its real-data benefit has not been demonstrated.
Keep the node-notifier sanitizer case as separate development evidence rather than
expanding R1 to encompass a general sanitizer proof. The next real-data search
should select applications with explicit interpreter calls and inspectable input
boundaries, alongside constant-command examples, before scanning. Record how many
S0 alerts actually fit a proposed exclusion condition before implementing it.

For evaluation, first make the four upstream rules' audit/vulnerability prediction
mapping concrete on development data. Preserve both raw warnings and interpreted
CWE-78 predictions. Then approve labels at the existing location/argument-role
unit. Do not silently tune S0, discard ambiguous alerts, or turn these authored
fixtures into real-data FPs. The rule-tuning baseline and CodeQL-only baseline
remain necessary if a policy is subsequently developed.

## Reproduce and verify

From repository root, with pinned native scanners available:

```bash
python -m experiments.diagnostics.probe_r1 \
  --semgrep /path/to/semgrep \
  --codeql /path/to/codeql \
  --javascript-query-pack /path/to/codeql/qlpacks/codeql/javascript-queries/2.4.6 \
  --output artifacts/r1-feasibility-new
```

Use a new output directory. Source is in `experiments/fixtures/r1-feasibility/`.
`execution-evidence.json` uses the existing gzip/base64 envelope: verify
`decoded_sha256`, then each decoded file's SHA-256. Database intermediates are
omitted; exact fixture source is committed. All zero-result cases remain in the
comparison table. A failed run would remain partial rather than becoming zero.

Validation: both real scanner invocations completed; 15 offline experiment tests,
43 frontend tests and 81 backend tests passed locally. Backend coverage 97.84%.
Repository hooks were run. No application code or Docker deployment changed.
