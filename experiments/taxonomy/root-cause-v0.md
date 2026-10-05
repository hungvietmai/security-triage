# Root-cause taxonomy v0

Status: **pre-scan frozen**  
Version: **0**  
Date: 2026-10-05  
Source: Amendment 02 §7.1.

This taxonomy is used only for development-set root-cause analysis. It describes
recurring mechanisms behind Semgrep/CodeQL disagreement, misses, evidence
extraction failure and canonical mapping failure.

A case may receive more than one root-cause label when the evidence supports
multiple interacting mechanisms. If no category can be supported, leave the
root cause unresolved rather than forcing a label.

| ID | Root-cause group | Short definition |
|---|---|---|
| RC01 | Source/sink modeling | The relevant untrusted source, execution sink, or source-to-sink model is absent, too narrow, or does not match the vulnerable API/use pattern. |
| RC02 | Aliasing | Data reaches the vulnerable operation through aliases, renamed references, destructuring, reassignment, or equivalent indirection that the analysis fails to follow. |
| RC03 | Wrappers/helpers | The vulnerable behavior is hidden behind a helper, wrapper, library abstraction, or user-defined function whose security semantics are not modeled. |
| RC04 | Interprocedural flow | The vulnerable flow crosses function, method, module, callback, or other procedure boundaries that the analysis does not connect correctly. |
| RC05 | Command construction | The command is assembled through concatenation, interpolation, templates, collections, builders, transformations, or staged construction that obscures the executable command. |
| RC06 | Argument role | The analysis does not correctly distinguish executable, command string, argument, option, delimiter, or other argument roles that change injection semantics. |
| RC07 | Shell/interpreter semantics | Detection depends on whether execution uses a shell/interpreter, how that interpreter parses metacharacters, or whether an API executes directly without shell parsing. |
| RC08 | Guards | A validation, allowlist, conditional check, escaping precondition, or other guard changes exploitability but is missed, over-trusted, or interpreted inconsistently. |
| RC09 | Sanitizers | A sanitizer/escaping/quoting transformation is absent from the model, incorrectly modeled, or applied in a way whose security effect is misinterpreted. |
| RC10 | Platform or trust boundary | Detection or scope changes because of platform-specific behavior, OS branches, environment assumptions, or whether the input actually crosses the declared untrusted-data boundary. |
| RC11 | Evidence-extraction failure | The scanner may report a relevant candidate, but the project cannot extract the evidence needed for adjudication or priority assignment reliably. |
| RC12 | Canonical mapping failure | Raw findings cannot be mapped confidently to the same canonical source unit or known vulnerable location, preventing valid agreement/disagreement comparison. |

## Coding notes

- The taxonomy applies to the eligible development population defined in
  Amendment 02 §7.2–7.3.
- The taxonomy is **multi-label**: one case can receive several RC identifiers.
- Outcome labels such as `Semgrep only`, `CodeQL only`, or `missed by both`
  are not root causes and must be stored separately.
- Human scope decisions are not root-cause labels.
- A new category or a material definition change is allowed only on development
  data and counts toward the Amendment 02 saturation rule.
- Held-out cases do not authorize taxonomy revision for the evaluated version.
