# Development rule provenance

`detect-child-process-upstream.yaml` is an unchanged copy of
[the upstream rule](https://github.com/semgrep/semgrep-rules/blob/a84ff9cc2453ca91d581380de4b8b3f272f6f4be/javascript/lang/security/detect-child-process.yaml).
Its source reference, authoring metadata and original rule ID are retained.

`detect-child-process-direct-alias.yaml` derives from that exact copy by adding
one pattern-sinks branch for direct CommonJS `require('child_process').exec` and
`.execSync` aliases. Existing sources/sinks are unchanged. It is a development
candidate, not a claim of complete alias resolution or a frozen S1 baseline.

The [diagnostic report](../reports/curling-direct-alias/REPORT.md) records scope,
checksums, controls, observed results and tuning effort. No held-out data was used.
