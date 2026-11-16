# Semgrep SQL injection rules (CWE-89), unchanged upstream copies

Detection rules of the `sql-injection` family, used by the profile
[`sql-injection-v0.2`](../../../profiles/sql-injection-v0.2/DETECTION.md) inside the composite
profile `multi-cwe-v0.3`.

- **Source:** [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) at commit
  `a84ff9cc2453ca91d581380de4b8b3f272f6f4be`, the commit this project already vendors its CWE-78
  JavaScript rule from (`experiments/rules/README.md`). The archive downloaded from that commit
  had SHA-256 `b227c2d234ffd9c84c4dbd6619a5897a7192637c141baeace3bfc37b0715a887`.
- **Licence:** "Semgrep Rules License v1.0", copied unchanged to [LICENSE](LICENSE). The files under
  `upstream/` keep their upstream paths, authoring metadata and rule IDs.
- **Unchanged:** every file under `upstream/` is byte-identical to the upstream file at that
  commit. Nothing was added, removed or edited.
- **Selection, decided before any rule was run on a labeled source** (P2b protocol): every rule
  file under `python/` or `javascript/` (no TypeScript folder exists upstream; the JavaScript rules
  list TypeScript as a language) that is not a test fixture and either
  1. has a rule whose `metadata.cwe` names CWE-89, or
  2. lies under a `/security/` path and has `sql` in its file name.
  That gives 37 files: 25 Python, 12 JavaScript/TypeScript. Clause 2 adds three SQL rules whose
  upstream CWE label is not 89 (`python/flask/security/injection/tainted-sql-string.yaml`: CWE-704;
  `python/django/security/injection/tainted-sql-string.yaml` and
  `javascript/lang/security/audit/sqli/node-postgres-sqli.yaml`: CWE-915). Those labels are kept as
  the tool reports them; the profile maps the rules to CWE-89.
- **Checked:** all 37 files pass `semgrep scan --validate` with the pinned Semgrep CE 1.178.0.

Each file is pinned by SHA-256 in the profile's language config and manifest. Do not edit a file
here; a different rule set needs a new directory and a new profile.
