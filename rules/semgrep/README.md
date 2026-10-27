# Semgrep rules

No rules live here. The rules in use are versioned with the research that pins them:

- `experiments/rules/batch-01/` (JavaScript) and `experiments/rules/python-upstream/`
  (Python): the eight unchanged upstream CWE-78 rules in the worker's scan profile
  `profiles/command-injection-v0.1/`, pinned by SHA-256.
- `experiments/rules/`: the upstream `detect-child-process` copy and its direct-alias
  development variant (see `experiments/rules/README.md`).
- `experiments/owasp-bp-pilot/semgrep_rules.json`: the 61 community Python rules used as
  a control in the CWE-22 study.

Semgrep is a control in the current CWE-22 study; see `docs/research.md`.
