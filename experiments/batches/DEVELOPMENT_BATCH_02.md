# Development batch 02 — application helpers

The fixed package order is open, node-notifier, launch-editor. Exact versions and
archive hashes are in the case manifests. Versions are resolved from registry
metadata before scanner execution. Selection is purposive: opening a target,
formatting a notification and selecting an editor offer more specific command
construction than batch 01's generic command-runner APIs. These remain libraries;
application-level caller trust boundaries may still be absent. They are not assumed
safe or FP-rich. Advisory status is unassessed.

Reuse the **exact batch 01 scanner configuration** and unchanged upstream rules.
The repaired runner retains failed-process metadata; this is not a rule change.
Dependencies, bundled executables and package scripts are not executed. Scanners
analyze the published snapshot only. No application UI or policy is added.

Use the same review cap and order as batch 01: listed package order, each tool's
alerts sorted by path, start line, start column, rule ID and raw ID; first three
raw alerts per tool per package. Keep other alerts unreviewed. Review the API's
actual claim and input construction. An argv list, absence of a CodeQL alert,
intended API behavior, or absence of an advisory cannot by itself justify an FP.
Review is preliminary and unblinded, with technical/scope labels separate.

This is development selection informed by batch 01, not a held-out evaluation or
an independent FP prevalence sample. Keep all outcomes, including zeros, failures
and unresolved labels. Configuration is published before this batch runs; that
ordering does not establish preregistration of the overall study.

Run the shared CLI with `--batch experiments/batches/development-batch-02.json`,
`--configuration-commit` set to this configuration commit and the same pinned
scanner paths used in batch 01. See the batch 01 selection note for full CLI usage.
