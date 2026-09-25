# Scanner integration boundary

Implement Semgrep first, then CodeQL, as subprocess adapters called by a worker.
No scanner is installed or executed by this starter; no endpoint reports a fake scan success.

- Use an argument list, never shell interpolation of uploaded paths.
- Run each scan in an isolated workspace with time/resource limits.
- Never execute uploaded source or install its dependencies automatically.
- Preserve raw SARIF, logs, tool/rule versions, source snapshot, and partial failures.
- Parse locations relative to the exact source snapshot, with nullable line/column information.
- Keep tool agreement, triage decisions, and independent evaluation labels separate.
- Check CodeQL terms for the intended repositories and deployment before distributing its CLI.
