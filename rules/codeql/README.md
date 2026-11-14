# CodeQL queries

Upstream baseline queries come from the pinned CodeQL bundle (`tools/pins.env`) and are
selected by checksum-pinned configurations in `experiments/configs/`. Keep them distinct
from the custom evidence queries:

| Location | Content | Phase |
|---|---|---|
| [python-evidence/](python-evidence/README.md) | Bounded integer-guard diagnostic; produces review evidence and authorizes no suppression | CWE-78 (historical) |
| [path-traversal-v0.2/](path-traversal-v0.2/README.md) | Worker copy of the v0.2 CWE-22 baseline and evidence queries, used by the `path-traversal-v0.2` scan profile; byte-identical to the research pack | CWE-22 (product) |
| `experiments/owasp-bp-pilot/ql/`, `ql_v02/` | Safety-evidence layer v0.1 (rejected) and v0.2 (current baseline) for CWE-22/78/79/643 | CWE-22 |
| `experiments/v03-interprocedural-guard/ql/` | v0.3 strict/scoped interprocedural guards for CWE-22 | CWE-22 (frozen) |
| `experiments/v021-normalization/pack/` | v0.2.1 development correction | CWE-22 (development) |
| `experiments/wave-c/ql/` | Extracted-file coverage check for Wave C | CWE-22 |

The CWE-22 packs are locked by the freeze manifests next to them; see
`experiments/README.md` and `docs/research.md`.
