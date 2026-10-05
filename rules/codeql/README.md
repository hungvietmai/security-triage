# CodeQL queries

Upstream baseline queries are checksum-pinned in `experiments/configs/` and loaded
from the matching CodeQL bundles. Keep them distinct from custom evidence queries.

The [Python evidence pack](python-evidence/README.md) contains the first bounded
integer-guard diagnostic. It produces review evidence and authorizes no suppression.
Its development runner records CLI/library versions, source hashes and raw results.
