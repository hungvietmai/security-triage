/**
 * @name Safety evidence items v0.2
 * @kind table
 * @id st/evidence-table
 */
import python
import SafetyEvidence

from DataFlow::Node n, string mech, string cwe, string kind, string role
where
  SafetyEvidence::barrierKind(n, mech, cwe, kind) and role = "barrier"
  or
  SafetyEvidence::excludedSink(n, mech, cwe) and kind = "canonicalisation-receiver" and role = "excluded-sink"
select n.getLocation().getFile().getRelativePath() as file, n.getLocation().getStartLine() as line,
  n.getLocation().getStartColumn() as col, n.getScope().getName() as function, cwe, mech, kind, role,
  n.toString() as node
