/**
 * @name Development normalization candidate v031s; safety evidence v0.3 (stage 1, scoped) for CWE-22
 * @kind problem
 * @problem.severity error
 * @id st/cwe-22/v031s
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import semmle.python.security.dataflow.PathInjectionCustomizations
import SafetyEvidence
import IpgGuard

// Baseline uses the isolated v0.2.1 normalization correction.
class ExtraSanitizer extends PathInjection::Sanitizer {
  ExtraSanitizer() { SafetyEvidence::barrier(this, _, "22") }
}

from DataFlow::Node source, DataFlow::Node sink
where
  PathInjectionFlow::flow(source, sink) and
  not SafetyEvidence::excludedSink(sink, _, "22") and
  // ... plus the v0.3 mechanism with contracts of every level, including "scoped" resource
  // contracts (SPEC_RESOURCE.md)
  not IpgGuard::suppressedSink(sink, _, _, _)
select sink, "flow from $@", source, "source"
