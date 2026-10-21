/**
 * @name Development normalization candidate v031; safety evidence v0.3 (stage 1, strict) for CWE-22
 * @kind problem
 * @problem.severity error
 * @id st/cwe-22/v031
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
  // ... plus the one v0.3 mechanism, with contracts of level "proved" only
  not exists(string s | IpgGuard::suppressedSink(sink, _, _, s) and IpgGuard::level(s) = "proved")
select sink, "flow from $@", source, "source"
