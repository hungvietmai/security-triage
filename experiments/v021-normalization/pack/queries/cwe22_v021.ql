/**
 * @name Development normalization candidate v021; safety evidence v0.2 variant all for CWE-22
 * @kind problem
 * @problem.severity error
 * @id st/cwe-22/v021
 */
import python
import semmle.python.security.dataflow.PathInjectionQuery
import semmle.python.security.dataflow.PathInjectionCustomizations
import SafetyEvidence

class ExtraSanitizer extends PathInjection::Sanitizer {
  ExtraSanitizer() { SafetyEvidence::barrier(this, _, "22") }
}

from DataFlow::Node source, DataFlow::Node sink
where PathInjectionFlow::flow(source, sink) and not SafetyEvidence::excludedSink(sink, _, "22")
select sink, "flow from $@", source, "source"
