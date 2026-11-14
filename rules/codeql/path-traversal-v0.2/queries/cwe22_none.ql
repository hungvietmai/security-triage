/**
 * @name Safety evidence v0.2 variant none for CWE-22
 * @kind problem
 * @problem.severity error
 * @id st/cwe-22/none
 */
import python
import semmle.python.security.dataflow.PathInjectionQuery
import semmle.python.security.dataflow.PathInjectionCustomizations
import SafetyEvidence

class ExtraSanitizer extends PathInjection::Sanitizer {
  ExtraSanitizer() { none() }
}

from DataFlow::Node source, DataFlow::Node sink
where PathInjectionFlow::flow(source, sink)
select sink, "flow from $@", source, "source"
