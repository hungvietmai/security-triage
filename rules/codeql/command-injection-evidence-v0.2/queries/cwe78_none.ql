/**
 * @name Safety evidence v0.2 variant none for CWE-78
 * @kind problem
 * @problem.severity error
 * @id st/cwe-78/none
 */
import python
import semmle.python.security.dataflow.CommandInjectionQuery
import semmle.python.security.dataflow.CommandInjectionCustomizations
import SafetyEvidence

class ExtraSanitizer extends CommandInjection::Sanitizer {
  ExtraSanitizer() { none() }
}

from DataFlow::Node source, DataFlow::Node sink
where CommandInjectionFlow::flow(source, sink)
select sink, "flow from $@", source, "source"
