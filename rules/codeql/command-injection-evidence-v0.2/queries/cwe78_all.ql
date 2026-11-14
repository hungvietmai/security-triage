/**
 * @name Safety evidence v0.2 variant all for CWE-78
 * @kind problem
 * @problem.severity error
 * @id st/cwe-78/all
 */
import python
import semmle.python.security.dataflow.CommandInjectionQuery
import semmle.python.security.dataflow.CommandInjectionCustomizations
import SafetyEvidence

class ExtraSanitizer extends CommandInjection::Sanitizer {
  ExtraSanitizer() { SafetyEvidence::barrier(this, _, "78") }
}

from DataFlow::Node source, DataFlow::Node sink
where CommandInjectionFlow::flow(source, sink) and not SafetyEvidence::excludedSink(sink, _, "78")
select sink, "flow from $@", source, "source"
