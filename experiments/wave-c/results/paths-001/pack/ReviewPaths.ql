/**
 * @name Post-hoc Wave C baseline path exemplars
 * @kind path-problem
 * @problem.severity error
 * @id st/wave-c/review-paths
 */
import python
import semmle.python.security.dataflow.PathInjectionQuery
import semmle.python.security.dataflow.PathInjectionCustomizations
import SafetyEvidence
import PathInjectionFlow::PathGraph

// Identical to cwe22_none.ql: no added sanitizer, source, sink or flow step.
class ExtraSanitizer extends PathInjection::Sanitizer {
  ExtraSanitizer() { none() }
}

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "flow from $@", source.getNode(), "source"
