/**
 * @name Post-hoc Wave C baseline abstract graph edges
 * @kind table
 * @id st/wave-c/review-edges
 */
import python
import semmle.python.security.dataflow.PathInjectionQuery
import semmle.python.security.dataflow.PathInjectionCustomizations
import SafetyEvidence
import PathInjectionFlow::PathGraph

class ExtraSanitizer extends PathInjection::Sanitizer {
  ExtraSanitizer() { none() }
}

string locationKey(PathInjectionFlow::PathNode n) {
  result =
    n.getNode().getLocation().getFile().getRelativePath() + ":" +
      n.getNode().getLocation().getStartLine() + ":" +
      n.getNode().getLocation().getStartColumn()
}

string callableName(PathInjectionFlow::PathNode n) {
  result = n.getNode().getEnclosingCallable().getQualifiedName()
  or
  not exists(n.getNode().getEnclosingCallable()) and result = "<module>"
}

from
  PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink,
  PathInjectionFlow::PathNode predecessor, PathInjectionFlow::PathNode successor
where
  PathInjectionFlow::flowPath(source, sink) and
  source.getASuccessor*() = predecessor and
  predecessor.getASuccessor() = successor and
  successor.getASuccessor*() = sink
select
  locationKey(source) as source_location, locationKey(sink) as sink_location,
  predecessor, locationKey(predecessor) as from_location,
  callableName(predecessor) as from_callable,
  successor, locationKey(successor) as to_location,
  callableName(successor) as to_callable
