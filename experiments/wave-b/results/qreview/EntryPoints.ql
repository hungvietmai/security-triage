/**
 * @name Entry functions and on-path functions per CWE-22 alert (review aid)
 * @kind table
 * @id st/review/cwe-22-entries
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph

string fn(PathInjectionFlow::PathNode n) {
  result = n.getNode().getEnclosingCallable().getQualifiedName()
  or
  not exists(n.getNode().getEnclosingCallable()) and result = "<module>"
}

from
  PathInjectionFlow::PathNode src, PathInjectionFlow::PathNode entry, PathInjectionFlow::PathNode sink,
  string role, PathInjectionFlow::PathNode n
where
  PathInjectionFlow::flowPath(src, sink) and
  entry = src.getASuccessor() and
  entry.getASuccessor*() = sink and
  (
    role = "entry" and n = entry
    or
    role = "on_path" and entry.getASuccessor*() = n and n.getASuccessor*() = sink
  )
select sink.getNode().getLocation().getFile().getRelativePath() + ":" +
    sink.getNode().getLocation().getStartLine() as sink_loc,
  role, n.getNode().getLocation().getFile().getRelativePath() as file,
  n.getNode().getLocation().getStartLine() as line, fn(n) as function
