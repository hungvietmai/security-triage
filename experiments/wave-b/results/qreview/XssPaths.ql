/**
 * @name Reflected XSS flow steps per alert (review aid)
 * @kind table
 * @id st/review/cwe-79-steps
 */

import python
import semmle.python.security.dataflow.ReflectedXssQuery
import ReflectedXssFlow::PathGraph

from ReflectedXssFlow::PathNode src, ReflectedXssFlow::PathNode sink, ReflectedXssFlow::PathNode n
where
  ReflectedXssFlow::flowPath(src, sink) and
  src.getASuccessor*() = n and
  n.getASuccessor*() = sink
select sink.getNode().getLocation().getFile().getRelativePath() + ":" +
    sink.getNode().getLocation().getStartLine() as sink_loc,
  n.getNode().getLocation().getFile().getRelativePath() as file,
  n.getNode().getLocation().getStartLine() as line, n.getNode().toString() as node
