/**
 * @name Safety evidence v0.3 suppressions
 * @kind table
 * @id st/v03-evidence-table
 */

import python
import semmle.python.security.dataflow.PathInjectionCustomizations
import IpgGuard

from DataFlow::Node sink, string root, string basis, string source
where sink instanceof PathInjection::Sink and IpgGuard::suppressedSink(sink, root, basis, source)
select sink.getLocation().getFile().getRelativePath() as file,
  sink.getLocation().getStartLine() as line, sink.getLocation().getStartColumn() as col,
  sink.getScope().getName() as function, root, basis, source, IpgGuard::level(source) as level,
  sink.toString() as node
