/**
 * @name Safety evidence v0.3 contracts and containment per sink
 * @kind table
 * @id st/v03-contract-table
 */

import python
import semmle.python.security.dataflow.PathInjectionCustomizations
import IpgGuard

from DataFlow::Node sink, string kind, string root, string detail
where
  sink instanceof PathInjection::Sink and
  (
    kind = "allowed" and IpgGuard::allowedRoot(sink, root, detail)
    or
    kind = "contained" and IpgGuard::contained(sink.asCfgNode(), root, detail, _)
  )
select sink.getLocation().getFile().getRelativePath() as file,
  sink.getLocation().getStartLine() as line, sink.getLocation().getStartColumn() as col, kind, root,
  detail
