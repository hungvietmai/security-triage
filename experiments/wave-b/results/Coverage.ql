/**
 * @name Source and sink coverage of the default CWE-22/643 queries (review aid)
 * @kind table
 * @id st/coverage
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.PathInjectionCustomizations
import semmle.python.security.dataflow.XpathInjectionCustomizations

from DataFlow::Node n, string cwe, string role
where
  n instanceof PathInjection::Source and cwe = "22" and role = "source"
  or
  n instanceof PathInjection::Sink and cwe = "22" and role = "sink"
  or
  n instanceof XpathInjection::Source and cwe = "643" and role = "source"
  or
  n instanceof XpathInjection::Sink and cwe = "643" and role = "sink"
select n.getLocation().getFile().getRelativePath() as file, n.getLocation().getStartLine() as line,
  cwe, role, n.toString() as node
