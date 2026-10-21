/**
 * @name Safety evidence v0.3 validator summaries and untrusted-root calls (diagnostics)
 * @kind table
 * @id st/v03-summary-table
 */

import python
import IpgGuard

from string kind, string file, int line, string scope, string detail
where
  exists(Function f, int i, string a, string target | IpgGuard::summary(f, i, a) |
    (
      i = -1 and target = "return"
      or
      i >= 0 and target = "param " + i.toString()
    ) and
    kind = "summary" and
    file = f.getLocation().getFile().getRelativePath() and
    line = f.getLocation().getStartLine() and
    scope = f.getQualifiedName() and
    detail = target + " " + a
  )
  or
  exists(ControlFlowNode c, string a, Expr root, string rk |
    IpgGuard::untrustedRootCall(c, a, root, rk)
  |
    kind = "untrusted-root call" and
    file = c.getLocation().getFile().getRelativePath() and
    line = c.getLocation().getStartLine() and
    scope = c.getScope().getName() and
    detail = a + " root=" + root.toString() + " (" + rk + ")"
  )
select kind, file, line, scope, detail
