/**
 * @name Safety evidence v0.3 resource-root candidates (diagnostics)
 * @kind table
 * @id st/v03-resource-table
 */

import python
import IpgGuard

from GlobalVariable g, string root, string detail
where IpgGuard::resourceDiagnostic(g, root, detail)
select g.getScope().(Module).getFile().getRelativePath() as file, g.getId() as name, root, detail
