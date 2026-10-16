"""Generate v0.2 queries: per (CWE, variant) the default query with extra sanitizers and sink
exclusions, plus Evidence.ql, a table of every evidence item (mechanism, kind, location)."""

import os

D = os.path.dirname(os.path.abspath(__file__))
CWES = {
    "22": ("PathInjection", "PathInjectionQuery", "PathInjectionFlow", "PathInjection"),
    "78": ("CommandInjection", "CommandInjectionQuery", "CommandInjectionFlow", "CommandInjection"),
    "79": ("ReflectedXss", "ReflectedXssQuery", "ReflectedXssFlow", "ReflectedXSS"),
    "643": ("XpathInjection", "XpathInjectionQuery", "XpathInjectionFlow", "XpathInjection"),
}
VARIANTS = ["none", "constbranch", "collection", "guard", "route", "header", "all"]
os.makedirs(f"{D}/queries", exist_ok=True)
for cwe, (mod, lib, flow, cust) in CWES.items():
    for v in VARIANTS:
        m = "_" if v == "all" else f'"{v}"'
        san = "none()" if v == "none" else f'SafetyEvidence::barrier(this, {m}, "{cwe}")'
        exc = "" if v == "none" else f' and not SafetyEvidence::excludedSink(sink, {m}, "{cwe}")'
        open(f"{D}/queries/cwe{cwe}_{v}.ql", "w").write(f"""/**
 * @name Safety evidence v0.2 variant {v} for CWE-{cwe}
 * @kind problem
 * @problem.severity error
 * @id st/cwe-{cwe}/{v}
 */
import python
import semmle.python.security.dataflow.{lib}
import semmle.python.security.dataflow.{cust}Customizations
import SafetyEvidence

class ExtraSanitizer extends {mod}::Sanitizer {{
  ExtraSanitizer() {{ {san} }}
}}

from DataFlow::Node source, DataFlow::Node sink
where {flow}::flow(source, sink){exc}
select sink, "flow from $@", source, "source"
""")
os.makedirs(f"{D}/table", exist_ok=True)
open(f"{D}/table/Evidence.ql", "w").write("""/**
 * @name Safety evidence items v0.2
 * @kind table
 * @id st/evidence-table
 */
import python
import SafetyEvidence

from DataFlow::Node n, string mech, string cwe, string kind, string role
where
  SafetyEvidence::barrierKind(n, mech, cwe, kind) and role = "barrier"
  or
  SafetyEvidence::excludedSink(n, mech, cwe) and
  kind = "canonicalisation-receiver" and
  role = "excluded-sink"
select n.getLocation().getFile().getRelativePath() as file,
  n.getLocation().getStartLine() as line, n.getLocation().getStartColumn() as col,
  n.getScope().getName() as function, cwe, mech, kind, role,
  n.toString() as node
""")
