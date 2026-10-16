"""Generate one query per (CWE, mechanism variant).

Each query is the default CodeQL query with extra sanitizers."""

import os

D = os.path.dirname(os.path.abspath(__file__))
CWES = {
    "22": ("PathInjection", "PathInjectionQuery", "PathInjectionFlow"),
    "78": ("CommandInjection", "CommandInjectionQuery", "CommandInjectionFlow"),
    "79": ("ReflectedXss", "ReflectedXssQuery", "ReflectedXssFlow"),
    "643": ("XpathInjection", "XpathInjectionQuery", "XpathInjectionFlow"),
}
VARIANTS = ["none", "constbranch", "collection", "guard", "route", "header", "all"]
os.makedirs(f"{D}/queries", exist_ok=True)
for cwe, (mod, lib, flow) in CWES.items():
    cust = "ReflectedXSS" if mod == "ReflectedXss" else mod
    for v in VARIANTS:
        cond = (
            "none()"
            if v == "none"
            else (
                f'SafetyEvidence::barrier(this, _, "{cwe}")'
                if v == "all"
                else f'SafetyEvidence::barrier(this, "{v}", "{cwe}")'
            )
        )
        open(f"{D}/queries/cwe{cwe}_{v}.ql", "w").write(f"""/**
 * @name Safety evidence variant {v} for CWE-{cwe}
 * @kind problem
 * @problem.severity error
 * @id st/cwe-{cwe}/{v}
 */
import python
import semmle.python.security.dataflow.{lib}
import semmle.python.security.dataflow.{cust}Customizations
import SafetyEvidence

class ExtraSanitizer extends {mod}::Sanitizer {{
  ExtraSanitizer() {{ {cond} }}
}}

from DataFlow::Node source, DataFlow::Node sink
where {flow}::flow(source, sink)
select sink, "flow from $@", source, "source"
""")
