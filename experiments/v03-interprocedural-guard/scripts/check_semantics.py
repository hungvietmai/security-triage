"""Executable check of the expectations table against the fixture code (no file reads or writes).

The table (expectations/ipg_expectations.csv, locked by EXPECTATIONS.sha256) gives, for every
(scenario, case), whether the alert must be kept or may be suppressed and which roots the
case's sink may access in that scenario. It is written from the fixture semantics, independently
of the model packs the query reads. Per row:
  may                     -> no corpus input accepted by the case leaves the allowed roots
  keep, escape            -> the case's witness leaves the allowed roots
  keep, contract-forbids  -> some accepted corpus input leaves the allowed roots
  keep, no-contract       -> nothing to check: the query lacks a contract, not a danger claim
A root "flat:R" admits only direct children of R (a flat store); "$TMPDIR" is the real temp dir.
Usage: check_semantics.py CEX_SRC_DIR EXPECTATIONS_CSV
"""

import csv
import functools
import itertools
import os
import pathlib
import posixpath
import sys
import tempfile

sys.path.insert(0, sys.argv[1])
import validators as V  # noqa: E402

BASE = "/srv/data"
TMPD = tempfile.gettempdir()
P = pathlib.Path
U = "12345678123456781234567812345678"


def outside(p, roots):
    n = os.path.normpath(str(p))
    for r in roots:
        r = r.replace("$TMPDIR", TMPD)
        if r.startswith("flat:"):
            if os.path.dirname(n) == os.path.normpath(r[len("flat:") :]):
                return False
        elif n == r or n.startswith(r + "/"):
            return False
    return True


J = os.path.join
N = os.path.normpath
# route -> function(args dict) returning opened path, or None when the route rejects
GOOD = {
    "ipg_1_good": lambda a: J(BASE, V.check_relative(a["name"])),
    "ipg_2_good": lambda a: (V.check_relative(a["name"]), J(BASE, a["name"]))[1],
    "ipg_3_good": lambda a: (V.check_contained(BASE, J(BASE, a["name"])), J(BASE, a["name"]))[1],
    "ipg_4_good": lambda a: V.safe_join_like(BASE, a["name"]),
    "ipg_5_good": lambda a: (V.check_uuid(a["name"]), J(BASE, f"{a['name']}.json"))[1],
    "ipg_7_good": lambda a: (V.check_nested(a["name"]), J(BASE, a["name"]))[1],
    "ipg_8_good": lambda a: N(J(BASE, V.check_relative_stripped(a["name"]))),
    "ipg_10_good": lambda a: J(BASE, posixpath.dirname(V.check_relative(a["name"]))),
    "ipg_11_good": lambda a: J(BASE, a["name"]) if V.is_safe(a["name"]) else None,
    "ipg_13_good": lambda a: V.safe_join_three(BASE, a["name"]),
    "ipg_15_good": lambda a: V.safe_join_normcase(BASE, a["name"]),
    "ipg_16_good": lambda a: J(BASE, V.check_relative_pure(a["name"])),
    "ipg_17_good": lambda a: J(BASE, V.check_relative_decoded(a["name"])),
    "ipg_18_good": lambda a: (V.Checks.relative(a["name"]), J(BASE, a["name"]))[1],
    "ipg_19_good": lambda a: (V.Checker().relative(a["name"]), J(BASE, a["name"]))[1],
    "ipg_14_good": lambda a: (
        V.check_contained_other(J(V.PUBLIC_ROOT, a["name"])),
        J(V.PUBLIC_ROOT, a["name"]),
    )[1],
}
uuid_then = lambda root, suffix: lambda a: (V.check_uuid(a["name"]), root / f"{a['name']}{suffix}")[1]  # noqa: E731
GOOD.update(
    {  # resources.py: a["name"] is the session id
        "res_1_good": uuid_then(P(TMPD) / "cex-sessions", ".json"),
        "res_2_good": uuid_then(P("/srv/store"), ".dat"),
        "res_5_good": uuid_then(P(TMPD) / "cex-cache", ".json"),
        "res_6_good": uuid_then(P("/srv/shared"), ".json"),
        "res_9_good": uuid_then(P(TMPD), ".json"),
        "res_11_good": uuid_then(P(TMPD) / "cex-tested", ".json"),
    }
)
GOOD["ipg_6_good"] = GOOD["ipg_2_good"]
GOOD["ipg_9_good"] = GOOD["ipg_5_good"]
GOOD["ipg_12_good"] = GOOD["ipg_2_good"]


def b2(a):
    try:
        V.check_relative(a["name"])
    except ValueError:
        pass
    return J(BASE, a["name"])


BAD = {
    "ipg_1_bad": (
        lambda a: (V.check_relative_stripped(a["name"]), N(J(BASE, a["name"])))[1],
        {"name": "a?/../../../etc/passwd"},
    ),
    "ipg_2_bad": (b2, {"name": "/etc/passwd"}),
    "ipg_3_bad": (
        lambda a: (V.check_swallow(a["name"]), J(BASE, a["name"]))[1],
        {"name": "/etc/passwd"},
    ),
    "ipg_4_bad": (
        lambda a: (V.check_relative(a["name"]), J(BASE, a["other"]))[1],
        {"name": "ok", "other": "/etc/passwd"},
    ),
    "ipg_5_bad": (
        lambda a: (V.check_relative(a["a"]), J(BASE, a["b"]))[1],
        {"a": "ok", "b": "/etc/passwd"},
    ),
    "ipg_6_bad": (
        lambda a: (V.check_relative(a["name"]), J(BASE, V.decode(a["name"])))[1],
        {"name": "%2e%2e/%2e%2e/etc/passwd"},
    ),
    "ipg_7_bad": (
        lambda a: N(V.decode(J(BASE, V.check_relative(a["name"])))),
        {"name": "%2e%2e/%2e%2e/etc/passwd"},
    ),
    "ipg_8_bad": (
        lambda a: (V.check_no_dotdot(a["name"]), J(BASE, a["name"]))[1],
        {"name": "/etc/passwd"},
    ),
    "ipg_9_bad": (
        lambda a: (V.check_not_absolute(a["name"]), N(J(BASE, a["name"])))[1],
        {"name": "../../etc/passwd"},
    ),
    "ipg_10_bad": (
        lambda a: (V.check_conditional(a["name"]), J(BASE, a["name"]))[1],
        {"name": "/etc/passwd"},
    ),
    "ipg_11_bad": (
        lambda a: (V.is_safe(a["name"]), J(BASE, a["name"]))[1],
        {"name": "/etc/passwd"},
    ),
    "ipg_12_bad": (
        lambda a: (V.check_uuid(a["sid"]), J(BASE, f"{a['other']}.json"))[1],
        {"sid": "12345678123456781234567812345678", "other": "../../etc/x"},
    ),
    "ipg_13_bad": (
        lambda a: (V.check_relative(a["name"][:8]), N(J(BASE, a["name"])))[1],
        {"name": "abcdefgh/../../../etc/passwd"},
    ),
    "ipg_14_bad": (
        lambda a: (V.check_contained(BASE, J(BASE, "public")), N(J(BASE, a["name"])))[1],
        {"name": "../../etc/passwd"},
    ),
    # SafeRel proven but no join to a trusted root: read relative to CWD, outside BASE.
    "ipg_15_bad": (lambda a: V.check_relative(a["name"]), {"name": "secret.txt"}),
    # Prefix check without separator: sibling dir sharing the prefix passes.
    "ipg_16_bad": (lambda a: V.check_prefix_weak(BASE, a["name"]), {"name": "../data-evil/secret"}),
    # Containment proven for PUBLIC, but the sink contract allows BASE only.
    "ipg_17_bad": (
        lambda a: (V.check_contained_other(J(V.PUBLIC_ROOT, a["name"])), J(V.PUBLIC_ROOT, a["name"]))[1],
        {"name": "x"},
    ),
    # Validator-shaped function returns an unsafe transform of its input.
    "ipg_18_bad": (lambda a: N(J(BASE, V.prepend_parent(a["name"]))), {"name": "x"}),
    # Intermediate function adds a parent component after the value was validated.
    "ipg_19_bad": (
        lambda a: N(J(BASE, V.prepend_parent(V.check_relative(a["name"])))),
        {"name": "x"},
    ),
    # Two paths to the sink; the unvalidated branch carries the attacker value.
    "ipg_20_bad": (lambda a: N(J(BASE, a["name"])), {"name": "../../etc/passwd"}),
    # Dynamically selected validator (unresolvable); the default never raises.
    "ipg_21_bad": (
        lambda a: (V.is_safe(a["name"]), J(BASE, a["name"]))[1],
        {"name": "/etc/passwd"},
    ),
    # SafeRel appended to BASE without a separator lands in a sibling directory.
    "ipg_22_bad": (lambda a: f"{BASE}{V.check_relative(a['name'])}", {"name": "-evil/secret"}),
    # Three-branch containment under "/" accepts every absolute path.
    "ipg_23_bad": (lambda a: V.safe_join_three("/", a["name"]), {"name": "etc/passwd"}),
    # Root written by an earlier request ("root"); containment under it proves nothing about BASE.
    "ipg_24_bad": (
        lambda a: (
            V.check_contained(a["root"], J(a["root"], a["name"])),
            J(a["root"], a["name"]),
        )[1],
        {"root": "/", "name": "etc/passwd"},
    ),
    # Windows path flavour does not treat "/etc/passwd" as absolute on POSIX.
    "ipg_25_bad": (
        lambda a: (V.check_windows_absolute(a["name"]), J(BASE, a["name"]))[1],
        {"name": "/etc/passwd"},
    ),
    # The lax override is one of the two targets and checks nothing.
    "ipg_26_bad": (
        lambda a: (V.pick_checker(True).relative(a["name"]), J(BASE, a["name"]))[1],
        {"name": "/etc/passwd"},
    ),
    # resources.py and counterexamples_tmpdir: "moved"/"root"/"tempdir" is the value another
    # request (or an admin helper) has put in place of the intended root.
    "res_3_bad": (
        lambda a: (V.check_uuid(a["sid"]), P(a["moved"]) / f"{a['sid']}.json")[1],
        {"sid": U, "moved": "/etc"},
    ),
    "res_4_bad": (
        lambda a: (V.check_uuid(a["sid"]), P(a["root"]) / f"{a['sid']}.json")[1],
        {"sid": U, "root": "/etc"},
    ),
    "res_7_bad": (lambda a: P("/srv/store") / V.check_relative(a["name"]), {"name": "secrets/key"}),
    "res_8_bad": (uuid_then(P("/srv/store"), ".dat"), {"name": U}),
    "res_10_bad": (
        lambda a: (V.check_uuid(a["sid"]), P(a["moved"]) / f"{a['sid']}.dat")[1],
        {"sid": U, "moved": "/etc"},
    ),
    "tmp_1_bad": (
        lambda a: (V.check_uuid(a["sid"]), P(a["tempdir"]) / "cex-sessions" / f"{a['sid']}.json")[1],
        {"sid": U, "tempdir": "/etc"},
    ),
}

atoms = [
    "..",
    ".",
    "/",
    "a",
    "%2e",
    "%2f",
    "?",
    "\\",
    "etc",
    "~",
    "",
    "12345678123456781234567812345678",
    "{12345678-1234-5678-1234-567812345678}",
    "urn:uuid:12345678123456781234567812345678",
]
corpus = sorted({"".join(t) for n in range(1, 5) for t in itertools.product(atoms, repeat=n)})
CASE = {**GOOD, **{name: f for name, (f, _) in BAD.items()}}


@functools.cache
def accepted(case):
    """(input, opened path) for every corpus input the case accepts."""
    out = []
    for s in corpus:
        try:
            p = CASE[case]({"name": s})
        except (ValueError, KeyError):
            continue
        if p is not None:
            out.append((s, p))
    return tuple(out)


with open(sys.argv[2]) as f:
    rows = list(csv.DictReader(f))
fail = 0
for r in rows:
    roots = [x for x in r["allowed_roots"].split(";") if x]
    case, why = r["case"], r["reason"]
    if r["expected"] == "may":
        esc = [(s, p) for s, p in accepted(case) if outside(p, roots)]
        ok = bool(accepted(case)) and not esc
        detail = f"accepted={len(accepted(case))} escaped={len(esc)}" + (f" e.g. {esc[0]}" if esc else "")
    elif why == "escape":
        f, w = BAD[case]
        p = f(w)
        ok, detail = outside(p, roots), f"witness {w} -> {N(p)}"
    elif why == "contract-forbids":
        esc = next(((s, p) for s, p in accepted(case) if outside(p, roots)), None)
        ok, detail = esc is not None, f"input {esc[0]!r} -> {esc[1]}" if esc else "nothing leaves"
    else:
        ok, detail = why == "no-contract", "no danger claim"
    fail += not ok
    print(f"{r['scenario']:10} {case:12} {r['expected']:4} {why:16} {detail}  {'ok' if ok else 'FAIL'}")
print("rows", len(rows), "corpus", len(corpus), "failures", fail)
sys.exit(1 if fail else 0)
