"""Counterexamples for interprocedural, exception-based path guards (CWE-22).

Naming: `ipg_<id>_bad` must stay reported (an attacker-chosen value reaches a file outside BASE);
`ipg_<id>_good` is safe under the threat model of SPEC.md and may be suppressed.
Validators live in validators.py (a separate module, so every guard is interprocedural).
Threat model: POSIX; the attacker controls request data, not the contents of BASE; no symbolic
link on the access path (planted or pre-existing) leaves the lexically proven root (SPEC.md A-SYM);
file-system races between check and use are out of scope.
"""

import os
import posixpath

from flask import Flask, request

import validators
from validators import (
    Checker,
    Checks,
    check_conditional,
    check_contained,
    check_contained_other,
    check_nested,
    check_no_dotdot,
    check_not_absolute,
    check_prefix_weak,
    check_relative,
    check_relative_decoded,
    check_relative_pure,
    check_relative_stripped,
    check_swallow,
    check_uuid,
    check_windows_absolute,
    decode,
    is_safe,
    pick_checker,
    prepend_parent,
    safe_join_like,
    safe_join_normcase,
    safe_join_three,
)

app = Flask(__name__)
BASE = "/srv/data"
FS_ROOT = "/"


# ------------------------------------------------------------------ safe: may be suppressed


@app.route("/g1")
def ipg_1_good():
    # The value returned by the validator is the value used.
    name = check_relative(request.args["name"])
    return open(os.path.join(BASE, name)).read()


@app.route("/g2")
def ipg_2_good():
    # The validator checks its parameter itself and the caller keeps using the same variable.
    name = request.args["name"]
    check_relative(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/g3")
def ipg_3_good():
    # Canonical containment check on the joined path; the same path is opened.
    full = os.path.join(BASE, request.args["name"])
    check_contained(BASE, full)
    return open(full).read()


@app.route("/g4")
def ipg_4_good():
    # Lexical containment; the returned (already normalised) path is opened.
    return open(safe_join_like(BASE, request.args["name"])).read()


@app.route("/g5")
def ipg_5_good():
    # A UUID has no '/', '\\' or '..'; the file name stays a single segment under BASE.
    sid = request.args["sid"]
    check_uuid(sid)
    return open(os.path.join(BASE, f"{sid}.json")).read()


@app.route("/g6")
def ipg_6_good():
    # The exception is caught, but the handler leaves the function before the sink.
    name = request.args["name"]
    try:
        check_relative(name)
    except ValueError:
        return "invalid", 400
    return open(os.path.join(BASE, name)).read()


@app.route("/g7")
def ipg_7_good():
    # Validator delegating to another validator on the same parameter.
    name = request.args["name"]
    check_nested(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/g8")
def ipg_8_good():
    # The validator checks a transformed copy and returns it; the returned copy is used.
    name = check_relative_stripped(request.args["name"])
    return open(os.path.normpath(os.path.join(BASE, name))).read()


def ipg_9_good(sid):
    # The validator runs inside the function that contains the sink (callers pass raw input).
    check_uuid(sid)
    return open(os.path.join(BASE, sid + ".json")).read()


@app.route("/g9")
def session_route():
    return ipg_9_good(request.args["sid"])


@app.route("/g10")
def ipg_10_good():
    # Directory part of a safe relative path is still safe under BASE.
    rel = check_relative(request.args["name"])
    os.makedirs(os.path.join(BASE, posixpath.dirname(rel)), exist_ok=True)
    return open(os.path.join(BASE, rel), "w").write("x")


@app.route("/g11")
def ipg_11_good():
    # Boolean validator used as a guard: safe, but outside the v0.3 mechanism (may stay reported).
    name = request.args["name"]
    if not is_safe(name):
        return "invalid", 400
    return open(os.path.join(BASE, name)).read()


@app.route("/g12")
def ipg_12_good():
    # Exception caught inside a loop; `continue` skips the sink for the rejected item.
    out = []
    for name in request.args.getlist("name"):
        try:
            check_relative(name)
        except ValueError:
            continue
        out.append(open(os.path.join(BASE, name)).read())
    return "".join(out)


@app.route("/g13")
def ipg_13_good():
    # safe_join-style containment (three branches) under a trusted root that is not "/".
    return open(safe_join_three(BASE, request.args["name"])).read()


@app.route("/g14")
def ipg_14_good():
    # Same code as ipg_17_bad; this handler's sink contract also allows PUBLIC_ROOT
    # (policy/cex_sink_policy.model.yml), so containment under PUBLIC_ROOT is enough.
    full = os.path.join(validators.PUBLIC_ROOT, request.args["name"])
    check_contained_other(full)
    return open(full).read()


@app.route("/g15")
def ipg_15_good():
    # Three-branch containment with normcase inside each test, as Django lays it out (added after
    # the development-set diagnostics showed this layout was not recognised).
    return open(safe_join_normcase(BASE, request.args["name"])).read()


# ------------------------------------------------------------------ dangerous: must stay reported


@app.route("/b1")
def ipg_1_bad():
    # Return value ignored; the check applied to a transformed copy ("a?/../../etc/passwd").
    name = request.args["name"]
    check_relative_stripped(name)
    return open(os.path.normpath(os.path.join(BASE, name))).read()


@app.route("/b2")
def ipg_2_bad():
    # Exception caught and execution continues to the sink.
    name = request.args["name"]
    try:
        check_relative(name)
    except ValueError:
        pass
    return open(os.path.join(BASE, name)).read()


@app.route("/b3")
def ipg_3_bad():
    # The validator swallows its own exception.
    name = request.args["name"]
    check_swallow(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/b4")
def ipg_4_bad():
    # The variable is rebound after the check.
    name = request.args["name"]
    check_relative(name)
    name = request.args["other"]
    return open(os.path.join(BASE, name)).read()


@app.route("/b5")
def ipg_5_bad():
    # One value is checked, another is used.
    checked = request.args["a"]
    used = request.args["b"]
    check_relative(checked)
    return open(os.path.join(BASE, used)).read()


@app.route("/b6")
def ipg_6_bad():
    # Decoding after the check: "%2e%2e/%2e%2e/etc/passwd" passes, the decoded value escapes.
    name = request.args["name"]
    check_relative(name)
    return open(os.path.join(BASE, decode(name))).read()


@app.route("/b7")
def ipg_7_bad():
    # Decoding after the join with BASE.
    name = check_relative(request.args["name"])
    return open(os.path.normpath(decode(os.path.join(BASE, name)))).read()


@app.route("/b8")
def ipg_8_bad():
    # Partial validator: an absolute name makes os.path.join discard BASE.
    name = request.args["name"]
    check_no_dotdot(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/b9")
def ipg_9_bad():
    # Partial validator: '..' passes.
    name = request.args["name"]
    check_not_absolute(name)
    return open(os.path.normpath(os.path.join(BASE, name))).read()


@app.route("/b10")
def ipg_10_bad():
    # The validator only raises in strict mode, which is off here.
    name = request.args["name"]
    check_conditional(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/b11")
def ipg_11_bad():
    # Boolean validator whose result is ignored.
    name = request.args["name"]
    is_safe(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/b12")
def ipg_12_bad():
    # UUID check on one parameter, another parameter forms the file name.
    sid = request.args["sid"]
    other = request.args["other"]
    check_uuid(sid)
    return open(os.path.join(BASE, f"{other}.json")).read()


@app.route("/b13")
def ipg_13_bad():
    # The check applies to a prefix of the value, not the value used.
    name = request.args["name"]
    check_relative(name[:8])
    return open(os.path.normpath(os.path.join(BASE, name))).read()


@app.route("/b14")
def ipg_14_bad():
    # Containment checked for a joined path that is not the path opened.
    name = request.args["name"]
    check_contained(BASE, os.path.join(BASE, "public"))
    return open(os.path.normpath(os.path.join(BASE, name))).read()


# ---- cases added after the SPEC review (the four mandatory corrections) ----


@app.route("/b15")
def ipg_15_bad():
    # SafeRel proven, but the value goes straight to the sink with no join to a trusted root,
    # so it is read relative to the process working directory, not BASE.
    name = check_relative(request.args["name"])
    return open(name).read()


@app.route("/b16")
def ipg_16_bad():
    # Containment check whose prefix test omits the separator: a sibling directory sharing the
    # prefix passes. The equality branch is safe, but the prefix branch is not.
    name = request.args["name"]
    return open(check_prefix_weak(BASE, name)).read()


@app.route("/b17")
def ipg_17_bad():
    # Containment is proven for PUBLIC_ROOT, but this handler's sink contract allows BASE only
    # (policy/cex_sink_policy.model.yml). Same code as ipg_14_good; only the contract differs.
    full = os.path.join(validators.PUBLIC_ROOT, request.args["name"])
    check_contained_other(full)
    return open(full).read()


@app.route("/b18")
def ipg_18_bad():
    # The validator-shaped function returns a value it has made unsafe.
    name = prepend_parent(request.args["name"])
    return open(os.path.normpath(os.path.join(BASE, name))).read()


@app.route("/b19")
def ipg_19_bad():
    # Safe value passed through an intermediate function that prepends a parent component.
    name = check_relative(request.args["name"])
    name = prepend_parent(name)
    return open(os.path.normpath(os.path.join(BASE, name))).read()


@app.route("/b20")
def ipg_20_bad():
    # Two paths to the same sink; only one is validated.
    if request.args.get("mode") == "safe":
        name = check_relative(request.args["name"])
    else:
        name = request.args["name"]
    return open(os.path.normpath(os.path.join(BASE, name))).read()


@app.route("/b21")
def ipg_21_bad():
    # The validator is selected dynamically; the call target is not statically resolvable.
    validate = getattr(validators, request.args.get("checker", "is_safe"))
    name = request.args["name"]
    validate(name)
    return open(os.path.join(BASE, name)).read()


# ---- cases added after the second SPEC review (trusted root, concatenation, root "/") ----


@app.route("/b22")
def ipg_22_bad():
    # SafeRel value appended to the trusted root without a separator: "-evil/x" -> "/srv/data-evil/x".
    name = check_relative(request.args["name"])
    return open(f"{BASE}{name}").read()


@app.route("/b23")
def ipg_23_bad():
    # The same three-branch containment under the filesystem root: every absolute path is
    # "contained", so files the application never meant to serve ("etc/passwd") are reachable.
    return open(safe_join_three(FS_ROOT, request.args["name"])).read()


SETTINGS = {}


@app.route("/settings", methods=["POST"])
def save_settings():
    # Second untrusted source: an earlier request stores the root that ipg_24_bad reads.
    SETTINGS["root"] = request.form["root"]
    return "saved"


@app.route("/b24")
def ipg_24_bad():
    # The root is not tainted by this request's source, but another request wrote it.
    root = SETTINGS.get("root", BASE)
    full = os.path.join(root, request.args["name"])
    check_contained(root, full)
    return open(full).read()


# ---- cases added after the development-set diagnostics (check shapes and call forms) ----


@app.route("/g16")
def ipg_16_good():
    # Relative test through the POSIX path flavour: PurePosixPath(s).is_absolute().
    name = check_relative_pure(request.args["name"])
    return open(os.path.join(BASE, name)).read()


@app.route("/g17")
def ipg_17_good():
    # The validator reassigns its parameter on one branch before checking (a phi variable) and
    # returns the checked value, which is the value used.
    name = check_relative_decoded(request.args["name"])
    return open(os.path.join(BASE, name)).read()


@app.route("/g18")
def ipg_18_good():
    # Static-method validator called through its class.
    name = request.args["name"]
    Checks.relative(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/g19")
def ipg_19_good():
    # Instance-method validator; the call binds `self`, so argument 0 is parameter 1.
    name = request.args["name"]
    Checker().relative(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/b25")
def ipg_25_bad():
    # The Windows path flavour: "/etc/passwd" is not absolute for it on POSIX, so it passes.
    name = request.args["name"]
    check_windows_absolute(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/b26")
def ipg_26_bad():
    # Two possible targets (Checker.relative, LaxChecker.relative); the override checks nothing.
    name = request.args["name"]
    pick_checker(request.args.get("lax")).relative(name)
    return open(os.path.join(BASE, name)).read()
