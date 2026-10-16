"""Counterexamples for path guards and path-related evidence (CWE-22).

Naming: `<mech>_<id>_bad` must remain reported (attacker can reach a file outside BASE);
`<mech>_<id>_good` is safe under the POSIX threat model and may be suppressed.
Written from the semantics of the check, not from any benchmark label.
"""

import os
import pathlib

from flask import Flask, abort, request

app = Flask(__name__)
BASE_DIR = "/srv/data"
BASE = pathlib.Path(BASE_DIR)


@app.route("/g1")
def guard_prefix_1_bad():
    # String prefix: "/srv/data-private/x" starts with "/srv/data".
    name = request.args.get("name", "")
    p = (BASE / name).resolve()
    if not str(p).startswith(str(BASE)):
        abort(400)
    return p.read_text()


@app.route("/g2")
def guard_prefix_2_good():
    # Prefix plus separator: only paths inside BASE pass.
    name = request.args.get("name", "")
    p = (BASE / name).resolve()
    if not str(p).startswith(str(BASE) + os.sep):
        abort(400)
    return p.read_text()


@app.route("/g3")
def guard_prefix_3_good():
    # Component-wise containment.
    name = request.args.get("name", "")
    p = (BASE / name).resolve()
    if not p.is_relative_to(BASE):
        abort(400)
    return p.read_text()


@app.route("/g4")
def guard_prefix_4_bad():
    # The checked value is not the value that is opened.
    name = request.args.get("name", "")
    checked = os.path.realpath(os.path.join(BASE_DIR, name))
    if not checked.startswith(BASE_DIR + os.sep):
        abort(400)
    return open(os.path.join(BASE_DIR, name)).read()


@app.route("/g5")
def guard_dotdot_5_bad():
    # No "..", but os.path.join discards BASE_DIR for an absolute name ("/etc/passwd").
    name = request.args.get("name", "")
    if ".." in name:
        abort(400)
    return open(os.path.join(BASE_DIR, name)).read()


@app.route("/g6")
def guard_dotdot_6_bad():
    # pathlib "/" also discards BASE for an absolute name.
    name = request.args.get("name", "")
    if ".." in name:
        abort(400)
    return (BASE / name).read_text()


@app.route("/g7")
def guard_dotdot_7_good():
    # String concatenation after a fixed directory prefix: an absolute name stays inside.
    name = request.args.get("name", "")
    if ".." in name:
        abort(400)
    return open(f"{BASE_DIR}/{name}").read()


@app.route("/g8")
def guard_dotdot_8_bad():
    # The guard does not stop execution.
    name = request.args.get("name", "")
    if ".." in name:
        print("suspicious name")
    return open(f"{BASE_DIR}/{name}").read()


@app.route("/g9")
def guard_dotdot_9_bad():
    # The guard checks a different variable from the one used in the path.
    name = request.args.get("name", "")
    other = request.args.get("other", "")
    if ".." in name:
        abort(400)
    return open(f"{BASE_DIR}/{other}").read()


# The same guards ending in `return`, so the guard really dominates the sink in the CFG
# (CodeQL does not treat `abort()` as non-returning).
@app.route("/r1")
def guard_prefix_r1_bad():
    name = request.args.get("name", "")
    p = (BASE / name).resolve()
    if not str(p).startswith(str(BASE)):
        return "invalid"
    return p.read_text()


@app.route("/r2")
def guard_prefix_r2_good():
    name = request.args.get("name", "")
    p = (BASE / name).resolve()
    if not str(p).startswith(str(BASE) + os.sep):
        return "invalid"
    return p.read_text()


@app.route("/r3")
def guard_prefix_r3_good():
    name = request.args.get("name", "")
    p = (BASE / name).resolve()
    if not p.is_relative_to(BASE):
        return "invalid"
    return p.read_text()


@app.route("/r5")
def guard_dotdot_r5_bad():
    name = request.args.get("name", "")
    if ".." in name:
        return "invalid"
    return open(os.path.join(BASE_DIR, name)).read()


@app.route("/r6")
def guard_dotdot_r6_bad():
    name = request.args.get("name", "")
    if "../" in name:
        return "invalid"
    return (BASE / name).read_text()


@app.route("/r7")
def guard_dotdot_r7_good():
    name = request.args.get("name", "")
    if "../" in name:
        return "invalid"
    return open(f"{BASE_DIR}/{name}").read()


@app.route("/r9")
def guard_dotdot_r9_bad():
    name = request.args.get("name", "")
    other = request.args.get("other", "")
    if ".." in name:
        return "invalid"
    return open(f"{BASE_DIR}/{other}").read()
