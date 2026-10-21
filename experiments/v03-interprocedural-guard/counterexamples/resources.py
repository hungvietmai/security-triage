"""Counterexamples for resource-derived sink contracts (SPEC_RESOURCE.md, CWE-22).

A resource root is a module constant from a recognised server-side origin that the program
creates and uses only as a flat store of validated single-segment names. Outcomes per mode
(strict, scoped) are in expectations/resources_expectations.csv; `res_<id>_bad` must stay
reported in every mode.
"""

import os
import shutil
import tempfile
from pathlib import Path

from flask import Flask, request

from validators import check_relative, check_uuid

app = Flask(__name__)

SESSIONS = Path(tempfile.gettempdir()) / "cex-sessions"  # temp-based resource root
STORE = Path("/srv/store")  # constant resource root
SECRETS = STORE / "secrets"  # a second store nested inside STORE
CACHE = Path(tempfile.gettempdir()) / "cex-cache"  # joined, never created
SHARED = Path("/srv/shared")  # created, but also handed to other code
MUTABLE = Path(tempfile.gettempdir()) / "cex-mutable"  # rebound from request data
TMP = Path(tempfile.gettempdir())  # the shared temp directory itself
STORE2 = Path("/srv/store2")  # rebound through an attribute write in resources_admin.py
TESTED = Path(tempfile.gettempdir()) / "cex-tested"  # rebound only by test code
SETTINGS = {}


def init_stores():
    SESSIONS.mkdir(parents=True, exist_ok=True)
    STORE.mkdir(parents=True, exist_ok=True)
    SECRETS.mkdir(parents=True, exist_ok=True)
    SHARED.mkdir(parents=True, exist_ok=True)
    MUTABLE.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)
    STORE2.mkdir(parents=True, exist_ok=True)
    TESTED.mkdir(parents=True, exist_ok=True)
    os.makedirs(user_root(), exist_ok=True)


def session_file(sid):
    check_uuid(sid)
    return SESSIONS / f"{sid}.json"


def user_root():
    return Path(SETTINGS.get("root", "/srv/uploads"))


def reset_shared():
    shutil.rmtree(SHARED)


@app.route("/res/settings", methods=["POST"])
def save_settings():
    SETTINGS["root"] = request.form["root"]
    return "saved"


@app.route("/res/move", methods=["POST"])
def move_store():
    global MUTABLE
    MUTABLE = Path(request.form["dir"])
    return "moved"


@app.route("/res1")
def res_1_good():
    # Temp-based resource root, created by init_stores, used only as a flat store; the path
    # comes back from a function with a single return.
    return session_file(request.args["sid"]).read_text()


@app.route("/res2")
def res_2_good():
    # Constant resource root.
    sid = request.args["sid"]
    check_uuid(sid)
    return (STORE / f"{sid}.dat").read_text()


@app.route("/res3")
def res_3_bad():
    # MUTABLE is rebound from request data by move_store.
    sid = request.args["sid"]
    check_uuid(sid)
    return (MUTABLE / f"{sid}.json").read_text()


@app.route("/res4")
def res_4_bad():
    # The root comes from settings that another request writes.
    sid = request.args["sid"]
    check_uuid(sid)
    return (user_root() / f"{sid}.json").read_text()


@app.route("/res5")
def res_5_good():
    # CACHE is joined but never created: no evidence that the program manages it as a store.
    sid = request.args["sid"]
    check_uuid(sid)
    return (CACHE / f"{sid}.json").read_text()


@app.route("/res6")
def res_6_good():
    # SHARED is also handed to other code (reset_shared), so it is not used only as a store.
    sid = request.args["sid"]
    check_uuid(sid)
    return (SHARED / f"{sid}.json").read_text()


@app.route("/res7")
def res_7_bad():
    # A multi-segment name reaches the nested SECRETS store: not a flat entry of STORE.
    rel = check_relative(request.args["name"])
    return (STORE / rel).read_text()


@app.route("/res8")
def res_8_bad():
    # The declared contract (policy_scenarios/resources) allows /srv/other only for this sink.
    sid = request.args["sid"]
    check_uuid(sid)
    return (STORE / f"{sid}.dat").read_text()


@app.route("/res9")
def res_9_good():
    # The shared temp directory itself is not a dedicated store (no own segment).
    sid = request.args["sid"]
    check_uuid(sid)
    return (TMP / f"{sid}.json").read_text()


@app.route("/res10")
def res_10_bad():
    # STORE2 is rebound by an attribute write in resources_admin.py.
    sid = request.args["sid"]
    check_uuid(sid)
    return (STORE2 / f"{sid}.dat").read_text()


@app.route("/res11")
def res_11_good():
    # TESTED is rebound only by test code (tests/test_resources.py): scoped assumption S-TEST.
    sid = request.args["sid"]
    check_uuid(sid)
    return (TESTED / f"{sid}.json").read_text()
