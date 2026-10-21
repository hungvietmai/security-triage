"""Synthetic static-analysis fixtures. Never import or run this application.

Markers identify individual operations, not whole functions. Filesystem metadata
access before a rejecting guard is distinct from content access after the guard.
"""

import os
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/srv/data"
BASE = Path(BASE_DIR)


@app.route("/checked-resolve")
def checked_resolve():
    name = request.args.get("name", "")
    path = (BASE / name).resolve()  # sink: resolve_metadata
    if not path.is_relative_to(BASE):
        return "invalid"
    return path.read_text()  # sink: checked_content


@app.route("/checked-realpath")
def checked_realpath():
    name = request.args.get("name", "")
    path = os.path.realpath(os.path.join(BASE_DIR, name))  # sink: realpath_metadata
    if not path.startswith(BASE_DIR + os.sep):
        return "invalid"
    return open(path).read()  # sink: realpath_content


@app.route("/discard-normalized")
def discard_normalized():
    name = request.args.get("name", "")
    checked = (BASE / name).resolve()  # sink: discarded_metadata
    if not checked.is_relative_to(BASE):
        return "invalid"
    return (BASE / name).read_text()  # sink: discarded_raw_content


@app.route("/swallowed-rejection")
def swallowed_rejection():
    name = request.args.get("name", "")
    path = (BASE / name).resolve()  # sink: swallowed_metadata
    try:
        if not path.is_relative_to(BASE):
            raise ValueError("invalid")
    except ValueError:
        pass
    return path.read_text()  # sink: swallowed_content


@app.route("/missing-boundary")
def missing_boundary():
    name = request.args.get("name", "")
    path = (BASE / name).resolve()  # sink: prefix_metadata
    if not str(path).startswith(str(BASE)):
        return "invalid"
    return path.read_text()  # sink: prefix_content


@app.route("/no-guard")
def no_guard():
    name = request.args.get("name", "")
    path = (BASE / name).resolve()  # sink: unchecked_metadata
    return path.read_text()  # sink: unchecked_content


def checked_helper(name):
    path = (BASE / name).resolve()  # sink: helper_metadata
    if not path.is_relative_to(BASE):
        raise ValueError("invalid")
    return path


@app.route("/returned-value")
def returned_value():
    name = request.args.get("name", "")
    return checked_helper(name).read_text()  # sink: returned_content


@app.route("/discarded-return")
def discarded_return():
    name = request.args.get("name", "")
    checked_helper(name)
    return (BASE / name).read_text()  # sink: discarded_return_content


@app.route("/lexical-control")
def lexical_control():
    name = request.args.get("name", "")
    path = os.path.abspath(os.path.join(BASE_DIR, name))
    if not path.startswith(BASE_DIR + os.sep):
        return "invalid"
    return open(path).read()  # sink: lexical_control_content
