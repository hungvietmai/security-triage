"""tempfile.tempdir can be set from request data before the store module is first imported.

Kept apart from counterexamples/: a write to tempfile.tempdir affects every temp-based root of
the program, so it would also invalidate the temp-based roots there.
"""

import tempfile

from flask import Flask, request

app = Flask(__name__)


@app.route("/tmpdir", methods=["POST"])
def set_tmpdir():
    tempfile.tempdir = request.form["dir"]
    return "ok"


@app.route("/t1")
def tmp_1_bad():
    # The store module is imported here, after set_tmpdir may have run: its root follows.
    from tmpdir_store import entry

    return entry(request.args["sid"]).read_text()
