"""Counterexamples for XPath quote handling (CWE-643). Same naming convention as paths.py."""

import lxml.etree
from flask import Flask, abort, request

app = Flask(__name__)
ROOT = lxml.etree.fromstring(b"<users><user name='a'/></users>")


@app.route("/x1")
def guard_quote_1_bad():
    # Single quotes replaced, but the literal is delimited by double quotes.
    name = request.args.get("name", "")
    safe = name.replace("'", "&apos;")
    query = f'//user[@name="{safe}"]'
    return str(ROOT.xpath(query))


@app.route("/x2")
def guard_quote_2_good():
    # Single quotes replaced and the literal is delimited by single quotes.
    name = request.args.get("name", "")
    safe = name.replace("'", "&apos;")
    query = f"//user[@name='{safe}']"
    return str(ROOT.xpath(query))


@app.route("/x3")
def guard_quote_3_bad():
    # Rejects single quotes, literal delimited by double quotes.
    name = request.args.get("name", "")
    if "'" in name:
        abort(400)
    query = '//user[@name="' + name + '"]'
    return str(ROOT.xpath(query))


@app.route("/x4")
def guard_quote_4_good():
    # Rejects single quotes, literal delimited by single quotes.
    name = request.args.get("name", "")
    if "'" in name:
        abort(400)
    query = "//user[@name='" + name + "']"
    return str(ROOT.xpath(query))


@app.route("/x5")
def guard_quote_5_bad():
    # Value inserted outside any string literal: quote handling is irrelevant.
    name = request.args.get("name", "")
    safe = name.replace("'", "&apos;")
    query = f"//user[{safe}]"
    return str(ROOT.xpath(query))


@app.route("/x6")
def guard_quote_6_good():
    # XPath variable binding: the value never becomes part of the expression.
    name = request.args.get("name", "")
    return str(ROOT.xpath("//user[@name=$n]", n=name))


@app.route("/xr3")
def guard_quote_r3_bad():
    name = request.args.get("name", "")
    if "'" in name:
        return "invalid"
    query = '//user[@name="' + name + '"]'
    return str(ROOT.xpath(query))


@app.route("/xr4")
def guard_quote_r4_good():
    name = request.args.get("name", "")
    if "'" in name:
        return "invalid"
    query = "//user[@name='" + name + "']"
    return str(ROOT.xpath(query))


@app.route("/xr7")
def guard_quote_r7_good():
    # Replacement inline inside a single-quoted literal, joined from a list.
    name = request.args.get("name", "")
    query = "".join(["//user[@name='", name.replace("'", "&apos;"), "']"])
    return str(ROOT.xpath(query))


@app.route("/xr8")
def guard_quote_r8_bad():
    # The replacement re-introduces the quote character.
    name = request.args.get("name", "")
    query = "//user[@name='" + name.replace("'", "\\'") + "']"
    return str(ROOT.xpath(query))
