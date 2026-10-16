"""Counterexamples for route-fixed path segments (sink: file open) and response headers (XSS).
Same naming convention as paths.py."""

from flask import Flask, make_response, request

app = Flask(__name__)
BASE_DIR = "/srv/data"


@app.route("/fixed/route")
def route_1_good():
    # Segment 1 of the path is always "fixed".
    parts = request.path.split("/")
    seg = parts[1]
    return open(f"{BASE_DIR}/{seg}").read()


@app.route("/fixed/route2")
def route_2_bad():
    # Segment 1 is fixed when routed here, but route_2_caller calls this function for any path.
    parts = request.path.split("/")
    seg = parts[1]
    return open(f"{BASE_DIR}/{seg}").read()


@app.route("/any/<path:rest>")
def route_2_caller(rest):
    return route_2_bad()


@app.route("/item/<name>")
def route_3_bad(name):
    # Segment 2 is a route placeholder.
    parts = request.path.split("/")
    seg = parts[2]
    return open(f"{BASE_DIR}/{seg}").read()


def status_and_body(text):
    return ("ok", text)


@app.route("/h1")
def header_1_bad():
    # A helper returns a tuple; the caller uses element 1 as the response body.
    param = request.args.get("p", "")
    body = status_and_body(param)[1]
    return body


@app.route("/h2")
def header_2_good():
    param = request.args.get("p", "")
    return make_response(("static body", {"X-Value": param}))


@app.route("/h3")
def header_3_bad():
    # Element 0 of the tuple is the body.
    param = request.args.get("p", "")
    return make_response((param, 200))


@app.route("/h4")
def header_4_bad():
    # Three-element response tuple: element 0 is still the body.
    param = request.args.get("p", "")
    return (param, 200, {"X-Static": "1"})
