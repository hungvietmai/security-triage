"""Counterexamples for constant branches and simulated collections (sink: file open, CWE-22).
Same naming convention as paths.py. Every *_bad function lets request data reach `open`."""

from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/srv/data"
LIMIT = 86


def set_limit(v):
    global LIMIT
    LIMIT = v


@app.route("/c1")
def constbranch_1_bad():
    # Condition depends on request data.
    param = request.args.get("p", "")
    num = int(request.args.get("n", "0"))
    if 7 * 42 - num > 200:
        bar = "safe"
    else:
        bar = param
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/c2")
def constbranch_2_good():
    # 294 - 86 = 208 > 200: the else branch never runs.
    param = request.args.get("p", "")
    num = 86
    if 7 * 42 - num > 200:
        bar = "safe"
    else:
        bar = param
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/c3")
def constbranch_3_bad():
    # The local has a second assignment on a request-dependent path.
    param = request.args.get("p", "")
    num = 86
    if request.args.get("big"):
        num = 1000
    if 7 * 42 - num > 200:
        bar = "safe"
    else:
        bar = param
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/c4")
def constbranch_4_bad():
    # Module-level value can be changed by another handler.
    param = request.args.get("p", "")
    if 7 * 42 - LIMIT > 200:
        bar = "safe"
    else:
        bar = param
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/c5")
def constbranch_5_bad():
    # Constant subject, but the selected case is the tainted one.
    param = request.args.get("p", "")
    possible = "ABC"
    guess = possible[0]
    match guess:
        case "A":
            bar = param
        case _:
            bar = "safe"
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/c6")
def constbranch_6_good():
    param = request.args.get("p", "")
    possible = "ABC"
    guess = possible[1]
    match guess:
        case "A":
            bar = param
        case _:
            bar = "safe"
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/c7")
def constbranch_7_bad():
    # Integer outside the supported bound: no evidence may be produced.
    param = request.args.get("p", "")
    num = 100000
    bar = "safe" if num * 3 > 10**6 else param
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/l1")
def collection_1_good():
    param = request.args.get("p", "")
    lst = []
    lst.append("safe")
    lst.append(param)
    lst.append("moresafe")
    lst.pop(0)
    bar = lst[1]
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/l2")
def collection_2_bad():
    # Alias mutation shifts the elements.
    param = request.args.get("p", "")
    lst = []
    lst.append("safe")
    lst.append(param)
    other = lst
    other.pop(0)
    bar = lst[0]
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/l3")
def collection_3_bad():
    # Unmodelled operation inserts tainted data at index 0.
    param = request.args.get("p", "")
    lst = []
    lst.append("safe")
    lst.insert(0, param)
    bar = lst[0]
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/l4")
def collection_4_bad():
    # Index from the request.
    param = request.args.get("p", "")
    i = int(request.args.get("i", "0"))
    lst = []
    lst.append("safe")
    lst.append(param)
    bar = lst[i]
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/l5")
def collection_5_bad():
    # Element overwritten through subscript assignment.
    param = request.args.get("p", "")
    lst = []
    lst.append("safe")
    lst[0] = param
    bar = lst[0]
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/l6")
def collection_6_bad():
    # Dict updated through a method call.
    param = request.args.get("p", "")
    m = {}
    m["a"] = "safe"
    m.update({"a": param})
    bar = m["a"]
    return open(f"{BASE_DIR}/{bar}").read()


@app.route("/l7")
def collection_7_good():
    param = request.args.get("p", "")
    m = {}
    m["a"] = "safe"
    m["b"] = param
    bar = m["a"]
    return open(f"{BASE_DIR}/{bar}").read()
