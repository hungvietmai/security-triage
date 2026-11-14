"""Synthetic checks for the Semgrep dead-branch evidence rules.

Each function is named <expectation>_<what it tests>:
  refuted_*  the flow into the command exists only through a branch that never runs, so the
             evidence rule must NOT report the command (control rule reports it);
  kept_*     the flow is live or the condition is not a provable constant, so the evidence
             rule MUST still report the command.
Synthetic test data written for this project; nothing here is executed.
"""

import os
import subprocess

from flask import request

LIMIT = 200
MUTABLE_LIMIT = 200


def _raise_limit():
    global MUTABLE_LIMIT
    MUTABLE_LIMIT = 500


def refuted_else_dead_constant_true():
    param = request.args.get("x")
    num = 86
    if 7 * 42 - num > 200:
        bar = "always"
    else:
        bar = param
    subprocess.run("echo " + bar, shell=True)


def refuted_if_dead_constant_false():
    param = request.args.get("x")
    bar = "fixed"
    if 3 + 4 == 8:
        bar = param
    os.system(f"echo {bar}")


def refuted_else_dead_less_or_equal():
    param = request.form["x"]
    if 10 <= 10:
        bar = "ok"
    else:
        bar = param
    subprocess.Popen("echo " + bar, shell=True)


def kept_else_live_constant_false():
    param = request.args.get("x")
    num = 106
    if 7 * 42 - num > 200:
        bar = "never"
    else:
        bar = param
    subprocess.run("echo " + bar, shell=True)


def kept_if_live_constant_true():
    param = request.args.get("x")
    bar = "fixed"
    if 3 + 4 == 7:
        bar = param
    os.system("echo " + bar)


def kept_condition_depends_on_input():
    param = request.args.get("x")
    if len(param) > 200:
        bar = "long"
    else:
        bar = param
    subprocess.run("echo " + bar, shell=True)


def kept_condition_uses_reassigned_variable(flag):
    param = request.args.get("x")
    num = 86
    if flag:
        num = 300
    if 7 * 42 - num > 200:
        bar = "sometimes"
    else:
        bar = param
    subprocess.run("echo " + bar, shell=True)


def refuted_module_name_assigned_once():
    # Semgrep treats a module-level name assigned exactly once in the file as a constant.
    # A value changed from another module would not be seen: a documented assumption.
    param = request.args.get("x")
    if 7 * 42 - 86 > LIMIT:
        bar = "always"
    else:
        bar = param
    subprocess.run("echo " + bar, shell=True)


def kept_module_name_reassigned_in_the_file():
    param = request.args.get("x")
    if 7 * 42 - 86 > MUTABLE_LIMIT:
        bar = "depends on who ran first"
    else:
        bar = param
    subprocess.run("echo " + bar, shell=True)


def kept_second_live_flow():
    param = request.args.get("x")
    other = request.args.get("y")
    if 1 > 0:
        bar = "always"
    else:
        bar = param
    subprocess.run("echo " + bar + other, shell=True)


def kept_tainted_after_dead_branch():
    param = request.args.get("x")
    if 1 > 0:
        bar = "always"
    else:
        bar = param
    bar = bar + param
    subprocess.run("echo " + bar, shell=True)


def kept_parameter_flow(name):
    if 1 > 0:
        bar = "always"
    else:
        bar = request.args.get("x")
    subprocess.run("echo " + bar + name, shell=True)


def kept_no_dead_branch():
    param = request.args.get("x")
    subprocess.run("echo " + param, shell=True)
