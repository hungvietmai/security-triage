"""Authored static-only development probes. Never execute the subprocess calls."""
import subprocess

def constant_true(user_input):
    num = 86
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def constant_false(user_input):
    num = 100
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def renamed_true(user_input):
    different = 50
    if 10 * 30 - different > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def dynamic_parameter(user_input):
    if 7 * 42 - user_input > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def reassigned_input(user_input):
    num = 86
    num = user_input
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def conditional_reassignment(user_input):
    num = 86
    if user_input:
        num = 100
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def augmented_input(user_input):
    num = 86
    num += user_input
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def closure_mutation(user_input):
    num = 86
    def mutate():
        nonlocal num
        num = user_input
    mutate()
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def conditional_definition(user_input):
    if user_input:
        num = 86
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def deleted_local(user_input):
    num = 86
    del num
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def oversized_integer(user_input):
    num = 50000
    if num * num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def oversized_intermediate(user_input):
    num = 10000
    if num * num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def unsupported_call(user_input):
    num = int(user_input)
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def floating_point(user_input):
    num = 86.0
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def chained_comparison(user_input):
    num = 86
    if 0 < num < 100:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def negative_literal(user_input):
    if -7 + 2 <= -5:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def greater_equal(user_input):
    if 5 >= 5:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def less_false(user_input):
    if 9 < 2:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def equal_false(user_input):
    if 42 == 43:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def unequal_true(user_input):
    if 42 != 43:
        command = "echo fixed"
    else:
        command = user_input
    subprocess.run(command, shell=True)


def tainted_after_guard(user_input):
    num = 86
    if 7 * 42 - num > 200:
        command = "echo fixed"
    else:
        command = user_input
    command = user_input  # The guard stays constant; this sink is still unsafe.
    subprocess.run(command, shell=True)


