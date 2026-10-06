from app.triage.sinks_python import locate_python_sinks


def test_python_locator_finds_aliases_nested_calls_shell_and_argv_forms():
    source = """import os as operating_system
from os import system as syscmd
import subprocess as sp
from subprocess import Popen as launch
import asyncio as aio
from asyncio import create_subprocess_shell as shell_async
import pty as terminal

def demo(user):
    operating_system.system("printf fixed")
    syscmd(user)
    sp.run(["echo", user], shell=False)
    launch("echo " + user, shell=True)
    aio.create_subprocess_exec("echo", user)
    shell_async("echo " + user)
    terminal.spawn(["sh", "-c", user])
    operating_system.execvp("echo", ["echo", user])
    operating_system.spawnvp(0, "echo", ["echo", user])
    sp.run(operating_system.popen("echo nested").read())
"""
    sinks = locate_python_sinks("fixture.py", source)

    assert len(sinks) == 11
    assert {sink["sink_kind"] for sink in sinks} == {
        "os.system",
        "os.popen",
        "os.execvp",
        "os.spawnvp",
        "subprocess.run",
        "subprocess.Popen",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "pty.spawn",
    }
    assert all(sink["path"] == "fixture.py" for sink in sinks)

    fixed = next(sink for sink in sinks if sink["callee"] == "operating_system.system")
    assert fixed["args"][0]["text"] == '"printf fixed"'
    assert fixed["args"][0]["value_kind"] == "string"

    list_run = next(
        sink
        for sink in sinks
        if sink["callee"] == "sp.run" and sink["args"][0]["value_kind"] == "list"
    )
    assert list_run["args"][0]["text"] == '["echo", user]'
    assert list_run["args"][1]["keyword"] == "shell"
    assert list_run["args"][1]["literal_bool"] is False

    shell_launch = next(sink for sink in sinks if sink["callee"] == "launch")
    assert shell_launch["sink_kind"] == "subprocess.Popen"
    assert shell_launch["args"][1]["keyword"] == "shell"
    assert shell_launch["args"][1]["literal_bool"] is True

    outer = next(
        sink
        for sink in sinks
        if sink["sink_kind"] == "subprocess.run"
        and sink["args"][0]["text"].startswith("operating_system.popen")
    )
    inner = next(sink for sink in sinks if sink["sink_kind"] == "os.popen")
    assert outer["span"]["startLine"] == inner["span"]["startLine"]
    assert outer["span"]["startColumn"] < inner["span"]["startColumn"]
    assert outer["span"]["endColumn"] > inner["span"]["endColumn"]


def test_python_locator_does_not_treat_non_execution_calls_as_sinks():
    source = """import os
import asyncio
from math import sqrt

os.path.join("a", "b")
asyncio.sleep(1)
sqrt(4)
"""
    assert locate_python_sinks("safe.py", source) == []
