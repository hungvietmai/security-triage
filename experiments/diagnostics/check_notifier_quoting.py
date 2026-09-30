"""Bounded development diagnostic for pinned node-notifier source, not a safety proof.

Runs only reviewed function slices; no require(), native notifier or package install.
Shell probes contain fixed printf markers only and print their parsed arguments.
"""

import argparse
import base64
import gzip
import hashlib
import itertools
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

UTILS_HASH = "bd5ed859adeda193e15672e769551966b31cecaa6294fc52297533d835af3702"
CALLER_HASH = "29fe357ee97ad29245f55bfcfee3ce75bc86375910d9b9709105a11d28f287de"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    envelope = json.loads(args.evidence.read_text())
    raw = gzip.decompress(base64.b64decode(envelope["payload"]))
    if sha(raw) != envelope["decoded_sha256"]:
        raise ValueError("Evidence digest mismatch")
    evidence = json.loads(raw)

    def source(name, expected):
        entry = evidence["source_files"][name]
        data = base64.b64decode(entry["content"])
        if sha(data) != expected or entry["sha256"] != expected:
            raise ValueError("Pinned source mismatch: " + name)
        return data.decode().splitlines(keepends=True)

    utils = source("lib/utils.js", UTILS_HASH)
    caller = source("notifiers/notifysend.js", CALLER_HASH)
    # Reviewed declarations only; line endpoints are inclusive and hash guarded.
    slices = [(13, 49), (134, 185), (241, 243), (287, 335)]
    js = "const module = {exports:{}}; const process = {platform:'linux'};\n"
    js += "".join("".join(utils[a - 1 : b]) for a, b in slices)
    js += "\nconst utils=module.exports; const notifier='notify-send'; let captured;\n"
    js += "utils.command=(program,args)=>{captured={program,args}};\n"
    js += "".join(caller[81:99])
    # stdin reading is outside reviewed package snippets; no package loader runs.
    prefix = "const input=JSON.parse(require('fs').readFileSync(0,'utf8'));\n"
    suffix = """
const results=input.map(c=>{
 try {
  captured=null;
  const options=JSON.parse(JSON.stringify(c.options));
  doNotification(options,()=>{});
  return {id:c.id,...captured};
 } catch(e) {return {id:c.id,error:e.name};}
});
console.log(JSON.stringify(results));
"""
    # Primary string corpus is specified deterministically, before execution.
    alphabet = ["a", " ", '"', "'", "$", "`", "\\", "\n"]
    strings = (
        [""] + alphabet + ["".join(x) for x in itertools.product(alphabet, repeat=2)]
    )
    strings += [
        "$(printf TRIAGE_PROBE)",
        "`printf TRIAGE_PROBE`",
        '"; printf TRIAGE_PROBE; #',
        "${TRIAGE_PROBE}",
        "*?[abc]",
        "a\r\nb",
        "a\rb",
        "Tiếng Việt",
        "--help",
        "a\tb",
    ]
    cases = []
    for index, value in enumerate(strings):
        # Nonempty prefix satisfies notifyRaw's truthy message guard.
        value = "data:" + value
        expected_value = value.replace("\r\n", "\\n").replace("\n", "\\n")
        for field in ("message", "icon"):
            opts = {"title": "fixed-title", "message": "fixed-message"}
            opts[field] = value
            expected = [
                "fixed-title",
                expected_value if field == "message" else "fixed-message",
            ]
            if field == "icon":
                expected += ["--icon", expected_value]
            expected += ["--expire-time", "10000"]
            cases.append(
                {
                    "id": f"{field}-{index}",
                    "group": "string",
                    "options": opts,
                    "expected": expected,
                }
            )
    types = [
        ("number", 42, "42"),
        ("boolean", True, "true"),
        ("null", None, "null"),
        ("object", {"x": 1}, "[object Object]"),
        ("array", ["a", "b"], "a,b"),
        ("nested-array", [["a"], ["b"]], "a,b"),
    ]
    for name, value, text in types:
        cases.append(
            {
                "id": name,
                "group": "json-type",
                "options": {
                    "title": "fixed-title",
                    "message": "fixed-message",
                    "icon": value,
                },
                "expected": [
                    "fixed-title",
                    "fixed-message",
                    "--icon",
                    text,
                    "--expire-time",
                    "10000",
                ],
            }
        )
    cases += [
        {
            "id": "empty-array",
            "group": "boundary",
            "options": {"title": "fixed-title", "message": "fixed-message", "icon": []},
            "expected": [
                "fixed-title",
                "fixed-message",
                "--icon",
                "--expire-time",
                "10000",
            ],
            "note": "Empty array emits no shell word: value arity changes, not proof of injection.",
        },
        {
            "id": "noncallable-toString",
            "group": "boundary",
            "options": {
                "title": "fixed-title",
                "message": "fixed-message",
                "icon": {"toString": "x"},
            },
            "expected_error": "TypeError",
        },
    ]
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node required")
    program = prefix + js + suffix
    built = subprocess.run(
        [node, "-e", program],
        input=json.dumps(cases),
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )
    results = json.loads(built.stdout)
    shells = ["/usr/bin/dash", "/usr/bin/bash"]
    for shell in shells:
        if not Path(shell).is_file():
            raise RuntimeError("Required shell unavailable: " + shell)
    rows = []
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    with tempfile.TemporaryDirectory(prefix="notifier-quoting-") as cwd:

        def parse(shell, words):
            # Fixed, benign corpus only. set/printf are shell builtins; no notifier runs.
            script = "set -- " + " ".join(words) + '; printf "%s\\0" "$@"'
            cmd = (
                [shell]
                + (["--posix"] if shell.endswith("/bash") else [])
                + ["-c", script]
            )
            p = subprocess.run(
                cmd, capture_output=True, env=env, cwd=cwd, timeout=3, check=False
            )
            return p.returncode, p.stdout, p.stderr

        for c, built in zip(cases, results, strict=True):
            if c["id"] != built["id"]:
                raise ValueError("Case ordering mismatch")
            row = {**c, "constructed": built, "shells": []}
            if "error" in built:
                row["matched_expectation"] = built["error"] == c.get("expected_error")
            else:
                row["matched_expectation"] = "expected_error" not in c
                expected = b"".join(s.encode() + b"\0" for s in c["expected"])
                for shell in shells:
                    code, stdout, stderr = parse(shell, built["args"])
                    passed = code == 0 and stdout == expected and not stderr
                    row["shells"].append(
                        {
                            "shell": shell,
                            "exit_code": code,
                            "stdout_base64": base64.b64encode(stdout).decode(),
                            "stderr": stderr.decode(errors="replace"),
                            "passed": passed,
                        }
                    )
                    row["matched_expectation"] &= passed
            rows.append(row)
        # Deliberately broken quoting control must reveal harmless substitution.
        controls = []
        for shell in shells:
            code, stdout, stderr = parse(shell, ['"$(printf TRIAGE_PROBE)"'])
            controls.append(
                {
                    "shell": shell,
                    "detected_unescaped_substitution": code == 0
                    and stdout == b"TRIAGE_PROBE\0"
                    and not stderr,
                }
            )
    result = {
        "diagnostic": "node-notifier-quoting-v1",
        "source_sha256": UTILS_HASH,
        "caller_sha256": CALLER_HASH,
        "runner_sha256": sha(Path(__file__).read_bytes()),
        "extracted_program_sha256": sha(program.encode()),
        "corpus_sha256": sha(json.dumps(cases, sort_keys=True).encode()),
        "node_version": subprocess.check_output([node, "--version"], text=True).strip(),
        "shell_binary_sha256": {s: sha(Path(s).read_bytes()) for s in shells},
        "cases": rows,
        "controls": controls,
        "summary": {
            "cases": len(rows),
            "matched": sum(r["matched_expectation"] for r in rows),
            "shell_checks": sum(len(r["shells"]) for r in rows),
        },
        "label_status": "unapproved; bounded diagnostic only; no FP metric",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as out:
        json.dump(result, out, ensure_ascii=False, indent=2)
        out.write("\n")
    print(json.dumps(result["summary"]))
    return (
        0
        if all(r["matched_expectation"] for r in rows)
        and all(c["detected_unescaped_substitution"] for c in controls)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
