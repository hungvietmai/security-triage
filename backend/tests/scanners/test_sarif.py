import json

from app.scanners.sarif import sarif_findings


def test_sarif_preserves_raw_result_and_marks_incomplete(tmp_path):
    path = tmp_path / "result.sarif"
    raw_result = {
        "ruleIndex": 0,
        "message": {"text": "candidate"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "lib/example.js"},
                    "region": {"startLine": 12, "startColumn": 3},
                }
            }
        ],
    }
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "invocations": [
                            {
                                "executionSuccessful": False,
                                "toolExecutionNotifications": [{"level": "warning"}],
                            }
                        ],
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "js/example",
                                        "properties": {"tags": ["external/cwe/cwe-78"]},
                                    }
                                ]
                            }
                        },
                        "results": [raw_result],
                    }
                ],
            }
        )
    )

    findings, complete = sarif_findings(path, "codeql", "c" * 64)

    assert complete is False
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "js/example"
    assert finding["reported_path"] == "lib/example.js"
    assert finding["reported_region"] == {"startLine": 12, "startColumn": 3}
    assert finding["reported_cwes"] == ["cwe-78"]
    assert finding["message"] == "candidate"
    assert finding["mapping_status"] == "unresolved"
    assert finding["raw_result"] == raw_result


def test_sarif_rejects_wrong_version(tmp_path):
    path = tmp_path / "result.sarif"
    path.write_text(json.dumps({"version": "2.0.0", "runs": []}))

    try:
        sarif_findings(path, "semgrep", "d" * 64)
    except ValueError as exc:
        assert str(exc) == "Invalid SARIF 2.1.0 document"
    else:
        raise AssertionError("invalid SARIF was accepted")
