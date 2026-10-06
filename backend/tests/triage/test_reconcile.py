from app.triage.reconcile import reconcile_findings


def _sink(*, path="a.js", start=10, end=10, start_col=1, end_col=20, kind="child_process.exec"):
    return {
        "path": path,
        "span": {
            "startLine": start,
            "startColumn": start_col,
            "endLine": end,
            "endColumn": end_col,
        },
        "callee": "exec",
        "sink_kind": kind,
        "args": [
            {
                "position": 0,
                "keyword": None,
                "span": {
                    "startLine": start,
                    "startColumn": start_col + 5,
                    "endLine": end,
                    "endColumn": end_col - 1,
                },
                "text": "command",
                "value_kind": "name",
                "literal_bool": None,
            }
        ],
    }


def _finding(*, raw_id="codeql:0:0", path="a.js", region=None, message="", raw_result=None):
    return {
        "raw_id": raw_id,
        "tool": "codeql",
        "snapshot_sha256": "a" * 64,
        "reported_path": path,
        "reported_region": region
        or {
            "startLine": 10,
            "startColumn": 6,
            "endLine": 10,
            "endColumn": 12,
        },
        "message": message,
        "raw_result": raw_result or {},
    }


def test_explicit_link_merges_multiple_findings_into_one_shell_unit():
    sink = _sink(start=56, end=58, start_col=3, end_col=5)
    related = {
        "relatedLocations": [
            {
                "id": 2,
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.js"},
                    "region": {
                        "startLine": 56,
                        "startColumn": 3,
                        "endLine": 58,
                        "endColumn": 5,
                    },
                },
            }
        ]
    }
    findings = [
        _finding(
            raw_id="codeql:0:0",
            region={"startLine": 20, "startColumn": 1, "endLine": 20, "endColumn": 5},
            message="later used in a [shell command](2)",
            raw_result=related,
        ),
        _finding(
            raw_id="codeql:0:1",
            region={"startLine": 30, "startColumn": 1, "endLine": 30, "endColumn": 5},
            message="later used in a [shell command](2)",
            raw_result=related,
        ),
    ]

    units = reconcile_findings(findings, [sink], {"a.js": "
" * 60})

    assert len(units) == 1
    unit = units[0]
    assert unit["mapping_status"] == "mapped"
    assert unit["argument_role"] == "shell_command"
    assert unit["sink_kind"] == "child_process.exec"
    assert unit["raw_finding_ids"] == ["codeql:0:0", "codeql:0:1"]
    assert [row["mapping_method"] for row in unit["mappings"]] == [
        "explicit_link",
        "explicit_link",
    ]


def test_containment_prefers_unique_innermost_sink():
    outer = _sink(start=10, end=12, start_col=1, end_col=30)
    inner = _sink(start=10, end=10, start_col=5, end_col=20)
    finding = _finding(
        region={
            "startLine": 10,
            "startColumn": 7,
            "endLine": 10,
            "endColumn": 12,
        }
    )

    unit = reconcile_findings([finding], [outer, inner], {"a.js": "
" * 15})[0]

    assert unit["mapping_status"] == "mapped"
    assert unit["sink_span"] == inner["span"]
    assert unit["mappings"][0]["mapping_method"] == "containment"


def test_exact_span_maps_when_containment_is_strict():
    sink = _sink()
    finding = _finding(region=dict(sink["span"]))

    unit = reconcile_findings([finding], [sink], {"a.js": "
" * 15})[0]

    assert unit["mapping_status"] == "mapped"
    assert unit["mappings"][0]["mapping_method"] == "exact_span"


def test_ambiguous_incomparable_sinks_fall_back():
    first = _sink(start=10, end=10, start_col=1, end_col=15)
    second = _sink(start=10, end=10, start_col=5, end_col=20)
    finding = _finding(
        region={
            "startLine": 10,
            "startColumn": 7,
            "endLine": 10,
            "endColumn": 10,
        }
    )

    unit = reconcile_findings([finding], [first, second], {"a.js": "
" * 15})[0]

    assert unit["mapping_status"] == "unmapped"
    assert unit["sink_span"] is None
    assert unit["argument_role"] is None


def test_non_ascii_relevant_line_requires_review():
    sink = _sink(start=1, end=1, start_col=1, end_col=20)
    finding = _finding(
        region={
            "startLine": 1,
            "startColumn": 6,
            "endLine": 1,
            "endColumn": 12,
        }
    )

    unit = reconcile_findings([finding], [sink], {"a.js": "éxec(command)
"})[0]

    assert unit["mapping_status"] == "column_encoding_requires_review"
    assert unit["sink_span"] is None


def test_process_sink_without_role_evidence_is_role_unresolved():
    sink = _sink(kind="child_process.spawn")
    finding = _finding(region=dict(sink["span"]))

    unit = reconcile_findings([finding], [sink], {"a.js": "
" * 15})[0]

    assert unit["mapping_status"] == "role_unresolved"
    assert unit["argument_role"] is None
    assert unit["sink_span"] == sink["span"]


def test_missing_location_uses_raw_id_to_keep_fallbacks_distinct():
    first = _finding(raw_id="semgrep:0:0", path=None, region={})
    second = _finding(raw_id="semgrep:0:1", path=None, region={})

    units = reconcile_findings([first, second], [], {})

    assert len(units) == 2
    assert units[0]["unit_id"] != units[1]["unit_id"]
