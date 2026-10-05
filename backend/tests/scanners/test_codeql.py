import json

from app.scanners.codeql import query_pack_for_language, run_codeql
from app.scanners.provenance import digest


def test_query_pack_selection_requires_explicit_path(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    assert (
        query_pack_for_language(
            "javascript", javascript_query_pack=pack, python_query_pack=None
        )
        == pack.resolve()
    )

    try:
        query_pack_for_language(
            "python", javascript_query_pack=pack, python_query_pack=None
        )
    except ValueError as exc:
        assert "--python-query-pack" in str(exc)
    else:
        raise AssertionError("missing query pack was accepted")


def test_run_codeql_preserves_cli_arguments(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    pack = tmp_path / "pack"
    query = pack / "Security/CWE-078/CommandInjection.ql"
    query.parent.mkdir(parents=True)
    query.write_text("select 1\n")
    (pack / "qlpack.yml").write_text("name: codeql/javascript-queries\n")

    commands = []

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None):
        commands.append((name, [str(item) for item in argv]))
        assert cwd == source
        assert output_dir == output
        assert timeout == 600
        if name == "codeql":
            (output / "codeql.sarif").write_text(
                json.dumps({"version": "2.1.0", "runs": []})
            )
        return {
            "argv": [str(item) for item in argv],
            "status": "completed",
            "exit_code": 0,
            "seconds": 0.1,
        }

    result = run_codeql(
        binary="/tools/codeql",
        language="javascript",
        source=source,
        output=output,
        snapshot_sha256="b" * 64,
        query_pack=pack,
        queries=["Security/CWE-078/CommandInjection.ql"],
        expected_query_sha256={
            "Security/CWE-078/CommandInjection.ql": digest(query)
        },
        jobs=1,
        ram_mb=2048,
        timeout_seconds=600,
        invoke_fn=fake_invoke,
    )

    assert commands == [
        (
            "codeql-create",
            [
                "/tools/codeql",
                "database",
                "create",
                str(output / "codeql-db"),
                "--language=javascript",
                "--source-root",
                str(source),
                "--build-mode=none",
                "--threads",
                "1",
                "--ram=2048",
            ],
        ),
        (
            "codeql",
            [
                "/tools/codeql",
                "database",
                "analyze",
                str(output / "codeql-db"),
                str(query),
                "--format=sarif-latest",
                "--output",
                str(output / "codeql.sarif"),
                "--threads",
                "1",
                "--ram=2048",
            ],
        ),
    ]
    assert result.analyze_record["raw_findings"] == 0
    assert result.findings == []
    assert result.complete is True
    assert result.query_files == {
        "Security/CWE-078/CommandInjection.ql": digest(query)
    }
