"""Post-hoc lexical/AST evidence from the two locked archives, without executing them."""

import ast
import argparse
import datetime
import hashlib
import json
import pathlib
import tarfile
import time

ROOT = pathlib.Path.cwd().resolve()
SYMBOLS = {
    "_resolve_download_path", "_setup_webrtc_routes", "_configure_server_app",
    "_serve_file", "_serve_file_contained", "_serve_under_dashboard", "do_GET",
    "safe_resolve_under", "get_agents_root", "DashboardHandler", "agents_root",
    "folder", "cli_args", "RUNNER_DOWNLOADS_FOLDER", "ATOMIC_AGENTS_ROOT",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Occurrences(ast.NodeVisitor):
    def __init__(self):
        self.scope = []
        self.rows = []

    def record(self, node, symbol, detail):
        self.rows.append({"line": node.lineno, "column": node.col_offset + 1,
                          "symbol": symbol, "node_type": type(node).__name__,
                          "scope": ".".join(self.scope), "detail": detail})

    def definition(self, node):
        if node.name in SYMBOLS:
            self.record(node, node.name, "definition")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = definition
    visit_AsyncFunctionDef = definition
    visit_ClassDef = definition

    def visit_Name(self, node):
        if node.id in SYMBOLS:
            self.record(node, node.id, type(node.ctx).__name__)

    def visit_Attribute(self, node):
        if node.attr in SYMBOLS:
            self.record(node, node.attr, ast.unparse(node))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name in SYMBOLS:
                self.record(node, alias.name, {"module": node.module, "asname": alias.asname})


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts/wave-c/source-audit-001")
    args = parser.parse_args()
    relative = pathlib.PurePosixPath(args.output)
    if relative.is_absolute() or ".." in relative.parts or "\\" in args.output:
        parser.error("Output must be workspace-relative")
    OUTPUT = ROOT.joinpath(*relative.parts)
    if not OUTPUT.resolve().is_relative_to(ROOT):
        parser.error("Output escapes workspace")
    if not (ROOT / "experiments/wave-c/sources.lock.json").is_file():
        parser.error("Run from the repository root")
    OUTPUT.mkdir(parents=True, exist_ok=False)
    sources = json.loads((ROOT / "experiments/wave-c/sources.lock.json").read_bytes())
    exclusions = json.loads((ROOT / "experiments/wave-c/exclusions.json").read_bytes())
    excluded = {r["repository"].lower() for r in exclusions["repositories"]}
    ancestry, audited = [], []
    for source in sources["records"]:
        if source["status"] != "prepared":
            continue
        metadata_object = source["objects"]["repository_metadata"]
        raw_metadata = (ROOT / metadata_object["path"]).read_bytes()
        assert digest(raw_metadata) == metadata_object["sha256"]
        metadata = json.loads(raw_metadata)
        identities = {
            metadata.get("full_name", "").lower(),
            metadata.get("parent", {}).get("full_name", "").lower(),
            metadata.get("source", {}).get("full_name", "").lower(),
        } - {""}
        ancestry.append({"rank": source["rank"], "repository": source["repository"],
                         "canonical": metadata.get("full_name"), "fork": metadata.get("fork"),
                         "parent": metadata.get("parent", {}).get("full_name"),
                         "source": metadata.get("source", {}).get("full_name"),
                         "excluded_identity_matches": sorted(identities & excluded),
                         "metadata_sha256": metadata_object["sha256"]})
        if source["rank"] not in (3, 8):
            continue
        archive = ROOT / source["objects"]["archive"]["path"]
        assert digest(archive.read_bytes()) == source["objects"]["archive"]["sha256"]
        files, errors, occurrences, differences = [], [], [], []
        with tarfile.open(archive) as stream:
            for member in stream:
                if not member.isfile() or not member.name.endswith(".py"):
                    continue
                relative = pathlib.PurePosixPath(member.name).relative_to(source["archive_root"])
                data = stream.extractfile(member).read()
                extracted = (ROOT / "artifacts/wave-c/study-001" / f"{source['rank']:02d}"
                             / "extracted" / source["archive_root"] / relative)
                if not extracted.exists() or extracted.read_bytes() != data:
                    differences.append(relative.as_posix())
                files.append({"file": relative.as_posix(), "sha256": digest(data), "bytes": len(data)})
                try:
                    tree = ast.parse(data, filename=relative.as_posix())
                except (SyntaxError, ValueError) as error:
                    errors.append({"file": relative.as_posix(), "error": str(error)})
                    continue
                visitor = Occurrences()
                visitor.visit(tree)
                occurrences.extend({"file": relative.as_posix(), **row} for row in visitor.rows)
        assert not differences, "Extracted source differs from locked archive"
        assert len(files) == len(source["archive_inventory"]["python_files"])
        audited.append({"rank": source["rank"], "repository": source["repository"],
                        "commit": source["commit"], "archive_sha256": source["objects"]["archive"]["sha256"],
                        "files": sorted(files, key=lambda r: r["file"]),
                        "parse_errors": errors, "extracted_source_mismatches": differences,
                        "symbol_occurrences": sorted(occurrences, key=lambda r: (r["file"], r["line"], r["column"]))})
    result = {
        "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "wall_seconds": time.monotonic() - started,
        "classification": "Post-hoc source-informed audit; not an independent reviewer or a change to frozen rules",
        "source_executed": False, "scanner_executed": False,
        "audited_repositories": audited, "repository_metadata_screen": ancestry,
        "limits": ["Name/attribute occurrences are candidates, not resolved interprocedural paths",
                   "Dynamic imports, monkeypatches and external bot code are not resolved",
                   "No historical held-out source was opened or scanned",
                   "Metadata and exact-byte checks do not establish semantic independence"],
        "human_review_confirmed": False,
    }
    with (OUTPUT / "source_audit.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"repositories": [{"repository": r["repository"], "files": len(r["files"]),
                                       "parse_errors": len(r["parse_errors"]), "occurrences": len(r["symbol_occurrences"])}
                                      for r in audited], "metadata_repositories": len(ancestry),
                      "source_executed": False}, indent=2))


if __name__ == "__main__":
    main()
