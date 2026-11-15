"""Build the labeling sheet for the JavaScript candidates of the v0.3 exports.

One item per candidate in a JavaScript or TypeScript file of the 84 npm sources that is not a
known vulnerable site: package, file, line and the code around that line. The sheet leaves out
which tools reported the candidate, its priority and whether it was filtered.

    python experiments/evaluation/js-labels-v0.3/label_sheet.py items
    python experiments/evaluation/js-labels-v0.3/label_sheet.py sheet <out.md> [--cache DIR]
    python experiments/evaluation/js-labels-v0.3/label_sheet.py review <out.md> [--cache DIR]

`items` prints the count and needs no network. `sheet` and `review` download each package from
npm (or read it from the cache folder) and only read text from the archive; nothing is run.
`review` adds the label, class and reason of labels.json under each item, for the person who
checks the labels.
"""

import argparse
import importlib.util
import io
import json
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MATCHING = HERE.parent / "js-matching-v0.3"
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
BEFORE, AFTER, WIDTH = 30, 8, 220


def _compare():
    spec = importlib.util.spec_from_file_location("js_matching_compare", MATCHING / "compare.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sources():
    return json.loads((MATCHING / "sources.json").read_bytes())["sources"]


def javascript_candidates(source):
    report = json.loads((MATCHING / "inputs" / source["id"] / "report.json").read_bytes())
    return [c for c in report["candidates"] if c["path"].endswith(JS)]


def item_id(source, candidate):
    return f"{source['id']}|{candidate['path']}|{candidate['start_line']}"


def items():
    """Candidates to label: every JavaScript candidate outside the known vulnerable sites."""
    known = _compare().known_sites()
    rows = {}
    for source in sources():
        sites = set(known.get(f"{source['package']}@{source['version']}", []))
        for candidate in javascript_candidates(source):
            if (candidate["path"], candidate["start_line"]) in sites:
                continue
            # Two candidates that start on one line of one file are one item.
            rows.setdefault(
                item_id(source, candidate),
                {
                    "id": item_id(source, candidate),
                    "package": source["package"],
                    "version": source["version"],
                    "path": candidate["path"],
                    "line": candidate["start_line"],
                },
            )
    return list(rows.values())


def archive_bytes(package, version, cache):
    name = f"{package.replace('/', '__')}@{version}.tgz"
    if cache and (cache / name).exists():
        return (cache / name).read_bytes()
    with urllib.request.urlopen(
        f"https://registry.npmjs.org/{package}/{version}", timeout=60
    ) as response:
        tarball = json.load(response)["dist"]["tarball"]
    with urllib.request.urlopen(tarball, timeout=120) as response:
        data = response.read()
    if cache:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / name).write_bytes(data)
    return data


def excerpt(text, line):
    lines = text.splitlines()
    if line is None:
        # An alert on the file as a whole: show its beginning.
        first, last = 1, min(len(lines), BEFORE + AFTER)
    else:
        first, last = max(1, line - BEFORE), min(len(lines), line + AFTER)
    shown = []
    for number in range(first, last + 1):
        mark = ">>" if number == line else "  "
        shown.append(f"{mark} {number:5d} | {lines[number - 1][:WIDTH]}")
    return "\n".join(shown)


def render(rows, cache, labels=None):
    parts, texts = [], {}
    for row in rows:
        key = (row["package"], row["version"])
        if key not in texts:
            data = archive_bytes(*key, cache)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                texts[key] = {
                    member.name.split("/", 1)[1]: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile() and "/" in member.name and member.name.endswith(JS)
                }
        raw = texts[key].get(row["path"])
        code = excerpt(raw.decode("utf-8", "replace"), row["line"]) if raw else "(file not found)"
        part = [f"## {row['id']}", "", "```", code, "```", ""]
        if labels is not None:
            label = labels.get(row["id"], {})
            part += [
                f"- Label: **{label.get('label', 'MISSING')}**"
                + (f" ({label['class']})" if label.get("class") else ""),
                f"- Reason: {label.get('reason', '')}",
                "- Reviewer: [ ] agree  [ ] change to: ____",
                "",
            ]
        parts.append("\n".join(part))
    return "\n".join(parts)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("items", "sheet", "review"))
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args(argv)
    rows = items()
    if args.command == "items":
        print(f"items {len(rows)} in {len({(r['package'], r['version']) for r in rows})} packages")
        return 0
    labels = None
    if args.command == "review":
        labels = {
            label["id"]: label
            for label in json.loads((HERE / "labels.json").read_bytes())["labels"]
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(rows, args.cache, labels), encoding="utf-8", newline="\n")
    print(f"wrote {len(rows)} items to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
