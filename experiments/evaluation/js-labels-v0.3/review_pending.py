"""Write one Markdown file with the labels that no person has reviewed yet.

For each label whose `review` is null: the code around the line, the label and the reason, and a
line for the reviewer's decision. Items are grouped by package.

    python experiments/evaluation/js-labels-v0.3/review_pending.py <out.md> [--cache DIR]

Downloads each package from npm (or reads it from the cache folder) and only reads text from
the archive; nothing is run.
"""

import argparse
import importlib.util
import io
import json
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEFORE, AFTER, WIDTH = 10, 3, 150
NAMES = {"vulnerable": "có lỗi", "safe": "an toàn", "undetermined": "chưa xác định"}


def _sheet():
    spec = importlib.util.spec_from_file_location("label_sheet", HERE / "label_sheet.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def excerpt(text, line):
    lines = text.splitlines()
    first = 1 if line is None else max(1, line - BEFORE)
    last = min(len(lines), (BEFORE + AFTER) if line is None else line + AFTER)
    shown = []
    for number in range(first, last + 1):
        mark = ">>" if number == line else "  "
        shown.append(f"{mark} {number:4d} | {lines[number - 1].expandtabs(2)[:WIDTH]}")
    return "\n".join(shown)


def render(cache):
    sheet = _sheet()
    labels = {row["id"]: row for row in json.loads((HERE / "labels.json").read_bytes())["labels"]}
    pending = [item for item in sheet.items() if labels[item["id"]].get("review") is None]
    parts = [
        f"# Nhãn JavaScript chưa được người kiểm: {len(pending)} ca",
        "",
        "Mỗi ca có đoạn mã quanh dòng được báo (dòng đánh dấu `>>`), nhãn do trợ lý AI gán",
        "và lý do. Đánh dấu vào dòng **Quyết định** của từng ca. Khi xong, báo lại số thứ tự",
        'các ca cần sửa kèm nhãn mới (hoặc "đồng ý hết"); khi đó các ca này mới được ghi là',
        "đã có người kiểm.",
        "",
        "Tiêu chí: `experiments/evaluation/js-labels-v0.3/PROTOCOL.md`, mục 5.",
        "",
    ]
    texts, package = {}, None
    for number, item in enumerate(pending, 1):
        key = (item["package"], item["version"])
        if key != package:
            package = key
            parts += [f"## {item['package']} {item['version']}", ""]
        if key not in texts:
            data = sheet.archive_bytes(*key, cache)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                texts[key] = {
                    member.name.split("/", 1)[1]: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile() and "/" in member.name and member.name.endswith(sheet.JS)
                }
        raw = texts[key].get(item["path"])
        code = excerpt(raw.decode("utf-8", "replace"), item["line"]) if raw else "(không thấy tệp)"
        label = labels[item["id"]]
        where = f"{item['path']}:{item['line']}" if item["line"] else f"{item['path']} (cả tệp)"
        parts += [
            f"### {number}. `{where}`",
            "",
            "```js",
            code,
            "```",
            "",
            f"- Nhãn: **{NAMES[label['label']]}**. Lý do: {label['reason']}",
            "- Quyết định: [ ] đồng ý   [ ] sửa thành: ________   Ghi chú: ",
            "",
        ]
    return "\n".join(parts), len(pending)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args(argv)
    text, count = render(args.cache)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {count} items to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
