"""Second review of a subset of the JavaScript labels by a person outside the project.

EVALUATION_PROTOCOL.md section 4 asks for an independent second review of every proposed
suppression and of a deterministic 20% sample of the other resolved units (sorted unit id,
every fifth unit). This script selects that subset, adds every unit labeled safe (the labels
false-positive counts rest on), writes a packet that shows only code, and scores the answers.

    python experiments/evaluation/js-labels-v0.3/second_review.py select
    python experiments/evaluation/js-labels-v0.3/second_review.py packet <out-dir> [--cache DIR]
    python experiments/evaluation/js-labels-v0.3/second_review.py score <answers.csv> [--json OUT]

`select` writes second-review/selection.json (unit ids in presentation order, nothing else).
`packet` downloads each package from npm (or reads the cache) and writes PACKET.md and
answers.csv; it only reads text from the archives. The packet names no tool, priority, filter
decision or existing label. `score` needs the reviewer's answers and prints agreement.
"""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import re
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SELECTION = HERE / "second-review" / "selection.json"
SALT = "security-triage/js-labels-v0.3/second-review/"
LABELS = ("vulnerable", "safe", "undetermined")
ANSWERS = {"co loi": "vulnerable", "an toan": "safe", "chua xac dinh": "undetermined"}
BEFORE, AFTER, WIDTH = 25, 8, 180
COMMAND_CALL = re.compile(r"\b(exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def choose(units):
    """Ids to review: every safe or filtered unit, and every fifth of the others by sorted id."""
    always = sorted(u["id"] for u in units if u["label"] == "safe" or u["filtered"])
    others = sorted(u["id"] for u in units if u["id"] not in set(always))
    sample = others[4::5]
    chosen = always + sample
    return sorted(chosen, key=lambda i: hashlib.sha256((SALT + i).encode()).hexdigest())


def select():
    units, _ = _load("score_labels").build_units()["all"]
    chosen = choose(units)
    record = {
        "rule": (
            "Every unit labeled safe or filtered, plus every fifth of the other units by sorted "
            "id; presented in the order of sha256(salt + id)."
        ),
        "salt": SALT,
        "units_total": len(units),
        "items": [{"number": n, "id": i} for n, i in enumerate(chosen, 1)],
    }
    SELECTION.parent.mkdir(exist_ok=True)
    SELECTION.write_bytes((json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode())
    return record


def cohen_kappa(pairs):
    """Observed agreement and Cohen's kappa for (first, second) label pairs."""
    total = len(pairs)
    if not total:
        return None, None
    observed = sum(1 for a, b in pairs if a == b) / total
    expected = sum(
        (sum(1 for a, _ in pairs if a == label) / total)
        * (sum(1 for _, b in pairs if b == label) / total)
        for label in LABELS
    )
    kappa = None if expected == 1 else round((observed - expected) / (1 - expected), 4)
    return round(observed, 4), kappa


def agreement(first, second):
    """Compare two {id: label} maps over the ids of `second`."""
    pairs = [(first[i], second[i]) for i in sorted(second)]
    observed, kappa = cohen_kappa(pairs)
    matrix = {a: {b: sum(1 for p in pairs if p == (a, b)) for b in LABELS} for a in LABELS}
    return {
        "units": len(pairs),
        "agreed": sum(1 for a, b in pairs if a == b),
        "observed_agreement": observed,
        "cohen_kappa": kappa,
        "first_by_second": matrix,
        "disagreements": [
            {"id": i, "first": first[i], "second": second[i]}
            for i in sorted(second)
            if first[i] != second[i]
        ],
    }


def score(answers_path):
    selection = json.loads(SELECTION.read_bytes())["items"]
    numbers = {item["number"]: item["id"] for item in selection}
    units, _ = _load("score_labels").build_units()["all"]
    by_id = {u["id"]: u for u in units}
    second, notes = {}, {}
    with answers_path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            answer = (row.get("nhan") or "").strip().lower()
            if not answer:
                continue
            unit = numbers[int(row["so"])]
            second[unit] = ANSWERS[answer]
            notes[unit] = (row.get("ghi_chu") or "").strip()
    first = {i: by_id[i]["label"] for i in second}
    result = {
        "selected": len(numbers),
        "answered": len(second),
        "all": agreement(first, second),
        "by_first_label_source": {
            source: agreement(first, {i: v for i, v in second.items() if by_id[i]["source"] == s})
            for source, s in (("known_cve_sites", "cve"), ("reviewed_labels", "assistant"))
        },
        "units_first_labeled_safe": agreement(
            first, {i: v for i, v in second.items() if first[i] == "safe"}
        ),
    }
    for row in result["all"]["disagreements"]:
        row["second_note"] = notes[row["id"]]
    return result


def _excerpt(lines, line):
    first, last = max(1, line - BEFORE), min(len(lines), line + AFTER)
    shown = []
    for number in range(first, last + 1):
        mark = ">>" if number == line else "  "
        shown.append(f"{mark} {number:5d} | {lines[number - 1].expandtabs(2)[:WIDTH]}")
    return shown


def _other_calls(lines, line):
    """Lines of the file that call a process-running function, for alerts not on a call."""
    shown = []
    for number, text in enumerate(lines, 1):
        if abs(number - line) > AFTER and COMMAND_CALL.search(text):
            shown.append(f"   {number:5d} | {text.strip()[:WIDTH]}")
    return shown[:12]


INSTRUCTIONS = """# Phiếu rà lần hai — ứng viên chèn lệnh (CWE-78) trong mã JavaScript/TypeScript

Bạn được nhờ đánh giá độc lập {count} vị trí mã trong các package npm công khai. Mỗi vị trí là
một dòng mã (đánh dấu `>>`). Xin **không** xem báo cáo, mã hay tài liệu của dự án đã tạo phiếu
này, và không trao đổi với người thực hiện dự án cho tới khi nộp phiếu. Bạn được đọc phần còn
lại của package (tải từ npm đúng tên và phiên bản ghi ở mỗi mục); không cần chạy mã.

## Câu hỏi cho mỗi vị trí

*Giá trị mà shell diễn giải ở lời gọi này có chứa dữ liệu do bên ngoài package kiểm soát mà
không được vô hiệu hóa không?* "Bên ngoài" gồm tham số của hàm mà package xuất ra cho người
dùng, tham số dòng lệnh, biến môi trường, nội dung tệp, dữ liệu mạng. Một thư viện ghép tham số
của hàm công khai vào chuỗi lệnh được coi là có lỗi.

Ba nhãn:

- `co loi`: thấy đường đi từ dữ liệu bên ngoài tới chuỗi lệnh (hoặc đối số được shell diễn
  giải) mà không có bước trích dẫn hay kiểm tra nào chặn ký tự đặc biệt của shell.
- `an toan`: chuỗi lệnh là hằng; hoặc chỉ ghép từ giá trị do package tự đặt; hoặc dữ liệu bên
  ngoài đã qua danh sách cho phép, ép kiểu số hay trích dẫn đúng; hoặc lời gọi không qua shell
  và tên chương trình không do bên ngoài kiểm soát.
- `chua xac dinh`: không quyết định được từ mã của package.

Quy tắc phụ:

- Khi phân vân, chọn `chua xac dinh`.
- Nếu dòng được đánh dấu không phải lời gọi chạy lệnh (ví dụ dòng `require`, hoặc một phép
  ghép chuỗi), hãy đánh giá theo các lời gọi chạy lệnh mà dòng đó dẫn tới trong cùng tệp; phiếu
  liệt kê các dòng như vậy dưới đoạn mã.
- Nhãn không nói lỗi có khai thác được trong một ứng dụng cụ thể hay không.

## Cách nộp

Điền tệp `answers.csv` kèm theo: cột `nhan` nhận `co loi`, `an toan` hoặc `chua xac dinh`; cột
`ghi_chu` ghi một câu lý do. Ghi thêm vào dòng đầu của thư trả lời: vai trò của bạn, ngày rà,
tổng thời gian, và xác nhận bạn không tham gia xây dựng hệ thống được đánh giá.
"""


def packet(output, cache):
    sheet = _load("label_sheet")
    items = json.loads(SELECTION.read_bytes())["items"]
    sources = {source["id"]: source for source in sheet.sources()}
    parts, texts = [INSTRUCTIONS.format(count=len(items))], {}
    for item in items:
        source_id, path, line = item["id"].split("|")
        source = sources[source_id]
        key = (source["package"], source["version"])
        if key not in texts:
            data = sheet.archive_bytes(*key, cache)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                texts[key] = {
                    member.name.split("/", 1)[1]: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile() and "/" in member.name and member.name.endswith(sheet.JS)
                }
        number = int(line.removeprefix("U"))
        lines = texts[key][path].decode("utf-8", "replace").splitlines()
        part = [
            f"## Mục {item['number']}",
            "",
            f"Package `{source['package']}` phiên bản `{source['version']}`, tệp `{path}`, "
            f"dòng {number}.",
            "",
            "```js",
            *_excerpt(lines, number),
            "```",
            "",
        ]
        if line.startswith("U"):
            calls = _other_calls(lines, number)
            if calls:
                part += ["Các dòng gọi hàm chạy tiến trình khác trong tệp:", "", "```js"]
                part += [*calls, "```", ""]
        parts.append("\n".join(part))
    output.mkdir(parents=True, exist_ok=True)
    (output / "PACKET.md").write_text("\n".join(parts), encoding="utf-8", newline="\n")
    with (output / "answers.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["so", "nhan", "ghi_chu"])
        writer.writerows([item["number"], "", ""] for item in items)
    return len(items)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("select", "packet", "score"))
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    if args.command == "select":
        record = select()
        print(f"selected {len(record['items'])} of {record['units_total']} units")
    elif args.command == "packet":
        print(f"wrote {packet(args.path, args.cache)} items to {args.path}")
    else:
        result = score(args.path)
        if args.json:
            data = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
            args.json.write_bytes(data.encode())
        everything = result["all"]
        print(f"answered {result['answered']} of {result['selected']}")
        print(
            f"agreed {everything['agreed']}/{everything['units']}, "
            f"kappa {everything['cohen_kappa']}"
        )
        for row in everything["disagreements"]:
            print("  ", row["id"], row["first"], "->", row["second"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
