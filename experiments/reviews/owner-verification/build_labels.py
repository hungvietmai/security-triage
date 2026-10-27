"""Turn the owner's verification worksheet into label files.

Reads PHIEU_XAC_MINH.md, checks each group's ticked decision against DECISIONS and copies
the owner's note verbatim. Writes wave-c.labels.json (evaluator format), wave-b.labels.json
and session.json next to this script. Nothing is inferred beyond the worksheet.

Usage (repository root): python experiments/reviews/owner-verification/build_labels.py
"""

import csv
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WORKSHEET = HERE / "PHIEU_XAC_MINH.md"
LOCKED_B = ROOT / "experiments/wave-b/results/wave_b_labels.csv"

REVIEWER = "Hùng"
STARTED_AT = "2026-10-28T21:00:00+07:00"
REVIEWED_AT = "2026-10-29T00:40:00+07:00"
ACTIVE_MINUTES = 180
MODE = "owner_verified_assistant_proposal"

# group: (ticked option text, technical_label, conditional)
DECISIONS = {
    1: ("Theo P1", "false_positive", False),
    2: ("Đồng ý", "false_positive", True),
    3: ("Theo P1", "false_positive", False),
    4: ("Đổi thành: FP có điều kiện", "false_positive", True),
    5: ("Khác: FP (sai loại CWE)", "false_positive", False),
    6: ("Theo P1", "false_positive", False),
    7: ("Đổi thành: FP có điều kiện", "false_positive", True),
    8: ("Đồng ý", "false_positive", True),
    9: ("Đồng ý", "true_positive", False),
    10: ("TP có điều kiện", "true_positive_conditional", True),
    11: ("Đồng ý", "false_positive", True),
}
POLICY = {"P1": "a. Không tính là lỗ hổng CWE-22", "P2": "Có (ghi vào điều kiện của nhãn FP)"}

WAVE_C = {  # unit_id: (group, root_cause_id)
    "8dcaf01d7907a8adda39bd13": (1, "C-PC-NORMALIZATION"),
    "5859e664e867d805eef70b8c": (2, "C-PC-DOWNLOAD-CONTAINMENT"),
    "c295eacf017f952ad64f5391": (2, "C-PC-DOWNLOAD-CONTAINMENT"),
    "b99a22ccccd631527dd62004": (3, "C-AA-NORMALIZATION"),
    "29973e5cc3b0b49c809a4873": (4, "C-AA-CALLER-CONTAINMENT"),
    "1d3c60e0364a3a006fa676d3": (4, "C-AA-CALLER-CONTAINMENT"),
    "788be445943d8a953ce5a232": (4, "C-AA-CALLER-CONTAINMENT"),
    "0f3b3e4c8adbc208a0ca43bd": (4, "C-AA-CALLER-CONTAINMENT"),
}
WAVE_B_GROUP = {
    "RC-M4": 5,
    "RC-M5": 6,
    "RC-M7": 7,
    "RC-C1": 8,
    "RC-C2": 9,
    "RC-D1": 10,
    "RC-D2": 11,
}
A_SYM_GROUPS = {2, 4, 11}
ASSUMPTIONS = ("A-SYM", "S-ENV", "S-PURPOSE", "S-TEST", "S-TMP")


def parse_worksheet(text: str) -> tuple[dict[int, str], dict[int, str]]:
    sections = re.split(r"^### Nhóm (\d+)\b.*$", text, flags=re.M)
    ticked, notes = {}, {}
    for number, body in zip(sections[1::2], sections[2::2], strict=True):
        decision = body[body.index("Quyết định:") :].split("\n---")[0]
        before, _, note = decision.partition("Ghi chú:")
        options = re.findall(r"\[x\]\s*([^\[]+?)\s*(?=\[|$)", before.replace("\n", " "))
        if len(options) != 1:
            raise SystemExit(f"Group {number}: expected one ticked decision, found {options}")
        ticked[int(number)] = options[0].strip()
        notes[int(number)] = " ".join(note.split())
        unchecked = re.findall(r"^- \[ \] (.+)$", body, flags=re.M)
        if unchecked:
            raise SystemExit(f"Group {number}: unchecked facts {unchecked}")
    return ticked, notes


def check_policy(text: str) -> None:
    for name, option in POLICY.items():
        if f"- [x] {option}" not in text:
            raise SystemExit(f"{name}: expected ticked option {option!r}")


def assumptions(group: int) -> dict:
    records = {a: {"status": "unknown", "evidence": None} for a in ASSUMPTIONS}
    if group in A_SYM_GROUPS:
        records["A-SYM"] = {
            "status": "supported",
            "evidence": "Owner accepted threat-model assumption P2: the attacker only sends "
            "requests and cannot create files or symlinks on the server.",
        }
    return records


def main() -> None:
    text = WORKSHEET.read_text(encoding="utf-8")
    check_policy(text)
    ticked, notes = parse_worksheet(text)
    for group, (option, _, _) in DECISIONS.items():
        if ticked.get(group) != option:
            found = ticked.get(group)
            raise SystemExit(f"Group {group}: worksheet ticks {found!r}, not {option!r}")

    review = {
        "review_status": "owner_reviewed",
        "review_mode": MODE,
        "reviewer": REVIEWER,
        "reviewed_at": REVIEWED_AT,
    }
    wave_c = []
    for unit_id, (group, root_cause) in WAVE_C.items():
        _, label, conditional = DECISIONS[group]
        wave_c.append(
            {
                "unit_id": unit_id,
                "technical_label": label,
                "label_is_conditional": conditional,
                "scope": "production",
                "root_cause_id": root_cause,
                **review,
                "all_reported_flows_reviewed": False,
                "assumptions": assumptions(group),
                "worksheet_group": group,
                "label_evidence": notes[group],
            }
        )

    with LOCKED_B.open(encoding="utf-8", newline="") as handle:
        pending = [r for r in csv.DictReader(handle) if "pending" in r["review_status"]]
    wave_b = []
    for row in pending:
        group = WAVE_B_GROUP[row["root_cause_id"]]
        _, label, conditional = DECISIONS[group]
        wave_b.append(
            {
                "sink_location": row["sink_location"],
                "repository": row["repository"],
                "cwe": row["cwe"],
                "function": row["function"],
                "scope": row["scope"],
                "root_cause_id": row["root_cause_id"],
                "technical_label": label,
                "label_is_conditional": conditional,
                **review,
                "all_reported_flows_reviewed": False,
                "worksheet_group": group,
                "label_evidence": notes[group],
                "prior_manual_label": row["manual_label"],
                "v02_decision_from_locked_record": row["v02_decision"],
            }
        )
    if len(wave_b) != 17:
        raise SystemExit(f"Expected 17 pending wave B alerts, found {len(wave_b)}")

    session = {
        "reviewer": REVIEWER,
        "review_mode": MODE,
        "started_at": STARTED_AT,
        "finished_at": REVIEWED_AT,
        "active_review_minutes": ACTIVE_MINUTES,
        "blind": False,
        "policy": {"P1": "a", "P2": "yes", "P3": None},
        "note": "Owner verified each fact cited by the assistant pass of 2026-10-27 against "
        "source at the reviewed commits, then accepted or changed the proposed label. "
        "Not a blind review and not an independent second reviewer.",
    }
    for name, value in (
        ("wave-c.labels.json", wave_c),
        ("wave-b.labels.json", wave_b),
        ("session.json", session),
    ):
        # LF matches .gitattributes, so the evaluator's labels_sha256 matches the committed file.
        (HERE / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    print(f"wave C: {len(wave_c)} labels; wave B: {len(wave_b)} labels")


if __name__ == "__main__":
    main()
