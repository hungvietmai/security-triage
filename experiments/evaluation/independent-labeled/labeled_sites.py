"""Before/after comparison on sites labeled vulnerable or safe, from one exported report.

Each labeled site is one line of one file. A configuration reports a site when one of its
candidates is in that file and starts on that line. With both kinds of label this gives true
and false positives, misses and true negatives, hence precision, recall and F1, for Semgrep
alone, CodeQL alone, the unions and the list after filtering, on the same scan.

    python experiments/evaluation/independent-labeled/labeled_sites.py \
        <labels.json> <report.json> [--json OUT]
"""

import argparse
import json
from pathlib import Path

DETECTORS = ("semgrep", "codeql", "bandit", "eslint")
FIRST_TIERS = {"P1", "P2"}
# Filter rules whose evidence comes from an open-source tool (Semgrep CE, Bandit).
OPEN_SOURCE_RULES = {"G3_SEMGREP_DEAD_BRANCH", "G2_LITERAL_COMMAND"}


def _rules(candidate):
    return set(candidate.get("filter_rules") or [])


def _configurations():
    def tools(*names):
        wanted = set(names)
        return lambda c: bool(wanted & set(c["tools"]))

    def kept(c):
        return c["disposition"] != "filtered"

    return {
        "semgrep": tools("semgrep"),
        "codeql": tools("codeql"),
        "bandit": tools("bandit"),
        "eslint": tools("eslint"),
        "semgrep ∪ codeql": tools("semgrep", "codeql"),
        "all sources": lambda c: True,
        "all sources, open-source filter": lambda c: kept(c) or not (_rules(c) & OPEN_SOURCE_RULES),
        "all sources, filtered": kept,
        "first tiers (P1+P2), filtered": lambda c: kept(c) and c["priority"] in FIRST_TIERS,
    }


def _ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def score(sites, found, member):
    """Counts and rates of one configuration over labeled sites."""
    tp = fp = fn = tn = 0
    for site in sites:
        reported = any(member(c) for c in found[(site["path"], site["line"])])
        if site["label"] == "vulnerable":
            tp, fn = tp + reported, fn + (not reported)
        else:
            fp, tn = fp + reported, tn + (not reported)
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = round(2 * precision * recall / (precision + recall), 4)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def filter_effect(sites, found):
    """What filtering removed, by label, and what it only moved down."""
    effect = {
        "filtered": {"vulnerable": 0, "safe": 0},
        "filtered_by_rule": {},
        "demoted_p3_p4": {"vulnerable": 0, "safe": 0},
        "filtered_sites": [],
    }
    for site in sites:
        candidates = found[(site["path"], site["line"])]
        if not candidates:
            continue
        label = site["label"]
        if all(c["disposition"] == "filtered" for c in candidates):
            effect["filtered"][label] += 1
            rules = sorted({rule for c in candidates for rule in _rules(c)})
            for rule in rules:
                by_rule = effect["filtered_by_rule"].setdefault(rule, {"vulnerable": 0, "safe": 0})
                by_rule[label] += 1
            effect["filtered_sites"].append(
                {"path": site["path"], "line": site["line"], "label": label, "rules": rules}
            )
        elif all(
            c["priority"] in {"P3", "P4"} for c in candidates if c["disposition"] != "filtered"
        ):
            effect["demoted_p3_p4"][label] += 1
    return effect


def evaluate(labels, report):
    candidates = report["candidates"]
    found = {
        (site["path"], site["line"]): [
            c for c in candidates if c["path"] == site["path"] and c["start_line"] == site["line"]
        ]
        for site in labels["sites"]
    }
    labeled_keys = {c["candidate_key"] for group in found.values() for c in group}
    unlabeled = [c for c in candidates if c["candidate_key"] not in labeled_keys]
    subsets = {
        "all labeled sites": labels["sites"],
        "python": [s for s in labels["sites"] if s["language"] == "python"],
        "javascript": [s for s in labels["sites"] if s["language"] == "javascript"],
        # Tests of rules the profile itself runs score Semgrep on its own expectations.
        "tests of rules the profile does not run": [
            s for s in labels["sites"] if not s["profile_rule"]
        ],
        "python, tests of rules the profile does not run": [
            s for s in labels["sites"] if s["language"] == "python" and not s["profile_rule"]
        ],
    }
    result = {
        "source": report["snapshot"]["source_coordinate"],
        "snapshot_sha256": report["snapshot"]["sha256"],
        "scan_status": report["status"],
        "profile": report["profile"],
        "profile_sha256": report.get("profile_sha256"),
        "step_statuses": {
            f"{language}/{step}": record.get("status")
            for language, steps in (report.get("steps") or {}).items()
            for step, record in steps.items()
            if not step.endswith("-version")
        },
        "stages": report["stages"],
        "subsets": {},
        "unlabeled": {
            "total": len(unlabeled),
            "filtered": sum(1 for c in unlabeled if c["disposition"] == "filtered"),
        },
    }
    for name, sites in subsets.items():
        result["subsets"][name] = {
            "sites": {
                "vulnerable": sum(1 for s in sites if s["label"] == "vulnerable"),
                "safe": sum(1 for s in sites if s["label"] == "safe"),
            },
            "scores": {
                config: score(sites, found, member) for config, member in _configurations().items()
            },
            "filter_effect": filter_effect(sites, found),
        }
    return result


def markdown(result):
    lines = [
        f"Source: {result['source']}; scan {result['scan_status']}; stages {result['stages']}.",
        f"Steps not completed: "
        f"{ {k: v for k, v in result['step_statuses'].items() if v != 'completed'} }.",
        f"Unlabeled candidates: {result['unlabeled']}.",
    ]
    for name, block in result["subsets"].items():
        sites = block["sites"]
        lines += [
            "",
            f"### {name}: {sites['vulnerable']} vulnerable, {sites['safe']} safe",
            "",
            "| Configuration | TP | FP | FN | TN | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for config, s in block["scores"].items():
            rates = " | ".join(
                "—" if s[key] is None else f"{s[key]:.2f}" for key in ("precision", "recall", "f1")
            )
            lines.append(f"| {config} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | {rates} |")
        effect = block["filter_effect"]
        lines.append("")
        lines.append(
            f"Filtered: {effect['filtered']}; by rule: {effect['filtered_by_rule']}; "
            f"only demoted to P3/P4: {effect['demoted_p3_p4']}."
        )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("labels", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = evaluate(json.loads(args.labels.read_bytes()), json.loads(args.report.read_bytes()))
    if args.json:
        args.json.write_bytes((json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode())
    print(markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
