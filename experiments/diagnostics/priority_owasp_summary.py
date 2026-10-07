"""Descriptive development-only priority distribution for reviewed OWASP cases."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    reviewed = json.loads(
        (root / "experiments/reports/owasp-python-development/summary.json").read_text()
    )
    labels = {case["path"]: case["technical_verdict"] for case in reviewed["units"]}
    units = json.loads((args.run_directory / "units.json").read_text())
    assessments = json.loads((args.run_directory / "assessments.json").read_text())
    findings = json.loads((args.run_directory / "findings.json").read_text())
    if len(units) != len(assessments):
        raise ValueError("Assessment conservation failed")
    counts = defaultdict(Counter)
    unlabeled = Counter()
    for unit, assessment in zip(units, assessments, strict=True):
        if unit["unit_id"] != assessment["unit_id"]:
            raise ValueError("Assessment order/identity mismatch")
        label = labels.get(unit["path"])
        if label in {"true_positive", "false_positive"}:
            counts[label][assessment["tier"]] += 1
        else:
            unlabeled[assessment["tier"]] += 1
    claim_unresolved = sum(
        all(
            item["claim_family"] == "classification_unresolved"
            for item in assessment["finding_evidence"]
        )
        for unit, assessment in zip(units, assessments, strict=True)
        if unit["path"] and unit["path"].endswith(".py")
    )
    result = {
        "raw_findings": len(findings),
        "units": len(units),
        "reviewed_by_tier": {k: dict(v) for k, v in counts.items()},
        "unlabeled_by_tier": dict(unlabeled),
        "all_python_claims_unresolved_units": claim_unresolved,
        "note": "Development diagnostics only; single unblinded review is not independent ground truth.",
    }
    (args.run_directory / "priority-owasp-summary.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result, sort_keys=True))
    if claim_unresolved:
        raise ValueError("Python rule-claims missing for at least one unit")


if __name__ == "__main__":
    main()
