"""Before/after evaluation: scoring rules on a synthetic report and the committed results."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments" / "evaluation"))
import before_after  # noqa: E402
import summarize  # noqa: E402

sys.path.insert(0, str(ROOT / "experiments" / "evaluation" / "independent"))
import known_sites  # noqa: E402

sys.path.insert(0, str(ROOT / "experiments" / "evaluation" / "independent-secbench"))
import build_labels  # noqa: E402
import configurations  # noqa: E402
import posthoc_missed  # noqa: E402

sys.path.insert(0, str(ROOT / "experiments" / "evaluation" / "pairs-v1"))
import importlib.util  # noqa: E402

import pair_labels  # noqa: E402


def _load(name, path):
    """Import a script by path; two evaluation folders both have a build_labels.py."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LABELED = ROOT / "experiments" / "evaluation" / "independent-labeled"
labeled_sites = _load("labeled_sites", LABELED / "labeled_sites.py")
rule_test_labels = _load("rule_test_labels", LABELED / "build_labels.py")
FILTER = ROOT / "experiments" / "evaluation" / "independent-filter"
filtered_candidates = _load("filtered_candidates", FILTER / "filtered_candidates.py")
verify_filtered = _load("verify_filtered", FILTER / "verify_filtered.py")
PAIRS_KIT = ROOT / "experiments" / "evaluation" / "pairs-v1"
score_pairs = _load("score_pairs", PAIRS_KIT / "score_pairs.py")
freeze = _load("freeze", PAIRS_KIT / "freeze.py")
JS_MATCHING = ROOT / "experiments" / "evaluation" / "js-matching-v0.3"
js_compare = _load("js_compare", JS_MATCHING / "compare.py")
constant_reference = _load("constant_reference", JS_MATCHING / "constant_reference.py")
JS_LABELS = ROOT / "experiments" / "evaluation" / "js-labels-v0.3"
js_label_sheet = _load("js_label_sheet", JS_LABELS / "label_sheet.py")
js_label_score = _load("js_label_score", JS_LABELS / "score_labels.py")

EVALUATION = ROOT / "experiments" / "evaluation"
PIPELINE_CHANGES = json.loads((EVALUATION / "PIPELINE_CHANGES.json").read_bytes())[
    "changed_after_registered_scans"
]


def _assert_registered(case, relative, registered):
    """A registered file is unchanged, or it is pipeline code with a recorded change."""
    import hashlib

    actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    if actual == registered:
        return
    case.assertIn(relative, PIPELINE_CHANGES, f"{relative} changed without a record")
    case.assertEqual(PIPELINE_CHANGES[relative]["registered_sha256"], registered)
    # What defines a check (protocol, labels, scoring, exports) may never be on that list.
    case.assertFalse(relative.startswith("experiments/"))


def _candidate(path, tools, priority="P3", disposition="review", rule=None):
    return {
        "candidate_key": path,
        "path": path,
        "tools": tools,
        "priority": priority,
        "disposition": disposition,
        "filter_rule": rule,
    }


def _report(candidates):
    """A synthetic exported report; identifiers and timings are test data, not scan output."""
    return {
        "status": "completed",
        "profile": "synthetic",
        "snapshot": {"sha256": "0" * 64, "source_coordinate": "synthetic:test"},
        "tool_versions": {},
        "stages": {"candidates": len(candidates)},
        "sources": {},
        "steps": {
            "python": {
                "codeql": {"seconds": 10.0},
                "codeql-version": {"seconds": 1.0},
                "codeql-evidence": {"seconds": 2.5},
            },
            "javascript": {"codeql": {"seconds": 4.0}},
        },
        "candidates": candidates,
    }


LABELS = {"vuln_both.py": True, "vuln_codeql.py": True, "vuln_missed.py": True, "safe.py": False}


class BeforeAfterTests(unittest.TestCase):
    def setUp(self):
        self.candidates = [
            _candidate("vuln_both.py", ["codeql", "semgrep"], "P1"),
            _candidate("vuln_codeql.py", ["codeql"], "P2"),
            _candidate("safe.py", ["codeql", "semgrep"], "P1", "filtered", "G1"),
            _candidate("other.py", ["semgrep"]),
        ]
        self.result = before_after.evaluate(_report(self.candidates), LABELS)

    def test_each_configuration_is_scored_on_labeled_sites_only(self):
        scores = self.result["scores"]
        # The unlabeled candidate is counted, never scored as true or false.
        self.assertEqual(
            {k: scores["semgrep"][k] for k in ("tp", "fp", "fn", "unlabeled")},
            {"tp": 1, "fp": 1, "fn": 2, "unlabeled": 1},
        )
        self.assertEqual(scores["codeql"]["tp"], 2)
        union = scores["all sources"]
        self.assertEqual((union["tp"], union["fp"], union["fn"]), (2, 1, 1))
        self.assertEqual(union["precision"], round(2 / 3, 4))
        self.assertEqual(union["recall"], round(2 / 3, 4))

    def test_filtering_removes_only_filtered_candidates_and_reports_what_it_removed(self):
        after = self.result["scores"]["all sources, filtered"]
        self.assertEqual((after["tp"], after["fp"], after["fn"]), (2, 0, 1))
        effect = self.result["filter_effect"]
        self.assertEqual(effect["filtered"], {"true": 0, "false": 1, "unlabeled": 0})
        self.assertEqual(effect["filtered_by_rule"]["G1"]["false"], 1)
        # other.py stays in the main list at P3: demoted, not filtered.
        self.assertEqual(effect["demoted_p3_p4"], {"true": 0, "false": 0, "unlabeled": 1})

    def test_open_source_only_filter_counts_rules_backed_by_open_source_tools(self):
        # safe.py was filtered by the CodeQL rule alone: the open-source filter keeps it.
        only = self.result["scores"]["all sources, open-source filter"]
        self.assertEqual((only["tp"], only["fp"]), (2, 1))
        self.candidates[2]["filter_rules"] = ["G3_SEMGREP_DEAD_BRANCH", "G1"]
        result = before_after.evaluate(_report(self.candidates), LABELS)
        self.assertEqual(result["scores"]["all sources, open-source filter"]["fp"], 0)
        by_rule = result["filter_effect"]["filtered_by_rule"]
        self.assertEqual(by_rule["G3_SEMGREP_DEAD_BRANCH"]["false"], 1)
        self.assertEqual(by_rule["G1"]["false"], 1)

    def test_a_filtered_true_site_is_reported_as_a_loss(self):
        self.candidates[0]["disposition"] = "filtered"
        self.candidates[0]["filter_rule"] = "G1"
        result = before_after.evaluate(_report(self.candidates), LABELS)
        self.assertEqual(result["filter_effect"]["filtered"]["true"], 1)
        self.assertEqual(result["scores"]["all sources, filtered"]["fn"], 2)

    def test_step_seconds_sum_languages_and_skip_version_checks(self):
        self.assertEqual(self.result["step_seconds"], {"codeql": 14.0, "codeql-evidence": 2.5})

    def test_without_labels_only_counts_are_reported(self):
        result = before_after.evaluate(_report(self.candidates))
        self.assertNotIn("scores", result)
        self.assertEqual(result["candidates_per_configuration"]["all sources"], 4)
        self.assertIn("| all sources | 4 |", before_after.markdown(result))

    def test_no_reported_site_gives_undefined_precision_not_zero(self):
        empty = before_after.score([], LABELS)
        self.assertIsNone(empty["precision"])
        self.assertEqual(empty["recall"], 0.0)


class CommittedResultsTests(unittest.TestCase):
    def test_committed_results_are_reproduced_from_the_committed_reports(self):
        labels = before_after.load_labels(
            ROOT / "experiments" / "labels" / "owasp-python-cwe78-expectations.json"
        )
        results = sorted((EVALUATION / "results").glob("*.json"))
        for result_file in (path for path in results if path.name != "summary.json"):
            with self.subTest(result=result_file.name):
                folder = EVALUATION / "inputs" / result_file.stem
                report = json.loads((folder / "report.json").read_bytes())
                expected = json.loads(result_file.read_bytes())
                use_labels = labels if "scores" in expected else None
                self.assertEqual(before_after.evaluate(report, use_labels), expected)

    def test_committed_summary_is_reproduced_from_the_committed_reports(self):
        expected = json.loads((EVALUATION / "results" / "summary.json").read_bytes())
        self.assertEqual(summarize.summarize(EVALUATION / "inputs"), expected)

    def test_every_saved_report_matches_its_manifest(self):
        import hashlib

        folders = sorted(path for path in (EVALUATION / "inputs").iterdir() if path.is_dir())
        self.assertTrue(folders)
        for folder in folders:
            with self.subTest(folder=folder.name):
                manifest = json.loads((folder / "manifest.json").read_bytes())
                for name, sha256 in manifest["files"].items():
                    actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, sha256)


class KnownSitesTests(unittest.TestCase):
    """Positives-only scoring against documented vulnerable sites."""

    SOURCE = {
        "id": "app",
        "sites": [
            {"path": "a.py", "line": 10, "basis": "documented_with_code"},
            {"path": "b.py", "line": 20, "basis": "documented_with_code"},
            {"path": "c.py", "line": 30, "basis": "documented_with_code"},
        ],
    }

    def _score(self, candidates):
        report = _report(candidates)
        for candidate in candidates:
            candidate.setdefault("start_line", 1)
        return known_sites.score_source(self.SOURCE, report)

    def test_reported_missed_filtered_and_unlabeled_are_told_apart(self):
        kept = {**_candidate("a.py", ["codeql", "eslint"], "P1"), "start_line": 10}
        gone = {
            **_candidate("b.py", ["semgrep"], "P3", "filtered", "G3"),
            "start_line": 20,
            "filter_rules": ["G3"],
        }
        elsewhere = {
            **_candidate("a.py", ["bandit"], "P3"),
            "candidate_key": "a.py:99",
            "start_line": 99,
        }
        hidden = {
            **_candidate("d.py", ["bandit"], "P3", "filtered", "G2"),
            "start_line": 5,
            "filter_rules": ["G2"],
        }
        result = self._score([kept, gone, elsewhere, hidden])
        first, second, third = result["sites"]
        self.assertEqual(
            (first["reported"], first["priority"], first["filtered"]), (True, "P1", False)
        )
        self.assertTrue(first["in_first_tiers"])
        # A documented vulnerability that filtering removed is reported as filtered, not hidden.
        self.assertEqual((second["reported"], second["filtered"]), (True, True))
        self.assertEqual(second["filter_rules"], ["G3"])
        self.assertEqual((third["reported"], third["priority"]), (False, None))
        # The same file at another line is a different call: unlabeled, never scored.
        self.assertEqual(result["unlabeled"]["total"], 2)
        self.assertEqual(result["unlabeled"]["main_list_by_priority"]["P3"], 1)
        self.assertEqual([c["path"] for c in result["unlabeled"]["filtered"]], ["d.py"])

    def test_a_source_without_a_saved_report_stays_in_the_table_as_missing(self):
        result = known_sites.evaluate({"sources": [self.SOURCE]}, ROOT / "no-such-inputs")
        self.assertEqual(result["sources"][0]["scan_status"], "missing")
        self.assertEqual(
            result["summary"],
            {
                "documented_sites": 3,
                "reported": 0,
                "in_first_tiers": 0,
                "filtered": 0,
                "missed": 3,
            },
        )

    def test_committed_independent_result_is_reproduced_and_matches_its_preregistration(self):
        import hashlib

        folder = EVALUATION / "independent"
        labels = json.loads((folder / "labels.json").read_bytes())
        expected = json.loads((folder / "results" / "known-sites.json").read_bytes())
        self.assertEqual(known_sites.evaluate(labels, folder / "inputs"), expected)
        # The protocol, labels and scoring script are the bytes hashed before the scans.
        record = json.loads((folder / "PREREGISTRATION.json").read_bytes())
        for name in ("PROTOCOL.md", "labels.json", "known_sites.py"):
            relative = f"experiments/evaluation/independent/{name}"
            with self.subTest(file=name):
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, record["sha256"][relative])


class ConfigurationsTests(unittest.TestCase):
    """Coverage of documented sites per configuration, on synthetic reports."""

    def _inputs(self, folder, reports):
        for name, report in reports.items():
            (folder / name).mkdir()
            (folder / name / "report.json").write_text(json.dumps(report), encoding="utf-8")

    def _source(self, name):
        site = {"path": "index.js", "line": 7, "basis": "dataset_published_sink"}
        return {"id": name, "sites": [site]}

    def _hit(self, tools, priority="P1", disposition="review", line=7):
        candidate = _candidate("index.js", tools, priority, disposition)
        return {**candidate, "candidate_key": f"index.js:{line}", "start_line": line}

    def test_each_configuration_counts_the_sites_its_tools_report(self):
        import tempfile

        reports = {
            "both": _report([self._hit(["codeql", "eslint", "semgrep"])]),
            "codeql": _report([self._hit(["codeql"], "P2")]),
            "eslint": _report([self._hit(["eslint"], "P3")]),
            "gone": _report([self._hit(["semgrep"], "P3", "filtered")]),
            # A call one line away is not the documented site.
            "near": _report([self._hit(["codeql"], line=8)]),
        }
        labels = {"sources": [self._source(name) for name in [*reports, "absent"]]}
        with tempfile.TemporaryDirectory() as folder:
            self._inputs(Path(folder), reports)
            result = configurations.evaluate(labels, folder)
        self.assertEqual(result["scan_statuses"], {"completed": 5, "missing": 1})
        block = result["configurations"]
        # The source that was never scanned has no place in the denominator.
        self.assertEqual(block["documented_sites_scanned"], 5)
        self.assertEqual(
            block["reported_by_configuration"],
            {
                "semgrep": 2,
                "codeql": 2,
                "eslint": 2,
                "semgrep ∪ codeql": 3,
                "all sources": 4,
                "all sources, after filtering": 3,
                "first tiers (P1+P2), after filtering": 2,
            },
        )
        self.assertEqual(block["lost_to_filtering"], 1)
        self.assertEqual(block["reported_by_one_tool_only"]["eslint"], 1)
        self.assertEqual(block["kept_sites_by_priority"]["P3"], 1)
        near = next(s for s in result["sources"] if s["id"] == "near")
        self.assertFalse(near["sites"][0]["reported"])
        self.assertEqual(near["sites"][0]["same_file_candidate_lines"], [8])
        self.assertEqual(result["unlabeled"]["total"], 1)

    def test_labels_are_built_from_the_published_fields_only(self):
        metadata = {
            "repository": "owner/dataset",
            "commit": "c0ffee",
            "folder": "command-injection",
            "entries": [
                {"directory": "pkg_1.0.0", "dependencies": {"pkg": "1.0.0"}, "sink": "a.js:3:5"},
                {
                    "directory": "pkg-b_2.0.0-beta",
                    "dependencies": {"other": "2.0.0"},
                    "sink": "a.js:1:1",
                },
                {"directory": "pkg-c_1.0.0", "dependencies": {"pkg-c": "1.0.0"}, "sink": "n/a"},
            ],
        }
        labels = build_labels.build(metadata)
        self.assertEqual([s["id"] for s in labels["sources"]], ["pkg_1.0.0"])
        source = labels["sources"][0]
        self.assertEqual((source["package"], source["version"]), ("pkg", "1.0.0"))
        self.assertEqual((source["sites"][0]["path"], source["sites"][0]["line"]), ("a.js", 3))
        self.assertEqual(
            [e["directory"] for e in labels["excluded"]], ["pkg-b_2.0.0-beta", "pkg-c_1.0.0"]
        )

    def test_committed_labels_are_the_ones_the_metadata_produces(self):
        self.assertEqual(build_labels.main(["--check"]), 0)


class PairLabelsTests(unittest.TestCase):
    """The pairs-v1 scoring kit, checked without scanning any pair."""

    def test_labels_cover_every_acquired_pair_of_a_split(self):
        held_out = pair_labels.build("held_out")
        self.assertEqual(len(held_out["sources"]), 16)
        self.assertEqual(sum(len(s["sites"]) for s in held_out["sources"]), 9)
        development = pair_labels.build("development")
        self.assertEqual(len(development["sources"]), 34)
        self.assertEqual(sum(len(s["sites"]) for s in development["sources"]), 26)
        # Ray was never acquired: it is listed, not turned into a source to scan.
        self.assertEqual(development["not_acquired"], ["pyvul-ray-project-ray-193ff8c80067"])
        # An unresolved pair stays in the table without a site.
        unresolved = [s for s in held_out["sources"] if not s["sites"]]
        self.assertEqual(len(unresolved), 7)

    def test_the_pair_with_prior_exposure_is_scored_from_its_saved_report(self):
        import shutil
        import tempfile

        labels = pair_labels.build("development", only="secbench-curling-0.2.0")
        self.assertTrue(labels["sources"][0]["prior_exposure"])
        saved = EVALUATION / "inputs" / "npm-curling-0.2.0-v0.2" / "report.json"
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "secbench-curling-0.2.0"
            target.mkdir()
            shutil.copy(saved, target / "report.json")
            result = configurations.evaluate(labels, folder)
            verified = pair_labels.verify(labels, folder)
        site = result["sources"][0]["sites"][0]
        self.assertEqual((site["path"], site["line"]), ("lib/curl-transport.js", 56))
        self.assertEqual(
            (site["reported"], site["priority"], site["filtered"]), (True, "P1", False)
        )
        self.assertEqual(site["tools"], ["codeql", "eslint"])
        # The saved report was produced from the archive bytes the source lock recorded.
        self.assertEqual(verified, [{"id": "secbench-curling-0.2.0", "locked_bytes": True}])

    def test_a_report_from_other_bytes_is_not_accepted_as_the_locked_pair(self):
        import tempfile

        labels = pair_labels.build("development", only="secbench-curling-0.2.0")
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "secbench-curling-0.2.0"
            target.mkdir()
            (target / "report.json").write_text(json.dumps(_report([])), encoding="utf-8")
            self.assertEqual(pair_labels.verify(labels, folder)[0]["locked_bytes"], False)
            self.assertIsNone(pair_labels.verify(labels, Path(folder) / "none")[0]["locked_bytes"])


class LaterIndependentChecksTests(unittest.TestCase):
    """The npm (SecBench.js) and Python checks: committed results, exports and registrations."""

    WAVES = ("independent-secbench", "independent-python")

    def test_committed_results_are_reproduced_from_the_saved_exports(self):
        for wave in self.WAVES:
            with self.subTest(wave=wave):
                folder = EVALUATION / wave
                labels = json.loads((folder / "labels.json").read_bytes())
                expected = json.loads((folder / "results" / "configurations.json").read_bytes())
                self.assertEqual(configurations.evaluate(labels, folder / "inputs"), expected)

    def test_every_saved_export_matches_its_manifest(self):
        import hashlib

        roots = [EVALUATION / wave / "inputs" for wave in self.WAVES]
        roots.append(EVALUATION / "independent-secbench" / "posthoc-after-fix")
        roots.append(EVALUATION / "independent" / "inputs")
        folders = [path for root in roots for path in sorted(root.iterdir()) if path.is_dir()]
        self.assertEqual(len(folders), 52 + 3 + 2 + 3)
        for folder in folders:
            with self.subTest(folder=folder.name):
                manifest = json.loads((folder / "manifest.json").read_bytes())
                for name, sha256 in manifest["files"].items():
                    actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, sha256)

    def test_registered_files_are_unchanged_except_for_the_recorded_deviation(self):
        import hashlib

        deviations = json.loads(
            (EVALUATION / "independent-secbench" / "DEVIATIONS.json").read_bytes()
        )["changed_after_registration"]
        for wave in self.WAVES:
            record = json.loads((EVALUATION / wave / "PREREGISTRATION.json").read_bytes())
            for relative, registered in record["sha256"].items():
                with self.subTest(wave=wave, file=relative):
                    actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                    if relative in deviations:
                        # A change after registration must be written down, hash by hash.
                        self.assertEqual(registered, deviations[relative]["registered_sha256"])
                        self.assertEqual(actual, deviations[relative]["current_sha256"])
                    else:
                        _assert_registered(self, relative, registered)

    def test_post_hoc_reading_is_reproduced_and_separates_unmerged_alerts_from_silence(self):
        folder = EVALUATION / "independent-secbench"
        result = json.loads((folder / "results" / "configurations.json").read_bytes())
        expected = json.loads((folder / "results" / "posthoc-missed.json").read_bytes())
        self.assertEqual(posthoc_missed.read(result, folder / "inputs"), expected)
        site = {"path": "a.js", "line": 12}
        alert = {"tool": "codeql", "path": "a.js", "start_line": 12, "end_line": 12}
        self.assertEqual(
            posthoc_missed.classify(site, [{**alert, "related": False}]),
            ("raw_alert_on_line", ["codeql"]),
        )
        self.assertEqual(
            posthoc_missed.classify(site, [{**alert, "related": True}]),
            ("related_location_on_line", ["codeql"]),
        )
        elsewhere = {**alert, "start_line": 3, "end_line": 3, "related": False}
        self.assertEqual(posthoc_missed.classify(site, [elsewhere])[0], "raw_alert_in_file")
        self.assertEqual(posthoc_missed.classify(site, []), ("no_alert_in_file", []))


class LabeledSitesTests(unittest.TestCase):
    """Vulnerable/safe labels from rule tests, and precision/recall/F1 on them."""

    def _site(self, line, label, language="python", profile_rule=False):
        return {
            "path": "t.py" if language == "python" else "t.js",
            "line": line,
            "label": label,
            "language": language,
            "profile_rule": profile_rule,
        }

    def _hit(self, line, tools, priority="P1", disposition="review", rules=(), path="t.py"):
        candidate = _candidate(path, tools, priority, disposition)
        return {
            **candidate,
            "candidate_key": f"{path}:{line}",
            "start_line": line,
            "filter_rules": list(rules),
        }

    def test_each_configuration_gets_all_four_counts_and_the_three_rates(self):
        labels = {
            "sites": [
                self._site(1, "vulnerable"),
                self._site(2, "vulnerable"),
                self._site(3, "vulnerable"),
                self._site(4, "safe"),
                self._site(5, "safe"),
                self._site(6, "safe"),
            ]
        }
        report = _report(
            [
                self._hit(1, ["codeql", "semgrep"]),
                self._hit(2, ["bandit"], "P3"),
                self._hit(4, ["bandit"], "P3", "filtered", ["G2_LITERAL_COMMAND"]),
                self._hit(5, ["codeql", "bandit"], "P1", "filtered", ["G1"]),
                # Another line of the labeled file is a different call: unlabeled.
                self._hit(9, ["semgrep"], "P3"),
            ]
        )
        block = labeled_sites.evaluate(labels, report)["subsets"]["all labeled sites"]
        scores = block["scores"]
        union = scores["all sources"]
        self.assertEqual((union["tp"], union["fp"], union["fn"], union["tn"]), (2, 2, 1, 1))
        self.assertEqual((union["precision"], union["recall"], union["f1"]), (0.5, 0.6667, 0.5714))
        after = scores["all sources, filtered"]
        self.assertEqual((after["tp"], after["fp"], after["fn"], after["tn"]), (2, 0, 1, 3))
        # Only the rule backed by an open-source tool counts in the open-source configuration.
        self.assertEqual(scores["all sources, open-source filter"]["fp"], 1)
        self.assertEqual(scores["codeql"]["fp"], 1)
        self.assertEqual(scores["first tiers (P1+P2), filtered"]["tp"], 1)
        effect = block["filter_effect"]
        self.assertEqual(effect["filtered"], {"vulnerable": 0, "safe": 2})
        self.assertEqual(effect["filtered_by_rule"]["G2_LITERAL_COMMAND"]["safe"], 1)
        self.assertEqual(effect["demoted_p3_p4"], {"vulnerable": 1, "safe": 0})

    def test_a_filtered_vulnerable_site_is_a_miss_after_filtering_and_is_listed(self):
        labels = {"sites": [self._site(1, "vulnerable")]}
        report = _report([self._hit(1, ["codeql"], "P1", "filtered", ["G1"])])
        block = labeled_sites.evaluate(labels, report)["subsets"]["all labeled sites"]
        self.assertEqual(block["scores"]["all sources"]["tp"], 1)
        self.assertEqual(block["scores"]["all sources, filtered"]["fn"], 1)
        self.assertEqual(block["filter_effect"]["filtered"]["vulnerable"], 1)
        self.assertEqual(block["filter_effect"]["filtered_sites"][0]["rules"], ["G1"])

    def test_sites_are_split_by_language_and_by_whether_the_profile_runs_the_rule(self):
        labels = {
            "sites": [
                self._site(1, "vulnerable"),
                self._site(2, "vulnerable", profile_rule=True),
                self._site(3, "safe", language="javascript"),
            ]
        }
        subsets = labeled_sites.evaluate(labels, _report([]))["subsets"]
        self.assertEqual(subsets["python"]["sites"], {"vulnerable": 2, "safe": 0})
        self.assertEqual(subsets["javascript"]["sites"], {"vulnerable": 0, "safe": 1})
        other = subsets["python, tests of rules the profile does not run"]
        self.assertEqual(other["sites"], {"vulnerable": 1, "safe": 0})
        # No site reported: precision is undefined, not zero.
        self.assertIsNone(subsets["python"]["scores"]["all sources"]["precision"])

    def test_rule_test_comments_label_the_next_code_line(self):
        text = "\n".join(
            [
                "import os",
                "# ok: rule-a",
                "os.system('ls')",
                "",
                "# ruleid: rule-a",
                "# a remark between the comment and the code",
                "os.system(cmd)",
                "# todoruleid: rule-a",
                "os.system(other)",
                "# ruleid: some-other-rule",
                "os.system(third)",
                "# ok: rule-a",
                "# ruleid: rule-b",
                "os.system(both)",
            ]
        )
        found = list(rule_test_labels.label_lines(text, {"rule-a", "rule-b"}))
        self.assertEqual(
            found,
            [
                (3, "safe", ["rule-a"]),
                (7, "vulnerable", ["rule-a"]),
                (14, "vulnerable", ["rule-a", "rule-b"]),
            ],
        )


class LabeledCheckResultsTests(unittest.TestCase):
    """The committed results of the labeled check, its exports and its registration."""

    RUNS = {
        "registered.json": "input",
        "posthoc-after-fix.json": "posthoc-after-fix",
        "v0.3-rescan.json": "v0.3-rescan",
    }

    def test_committed_results_are_reproduced_from_the_saved_exports(self):
        labels = json.loads((LABELED / "labels.json").read_bytes())
        for result_name, folder in self.RUNS.items():
            with self.subTest(result=result_name):
                report = json.loads((LABELED / folder / "report.json").read_bytes())
                expected = json.loads((LABELED / "results" / result_name).read_bytes())
                self.assertEqual(labeled_sites.evaluate(labels, report), expected)

    def test_the_registered_scan_failed_and_the_rescan_read_the_labeled_archive(self):
        labels = json.loads((LABELED / "labels.json").read_bytes())
        registered = json.loads((LABELED / "results" / "registered.json").read_bytes())
        # The registered result stays what it was: a failed scan without candidates.
        self.assertEqual(registered["scan_status"], "failed")
        self.assertEqual(registered["stages"]["candidates"], 0)
        rescan = json.loads((LABELED / "results" / "posthoc-after-fix.json").read_bytes())
        self.assertEqual(rescan["snapshot_sha256"], labels["archive_sha256"])
        # An incomplete run filters nothing, by design.
        self.assertEqual(rescan["scan_status"], "partial")
        self.assertEqual(rescan["stages"]["filtered"], 0)

    def test_saved_exports_match_their_manifests_and_registered_files_are_unchanged(self):
        import hashlib

        for folder in self.RUNS.values():
            manifest = json.loads((LABELED / folder / "manifest.json").read_bytes())
            for name, sha256 in manifest["files"].items():
                with self.subTest(folder=folder, file=name):
                    actual = hashlib.sha256((LABELED / folder / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, sha256)
        record = json.loads((LABELED / "PREREGISTRATION.json").read_bytes())
        for relative, registered in record["sha256"].items():
            with self.subTest(file=relative):
                _assert_registered(self, relative, registered)


class FilterCheckTests(unittest.TestCase):
    """What the filter did on unlabeled sources, and the independent constant-command check."""

    def _source(self, name):
        return {"id": name, "owner": "o", "repo": name, "commit": "c" * 40}

    def _report_with(self, candidates, status="completed"):
        report = _report(candidates)
        filtered = [c for c in candidates if c["disposition"] == "filtered"]
        by_rule = {}
        for candidate in filtered:
            for rule in candidate["filter_rules"]:
                by_rule[rule] = by_rule.get(rule, 0) + 1
        return {
            **report,
            "status": status,
            "stages": {
                "raw_alerts": len(candidates),
                "units": len(candidates),
                "candidates": len(candidates),
                "main_list": len(candidates) - len(filtered),
                "filtered": len(filtered),
                "demoted": 0,
            },
            "filtered_by_rule": by_rule,
            "main_list_by_priority": {},
        }

    def _call(self, line, disposition="review", rules=()):
        candidate = _candidate("cli.py", ["bandit", "semgrep"], "P4", disposition)
        return {
            **candidate,
            "candidate_key": f"cli.py:{line}",
            "start_line": line,
            "sink_kind": "os.system",
            "filter_rules": list(rules),
        }

    def test_counts_separate_completed_scans_and_list_every_filtered_call(self):
        import tempfile

        reports = {
            "done": self._report_with(
                [self._call(3, "filtered", ["G2_LITERAL_COMMAND"]), self._call(9)]
            ),
            "half": self._report_with([self._call(4)], status="partial"),
        }
        sources = {"sources": [self._source(name) for name in [*reports, "gone"]]}
        with tempfile.TemporaryDirectory() as folder:
            for name, report in reports.items():
                (Path(folder) / name).mkdir()
                (Path(folder) / name / "report.json").write_text(
                    json.dumps(report), encoding="utf-8"
                )
            result = filtered_candidates.evaluate(sources, folder)
        self.assertEqual(result["scan_statuses"], {"completed": 1, "partial": 1, "missing": 1})
        self.assertEqual(
            result["completed_scans"],
            {"scans": 1, "candidates": 2, "filtered": 1, "with_a_filtered_candidate": 1},
        )
        self.assertEqual(result["filtered_by_rule"], {"G2_LITERAL_COMMAND": 1})
        (item,) = result["filtered"]
        self.assertEqual((item["id"], item["path"], item["line"]), ("done", "cli.py", 3))
        self.assertIn("| done `cli.py:3` |", filtered_candidates.markdown(result))

    def test_constant_command_check_accepts_literals_only(self):
        source = "\n".join(
            [
                "import os, subprocess",
                "os.system('clear')",
                "os.system('git ' + 'status')",
                "subprocess.run(['ls', '-l'])",
                "os.system('rm ' + name)",
                "os.system(f'echo {name}')",
                "subprocess.run(args=cmd)",
                "os.system('echo %s' % name)",
                "x = 1",
            ]
        )
        verdicts = [verify_filtered.verdict(source, line)[0] for line in range(2, 10)]
        self.assertEqual(
            verdicts,
            [
                "constant_command",
                "constant_command",
                "constant_command",
                "not_constant",
                "not_constant",
                "not_constant",
                "not_constant",
                "unreadable",
            ],
        )
        self.assertEqual(verify_filtered.verdict("def broken(:", 1), ("unreadable", None))

    def test_verification_reads_the_pinned_file_and_keeps_unreadable_sources(self):
        item = {**self._source("done"), "path": "cli.py", "line": 2, "filter_rules": ["G2"]}
        result = {"filtered": [item, {**item, "path": "missing.py"}]}

        def fetch(entry):
            if entry["path"] == "missing.py":
                raise OSError("404")
            return "import os\nos.system('clear')\n"

        checked = verify_filtered.verify(result, fetch_fn=fetch)
        self.assertEqual(checked["verdicts"], {"constant_command": 1, "unreadable": 1})
        self.assertEqual(checked["filtered"][0]["command"], "'clear'")
        self.assertIn("2: os.system('clear')", checked["filtered"][0]["lines"])


class FilterCheckResultsTests(unittest.TestCase):
    """The committed results of the filter check, its exports and its registration."""

    def test_committed_result_is_reproduced_from_the_saved_exports(self):
        sources = json.loads((FILTER / "sources.json").read_bytes())
        expected = json.loads((FILTER / "results" / "filtered-candidates.json").read_bytes())
        self.assertEqual(filtered_candidates.evaluate(sources, FILTER / "inputs"), expected)
        # The filter acted in completed scans only.
        self.assertEqual(expected["completed_scans"]["filtered"], 19)
        self.assertTrue(all(item["scan_status"] == "completed" for item in expected["filtered"]))

    def test_saved_verdicts_follow_from_the_saved_source_lines_of_the_registered_check(self):
        verified = json.loads((FILTER / "results" / "verified.json").read_bytes())
        # The registered verdicts stay as they were, including the two the check rejected.
        self.assertEqual(verified["verdicts"], {"constant_command": 17, "not_constant": 2})
        listed = json.loads((FILTER / "results" / "filtered-candidates.json").read_bytes())
        self.assertEqual(
            [(r["id"], r["path"], r["line"]) for r in verified["filtered"]],
            [(r["id"], r["path"], r["line"]) for r in listed["filtered"]],
        )

    def test_saved_exports_match_their_manifests_and_registered_files_are_unchanged(self):
        import hashlib

        folders = sorted(path for path in (FILTER / "inputs").iterdir() if path.is_dir())
        self.assertEqual(len(folders), 20)
        for folder in folders:
            manifest = json.loads((folder / "manifest.json").read_bytes())
            for name, sha256 in manifest["files"].items():
                with self.subTest(folder=folder.name, file=name):
                    actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, sha256)
        record = json.loads((FILTER / "PREREGISTRATION.json").read_bytes())
        for relative, registered in record["sha256"].items():
            with self.subTest(file=relative):
                _assert_registered(self, relative, registered)


class PairsRunKitTests(unittest.TestCase):
    """Scoring of a pairs-v1 run and the freeze gate, without scanning any pair."""

    def test_only_pairs_scanned_from_the_locked_bytes_are_scored(self):
        import shutil
        import tempfile

        labels = pair_labels.build("development")
        labels["sources"] = [
            s
            for s in labels["sources"]
            if s["id"] in {"secbench-curling-0.2.0", "secbench-arpping-2.0.0", "secbench-gm-1.20.0"}
        ]
        saved = EVALUATION / "inputs" / "npm-curling-0.2.0-v0.2" / "report.json"
        with tempfile.TemporaryDirectory() as folder:
            inputs = Path(folder)
            (inputs / "secbench-curling-0.2.0").mkdir()
            shutil.copy(saved, inputs / "secbench-curling-0.2.0" / "report.json")
            # A report produced from other bytes must not be scored as this pair.
            (inputs / "secbench-arpping-2.0.0").mkdir()
            (inputs / "secbench-arpping-2.0.0" / "report.json").write_text(
                json.dumps(_report([])), encoding="utf-8"
            )
            scored = score_pairs.score(labels, inputs)
        self.assertEqual((scored["pairs"], scored["scored_pairs"]), (3, 1))
        self.assertEqual(
            {row["id"]: row["reason"] for row in scored["left_out"]},
            {
                "secbench-arpping-2.0.0": "scanned archive differs from the locked bytes",
                "secbench-gm-1.20.0": "no exported report",
            },
        )
        block = scored["result"]["configurations"]
        self.assertEqual(block["documented_sites_scanned"], 1)
        self.assertEqual(block["reported_by_configuration"]["all sources"], 1)

    def test_freeze_reports_changed_added_and_removed_files(self):
        record = {"a": "1", "b": "2", "c": "3"}
        self.assertEqual(freeze.changed(record, dict(record)), [])
        self.assertEqual(freeze.changed(record, {"a": "1", "b": "x", "d": "4"}), ["b", "c", "d"])

    def test_committed_labels_come_from_the_locked_manifests(self):
        # FROZEN_CONFIGURATION.json describes the files at the commit of the development run
        # (f1e7c0c). Amendment 07 lifted that freeze, so later versions of those files differ.
        record = json.loads((PAIRS_KIT / "FROZEN_CONFIGURATION.json").read_bytes())
        self.assertEqual(len(record["sha256"]), 46)
        for split, pairs in (("development", 34), ("held_out", 16)):
            labels = json.loads((PAIRS_KIT / split / "labels.json").read_bytes())
            self.assertEqual(labels, pair_labels.build(split))
            self.assertEqual(len(labels["sources"]), pairs)


class PairsDevelopmentResultTests(unittest.TestCase):
    """The committed development-split result of pairs-v1 (Amendment 06, pipeline v0.2)."""

    RUN = PAIRS_KIT / "development"

    def test_result_is_reproduced_and_every_pair_was_scanned_from_the_locked_bytes(self):
        labels = json.loads((self.RUN / "labels.json").read_bytes())
        expected = json.loads((self.RUN / "result.json").read_bytes())
        self.assertEqual(score_pairs.score(labels, self.RUN / "inputs"), expected)
        self.assertEqual((expected["pairs"], expected["scored_pairs"]), (34, 34))
        self.assertEqual(expected["left_out"], [])
        self.assertEqual(expected["result"]["configurations"]["lost_to_filtering"], 0)

    def test_saved_exports_match_their_manifests(self):
        import hashlib

        folders = sorted(path for path in (self.RUN / "inputs").iterdir() if path.is_dir())
        self.assertEqual(len(folders), 34)
        for folder in folders:
            manifest = json.loads((folder / "manifest.json").read_bytes())
            for name, sha256 in manifest["files"].items():
                with self.subTest(folder=folder.name, file=name):
                    actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, sha256)

    def test_a_held_out_scan_exists_only_after_the_recorded_gate(self):
        # Amendment 08: the frozen hashes are checked and the commit recorded before the first
        # held-out scan. Exports without that record would be an unregistered run.
        if (PAIRS_KIT / "held_out" / "inputs").exists():
            gate = json.loads((PAIRS_KIT / "HELD_OUT_GATE.json").read_bytes())
            self.assertTrue(gate["frozen_files_unchanged"])
            self.assertRegex(gate["commit"], r"^[0-9a-f]{40}$")
            frozen = json.loads((PAIRS_KIT / "FROZEN_CONFIGURATION_v0.3.json").read_bytes())
            self.assertIn("profiles/command-injection-v0.3/profile.json", frozen["sha256"])

    def test_rehearsal_of_v0_3_on_the_python_development_pairs_is_reproduced(self):
        run = PAIRS_KIT / "development-v0.3-python"
        labels = json.loads((run / "labels.json").read_bytes())
        expected = json.loads((run / "result.json").read_bytes())
        self.assertEqual(score_pairs.score(labels, run / "inputs"), expected)
        self.assertEqual((expected["pairs"], expected["scored_pairs"]), (9, 9))
        statuses = expected["result"]["scan_statuses"]
        self.assertNotIn("failed", statuses)
        self.assertEqual(expected["result"]["summary"]["filtered"], 0)


class PairsHeldOutResultTests(unittest.TestCase):
    """The committed held-out result of pairs-v1 (Amendment 08, pipeline v0.3, scanned once)."""

    RUN = PAIRS_KIT / "held_out"

    def test_result_is_reproduced_and_every_pair_was_scanned_from_the_locked_bytes(self):
        labels = json.loads((self.RUN / "labels.json").read_bytes())
        expected = json.loads((self.RUN / "result.json").read_bytes())
        self.assertEqual(score_pairs.score(labels, self.RUN / "inputs"), expected)
        self.assertEqual((expected["pairs"], expected["scored_pairs"]), (16, 16))
        self.assertEqual(expected["left_out"], [])
        self.assertEqual(expected["result"]["scan_statuses"], {"completed": 12, "partial": 4})
        self.assertEqual(
            expected["result"]["summary"],
            {"documented_sites": 9, "reported": 9, "in_first_tiers": 7, "filtered": 0, "missed": 0},
        )
        self.assertEqual(expected["result"]["configurations"]["lost_to_filtering"], 0)

    def test_each_pair_was_scanned_once_with_the_frozen_profile(self):
        import hashlib

        frozen = json.loads((PAIRS_KIT / "FROZEN_CONFIGURATION_v0.3.json").read_bytes())
        profile = frozen["sha256"]["profiles/command-injection-v0.3/profile.json"]
        log = (self.RUN / "collection.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len([line for line in log if line.strip()]), 16)
        folders = sorted(path for path in (self.RUN / "inputs").iterdir() if path.is_dir())
        self.assertEqual(len(folders), 16)
        for folder in folders:
            report = json.loads((folder / "report.json").read_bytes())
            manifest = json.loads((folder / "manifest.json").read_bytes())
            with self.subTest(folder=folder.name):
                self.assertEqual(report["profile"], "command-injection-v0.3")
                self.assertEqual(report["profile_sha256"], profile)
                for name, sha256 in manifest["files"].items():
                    actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, sha256)


class JavaScriptMatchingTests(unittest.TestCase):
    """The v0.2 against v0.3 comparison of JavaScript matching (development data)."""

    def test_committed_comparison_is_reproduced_from_the_saved_exports(self):
        expected = json.loads((JS_MATCHING / "results" / "compare.json").read_bytes())
        self.assertEqual(js_compare.evaluate(), expected)
        total = expected["all"]
        self.assertEqual(total["unmatched_candidates"], [37, 14])
        self.assertEqual(total["alerts_unmatched_before"]["merged"], 23)
        # Neither a wrong merge nor a lost match, and no known vulnerable site was filtered.
        self.assertEqual(total["newly_merged_not_inside_the_call"], 0)
        self.assertEqual(total["alerts_that_lost_their_call"], 0)
        self.assertEqual(total["known_sites"]["filtered_after"], 0)

    def test_every_rescan_used_one_profile_version_and_matches_its_manifest(self):
        import hashlib

        folders = sorted(path for path in (JS_MATCHING / "inputs").iterdir() if path.is_dir())
        self.assertEqual(len(folders), 84)
        profiles = set()
        for folder in folders:
            manifest = json.loads((folder / "manifest.json").read_bytes())
            for name, sha256 in manifest["files"].items():
                with self.subTest(folder=folder.name, file=name):
                    actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, sha256)
            report = json.loads((folder / "report.json").read_bytes())
            profiles.add((report["profile"], report["profile_sha256"]))
        self.assertEqual(len(profiles), 1)
        self.assertEqual(next(iter(profiles))[0], "command-injection-v0.3")

    def test_an_alert_is_consistent_only_inside_the_call_its_candidate_starts_on(self):
        call = {"path": "a.js", "start": [5, 3], "end": [7, 4]}
        candidate = {"path": "a.js", "start_line": 5}
        inside = {"startLine": 6, "startColumn": 5, "endLine": 6, "endColumn": 9}
        outside = {"startLine": 9, "startColumn": 1, "endLine": 9, "endColumn": 4}
        alert = {"candidate": candidate, "region": inside, "related": []}
        self.assertTrue(js_compare.consistent(alert, [call]))
        self.assertFalse(js_compare.consistent({**alert, "region": outside}, [call]))
        # A related location inside the call is an explicit link to it.
        linked = {**alert, "region": outside, "related": [("a.js", inside)]}
        self.assertTrue(js_compare.consistent(linked, [call]))
        # A call that starts on another line is not the candidate's call.
        self.assertFalse(js_compare.consistent(alert, [{**call, "start": [6, 1]}]))


class ConstantReferenceTests(unittest.TestCase):
    """Reference labels for the constant-command class and the score of filter rule G4."""

    def test_committed_summary_follows_from_the_saved_reference_labels(self):
        saved = json.loads((JS_MATCHING / "results" / "constant-reference.json").read_bytes())
        self.assertEqual(constant_reference.summarize(saved["candidates"]), saved)
        self.assertEqual(saved["shell_string_candidates"], 120)
        self.assertEqual(
            saved["g4"],
            {
                "filtered": 1,
                "filtered_and_constant_by_reference": 1,
                "filtered_but_not_constant_by_reference": 0,
                "constant_pattern_only_but_kept": 0,
            },
        )

    def test_a_filtered_call_without_a_constant_reference_counts_as_a_wrong_filter(self):
        row = {
            "reference": "not_constant",
            "flow_claim": False,
            "disposition": "filtered",
        }
        kept = {"reference": "constant_command", "flow_claim": False, "disposition": "review"}
        flow = {"reference": "constant_command", "flow_claim": True, "disposition": "review"}
        result = constant_reference.summarize([row, kept, flow])
        self.assertEqual(result["g4"]["filtered_but_not_constant_by_reference"], 1)
        self.assertEqual(result["g4"]["constant_pattern_only_but_kept"], 1)
        # A constant command with a flow claim is a conflict to review, not a missed filter.
        self.assertEqual(result["constant_by_reference"]["with_a_flow_claim"], 1)

    def test_the_reference_labeler_agrees_with_the_stated_synthetic_cases(self):
        import re
        import shutil
        import subprocess

        espree = ROOT / "tools" / "eslint" / "node_modules" / "espree"
        if shutil.which("node") is None or not espree.is_dir():
            self.skipTest("needs Node.js and tools/eslint/node_modules (npm ci in tools/eslint)")
        pack = ROOT / "rules" / "semgrep" / "command-injection-evidence-js-v0.1"
        cases = pack / "tests" / "cases.js"
        calls, names = [], []
        for number, line in enumerate(cases.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"function (constant_\w+|kept_\w+)\(", line)
            # spawn takes arguments; the labeler is only used for exec and execSync.
            if not match or "spawn" in match.group(1):
                continue
            column = max(line.rfind("cp.exec("), line.rfind(" exec(") + 1)
            end = line.index(");", column) + 1
            calls.append(
                {"line": number, "column": column + 1, "endLine": number, "endColumn": end + 1}
            )
            names.append(match.group(1))
        done = subprocess.run(
            ["node", str(JS_MATCHING / "constant_reference.cjs")],
            input=json.dumps({"file": str(cases), "calls": calls}),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        verdicts = [item["verdict"] for item in json.loads(done.stdout)]
        expected = [
            "constant_command" if n.startswith("constant_") else "not_constant" for n in names
        ]
        self.assertEqual(verdicts, expected)
        self.assertEqual(len(names), 19)


class JavaScriptLabelScoringTests(unittest.TestCase):
    """Scoring of the v0.3 exports against candidate labels (js-labels-v0.3)."""

    @staticmethod
    def _unit(label, tools, priority, *, filtered=False, source="assistant", kind=None):
        return {
            "label": label,
            "source": source,
            "class": kind,
            "tools": tools,
            "priority": priority,
            "filtered": filtered,
            "filter_rules": ["G4_JS_CONSTANT_COMMAND"] if filtered else [],
        }

    def test_counts_rates_and_filter_outcome_on_synthetic_units(self):
        units = [
            self._unit("vulnerable", ["codeql"], "P1", source="cve"),
            self._unit("vulnerable", ["semgrep"], "P2"),
            self._unit("safe", ["eslint"], "P3", filtered=True, kind="constant_command"),
            self._unit("safe", ["eslint", "semgrep"], "P3", kind="internal_values_only"),
            self._unit("undetermined", ["eslint"], "U"),
        ]
        result = js_label_score.score(units, missed_known=1)
        everything = result["configurations"]["all sources"]
        self.assertEqual(
            (everything["tp"], everything["fp"], everything["undetermined"], everything["fn"]),
            (2, 2, 1, 1),
        )
        self.assertEqual(everything["precision"], 0.5)
        self.assertEqual(everything["recall_upper_bound"], 0.6667)
        after = result["configurations"]["all sources, after filtering"]
        self.assertEqual((after["tp"], after["fp"], after["precision"]), (2, 1, 0.6667))
        first = result["configurations"]["first tiers (P1+P2), after filtering"]
        self.assertEqual((first["tp"], first["fp"], first["precision"]), (2, 0, 1.0))
        self.assertEqual(result["configurations"]["semgrep"]["fp"], 1)
        self.assertEqual(result["filter"], {"vulnerable": 0, "safe": 1, "undetermined": 0})
        self.assertEqual(
            result["safe_left_in_review_list"]["by_class"], {"internal_values_only": 1}
        )
        self.assertEqual(result["labels"]["vulnerable"], {"cve": 1, "assistant": 1})

    def test_a_line_is_filtered_only_when_every_candidate_on_it_is(self):
        filtered = {"tools": ["eslint"], "priority": "P3", "disposition": "filtered"}
        kept = {"tools": ["codeql"], "priority": "P2", "disposition": "review"}
        unit = js_label_score.merge([{**filtered, "filter_rules": ["G4"]}, kept])
        self.assertEqual(
            (unit["filtered"], unit["priority"], unit["tools"]), (False, "P2", ["codeql", "eslint"])
        )
        self.assertTrue(js_label_score.merge([filtered])["filtered"])

    def test_committed_score_is_reproduced_from_the_saved_exports_and_labels(self):
        expected = json.loads((JS_LABELS / "results" / "score.json").read_bytes())
        self.assertEqual(js_label_score.evaluate(), expected)
        everything = expected["groups"]["all"]
        self.assertEqual(everything["units"], 146)
        self.assertEqual(everything["filter"], {"vulnerable": 0, "safe": 1, "undetermined": 0})

    def test_every_item_has_one_label_with_a_reason_and_a_valid_class(self):
        meta = json.loads((JS_LABELS / "labels.json").read_bytes())
        labels = {row["id"]: row for row in meta["labels"]}
        self.assertEqual(sorted(labels), sorted(item["id"] for item in js_label_sheet.items()))
        classes = {
            "constant_command",
            "internal_values_only",
            "validated_or_escaped",
            "no_shell",
            "not_a_command_sink",
            "test_or_example_code",
        }
        for row in labels.values():
            with self.subTest(id=row["id"]):
                self.assertIn(row["label"], js_label_score.LABELS)
                self.assertTrue(row["reason"].strip())
                self.assertEqual(row["class"] in classes, row["label"] == "safe")

    def test_labels_are_not_presented_as_reviewed_without_a_review_record(self):
        # The labels were assigned by an AI assistant. A reviewer may be recorded only together
        # with a note of what the review changed.
        meta = json.loads((JS_LABELS / "labels.json").read_bytes())
        self.assertIn("AI", meta["assigned_by"])
        if meta["reviewed_by"] is not None:
            self.assertRegex(meta["reviewed_by"], r"\d{4}-\d{2}-\d{2}")
            self.assertNotIn("No person has checked", meta["review_note"])

    def test_every_label_has_the_owner_review_record(self):
        # The owner reviewed all labels on 2026-11-15: 31 interactively, 47 in a review file.
        # A label without a review entry must not be counted as reviewed by a person.
        labels = json.loads((JS_LABELS / "labels.json").read_bytes())["labels"]
        reviewed = [row for row in labels if row["review"] is not None]
        self.assertEqual((len(labels), len(reviewed)), (84, 84))
        self.assertEqual(sum(1 for row in reviewed if row["review"]["decision"] == "changed"), 12)
        for row in reviewed:
            with self.subTest(id=row["id"]):
                review = row["review"]
                self.assertEqual(review["by"], "project owner")
                self.assertTrue(review["note"].strip())
                same = (review["assistant_label"], review["assistant_class"]) == (
                    row["label"],
                    row["class"],
                )
                self.assertEqual(review["decision"], "agreed" if same else "changed")

    def test_each_unmatched_alert_is_its_own_unit(self):
        # The reviewer's decision for extra-asciinema: seven alerts, seven units.
        labels = json.loads((JS_LABELS / "labels.json").read_bytes())["labels"]
        split = [row["id"] for row in labels if row["id"].startswith("extra-asciinema_1.0.0|")]
        unmatched = sorted(i.rsplit("|", 1)[1] for i in split if "|U" in i)
        self.assertEqual(unmatched, ["U31", "U35", "U40", "U41", "U42", "U43", "U45"])
        self.assertFalse([row["id"] for row in labels if row["id"].endswith("|None")])

    def test_protocol_is_the_registered_file_and_script_changes_are_recorded(self):
        import hashlib

        registered = json.loads((JS_LABELS / "PREREGISTRATION.json").read_bytes())["sha256"]
        protocol = "experiments/evaluation/js-labels-v0.3/PROTOCOL.md"
        actual = hashlib.sha256((ROOT / protocol).read_bytes()).hexdigest()
        self.assertEqual(actual, registered[protocol])
        # Both scripts changed after registration (a sort key, then one unit per unmatched
        # alert at the reviewer's decision); README.md records the registered and current hash.
        readme = (JS_LABELS / "README.md").read_text(encoding="utf-8")
        for name in ("label_sheet.py", "score_labels.py"):
            relative = f"experiments/evaluation/js-labels-v0.3/{name}"
            self.assertIn(registered[relative][:8], readme)
            current = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertIn(current[:8], readme)


if __name__ == "__main__":
    unittest.main()
