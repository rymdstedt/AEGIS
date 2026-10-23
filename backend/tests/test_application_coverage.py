"""Known-answer benchmark assertions; all artifacts are synthetic."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.application_coverage import (
    REPO_ROOT,
    V2_PRIVATE_MARKERS,
    benchmark_cases,
    run_case,
    run_suite,
)
from scripts.application_coverage import (
    main as benchmark_main,
)


class ApplicationCoverageBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cases = benchmark_cases(self.root / "fixtures")

    def tearDown(self):
        self.temporary.cleanup()

    def test_all_curated_cases_pass_and_report_known_gaps(self):
        report = run_suite(self.cases, self.root / "private-data")

        self.assertTrue(report["passed"], report)
        self.assertEqual(report["cases_passed"], 10)
        self.assertEqual(report["cases_total"], 10)
        self.assertEqual(report["captured_indicator_instances"], 694)
        self.assertEqual(report["planted_indicator_instances"], 697)
        self.assertEqual(report["known_capped_indicator_instances"], 3)
        self.assertEqual(report["known_uninspected_indicator_instances"], 0)
        self.assertEqual(report["deep_source_cve_controls_passed"], 5)
        self.assertTrue(all(item["passed"] for item in report["deep_source_cve_controls"]))
        self.assertTrue(all(item["external_scanner_invoked"] is False for item in report["deep_source_cve_controls"]))
        self.assertTrue(report["cancellation_control"]["passed"])
        cases = {case["name"]: case for case in report["cases"]}
        self.assertTrue(cases["per-file-cap"]["finding_results_truncated"])
        self.assertEqual(cases["per-file-cap"]["findings_omitted_lower_bound"], 1)
        self.assertEqual(cases["oversized-source"]["observed_findings"], 1)
        self.assertEqual(cases["oversized-source"]["inventory"]["skipped_large_text_candidates"], 0)
        self.assertEqual(cases["paged-many-findings"]["observed_findings"], 540)
        self.assertEqual(cases["negative-controls"]["observed_findings"], 0)
        self.assertEqual(cases["moderate-multi-value"]["observed_findings"], 15)
        self.assertEqual(
            set(cases["archive-boundaries"]["import_warning_reasons"]),
            {"path rejected", "duplicate path skipped", "symbolic link skipped"},
        )
        self.assertTrue(all(case["source_unchanged"] for case in report["cases"]))
        self.assertTrue(all(case["artifact_executed"] is False for case in report["cases"]))
        public = json.dumps(report)
        for marker in V2_PRIVATE_MARKERS:
            self.assertNotIn(marker, public)
        self.assertNotIn("SyntheticFirmwareOnlySecret", public)

    def test_wrong_expectation_fails_without_exporting_exact_values(self):
        original = self.cases[0]
        incorrect = replace(
            original,
            expected_rules={**original.expected_rules, "evidence.scoring-flag": 4},
        )
        result = run_case(incorrect, self.root / "private-data")

        self.assertFalse(result["passed"])
        self.assertTrue(any("finding counts differ" in item for item in result["problems"]))
        public = json.dumps(result)
        for marker in V2_PRIVATE_MARKERS:
            self.assertNotIn(marker, public)

    def test_cli_returns_failure_for_wrong_expected_finding_count(self):
        original = self.cases[0]
        incorrect = replace(
            original,
            expected_rules={**original.expected_rules, "evidence.scoring-flag": 4},
        )
        output = io.StringIO()
        with (
            patch("scripts.application_coverage.benchmark_cases", return_value=[incorrect]),
            patch.object(sys, "argv", ["application_coverage.py"]),
            contextlib.redirect_stdout(output),
        ):
            exit_code = benchmark_main()

        self.assertEqual(exit_code, 1)
        self.assertIn("FAIL source-v2", output.getvalue())
        for marker in V2_PRIVATE_MARKERS:
            self.assertNotIn(marker, output.getvalue())

    def test_case_exception_redacts_path_and_content(self):
        marker = "SYNTHETIC_PRIVATE_PATH_MARKER"
        broken = replace(
            self.cases[0],
            source=self.root / marker / "missing",
        )
        report = run_suite([broken], self.root / "private-data")

        self.assertFalse(report["passed"])
        self.assertNotIn(marker, json.dumps(report))
        self.assertTrue(report["cases"][0]["problems"][0].startswith("case raised "))

    def test_command_line_writes_redacted_machine_readable_report(self):
        output = self.root / "coverage.json"
        result = subprocess.run(  # noqa: S603 - fixed local benchmark script and interpreter
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "application_coverage.py"),
                "--case", "per-file-cap", "--json-output", str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(payload["passed"])
        self.assertEqual(payload["cases_total"], 1)
        self.assertNotIn("AEGIS{COVERAGE_LIMIT_00}", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
