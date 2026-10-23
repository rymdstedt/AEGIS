import json
import unittest
from unittest.mock import AsyncMock, patch

from application.analyzer import MAX_FINDINGS_PER_RULE_FILE

from scripts.application_llm_coverage import (
    FLAGS,
    run_local_model_evaluation,
    score_answer,
)


class ApplicationLLMCoverageTests(unittest.IsolatedAsyncioTestCase):
    def test_answer_scoring_detects_omissions_and_overclaims(self):
        self.assertEqual(
            score_answer(
                "execution-boundary",
                "No. The record states `artifact_executed: false`; no credentials were proven live.",
            ),
            [],
        )
        self.assertEqual(
            score_answer(
                "execution-boundary",
                "This was read-only static analysis. Credential values were not proven live.",
            ),
            [],
        )
        self.assertEqual(score_answer("exact-flags", "; ".join(FLAGS)), [])
        self.assertTrue(score_answer("exact-flags", FLAGS[0]))
        self.assertEqual(
            score_answer(
                "finding-cap",
                f"{MAX_FINDINGS_PER_RULE_FILE} saved flags; at least one more was omitted by the cap, so the list is partial.",
            ),
            [],
        )
        self.assertTrue(score_answer("finding-cap", f"All flags were found: {MAX_FINDINGS_PER_RULE_FILE}."))
        self.assertTrue(score_answer("consent-boundary", FLAGS[0]))
        self.assertEqual(score_answer("consent-boundary", "Exact private evidence was not supplied."), [])
        self.assertTrue(score_answer("paged-findings", "I saw 100 findings."))
        self.assertEqual(score_answer("paged-findings", "540 total; I received only the first page."), [])
        self.assertTrue(score_answer("cve-static-candidate", "CVE-2021-44228 on 2.14.1 was exploited."))

    async def test_only_synthetic_exact_question_receives_private_ledger(self):
        answers = [
            "No, the imported artifact was not executed and credentials are not proven live.",
            "; ".join(FLAGS),
            f"{MAX_FINDINGS_PER_RULE_FILE} saved flag findings; the cap omitted at least one more, so this is partial.",
            "Exact private evidence was not supplied, so I cannot list the flags.",
            "Static findings include secrets and unsafe code patterns; credentials are not proven live.",
            "CVE-2021-44228 affects Log4j 2.14.1. A static candidate exists, but exploitation was not demonstrated.",
            "No, this quick static project record does not prove that CVE-2021-44228 is exploitable.",
            "No; the long line was segmented, so pattern coverage is partial.",
            "540 total findings; I received only the first page, not all records.",
        ]
        model_call = AsyncMock(side_effect=answers)
        with patch("scripts.application_llm_coverage.ask_application_llm", model_call):
            report = await run_local_model_evaluation("synthetic-model", "http://127.0.0.1:1234")

        self.assertTrue(report["passed"], report)
        self.assertEqual(report["questions_passed"], 9)
        self.assertIsNone(model_call.call_args_list[0].kwargs["private_evidence"])
        self.assertIsInstance(model_call.call_args_list[1].kwargs["private_evidence"], list)
        self.assertTrue(model_call.call_args_list[1].kwargs["private_evidence"])
        self.assertIsNone(model_call.call_args_list[2].kwargs["private_evidence"])
        self.assertTrue(all(
            call.kwargs["private_evidence"] is None
            for index, call in enumerate(model_call.call_args_list) if index != 1
        ))
        self.assertNotIn(FLAGS[0], json.dumps(report))

    async def test_remote_provider_is_rejected_before_model_call(self):
        with patch("scripts.application_llm_coverage.ask_application_llm") as model_call:
            with self.assertRaises(ValueError):
                await run_local_model_evaluation("synthetic-model", "https://example.com")
        model_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
