import asyncio
import json
import unittest
from unittest.mock import patch

import httpx
from application.llm import (
    MAX_CONTEXT_CHARACTERS,
    ApplicationLLMError,
    ApplicationLLMPartialAnswer,
    _bounded_context,
    _native_message,
    _private_evidence_category,
    _private_evidence_values,
    _requested_private_categories,
    ask_application_llm,
)


class ApplicationLLMTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def project() -> dict:
        return {
            "id": "app_" + "1" * 32,
            "name": "fixture",
            "artifact_kind": "source directory",
            "status": "complete",
            "summary": {
                "finding_counts": {"high": 1},
                "inventory": {"files": 1, "analyzed_text_files": 1},
            },
            "findings": [{
                "id": "appf_" + "2" * 20,
                "rule_id": "secret.labeled-value",
                "severity": "high",
                "confidence": "medium",
                "title": "Labeled Secret Value Present",
                "description": "A labeled value was found.",
                "file_path": "notes.txt",
                "line": 1,
                "evidence": "Password: [REDACTED]",
                "remediation": "Rotate it.",
            }],
        }

    def test_paged_context_preserves_authoritative_total_and_private_omissions(self):
        project = self.project()
        project["findings_total"] = 540
        project["summary"]["finding_total"] = 540
        public = json.loads(_bounded_context(project, None, "Briefly summarize findings"))
        self.assertEqual(public["authoritative_facts"]["total_finding_records"], 540)
        self.assertEqual(public["authoritative_facts"]["finding_records_not_retrieved"], 539)
        private = json.loads(_bounded_context(
            project,
            [{"rule_id": "evidence.scoring-flag", "raw_evidence": "AEGIS{SYNTHETIC_FLAG_71C9}"}],
            "What exact flag was found?",
            private_evidence_total=540,
        ))
        self.assertEqual(private["private_evidence_records_not_retrieved"], 539)
        self.assertIn("lower bounds", private["authoritative_facts"]["count_semantics"])
        self.assertIn("lower bounds", public["authoritative_facts"]["count_semantics"])

    async def test_native_qwen_request_reuses_loaded_instance_configuration(self):
        observed: dict[str, object] = {}
        events: list[dict] = []

        class StreamResponse:
            status_code = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def aiter_lines(self):
                for line in (
                    "event: prompt_processing.progress",
                    'data: {"type":"prompt_processing.progress","progress":1}',
                    "",
                    "event: message.delta",
                    'data: {"type":"message.delta","content":"Grounded "}',
                    "",
                    "event: message.delta",
                    'data: {"type":"message.delta","content":"answer"}',
                    "",
                    "event: chat.end",
                    'data: {"type":"chat.end","result":{"output":[]}}',
                ):
                    yield line

        class Client:
            def __init__(self, **kwargs):
                observed["timeout"] = kwargs.get("timeout")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def stream(self, method, endpoint, json):
                observed["method"] = method
                observed["endpoint"] = endpoint
                observed["payload"] = json
                return StreamResponse()

        with patch("application.llm.httpx.AsyncClient", Client):
            answer = await ask_application_llm(
                project=self.project(),
                question="Briefly summarize it",
                lm_url="http://localhost:1234",
                model="qwen/qwen3.5-9b",
                history=[
                    {"role": "user", "content": "Can the dependency be exploited?"},
                    {"role": "assistant", "content": "Not from static evidence alone."},
                ],
                on_event=events.append,
            )

        self.assertEqual(answer, "Grounded answer")
        self.assertTrue(str(observed["endpoint"]).endswith("/api/v1/chat"))
        payload = observed["payload"]
        self.assertNotIn("context_length", payload)
        self.assertEqual(payload["reasoning"], "off")
        self.assertIs(payload["stream"], True)
        self.assertIn("RECENT OPERATOR DIALOGUE", payload["input"])
        self.assertIn("Not from static evidence alone.", payload["input"])
        self.assertEqual(
            "".join(event.get("content", "") for event in events),
            "Grounded answer",
        )

    async def test_timeout_error_is_actionable_and_never_blank(self):
        class StreamResponse:
            async def __aenter__(self):
                raise httpx.ReadTimeout(
                    "",
                    request=httpx.Request(
                        "POST", "http://localhost:1234/api/v1/chat"
                    ),
                )

            async def __aexit__(self, *_args):
                return False

        class Client:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def stream(self, method, endpoint, json):
                del method, endpoint, json
                return StreamResponse()

        with patch("application.llm.httpx.AsyncClient", Client):
            with self.assertRaisesRegex(
                ApplicationLLMError,
                r"stopped sending progress for 75 seconds",
            ):
                await ask_application_llm(
                    project=self.project(),
                    question="What was found?",
                    lm_url="http://localhost:1234",
                    model="qwen/qwen3.5-9b",
                )

    async def test_timeout_preserves_a_useful_streamed_partial_answer(self):
        class StreamResponse:
            status_code = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def aiter_lines(self):
                yield 'data: {"type":"message.delta","content":"Useful grounded sentence."}'
                await asyncio.sleep(0.05)

        class Client:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def stream(self, method, endpoint, json):
                del method, endpoint, json
                return StreamResponse()

        with (
            patch("application.llm.httpx.AsyncClient", Client),
            patch("application.llm.MODEL_ANSWER_WALL_TIMEOUT_SECONDS", 0.01),
        ):
            with self.assertRaises(ApplicationLLMPartialAnswer) as raised:
                await ask_application_llm(
                    project=self.project(),
                    question="What was found?",
                    lm_url="http://localhost:1234",
                    model="qwen/qwen3.5-9b",
                )

        self.assertEqual(raised.exception.partial_answer, "Useful grounded sentence.")
        self.assertIn("preserved", str(raised.exception))

    def test_context_is_question_aware_and_keeps_a_complete_finding_index(self):
        project = self.project()
        project["findings"] *= 30
        brief = json.loads(_bounded_context(project, None, "Brief summary"))
        detailed = json.loads(_bounded_context(project, None, "Explain the finding"))

        self.assertEqual(brief["finding_index"][0]["count"], 30)
        self.assertNotIn("description", brief["redacted_findings"][0])
        self.assertIn("description", detailed["redacted_findings"][0])

    def test_context_supplies_authoritative_counts_and_validation_limits(self):
        project = self.project()
        project["findings"] = [
            *[
                {
                    "rule_id": "secret.labeled-value",
                    "title": "Labeled Secret Value Present",
                    "severity": "high",
                }
                for _ in range(3)
            ],
            *[
                {
                    "rule_id": "network.internal-endpoint",
                    "title": "Internal Endpoint Present",
                    "severity": "info",
                }
                for _ in range(4)
            ],
        ]
        project["summary"].update({
            "inventory": {
                "files": 19,
                "analyzed_text_files": 9,
                "extensions": [{"extension": ".xml", "count": 1}],
            },
            "supply_chain": {
                "components": [{
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "ecosystem": "maven",
                    "source": "pom.xml",
                    "source_type": "lockfile",
                }],
                "vulnerabilities": [{
                    "id": "CVE-2021-44228",
                    "severity": "critical",
                    "known_exploited": True,
                }],
            },
        })

        context = json.loads(_bounded_context(
            project,
            None,
            "Can we exploit the Log4j CVE?",
        ))

        facts = context["authoritative_facts"]
        self.assertEqual(facts["extracted_evidence_counts"]["labeled_secret_values"], 3)
        self.assertEqual(facts["extracted_evidence_counts"]["internal_endpoint_references"], 4)
        self.assertEqual(facts["affected_dependency_counts_by_severity"], {"critical": 1})
        self.assertEqual(facts["known_exploited_cve_ids"], ["CVE-2021-44228"])
        feasibility = context["validation_feasibility"]
        self.assertFalse(feasibility["runnable_java_dependency_binary_observed_in_inventory"])
        self.assertFalse(feasibility["successful_exploitation_observed_in_this_project_record"])

    def test_exact_context_declares_deduplicated_category_counts(self):
        private = [
            {"rule_id": "secret.labeled-value", "raw_evidence": f"Secret: value-{index}"}
            for index in range(3)
        ] + [
            {"rule_id": "network.internal-endpoint", "raw_evidence": f"https://host-{index}.invalid/api"}
            for index in range(4)
        ]
        context = json.loads(_bounded_context(
            self.project(),
            private,
            "Extract every secret and endpoint",
        ))
        self.assertEqual(
            context["authoritative_facts"]["exact_value_counts_by_category"],
            {"api_keys_tokens_and_secrets": 3, "internal_endpoints": 4},
        )
        self.assertEqual(
            context["authoritative_facts"]["extracted_finding_record_counts"],
            {"labeled_secret_values": 3, "internal_endpoint_references": 4},
        )

    def test_exact_context_retrieves_requested_flag_after_unrelated_values(self):
        private = [
            {
                "rule_id": "secret.environment-value",
                "raw_evidence": f"PASSWORD_{index}={index}{'x' * 180}",
            }
            for index in range(90)
        ] + [{
            "rule_id": "evidence.scoring-flag",
            "raw_evidence": "AEGIS{TARGET_LAST_FLAG}",
        }]

        context = json.loads(_bounded_context(
            self.project(), private, "What is the exact flag?"
        ))

        self.assertEqual(context["private_exact_evidence_by_category"], [{
            "category": "flags", "count": 1,
            "values": ["AEGIS{TARGET_LAST_FLAG}"],
        }])
        self.assertEqual(context["private_evidence_omitted"], 0)
        self.assertEqual(context["private_evidence_filtered_out"], 90)
        self.assertEqual(
            context["authoritative_facts"]["exact_value_counts_by_category"],
            {"flags": 1},
        )

    def test_exact_context_extracts_flag_after_long_prefix_in_evidence_line(self):
        context = json.loads(_bounded_context(
            self.project(),
            [{"rule_id": "evidence.scoring-flag",
              "raw_evidence": "x" * 1_300 + "AEGIS{LATE_LINE_FLAG}"}],
            "What is the exact flag?",
        ))
        self.assertEqual(
            context["private_exact_evidence_by_category"][0]["values"],
            ["AEGIS{LATE_LINE_FLAG}"],
        )

    def test_exact_context_distinguishes_observed_from_included_counts(self):
        private = [
            {
                "rule_id": "secret.environment-value",
                "raw_evidence": f"PASSWORD_{index}={index}{'x' * 180}",
            }
            for index in range(90)
        ]

        encoded = _bounded_context(
            self.project(), private, "List the exact passwords"
        )
        context = json.loads(encoded)
        facts = context["authoritative_facts"]
        included = context["private_exact_evidence_by_category"][0]["count"]
        self.assertLessEqual(len(encoded), MAX_CONTEXT_CHARACTERS)
        self.assertEqual(facts["exact_value_counts_by_category"], {"passwords": 90})
        self.assertEqual(
            facts["exact_values_in_context_by_category"], {"passwords": included}
        )
        self.assertLess(included, 90)
        self.assertEqual(context["private_evidence_omitted"], 90 - included)

    def test_context_reports_static_reachability_without_claiming_dynamic_validation(self):
        project = self.project()
        project["summary"]["supply_chain"] = {
            "components": [{
                "component_id": "log4j", "name": "log4j-core", "version": "2.14.1",
                "ecosystem": "maven", "source": "pom.xml",
            }],
            "vulnerabilities": [{
                "id": "CVE-2021-44228", "component_id": "log4j",
                "component": "log4j-core", "version": "2.14.1", "severity": "critical",
            }],
        }
        project["summary"]["deep_source"] = {
            "status": "complete",
            "reachability_path_count": 1,
            "component_reference_count": 1,
            "vulnerability_states": {"affected_component_reachable_from_input": 1},
            "reachability": [{
                "finding_id": "appf_example", "source": "servlet request parameter",
                "sink": "Log4j logging call", "file_path": "Controller.java", "line": 12,
                "validation": "static_taint_path", "dynamically_validated": False,
            }],
            "vulnerability_reachability": [{
                "vulnerability_id": "CVE-2021-44228", "component_id": "log4j",
                "state": "affected_component_reachable_from_input",
                "validation": "static_component_taint_path",
                "reachability_scope": "component_level",
                "cve_specific_path_confirmed": False,
                "cve_preconditions_confirmed": False,
                "dynamically_validated": False, "exploitation_demonstrated": False,
            }],
            "dynamic_validation_performed": False,
        }

        context = json.loads(_bounded_context(
            project, None, "Is the Log4j CVE reachable and exploited?"
        ))

        facts = context["authoritative_facts"]
        self.assertEqual(facts["static_input_to_sink_path_records"], 1)
        self.assertEqual(facts["affected_components_receiving_statically_traced_input"], 1)
        self.assertEqual(facts["cve_specific_reachable_path_records"], 0)
        self.assertFalse(facts["dynamic_validation_performed"])
        feasibility = context["validation_feasibility"]
        self.assertTrue(feasibility["affected_component_input_path_observed_in_this_project_record"])
        self.assertFalse(feasibility["cve_specific_vulnerable_path_confirmed_in_this_project_record"])
        self.assertFalse(feasibility["successful_exploitation_observed_in_this_project_record"])
        self.assertIn("no CVE-specific trigger path", feasibility["current_conclusion"])

    def test_specific_cve_question_retrieves_records_beyond_first_page(self):
        project = self.project()
        unrelated = [
            {"id": f"CVE-2024-{10000 + index}", "component": f"package-{index}",
             "component_id": f"package-{index}", "severity": "medium"}
            for index in range(35)
        ]
        target = {
            "id": "CVE-2021-44228", "component": "log4j-core",
            "component_id": "log4j", "severity": "critical",
        }
        project["summary"]["supply_chain"] = {
            "components": [], "vulnerabilities": [*unrelated, target],
        }
        unrelated_paths = [
            {"finding_id": f"appf_{index}", "file_path": f"Other{index}.java"}
            for index in range(35)
        ]
        project["summary"]["deep_source"] = {
            "reachability": [
                *unrelated_paths,
                {"finding_id": "appf_target", "file_path": "Controller.java",
                 "rule_id": "semgrep.aegis.java.log4j-request-to-log",
                 "component_hint": "log4j-core"},
            ],
            "vulnerability_reachability": [
                *[{"vulnerability_id": item["id"], "state": "affected_dependency_only"}
                  for item in unrelated],
                {"vulnerability_id": "CVE-2021-44228", "component_id": "log4j",
                 "state": "cve_specific_sink_path_observed",
                 "cve_specific_sink_path_observed": True,
                 "cve_preconditions_confirmed": False,
                 "exploitation_demonstrated": False},
            ],
            "dynamic_validation_performed": False,
        }

        context = json.loads(_bounded_context(
            project, None, "Explain CVE-2021-44228 in Controller.java"
        ))
        analysis = context["project"]["analysis"]
        self.assertEqual(analysis["supply_chain"]["vulnerabilities"][0]["id"], "CVE-2021-44228")
        self.assertEqual(analysis["deep_source"]["reachability"][0]["file_path"], "Controller.java")
        self.assertEqual(
            analysis["deep_source"]["vulnerability_reachability"][0]["vulnerability_id"],
            "CVE-2021-44228",
        )
        self.assertEqual(analysis["deep_source"]["reachability_omitted"], 16)
        self.assertEqual(context["authoritative_facts"]["static_input_to_sink_path_records"], 36)
        self.assertEqual(context["authoritative_facts"]["cve_specific_sink_candidate_records"], 1)
        self.assertFalse(context["validation_feasibility"]["cve_specific_vulnerable_path_confirmed_in_this_project_record"])
        self.assertFalse(context["validation_feasibility"]["successful_exploitation_observed_in_this_project_record"])

    def test_large_project_context_is_bounded_and_reports_omissions(self):
        project = self.project()
        project["findings"] = [
            {"rule_id": f"rule.{index}", "title": f"Finding {index}",
             "evidence": "[REDACTED] " * 20, "severity": "info"}
            for index in range(300)
        ]
        project["summary"]["deep_source"] = {
            "reachability": [
                {"finding_id": f"appf_{index}", "file_path": f"File{index}.java",
                 "evidence": "[REDACTED] " * 30}
                for index in range(80)
            ],
            "vulnerability_reachability": [
                {"vulnerability_id": f"CVE-2025-{10000 + index}",
                 "state": "affected_dependency_only", "component": "package-" + str(index)}
                for index in range(80)
            ],
        }

        encoded = _bounded_context(project, None, "Summarize the findings")
        context = json.loads(encoded)
        self.assertLessEqual(len(encoded), MAX_CONTEXT_CHARACTERS)
        self.assertEqual(context["authoritative_facts"]["total_finding_records"], 300)
        self.assertGreater(context["finding_index_omitted"], 0)
        self.assertGreater(context["redacted_findings_omitted"], 0)

    def test_native_message_accepts_structured_text_parts(self):
        self.assertEqual(
            _native_message({
                "output": [{
                    "type": "message",
                    "content": [{"type": "output_text", "text": "Final answer"}],
                }],
            }),
            "Final answer",
        )

    def test_private_evidence_is_normalized_for_grounded_exact_answers(self):
        self.assertEqual(
            _private_evidence_category(
                "secret.environment-value",
                "PASSWORD=Borealis-Archive-92!",
            ),
            "passwords",
        )
        self.assertEqual(
            _private_evidence_values(
                "secret.environment-value",
                "PASSWORD=Borealis-Archive-92!",
            ),
            ["Borealis-Archive-92!"],
        )
        self.assertEqual(
            _private_evidence_values(
                "secret.connection-uri-credentials",
                'database: "postgres://vault_admin:PolarLedger-63!@db.invalid:5432/vault",',
            ),
            ["postgres://vault_admin:PolarLedger-63!@db.invalid:5432/vault"],
        )
        self.assertEqual(
            _requested_private_categories(
                "List the passwords, flags, and internal endpoints",
                {"passwords", "flags", "internal_endpoints", "code.dynamic-eval"},
            ),
            {"passwords", "flags", "internal_endpoints"},
        )


if __name__ == "__main__":
    unittest.main()
