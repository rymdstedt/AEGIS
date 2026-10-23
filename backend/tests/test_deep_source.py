import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
import yaml
from application.deep_source import (
    LOG4J_REQUEST_TO_LOG_RULE,
    SEMGREP_RULES,
    ToolRun,
    analyze_deep_source,
    correlate_vulnerabilities,
    find_semgrep,
    map_component_references,
    normalize_gitleaks,
    normalize_semgrep,
)
from application.service import ApplicationResearchService


class DeepSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.project_id = "app_" + "4" * 32

    def tearDown(self):
        self.temporary.cleanup()

    def test_bundled_semgrep_rules_are_local_taint_rules(self):
        payload = yaml.safe_load(SEMGREP_RULES)
        rules = payload["rules"]
        self.assertGreaterEqual(len(rules), 10)
        self.assertTrue(all(item["mode"] == "taint" for item in rules))
        self.assertTrue(all(item["metadata"]["aegis"]["kind"] == "reachability" for item in rules))

    def test_log4j_rule_excludes_other_logger_with_same_class_names(self):
        if not find_semgrep():
            self.skipTest("Semgrep is not installed")
        fixture = Path(__file__).resolve().parents[2] / "lab" / "application_reachability_fixture"
        with patch("application.deep_source.find_gitleaks", return_value=None):
            summary, _findings, _private = analyze_deep_source(
                fixture, self.project_id, self.root / "reports", [], None
            )
        self.assertEqual(summary["analyzers"]["semgrep"]["status"], "complete")
        matched_files = {
            path["file_path"] for path in summary["reachability"]
            if path["rule_id"] == LOG4J_REQUEST_TO_LOG_RULE
        }
        self.assertEqual(matched_files, {"Controller.java"})

    def test_semgrep_normalization_redacts_public_source_and_records_path(self):
        secret = "private-value-that-must-stay-local"  # noqa: S105 - synthetic fixture
        source_file = self.source / "server.py"
        source_file.write_text("print('fixture')\n", encoding="utf-8")
        payload = {
            "results": [{
                "check_id": "aegis.python.request-to-command",
                "path": "server.py",
                "start": {"line": 7, "col": 1},
                "extra": {
                    "message": "request data reaches a command",
                    "severity": "ERROR",
                    "lines": f'password = "{secret}"',
                    "metadata": {
                        "aegis": {
                            "kind": "reachability",
                            "source": "web request input",
                            "sink": "operating-system command execution",
                            "severity": "critical",
                        }
                    },
                },
            }],
            "errors": [],
        }

        findings, private, paths = normalize_semgrep(
            payload, self.source, self.source, self.project_id
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "reachable_from_input")
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertNotIn(secret, json.dumps(findings))
        self.assertIn("[REDACTED]", findings[0]["evidence"])
        self.assertIn(secret, private[0]["raw_evidence"])
        self.assertEqual(paths[0]["validation"], "static_taint_path")
        self.assertFalse(paths[0]["dynamically_validated"])

    def test_gitleaks_exact_secret_is_private_and_built_in_duplicate_is_merged(self):
        secret = "glpat-super-secret-value"  # noqa: S105 - synthetic fixture
        (self.source / "config.js").write_text("fixture\n", encoding="utf-8")
        payload = [{
            "RuleID": "gitlab-pat",
            "Description": "GitLab personal access token",
            "File": "config.js",
            "StartLine": 3,
            "Match": f'token = "{secret}"',
            "Secret": secret,
        }]
        findings, private, duplicates = normalize_gitleaks(
            payload, self.source, self.source, self.project_id, []
        )
        self.assertEqual(duplicates, 0)
        self.assertEqual(len(findings), 1)
        self.assertNotIn(secret, json.dumps(findings))
        self.assertIn(secret, private[0]["raw_evidence"])

        existing = [{
            "rule_id": "secret.hardcoded-assignment",
            "file_path": "config.js",
            "line": 3,
        }]
        deduped, private_deduped, duplicates = normalize_gitleaks(
            payload, self.source, self.source, self.project_id, existing
        )
        self.assertEqual(deduped, [])
        self.assertEqual(private_deduped, [])
        self.assertEqual(duplicates, 1)

    def test_component_import_and_log4j_taint_upgrade_vulnerability_state(self):
        java = self.source / "Controller.java"
        java.write_text(
            "import org.apache.logging.log4j.LogManager;\n"
            "import org.apache.logging.log4j.Logger;\n",
            encoding="utf-8",
        )
        component = {
            "component_id": "component-log4j",
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "ecosystem": "Maven",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        }
        supply = {
            "components": [component],
            "vulnerabilities": [{
                "id": "CVE-2021-44228",
                "component_id": "component-log4j",
                "component": component["name"],
                "version": component["version"],
            }],
        }
        references, coverage = map_component_references(self.source, supply)
        self.assertGreaterEqual(len(references), 1)
        self.assertEqual(coverage["files"], 1)
        paths = [{
            "finding_id": "appf_" + "a" * 20,
            "component_hint": "log4j-core",
        }]
        correlated = correlate_vulnerabilities(supply, references, paths)
        self.assertEqual(
            correlated[0]["state"], "affected_component_reachable_from_input"
        )
        self.assertEqual(correlated[0]["validation"], "static_component_taint_path")
        self.assertFalse(correlated[0]["cve_specific_path_confirmed"])
        self.assertFalse(correlated[0]["cve_preconditions_confirmed"])
        self.assertFalse(correlated[0]["exploitation_demonstrated"])

    def test_log4shell_static_sink_candidate_does_not_claim_exploitation(self):
        component = {
            "component_id": "log4j", "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1", "ecosystem": "Maven",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        }
        path = {
            "finding_id": "appf_" + "b" * 20,
            "rule_id": "semgrep.aegis.java.log4j-request-to-log",
            "validation": "static_taint_path",
            "component_hint": "log4j-core",
            "source": "servlet request parameter",
            "sink": "Log4j logging call",
        }
        supply = {
            "components": [component],
            "vulnerabilities": [{
                "id": "CVE-2021-44228", "component_id": "log4j",
                "component": component["name"], "version": "2.14.1",
            }],
        }
        result = correlate_vulnerabilities(supply, [], [path])[0]
        self.assertEqual(result["state"], "cve_specific_sink_path_observed")
        self.assertEqual(result["validation"], "static_cve_specific_sink_candidate")
        self.assertEqual(result["cve_specific_sink_finding_ids"], [path["finding_id"]])
        self.assertTrue(result["cve_specific_sink_path_observed"])
        self.assertTrue(result["preconditions_not_verified"])
        self.assertFalse(result["cve_specific_path_confirmed"])
        self.assertFalse(result["cve_preconditions_confirmed"])
        self.assertFalse(result["dynamically_validated"])
        self.assertFalse(result["exploitation_demonstrated"])

        earlier_paths = [
            {"finding_id": f"appf_generic_{index}",
             "rule_id": "semgrep.aegis.java.other-component-rule",
             "validation": "static_taint_path", "component_hint": "log4j-core"}
            for index in range(8)
        ]
        late_result = correlate_vulnerabilities(supply, [], [*earlier_paths, path])[0]
        self.assertTrue(late_result["cve_specific_sink_path_observed"])
        self.assertEqual(late_result["reachability_finding_ids"][0], path["finding_id"])
        self.assertEqual(late_result["cve_specific_sink_path_count"], 1)

        supply["vulnerabilities"][0]["id"] = "CVE-2021-45046"
        other_cve = correlate_vulnerabilities(supply, [], [path])[0]
        self.assertFalse(other_cve["cve_specific_sink_path_observed"])
        self.assertEqual(other_cve["state"], "affected_component_reachable_from_input")

        supply["vulnerabilities"][0]["id"] = "CVE-2021-44228"
        component["name"] = "example:unrelated-log4j-core-wrapper"
        component["purl"] = "pkg:maven/example/unrelated-log4j-core-wrapper@1.0"
        unrelated = correlate_vulnerabilities(supply, [], [path])[0]
        self.assertFalse(unrelated["cve_specific_sink_path_observed"])

    def test_deep_analyzers_are_bounded_and_do_not_use_project_configuration(self):
        secret = "ghp_fixture_private_token_value"  # noqa: S105 - synthetic fixture
        (self.source / "app.py").write_text("from flask import request\n", encoding="utf-8")
        reports = self.root / "reports"

        semgrep_payload = {
            "results": [{
                "check_id": "aegis.python.request-to-command",
                "path": "app.py",
                "start": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "source reaches sink",
                    "lines": "os.system(request.args.get('cmd'))",
                    "metadata": {"aegis": {
                        "kind": "reachability", "source": "web request input",
                        "sink": "operating-system command execution", "severity": "critical",
                    }},
                },
            }],
            "errors": [],
        }

        def fake_run(command, _cwd, _timeout, watched_paths=(), environment_overrides=None):
            if "semgrep" in Path(command[0]).name:
                return ToolRun(0, json.dumps(semgrep_payload).encode(), b"", 0.1)
            report = Path(command[command.index("--report-path") + 1])
            report.write_text(json.dumps([{
                "RuleID": "github-pat", "Description": "GitHub token",
                "File": "app.py", "StartLine": 2,
                "Match": f'token = "{secret}"', "Secret": secret,
            }]), encoding="utf-8")
            return ToolRun(0, b"", b"", 0.1)

        with (
            patch("application.deep_source.find_semgrep", return_value="/usr/bin/semgrep"),
            patch("application.deep_source.find_gitleaks", return_value="/usr/bin/gitleaks"),
            patch("application.deep_source._run_bounded", side_effect=fake_run),
        ):
            summary, findings, private = analyze_deep_source(
                self.source, self.project_id, reports, [], None
            )

        self.assertEqual(summary["status"], "complete")
        self.assertFalse(summary["artifact_executed"])
        self.assertFalse(summary["project_analyzer_configuration_used"])
        self.assertEqual(summary["reachability_path_count"], 1)
        self.assertEqual(len(findings), 2)
        self.assertNotIn(secret, json.dumps(summary))
        self.assertNotIn(secret, json.dumps(findings))
        self.assertIn(secret, json.dumps(private))

    def test_service_profile_persists_deep_findings_private_evidence_and_graph(self):
        source_file = self.source / "server.py"
        source_file.write_text("print('fixture')\n", encoding="utf-8")
        service = ApplicationResearchService(self.root / "data")
        imported = service.import_path(str(self.source))
        dependency_finding = {
            "id": "appf_" + "1" * 20,
            "rule_id": "dependency.osv.cve-2025-1111",
            "severity": "high", "confidence": "high",
            "status": "affected_dependency", "title": "Affected dependency",
            "description": "Version match only.", "file_path": "requirements.txt",
            "line": None, "evidence": "package@1 matched CVE-2025-1111",
            "remediation": "Upgrade.", "vulnerability_id": "CVE-2025-1111",
            "component_id": "component-1",
        }
        supply = {
            "status": "complete", "component_count": 1, "vulnerability_count": 1,
            "components": [{
                "component_id": "component-1", "name": "package", "version": "1",
                "ecosystem": "PyPI", "source": "requirements.txt", "purl": "pkg:pypi/package@1",
            }],
            "vulnerabilities": [{
                "id": "CVE-2025-1111", "component_id": "component-1",
                "component": "package", "version": "1", "severity": "high",
            }],
            "limitations": [],
            "sbom": {"available": False},
        }
        deep_finding_id = "appf_" + "2" * 20
        deep = {
            "status": "complete", "artifact_executed": False,
            "finding_count": 1, "reachability_path_count": 1,
            "component_reference_count": 0, "component_references": [],
            "analyzers": {"semgrep": {"analyzer": "Semgrep CE", "status": "complete"}},
            "reachability": [{
                "finding_id": deep_finding_id, "file_path": "server.py", "line": 1,
                "source": "web input", "sink": "command execution",
                "validation": "static_taint_path", "dynamically_validated": False,
            }],
            "vulnerability_reachability": [], "limitations": [],
        }
        deep_finding = {
            "id": deep_finding_id, "rule_id": "semgrep.test", "severity": "critical",
            "confidence": "high", "status": "reachable_from_input",
            "title": "Static input path", "description": "Static only.",
            "file_path": "server.py", "line": 1, "evidence": "[REDACTED]",
            "remediation": "Validate input.",
        }

        def fake_supply(_root, _project_id, _name, output_path):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("{}", encoding="utf-8")
            return supply, [dependency_finding]

        with (
            patch("application.service.analyze_supply_chain", side_effect=fake_supply),
            patch("application.service.analyze_deep_source", return_value=(
                deep, [deep_finding], [{"finding_id": deep_finding_id, "raw_evidence": "exact private line"}]
            )),
        ):
            analyzed = service.analyze_project(imported["id"], "deep_source")

        self.assertEqual(analyzed["summary"]["analysis_profile"], "deep_source_and_supply_chain")
        self.assertEqual(analyzed["summary"]["finding_counts"]["critical"], 1)
        persisted = service.get_private_finding(imported["id"], deep_finding_id)
        self.assertEqual(persisted["raw_evidence"], "exact private line")
        graph_kinds = analyzed["summary"]["evidence_graph"]["stats"]["kinds"]
        self.assertEqual(graph_kinds["input"], 1)
        self.assertEqual(graph_kinds["sink"], 1)

    def test_api_schema_accepts_deep_source_profile(self):
        request = main.ApplicationAnalyzeRequest(profile="deep_source")
        self.assertEqual(request.profile, "deep_source")


if __name__ == "__main__":
    unittest.main()
