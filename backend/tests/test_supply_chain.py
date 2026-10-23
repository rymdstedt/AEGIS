import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from agent import risk
from application.service import ApplicationResearchService
from application.supply_chain import _normalize, analyze_supply_chain, build_cyclonedx
from evidence_graph import build_scan_evidence_graph, graph_digest


class SupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def osv_payload() -> dict:
        return {
            "results": [{
                "source": {"path": "requirements.txt", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "django", "version": "2.2.0", "ecosystem": "PyPI"},
                    "groups": [{
                        "ids": ["PYSEC-2019-10", "GHSA-6c7v-2f49-8h26"],
                        "aliases": ["CVE-2019-12781", "PYSEC-2019-10", "GHSA-6c7v-2f49-8h26"],
                        "max_severity": "6.9",
                    }],
                    "vulnerabilities": [{
                        "id": "PYSEC-2019-10",
                        "aliases": ["CVE-2019-12781", "GHSA-6c7v-2f49-8h26"],
                        "summary": "Django proxy redirect issue",
                        "affected": [{"ranges": [{"events": [{"introduced": "2.2"}, {"fixed": "2.2.3"}]}]}],
                        "references": [{"url": "https://osv.dev/vulnerability/PYSEC-2019-10"}],
                    }],
                }],
            }],
        }

    def test_osv_alias_group_becomes_one_component_and_one_vulnerability(self):
        (self.root / "requirements.txt").write_text("Django==2.2.0\n", encoding="utf-8")
        payload = self.osv_payload()
        payload["results"][0]["source"]["path"] = str(self.root / "requirements.txt")

        components, vulnerabilities = _normalize(payload, self.root, "app_" + "1" * 32)

        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["purl"], "pkg:pypi/django@2.2.0")
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]["id"], "CVE-2019-12781")
        self.assertEqual(vulnerabilities[0]["fixed_versions"], ["2.2.3"])
        self.assertEqual(vulnerabilities[0]["severity"], "medium")

        sbom = build_cyclonedx("app_" + "1" * 32, "fixture", components, vulnerabilities)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.6")
        self.assertEqual(len(sbom["components"]), 1)
        self.assertEqual(len(sbom["vulnerabilities"]), 1)

    def test_risk_enrichment_combines_kev_and_epss_without_claiming_exploit(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "known_exploited" in str(request.url):
                return httpx.Response(200, json={"vulnerabilities": [{
                    "cveID": "CVE-2021-44228",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                    "requiredAction": "Apply updates per vendor instructions.",
                }]})
            return httpx.Response(200, json={"data": [{
                "cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.999",
            }]})

        item = {"id": "GHSA-test", "aliases": ["CVE-2021-44228"], "cvss": 10.0}
        client = httpx.Client(transport=httpx.MockTransport(handler))
        with patch.object(risk, "_kev_cache", None), patch.object(risk, "_epss_cache", {}):
            result = risk.enrich_cve_items([item], client=client)
        client.close()

        self.assertEqual(result["status"], "complete")
        self.assertTrue(item["known_exploited"])
        self.assertEqual(item["epss"], 0.975)
        self.assertEqual(item["risk_priority"], "urgent")
        self.assertIn("listed in CISA KEV", item["risk_reasons"])

    def test_supply_chain_project_persists_graph_and_resolves_sbom(self):
        source = self.root / "source"
        source.mkdir()
        (source / "requirements.txt").write_text("safe-package==1.0\n", encoding="utf-8")
        service = ApplicationResearchService(self.root / "data")
        imported = service.import_path(str(source))

        def fake_analysis(_root, project_id, _name, output_path):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}\n', encoding="utf-8")
            component = {
                "component_id": "component-1", "name": "safe-package", "version": "1.0",
                "ecosystem": "PyPI", "source": "requirements.txt", "purl": "pkg:pypi/safe-package@1.0",
            }
            vulnerability = {
                "id": "CVE-2025-9999", "component_id": "component-1", "component": "safe-package",
                "version": "1.0", "ecosystem": "PyPI", "source": "requirements.txt",
                "severity": "high", "cvss": 8.0, "known_exploited": False,
            }
            finding = {
                "id": "appf_" + "2" * 20,
                "rule_id": "dependency.osv.cve-2025-9999", "severity": "high",
                "confidence": "high", "status": "affected_dependency",
                "title": "Affected dependency", "description": "Affected locked version.",
                "file_path": "requirements.txt", "line": None,
                "evidence": "safe-package@1.0 matched CVE-2025-9999",
                "remediation": "Upgrade.", "vulnerability_id": "CVE-2025-9999",
                "component_id": "component-1",
            }
            return ({
                "status": "complete", "analyzer": "OSV-Scanner", "component_count": 1,
                "vulnerability_count": 1, "components": [component],
                "vulnerabilities": [vulnerability], "limitations": [],
                "sbom": {"available": True, "format": "CycloneDX", "spec_version": "1.6"},
            }, [finding])

        with patch("application.service.analyze_supply_chain", side_effect=fake_analysis):
            analyzed = service.analyze_project(imported["id"], "supply_chain")

        self.assertEqual(analyzed["summary"]["analysis_profile"], "static_and_supply_chain")
        self.assertEqual(analyzed["summary"]["finding_counts"]["high"], 1)
        graph = analyzed["summary"]["evidence_graph"]
        self.assertEqual(graph["schema"], "aegis-evidence-graph/v1")
        self.assertEqual(graph["stats"]["kinds"]["component"], 1)
        self.assertEqual(graph["stats"]["kinds"]["vulnerability"], 1)
        self.assertEqual(graph_digest(graph), graph_digest(json.loads(json.dumps(graph))))
        path, filename = service.get_sbom_path(imported["id"])
        self.assertTrue(path.is_file())
        self.assertTrue(filename.endswith("-sbom.cdx.json"))
        self.assertEqual(json.loads(path.read_text())["specVersion"], "1.6")

    def test_single_file_snapshot_uses_parent_as_scanner_working_directory(self):
        snapshot = self.root / "analyzer.py"
        snapshot.write_text("print('not executed')\n", encoding="utf-8")
        output = self.root / "reports" / "sbom.cdx.json"
        observed: dict[str, object] = {}

        def fake_popen(command, **kwargs):
            observed["command"] = command
            observed["cwd"] = kwargs["cwd"]
            kwargs["stdout"].write(json.dumps({
                "results": [{
                    "source": {"path": str(snapshot), "type": "lockfile"},
                    "packages": [{
                        "package": {
                            "name": "single-file-package",
                            "version": "1.0",
                            "ecosystem": "PyPI",
                        },
                        "groups": [],
                        "vulnerabilities": [],
                    }],
                }],
            }).encode())
            return SimpleNamespace(poll=lambda: 0, wait=lambda timeout: 0)

        with (
            patch("application.supply_chain.find_osv_scanner", return_value="/usr/bin/osv-scanner"),
            patch("application.supply_chain.subprocess.Popen", side_effect=fake_popen),
            patch("application.supply_chain.enrich_cve_items", return_value={"status": "not_applicable"}),
        ):
            summary, findings = analyze_supply_chain(
                snapshot,
                "app_" + "3" * 32,
                "analyzer.py",
                output,
            )

        self.assertEqual(observed["cwd"], snapshot.resolve().parent)
        self.assertEqual(observed["command"][-1], str(snapshot.resolve()))
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["components"][0]["source"], "analyzer.py")
        self.assertEqual(findings, [])
        self.assertTrue(output.is_file())

    def test_live_graph_records_access_without_copying_secret_values(self):
        state = SimpleNamespace(
            target="127.0.0.1",
            discovered_hosts=["127.0.0.1"],
            host_ports={"127.0.0.1": {443}},
            host_services={"127.0.0.1": {443: "https"}},
            confirmed_service_ports={"127.0.0.1": {443}},
            findings=[], cve_research={}, cve_product_searches={}, tool_history=[],
            profile={"products": []},
            loot=[{"type": "credentials", "username": "admin", "password": "do-not-copy-me", "service": "https", "source": "fixture"}],
        )

        graph = build_scan_evidence_graph(state)
        encoded = json.dumps(graph)

        self.assertNotIn("do-not-copy-me", encoded)
        self.assertNotIn("admin", encoded)
        access = next(node for node in graph["nodes"] if node["kind"] == "access_artifact")
        self.assertTrue(access["properties"]["contains_secret"])


if __name__ == "__main__":
    unittest.main()
