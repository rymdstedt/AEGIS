import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from agent.core import (
    PentestAgent,
    ScanState,
    _deprecated_tls_evidence_lines,
    _weak_tls_cipher_evidence_lines,
)
from agent.cve import (
    correlate_cve,
    extract_cve_ids,
    extract_product_fingerprints,
    fetch_cve_record,
    normalize_cve_record,
    search_cve_candidates,
    search_nvd_candidates,
)
from agent.scope import ScopePolicy, parse_target
from tools.executor import _web_identity_records


def siemens_record(*, less_than="*"):
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": "CVE-2025-40833",
            "state": "PUBLISHED",
            "datePublished": "2026-05-12T00:00:00Z",
            "dateUpdated": "2026-08-11T00:00:00Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "Siemens AG"},
                "descriptions": [{
                    "lang": "en",
                    "value": "A crafted IPv4 request can cause denial of service and require a manual restart.",
                }],
                "affected": [{
                    "vendor": "Siemens",
                    "product": "SCALANCE X204-2",
                    "defaultStatus": "unknown",
                    "versions": [{
                        "version": "0",
                        "lessThan": less_than,
                        "versionType": "custom",
                        "status": "affected",
                    }],
                }],
                "metrics": [{"cvssV4_0": {
                    "baseScore": 8.7,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VA:H",
                }}],
                "problemTypes": [{"descriptions": [{
                    "lang": "en", "cweId": "CWE-476", "description": "NULL Pointer Dereference",
                }]}],
                "references": [{
                    "url": "https://cert-portal.siemens.com/productcert/html/ssa-392349.html",
                }],
            }
        },
    }


class CveHelpersTests(unittest.IsolatedAsyncioTestCase):
    def test_extracts_and_canonicalizes_scope_cves(self):
        self.assertEqual(
            extract_cve_ids("check cve-2025-40833 and CVE-2024-1234; repeat CVE-2025-40833"),
            ["CVE-2025-40833", "CVE-2024-1234"],
        )

    def test_cve_digits_do_not_become_a_port_scope(self):
        policy = ScopePolicy.from_notes(
            parse_target("192.0.2.10"),
            "Identify the device and investigate CVE-2025-40833",
        )
        self.assertFalse(policy.ports_restricted)
        self.assertFalse(policy.allowed_ports)

    def test_normalizes_official_record_and_marks_dos(self):
        record = normalize_cve_record(siemens_record())
        self.assertEqual(record["cve_id"], "CVE-2025-40833")
        self.assertEqual(record["affected_count"], 1)
        self.assertEqual(record["cvss"]["score"], 8.7)
        self.assertTrue(record["availability_impact"])

    def test_all_versions_product_match_is_potentially_affected(self):
        record = normalize_cve_record(siemens_record())
        correlation = correlate_cve(record, [{
            "vendor": "Siemens",
            "product": "SCALANCE X204-2",
            "version": "",
            "evidence": "SCALANCE X204-2",
        }])
        self.assertEqual(correlation["status"], "potentially_affected")

    def test_record_without_observed_identity_is_not_a_product_match(self):
        correlation = correlate_cve(normalize_cve_record(siemens_record()), [])
        self.assertEqual(correlation["status"], "no_identity")
        self.assertFalse(correlation["matches"])

    def test_version_range_can_rule_out_fixed_release(self):
        record = normalize_cve_record(siemens_record(less_than="V3.2"))
        affected = correlate_cve(record, [{
            "vendor": "Siemens", "product": "SCALANCE X204-2", "version": "3.1",
        }])
        fixed = correlate_cve(record, [{
            "vendor": "Siemens", "product": "SCALANCE X204-2", "version": "3.2",
        }])
        self.assertEqual(affected["status"], "potentially_affected")
        self.assertEqual(fixed["status"], "observed_version_not_affected")

    def test_web_identity_fingerprint_is_evidence_backed(self):
        line = json.dumps({
            "type": "web_identity",
            "vendor": "Siemens",
            "product": "SCALANCE X204-2",
            "version": "2.1",
            "title": "SCALANCE X204-2",
            "confidence": "high",
        })
        fingerprints = extract_product_fingerprints("web_assess", line)
        self.assertTrue(any(item["product"] == "SCALANCE X204-2" for item in fingerprints))

    def test_management_page_extracts_siemens_product_without_page_contents(self):
        records = _web_identity_records(
            "<html><title>SCALANCE X204-2 Management</title>"
            "<body>Siemens SCALANCE X204-2 Firmware V3.1 secret=do-not-emit</body></html>",
            {"server": "embedded"},
        )
        self.assertEqual(records[0]["vendor"], "Siemens")
        self.assertEqual(records[0]["product"], "SCALANCE X204-2")
        self.assertEqual(records[0]["version"], "3.1")
        self.assertNotIn("secret", json.dumps(records))

    async def test_fetch_uses_official_cve_service(self):
        async def handler(request):
            self.assertEqual(request.url.host, "cveawg.mitre.org")
            return httpx.Response(200, json=siemens_record())

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            record = await fetch_cve_record("CVE-2025-40833", client=client)
        self.assertEqual(record["source"], "CVE Services API")

    async def test_nvd_keyword_results_remain_candidates(self):
        response = {
            "totalResults": 1,
            "vulnerabilities": [{"cve": {
                "id": "CVE-2025-40833",
                "published": "2026-05-12",
                "lastModified": "2026-08-11",
                "descriptions": [{"lang": "en", "value": "SCALANCE availability issue"}],
                "metrics": {},
            }}],
        }

        async def handler(request):
            self.assertEqual(request.url.host, "services.nvd.nist.gov")
            return httpx.Response(200, json=response)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await search_nvd_candidates("Siemens SCALANCE X204-2", client=client)
        self.assertEqual(result["candidates"][0]["cve_id"], "CVE-2025-40833")

    async def test_circl_exact_product_fills_nvd_mapping_gap(self):
        requested_hosts = []

        async def handler(request):
            requested_hosts.append(request.url.host)
            if request.url.host == "services.nvd.nist.gov":
                self.fail("NVD fallback should not run when the exact product index has matches")
            self.assertEqual(request.url.host, "vulnerability.circl.lu")
            self.assertIn("scalance%20x204-2", str(request.url))
            return httpx.Response(200, json={
                "results": {"cvelistv5": [["cve-2025-40833", siemens_record()]]},
                "total_count": 1,
                "page_size": 40,
                "page": 1,
            })

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await search_cve_candidates(
                "Siemens SCALANCE X204-2",
                vendor="Siemens",
                product="SCALANCE X204-2",
                client=client,
            )
        self.assertEqual(result["candidates"][0]["cve_id"], "CVE-2025-40833")
        self.assertEqual(result["candidates"][0]["match"], "exact_vendor_product_index")
        self.assertTrue(result["candidate_only"])
        self.assertEqual(requested_hosts, ["vulnerability.circl.lu"])

    async def test_empty_exact_index_falls_back_to_recent_nvd_candidates(self):
        requested_hosts = []

        async def handler(request):
            requested_hosts.append(request.url.host)
            if request.url.host == "vulnerability.circl.lu":
                return httpx.Response(200, json={
                    "results": {}, "total_count": 0, "page_size": 40, "page": 1,
                })
            return httpx.Response(200, json={
                "totalResults": 2,
                "vulnerabilities": [
                    {"cve": {
                        "id": "CVE-2019-1234", "published": "2019-01-01",
                        "lastModified": "2019-01-02", "descriptions": [], "metrics": {},
                    }},
                    {"cve": {
                        "id": "CVE-2026-9999", "published": "2026-08-01",
                        "lastModified": "2026-08-02", "descriptions": [], "metrics": {},
                    }},
                ],
            })

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await search_cve_candidates(
                "Example Hypervisor",
                vendor="example",
                product="hypervisor",
                client=client,
            )
        self.assertEqual(
            requested_hosts,
            ["vulnerability.circl.lu", "services.nvd.nist.gov"],
        )
        self.assertEqual(result["candidates"][0]["cve_id"], "CVE-2026-9999")

    def test_exact_model_wins_over_substring_models(self):
        payload = siemens_record()
        payload["containers"]["cna"]["affected"].append({
            "vendor": "Siemens",
            "product": "SCALANCE X204-2FM",
            "versions": [{"version": "0", "lessThan": "2.0", "status": "affected"}],
        })
        correlation = correlate_cve(normalize_cve_record(payload), [{
            "vendor": "Siemens", "product": "SCALANCE X204-2", "version": "3.1",
        }])
        self.assertEqual(len(correlation["matches"]), 1)
        self.assertEqual(correlation["matches"][0]["affected_product"], "SCALANCE X204-2")


class CveAgentIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.events = []

        async def emit(event, data):
            self.events.append((event, data))

        self.agent = PentestAgent("http://localhost:1234", "test-model", emit)
        self.agent.state = ScanState(target="192.0.2.10")
        self.agent.state.is_running = True
        self.agent.state.requested_cves = ["CVE-2025-40833"]
        self.agent.state.profile["products"] = [{
            "vendor": "Siemens",
            "product": "SCALANCE X204-2",
            "version": "",
            "evidence": "SCALANCE X204-2",
            "confidence": "high",
        }]
        self.agent.scope_policy = ScopePolicy.from_notes(parse_target("192.0.2.10"), "")

    async def test_required_lookup_creates_audited_potential_finding(self):
        normalized = normalize_cve_record(siemens_record())
        with patch("agent.core.fetch_cve_record", new=AsyncMock(return_value=normalized)):
            ran = await self.agent._run_required_cve_research_step()
        self.assertTrue(ran)
        self.assertEqual(self.agent.state.tool_history[0]["tool"], "cve_lookup")
        self.assertTrue(any(
            finding.title.startswith("Potential Exposure to CVE-2025-40833")
            for finding in self.agent.state.findings
        ))
        finding = self.agent.state.findings[0]
        self.assertIn("did not send", finding.description)
        self.assertEqual(self.agent._permitted_exploit_tools(finding), set())
        report = self.agent.generate_report()
        self.assertIn("CVE Research and Product Correlation", report)
        self.assertIn("CVE-2025-40833", report)
        self.assertIn("disruptive test excluded", report)

    async def test_product_search_uses_database_aliases_from_fingerprint(self):
        fingerprint = {
            "vendor": "VMware",
            "product": "VMware ESXi",
            "version": "8.0.3",
            "search_vendor": "vmware",
            "search_product": "esxi",
            "confidence": "high",
            "category": "hypervisor",
            "priority": 129,
        }
        search_result = {
            "type": "cve_candidate_search",
            "query": "vmware esxi",
            "source": "fixture",
            "candidates": [],
        }
        with patch(
            "agent.core.search_cve_candidates",
            new=AsyncMock(return_value=search_result),
        ) as search:
            await self.agent._run_product_cve_search("vmware-esxi", fingerprint)
        search.assert_awaited_once_with(
            "vmware esxi",
            vendor="vmware",
            product="esxi",
        )
        stored = self.agent.state.cve_product_searches["vmware-esxi"]
        self.assertEqual(stored["observed_query"], "VMware ESXi")
        self.assertEqual(self.agent.state.phase_tool_count, 0)

    async def test_tls_12_and_aes_gcm_do_not_create_false_findings(self):
        healthy = "TLS 1.2    offered (OK)\nTLS 1.3    offered (OK): final\nCiphers: AEAD-AES128-GCM-SHA256\n"
        self.assertEqual(_deprecated_tls_evidence_lines(healthy), [])
        self.assertEqual(_weak_tls_cipher_evidence_lines(healthy), [])
        await self.agent._post_analyze_and_findings("testssl_tls", healthy, "192.0.2.10")
        self.assertFalse(self.agent.state.findings)

    def test_only_affirmative_obsolete_tls_and_cipher_lines_match(self):
        protocols = "TLS 1.0 offered (deprecated)\nTLS 1.1 not offered\nTLS 1.2 offered (OK)\n"
        ciphers = "RC4 offered (weak)\n3DES not offered\nAEAD-AES128-GCM-SHA256 offered\n"
        self.assertEqual(_deprecated_tls_evidence_lines(protocols), ["TLS 1.0 offered (deprecated)"])
        self.assertEqual(_weak_tls_cipher_evidence_lines(ciphers), ["RC4 offered (weak)"])

    async def test_llm_false_cipher_claim_is_rejected(self):
        output = "Ciphers: AEAD-AES128-GCM-SHA256\n"
        self.agent.state.tool_history.append({
            "tool": "nikto",
            "target": "https://192.0.2.10",
            "succeeded": True,
            "output": output,
        })
        await self.agent._record_finding({
            "title": "Weak SSL/TLS Cipher Suite Configuration",
            "severity": "medium",
            "description": "The AES-GCM cipher is weak.",
            "evidence": output.strip(),
            "remediation": "Use AES-GCM.",
        })
        self.assertFalse(self.agent.state.findings)


if __name__ == "__main__":
    unittest.main()
