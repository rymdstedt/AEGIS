"""Synthetic provider responses for passive, bounded exposure lookups."""
import unittest
from unittest.mock import patch

import httpx
import main
from exposure.live import check_owned, search_world
from fastapi.testclient import TestClient
from security import AUTH_TOKEN


class PassiveLookupTests(unittest.TestCase):
    def test_owned_ip_joins_shodan_candidate_to_kev_without_claiming_compromise(self):
        requests = []

        def respond(request):
            requests.append(request)
            if request.url.host == "app.netlas.io":
                return httpx.Response(200, json={
                    "ip": "8.8.8.8", "ports": [{"port": 502, "protocol": "modbus"}],
                })
            if request.url.host == "internetdb.shodan.io":
                return httpx.Response(200, json={
                    "ip": "8.8.8.8", "ports": [80, 502], "cpes": [],
                    "vulns": ["CVE-2025-12345", "not-a-cve"],
                })
            raise AssertionError("unexpected request")

        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            with patch("exposure.live._kev_catalog", return_value={"CVE-2025-12345": {"known_exploited": True}}):
                result = check_owned("8.8.8.8", client=client)
        self.assertEqual([request.url.host for request in requests],
                         ["app.netlas.io", "internetdb.shodan.io"])
        self.assertEqual(result["kev_matches_total"], 1)
        self.assertEqual(result["records"][0]["observations"][0]["review_group"], "OT / control")
        record = result["records"][1]
        self.assertEqual(record["cve_candidates"], ["CVE-2025-12345"])
        self.assertEqual(record["kev_matches"], ["CVE-2025-12345"])
        self.assertTrue(all(item["patch_status"] == "unknown" for item in record["observations"]))
        self.assertTrue(all(item["review_group"] == "Other service" for item in record["observations"]))
        self.assertIn("unverified", result["interpretation"])

    def test_owned_domains_use_only_fixed_index_endpoints_and_bound_censys_credits(self):
        requests = []

        def respond(request):
            requests.append(request)
            self.assertNotIn("secret-token-value", str(request.url))
            if request.url.host == "api.platform.censys.io":
                port = 80 if str(request.url).endswith(":80") else 443
                return httpx.Response(200, json={"result": {"resource": {
                    "hostname": "example.com", "port": port,
                    "endpoints": [{"http": {"response": {"html_title": "Danfoss StoreView Web"}}}],
                }}})
            if request.url.host == "app.netlas.io":
                self.assertEqual(request.url.path, "/api/host/example.com/")
                return httpx.Response(200, json={"domain": "example.com", "ports": [
                    {"port": 443, "protocol": "https"},
                ]})
            raise AssertionError("unexpected request")

        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            result = check_owned("example.com", censys_pat="secret-token-value",
                                 netlas_key="netlas-token-value", client=client)
        self.assertEqual(result["censys_credits_planned"], 2)
        self.assertEqual(len(result["records"]), 3)
        self.assertEqual({request.url.host for request in requests},
                         {"api.platform.censys.io", "app.netlas.io"})
        self.assertEqual(sum(len(record["observations"]) for record in result["records"]), 3)
        self.assertNotIn("secret-token-value", str(result))
        self.assertNotIn("netlas-token-value", str(result))

    def test_censys_host_cves_include_service_context_without_claiming_confirmation(self):
        def respond(request):
            if request.url.host == "app.netlas.io":
                return httpx.Response(200, json={"ip": "8.8.8.8", "ports": []})
            if request.url.host == "internetdb.shodan.io":
                return httpx.Response(200, json={"ip": "8.8.8.8", "ports": [], "vulns": []})
            if request.url.host == "api.platform.censys.io":
                return httpx.Response(200, json={"result": {"resource": {
                    "ip": "8.8.8.8",
                    "services": [{
                        "port": 443,
                        "protocol": "HTTP",
                        "vulns": [{
                            "id": "CVE-2025-54321",
                            "severity": "HIGH",
                            "kev": True,
                            "metrics": {"cvss_v31": {"score": 8.8}},
                        }],
                    }],
                }}})
            raise AssertionError("unexpected request")

        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            with patch("exposure.live._kev_catalog", return_value={"CVE-2025-54321": {}}):
                result = check_owned(
                    "8.8.8.8", censys_pat="secret-token-value", client=client,
                )
        record = result["records"][2]
        self.assertEqual(record["cve_data_status"], "reported")
        self.assertEqual(record["cve_candidates"], ["CVE-2025-54321"])
        self.assertEqual(record["kev_matches"], ["CVE-2025-54321"])
        self.assertEqual(record["vulnerabilities"], [{
            "id": "CVE-2025-54321",
            "source": "Censys Platform",
            "service_port": 443,
            "service_protocol": "HTTP",
            "severity": "HIGH",
            "cvss_score": 8.8,
            "cvss_version": "3.1",
            "provider_kev": True,
            "cisa_kev": True,
            "basis": "Censys associated the observed service software with this CVE by CPE.",
        }])
        self.assertIn("unverified", result["interpretation"])

    def test_censys_host_marks_missing_cve_fields_as_not_provided(self):
        def respond(request):
            if request.url.host == "app.netlas.io":
                return httpx.Response(200, json={"ip": "8.8.8.8", "ports": []})
            if request.url.host == "internetdb.shodan.io":
                return httpx.Response(200, json={"ip": "8.8.8.8", "ports": []})
            if request.url.host == "api.platform.censys.io":
                return httpx.Response(200, json={"result": {"resource": {
                    "ip": "8.8.8.8", "services": [{"port": 443, "protocol": "HTTP"}],
                }}})
            raise AssertionError("unexpected request")

        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            result = check_owned(
                "8.8.8.8", censys_pat="secret-token-value", client=client,
            )
        record = result["records"][2]
        self.assertEqual(record["cve_data_status"], "not_provided")
        self.assertEqual(record["vulnerabilities"], [])
        self.assertIn("plan", record["note"])

    def test_censys_software_uses_bounded_independent_cve_index_fallback(self):
        searches = []

        def respond(request):
            if request.url.host == "app.netlas.io":
                return httpx.Response(200, json={"ip": "8.8.8.8", "ports": []})
            if request.url.host == "internetdb.shodan.io":
                return httpx.Response(200, json={"ip": "8.8.8.8", "ports": []})
            if request.url.host == "api.platform.censys.io":
                return httpx.Response(200, json={"result": {"resource": {
                    "ip": "8.8.8.8",
                    "services": [
                        {"port": 443 + index, "protocol": "HTTP", "software": [{
                            "vendor": f"Vendor {index}", "product": f"Product {index}",
                            "version": "1.2.3",
                        }]}
                        for index in range(4)
                    ],
                }}})
            raise AssertionError("unexpected request")

        async def search(query, *, vendor, product, limit):
            searches.append((query, vendor, product, limit))
            index = vendor.rsplit(" ", 1)[-1]
            return {
                "source": "CIRCL Vulnerability-Lookup exact product index",
                "candidates": [{
                    "cve_id": f"CVE-2025-1234{index}",
                    "database": "CIRCL Vulnerability-Lookup (cvelistv5)",
                    "cvss": {"score": 7.5, "version": "3.1", "severity": "high"},
                }],
            }

        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            with patch("exposure.live.search_cve_candidates", side_effect=search), \
                    patch("exposure.live._kev_catalog", return_value={}):
                result = check_owned(
                    "8.8.8.8", censys_pat="secret-token-value", client=client,
                )
        self.assertEqual(len(searches), 3)
        self.assertTrue(all(item[-1] == 8 for item in searches))
        record = result["records"][2]
        self.assertEqual(record["cve_data_status"], "reported")
        self.assertEqual(len(record["vulnerabilities"]), 3)
        self.assertEqual(record["vulnerabilities"][0]["source"],
                         "CIRCL Vulnerability-Lookup (cvelistv5)")
        self.assertIn("installed-version applicability is unverified",
                      record["vulnerabilities"][0]["basis"])
        self.assertFalse(record["vulnerabilities"][0]["cisa_kev"])
        self.assertEqual(result["cve_product_enrichment"], {
            "status": "complete", "products_checked": 3,
            "candidates_added": 3, "warnings": [],
        })

    def test_world_search_returns_safe_metadata_for_requested_page(self):
        captured = []
        def respond(request):
            captured.append(request)
            return httpx.Response(200, json={"items": [
                {"data": {"ip": "8.8.8.8", "host": "example.com", "port": 443,
                          "protocol": "https", "http": {"title": "Proxmox Virtual Environment"},
                          "last_updated": "2026-11-02T12:00:00Z", "raw": "private-banner"}},
                {"data": {"ip": "192.0.2.2", "port": 502, "protocol": "modbus"}},
            ]})
        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            result = search_world(
                'http.title:"Proxmox"', netlas_key="netlas-token-value",
                start=40, client=client,
            )
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].url.host, "app.netlas.io")
        self.assertEqual(captured[0].url.params["start"], "40")
        self.assertEqual(captured[0].url.params["source_type"], "include")
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["page"], 3)
        self.assertTrue(result["has_previous"])
        self.assertFalse(result["has_next"])
        self.assertEqual(len(result["observations"]), 1)
        self.assertNotIn("private-banner", str(result))
        self.assertNotIn("netlas-token-value", str(result))

    def test_bounds_and_failures_do_not_trigger_target_requests(self):
        for targets in ("192.0.2.1", "10.0.0.0/30", "8.8.8.0/24", "http://example.com"):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                check_owned(targets)
        with self.assertRaisesRegex(ValueError, "10 Censys"):
            check_owned("8.8.8.0/28", censys_pat="secret-token-value",
                        netlas_key="netlas-token-value")
        with self.assertRaisesRegex(ValueError, "Guest Netlas"):
            check_owned("8.8.8.0/29")
        with self.assertRaisesRegex(ValueError, "specific Netlas query"):
            search_world("*", netlas_key="netlas-token-value")
        for start in (-20, 1, 10_000, True):
            with self.subTest(start=start), self.assertRaisesRegex(ValueError, "page offset"):
                search_world("prot7:modbus", start=start)

        def respond(request):
            self.assertIn(request.url.host, {"app.netlas.io", "internetdb.shodan.io"})
            return httpx.Response(404)
        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            result = check_owned("8.8.8.8", client=client)
        self.assertEqual(result["records"][0]["status"], "no_record")

    def test_guest_world_search_omits_auth_header(self):
        def respond(request):
            self.assertEqual(request.url.host, "app.netlas.io")
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(200, json={"items": []})
        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            result = search_world("prot7:modbus", client=client)
        self.assertEqual(result["status"], "no_record")

    def test_new_api_routes_require_local_auth_and_do_not_echo_tokens(self):
        client = TestClient(main.app)
        payload = {"targets": "8.8.8.8", "censys_pat": "secret-token-value"}
        self.assertEqual(client.post("/api/exposure/owned/check", json=payload).status_code, 401)
        with patch("main.check_owned", return_value={"mode": "owned", "records": []}) as lookup:
            response = client.post("/api/exposure/owned/check", json=payload,
                                   headers={"Authorization": f"Bearer {AUTH_TOKEN}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(lookup.call_args.kwargs["censys_pat"], "secret-token-value")
        self.assertNotIn("secret-token-value", response.text)
        self.assertEqual(client.post("/api/exposure/world/search", json={
            "query": "prot7:modbus", "netlas_key": "netlas-token-value",
        }).status_code, 401)
        with patch("main.search_world", return_value={"mode": "world", "observations": []}) as lookup:
            response = client.post("/api/exposure/world/search", json={
                "query": "prot7:modbus", "netlas_key": "netlas-token-value", "start": 60,
            }, headers={"Authorization": f"Bearer {AUTH_TOKEN}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(lookup.call_args.kwargs["start"], 60)


if __name__ == "__main__":
    unittest.main()
