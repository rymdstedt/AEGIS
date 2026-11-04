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

    def test_world_search_returns_safe_metadata_only_and_one_page(self):
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
            result = search_world('http.title:"Proxmox"', netlas_key="netlas-token-value", client=client)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].url.host, "app.netlas.io")
        self.assertEqual(captured[0].url.params["start"], "0")
        self.assertEqual(captured[0].url.params["source_type"], "include")
        self.assertEqual(result["status"], "observed")
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


if __name__ == "__main__":
    unittest.main()
