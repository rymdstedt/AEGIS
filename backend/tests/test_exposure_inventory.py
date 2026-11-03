"""Synthetic controls for local, scope-bound Censys exposure imports."""
import json
import unittest
from unittest.mock import patch

import main
from exposure.censys import analyze_censys_export
from fastapi.testclient import TestClient
from security import AUTH_TOKEN


class CensysImportTests(unittest.TestCase):
    def test_csv_keeps_only_owned_hosts_and_never_claims_patching(self):
        source = (
            "IP,Port,HTTP Title,Product,Version\n"
            "192.0.2.10,443,Danfoss StoreView Web,,\n"
            "192.0.2.11,8443,Proxmox Virtual Environment,pve-manager,8.2.4\n"
            "192.0.2.12,22,,OpenSSH,9.6\n"
            "198.51.100.20,80,Out of scope admin panel,nginx,1.24.0\n"
        )
        with patch("socket.getaddrinfo", side_effect=AssertionError("network access")):
            result = analyze_censys_export("hosts.csv", source, "192.0.2.0/24")
        self.assertEqual(result["records_total"], 4)
        self.assertEqual(result["records_in_scope"], 3)
        self.assertEqual(result["records_out_of_scope"], 1)
        self.assertEqual(result["observations_total"], 3)
        self.assertEqual(result["ot_total"], 1)
        self.assertEqual(result["network_requests"], 0)
        self.assertNotIn("198.51.100.20", json.dumps(result))
        self.assertEqual(result["observations"][0]["product"], "StoreView")
        self.assertTrue(all(item["patch_status"] == "unknown" for item in result["observations"]))
        self.assertIn("OpenSSH", [item["product"] for item in result["observations"]])

    def test_json_supports_legacy_and_platform_service_fields(self):
        source = {"result": {"hits": [
            {"ip": "192.0.2.20", "services": [{
                "port": 80, "protocol": "HTTP",
                "http": {"response": {"html_title": "Danfoss StoreView Web"}},
            }]},
            {"host": {"ip": "192.0.2.21", "services": [{
                "port": 443, "protocol": "HTTPS",
                "software": [{"vendor": "VMware", "product": "vCenter Server", "version": "8.0.2"}],
                "endpoints": [{"http": {"html_title": "vSphere Client - VMware vCenter Server 8.0.2"}}],
            }]}},
        ]}}
        result = analyze_censys_export("hosts.json", json.dumps(source), "192.0.2.20,192.0.2.21")
        self.assertEqual(result["observations_total"], 2)
        self.assertEqual(result["ot_total"], 1)
        products = {item["product"] for item in result["observations"]}
        self.assertIn("StoreView", products)
        self.assertIn("VMware vCenter Server", products)
        self.assertEqual(result["observations"][1]["version"], "8.0.2")

    def test_jsonl_and_flat_platform_csv_are_supported(self):
        rows = [
            {"host.ip": "2001:db8:1234::10", "host.services.port": 443,
             "host.services.endpoints.http.html_title": "Danfoss StoreView Web"},
            {"host.ip": "2001:db8:1234::11", "host.services.port": 22,
             "host.services.protocol": "SSH"},
        ]
        jsonl = "\n".join(json.dumps(row) for row in rows)
        result = analyze_censys_export("hosts.jsonl", jsonl, "2001:db8:1234::/64")
        self.assertEqual(result["records_in_scope"], 2)
        self.assertEqual(result["observations_total"], 2)
        csv_source = (
            "host.ip,host.services.port,host.services.endpoints.http.html_title\n"
            "192.0.2.1,443,Danfoss StoreView Web\n"
        )
        self.assertEqual(analyze_censys_export("hosts.csv", csv_source, "192.0.2.1")["ot_total"], 1)

    def test_multiple_titles_select_a_recognized_management_title(self):
        source = json.dumps({
            "ip": "192.0.2.30", "services": [{
                "port": 443, "http": {"response": {"html_title": [
                    "Generic welcome page", "Danfoss StoreView Web",
                ]}},
            }],
        })
        result = analyze_censys_export("hosts.json", source, "192.0.2.30")
        self.assertEqual(result["ot_total"], 1)
        self.assertEqual(result["observations"][0]["title"], "Danfoss StoreView Web")

    def test_display_limit_reports_omitted_observations(self):
        source = "IP,Port,Protocol\n" + "".join(
            f"192.0.2.40,{port},TCP\n" for port in range(1000, 1501)
        )
        result = analyze_censys_export("hosts.csv", source, "192.0.2.40")
        self.assertEqual(result["observations_total"], 501)
        self.assertEqual(result["observations_returned"], 500)
        self.assertEqual(result["observations_omitted"], 1)

    def test_unknown_services_remain_visible_without_false_patch_claim(self):
        result = analyze_censys_export(
            "hosts.csv", "IP,Port,Protocol,HTTP Title\n192.0.2.50,5000,TCP,Unfamiliar service\n",
            "192.0.2.0/24",
        )
        self.assertEqual(result["observations_total"], 1)
        item = result["observations"][0]
        self.assertEqual(item["review_group"], "Other service")
        self.assertEqual(item["product"], "")
        self.assertEqual(item["patch_status"], "unknown")

    def test_explicit_ot_protocol_is_flagged_without_port_based_guessing(self):
        source = (
            "IP,Port,host.services.service_name\n"
            "192.0.2.60,502,MODBUS\n"
            "192.0.2.61,502,TCP\n"
        )
        result = analyze_censys_export("hosts.csv", source, "192.0.2.0/24")
        self.assertEqual(result["ot_total"], 1)
        self.assertEqual(result["observations"][0]["review_basis"], "Censys protocol")
        self.assertEqual(result["observations"][1]["review_group"], "Other service")
        self.assertEqual(result["observations"][1]["patch_status"], "unknown")

    def test_invalid_scope_and_incomplete_exports_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError, "too broad"):
            analyze_censys_export("hosts.csv", "IP,Port\n192.0.2.1,80\n", "0.0.0.0/0")
        with self.assertRaisesRegex(ValueError, "IP addresses and CIDR"):
            analyze_censys_export("hosts.csv", "IP,Port\n192.0.2.1,80\n", "example.com")
        with self.assertRaisesRegex(ValueError, "service data"):
            analyze_censys_export("hosts.json", '{"ip":"192.0.2.1"}', "192.0.2.1")
        with self.assertRaisesRegex(ValueError, "2 MB"):
            analyze_censys_export("hosts.csv", "x" * 2_000_001, "192.0.2.1")
        with self.assertRaisesRegex(ValueError, "needs an IP column"):
            analyze_censys_export("hosts.csv", "Title,Port\nPanel,80\n", "192.0.2.1")
        with self.assertRaisesRegex(ValueError, "could not be parsed"):
            analyze_censys_export("hosts.json", "{broken", "192.0.2.1")
        with self.assertRaisesRegex(ValueError, "invalid text"):
            analyze_censys_export("hosts.json", "\ud800", "192.0.2.1")

    def test_authenticated_api_and_no_remote_lookup(self):
        payload = {
            "filename": "hosts.csv", "scope": "192.0.2.0/24",
            "content": "IP,Port,HTTP Title\n192.0.2.10,443,Danfoss StoreView Web\n",
        }
        client = TestClient(main.app)
        self.assertEqual(client.post("/api/exposure/censys/analyze", json=payload).status_code, 401)
        response = client.post(
            "/api/exposure/censys/analyze", json=payload,
            headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ot_total"], 1)
        self.assertEqual(response.json()["network_requests"], 0)


if __name__ == "__main__":
    unittest.main()
