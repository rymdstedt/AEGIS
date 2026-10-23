import json
import unittest

from agent.core import PentestAgent, ScanState
from agent.cve import extract_product_fingerprints
from agent.fingerprints import (
    PRODUCT_FINGERPRINT_RULES,
    identify_product_fingerprints,
    identify_vendor,
)
from tools.executor import _web_identity_records


class ProductFingerprintRegistryTests(unittest.TestCase):
    CASES = (
        ("VMware ESXi 8.0.3 build-24585383", "vmware-esxi", "8.0.3", "esxi"),
        ("vSphere Client - VMware vCenter Server 8.0.2", "vmware-vcenter", "8.0.2", "vcenter_server"),
        ("Proxmox Virtual Environment pve-manager/8.2.4", "proxmox-ve", "8.2.4", "pve-manager"),
        ("Microsoft Hyper-V Server 2022", "microsoft-hyper-v", "2022", "windows hyper-v"),
        ("Nutanix Prism Central pc.2024.3", "nutanix-prism-central", "pc.2024.3", "prism central"),
        ("XCP-ng 8.3", "xcp-ng", "8.3", "xcp-ng"),
        ("Citrix Hypervisor 8.2", "citrix-xenserver", "8.2", "xenserver"),
        ("OpenStack Horizon 24.0", "openstack-horizon", "24.0", "horizon"),
        ("oVirt Engine 4.5.6", "ovirt-engine", "4.5.6", "ovirt-engine"),
        (
            "Red Hat Virtualization 4.4",
            "redhat-virtualization",
            "4.4",
            "virtualization",
        ),
        ("libvirt 10.0.0", "libvirt", "10.0.0", "libvirt"),
        ("iDRAC9 Firmware 7.00.00.00", "dell-idrac9", "7.00.00.00", "idrac9"),
        ("HPE iLO 5 firmware 3.05", "hpe-ilo5", "3.05", "integrated lights-out 5"),
        ("Lenovo XClarity Controller 2.1", "lenovo-xclarity", "2.1", "xclarity_controller"),
        ("Supermicro BMC firmware 01.03.04 IPMI", "supermicro-bmc", "01.03.04", "bmc"),
        ("Fujitsu iRMC S5 3.10", "fujitsu-irmc", "3.10", "irmc"),
        ("Oracle ILOM 5.1.2", "oracle-ilom", "5.1.2", "integrated lights out manager"),
        ("Cisco IOS XE Software, Version 17.12.4", "cisco-ios-xe", "17.12.4", "ios xe"),
        ("SCALANCE X204-2 firmware 3.1", "siemens-industrial", "3.1", "SCALANCE X204-2"),
        ("FortiOS v7.4.3", "fortinet-fortios", "7.4.3", "fortios"),
        ("PAN-OS 11.1.2", "paloalto-panos", "11.1.2", "pan-os"),
        ("SonicOS 7.1.1", "sonicwall-sonicos", "7.1.1", "sonicos"),
        ("RouterOS 7.15.2", "mikrotik-routeros", "7.15.2", "routeros"),
        ("EdgeOS 2.0.9", "ubiquiti-edgeos", "2.0.9", "edgeos"),
        ("JUNOS 23.4R1", "juniper-junos", "23.4R1", "junos"),
        ("F5 BIG-IP 17.1.1", "f5-bigip", "17.1.1", "big-ip"),
        ("pfSense Plus 24.03", "netgate-pfsense", "24.03", "pfsense"),
        ("OPNsense 24.1.8", "opnsense", "24.1.8", "opnsense"),
        ("TrueNAS SCALE 24.04", "truenas", "24.04", "truenas"),
        ("Synology DSM 7.2.1-69057", "synology-dsm", "7.2.1-69057", "dsm"),
        ("QNAP QTS Administration QTS 5.1.7", "qnap-qts", "5.1.7", "qts"),
        ("Rancher/2.9.1", "rancher", "2.9.1", "rancher"),
        ("Portainer CE/2.20.3", "portainer", "2.20.3", "portainer"),
        ("Cockpit Web Console Cockpit 316", "cockpit", "316", "cockpit"),
        (
            "Windows Admin Center 2311",
            "windows-admin-center",
            "2311",
            "windows admin center",
        ),
        (
            'Kubernetes API Server {"gitVersion":"v1.30.3"}',
            "kubernetes-api",
            "1.30.3",
            "kubernetes",
        ),
        ("Server: Microsoft-IIS/10.0", "microsoft-iis", "10.0", "internet information services"),
        ("Server: Apache/2.4.58", "apache-httpd", "2.4.58", "http server"),
        ("Server: nginx/1.24.0", "nginx", "1.24.0", "nginx"),
        ("Apache Tomcat/9.0.82", "apache-tomcat", "9.0.82", "tomcat"),
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu", "openssh", "9.6p1", "openssh"),
        ("X-Grafana-Version: 10.4.2", "grafana", "10.4.2", "grafana"),
        ("X-Jenkins: 2.452.2", "jenkins", "2.452.2", "jenkins"),
        ("GitLab/17.1.0", "gitlab", "17.1.0", "gitlab"),
        ("Atlassian Confluence ajs-version-number=8.9.2", "atlassian-confluence", "8.9.2", "confluence"),
        ("Kubernetes Dashboard v2.7.0", "kubernetes-dashboard", "2.7.0", "dashboard"),
    )

    def test_registry_has_unique_complete_rules(self):
        keys = [rule.key for rule in PRODUCT_FINGERPRINT_RULES]
        self.assertEqual(len(keys), len(set(keys)))
        for rule in PRODUCT_FINGERPRINT_RULES:
            self.assertTrue(rule.vendor)
            self.assertTrue(rule.product)
            self.assertTrue(rule.search_vendor)
            self.assertTrue(rule.search_product)
            self.assertTrue(rule.patterns)

    def test_supported_product_and_version_signatures(self):
        for text, expected_id, expected_version, expected_search_product in self.CASES:
            with self.subTest(expected_id=expected_id):
                matches = identify_product_fingerprints(text, source="fixture")
                match = next(
                    (item for item in matches if item["fingerprint_id"] == expected_id),
                    None,
                )
                self.assertIsNotNone(match, text)
                self.assertEqual(match["version"], expected_version)
                self.assertEqual(match["search_product"], expected_search_product)

    def test_specific_idrac_generation_suppresses_generic_duplicate(self):
        matches = identify_product_fingerprints(
            "Integrated Dell Remote Access Controller 9 iDRAC9 Firmware 7.00.00.00",
            source="fixture",
        )
        ids = [item["fingerprint_id"] for item in matches]
        self.assertIn("dell-idrac9", ids)
        self.assertNotIn("dell-idrac", ids)

    def test_page_body_does_not_promote_generic_server_word(self):
        body = "This documentation explains how to configure nginx and OpenSSH clients."
        self.assertEqual(
            identify_product_fingerprints(body, source="body", body_context=True),
            [],
        )
        branded = identify_product_fingerprints(
            "Welcome to VMware ESXi 8.0.3",
            source="body",
            body_context=True,
        )
        self.assertEqual(branded[0]["fingerprint_id"], "vmware-esxi")

    def test_vendor_only_detection_does_not_invent_a_product(self):
        self.assertEqual(identify_vendor("Copyright ZTE Corporation"), "ZTE")
        self.assertEqual(
            identify_product_fingerprints("Copyright ZTE Corporation", source="fixture"),
            [],
        )

    def test_web_records_emit_only_bounded_safe_metadata(self):
        records = _web_identity_records(
            "<html><title>Proxmox Virtual Environment</title>"
            "<body>PVE Manager pve-manager/8.2.4 password=do-not-emit</body></html>",
            {
                "server": "pve2-api-daemon",
                "set-cookie": "PVEAuthCookie=secret-cookie-value; Secure; HttpOnly",
            },
        )
        serialized = json.dumps(records)
        self.assertTrue(any(item.get("fingerprint_id") == "proxmox-ve" for item in records))
        self.assertIn("PVEAuthCookie", serialized)
        self.assertNotIn("secret-cookie-value", serialized)
        self.assertNotIn("do-not-emit", serialized)

    def test_httpx_metadata_enters_shared_cve_fingerprint_format(self):
        output = json.dumps({
            "url": "https://192.0.2.10",
            "title": "VMware ESXi 8.0.3",
            "webserver": "",
            "tech": ["VMware"],
        })
        matches = extract_product_fingerprints("httpx_probe", output)
        match = next(item for item in matches if item.get("fingerprint_id") == "vmware-esxi")
        self.assertEqual(match["search_vendor"], "vmware")
        self.assertEqual(match["search_product"], "esxi")


class ProductProfileIntegrationTests(unittest.TestCase):
    def setUp(self):
        async def emit(_event, _data):
            return None

        self.agent = PentestAgent("http://localhost:1234", "test-model", emit)
        self.agent.state = ScanState(target="192.0.2.10")

    def test_hypervisor_identity_sets_infrastructure_profile(self):
        self.agent._update_profile("httpx_probe", json.dumps({
            "title": "VMware ESXi 8.0.3",
            "webserver": "",
            "tech": ["VMware"],
        }))
        self.assertEqual(
            self.agent.state.profile["device_type"],
            "hypervisor_or_cloud_management",
        )
        self.assertEqual(self.agent.state.profile["web_app_type"], "infrastructure_mgmt")
        self.assertFalse(self.agent.state.profile.get("is_embedded", False))
        report = self.agent.generate_report()
        self.assertIn("## Product Identification", report)
        self.assertIn("VMware ESXi", report)
        self.assertIn("8.0.3", report)

    def test_bmc_identity_sets_server_management_profile(self):
        line = json.dumps({
            "type": "web_identity",
            "fingerprint_id": "dell-idrac9",
            "category": "bmc",
            "vendor": "Dell",
            "product": "iDRAC9",
            "version": "7.00.00.00",
            "search_vendor": "dell",
            "search_product": "idrac9",
            "cve_searchable": True,
            "priority": 122,
            "confidence": "high",
        })
        self.agent._update_profile("web_assess", line)
        self.assertEqual(
            self.agent.state.profile["device_type"],
            "server_management_controller",
        )
        self.assertTrue(self.agent.state.profile["is_embedded"])

    def test_storage_identity_sets_infrastructure_profile_without_embedded_skip(self):
        self.agent._update_profile("httpx_probe", json.dumps({
            "title": "TrueNAS SCALE 24.04",
            "webserver": "",
            "tech": ["TrueNAS"],
        }))
        self.assertEqual(self.agent.state.profile["device_type"], "storage_appliance")
        self.assertEqual(self.agent.state.profile["web_app_type"], "infrastructure_mgmt")
        self.assertFalse(self.agent.state.profile.get("is_embedded", False))

    def test_server_console_sets_infrastructure_profile(self):
        self.agent._update_profile("httpx_probe", json.dumps({
            "title": "Windows Admin Center 2311",
            "webserver": "Microsoft-HTTPAPI/2.0",
            "tech": ["Microsoft"],
        }))
        self.assertEqual(
            self.agent.state.profile["device_type"],
            "server_management_console",
        )
        self.assertEqual(self.agent.state.profile["web_app_type"], "infrastructure_mgmt")


if __name__ == "__main__":
    unittest.main()
