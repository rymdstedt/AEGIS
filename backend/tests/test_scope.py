import unittest

from agent.scope import ScopePolicy, parse_target


class TargetParsingTests(unittest.TestCase):
    def test_parses_and_normalizes_supported_targets(self):
        self.assertEqual(parse_target("192.168.1.7").host, "192.168.1.7")
        self.assertEqual(parse_target("192.168.1.9/24").network_target, "192.168.1.0/24")
        self.assertEqual(parse_target("Example.COM.").host, "example.com")
        self.assertEqual(
            parse_target("https://Example.COM:8443/admin?q=1").base_url,
            "https://example.com:8443/admin?q=1",
        )
        self.assertEqual(parse_target("[::1]:8443").host, "::1")

    def test_rejects_ambiguous_or_injectable_targets(self):
        for raw in (
            "",
            "example.com;id",
            "example.com/path",
            "https://user:pass@example.com",
            "https://example.com/#hidden-target-state",
            "my local network",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_target(raw)


class ScopePolicyTests(unittest.TestCase):
    def test_bare_port_lists_ranges_and_all_ports_are_exact_scope(self):
        policy = ScopePolicy.from_notes(
            parse_target("192.0.2.10"),
            "22,443,8000-8002",
        )
        self.assertTrue(policy.ports_restricted)
        self.assertEqual(policy.allowed_ports, {22, 443, 8000, 8001, 8002})
        policy.authorize("192.0.2.10", port=8001)
        with self.assertRaises(PermissionError):
            policy.authorize("192.0.2.10", port=80)

        all_ports = ScopePolicy.from_notes(parse_target("192.0.2.10"), "all ports")
        self.assertTrue(all_ports.ports_restricted)
        self.assertEqual(len(all_ports.allowed_ports), 65535)
        all_ports.authorize("192.0.2.10", port=65535)

    def test_single_host_does_not_expand_to_network(self):
        policy = ScopePolicy.from_notes(parse_target("10.0.0.10"), "")
        policy.authorize("10.0.0.10")
        with self.assertRaises(PermissionError):
            policy.authorize("10.0.0.0/24")

    def test_network_allows_subnets_but_not_parent(self):
        policy = ScopePolicy.from_notes(parse_target("10.0.4.0/24"), "")
        policy.authorize("10.0.4.20")
        policy.authorize("10.0.4.128/25")
        with self.assertRaises(PermissionError):
            policy.authorize("10.0.0.0/8")

    def test_exclusions_ports_and_subdomains_are_enforced(self):
        policy = ScopePolicy.from_notes(
            parse_target("example.com"),
            "allow subdomains; include 10.0.0.0/24; exclude 10.0.0.8; only ports 80,443",
        )
        policy.authorize("api.example.com", port=443)
        policy.authorize("10.0.0.9", port=80)
        with self.assertRaises(PermissionError):
            policy.authorize("10.0.0.8", port=80)
        with self.assertRaises(PermissionError):
            policy.authorize("api.example.com", port=22)
        with self.assertRaises(PermissionError):
            policy.authorize("notexample.com", port=443)

    def test_dns_resolution_is_explicitly_added(self):
        policy = ScopePolicy.from_notes(parse_target("example.com"), "")
        with self.assertRaises(PermissionError):
            policy.authorize("203.0.113.8")
        policy.add_resolved_address("203.0.113.8")
        policy.authorize("203.0.113.8")


if __name__ == "__main__":
    unittest.main()
