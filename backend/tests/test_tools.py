import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.definitions import (
    TOOLS,
    CommandSpec,
    build_command,
    ensure_script_tools,
    get_tool_descriptions,
)
from tools.executor import ToolExecutor


class CommandBuilderTests(unittest.TestCase):
    def test_destructive_slowloris_implementation_is_not_exposed(self):
        self.assertNotIn("slowloris", TOOLS)
        self.assertIn("slowloris_test", TOOLS)

    def test_web_metadata_fetch_does_not_follow_redirects(self):
        spec = build_command("robots_sitemap", {"target": "https://example.com"})
        for command in spec.commands:
            self.assertNotIn("-L", command)

    def test_untrusted_target_is_one_argv_element(self):
        target = "example.com; touch /tmp/never"
        spec = build_command("nmap_quick", {"target": target})
        self.assertEqual(spec.commands[0][-1], target)
        self.assertNotIn("sh", spec.commands[0][0])

    def test_unknown_parameters_are_rejected(self):
        with self.assertRaises(ValueError):
            build_command("nmap_quick", {"target": "127.0.0.1", "flags": "; id"})

    def test_naabu_discovery_is_unprivileged_and_bounded(self):
        spec = build_command("naabu_quick", {"target": "192.0.2.10"})
        command = spec.commands[0]
        self.assertIn("-scan-type", command)
        self.assertEqual(command[command.index("-scan-type") + 1], "c")
        self.assertEqual(command[command.index("-top-ports") + 1], "1000")
        self.assertEqual(command[command.index("-host") + 1], "192.0.2.10")
        self.assertIn("-Pn", command)
        self.assertNotIn("-verify", command)
        self.assertEqual(command[command.index("-retries") + 1], "2")
        self.assertEqual(command[command.index("-timeout") + 1], "1500")
        self.assertIn("-disable-update-check", command)
        self.assertIn("-no-stdin", command)
        self.assertLessEqual(spec.timeout, 20)

    def test_naabu_full_covers_every_tcp_port_for_single_host_discovery(self):
        spec = build_command("naabu_full", {"target": "192.0.2.10"})
        command = spec.commands[0]
        self.assertEqual(command[command.index("-top-ports") + 1], "full")
        self.assertEqual(command[command.index("-scan-type") + 1], "c")
        self.assertEqual(command[command.index("-host") + 1], "192.0.2.10")
        self.assertIn("-Pn", command)
        self.assertIn("-disable-update-check", command)
        self.assertIn("-no-stdin", command)
        self.assertGreater(spec.timeout, 20)
        self.assertLessEqual(spec.timeout, 90)

    def test_naabu_range_accepts_only_bounded_numeric_port_windows(self):
        spec = build_command("naabu_range", {
            "target": "192.0.2.10", "port_start": 16_385, "port_end": 32_768,
        })
        command = spec.commands[0]
        self.assertEqual(command[command.index("-p") + 1], "16385-32768")
        self.assertEqual(command[command.index("-scan-type") + 1], "c")
        self.assertLessEqual(spec.timeout, 35)
        for start, end in ((0, 10), (5, 65_536), (1, 16_385), (50, 49), ("--script", 10)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                build_command("naabu_range", {
                    "target": "192.0.2.10", "port_start": start, "port_end": end,
                })

    def test_nmap_discovery_fallback_is_fast_and_has_no_service_scripts(self):
        spec = build_command("nmap_quick", {"target": "192.0.2.10"})
        command = spec.commands[0]
        self.assertIn("--top-ports", command)
        self.assertIn("--host-timeout", command)
        self.assertIn("-n", command)
        self.assertIn("-sT", command)
        self.assertIn("--reason", command)
        self.assertNotIn("--open", command)
        self.assertEqual(command[command.index("--max-retries") + 1], "2")
        self.assertNotIn("--defeat-rst-ratelimit", command)
        self.assertNotIn("-sV", command)
        self.assertNotIn("-sC", command)
        self.assertLessEqual(spec.timeout, 100)

    def test_nmap_targeted_accepts_only_valid_explicit_ports(self):
        spec = build_command(
            "nmap_targeted",
            {"target": "192.0.2.10", "ports": [443, 22, 443]},
        )
        command = spec.commands[0]
        self.assertEqual(command[command.index("-p") + 1], "22,443")
        self.assertEqual(command[command.index("--version-intensity") + 1], "5")
        self.assertNotIn("-sC", command)
        self.assertNotIn("--script", command)
        self.assertEqual(command[command.index("--max-retries") + 1], "1")
        self.assertIn("--host-timeout", command)
        self.assertLessEqual(spec.timeout, 42)
        with self.assertRaises(ValueError):
            build_command("nmap_targeted", {"target": "192.0.2.10", "ports": [0, 443]})
        with self.assertRaises(ValueError):
            build_command("nmap_targeted", {"target": "192.0.2.10", "ports": ["443;id"]})

    def test_every_nmap_path_disables_name_resolution_for_literal_ips(self):
        target = "192.0.2.10"
        commands = {
            "nmap_ping_sweep": build_command("nmap_ping_sweep", {"target": target}),
            "nmap_quick": build_command("nmap_quick", {"target": target}),
            "nmap_targeted": build_command(
                "nmap_targeted", {"target": target, "ports": [443]}
            ),
            "nmap_full": build_command("nmap_full", {"target": target}),
            "nmap_udp": build_command("nmap_udp", {"target": target}),
            "nmap_vuln": build_command("nmap_vuln", {"target": target}),
            "ssl_check": build_command(
                "ssl_check", {"target": target, "port": 443}
            ),
            "slowloris_test": build_command("slowloris_test", {"target": target}),
        }
        for tool_name, spec in commands.items():
            with self.subTest(tool=tool_name):
                self.assertIn("-n", spec.commands[0])

    def test_nuclei_defaults_disable_intrusive_and_external_interaction_modes(self):
        command = build_command("nuclei_scan", {"target": "https://example.com"}).commands[0]
        self.assertIn("-no-interactsh", command)
        self.assertIn("-disable-update-check", command)
        excluded = command[command.index("-exclude-tags") + 1]
        self.assertEqual(set(excluded.split(",")), {"dos", "fuzz", "intrusive"})
        excluded_types = command[command.index("-exclude-type") + 1]
        self.assertEqual(set(excluded_types.split(",")), {"headless", "code", "javascript"})
        self.assertIn("-disable-unsigned-templates", command)
        self.assertIn("-disable-redirects", command)
        self.assertNotIn("-code", command)
        self.assertNotIn("-headless", command)

    def test_katana_is_exact_host_scoped_and_bounded(self):
        command = build_command("katana_crawl", {"target": "https://example.com"}).commands[0]
        self.assertEqual(command[command.index("-field-scope") + 1], "fqdn")
        self.assertIn("-disable-redirects", command)
        self.assertEqual(command[command.index("-rate-limit") + 1], "25")
        self.assertIn("-omit-body", command)
        self.assertEqual(command[command.index("-crawl-duration") + 1], "2m")
        self.assertEqual(command[command.index("-max-domain-pages") + 1], "250")

    def test_httpx_probe_is_bounded_and_non_redirecting(self):
        command = build_command("httpx_probe", {"target": "https://example.com"}).commands[0]
        self.assertNotIn("-follow-redirects", command)
        self.assertNotIn("-follow-host-redirects", command)
        self.assertEqual(command[command.index("-rate-limit") + 1], "20")
        self.assertEqual(command[command.index("-timeout") + 1], "4")
        self.assertEqual(command[command.index("-retries") + 1], "0")
        self.assertIn("-omit-body", command)
        self.assertIn("-no-stdin", command)

    def test_httpx_batches_every_valid_requested_port(self):
        command = build_command(
            "httpx_probe",
            {"target": "192.0.2.10", "ports": [17988, 443, 22, 443]},
        ).commands[0]
        self.assertEqual(command[command.index("-ports") + 1], "22,443,17988")
        with self.assertRaises(ValueError):
            build_command("httpx_probe", {"target": "192.0.2.10", "ports": [0]})

    def test_header_probe_uses_get_and_accepts_target_tls_certificate(self):
        command = build_command("curl_headers", {"target": "https://192.0.2.10"}).commands[0]
        self.assertNotIn("-I", command)
        self.assertIn("--insecure", command)
        self.assertIn("-D", command)
        self.assertEqual(command[command.index("-o") + 1], "/dev/null")

    def test_windows_commands_use_native_ping_flags_and_null_device(self):
        with (
            patch("tools.definitions.sys.platform", "win32"),
            patch("tools.definitions.os.devnull", "nul"),
            patch("tools.definitions._find_external_tool", return_value=None),
            patch("tools.definitions._find_managed_tool", return_value=None),
        ):
            ping = build_command("ping", {"target": "192.0.2.10"}).commands[0]
            headers = build_command(
                "curl_headers", {"target": "https://192.0.2.10"}
            ).commands[0]
            ssh = build_command(
                "creds_ssh_exec",
                {
                    "target": "192.0.2.10",
                    "username": "tester",
                    "password": "secret",
                    "command": "whoami",
                },
            ).commands[0]

        self.assertEqual(ping[-5:], ["-n", "4", "-w", "2000", "192.0.2.10"])
        self.assertEqual(headers[headers.index("-o") + 1], "nul")
        self.assertIn("UserKnownHostsFile=nul", ssh)

    def test_internal_web_tools_are_bounded_and_shell_free(self):
        for tool_name in (
            "web_discover", "web_assess", "sqli_probe", "xss_check",
            "csrf_get_check", "cookie_auth_check", "unauthenticated_write_check",
            "default_web_login",
        ):
            with self.subTest(tool=tool_name):
                spec = build_command(
                    tool_name,
                    {"target": "http://127.0.0.1:18080/test?id=1"},
                )
                self.assertEqual(spec.commands[0][0], "__aegis_internal__")
                self.assertLessEqual(spec.timeout, 45)

    def test_sqlmap_does_not_reuse_stale_cross_scan_sessions(self):
        for tool_name in ("sqlmap_test", "sqlmap_forms"):
            with self.subTest(tool=tool_name):
                command = build_command(
                    tool_name,
                    {"target": "http://127.0.0.1:18080/api/products?id=1"},
                ).commands[0]
                self.assertIn("--flush-session", command)
                self.assertIn("--fresh-queries", command)

    def test_sqlmap_forms_treats_expected_login_rejection_as_a_baseline(self):
        command = build_command(
            "sqlmap_forms",
            {"target": "http://127.0.0.1:18080/login"},
        ).commands[0]
        self.assertEqual(command[command.index("--ignore-code") + 1], "401")

    def test_ssl_check_uses_the_discovered_tls_port_and_is_bounded(self):
        spec = build_command("ssl_check", {"target": "192.0.2.10", "port": 8443})
        command = spec.commands[0]
        self.assertEqual(command[command.index("-p") + 1], "8443")
        self.assertIn("--script-timeout", command)
        self.assertIn("--host-timeout", command)
        with self.assertRaises(ValueError):
            build_command("ssl_check", {"target": "192.0.2.10", "port": 70000})

    def test_testssl_uses_exact_authority_and_bounded_noninteractive_options(self):
        spec = build_command(
            "testssl_tls",
            {"target": "https://[2001:db8::10]:9443/resource?id=1", "port": 9443},
        )
        command = spec.commands[0]
        self.assertEqual(command[-1], "[2001:db8::10]:9443")
        self.assertIn("--protocols", command)
        self.assertIn("--categories", command)
        self.assertIn("--server-defaults", command)
        self.assertEqual(command[command.index("--warnings") + 1], "off")
        self.assertEqual(command[command.index("--color") + 1], "0")
        self.assertLessEqual(spec.timeout, 120)
        with self.assertRaises(ValueError):
            build_command("testssl_tls", {"target": "example.com", "port": 0})

    def test_dalfox_is_query_preserving_bounded_and_has_no_blind_callbacks(self):
        target = "https://example.com/search?q=hello"
        spec = build_command("dalfox_scan", {"target": target})
        command = spec.commands[0]
        self.assertEqual(command[command.index("scan") + 1], target)
        self.assertEqual(command[command.index("--format") + 1], "jsonl")
        self.assertEqual(command[command.index("--scan-timeout") + 1], "60")
        self.assertEqual(command[command.index("--rate-limit") + 1], "25")
        self.assertEqual(command[command.index("--max-payloads-per-param") + 1], "250")
        self.assertIn("--skip-mining", command)
        self.assertIn("--skip-waf-probe", command)
        self.assertNotIn("--blind", command)

    def test_zap_recon_is_one_request_command_mode_against_the_origin(self):
        command = build_command(
            "zap_recon", {"target": "https://example.com/path?q=1"}
        ).commands[0]
        self.assertIn("-cmd", command)
        self.assertIn("-zapit", command)
        self.assertEqual(command[command.index("-zapit") + 1], "https://example.com")
        self.assertNotIn("-quickurl", command)

    def test_waf_detection_is_origin_scoped_and_does_not_follow_redirects(self):
        command = build_command(
            "waf_detect", {"target": "https://example.com/path?q=1"}
        ).commands[0]
        self.assertEqual(command[-1], "https://example.com")
        self.assertIn("--noredirect", command)

    def test_netexec_smb_is_credential_free_metadata_discovery(self):
        command = build_command("netexec_smb", {"target": "192.0.2.10"}).commands[0]
        self.assertEqual(command[-2:], ["smb", "192.0.2.10"])
        self.assertIn("--no-progress", command)
        self.assertNotIn("-u", command)
        self.assertNotIn("-p", command)
        self.assertNotIn("-x", command)

    def test_amass_is_passive_and_domain_scoped(self):
        command = build_command(
            "amass_passive", {"target": "example.com"}
        ).commands[0]
        self.assertIn("-passive", command)
        self.assertIn("-silent", command)
        self.assertEqual(command[command.index("-d") + 1], "example.com")
        self.assertNotIn("-brute", command)

    def test_ssh_audit_uses_a_discovered_nonstandard_port(self):
        command = build_command(
            "ssh_audit",
            {"target": "192.0.2.10", "port": 2222},
        ).commands[0]
        self.assertEqual(command[-1], "192.0.2.10")
        self.assertEqual(command[command.index("--port") + 1], "2222")
        self.assertIn("--skip-rate-test", command)
        self.assertIn("--no-colors", command)
        self.assertIn("-jj", command)
        with self.assertRaises(ValueError):
            build_command("ssh_audit", {"target": "192.0.2.10", "port": 70000})

    def test_nikto_is_time_bounded_and_excludes_dos_category(self):
        spec = build_command(
            "nikto", {"target": "https://192.0.2.10/products?id=1"}
        )
        command = spec.commands[0]
        self.assertEqual(command[command.index("-h") + 1], "https://192.0.2.10")
        tuning = command[command.index("-Tuning") + 1]
        self.assertNotIn("6", tuning)
        self.assertEqual(command[command.index("-maxtime") + 1], "60s")
        self.assertIn("-nocheck", command)
        self.assertIn("-nointeractive", command)
        self.assertEqual(command[command.index("-ask") + 1], "no")
        self.assertLessEqual(spec.timeout, 75)

    def test_origin_level_discovery_does_not_append_paths_after_a_query(self):
        spec = build_command(
            "robots_sitemap",
            {"target": "http://127.0.0.1:18080/api/products?id=1"},
        )
        self.assertEqual(
            [command[-1] for command in spec.commands],
            [
                "http://127.0.0.1:18080/robots.txt",
                "http://127.0.0.1:18080/sitemap.xml",
            ],
        )

    def test_existing_managed_whatweb_receives_compatibility_shim(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bundled = os.path.join(temp_dir, "bundled")
            managed = os.path.join(temp_dir, "managed")
            source_file = os.path.join(bundled, "whatweb", "lib", "target.rb")
            target_file = os.path.join(managed, "whatweb", "lib", "target.rb")
            os.makedirs(os.path.dirname(source_file))
            os.makedirs(os.path.dirname(target_file))
            with open(source_file, "w", encoding="utf-8") as handle:
                handle.write("ruby-4-compatible\n")
            with open(target_file, "w", encoding="utf-8") as handle:
                handle.write("old-incompatible-copy\n")

            with (
                patch("tools.definitions._get_bundled_script_sources_dir", return_value=bundled),
                patch("tools.definitions._get_managed_tools_dir", return_value=managed),
            ):
                ensure_script_tools()

            with open(target_file, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "ruby-4-compatible\n")

    def test_planner_is_not_offered_internal_or_expensive_nmap_tools(self):
        descriptions = get_tool_descriptions()
        self.assertNotIn("nmap_quick", descriptions)
        self.assertNotIn("naabu_quick", descriptions)
        self.assertNotIn("naabu_full", descriptions)
        self.assertNotIn("nmap_vuln", descriptions)
        self.assertNotIn("security_headers", descriptions)

    def test_ssh_credentials_are_redacted_and_commands_allowlisted(self):
        spec = build_command(
            "creds_ssh_exec",
            {"target": "127.0.0.1", "username": "tester", "password": "supersecret", "command": "whoami"},
        )
        self.assertNotIn("supersecret", spec.display)
        self.assertIn("[REDACTED]", spec.display)
        with self.assertRaises(ValueError):
            build_command(
                "creds_ssh_exec",
                {"target": "127.0.0.1", "username": "tester", "password": "x", "command": "rm -rf /"},
            )

    def test_wordlists_cannot_read_arbitrary_files(self):
        with self.assertRaises(ValueError):
            build_command("hydra_ssh", {"target": "127.0.0.1", "wordlist": "/etc/passwd"})

    def test_wordlist_validation_treats_cross_drive_paths_as_outside(self):
        with patch("tools.definitions.os.path.commonpath", side_effect=ValueError):
            with self.assertRaisesRegex(ValueError, "inside an AEGIS"):
                build_command(
                    "hydra_ssh",
                    {"target": "127.0.0.1", "wordlist": "D:\\wordlists\\users.txt"},
                )


class ExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def test_executes_without_a_shell(self):
        executor = ToolExecutor()
        spec = CommandSpec(
            commands=[[sys.executable, "-c", "print('safe output')"]],
            timeout=5,
            display="test",
        )
        output = "".join([line async for line in executor.run_stream("test", spec)])
        self.assertEqual(output.strip(), "safe output")
        self.assertEqual(executor.last_result.exit_code, 0)

    async def test_timeout_terminates_child(self):
        executor = ToolExecutor()
        spec = CommandSpec(
            commands=[[sys.executable, "-c", "import time; time.sleep(5)"]],
            timeout=1,
            display="test-timeout",
        )
        output = "".join([line async for line in executor.run_stream("timeout", spec)])
        self.assertIn("[TIMEOUT]", output)
        self.assertTrue(executor.last_result.timed_out)
        self.assertFalse(executor.active_processes)


if __name__ == "__main__":
    unittest.main()
