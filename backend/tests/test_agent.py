import asyncio
import json
import time
import unittest
from unittest.mock import AsyncMock, patch

from agent.core import (
    AGENT_ACTION_RESPONSE_FORMAT,
    AgentMode,
    Finding,
    LLMContextError,
    LMStudioRequestError,
    PentestAgent,
    ScanState,
    _classify_from_output,
    _evidence_is_supported,
    _extract_httpx_endpoint,
    _extract_lm_message_content,
    _extract_lm_native_message_content,
    _extract_naabu_ports,
    _extract_nmap_hosts,
    _macos_local_network_preflight,
    _route_uses_tunnel,
    _scope_explicitly_allows_tunnel,
    _tool_output_succeeded,
    is_garbage_finding,
)
from agent.scope import ScopePolicy, TargetSpec, parse_target


class AgentSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.events = []

        async def emit(event, data):
            self.events.append((event, data))

        self.agent = PentestAgent("http://localhost:1234", "test-model", emit)
        self.agent.state = ScanState(target="192.0.2.10")
        self.agent.state.is_running = True
        self.agent.scope_policy = ScopePolicy.from_notes(parse_target("192.0.2.10"), "")

    async def test_tool_command_uses_authorized_host_not_original_target(self):
        captured = []

        async def fake_stream(_tool_name, spec):
            captured.append(spec.commands[0][-1])
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield "Nmap done: 1 IP address (1 host up) scanned in 0.1 seconds\n"

        # Simulate a future, looser parser returning a safe normalized host.
        # The original spelling must never become a scanner argv element.
        authorized = TargetSpec("--script=unexpected", "192.0.2.10", "ip")
        with (
            patch.object(self.agent.scope_policy, "authorize", return_value=authorized),
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "nmap_quick", {"target": "--script=unexpected"}, "normalization test"
            )

        self.assertEqual(captured, ["192.0.2.10"])

    async def test_web_command_keeps_authorized_url_path_and_query(self):
        captured = []

        async def fake_stream(_tool_name, spec):
            captured.append(spec.commands[0][-1])
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield "HTTP/1.1 200 OK\r\n\r\n"

        self.agent.state.current_phase = "web"
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "curl_headers",
                {"target": "HTTPS://192.0.2.10:8443/search?q=hello"},
                "URL normalization test",
            )

        self.assertEqual(captured, ["https://192.0.2.10:8443/search?q=hello"])

    async def test_macos_local_network_preflight_retries_initial_privacy_denial(self):
        with (
            patch("agent.core.sys.platform", "darwin"),
            patch.dict("agent.core.os.environ", {"AEGIS_DESKTOP": "1"}),
            patch(
                "agent.core._udp_local_network_permission_probe",
                side_effect=[OSError(65, "No route to host"), None],
            ) as probe,
            patch("agent.core.asyncio.sleep", new_callable=AsyncMock) as sleep,
        ):
            allowed, error = await _macos_local_network_preflight("192.168.1.99")

        self.assertTrue(allowed)
        self.assertEqual(error, "")
        self.assertEqual(probe.call_count, 2)
        sleep.assert_awaited_once_with(1)

    def test_tunnel_route_and_explicit_scope_are_distinguished(self):
        self.assertTrue(_route_uses_tunnel("route via utun4, source 10.136.11.182"))
        self.assertTrue(_route_uses_tunnel("route 10.0.5.20 dev tailscale0"))
        self.assertFalse(_route_uses_tunnel("route via en4 (Ethernet Adapter)"))
        self.assertTrue(_scope_explicitly_allows_tunnel("Authorized via VPN for this engagement"))
        self.assertFalse(_scope_explicitly_allows_tunnel("Scan the local Ethernet segment"))

    async def test_private_target_scan_stops_when_macos_selects_unapproved_tunnel(self):
        with (
            patch("agent.core.sys.platform", "darwin"),
            patch.dict("agent.core.os.environ", {"AEGIS_DESKTOP": "1"}),
            patch("agent.core._macos_local_network_preflight", new_callable=AsyncMock) as preflight,
            patch("agent.core._diagnose_target_path", new_callable=AsyncMock) as diagnose,
            patch.object(self.agent, "_agent_loop", new_callable=AsyncMock) as agent_loop,
        ):
            preflight.return_value = (True, "")
            diagnose.return_value = (
                "route via utun4, source 10.136.11.182, tunnel/VPN interface selected"
            )
            await self.agent.start_scan("10.0.5.20", llm_enabled=True)

        agent_loop.assert_not_awaited()
        self.assertTrue(self.agent.state.is_complete)
        self.assertEqual(self.agent.state.outcome, "inconclusive")
        self.assertIn("tunnel/VPN", self.agent.state.inconclusive_reason)
        self.assertTrue(any(
            event == "log" and "TUNNEL ROUTE BLOCKED" in data["message"]
            for event, data in self.events
        ))

    async def test_explicitly_authorized_vpn_target_is_allowed_to_scan(self):
        with (
            patch("agent.core.sys.platform", "darwin"),
            patch.dict("agent.core.os.environ", {"AEGIS_DESKTOP": "1"}),
            patch("agent.core._macos_local_network_preflight", new_callable=AsyncMock) as preflight,
            patch("agent.core._diagnose_target_path", new_callable=AsyncMock) as diagnose,
            patch.object(self.agent, "_agent_loop", new_callable=AsyncMock) as agent_loop,
        ):
            preflight.return_value = (True, "")
            diagnose.return_value = (
                "route via utun4, source 10.136.11.182, tunnel/VPN interface selected"
            )
            await self.agent.start_scan(
                "10.0.5.20",
                scope="Authorized via VPN for this engagement",
                llm_enabled=True,
            )

        agent_loop.assert_awaited_once()
        self.assertTrue(self.agent.state.is_running)
        self.assertFalse(self.agent.state.is_complete)

    async def test_selected_phases_are_always_run_in_safe_canonical_order(self):
        with patch.object(self.agent, "_agent_loop", new_callable=AsyncMock):
            await self.agent.start_scan(
                "192.0.2.10",
                phases=["network", "exploit", "web", "recon"],
                llm_enabled=False,
            )
        self.assertEqual(self.agent.state.phases, ["recon", "web", "network", "exploit"])
        self.assertEqual(self.agent.state.current_phase, "recon")

    async def test_empty_phase_selection_is_rejected(self):
        with self.assertRaises(ValueError):
            await self.agent.start_scan(
                "192.0.2.10",
                phases=[],
                llm_enabled=False,
            )

    async def test_restricted_ssh_scope_keeps_exploit_and_network_phases(self):
        with patch.object(self.agent, "_agent_loop", new_callable=AsyncMock):
            await self.agent.start_scan(
                "192.0.2.10",
                scope="only ports 22",
                llm_enabled=False,
            )
        self.assertIn("exploit", self.agent.state.phases)
        self.assertIn("network", self.agent.state.phases)

    async def test_arbitrary_port_scope_does_not_prune_phases_by_port_number(self):
        with patch.object(self.agent, "_agent_loop", new_callable=AsyncMock):
            await self.agent.start_scan(
                "192.0.2.10",
                scope="5000",
                phases=["recon", "web", "network", "exploit"],
                llm_enabled=False,
            )
        self.assertEqual(
            self.agent.state.phases,
            ["recon", "web", "network", "exploit"],
        )

    def test_web_service_on_arbitrary_port_is_detected_from_service_name(self):
        target = self.agent.state.target
        self.agent.state.host_ports[target] = {5000}
        self.agent.state.host_services[target] = {5000: "ssl/http"}
        self.agent.state.confirmed_service_ports[target] = {5000}
        self.assertEqual(self.agent._known_web_ports(target), {5000})
        self.assertEqual(self.agent._known_tls_ports(target), {5000})

    def test_ssh_service_on_arbitrary_port_is_not_skipped(self):
        target = self.agent.state.target
        self.agent.state.host_ports[target] = {2222}
        self.agent.state.host_services[target] = {2222: "ssh"}
        self.agent.state.confirmed_service_ports[target] = {2222}
        self.assertEqual(self.agent._known_ssh_ports(target), {2222})
        self.assertEqual(self.agent._known_network_ports(target), {2222})

    def test_evidence_must_quote_output(self):
        output = "22/tcp open ssh OpenSSH_9.9\n"
        self.assertTrue(_evidence_is_supported("22/tcp open ssh OpenSSH_9.9", output))
        self.assertFalse(_evidence_is_supported("OpenSSH 7.2 is vulnerable", output))

    def test_expected_missing_robots_files_are_a_successful_negative_result(self):
        output = (
            "curl: (22) The requested URL returned error: 404\n"
            "curl: (22) The requested URL returned error: 404\n"
        )
        self.assertTrue(_tool_output_succeeded("robots_sitemap", 22, False, "", output))
        self.assertFalse(
            _tool_output_succeeded(
                "robots_sitemap",
                22,
                False,
                "",
                output + "curl: (7) Failed to connect\n",
            )
        )

    def test_dalfox_findings_exit_is_success_but_execution_error_is_not(self):
        finding = json.dumps({
            "type": "V",
            "url": "https://example.com/search?q=payload",
            "confidence": "high",
        })
        self.assertTrue(
            _tool_output_succeeded("dalfox_scan", 1, False, "", finding + "\n")
        )
        self.assertFalse(
            _tool_output_succeeded("dalfox_scan", 2, False, "", finding + "\n")
        )
        self.assertFalse(
            _tool_output_succeeded("dalfox_scan", 1, False, "", "invalid input\n")
        )

    async def test_hallucinated_finding_is_rejected(self):
        self.agent.state.tool_history.append(
            {"tool": "nmap_quick", "exit_code": 0, "timed_out": False, "output": "22/tcp open ssh OpenSSH_9.9"}
        )
        await self.agent._record_finding(
            {
                "title": "Invented old SSH",
                "severity": "critical",
                "description": "An old version was allegedly found.",
                "evidence": "OpenSSH 7.2 is vulnerable",
                "remediation": "Upgrade.",
            }
        )
        self.assertEqual(self.agent.state.findings, [])

    async def test_approval_is_bound_to_real_finding_and_exact_tools(self):
        finding = Finding(
            title="Legacy Telnet Service Exposed",
            severity="high",
            description="Telnet is unencrypted.",
            evidence="23/tcp open telnet",
            remediation="Disable Telnet.",
            tool="nmap_quick",
            phase="recon",
        )
        self.agent.state.findings.append(finding)
        await self.agent.approve_finding_for_exploitation(finding.id)
        self.assertEqual(
            {
                approval["tool"]
                for approval in self.agent.state.approved_for_exploitation.values()
            },
            {"hydra_telnet"},
        )
        with self.assertRaises(ValueError):
            await self.agent.approve_finding_for_exploitation("missing")
        with self.assertRaises(ValueError):
            await self.agent.approve_finding_for_exploitation(finding.id, "sqlmap_test")

    async def test_same_tool_can_be_approved_for_multiple_finding_targets(self):
        urls = [
            "http://192.0.2.10:3000/products?id=1",
            "http://192.0.2.10:4000/items?id=2",
        ]
        findings = []
        for url in urls:
            finding = Finding(
                title="SQL Injection Indicator Confirmed",
                severity="high",
                description="A GET parameter produced a database error differential.",
                evidence=json.dumps({"url": url, "indicator": "database-error-differential"}),
                remediation="Use parameterized queries.",
                tool="sqli_probe",
                phase="web",
                target=url,
            )
            findings.append(finding)
            self.agent.state.findings.append(finding)
            await self.agent.approve_finding_for_exploitation(finding.id)

        approvals = self.agent._approved_actions_for_tool("sqlmap_test")
        self.assertEqual(len(approvals), 2)
        self.assertEqual({item[1]["target"] for item in approvals}, set(urls))

    def test_open_ssh_info_finding_cannot_be_approved_for_exploitation(self):
        finding = Finding(
            title="Open Port 22 (ssh)",
            severity="info",
            description="Service 'ssh' is listening on 22/tcp.",
            evidence="22/tcp open ssh",
            remediation="Restrict access.",
            tool="nmap_quick",
            phase="recon",
        )
        self.assertEqual(self.agent._permitted_exploit_tools(finding), set())

    async def test_uncertain_nmap_service_guesses_do_not_unlock_protocol_tools_or_telnet_finding(self):
        target = self.agent.state.target
        self.agent.state.host_ports[target] = {22, 23, 80, 443}
        output = (
            f"Nmap scan report for {target}\n"
            "22/tcp open ssh?\n"
            "23/tcp open telnet?\n"
            "80/tcp open http?\n"
            "443/tcp open https?\n"
        )

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield output

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "nmap_targeted",
                {"target": target, "ports": [22, 23, 80, 443]},
                "classify",
            )

        self.assertEqual(self.agent.state.confirmed_service_ports.get(target, set()), set())
        self.assertEqual(self.agent._known_web_ports(target), set())
        self.assertEqual(self.agent._known_ssh_ports(target), set())
        self.assertNotIn(
            "Legacy Telnet Service Exposed",
            {finding.title for finding in self.agent.state.findings},
        )
        self.assertTrue(all(
            "did not confirm an application protocol" in finding.description
            for finding in self.agent.state.findings
        ))

    def test_partial_ssh_audit_json_without_banner_is_failure(self):
        output = json.dumps({
            "target": "192.0.2.10:22",
            "banner": {"protocol": None, "software": None, "raw": ""},
            "kex": None,
            "key": ["ssh-rsa1"],
            "enc": None,
            "mac": None,
        }) + "\n[exception] did not receive banner: timed out\n"
        self.assertFalse(_tool_output_succeeded("ssh_audit", 1, False, "", output))

    async def test_port_name_from_non_version_nmap_is_not_telnet_evidence(self):
        await self.agent._post_analyze_and_findings(
            "nmap_quick",
            "23/tcp open telnet\n",
            self.agent.state.target,
        )
        self.assertNotIn(
            "Legacy Telnet Service Exposed",
            {finding.title for finding in self.agent.state.findings},
        )
        self.assertIn(
            "did not confirm an application protocol",
            self.agent.state.findings[0].description,
        )

    async def test_llm_cannot_promote_uncertain_nmap_label_to_vulnerability(self):
        target = self.agent.state.target
        output = "23/tcp open telnet?\n"
        self.agent.state.tool_history.append({
            "tool": "nmap_targeted",
            "target": target,
            "output": output,
            "exit_code": 0,
            "timed_out": False,
            "succeeded": True,
        })

        await self.agent._record_finding({
            "action": "finding",
            "title": "Legacy Telnet Service Exposed",
            "severity": "high",
            "description": "A Telnet service is exposed.",
            "evidence": "23/tcp open telnet?",
            "remediation": "Disable Telnet.",
            "phase": "recon",
        })

        self.assertEqual(self.agent.state.findings, [])
        self.assertTrue(any(
            event == "log" and "Rejected unconfirmed Nmap service finding" in data["message"]
            for event, data in self.events
        ))

    async def test_llm_cannot_treat_quick_scan_port_name_as_protocol_proof(self):
        target = self.agent.state.target
        output = "23/tcp open telnet\n"
        self.agent.state.tool_history.append({
            "tool": "nmap_quick",
            "target": target,
            "output": output,
            "exit_code": 0,
            "timed_out": False,
            "succeeded": True,
        })

        await self.agent._record_finding({
            "action": "finding",
            "title": "Insecure Telnet Protocol Enabled",
            "severity": "high",
            "description": "A Telnet service is exposed.",
            "evidence": "23/tcp open telnet",
            "remediation": "Disable Telnet.",
            "phase": "recon",
        })

        self.assertEqual(self.agent.state.findings, [])

    def test_explicit_domain_uses_httpx_verified_origin_from_hostname(self):
        pinned_address = self.agent.state.target
        self.agent.state.web_target = "https://example.test/login"
        self.agent.state.web_target_explicit = True
        self.agent.state.verified_web_origins["example.test"] = ["https://example.test"]
        self.assertEqual(
            self.agent._web_origins(pinned_address),
            ["https://example.test"],
        )

    def test_nmap_host_extraction_handles_named_and_plain_hosts(self):
        output = "\n".join(
            (
                "Nmap scan report for 10.0.10.46",
                "Nmap scan report for printer.local (10.0.10.71)",
                "Nmap scan report for not-an-address",
            )
        )
        self.assertEqual(_extract_nmap_hosts(output), ["10.0.10.46", "10.0.10.71"])

    def test_naabu_jsonl_and_plain_output_are_parsed(self):
        output = "\n".join(
            (
                '{"ip":"192.0.2.10","port":443}',
                '{"host":"192.0.2.10","port":80}',
                "192.0.2.11:22",
                "not a result",
            )
        )
        self.assertEqual(
            _extract_naabu_ports(output),
            {"192.0.2.10": {80, 443}, "192.0.2.11": {22}},
        )

    async def test_timed_out_naabu_preserves_partial_ports_for_targeted_nmap(self):
        target = self.agent.state.target
        output = "\n".join((
            f'{{"ip":"{target}","port":22}}',
            f'{{"ip":"{target}","port":80}}',
            f'{{"ip":"{target}","port":443}}',
            "[TIMEOUT]",
        )) + "\n"

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = None
            self.agent.executor.last_result.timed_out = True
            self.agent.executor.last_result.duration = 20.0
            yield output

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "naabu_quick",
                {"target": target},
                "discover",
            )

        self.assertEqual(self.agent.state.host_ports[target], {22, 80, 443})
        self.assertEqual(self.agent.state.profile["open_ports"], [22, 80, 443])
        self.assertEqual(
            self.agent.state.tool_history[-1]["partial_ports"],
            [22, 80, 443],
        )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_recon_step())

        run_tool.assert_awaited_once_with(
            "nmap_targeted",
            {"target": target, "ports": [22, 80, 443]},
            "Identify services and collect bounded protocol metadata on discovered ports",
        )

    async def test_naabu_open_ports_remain_findings_when_nmap_prints_no_port_table(self):
        target = self.agent.state.target
        naabu_output = "".join(
            f'{{"ip":"{target}","port":{port}}}\n'
            for port in (22, 23, 53, 80, 443)
        )

        async def successful_naabu(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.timed_out = False
            self.agent.executor.last_result.duration = 1.0
            yield naabu_output

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=successful_naabu),
        ):
            await self.agent._run_tool("naabu_quick", {"target": target}, "discover")

        self.assertEqual(len(self.agent.state.findings), 5)
        self.assertEqual(
            {finding.title for finding in self.agent.state.findings},
            {
                f"Open TCP Port {port} (protocol unconfirmed)"
                for port in (22, 23, 53, 80, 443)
            },
        )

        async def timed_out_nmap(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = None
            self.agent.executor.last_result.timed_out = True
            self.agent.executor.last_result.duration = 42.0
            yield f"Starting Nmap\nNmap scan report for {target}\n[TIMEOUT]\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=timed_out_nmap),
        ):
            await self.agent._run_tool(
                "nmap_targeted",
                {"target": target, "ports": [22, 23, 53, 80, 443]},
                "identify services",
            )

        self.assertEqual(len(self.agent.state.findings), 5)
        self.assertEqual(self.agent.state.profile["open_ports"], [22, 23, 53, 80, 443])

    async def test_nmap_service_result_upgrades_existing_naabu_port_finding(self):
        target = self.agent.state.target
        self.agent.state.tool_history.append({"tool": "naabu_quick", "target": target})
        await self.agent._post_analyze_and_findings(
            "naabu_quick",
            f'{{"ip":"{target}","port":22}}\n',
            target,
        )
        original_id = self.agent.state.findings[0].id

        self.agent.state.tool_history.append({"tool": "nmap_targeted", "target": target})
        await self.agent._post_analyze_and_findings(
            "nmap_targeted",
            f"Nmap scan report for {target}\n22/tcp open ssh OpenSSH 9.9\n",
            target,
        )

        self.assertEqual(len(self.agent.state.findings), 1)
        self.assertEqual(self.agent.state.findings[0].id, original_id)
        self.assertEqual(self.agent.state.findings[0].title, "Open Port 22 (ssh)")
        self.assertIn("Service 'ssh'", self.agent.state.findings[0].description)
        self.assertEqual(self.agent.state.findings[0].source_run_indices, [0, 1])

    async def test_fast_nmap_port_finding_does_not_claim_version_probes(self):
        target = self.agent.state.target
        await self.agent._post_analyze_and_findings(
            "nmap_quick",
            f"Nmap scan report for {target}\n18081/tcp open unknown\n",
            target,
        )
        self.assertEqual(len(self.agent.state.findings), 1)
        self.assertIn("did not confirm an application protocol", self.agent.state.findings[0].description)
        self.assertNotIn("version-detection probes", self.agent.state.findings[0].description)

    def test_httpx_prefers_https_and_returns_its_port(self):
        output = "\n".join(
            (
                '{"url":"http://192.0.2.10","port":"80"}',
                '{"url":"https://192.0.2.10/login","port":"443"}',
            )
        )
        self.assertEqual(_extract_httpx_endpoint(output), ("https://192.0.2.10", 443))

    def test_discovered_https_becomes_the_default_web_origin(self):
        target = self.agent.state.target
        self.agent.state.web_target = f"http://{target}"
        self.agent.state.host_ports[target] = {80, 443}
        self.agent.state.host_services[target] = {80: "http", 443: "https"}
        self.agent.state.confirmed_service_ports[target] = {80, 443}
        self.assertTrue(self.agent._sync_web_target_from_ports(target))
        self.assertEqual(self.agent.state.web_target, f"https://{target}")

    def test_tls_service_on_port_80_keeps_the_explicit_nondefault_port(self):
        target = self.agent.state.target
        self.agent.state.web_target = f"http://{target}"
        self.agent.state.host_ports[target] = {80}
        self.agent.state.host_services[target] = {80: "ssl/http"}
        self.agent.state.confirmed_service_ports[target] = {80}
        self.assertTrue(self.agent._sync_web_target_from_ports(target))
        self.assertEqual(self.agent.state.web_target, f"https://{target}:80")

    def test_filtered_and_closed_nmap_ports_are_not_profiled_as_open(self):
        output = "22/tcp closed ssh\n80/tcp filtered http\n443/tcp open https\n"
        updates = _classify_from_output("nmap_quick", output)
        self.assertEqual(updates["open_ports"], [443])
        self.assertEqual(updates["services"], {443: "https"})

    def test_zte_certificate_is_classified_as_embedded_appliance(self):
        output = "ssl-cert: Subject: commonName=MBB-1250746097/organizationName=ZTE\nDNS:*.ztedevice.com"
        updates = _classify_from_output("nmap_targeted", output)
        self.assertEqual(updates["device_type"], "network_appliance")
        self.assertTrue(updates["is_embedded"])

    def test_hpe_ilo_is_classified_as_embedded_management_controller(self):
        output = (
            "22/tcp open ssh HP Integrated Lights-Out mpSSH 0.2.1\n"
            "Service Info: CPE: cpe:/h:hp:integrated_lights-out\n"
        )
        updates = _classify_from_output("nmap_targeted", output)
        self.assertEqual(updates["device_type"], "server_management_controller")
        self.assertEqual(updates["web_app_type"], "embedded_mgmt")
        self.assertTrue(updates["is_embedded"])

    async def test_host_tool_is_blocked_when_given_network_range(self):
        self.agent.state = ScanState(target="10.0.10.0/24", is_subnet_target=True)
        self.agent.state.is_running = True
        self.agent.scope_policy = ScopePolicy.from_notes(parse_target("10.0.10.0/24"), "")

        with patch("agent.core.is_tool_available", return_value=True):
            await self.agent._run_tool(
                "nmap_quick",
                {"target": "10.0.10.0/24"},
                "invalid host scan",
            )

        self.assertFalse(any(event == "tool_start" for event, _ in self.events))
        self.assertTrue(
            any(
                "requires one host" in data["message"]
                for event, data in self.events
                if event == "log"
            )
        )

    async def test_restricted_ports_replace_nmap_top_ports_scan(self):
        target = self.agent.state.target
        self.agent.scope_policy = ScopePolicy.from_notes(
            parse_target(target),
            "only ports 22",
        )
        self.agent.state.target_ports = {22}
        self.agent.state.scope_restricted = True
        captured = {}

        async def fake_stream(_tool_name, spec):
            captured["commands"] = spec.commands
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield f"Nmap scan report for {target}\n22/tcp open ssh\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "nmap_quick",
                {"target": target},
                "scoped fallback",
            )

        argv = captured["commands"][0]
        self.assertNotIn("--top-ports", argv)
        self.assertNotIn("--open", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "22")

    async def test_arbitrary_scoped_port_ranges_are_compacted_in_nmap_command(self):
        target = self.agent.state.target
        self.agent.scope_policy = ScopePolicy.from_notes(
            parse_target(target),
            "22,443,8000-8002",
        )
        self.agent.state.target_ports = set(self.agent.scope_policy.allowed_ports)
        captured = {}

        async def fake_stream(_tool_name, spec):
            captured["commands"] = spec.commands
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield f"Nmap scan report for {target}\n443/tcp closed https conn-refused\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "nmap_quick",
                {"target": target},
                "scoped arbitrary ports",
            )

        argv = captured["commands"][0]
        self.assertEqual(argv[argv.index("-p") + 1], "22,443,8000-8002")
        self.assertNotIn("--open", argv)

    async def test_explicit_custom_web_port_is_not_skipped(self):
        target_url = "https://192.0.2.10:5000"
        self.agent.scope_policy = ScopePolicy.from_notes(
            parse_target(target_url),
            "only ports 5000",
        )
        self.agent.state.current_phase = "web"
        self.agent.state.target_ports = {5000}
        self.agent.state.scope_restricted = True
        self.agent.state.web_target = target_url
        self.agent.state.web_target_explicit = True

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield "HTTP/1.1 200 OK\nContent-Type: text/html\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "curl_headers",
                {"target": target_url},
                "custom HTTPS service",
            )

        self.assertTrue(any(event == "tool_start" for event, _data in self.events))

    async def test_subnet_pipeline_scans_discovered_host_not_cidr(self):
        network = "10.0.10.0/24"
        host = "10.0.10.46"
        self.agent.state = ScanState(
            target=network,
            is_subnet_target=True,
            discovered_hosts=[host],
        )
        self.agent.state.is_running = True
        self.agent.scope_policy = ScopePolicy.from_notes(parse_target(network), "")
        sweep_params = {"target": network}
        self.agent.state.executed_commands.update(
            {
                f"nmap_ping_sweep:recon:{network}",
                f"nmap_ping_sweep|{json.dumps(sweep_params, sort_keys=True)}",
            }
        )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._auto_run_next()

        run_tool.assert_awaited_once()
        tool_name, params, _ = run_tool.await_args.args
        self.assertEqual(tool_name, "naabu_quick")
        self.assertEqual(params["target"], host)

    async def test_planner_cannot_override_single_host_recon_order(self):
        # Discovery ordering is a planner contract, not a test of whether the
        # host running the suite happens to have Naabu installed.  A clean
        # Linux packaging container intentionally starts without it.
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._dispatch(
                {
                    "action": "run_tool",
                    "tool": "nmap_ping_sweep",
                    "params": {"target": "192.0.2.10/24"},
                    "reasoning": "incorrect expansion",
                }
            )

        run_tool.assert_awaited_once()
        tool_name, params, _ = run_tool.await_args.args
        self.assertEqual(tool_name, "naabu_full")
        self.assertEqual(params, {"target": "192.0.2.10"})

    async def test_preset_does_not_run_broad_nmap_vuln_after_recon(self):
        target = self.agent.state.target
        self.agent.state.tool_history.append(
            {
                "tool": "nmap_quick",
                "target": target,
                "exit_code": 0,
                "timed_out": False,
                "output": f"Nmap scan report for {target}\nHost is up.",
            }
        )
        self.agent.state.executed_commands.add(f"nmap_quick:recon:{target}")

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._auto_run_next()

        run_tool.assert_not_awaited()
        self.assertEqual(self.agent.state.current_phase, "web")

    async def test_preset_uses_full_naabu_then_targeted_nmap_for_single_host(self):
        target = self.agent.state.target
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._auto_run_next()
        self.assertEqual(run_tool.await_args.args[0], "naabu_full")

        run_tool.reset_mock()
        self.agent.state.executed_commands.update(
            {
                f"naabu_full:recon:{target}",
                f'naabu_full|{{"target": "{target}"}}',
            }
        )
        self.agent.state.tool_history.append({
            "tool": "naabu_full", "target": target, "succeeded": True,
            "exit_code": 0, "timed_out": False, "params": {"target": target},
        })
        self.agent.state.host_ports[target] = {22, 443}
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._auto_run_next()
        tool_name, params, _reason = run_tool.await_args.args
        self.assertEqual(tool_name, "nmap_targeted")
        self.assertEqual(params, {"target": target, "ports": [22, 443]})

    async def test_timed_out_full_discovery_retries_windows_before_targeted_nmap(self):
        target = self.agent.state.target
        self.agent.state.host_ports[target] = {22, 443}
        self.agent.state.tool_history.append({
            "tool": "naabu_full", "target": target, "succeeded": False,
            "exit_code": None, "timed_out": True, "partial_ports": [22, 443],
            "params": {"target": target},
        })
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_recon_step())
        self.assertEqual(run_tool.await_args.args[0], "naabu_range")
        self.assertEqual(run_tool.await_args.args[1], {
            "target": target, "port_start": 1, "port_end": 16_384,
        })
        coverage = self.agent.discovery_coverage()
        self.assertEqual(coverage["status"], "partial")
        self.assertEqual(coverage["hosts"][0]["completed_port_count"], 0)
        self.assertEqual(coverage["hosts"][0]["observed_ports"], [22, 443])

    async def test_completed_discovery_windows_skip_finished_ranges(self):
        target = self.agent.state.target
        self.agent.state.tool_history.extend([
            {"tool": "naabu_full", "target": target, "succeeded": False, "timed_out": True},
            {"tool": "naabu_range", "target": target, "succeeded": True,
             "params": {"target": target, "port_start": 1, "port_end": 16_384}},
            {"tool": "naabu_range", "target": target, "succeeded": False, "timed_out": True,
             "params": {"target": target, "port_start": 16_385, "port_end": 32_768}},
        ])
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_recon_step())
        self.assertEqual(run_tool.await_args.args[1]["port_start"], 32_769)
        self.assertEqual(self.agent.discovery_coverage()["hosts"][0]["completed_port_count"], 16_384)

    async def test_incomplete_windows_pause_then_retry_only_failed_windows(self):
        target = self.agent.state.target
        self.agent.state.tool_history.append({
            "tool": "naabu_full", "target": target, "succeeded": False, "timed_out": True,
        })
        for start, end in ((1, 16_384), (16_385, 32_768), (32_769, 49_152), (49_153, 65_535)):
            self.agent.state.tool_history.append({
                "tool": "naabu_range", "target": target, "succeeded": False,
                "timed_out": True, "params": {"target": target, "port_start": start, "port_end": end},
            })
        with patch("agent.core.is_tool_available", return_value=True):
            pending = asyncio.create_task(self.agent._run_required_recon_step())
            await asyncio.sleep(0)
            self.assertTrue(self.agent.state.awaiting_discovery_decision)
            self.assertTrue(self.agent.state.is_paused)
            self.assertTrue(any(event == "discovery_decision_needed" for event, _ in self.events))
            self.assertTrue(await self.agent.retry_incomplete_discovery())
            self.assertFalse(await self.agent.retry_incomplete_discovery())
            self.assertFalse(await self.agent.continue_with_partial_discovery())
            self.assertTrue(await pending)
            self.assertEqual(self.agent.state.discovery_window_attempt_limit, 2)
            with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
                self.assertTrue(await self.agent._run_required_recon_step())
            self.assertEqual(run_tool.await_args.args[1]["port_start"], 1)

    async def test_successful_recovery_windows_count_complete_full_range(self):
        target = self.agent.state.target
        self.agent.state.tool_history.append({
            "tool": "naabu_full", "target": target, "succeeded": False, "timed_out": True,
        })
        for start, end in ((1, 16_384), (16_385, 32_768), (32_769, 49_152), (49_153, 65_535)):
            self.agent.state.tool_history.append({
                "tool": "naabu_range", "target": target, "succeeded": True,
                "params": {"target": target, "port_start": start, "port_end": end},
            })
        coverage = self.agent.discovery_coverage()
        self.assertEqual(coverage["status"], "complete")
        self.assertEqual(coverage["hosts"][0]["completed_port_count"], 65_535)
        self.assertEqual(coverage["hosts"][0]["incomplete_ranges"], [])

    async def test_autonomous_discovery_retries_are_bounded_then_partial(self):
        target = self.agent.state.target
        self.agent.state.mode = AgentMode.AUTONOMOUS
        self.agent.state.tool_history.append({
            "tool": "naabu_full", "target": target, "succeeded": False, "timed_out": True,
        })
        self.assertTrue(await self.agent._await_discovery_decision(target))
        self.assertEqual(self.agent.state.discovery_window_attempt_limit, 2)
        self.assertFalse(self.agent.state.awaiting_discovery_decision)
        self.assertTrue(await self.agent._await_discovery_decision(target))
        self.assertEqual(self.agent.state.discovery_window_attempt_limit, 3)
        self.assertTrue(await self.agent._await_discovery_decision(target))
        self.assertTrue(self.agent.state.continue_partial_discovery)
        self.assertFalse(self.agent.state.is_paused)

    async def test_partial_coverage_survives_continue_and_report(self):
        target = self.agent.state.target
        self.agent.state.coverage_enforced = True
        self.agent.state.tool_history.append({
            "tool": "naabu_full", "target": target, "succeeded": False,
            "timed_out": True, "partial_ports": [443], "observed_ports": [443],
        })
        self.agent.state.host_ports[target] = {443}
        self.agent.state.continue_partial_discovery = True
        with patch.object(self.agent, "_ensure_findings_from_history", new_callable=AsyncMock):
            await self.agent._finish("completed checks")
        self.assertEqual(self.agent.state.outcome, "partial")
        report = self.agent.generate_report()
        self.assertIn("**Outcome:** PARTIAL", report)
        self.assertIn("0 / 65,535", report)
        self.assertIn("Unfinished ranges", report)
        self.assertIn("not assessed", report)

    def test_evidence_snapshot_links_runs_without_raw_output_or_credentials(self):
        target = self.agent.state.target
        self.agent.state.tool_history.extend([
            {"tool": "naabu_full", "target": target, "phase": "recon",
             "succeeded": True, "duration": 3.0, "observed_ports": [443],
             "output": "password=do-not-copy-me"},
            {"tool": "nmap_targeted", "target": target, "phase": "recon",
             "succeeded": True, "duration": 2.0, "observed_ports": [443],
             "output": "443/tcp open https"},
        ])
        self.agent.state.host_ports[target] = {443}
        self.agent.state.host_services[target] = {443: "https"}
        self.agent.state.confirmed_service_ports[target] = {443}
        finding = Finding(
            title="TLS service observed", severity="info", description="TLS response",
            evidence="password=do-not-copy-me", remediation="Review", tool="nmap_targeted",
            phase="recon", target="http://192.0.2.10/admin?token=do-not-copy-me",
            source_run_indices=[1],
        )
        self.agent.state.findings.append(finding)

        snapshot = self.agent.evidence_snapshot()
        self.assertEqual(snapshot["coverage"]["status"], "complete")
        self.assertEqual(snapshot["services"][0]["stage"], "protocol_confirmed")
        self.assertEqual(snapshot["services"][0]["source_runs"], [0, 1])
        self.assertEqual(snapshot["findings"][0]["source_runs"], [1])
        self.assertEqual(snapshot["findings"][0]["target"], "http://192.0.2.10")
        self.assertFalse(snapshot["raw_values_included"])
        self.assertNotIn("do-not-copy-me", json.dumps(snapshot))
        self.assertGreater(snapshot["graph_stats"]["edges"], 0)

    async def test_completed_core_recon_advances_without_an_llm_round_trip(self):
        target = self.agent.state.target
        self.agent.state.host_ports[target] = {22, 443}
        self.agent.state.tool_history.append({
            "tool": "nmap_targeted",
            "target": target,
            "exit_code": 0,
            "timed_out": False,
            "output": f"Nmap scan report for {target}\n22/tcp open ssh\n443/tcp open https\n",
        })

        with patch("agent.core.is_tool_available", return_value=True):
            advanced = await self.agent._advance_empty_phase_without_llm()

        self.assertTrue(advanced)
        self.assertEqual(self.agent.state.current_phase, "web")

    async def test_required_web_checks_cover_each_discovered_origin(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {80, 443}
        self.agent.state.host_services[target] = {80: "http", 443: "ssl/http"}
        self.agent.state.confirmed_service_ports[target] = {80, 443}
        self.agent.state.web_target = f"https://{target}"
        self.agent.state.profile["is_embedded"] = True

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_web_step())
            run_tool.assert_awaited_once_with(
                "httpx_probe",
                {"target": target, "ports": [80, 443]},
                "Probe every discovered port for HTTP(S) in one bounded batch",
            )

            run_tool.reset_mock()
            batch_params = {"target": target, "ports": [80, 443]}
            self.agent.state.executed_commands.add(
                f'httpx_probe|{json.dumps(batch_params, sort_keys=True)}'
            )
            self.assertTrue(await self.agent._run_required_web_step())
            self.assertEqual(run_tool.await_args.args[0], "curl_headers")
            self.assertEqual(run_tool.await_args.args[1], {"target": f"https://{target}"})

            run_tool.reset_mock()
            https_params = {"target": f"https://{target}"}
            self.agent.state.executed_commands.add(
                f'curl_headers|{json.dumps(https_params, sort_keys=True)}'
            )
            self.assertTrue(await self.agent._run_required_web_step())
            self.assertEqual(run_tool.await_args.args[0], "curl_headers")
            self.assertEqual(run_tool.await_args.args[1], {"target": f"http://{target}"})

    async def test_required_network_step_audits_discovered_ssh_port(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "network"
        self.agent.state.current_phase_idx = 2
        self.agent.state.host_ports[target] = {2222}
        self.agent.state.host_services[target] = {2222: "ssh"}
        self.agent.state.confirmed_service_ports[target] = {2222}
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            ran = await self.agent._run_required_network_step()
        self.assertTrue(ran)
        self.assertEqual(run_tool.await_args.args[0], "ssh_audit")
        self.assertEqual(run_tool.await_args.args[1], {"target": target, "port": 2222})

    async def test_empty_httpx_result_stops_all_followup_web_scanners(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {80, 443}
        self.agent.state.host_services[target] = {80: "http?", 443: "https?"}
        params = {"target": target, "ports": [80, 443]}
        self.agent.state.tool_history.append({
            "tool": "httpx_probe",
            "target": target,
            "params": params,
            "exit_code": 0,
            "succeeded": True,
            "output": "",
        })

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
            patch.object(self.agent, "_advance_phase", new_callable=AsyncMock) as advance,
        ):
            await self.agent._auto_run_next()

        run_tool.assert_not_awaited()
        advance.assert_awaited_once()
        self.assertIn("No HTTP or HTTPS service", advance.await_args.args[0])

    async def test_confirmed_web_endpoint_runs_bounded_nuclei_without_llm(self):
        target = self.agent.state.target
        origin = f"https://{target}"
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {443}
        self.agent.state.host_services[target] = {443: "https"}
        self.agent.state.confirmed_service_ports[target] = {443}
        self.agent.state.verified_web_origins[target] = [origin]
        probe_params = {"target": target, "ports": [443]}
        self.agent.state.executed_commands.add(
            f'httpx_probe|{json.dumps(probe_params, sort_keys=True)}'
        )
        for tool_name in ("curl_headers", "web_assess"):
            params = {"target": origin}
            self.agent.state.executed_commands.add(
                f'{tool_name}|{json.dumps(params, sort_keys=True)}'
            )
        tls_params = {"target": target, "port": 443}
        self.agent.state.executed_commands.add(
            f'testssl_tls|{json.dumps(tls_params, sort_keys=True)}'
        )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_web_step())

        run_tool.assert_awaited_once_with(
            "nuclei_scan",
            {"target": origin},
            "Run a bounded signed-template vulnerability scan against this confirmed web endpoint",
        )

    async def test_multi_origin_web_checks_are_breadth_first_before_deep_scans(self):
        target = self.agent.state.target
        first = f"http://{target}:1234"
        second = f"http://{target}:18080"
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {1234, 18080}
        self.agent.state.host_services[target] = {1234: "http", 18080: "http"}
        self.agent.state.confirmed_service_ports[target] = {1234, 18080}
        self.agent.state.verified_web_origins[target] = [first, second]
        probe_params = {"target": target, "ports": [1234, 18080]}
        self.agent.state.executed_commands.add(
            f'httpx_probe|{json.dumps(probe_params, sort_keys=True)}'
        )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_web_step())
            run_tool.assert_awaited_once_with(
                "curl_headers",
                {"target": first},
                "Collect response headers from the discovered web endpoint",
            )

            for origin in (first, second):
                self.agent.state.executed_commands.add(
                    f'curl_headers|{json.dumps({"target": origin}, sort_keys=True)}'
                )
            run_tool.reset_mock()
            self.assertTrue(await self.agent._run_required_web_step())
            run_tool.assert_awaited_once_with(
                "web_assess",
                {"target": first},
                "Run bounded same-origin discovery and evidence-backed application checks",
            )

            self.agent.state.executed_commands.add(
                f'web_assess|{json.dumps({"target": first}, sort_keys=True)}'
            )
            run_tool.reset_mock()
            self.assertTrue(await self.agent._run_required_web_step())
            run_tool.assert_awaited_once_with(
                "web_assess",
                {"target": second},
                "Run bounded same-origin discovery and evidence-backed application checks",
            )

    async def test_discovered_query_on_later_origin_runs_confirmation_probes(self):
        target = self.agent.state.target
        first = f"http://{target}:1234"
        second = f"http://{target}:18080"
        query_url = f"{second}/products?id=1"
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {1234, 18080}
        self.agent.state.host_services[target] = {1234: "http", 18080: "http"}
        self.agent.state.confirmed_service_ports[target] = {1234, 18080}
        self.agent.state.verified_web_origins[target] = [first, second]
        self.agent.state.discovered_web_urls[second] = [query_url]
        for tool_name, params in (
            ("httpx_probe", {"target": target, "ports": [1234, 18080]}),
            ("curl_headers", {"target": first}),
            ("curl_headers", {"target": second}),
            ("web_assess", {"target": first}),
            ("web_assess", {"target": second}),
        ):
            self.agent.state.executed_commands.add(
                f'{tool_name}|{json.dumps(params, sort_keys=True)}'
            )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_web_step())

        run_tool.assert_awaited_once_with(
            "sqli_probe",
            {"target": query_url},
            "Test discovered query parameters for bounded SQL-injection indicators",
        )

    def test_automatic_query_probes_skip_obvious_state_changing_routes(self):
        target = self.agent.state.target
        origin = f"http://{target}:18080"
        safe_url = f"{origin}/search?q=hello"
        self.agent.state.current_phase = "web"
        self.agent.state.verified_web_origins[target] = [origin]
        self.agent.state.discovered_web_urls[origin] = [
            f"{origin}/transfer?to=alice&amount=10",
            f"{origin}/logout?confirm=yes",
            safe_url,
        ]

        self.assertEqual(self.agent._web_query_targets(), [safe_url])

    def test_web_phase_budget_grows_for_multiple_origins(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.verified_web_origins[target] = [
            f"http://{target}:{port}" for port in (3000, 4000, 5000, 6000)
        ]
        with patch("agent.core.is_tool_available", return_value=True):
            self.assertGreater(self.agent._phase_tool_limit(), 10)
            self.assertLessEqual(self.agent._phase_tool_limit(), 42)

    async def test_approved_exploit_is_offered_at_exploit_phase_with_second_gate(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "exploit"
        self.agent.state.current_phase_idx = 3
        self.agent.state.approved_for_exploitation["hydra_telnet"] = {
            "finding_id": "finding-1",
            "finding_title": "Legacy Telnet Service Exposed",
            "target": target,
            "port": 23,
            "approved_at": 9999999999,
        }

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_exploit_step())

        run_tool.assert_awaited_once_with(
            "hydra_telnet",
            {"target": target},
            "Second confirmation for approved finding: Legacy Telnet Service Exposed",
        )

    async def test_exploit_phase_waits_for_operator_when_mapped_actions_exist(self):
        target_url = "http://192.0.2.10:18080/products?id=1"
        finding = Finding(
            title="SQL Injection Indicator Confirmed",
            severity="high",
            description="A bounded probe produced a database error differential.",
            evidence=json.dumps({"url": target_url, "indicator": "database-error-differential"}),
            remediation="Use parameterized queries.",
            tool="sqli_probe",
            phase="web",
            target=target_url,
        )
        self.agent.state.findings.append(finding)
        self.agent.state.phases = ["exploit"]
        self.agent.state.current_phase = "exploit"
        self.agent.state.current_phase_idx = 0

        wait_task = asyncio.create_task(self.agent._advance_empty_phase_without_llm())
        await asyncio.sleep(0)

        self.assertFalse(wait_task.done())
        self.assertTrue(self.agent.state.awaiting_exploit_decision)
        self.assertTrue(self.agent.state.is_paused)
        decision = [data for event, data in self.events if event == "exploit_decision_needed"][-1]
        self.assertEqual(decision["findings"][0]["id"], finding.id)
        self.assertEqual(decision["findings"][0]["tools"], ["sqlmap_test"])

        resume_needed = await self.agent.approve_finding_for_exploitation(finding.id)
        self.assertFalse(resume_needed)
        self.assertTrue(await asyncio.wait_for(wait_task, timeout=1))
        self.assertFalse(self.agent.state.is_complete)
        self.assertFalse(self.agent.state.awaiting_exploit_decision)

    async def test_autonomous_exploit_phase_queues_all_mapped_actions_without_pause(self):
        target_url = "http://192.0.2.10:18080/products?id=1"
        finding = Finding(
            title="SQL Injection Indicator Confirmed",
            severity="high",
            description="A bounded probe produced a database error differential.",
            evidence=json.dumps({"url": target_url, "indicator": "database-error-differential"}),
            remediation="Use parameterized queries.",
            tool="sqli_probe",
            phase="web",
            target=target_url,
        )
        self.agent.state.mode = AgentMode.AUTONOMOUS
        self.agent.state.findings.append(finding)
        self.agent.state.phases = ["exploit"]
        self.agent.state.current_phase = "exploit"
        self.agent.state.current_phase_idx = 0

        self.assertTrue(await self.agent._advance_empty_phase_without_llm())

        self.assertFalse(self.agent.state.awaiting_exploit_decision)
        self.assertFalse(self.agent.state.is_paused)
        self.assertFalse(any(event == "exploit_decision_needed" for event, _ in self.events))
        approvals = self.agent._approved_actions_for_tool("sqlmap_test")
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0][1]["approved_by"], "autonomous-mode")
        self.assertTrue(any(
            event == "exploitation_approved" and data.get("automatic") is True
            for event, data in self.events
        ))

    async def test_autonomous_exploit_skips_immediate_confirmation(self):
        target = self.agent.state.target
        self.agent.state.mode = AgentMode.AUTONOMOUS
        self.agent.state.current_phase = "exploit"
        self.agent.state.approved_for_exploitation["slowloris_test|finding-1"] = {
            "finding_id": "finding-1",
            "finding_title": "Potential Slowloris Exposure",
            "target": target,
            "tool": "slowloris_test",
            "approved_at": time.time(),
            "approved_by": "autonomous-mode",
        }

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield "No Slowloris vulnerability detected\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "slowloris_test",
                {"target": target},
                "Autonomous execution for evidence-mapped finding",
            )

        self.assertIsNone(self.agent.state.pending_approval)
        self.assertFalse(any(event == "approval_needed" for event, _ in self.events))
        self.assertTrue(any(event == "tool_start" for event, _ in self.events))

    async def test_operator_can_explicitly_finish_without_exploitation(self):
        finding = Finding(
            title="Unescaped HTML Reflection Detected",
            severity="medium",
            description="An HTML probe was returned without encoding.",
            evidence='{"indicator":"unescaped-html-reflection"}',
            remediation="Encode untrusted output.",
            tool="xss_check",
            phase="web",
            target="http://192.0.2.10:18080/search?q=hello",
        )
        self.agent.state.findings.append(finding)
        self.agent.state.phases = ["exploit"]
        self.agent.state.current_phase = "exploit"
        self.agent.state.current_phase_idx = 0

        wait_task = asyncio.create_task(self.agent._advance_empty_phase_without_llm())
        await asyncio.sleep(0)
        self.assertTrue(await self.agent.skip_exploitation())
        self.assertTrue(await asyncio.wait_for(wait_task, timeout=1))
        self.assertTrue(self.agent.state.is_complete)
        self.assertTrue(any(event == "scan_complete" for event, _data in self.events))

    async def test_late_finding_approval_reopens_only_exploit_phase(self):
        finding = Finding(
            title="SQL Injection Indicator Confirmed",
            severity="high",
            description="A database error differential was observed.",
            evidence='{"indicator":"database-error-differential"}',
            remediation="Use parameterized queries.",
            tool="sqli_probe",
            phase="web",
            target="http://192.0.2.10:18080/products?id=1",
        )
        self.agent.state.findings.append(finding)
        self.agent.state.phases = ["recon", "web", "network", "exploit"]
        self.agent.state.current_phase = "exploit"
        self.agent.state.current_phase_idx = 3
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.outcome = "complete"

        self.assertTrue(await self.agent.approve_finding_for_exploitation(finding.id))
        self.assertTrue(self.agent.state.is_running)
        self.assertFalse(self.agent.state.is_complete)
        self.assertEqual(self.agent.state.current_phase, "exploit")
        self.assertTrue(any(event == "scan_resumed" for event, _data in self.events))

    async def test_existing_nmap_discovery_never_schedules_naabu_afterward(self):
        target = self.agent.state.target
        self.agent.state.tool_history.append(
            {
                "tool": "nmap_quick",
                "target": target,
                "exit_code": 0,
                "timed_out": False,
                "output": f"Nmap scan report for {target}\n443/tcp open https",
            }
        )
        self.agent.state.host_ports[target] = {443}
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._run_required_recon_step()

        run_tool.assert_awaited_once()
        self.assertEqual(run_tool.await_args.args[0], "nmap_targeted")

    async def test_explicit_port_scope_checks_every_port_with_nmap_before_naabu(self):
        target = self.agent.state.target
        self.agent.scope_policy = ScopePolicy.from_notes(
            parse_target(target),
            "22,443,8000-8002",
        )
        self.agent.state.target_ports = set(self.agent.scope_policy.allowed_ports)

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            ran = await self.agent._run_required_recon_step()

        self.assertTrue(ran)
        self.assertEqual(run_tool.await_args.args[0], "nmap_quick")
        self.assertEqual(run_tool.await_args.args[1], {"target": target})
        self.assertIn("every explicitly scoped TCP port", run_tool.await_args.args[2])

    async def test_cross_phase_request_cannot_bypass_new_phase_prerequisites(self):
        with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
            await self.agent._dispatch(
                {
                    "action": "run_tool",
                    "tool": "httpx_probe",
                    "params": {"target": self.agent.state.target},
                }
            )

        self.assertEqual(self.agent.state.current_phase, "web")
        run_tool.assert_not_awaited()

    async def test_empty_network_and_exploit_phases_advance_without_model_calls(self):
        self.agent.state.phases = ["network", "exploit"]
        self.agent.state.current_phase = "network"
        self.agent.state.current_phase_idx = 0
        self.agent.state.visited_phases = ["network"]

        self.assertTrue(await self.agent._advance_empty_phase_without_llm())
        self.assertEqual(self.agent.state.current_phase, "exploit")
        self.assertTrue(await self.agent._advance_empty_phase_without_llm())
        self.assertTrue(self.agent.state.is_complete)

    async def test_unreachable_target_finishes_inconclusive_before_web_phase(self):
        target = self.agent.state.target
        self.agent.state.phases = ["recon", "web", "network", "exploit"]
        self.agent.state.current_phase = "recon"
        self.agent.state.current_phase_idx = 0
        self.agent.state.visited_phases = ["recon"]
        self.agent.state.executed_commands.add(f"nmap_quick:recon:{target}")
        self.agent.state.inconclusive_reason = "Nmap could not reach the target."
        self.agent.state.path_diagnostic = "route via en0 (Wi-Fi), ARP neighbor unresolved"

        self.assertTrue(await self.agent._advance_empty_phase_without_llm())
        self.assertTrue(self.agent.state.is_complete)
        self.assertEqual(self.agent.state.outcome, "inconclusive")
        self.assertEqual(self.agent.state.visited_phases, ["recon"])
        completion = [data for event, data in self.events if event == "scan_complete"][-1]
        self.assertEqual(completion["outcome"], "inconclusive")
        report = self.agent.generate_report()
        self.assertIn("**Outcome:** INCONCLUSIVE", report)
        self.assertNotIn("*No vulnerabilities found.*", report)

    async def test_nmap_unreachable_output_records_selected_interface(self):
        target = self.agent.state.target

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield (
                f"Nmap scan report for {target}\n"
                "All 1000 scanned ports are in ignored states.\n"
                "Not shown: 1000 filtered tcp ports (host-unreach)\n"
            )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch("agent.core._diagnose_target_path", new_callable=AsyncMock) as diagnose,
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            diagnose.return_value = "route via en0 (Wi-Fi), ARP neighbor unresolved"
            await self.agent._run_tool(
                "nmap_quick",
                {"target": target},
                "connectivity check",
            )

        self.assertIn("could not reach", self.agent.state.inconclusive_reason)
        self.assertIn("Wi-Fi", self.agent.state.path_diagnostic)
        self.assertTrue(
            any(
                event == "log" and "CONNECTIVITY BLOCKED" in data["message"]
                for event, data in self.events
            )
        )

    async def test_web_phase_directly_probes_https_and_http_when_discovery_found_nothing(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.web_target = f"http://{target}"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            ran = await self.agent._run_required_default_web_probe()

        self.assertTrue(ran)
        run_tool.assert_awaited_once_with(
            "httpx_probe",
            {"target": target},
            "Verify default HTTPS and HTTP endpoints after port discovery found no open ports",
        )

    async def test_restricted_web_probe_never_leaves_authorized_port(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.target_ports = {443}
        self.agent.scope_policy.ports_restricted = True
        self.agent.scope_policy.allowed_ports = {443}

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            ran = await self.agent._run_required_default_web_probe()

        self.assertTrue(ran)
        self.assertEqual(
            run_tool.await_args.args[1],
            {"target": target, "ports": [443]},
        )

    async def test_restricted_arbitrary_port_is_http_probed_even_when_nmap_misses_it(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.target_ports = {17988}
        self.agent.scope_policy.ports_restricted = True
        self.agent.scope_policy.allowed_ports = {17988}

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            ran = await self.agent._run_required_default_web_probe()

        self.assertTrue(ran)
        self.assertEqual(
            run_tool.await_args.args[1],
            {"target": target, "ports": [17988]},
        )

    def test_nmap_summary_does_not_treat_pn_footer_as_reachability(self):
        output = (
            "Nmap scan report for 192.0.2.10\n"
            "Host seems down. If it is really up, but blocking our ping probes, try -Pn\n"
            "Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds\n"
        )
        summary = self.agent._summarize_for_llm("nmap_quick", output)
        self.assertIn("No confirmed open ports", summary)
        self.assertIn("do not infer that the target is reachable", summary)

    async def test_httpx_result_updates_followup_web_origin(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.web_target = f"http://{target}"

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield json.dumps({"url": f"https://{target}/login", "port": 443}) + "\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "httpx_probe",
                {"target": f"http://{target}"},
                "probe",
            )

        self.assertEqual(self.agent.state.web_target, f"https://{target}")
        self.assertIn(443, self.agent.state.host_ports[target])

    async def test_batched_httpx_classifies_every_confirmed_web_port(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {80, 8443, 17988}

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield json.dumps({"url": f"http://{target}:80", "port": "80"}) + "\n"
            yield json.dumps({"url": f"https://{target}:8443", "port": "8443"}) + "\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "httpx_probe",
                {"target": target, "ports": [80, 8443, 17988]},
                "batch probe",
            )

        self.assertEqual(self.agent.state.host_services[target][80], "http")
        self.assertEqual(self.agent.state.host_services[target][8443], "https")
        self.assertNotIn(17988, self.agent.state.host_services[target])
        self.assertEqual(self.agent.state.web_target, f"https://{target}:8443")

    async def test_http_probe_never_downgrades_a_preferred_https_origin(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.web_target = f"https://{target}"

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield json.dumps({"url": f"http://{target}", "port": 80}) + "\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "httpx_probe",
                {"target": f"http://{target}"},
                "probe HTTP",
            )

        self.assertEqual(self.agent.state.web_target, f"https://{target}")

    async def test_resume_preserves_tool_history_phase_and_dedup_state(self):
        self.agent.state.is_running = False
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.visited_phases = ["recon", "web"]
        self.agent.state.tool_history.append({"tool": "naabu_quick", "target": self.agent.state.target})
        self.agent.state.executed_commands.add("sentinel")

        with patch.object(self.agent, "_agent_loop", new_callable=AsyncMock) as loop:
            await self.agent.user_message("continue")
            await asyncio.sleep(0)

        self.assertEqual(self.agent.state.current_phase, "web")
        self.assertEqual(len(self.agent.state.tool_history), 1)
        self.assertIn("sentinel", self.agent.state.executed_commands)
        loop.assert_awaited_once()

    async def test_skip_advances_without_clearing_history(self):
        self.agent.state.visited_phases = ["recon"]
        self.agent.state.tool_history.append({"tool": "naabu_quick", "target": self.agent.state.target})
        await self.agent.user_message("go to the next phase")
        self.assertEqual(self.agent.state.current_phase, "web")
        self.assertEqual(len(self.agent.state.tool_history), 1)
        self.assertEqual(self.agent.state.visited_phases, ["recon", "web"])

    async def test_next_phase_does_not_require_irrelevant_tool_quota(self):
        await self.agent._dispatch({"action": "next_phase", "summary": "nothing applicable"})
        self.assertEqual(self.agent.state.current_phase, "web")

    async def test_completed_scan_still_requires_per_action_confirmation(self):
        target = self.agent.state.target
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.approved_for_exploitation["slowloris_test"] = {
            "target": target,
            "approved_at": 9999999999,
        }
        with patch("agent.core.is_tool_available", return_value=True):
            task = asyncio.create_task(
                self.agent._run_tool(
                    "slowloris_test",
                    {"target": target},
                    "confirm after investigation",
                )
            )
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertEqual(self.agent.state.pending_approval["tool"], "slowloris_test")
            await self.agent.reject_tool()
            await asyncio.wait_for(task, timeout=1)
        self.assertFalse(any(event == "tool_start" for event, _data in self.events))

    async def test_completed_scan_answers_exploit_question_without_running_anything(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.scope = "original scope"
        self.agent.state.findings.append(
            Finding(
                title="Weak and Deprecated SSH Algorithms Enabled",
                severity="medium",
                description="The SSH service permits legacy algorithms.",
                evidence="[fail] ssh-dss -- [fail] using weak hashing algorithm",
                remediation="Disable legacy SSH algorithms.",
                tool="ssh_audit",
                phase="network",
            )
        )

        with (
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
            patch.object(self.agent, "_ask_completed_scan_llm", new_callable=AsyncMock) as ask_llm,
        ):
            await self.agent.user_message("any exploits to run?")

        run_tool.assert_not_awaited()
        ask_llm.assert_not_awaited()
        self.assertEqual(self.agent.state.scope, "original scope")
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertIn("No automated exploit is justified", messages[-1])
        self.assertIn("Asking this question did not run anything", messages[-1])

    async def test_completed_scan_reports_what_active_validation_proved(self):
        target_url = "http://192.0.2.10/search?q=hello"
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.tool_history.append({
            "tool": "dalfox_scan",
            "phase": "exploit",
            "target": target_url,
            "exit_code": 1,
            "succeeded": True,
        })
        self.agent.state.findings.append(Finding(
            title="Dalfox Confirmed Cross-Site Scripting",
            severity="high",
            description="Dalfox confirmed executable XSS.",
            evidence='{"type":"V"}',
            remediation="Encode untrusted output.",
            tool="dalfox_scan",
            phase="exploit",
            target=target_url,
        ))

        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            new_callable=AsyncMock,
            return_value=(
                "Yes. A user-approved Dalfox run confirmed executable XSS, but it did not "
                "extract credentials or establish a session."
            ),
        ) as ask_llm:
            await self.agent.user_message("did AEGIS actually exploit anything?")

        ask_llm.assert_awaited_once_with("did AEGIS actually exploit anything?")
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertIn("confirmed executable XSS", messages[-1])
        self.assertIn("did not extract credentials", messages[-1])

    async def test_completed_scan_raw_evidence_export_bypasses_llm_and_reveals_values(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.loot.append({
            "type": "creds",
            "service": "http",
            "host": "192.0.2.10",
            "username": "admin",
            "password": "admin",
            "source": "default_web_login",
        })
        self.agent._operator_evidence.append({
            "source": "cookie_auth_check",
            "category": "approved-authorization-bypass-response",
            "url": "http://192.0.2.10/admin",
            "content_type": "application/json",
            "body": json.dumps({"flag": "AEGIS-LAB{captured-proof}"}),
            "truncated": False,
        })

        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            new_callable=AsyncMock,
        ) as ask_llm:
            await self.agent.user_message("show all raw extracted credentials and evidence")

        ask_llm.assert_not_awaited()
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertIn("username=admin", messages[-1])
        self.assertIn("password=admin", messages[-1])
        self.assertIn("AEGIS-LAB{captured-proof}", messages[-1])
        self.assertNotIn("AEGIS-LAB{captured-proof}", self.agent._completed_scan_context())
        self.assertNotIn("AEGIS-LAB{captured-proof}", self.agent.generate_report())

    async def test_approved_evidence_survives_full_ledger_and_is_ranked_for_flag_question(self):
        question = "Briefly, what flag did the approved cookie bypass retrieve?"
        self.assertTrue(self.agent._is_extracted_information_question(question))
        self.assertFalse(self.agent._is_extracted_information_question("What is a flag?"))
        for index in range(80):
            self.agent._retain_operator_evidence("web_assess", [{
                "category": "passive-response",
                "url": f"http://192.0.2.10/path/{index}",
                "body": (
                    '{"flag":"AEGIS-LAB{passive-decoy}"}'
                    if index == 40 else "unrelated response content " * 100
                ),
            }])
        self.agent._retain_operator_evidence("cookie_auth_check", [{
            "category": "approved-authorization-bypass-response",
            "url": "http://192.0.2.10/admin",
            "body": '{"flag":"AEGIS-LAB{captured-proof}"}',
        }])

        self.assertEqual(len(self.agent._operator_evidence), 80)
        self.assertIn(
            "AEGIS-LAB{captured-proof}",
            self.agent._completed_scan_private_evidence_context(question),
        )
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            side_effect=TimeoutError("local model timeout"),
        ):
            await self.agent.user_message(question)
        answers = [
            data["message"] for event, data in self.events
            if event == "log" and data.get("type") == "agent"
        ]
        self.assertIn("AEGIS-LAB{captured-proof}", answers[-1])
        self.assertNotIn("AEGIS-LAB{passive-decoy}", answers[-1])
        self.assertNotIn("AEGIS-LAB{captured-proof}", self.agent.generate_report())

    async def test_flag_timeout_does_not_attribute_unrelated_approved_evidence(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent._retain_operator_evidence("default_web_login", [{
            "category": "approved-default-login-access",
            "url": "http://192.0.2.10/login",
            "body": '{"flag":"AEGIS-LAB{unrelated-login}"}',
        }])
        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            side_effect=TimeoutError("local model timeout"),
        ):
            await self.agent.user_message(
                "What flag did the approved cookie bypass retrieve?"
            )
        answers = [
            data["message"] for event, data in self.events
            if event == "log" and data.get("type") == "agent"
        ]
        self.assertNotIn("AEGIS-LAB{unrelated-login}", answers[-1])
        self.assertIn("could not tie", answers[-1])

    async def test_tool_run_copies_private_evidence_without_public_output(self):
        target = "http://192.0.2.10/.env"
        self.agent.state.current_phase = "web"

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            self.agent.executor.last_private_artifacts = [{
                "category": "secret-or-configuration",
                "url": target,
                "content_type": "text/plain",
                "body": "API_TOKEN=raw-private-value",
                "truncated": False,
            }]
            yield json.dumps({
                "type": "exposed_sensitive_resource",
                "url": target,
                "status": 200,
                "category": "secret-or-configuration",
                "markers": ["API_TOKEN"],
                "content_type": "text/plain",
            }) + "\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool("web_assess", {"target": target}, "assess")

        self.assertIn("raw-private-value", self.agent._operator_evidence[0]["body"])
        public_tool_output = "".join(
            data["line"]
            for event, data in self.events
            if event == "tool_output"
        )
        self.assertNotIn("raw-private-value", public_tool_output)
        self.assertNotIn("raw-private-value", self.agent.state.tool_history[-1]["output"])

    async def test_completed_scan_findings_summary_uses_grounded_llm(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        for index in range(10):
            self.agent.state.findings.append(Finding(
                title=f"Finding {index}",
                severity="high" if index < 5 else "medium",
                description=f"Concrete detail {index}.",
                evidence=f"proof-{index}",
                remediation=f"Fix {index}.",
                tool="test_tool",
                phase="web",
                target=f"http://192.0.2.10/item/{index}",
            ))

        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            new_callable=AsyncMock,
            return_value="Ten findings were recorded; five high and five medium.",
        ) as ask_llm:
            await self.agent.user_message("summarize all the findings")

        ask_llm.assert_awaited_once_with("summarize all the findings")
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertEqual(messages[-1], "Ten findings were recorded; five high and five medium.")

    async def test_completed_scan_credential_question_uses_llm_with_private_evidence(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.loot.append({
            "type": "creds",
            "service": "http",
            "host": "192.0.2.10",
            "username": "admin",
            "password": "admin",
        })
        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            new_callable=AsyncMock,
            return_value="Yes — AEGIS confirmed admin:admin for the web login.",
        ) as ask_llm:
            await self.agent.user_message("did any credentials get extracted?")

        ask_llm.assert_awaited_once_with(
            "did any credentials get extracted?", include_private=True,
        )
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertEqual(messages[-1], "Yes — AEGIS confirmed admin:admin for the web login.")

    async def test_completed_scan_answers_unpunctuated_question_as_read_only(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.scope = "original scope"

        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            new_callable=AsyncMock,
            return_value="No evidence-backed exploit is available.",
        ) as ask_llm:
            await self.agent.user_message("do you have anything else to investigate")

        ask_llm.assert_awaited_once()
        self.assertEqual(self.agent.state.scope, "original scope")
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertEqual(messages[-1], "No evidence-backed exploit is available.")

    async def test_completed_scan_general_question_uses_grounded_qa(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.scope = "original scope"

        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            new_callable=AsyncMock,
            return_value="Prioritize removal of the legacy SSH algorithms.",
        ) as ask_llm:
            await self.agent.user_message("what should I fix first?")

        ask_llm.assert_awaited_once_with("what should I fix first?")
        self.assertEqual(self.agent.state.scope, "original scope")
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertEqual(messages[-1], "Prioritize removal of the legacy SSH algorithms.")

    async def test_conceptual_exploitability_question_uses_local_llm(self):
        question = "so why would you care if TLS protocol is deprecated if it cant be exploited?"
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.findings.append(
            Finding(
                title="Deprecated TLS Protocols Enabled",
                severity="medium",
                description="TLS 1.0 is enabled.",
                evidence="TLSv1.0 offered",
                remediation="Disable TLS 1.0 and TLS 1.1.",
                tool="testssl_tls",
                phase="web",
            )
        )

        with patch.object(
            self.agent,
            "_ask_completed_scan_llm",
            new_callable=AsyncMock,
            return_value="It is a hardening risk, not proof of direct exploitability.",
        ) as ask_llm:
            await self.agent.user_message(question)

        ask_llm.assert_awaited_once_with(question)
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertIn("Consulting the selected local LLM", messages[-2])
        self.assertEqual(
            messages[-1],
            "It is a hardening risk, not proof of direct exploitability.",
        )

    async def test_completed_scan_question_has_useful_no_llm_fallback(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.llm_enabled = False
        self.agent.state.findings.append(
            Finding(
                title="Deprecated TLS Protocols Enabled",
                severity="medium",
                description="TLS 1.0 is enabled.",
                evidence="TLSv1.0",
                remediation="Disable TLS 1.0 and TLS 1.1.",
                tool="ssl_check",
                phase="web",
            )
        )

        await self.agent.user_message("what should I fix first?")

        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertIn("Deprecated TLS Protocols Enabled", messages[-1])
        self.assertIn("Disable TLS 1.0 and TLS 1.1", messages[-1])

    async def test_completed_scan_explicit_tool_command_still_reaches_tool_gates(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True

        with (
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
            patch.object(self.agent, "_answer_completed_scan_question", new_callable=AsyncMock) as answer,
        ):
            await self.agent.user_message("run nmap_vuln 192.0.2.10")

        run_tool.assert_awaited_once_with(
            "nmap_vuln",
            {"target": "192.0.2.10"},
            "Direct tool execution requested by operator",
        )
        answer.assert_not_awaited()

    async def test_completed_scan_direct_tool_accepts_a_url_query_string(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        target = "http://192.0.2.10/search?q=hello"

        with (
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
            patch.object(self.agent, "_answer_completed_scan_question", new_callable=AsyncMock) as answer,
        ):
            await self.agent.user_message(f"run xss_check {target}")

        run_tool.assert_awaited_once_with(
            "xss_check",
            {"target": target},
            "Direct tool execution requested by operator",
        )
        answer.assert_not_awaited()

    async def test_completed_scan_execute_alias_reaches_the_direct_tool_path(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        target = "http://192.0.2.10/search?q=hello"

        with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
            await self.agent.user_message(f"execute xss_check {target}")

        run_tool.assert_awaited_once_with(
            "xss_check",
            {"target": target},
            "Direct tool execution requested by operator",
        )

    async def test_completed_scan_inapplicable_exploit_command_gets_an_answer(self):
        self.agent.state.is_running = False
        self.agent.state.is_complete = True
        self.agent.state.scope = "original scope"

        with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
            await self.agent.user_message("exploit the SSH service")

        run_tool.assert_not_awaited()
        self.assertEqual(self.agent.state.scope, "original scope")
        messages = [data["message"] for event, data in self.events if event == "log"]
        self.assertIn("No automated exploit is justified", messages[-1])

    async def test_skipping_phase_rejects_a_pending_tool_confirmation(self):
        target = self.agent.state.target
        self.agent.state.approved_for_exploitation["slowloris_test"] = {
            "target": target,
            "approved_at": 9999999999,
        }
        with patch("agent.core.is_tool_available", return_value=True):
            task = asyncio.create_task(
                self.agent._run_tool(
                    "slowloris_test",
                    {"target": target},
                    "pending confirmation",
                )
            )
            await asyncio.sleep(0)
            await self.agent.user_message("next phase")
            await asyncio.wait_for(task, timeout=1)
        self.assertIsNone(self.agent.state.pending_approval)
        self.assertEqual(self.agent.state.current_phase, "web")

    def test_phase_pruning_never_rewinds_an_active_web_phase(self):
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.profile["is_embedded"] = True
        self.agent._prune_phases()
        self.assertEqual(self.agent.state.current_phase, "web")
        self.assertIn("web", self.agent.state.phases)
        self.assertIn("exploit", self.agent.state.phases)

    def test_embedded_profile_keeps_lightweight_web_and_gated_exploit_phases(self):
        self.agent.state.profile["is_embedded"] = True
        self.agent.state.profile["skip_heavy_web"] = True
        self.agent.state.profile["skip_exploit"] = True
        self.agent._prune_phases()
        self.assertIn("web", self.agent.state.phases)
        self.assertIn("exploit", self.agent.state.phases)

    def test_report_keeps_full_commands_and_records_actual_phases(self):
        command = "nmap -Pn -sV --version-light -sC -T4 --open -p 53,80,443 192.0.2.10"
        self.agent.state.visited_phases = ["recon", "web"]
        self.agent.state.tool_history.append(
            {
                "tool": "nmap_targeted",
                "phase": "recon",
                "command": command,
                "duration": 41.42,
                "exit_code": 0,
                "timed_out": False,
            }
        )
        report = self.agent.generate_report()
        self.assertIn("**Phases run:** recon, web", report)
        self.assertIn(command, report)
        self.assertIn("41.4s", report)

    def test_report_separates_validation_from_obtained_access(self):
        target_url = "http://192.0.2.10/search?q=hello"
        self.agent.state.tool_history.append({
            "tool": "dalfox_scan",
            "phase": "exploit",
            "target": target_url,
            "command": "dalfox scan http://192.0.2.10/search?q=hello",
            "duration": 1.2,
            "exit_code": 1,
            "succeeded": True,
        })
        self.agent.state.findings.append(Finding(
            title="Dalfox Confirmed Cross-Site Scripting",
            severity="high",
            description="Executable XSS was confirmed.",
            evidence='{"type":"V"}',
            remediation="Encode untrusted output.",
            tool="dalfox_scan",
            phase="exploit",
            target=target_url,
        ))

        report = self.agent.generate_report()

        self.assertIn("**Approved active exploit/validation runs:** 1", report)
        self.assertIn("**Exploit-phase confirmations:** 1", report)
        self.assertIn("**Reusable credentials/session artifacts retained:** no", report)
        self.assertIn("## Exploitation Outcome", report)
        self.assertIn("Credentials, sessions, shells, or files obtained:** None", report)
        self.assertNotIn("## Loot / Collected Access", report)

    def test_report_distinguishes_tcp_acceptance_from_protocol_confirmation(self):
        target = self.agent.state.target
        self.agent.state.host_ports[target] = {23, 443}
        self.agent.state.host_services[target] = {23: "telnet?", 443: "https"}
        self.agent.state.confirmed_service_ports[target] = {443}
        self.agent.state.profile["open_ports"] = [23, 443]
        self.agent.state.llm_planner_calls = 2
        report = self.agent.generate_report()
        self.assertIn("**TCP ports accepting connections:** 23, 443", report)
        self.assertIn("**Application protocols confirmed:** 1", report)
        self.assertIn("**Local-LLM planner calls:** 2", report)
        self.assertIn("service label is an unconfirmed port-name guess", report)
        self.assertIn("Protocol handshake confirmed", report)

    async def test_web_tool_dedup_happens_after_target_normalization(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.web_target = f"http://{target}"
        self.agent.state.executed_commands.add(
            f'nikto|{{"target": "http://{target}"}}'
        )
        with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
            await self.agent._dispatch(
                {"action": "run_tool", "tool": "nikto", "params": {"target": target}}
            )
        run_tool.assert_not_awaited()

    async def test_subnet_web_planning_targets_a_discovered_host_not_network_address(self):
        network = "10.0.10.0/24"
        host = "10.0.10.46"
        self.agent.state = ScanState(
            target=network,
            is_subnet_target=True,
            discovered_hosts=[host],
            host_ports={host: {80, 443}},
            host_services={host: {80: "http", 443: "https"}},
            confirmed_service_ports={host: {80, 443}},
            current_phase="web",
            current_phase_idx=1,
        )
        self.agent.state.is_running = True
        self.agent.scope_policy = ScopePolicy.from_notes(parse_target(network), "")
        with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
            await self.agent._dispatch(
                {"action": "run_tool", "tool": "whatweb", "params": {"target": network}}
            )
        run_tool.assert_awaited_once()
        self.assertEqual(run_tool.await_args.args[1]["target"], f"https://{host}")

    async def test_planner_ssl_check_uses_discovered_nondefault_tls_port(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {8443}
        self.agent.state.host_services[target] = {8443: "https-alt"}
        self.agent.state.confirmed_service_ports[target] = {8443}
        with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
            await self.agent._dispatch(
                {
                    "action": "run_tool",
                    "tool": "ssl_check",
                    "params": {"target": target},
                }
            )
        run_tool.assert_awaited_once()
        self.assertEqual(
            run_tool.await_args.args[1],
            {"target": target, "port": 8443},
        )

    async def test_planner_cannot_run_web_tools_during_exploit_phase(self):
        self.agent.state.current_phase = "exploit"
        with patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool:
            await self.agent._dispatch(
                {"action": "run_tool", "tool": "nikto", "params": {"target": self.agent.state.target}}
            )
        run_tool.assert_not_awaited()

    async def test_preset_network_skips_tools_for_absent_service_ports(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "network"
        self.agent.state.current_phase_idx = 2
        self.agent.state.host_ports[target] = {53, 80, 443}
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._auto_run_next()
        run_tool.assert_not_awaited()

    async def test_preset_web_verifies_default_protocols_when_recon_found_no_web_service(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.host_ports[target] = {22, 53}
        self.agent.state.executed_commands.add(f"naabu_quick:recon:{target}")
        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            await self.agent._auto_run_next()
        run_tool.assert_awaited_once()
        self.assertEqual(run_tool.await_args.args[0], "httpx_probe")
        self.assertEqual(
            run_tool.await_args.args[1],
            {"target": target, "ports": [22, 53]},
        )

    async def test_nuclei_jsonl_becomes_a_deterministic_finding(self):
        output = json.dumps({
            "template-id": "example-check",
            "info": {
                "name": "Example Exposure",
                "severity": "medium",
                "description": "An example exposure was detected.",
                "remediation": "Disable the exposed endpoint.",
            },
            "matched-at": "https://192.0.2.10/example",
        })
        await self.agent._post_analyze_and_findings(
            "nuclei_scan", output, "https://192.0.2.10"
        )
        finding = next(item for item in self.agent.state.findings if item.title == "Nuclei: Example Exposure")
        self.assertEqual(finding.severity, "medium")
        self.assertTrue(_evidence_is_supported(finding.evidence, output))

    def test_scope_errors_are_not_vulnerability_findings(self):
        self.assertTrue(is_garbage_finding("Target Out of Scope", "Scope blocked"))

    async def test_context_rejection_shrinks_without_duplicate_format_retry(self):
        class ContextResponse:
            status_code = 400
            text = "context length exceeded"

            @staticmethod
            def json():
                return {"error": "context length exceeded"}

        class FakeClient:
            calls = 0

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def post(self, *_args, **_kwargs):
                self.calls += 1
                return ContextResponse()

        client = FakeClient()
        with patch("agent.core.httpx.AsyncClient", return_value=client):
            with self.assertRaises(LLMContextError):
                await self.agent._ask_llm()
        self.assertEqual(client.calls, 2)

    async def test_lm_studio_request_uses_json_schema_response_format(self):
        class SuccessResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json():
                return {
                    "choices": [
                        {"message": {"content": '{"action":"next_phase","summary":"done"}'}}
                    ]
                }

        class FakeClient:
            payload = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def post(self, *_args, **kwargs):
                self.payload = kwargs["json"]
                return SuccessResponse()

        client = FakeClient()
        with patch("agent.core.httpx.AsyncClient", return_value=client):
            response = await self.agent._ask_llm()

        self.assertEqual(response, '{"action":"next_phase","summary":"done"}')
        self.assertEqual(client.payload["response_format"], AGENT_ACTION_RESPONSE_FORMAT)
        self.assertEqual(client.payload["response_format"]["type"], "json_schema")
        self.assertEqual(client.payload["messages"][-1]["role"], "user")

    async def test_qwen_requests_non_thinking_mode_and_complete_json_budget(self):
        class SuccessResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json():
                return {"output": [{"type": "message", "content": '{"action":"next_phase"}'}]}

        class FakeClient:
            payload = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def post(self, *_args, **kwargs):
                self.payload = kwargs["json"]
                return SuccessResponse()

        self.agent.model = "qwen/qwen3.5-9b"
        client = FakeClient()
        with patch("agent.core.httpx.AsyncClient", return_value=client):
            await self.agent._ask_llm()

        self.assertEqual(client.payload["reasoning"], "off")
        self.assertGreaterEqual(client.payload["max_output_tokens"], 640)
        self.assertEqual(client.payload["context_length"], 8192)
        self.assertNotIn("/no_think", client.payload["input"])

    async def test_qwen_prompt_template_error_retries_with_simplified_history(self):
        class FakeResponse:
            text = ""

            def __init__(self, status_code, payload):
                self.status_code = status_code
                self.payload = payload

            def json(self):
                return self.payload

        class FakeClient:
            def __init__(self):
                self.payloads = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def post(self, *_args, **kwargs):
                self.payloads.append(kwargs["json"])
                if len(self.payloads) == 1:
                    return FakeResponse(
                        400,
                        {"error": 'Error rendering prompt with jinja template: "No user query found in messages."'},
                    )
                return FakeResponse(
                    200,
                    {"choices": [{"message": {"content": '{"action":"next_phase","summary":"done"}'}}]},
                )

        self.agent.state.message_history = [
            {"role": "assistant", "content": '{"action":"finding"}'},
            {"role": "user", "content": "Finding rejected. Continue."},
            {"role": "assistant", "content": '{"action":"finding"}'},
        ]
        client = FakeClient()
        with patch("agent.core.httpx.AsyncClient", return_value=client):
            response = await self.agent._ask_llm()

        self.assertEqual(response, '{"action":"next_phase","summary":"done"}')
        self.assertEqual(len(client.payloads), 2)
        for payload in client.payloads:
            conversation = payload["messages"][1:]
            self.assertTrue(conversation)
            self.assertEqual(conversation[0]["role"], "user")
            self.assertEqual(conversation[-1]["role"], "user")

    async def test_nikto_missing_header_output_creates_supported_finding(self):
        output = "\n".join(
            (
                "- [013587] /: Suggested security header missing: permissions-policy.",
                "- [013587] /: Suggested security header missing: content-security-policy.",
            )
        )

        await self.agent._post_analyze_and_findings("nikto", output, "http://192.0.2.10")

        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Recommended Browser Security Headers Missing"
        )
        self.assertEqual(finding.severity, "low")
        self.assertTrue(_evidence_is_supported(finding.evidence, output))
        self.assertIn("content-security-policy", finding.description)

    async def test_ssl_check_records_deprecated_protocols(self):
        output = "\n".join((
            "| ssl-enum-ciphers:",
            "|   TLSv1.0:",
            "|     ciphers:",
            "|   TLSv1.1:",
            "|     ciphers:",
            "|   TLSv1.2:",
        ))
        await self.agent._post_analyze_and_findings("ssl_check", output, "192.0.2.10")
        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Deprecated TLS Protocols Enabled"
        )
        self.assertEqual(finding.severity, "medium")
        self.assertTrue(_evidence_is_supported(finding.evidence, output))
        self.assertIn("TLSv1.0", finding.description)

    async def test_testssl_records_only_offered_deprecated_protocols(self):
        output = "\n".join((
            " SSLv3      not offered",
            " TLS 1.0    offered (deprecated)",
            " TLS 1.1    offered (deprecated)",
            " TLS 1.2    offered",
        ))
        await self.agent._post_analyze_and_findings(
            "testssl_tls", output, "192.0.2.10"
        )
        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Deprecated TLS Protocols Enabled"
        )
        self.assertEqual(finding.severity, "medium")
        self.assertIn("TLS 1.0", finding.evidence)
        self.assertNotIn("SSLv3", finding.evidence)
        self.assertTrue(_evidence_is_supported(finding.evidence, output))

    async def test_netexec_records_disabled_smb_signing(self):
        output = "SMB 192.0.2.10 445 LAB [*] Windows 11 (signing:False) (SMBv1:False)\n"
        await self.agent._post_analyze_and_findings(
            "netexec_smb", output, "192.0.2.10"
        )
        finding = next(
            item for item in self.agent.state.findings
            if item.title == "SMB Signing Is Not Required"
        )
        self.assertEqual(finding.severity, "medium")
        self.assertTrue(_evidence_is_supported(finding.evidence, output))

    async def test_dalfox_records_confirmed_xss_from_jsonl(self):
        output = json.dumps({
            "type": "V",
            "url": "http://192.0.2.10/search?q=%3Csvg%3E",
            "confidence": "high",
        })
        await self.agent._post_analyze_and_findings(
            "dalfox_scan", output, "http://192.0.2.10/search?q=hello"
        )
        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Dalfox Confirmed Cross-Site Scripting"
        )
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.target, "http://192.0.2.10/search?q=hello")
        self.assertTrue(_evidence_is_supported(finding.evidence, output))
        self.assertEqual(self.agent._permitted_exploit_tools(finding), set())

    async def test_exploit_confirmation_does_not_create_a_recursive_decision(self):
        self.agent.state.current_phase = "exploit"
        target_url = "http://192.0.2.10/search?q=hello"
        output = json.dumps({
            "type": "V",
            "data": "http://192.0.2.10/search?q=%3Csvg%20onload%3Dalert(1)%3E",
            "confidence": "high",
        })

        await self.agent._post_analyze_and_findings(
            "dalfox_scan",
            output,
            target_url,
        )

        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Dalfox Confirmed Cross-Site Scripting"
        )
        self.assertEqual(finding.target, target_url)
        self.assertEqual(self.agent._permitted_exploit_tools(finding), set())
        self.assertEqual(self.agent._unresolved_exploit_findings(), [])

    async def test_sqlmap_confirmation_is_a_terminal_finding_not_loot(self):
        self.agent.state.current_phase = "exploit"
        target_url = "http://192.0.2.10/api/products?id=1"
        output = """[INFO] sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234
---
"""

        await self.agent._post_analyze_and_findings(
            "sqlmap_test",
            output,
            target_url,
        )
        await self.agent._extract_and_store_loot("sqlmap_test", output)

        finding = next(
            item for item in self.agent.state.findings
            if item.title == "SQLMap Confirmed SQL Injection"
        )
        self.assertEqual(finding.target, target_url)
        self.assertIn("GET parameter 'id'", finding.description)
        self.assertTrue(_evidence_is_supported(finding.evidence, output))
        self.assertEqual(self.agent._permitted_exploit_tools(finding), set())
        self.assertEqual(self.agent.state.loot, [])

    async def test_default_web_login_confirmation_is_redacted_reusable_access(self):
        output = json.dumps({
            "type": "default_web_login_confirmation",
            "url": "http://192.0.2.10/login",
            "username": "admin",
            "baseline_status": 401,
            "candidate_status": 302,
        })

        await self.agent._extract_and_store_loot("default_web_login", output)

        self.assertEqual(len(self.agent.state.loot), 1)
        self.assertEqual(self.agent.state.loot[0]["username"], "admin")
        self.assertEqual(self.agent.state.loot[0]["password"], "admin")
        public = [data for event, data in self.events if event == "loot"][-1]
        self.assertEqual(public["password"], "[REDACTED]")
        self.agent.state.findings.append(Finding(
            title="Admin Route Access Confirmed",
            severity="critical",
            description="The /admin route accepted the approved session.",
            evidence="GET /admin -> 200",
            remediation="Protect /admin with server-side authorization.",
            tool="default_web_login",
            phase="exploit",
            target="http://192.0.2.10/admin",
        ))
        report = self.agent.generate_report()
        self.assertIn("http://192.0.2.10/admin", report)
        self.assertIn("**Reusable credentials/session artifacts retained:** yes", report)

    async def test_reprocessing_identical_targeted_nmap_output_does_not_reemit_update(self):
        output = """Nmap scan report for 192.0.2.10
PORT      STATE SERVICE
18080/tcp open  http
"""
        await self.agent._post_analyze_and_findings("nmap_quick", output, "192.0.2.10")
        await self.agent._post_analyze_and_findings("nmap_targeted", output, "192.0.2.10")
        await self.agent._post_analyze_and_findings("nmap_targeted", output, "192.0.2.10")

        updates = [data for event, data in self.events if event == "finding_updated"]
        self.assertEqual(len(updates), 1)

    async def test_web_assessment_candidates_map_to_specific_gated_actions(self):
        records = [
            {
                "type": "state_changing_get_candidate",
                "url": "http://192.0.2.10/transfer?amount=10",
            },
            {
                "type": "privileged_cookie_candidate",
                "url": "http://192.0.2.10/impersonate?role=admin",
                "cookie_names": ["role"],
            },
            {
                "type": "unauthenticated_write_candidate",
                "url": "http://192.0.2.10/api/notes",
                "advertised_methods": ["POST"],
            },
            {
                "type": "default_login_candidate",
                "url": "http://192.0.2.10/login",
                "username": "admin",
            },
        ]
        await self.agent._post_analyze_and_findings(
            "web_assess",
            "\n".join(json.dumps(item, sort_keys=True) for item in records),
            "http://192.0.2.10",
        )

        mapped = {
            finding.title: self.agent._permitted_exploit_tools(finding)
            for finding in self.agent.state.findings
        }
        self.assertEqual(
            mapped["Potential State-Changing GET / CSRF Exposure"],
            {"csrf_get_check"},
        )
        self.assertEqual(
            mapped["Unauthenticated Privileged Cookie Issuance"],
            {"cookie_auth_check"},
        )
        self.assertEqual(
            mapped["Potential Unauthenticated API Write"],
            {"unauthenticated_write_check"},
        )
        self.assertEqual(
            mapped["Default Web Credential Candidate"],
            {"default_web_login"},
        )

    async def test_active_confirmation_upgrades_candidate_without_a_loop(self):
        target = "http://192.0.2.10/transfer?amount=10"
        candidate = json.dumps({
            "type": "state_changing_get_candidate",
            "url": target,
        })
        await self.agent._post_analyze_and_findings("web_assess", candidate, target)
        original_id = self.agent.state.findings[0].id
        self.agent.state.current_phase = "exploit"
        confirmation = json.dumps({
            "type": "csrf_get_confirmation",
            "url": target,
            "status": 200,
            "csrf_token_checked": False,
            "result_fields": ["accepted"],
        })

        await self.agent._post_analyze_and_findings("csrf_get_check", confirmation, target)

        self.assertEqual(len(self.agent.state.findings), 1)
        finding = self.agent.state.findings[0]
        self.assertEqual(finding.id, original_id)
        self.assertEqual(finding.title, "State-Changing GET Without CSRF Protection Confirmed")
        self.assertEqual(finding.phase, "exploit")
        self.assertEqual(self.agent._permitted_exploit_tools(finding), set())
        self.assertEqual(self.agent._unresolved_exploit_findings(), [])

    def test_html_reflection_finding_maps_to_dalfox(self):
        finding = Finding(
            title="Unescaped HTML Reflection Detected",
            severity="medium",
            description="A non-executable marker was reflected without encoding.",
            evidence='{"type":"xss_probe","indicator":"unescaped-html-reflection"}',
            remediation="Apply contextual encoding.",
            tool="xss_check",
            phase="web",
            target="http://192.0.2.10/search?q=hello",
        )
        self.assertEqual(
            self.agent._permitted_exploit_tools(finding),
            {"dalfox_scan"},
        )

    async def test_required_web_step_prefers_testssl_for_discovered_tls(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "web"
        self.agent.state.current_phase_idx = 1
        self.agent.state.web_target = f"https://{target}"
        self.agent.state.profile["is_embedded"] = True
        self.agent.state.host_ports[target] = {443}
        self.agent.state.host_services[target] = {443: "https"}
        self.agent.state.confirmed_service_ports[target] = {443}
        for tool_name, params in (
            ("httpx_probe", {"target": target, "ports": [443]}),
            ("curl_headers", {"target": f"https://{target}"}),
            ("web_assess", {"target": f"https://{target}"}),
        ):
            self.agent.state.executed_commands.add(
                f'{tool_name}|{json.dumps(params, sort_keys=True)}'
            )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_web_step())

        run_tool.assert_awaited_once_with(
            "testssl_tls",
            {"target": target, "port": 443},
            "Audit TLS protocols, cipher categories, and certificate metadata on port 443",
        )

    async def test_ssh_audit_findings_exit_is_treated_as_success(self):
        target = self.agent.state.target
        self.agent.state.current_phase = "network"
        payload = {
            "target": f"{target}:22",
            "kex": [{
                "algorithm": "diffie-hellman-group1-sha1",
                "notes": {"fail": [
                    "using small 1024-bit modulus",
                    "vulnerable to the Logjam attack",
                ]},
            }],
            "key": [],
            "enc": [{
                "algorithm": "3des-cbc",
                "notes": {"fail": ["using broken & deprecated 3DES cipher"]},
            }],
            "mac": [],
        }

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 3
            self.agent.executor.last_result.duration = 0.1
            yield json.dumps(payload, indent=4) + "\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool(
                "ssh_audit",
                {"target": target, "port": 22},
                "audit",
            )

        self.assertTrue(self.agent.state.tool_history[-1]["succeeded"])
        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Weak and Deprecated SSH Algorithms Enabled"
        )
        self.assertTrue(_evidence_is_supported(finding.evidence, json.dumps(payload, indent=4)))

    async def test_whatweb_error_with_zero_exit_is_not_success(self):
        target = f"https://{self.agent.state.target}"
        self.agent.state.current_phase = "web"

        async def fake_stream(_tool_name, _spec):
            self.agent.executor.last_result.exit_code = 0
            self.agent.executor.last_result.duration = 0.1
            yield "ERROR Opening: target - can't modify frozen Hash\n"

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent.executor, "run_stream", side_effect=fake_stream),
        ):
            await self.agent._run_tool("whatweb", {"target": target}, "fingerprint")

        self.assertFalse(self.agent.state.tool_history[-1]["succeeded"])

    def test_waf_timeout_text_with_zero_exit_is_not_success(self):
        output = (
            "ERROR:wafw00f:Something went wrong HTTPSConnectionPool: Read timed out.\n"
            "ERROR:wafw00f:Site 192.0.2.10 appears to be down\n"
        )
        self.assertFalse(_tool_output_succeeded("waf_detect", 0, False, "", output))

    async def test_curl_headers_create_supported_missing_header_finding(self):
        output = "HTTP/1.1 200 OK\nServer: example\nContent-Type: text/html\n"
        await self.agent._post_analyze_and_findings(
            "curl_headers", output, "https://192.0.2.10"
        )
        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Recommended Browser Security Headers Missing"
        )
        self.assertTrue(_evidence_is_supported(finding.evidence, output))
        self.assertIn("strict-transport-security", finding.description)

    async def test_custom_port_ending_in_80_is_not_mistaken_for_port_80(self):
        output = "PORT STATE SERVICE\n18080/tcp open unknown\n"
        await self.agent._post_analyze_and_findings(
            "nmap_quick", output, "127.0.0.1"
        )
        self.assertNotIn(
            "HTTP Service Observed Without HTTPS on Scanned Ports",
            {finding.title for finding in self.agent.state.findings},
        )

    async def test_explicit_query_target_runs_bounded_injection_probes(self):
        target = self.agent.state.target
        query_url = f"http://{target}:18080/api/products?id=1"
        self.agent.state.current_phase = "web"
        self.agent.state.web_target = query_url
        self.agent.state.web_target_explicit = True
        self.agent.state.host_ports[target] = {18080}
        self.agent.state.host_services[target] = {18080: "http"}
        self.agent.state.confirmed_service_ports[target] = {18080}
        self.agent.state.verified_web_origins[target] = [f"http://{target}:18080"]
        httpx_params = {"target": query_url}
        self.agent.state.executed_commands.add(
            f'httpx_probe|{json.dumps(httpx_params, sort_keys=True)}'
        )
        for tool_name in ("curl_headers", "web_assess"):
            params = {"target": f"http://{target}:18080"}
            self.agent.state.executed_commands.add(
                f'{tool_name}|{json.dumps(params, sort_keys=True)}'
            )

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch.object(self.agent, "_run_tool", new_callable=AsyncMock) as run_tool,
        ):
            self.assertTrue(await self.agent._run_required_web_step())
            run_tool.assert_awaited_once_with(
                "sqli_probe",
                {"target": query_url},
                "Test discovered query parameters for bounded SQL-injection indicators",
            )

            run_tool.reset_mock()
            self.agent.state.executed_commands.add(
                f'sqli_probe|{json.dumps({"target": query_url}, sort_keys=True)}'
            )
            self.assertTrue(await self.agent._run_required_web_step())
            run_tool.assert_awaited_once_with(
                "xss_check",
                {"target": query_url},
                "Test discovered query parameters for unescaped HTML reflection",
            )

    async def test_sqli_probe_creates_an_approvable_evidence_backed_finding(self):
        output = json.dumps({
            "type": "sqli_probe",
            "indicator": "database-error-differential",
            "parameter": "id",
            "baseline_status": 200,
            "probe_status": 500,
            "error_marker": "sqlite3.",
            "url": "http://192.0.2.10/products?id=1",
        }, sort_keys=True)

        await self.agent._post_analyze_and_findings(
            "sqli_probe",
            output,
            "http://192.0.2.10/products?id=1",
        )

        finding = next(
            item for item in self.agent.state.findings
            if item.title == "SQL Injection Indicator Confirmed"
        )
        self.assertTrue(_evidence_is_supported(finding.evidence, output))
        self.assertEqual(
            self.agent._permitted_exploit_tools(finding),
            {"sqlmap_test"},
        )

    async def test_same_finding_type_is_preserved_on_distinct_urls(self):
        urls = [
            "http://192.0.2.10:3000/products?id=1",
            "http://192.0.2.10:4000/items?id=2",
        ]
        for url in urls:
            output = json.dumps({
                "type": "sqli_probe",
                "indicator": "database-error-differential",
                "parameter": "id",
                "baseline_status": 200,
                "probe_status": 500,
                "error_marker": "sqlite3.",
                "url": url,
            }, sort_keys=True)
            await self.agent._post_analyze_and_findings("sqli_probe", output, url)

        findings = [
            finding
            for finding in self.agent.state.findings
            if finding.title == "SQL Injection Indicator Confirmed"
        ]
        self.assertEqual(len(findings), 2)
        self.assertEqual({finding.target for finding in findings}, set(urls))

    def test_form_sqli_finding_maps_only_to_sqlmap_forms(self):
        finding = Finding(
            title="SQL Injection Confirmed",
            severity="high",
            description="A POST parameter in an HTML form is injectable.",
            evidence="POST parameter: username",
            remediation="Use parameterized queries.",
            tool="nuclei_scan",
            phase="web",
        )
        self.assertEqual(
            self.agent._permitted_exploit_tools(finding),
            {"sqlmap_forms"},
        )

    async def test_non_executable_html_probe_records_injection_not_executed_xss(self):
        output = json.dumps({
            "type": "xss_probe",
            "indicator": "unescaped-html-reflection",
            "parameter": "q",
            "status": 200,
            "url": "http://192.0.2.10/search?q=probe",
            "payload": '<aegis-xss-probe data-token="7f31"></aegis-xss-probe>',
        }, sort_keys=True)

        await self.agent._post_analyze_and_findings(
            "xss_check",
            output,
            "http://192.0.2.10/search?q=probe",
        )

        finding = next(
            item for item in self.agent.state.findings
            if item.title == "Unescaped HTML Reflection Detected"
        )
        self.assertTrue(_evidence_is_supported(finding.evidence, output))
        self.assertIn("executable XSS still requires", finding.description)

    async def test_snmp_finding_evidence_is_an_exact_output_excerpt(self):
        output = "\n".join(
            (
                "SNMPv2-MIB::sysDescr.0 = STRING: Router",
                "SNMPv2-MIB::sysName.0 = STRING: gateway",
                "IF-MIB::ifNumber.0 = INTEGER: 4",
            )
        )
        await self.agent._post_analyze_and_findings("snmp_enum", output, "192.0.2.10")
        finding = next(
            item for item in self.agent.state.findings
            if item.title == "SNMP Public Community Allows Full Enumeration"
        )
        self.assertTrue(_evidence_is_supported(finding.evidence, output))

    def test_qwen_reasoning_content_is_used_when_content_is_empty(self):
        response = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "reasoning_content": '{"action":"next_phase","summary":"done"}',
                    }
                }
            ]
        }
        self.assertEqual(
            _extract_lm_message_content(response),
            '{"action":"next_phase","summary":"done"}',
        )

    def test_unstructured_reasoning_content_is_not_used_as_a_completion(self):
        response = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "reasoning_content": "I should probably run another scan...",
                    }
                }
            ]
        }
        with self.assertRaises(LMStudioRequestError):
            _extract_lm_message_content(response)

    def test_native_lm_studio_response_uses_final_message_not_reasoning(self):
        response = {
            "output": [
                {"type": "reasoning", "content": "private analysis"},
                {"type": "message", "content": '{"action":"next_phase"}'},
            ]
        }
        self.assertEqual(
            _extract_lm_native_message_content(response),
            '{"action":"next_phase"}',
        )

    async def test_non_context_model_error_is_not_retried_as_overflow(self):
        class ModelResponse:
            status_code = 400
            text = "model not found"

            @staticmethod
            def json():
                return {"error": "model not found"}

        class FakeClient:
            calls = 0

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def post(self, *_args, **_kwargs):
                self.calls += 1
                return ModelResponse()

        client = FakeClient()
        with patch("agent.core.httpx.AsyncClient", return_value=client):
            with self.assertRaises(LMStudioRequestError):
                await self.agent._ask_llm()
        self.assertEqual(client.calls, 1)

    async def test_dns_change_blocks_tool_execution(self):
        self.agent.state = ScanState(
            target="example.com",
            resolved_addresses=["192.0.2.10"],
        )
        self.agent.state.is_running = True
        self.agent.scope_policy = ScopePolicy.from_notes(parse_target("example.com"), "")
        self.agent.scope_policy.add_resolved_address("192.0.2.10")

        with (
            patch("agent.core.is_tool_available", return_value=True),
            patch("agent.core.resolve_addresses", return_value=["192.0.2.99"]),
        ):
            await self.agent._run_tool(
                "nmap_quick",
                {"target": "example.com"},
                "test DNS pinning",
            )

        self.assertFalse(any(event == "tool_start" for event, _ in self.events))
        self.assertTrue(
            any("DNS for example.com changed" in data["message"] for event, data in self.events if event == "log")
        )


if __name__ == "__main__":
    unittest.main()
