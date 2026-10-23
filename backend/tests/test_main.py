import json
import unittest
from unittest.mock import AsyncMock, Mock, patch

import main
from agent.core import Finding, PentestAgent, ScanState
from agent.scope import ScopePolicy, parse_target
from fastapi.testclient import TestClient
from main import (
    _loaded_lm_instances,
    _normalize_lm_models,
    _prepare_application_llm,
    _set_exclusive_lm_model_via_api,
    _tool_install_guidance,
)
from security import AUTH_TOKEN


class ModelListingTests(unittest.TestCase):
    def test_missing_tool_guidance_includes_manual_recovery_command(self):
        # These assertions intentionally exercise the macOS/Homebrew branch;
        # the release test suite also runs inside the Ubuntu build container.
        with patch("main.sys.platform", "darwin"):
            guidance = _tool_install_guidance("whatweb")
            self.assertTrue(guidance["manual_command"])
            self.assertTrue(guidance["note"])
            self.assertIn("brew install ruby", guidance["manual_command"])

            dns_guidance = _tool_install_guidance("dnsrecon")
            self.assertIn("-m venv", dns_guidance["manual_command"])
            self.assertNotIn("--user", dns_guidance["manual_command"])

            nuclei_guidance = _tool_install_guidance("nuclei_scan")
            self.assertIn("brew install nuclei", nuclei_guidance["manual_command"])
            self.assertIn("nuclei -update-templates", nuclei_guidance["manual_command"])

            self.assertIn("brew install testssl", _tool_install_guidance("testssl_tls")["manual_command"])
            self.assertIn("brew install dalfox", _tool_install_guidance("dalfox_scan")["manual_command"])
            self.assertIn("brew install amass", _tool_install_guidance("amass_passive")["manual_command"])

            waf_guidance = _tool_install_guidance("waf_detect")
            self.assertTrue(waf_guidance["automatic"])
            self.assertIn("-m venv", waf_guidance["manual_command"])
            self.assertIn("wafw00f==2.4.2", waf_guidance["manual_command"])

            netexec_guidance = _tool_install_guidance("netexec_smb")
            self.assertTrue(netexec_guidance["automatic"])
            self.assertIn("NetExec@v1.5.1", netexec_guidance["manual_command"])

            zap_guidance = _tool_install_guidance("zap_recon")
            self.assertFalse(zap_guidance["automatic"])
            self.assertIn("zaproxy.org/download", zap_guidance["manual_command"])

    def test_windows_tool_guidance_uses_fixed_winget_ids_or_safe_manual_steps(self):
        with patch("main.sys.platform", "win32"):
            nmap = _tool_install_guidance("nmap_quick")
            self.assertTrue(nmap["automatic"])
            self.assertIn("Insecure.Nmap", nmap["manual_command"])
            self.assertNotIn("nmap_quick", nmap["manual_command"])

            sqlmap = _tool_install_guidance("sqlmap_test")
            self.assertFalse(sqlmap["automatic"])
            self.assertIn("pip install --user sqlmap", sqlmap["manual_command"])

    def test_normalizes_native_lm_studio_models_and_loaded_state(self):
        payload = {
            "models": [
                {
                    "type": "llm",
                    "key": "openai/gpt-oss-20b",
                    "display_name": "GPT-OSS 20B",
                    "architecture": "gpt_oss",
                    "quantization": "MXFP4",
                    "loaded_instances": [{"id": "gpt-oss-20b"}],
                    "capabilities": {"trained_for_tool_use": True},
                },
                {
                    "type": "embedding",
                    "key": "text-embedding-model",
                    "display_name": "Embedding model",
                },
                {
                    "type": "llm",
                    "key": "qwen/qwen3-14b",
                    "display_name": "Qwen3 14B",
                    "loaded_instances": [],
                },
            ]
        }

        models = _normalize_lm_models(payload)

        self.assertEqual([item["id"] for item in models], ["openai/gpt-oss-20b", "qwen/qwen3-14b"])
        self.assertTrue(models[0]["loaded"])
        self.assertTrue(models[0]["trained_for_tool_use"])
        self.assertFalse(models[1]["loaded"])

    def test_normalizes_openai_compatible_fallback(self):
        models = _normalize_lm_models({"data": [{"id": "local/model-a"}]})
        self.assertEqual(models[0]["id"], "local/model-a")
        self.assertEqual(models[0]["display_name"], "local/model-a")

    def test_extracts_every_loaded_instance(self):
        payload = {
            "models": [
                {"key": "model-a", "loaded_instances": [{"id": "a-1"}, {"id": "a-2"}]},
                {"key": "model-b", "loaded_instances": [{"id": "b-1"}]},
            ]
        }
        self.assertEqual(
            _loaded_lm_instances(payload),
            [("model-a", "a-1"), ("model-a", "a-2"), ("model-b", "b-1")],
        )


class ModelSwitchTests(unittest.IsolatedAsyncioTestCase):
    async def test_application_chat_normalizes_native_lm_studio_instances(self):
        ensure = AsyncMock(return_value=None)
        with (
            patch(
                "main._uses_lm_studio_model_management",
                new=AsyncMock(return_value=True),
            ),
            patch("main._ensure_lm_model_loaded", ensure),
        ):
            await _prepare_application_llm(
                "http://localhost:1234",
                "qwen/qwen3.5-9b",
            )

        ensure.assert_awaited_once_with(
            "qwen/qwen3.5-9b",
            "http://localhost:1234",
        )

    async def test_unloads_all_instances_then_loads_and_verifies_selected_model(self):
        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def json(self):
                return self.payload

            @staticmethod
            def raise_for_status():
                return None

        class FakeClient:
            def __init__(self):
                self.loaded = [
                    ("old/model", "old-1", 55_808, 4),
                    ("selected/model", "selected-old", 55_808, 4),
                ]
                self.posts = []

            async def get(self, _url):
                keys = {"old/model", "selected/model"}
                return FakeResponse({
                    "models": [
                        {
                            "key": key,
                            "loaded_instances": [
                                {
                                    "id": instance_id,
                                    "config": {
                                        "context_length": context_length,
                                        "parallel": parallel,
                                    },
                                }
                                for model_key, instance_id, context_length, parallel in self.loaded
                                if model_key == key
                            ],
                        }
                        for key in keys
                    ]
                })

            async def post(self, url, json):
                self.posts.append((url, json))
                if url.endswith("/unload"):
                    self.loaded = [item for item in self.loaded if item[1] != json["instance_id"]]
                elif url.endswith("/load"):
                    self.loaded.append((
                        json["model"],
                        "selected-new",
                        json["context_length"],
                        json["parallel"],
                    ))
                return FakeResponse({"status": "ok"})

        client = FakeClient()
        await _set_exclusive_lm_model_via_api(
            client,
            "http://127.0.0.1:1234",
            "selected/model",
        )

        self.assertEqual(client.loaded, [("selected/model", "selected-new", 8192, 1)])
        self.assertCountEqual(
            [payload["instance_id"] for url, payload in client.posts if url.endswith("/unload")],
            ["old-1", "selected-old"],
        )
        self.assertEqual(
            [payload["model"] for url, payload in client.posts if url.endswith("/load")],
            ["selected/model"],
        )
        load_payload = next(payload for url, payload in client.posts if url.endswith("/load"))
        self.assertEqual(load_payload["context_length"], 8192)
        self.assertEqual(load_payload["eval_batch_size"], 256)
        self.assertEqual(load_payload["parallel"], 1)
        self.assertTrue(load_payload["flash_attention"])


class ScanEvidenceApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.scan_id = "scan_1234567890abcdef"
        self.headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        self.agent = Mock()
        self.agent.evidence_snapshot.return_value = {
            "coverage": {"status": "partial", "hosts": []},
            "services": [], "findings": [], "tool_runs": [],
            "raw_values_included": False,
        }
        self.agent.retry_incomplete_discovery = AsyncMock(return_value=False)
        self.agent.continue_with_partial_discovery = AsyncMock(return_value=False)
        main.active_agents[self.scan_id] = self.agent

    def tearDown(self):
        main.active_agents.pop(self.scan_id, None)
        self.client.close()

    def test_evidence_requires_authentication_and_returns_only_snapshot(self):
        self.assertEqual(self.client.get(f"/api/scan/{self.scan_id}/evidence").status_code, 401)
        response = self.client.get(f"/api/scan/{self.scan_id}/evidence", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["raw_values_included"])
        self.agent.evidence_snapshot.assert_called_once_with()

    def test_discovery_decisions_reject_when_not_paused(self):
        retry = self.client.post(f"/api/scan/{self.scan_id}/retry_discovery", headers=self.headers)
        partial = self.client.post(f"/api/scan/{self.scan_id}/continue_partial", headers=self.headers)
        self.assertEqual(retry.status_code, 409)
        self.assertEqual(partial.status_code, 409)

    def test_discovery_decisions_resume_when_agent_accepts(self):
        self.agent.retry_incomplete_discovery.return_value = True
        self.agent.continue_with_partial_discovery.return_value = True
        retry = self.client.post(f"/api/scan/{self.scan_id}/retry_discovery", headers=self.headers)
        partial = self.client.post(f"/api/scan/{self.scan_id}/continue_partial", headers=self.headers)
        self.assertEqual(retry.json()["status"], "retrying_incomplete_discovery")
        self.assertEqual(partial.json()["status"], "continuing_with_partial_coverage")


class ScanReconnectTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scan_id = "scan_reconnect1234567890"
        self.events = []

        async def emit(event, data):
            self.events.append((event, data))

        self.emit = emit
        self.agent = PentestAgent("http://localhost:1234", "test-model", emit)
        self.agent.state = ScanState(target="127.0.0.1", phases=["recon"], is_running=True)
        self.agent.scope_policy = ScopePolicy.from_notes(parse_target("127.0.0.1"), "")
        main.active_agents[self.scan_id] = self.agent

    async def asyncTearDown(self):
        main.active_agents.pop(self.scan_id, None)
        if pending := main.orphan_scan_tasks.pop(self.scan_id, None):
            pending.cancel()

    async def test_reconnect_snapshot_retains_decision_without_raw_finding_evidence(self):
        self.agent.state.is_paused = True
        self.agent.state.awaiting_discovery_decision = True
        self.agent.state.tool_history.append({
            "tool": "naabu_full", "target": "127.0.0.1",
            "succeeded": False, "timed_out": True,
            "output": "password=do-not-replay",
        })
        self.agent.state.findings.append(Finding(
            title="Synthetic finding", severity="info",
            description="password=do-not-replay", evidence="password=do-not-replay",
            remediation="Review", tool="naabu_full", phase="recon",
            target="http://127.0.0.1/reset?token=do-not-replay",
        ))
        snapshot = main._scan_reconnect_snapshot(self.agent)
        self.assertEqual(snapshot["status"], "paused")
        self.assertEqual(snapshot["coverage"]["status"], "partial")
        self.assertIsNotNone(snapshot["discovery_decision"])
        self.assertEqual(snapshot["findings"][0]["target"], "http://127.0.0.1")
        self.assertNotIn("do-not-replay", json.dumps(snapshot))

    async def test_unattended_disconnected_scan_stops_after_grace(self):
        with patch("main.DISCONNECT_GRACE_SECONDS", 0):
            await main._expire_disconnected_scan(self.scan_id, self.agent, self.emit)
        self.assertFalse(self.agent.state.is_running)
        self.assertNotIn(self.scan_id, main.active_agents)
        self.assertIn("scan_stopped", [event for event, _ in self.events])

    async def test_rebound_emitter_prevents_old_disconnect_from_stopping_scan(self):
        async def new_emit(_event, _data):
            pass

        self.agent.emit = new_emit
        with patch("main.DISCONNECT_GRACE_SECONDS", 0):
            await main._expire_disconnected_scan(self.scan_id, self.agent, self.emit)
        self.assertTrue(self.agent.state.is_running)
        self.assertIs(main.active_agents[self.scan_id], self.agent)


class ScanRecoveryApiTests(unittest.TestCase):
    def test_interrupted_notice_requires_auth_and_is_not_live_scan_state(self):
        client = TestClient(main.app)
        journal = Mock()
        journal.list_interrupted.return_value = [{
            "scan_id": "scan_1234567890abcdef", "target": "127.0.0.1",
            "coverage": "partial", "completed_ports": 49_151,
            "requested_ports": 65_535, "phases": ["recon"],
            "mode": "supervised", "updated_at": "2026-10-08T12:00:00+00:00",
        }]
        with patch.object(main, "recovery_journal", journal):
            self.assertEqual(client.get("/api/scan/recovery").status_code, 401)
            response = client.get(
                "/api/scan/recovery", headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["interrupted"][0]["coverage"], "partial")
            journal.list_interrupted.assert_called_once_with(set(main.active_agents))
            cleared = client.delete(
                "/api/scan/recovery/scan_1234567890abcdef",
                headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
            )
            self.assertEqual(cleared.status_code, 200)
            journal.remove.assert_called_once_with("scan_1234567890abcdef")
        client.close()

if __name__ == "__main__":
    unittest.main()
