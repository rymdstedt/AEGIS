"""End-to-end agent acceptance against AEGIS's loopback-only synthetic lab.

The local provider is a deterministic OpenAI-compatible test double. It checks
that exact approved evidence reaches post-scan Q&A; it does not grade a model's
reasoning quality or require LM Studio to be installed for the test suite.
"""

from __future__ import annotations

import asyncio
import json
import threading
import unittest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from agent.core import PentestAgent

from lab.vulnerable_app import VulnLabHandler, VulnLabServer, _reset_database

LAB_FLAG = "AEGIS-LAB{unsigned-role-cookie}"
MODEL_ID = "aegis-acceptance-model"


class _ProviderHandler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/models":
            self._json(HTTPStatus.OK, {"data": [{"id": MODEL_ID}]})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        length = min(int(self.headers.get("Content-Length", "0")), 1_000_000)
        payload = json.loads(self.rfile.read(length))
        user_text = "\n".join(
            str(item.get("content") or "")
            for item in payload.get("messages", [])
            if item.get("role") == "user"
        )
        with self.server.records_lock:
            self.server.requests.append(payload)
        response_format = payload.get("response_format") or {}
        if response_format.get("type") == "json_schema":
            answer = json.dumps({"action": "next_phase", "summary": "Acceptance fixture: optional checks complete"})
        elif "OPERATOR QUESTION" in user_text and LAB_FLAG in user_text:
            answer = f"The approved cookie bypass returned {LAB_FLAG}."
        else:
            answer = "The requested exact value is not in the supplied evidence."
        self._json(HTTPStatus.OK, {
            "choices": [{"message": {"role": "assistant", "content": answer}}],
        })

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class LabEngagementAcceptanceTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _reset_database()
        cls.lab = VulnLabServer(("127.0.0.1", 0), VulnLabHandler)
        cls.lab_thread = threading.Thread(target=cls.lab.serve_forever, daemon=True)
        cls.lab_thread.start()
        cls.provider = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
        cls.provider.requests = []
        cls.provider.records_lock = threading.Lock()
        cls.provider_thread = threading.Thread(target=cls.provider.serve_forever, daemon=True)
        cls.provider_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        for server, thread in ((cls.provider, cls.provider_thread), (cls.lab, cls.lab_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    async def test_supervised_approval_private_evidence_and_local_answer(self) -> None:
        events: list[tuple[str, dict]] = []
        approved = False
        confirmed = False
        agent: PentestAgent

        async def emit(event: str, data: dict) -> None:
            nonlocal approved, confirmed
            events.append((event, data))
            if event == "exploit_decision_needed":
                candidate = next(
                    (item for item in data["findings"] if "cookie_auth_check" in item["tools"]),
                    None,
                )
                if candidate and not approved:
                    approved = True
                    await agent.approve_finding_for_exploitation(candidate["id"], "cookie_auth_check")
                else:
                    await agent.skip_exploitation()
            elif event == "approval_needed" and data.get("tool") == "cookie_auth_check":
                await agent.approve_tool()
            elif event == "finding" and "Authorization Bypass Confirmed" in str(data.get("title")):
                confirmed = True

        origin = f"http://127.0.0.1:{self.lab.server_address[1]}"
        provider_url = f"http://127.0.0.1:{self.provider.server_address[1]}"
        agent = PentestAgent(provider_url, MODEL_ID, emit)
        # Keep the regression fast and independent of installed deep scanners.
        # The real curl and internal assessment/confirmation tools still run.
        available = {"curl_headers", "web_assess", "cookie_auth_check"}
        with patch("agent.core.is_tool_available", side_effect=lambda name: name in available):
            await asyncio.wait_for(
                agent.start_scan(
                    origin,
                    scope=f"Only TCP port {self.lab.server_address[1]}",
                    mode="supervised",
                    phases=["web", "exploit"],
                    llm_enabled=True,
                ),
                timeout=90,
            )

        self.assertTrue(approved, "The scan did not offer the cookie bypass for approval")
        self.assertTrue(agent.state.is_complete)
        self.assertTrue(any(item["tool"] == "web_assess" for item in agent.state.tool_history))
        self.assertTrue(any(item["tool"] == "cookie_auth_check" for item in agent.state.tool_history))
        self.assertTrue(confirmed or any(
            "Authorization Bypass Confirmed" in finding.title
            for finding in agent.state.findings
        ))
        public = json.dumps(agent.evidence_snapshot()) + agent.generate_report()
        self.assertNotIn(LAB_FLAG, public)
        self.assertTrue(any(
            LAB_FLAG in str(item.get("body") or "") for item in agent._operator_evidence
        ), "The approved confirmation was not retained in private evidence")

        await agent.user_message("Briefly, what flag did the approved cookie bypass retrieve?")
        answers = [data["message"] for event, data in events if event == "log" and data.get("type") == "agent"]
        self.assertIn(LAB_FLAG, answers[-1])
        with self.provider.records_lock:
            requests = list(self.provider.requests)
        self.assertTrue(any(
            LAB_FLAG in json.dumps(request)
            and "OPERATOR QUESTION" in json.dumps(request)
            for request in requests
        ), "The local provider did not receive the approved private evidence")
        qa_prompts = [
            str(message.get("content") or "")
            for request in requests
            for message in request.get("messages", [])
            if message.get("role") == "user" and "OPERATOR QUESTION" in str(message.get("content") or "")
        ]
        self.assertTrue(qa_prompts)
        self.assertLess(len(qa_prompts[-1]), 8500, "One-value Q&A should not send the entire scan")

        # The exact private value must still be available when the local model
        # misses its deadline; the routine report must remain redacted.
        with patch.object(agent, "_ask_completed_scan_llm", side_effect=TimeoutError("model timeout")):
            await agent.user_message("Briefly, what flag did the approved cookie bypass retrieve?")
        answers = [data["message"] for event, data in events if event == "log" and data.get("type") == "agent"]
        self.assertIn(LAB_FLAG, answers[-1])
        self.assertNotIn(LAB_FLAG, json.dumps(agent.evidence_snapshot()) + agent.generate_report())


if __name__ == "__main__":
    unittest.main()
