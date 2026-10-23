#!/usr/bin/env python3
"""Exercise full-range timeout recovery against the packaged AEGIS backend.

No production test hook is used. A temporary PATH shim impersonates Naabu,
refuses non-loopback targets, returns one partial TCP observation, then exceeds
the packaged 90-second deadline. The test drives the real authenticated
WebSocket and checks the same redacted Evidence/report endpoints as the UI.
"""
# ruff: noqa: S101

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import socket
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import websockets

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BACKEND = ROOT / "backend/dist/aegis-server/aegis-server"
STUB = ROOT / "scripts/fixtures/naabu_recovery_stub.py"
WINDOWS = ["1-16384", "16385-32768", "32769-49152", "49153-65535"]


async def _response(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.read(2048), timeout=2)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _wait_health(client: httpx.AsyncClient, proc: asyncio.subprocess.Process) -> None:
    for _ in range(150):
        if proc.returncode is not None:
            raise AssertionError(f"Packaged backend exited early: {proc.returncode}")
        try:
            response = await client.get("/api/health")
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.2)
    raise TimeoutError("Packaged backend did not become ready")


async def _get_json(client: httpx.AsyncClient, path: str) -> dict:
    response = await client.get(path)
    response.raise_for_status()
    return response.json()


async def _scenario(backend: Path, scenario: str) -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-recovery-acceptance-") as tmp:
        root = Path(tmp)
        shim = root / "bin"
        shim.mkdir()
        (shim / "naabu").symlink_to(STUB)
        calls = root / "calls.txt"
        server = await asyncio.start_server(_response, "127.0.0.1", 0)
        listener_port = server.sockets[0].getsockname()[1]
        backend_port = _free_port()
        token = secrets.token_urlsafe(32)
        instance = secrets.token_urlsafe(18)
        origin = f"http://127.0.0.1:{backend_port}"
        scan_id = "scan_" + secrets.token_hex(16)
        env = dict(os.environ)
        env.update({
            "PATH": f"{shim}{os.pathsep}{env.get('PATH', '')}",
            "AEGIS_AUTH_TOKEN": token,
            "AEGIS_INSTANCE_ID": instance,
            "AEGIS_PORT": str(backend_port),
            "AEGIS_ALLOWED_ORIGINS": origin,
            "AEGIS_DATA_DIR": str(root / "data"),
            "AEGIS_RECOVERY_TEST_CALLS": str(calls),
            "AEGIS_RECOVERY_TEST_PORT": str(listener_port),
            "AEGIS_RECOVERY_TEST_SCENARIO": scenario,
        })
        proc = await asyncio.create_subprocess_exec(
            str(backend), "--host", "127.0.0.1", "--port", str(backend_port),
            "--auth-token", token, "--instance-id", instance,
            "--allowed-origin", origin,
            env=env, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with httpx.AsyncClient(
                base_url=origin, headers={"Authorization": f"Bearer {token}"}, timeout=15,
            ) as client:
                await _wait_health(client, proc)
                ui = await client.get("/")
                assert ui.status_code == 200 and "<html" in ui.text.lower(), "Packaged UI missing"
                async with websockets.connect(
                    f"ws://127.0.0.1:{backend_port}/ws/{scan_id}",
                    origin=origin,
                    subprotocols=["aegis.v1", f"aegis.auth.{token}"],
                    max_size=8_000_000,
                ) as ws:
                    await ws.send(json.dumps({
                        "action": "start_scan", "target": "127.0.0.1",
                        "scope": "", "mode": "supervised", "phases": ["recon"],
                        "llm_enabled": False,
                    }))
                    decision_seen = False
                    complete = None
                    tool_names = []
                    started = time.monotonic()
                    while time.monotonic() - started < 185:
                        message = json.loads(await asyncio.wait_for(ws.recv(), timeout=185))
                        event = message.get("event")
                        if event == "tool_start":
                            tool_names.append(message["tool"])
                            if message["tool"] == "naabu_full":
                                assert str(shim / "naabu") in message["command"], "Test shim not used"
                        elif event == "error":
                            raise AssertionError(f"Backend error: {message.get('message')}")
                        elif event == "discovery_decision_needed":
                            assert not decision_seen, "Unexpected repeated discovery decision"
                            decision_seen = True
                            coverage = message["coverage"]
                            row = coverage["hosts"][0]
                            assert coverage["status"] == "partial", coverage
                            assert row["completed_port_count"] == 49_151, row
                            assert row["observed_ports"] == [listener_port], row
                            assert row["incomplete_ranges"] == [{"start": 1, "end": 16_384}], row
                            evidence = await _get_json(client, f"/api/scan/{scan_id}/evidence")
                            assert evidence["coverage"] == coverage
                            assert evidence["raw_values_included"] is False
                            assert [run["tool"] for run in evidence["tool_runs"]] == [
                                "naabu_full", *(["naabu_range"] * 4)
                            ]
                            assert evidence["tool_runs"][0]["result"] == "timed_out"
                            assert all(run["tool"] != "nmap_targeted" for run in evidence["tool_runs"])
                            await ws.send(json.dumps({
                                "action": "retry_discovery" if scenario == "retry" else "continue_partial",
                            }))
                        elif event == "scan_complete":
                            complete = message
                            break
                    assert decision_seen and complete, "Scan did not reach decision and completion"
                    expected = "complete" if scenario == "retry" else "partial"
                    assert complete["outcome"] == expected, complete
                    assert complete["coverage"]["status"] == expected, complete["coverage"]
                    evidence = await _get_json(client, f"/api/scan/{scan_id}/evidence")
                    runs = evidence["tool_runs"]
                    assert any(run["tool"] == "nmap_targeted" for run in runs), runs
                    assert any(service["port"] == listener_port for service in evidence["services"]), evidence
                    assert evidence["raw_values_included"] is False
                    report = (await _get_json(client, f"/api/scan/{scan_id}/report"))["report"]
                    assert f"**Outcome:** {expected.upper()}" in report, report[:800]
                    assert f"**TCP discovery coverage:** {expected}" in report, report[:800]
                    used = calls.read_text(encoding="ascii").splitlines()
                    assert used[:5] == ["full", *WINDOWS], used
                    assert used.count("full") == 1, used
                    if scenario == "retry":
                        assert used[5:] == [WINDOWS[0]], used
                        assert evidence["coverage"]["hosts"][0]["completed_port_count"] == 65_535
                    else:
                        assert used == ["full", *WINDOWS], used
                        assert evidence["coverage"]["hosts"][0]["completed_port_count"] == 49_151
                    print(f"PASS {scenario}: packaged backend/UI served; {len(runs)} runs; {expected.upper()} coverage; window calls verified", flush=True)
        finally:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.communicate(), timeout=5)
            except TimeoutError:
                proc.kill()
                await proc.communicate()
            server.close()
            await server.wait_closed()


async def _restart_scenario(backend: Path) -> None:
    """Crash between approval and execution, then require fresh discovery."""
    with tempfile.TemporaryDirectory(prefix="aegis-restart-acceptance-") as tmp:
        root = Path(tmp)
        server = await asyncio.start_server(_response, "127.0.0.1", 0)
        listener_port = server.sockets[0].getsockname()[1]
        backend_port = _free_port()
        origin = f"http://127.0.0.1:{backend_port}"
        scan_id = "scan_" + secrets.token_hex(16)
        fixture_marker = "synthetic-do-not-persist"

        async def launch() -> tuple[asyncio.subprocess.Process, httpx.AsyncClient, str]:
            token = secrets.token_urlsafe(32)
            instance = secrets.token_urlsafe(18)
            env = dict(os.environ)
            env.update({
                "AEGIS_AUTH_TOKEN": token,
                "AEGIS_INSTANCE_ID": instance,
                "AEGIS_PORT": str(backend_port),
                "AEGIS_ALLOWED_ORIGINS": origin,
                "AEGIS_DATA_DIR": str(root / "data"),
            })
            proc = await asyncio.create_subprocess_exec(
                str(backend), "--host", "127.0.0.1", "--port", str(backend_port),
                "--auth-token", token, "--instance-id", instance,
                "--allowed-origin", origin,
                env=env, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            client = httpx.AsyncClient(base_url=origin, headers={"Authorization": f"Bearer {token}"}, timeout=15)
            await _wait_health(client, proc)
            return proc, client, token

        async def close(proc: asyncio.subprocess.Process, client: httpx.AsyncClient, *, crash: bool = False) -> None:
            await client.aclose()
            if proc.returncode is None:
                # The first stop simulates abrupt app/backend failure. A
                # graceful stop would correctly clear the restart notice.
                if crash:
                    proc.kill()
                else:
                    proc.terminate()
            try:
                await asyncio.wait_for(proc.communicate(), timeout=5)
            except TimeoutError:
                proc.kill()
                await proc.communicate()

        first, client, token = await launch()
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{backend_port}/ws/{scan_id}", origin=origin,
                subprotocols=["aegis.v1", f"aegis.auth.{token}"],
            ) as ws:
                await ws.send(json.dumps({
                    "action": "start_scan",
                    "target": f"http://127.0.0.1:{listener_port}/private?token={fixture_marker}",
                    "scope": str(listener_port), "mode": "manual",
                    "phases": ["recon"], "llm_enabled": False,
                }))
                while True:
                    event = json.loads(await asyncio.wait_for(ws.recv(), timeout=20))
                    if event.get("event") == "error":
                        raise AssertionError(event)
                    if event.get("event") == "approval_needed":
                        assert event["tool"] == "nmap_quick", event
                        break
            live_notice = await _get_json(client, "/api/scan/recovery")
            assert live_notice["interrupted"] == [], live_notice
        finally:
            await close(first, client, crash=True)

        saved = (root / "data" / "scan-recovery" / "scan-recovery.json").read_text()
        assert fixture_marker not in saved and "/private" not in saved, saved
        second, client, token = await launch()
        try:
            notice = await _get_json(client, "/api/scan/recovery")
            assert len(notice["interrupted"]) == 1, notice
            assert notice["interrupted"][0]["target"] == f"http://127.0.0.1:{listener_port}", notice
            async with websockets.connect(
                f"ws://127.0.0.1:{backend_port}/ws/{scan_id}", origin=origin,
                subprotocols=["aegis.v1", f"aegis.auth.{token}"],
            ) as ws:
                initial = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                assert initial["event"] == "scan_missing", initial
                await ws.send(json.dumps({
                    "action": "start_scan", "target": "127.0.0.1",
                    "scope": str(listener_port), "mode": "supervised",
                    "phases": ["recon"], "llm_enabled": False,
                }))
                while True:
                    event = json.loads(await asyncio.wait_for(ws.recv(), timeout=80))
                    if event.get("event") == "error":
                        raise AssertionError(event)
                    if event.get("event") == "scan_complete":
                        assert event["coverage"]["status"] == "complete", event
                        break
            evidence = await _get_json(client, f"/api/scan/{scan_id}/evidence")
            names = [run["tool"] for run in evidence["tool_runs"]]
            assert names[:2] == ["nmap_quick", "nmap_targeted"], names
            assert all(run["tool"] != "naabu_full" for run in evidence["tool_runs"]), names
            assert (await _get_json(client, "/api/scan/recovery"))["interrupted"] == []
            assert not (root / "data" / "scan-recovery" / "scan-recovery.json").exists()
            print("PASS restart: historical notice only; fresh scoped Nmap discovery; no stale scan state", flush=True)
        finally:
            await close(second, client)
            server.close()
            await server.wait_closed()


async def _ui_session(backend: Path, *, notice: bool = False) -> None:
    """Keep the packaged UI available for a manual renderer-control check."""
    with tempfile.TemporaryDirectory(prefix="aegis-recovery-ui-") as tmp:
        root = Path(tmp)
        shim = root / "bin"
        shim.mkdir()
        (shim / "naabu").symlink_to(STUB)
        server = await asyncio.start_server(_response, "127.0.0.1", 0)
        listener_port = server.sockets[0].getsockname()[1]
        backend_port = _free_port()
        token = secrets.token_urlsafe(32)
        instance = secrets.token_urlsafe(18)
        origin = f"http://127.0.0.1:{backend_port}"
        env = dict(os.environ)
        env.update({
            "PATH": f"{shim}{os.pathsep}{env.get('PATH', '')}",
            "AEGIS_AUTH_TOKEN": token,
            "AEGIS_INSTANCE_ID": instance,
            "AEGIS_PORT": str(backend_port),
            "AEGIS_ALLOWED_ORIGINS": origin,
            "AEGIS_DATA_DIR": str(root / "data"),
            "AEGIS_RECOVERY_TEST_CALLS": str(root / "calls.txt"),
            "AEGIS_RECOVERY_TEST_PORT": str(listener_port),
            "AEGIS_RECOVERY_TEST_SCENARIO": "retry",
        })
        if notice:
            notice_dir = root / "data" / "scan-recovery"
            notice_dir.mkdir(parents=True, mode=0o700)
            (notice_dir / "scan-recovery.json").write_text(json.dumps({
                "version": 1,
                "entries": [{
                    "scan_id": "scan_1234567890abcdef",
                    "target": "127.0.0.1",
                    "phases": ["recon", "web", "exploit"],
                    "mode": "autonomous",
                    "coverage": "partial",
                    "completed_ports": 49_151,
                    "requested_ports": 65_535,
                    "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                }],
            }))
        proc = await asyncio.create_subprocess_exec(
            str(backend), "--host", "127.0.0.1", "--port", str(backend_port),
            "--auth-token", token, "--instance-id", instance,
            "--allowed-origin", origin,
            env=env, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with httpx.AsyncClient(
                base_url=origin, headers={"Authorization": f"Bearer {token}"}, timeout=15,
            ) as client:
                await _wait_health(client, proc)
            print(f"UI_URL={origin}/#token={token}", flush=True)
            print(f"LOOPBACK_LISTENER=127.0.0.1:{listener_port}", flush=True)
            if notice:
                print("Inspect the interrupted-scan card and fresh-scope confirmation; the fixture is historical metadata only.", flush=True)
            else:
                print("Run supervised, recon-only, no-LLM scan of 127.0.0.1 with blank scope.", flush=True)
            await asyncio.Event().wait()
        finally:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.communicate(), timeout=5)
            except TimeoutError:
                proc.kill()
                await proc.communicate()
            server.close()
            await server.wait_closed()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", type=Path, default=DEFAULT_BACKEND)
    parser.add_argument("--scenario", choices=["retry", "partial", "restart", "ui", "ui-notice", "both", "all"], default="all")
    options = parser.parse_args()
    backend = options.backend.resolve()
    if not backend.is_file():
        raise SystemExit(f"Packaged backend not found: {backend}")
    if options.scenario in {"ui", "ui-notice"}:
        await _ui_session(backend, notice=options.scenario == "ui-notice")
        return
    scenarios = ["retry", "partial", "restart"] if options.scenario == "all" else [
        "retry", "partial"
    ] if options.scenario == "both" else [options.scenario]
    for scenario in scenarios:
        if scenario == "restart":
            await _restart_scenario(backend)
            continue
        await _scenario(backend, scenario)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
