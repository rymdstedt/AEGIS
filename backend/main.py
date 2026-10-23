import asyncio
import json
import logging
import os
import pathlib
import re
import secrets
import shlex
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Literal

import httpx
from agent.core import PentestAgent
from application import ApplicationResearchService
from application.analyzer import AnalysisCancelled
from application.cisco_psirt import (
    CiscoPsirtError,
    cisco_os_type,
    fetch_cisco_advisories,
)
from application.intake import IntakeError, IntakeLimitError
from application.llm import (
    ApplicationLLMError,
    ApplicationLLMPartialAnswer,
    ask_application_llm,
)
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, SecretStr
from scan_recovery import ScanRecoveryJournal
from security import (
    INSTANCE_ID,
    allowed_origins,
    origin_allowed,
    token_matches,
    validate_provider_url,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis")

active_agents: dict[str, PentestAgent] = {}
active_tasks: dict[str, asyncio.Task] = {}
orphan_scan_tasks: dict[str, asyncio.Task] = {}
DISCONNECT_GRACE_SECONDS = 60
model_switch_lock = asyncio.Lock()
_MODEL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}")
_LM_CONTEXT_LENGTH = 8192
_LM_PARALLEL_PREDICTIONS = 1
_application_service: ApplicationResearchService | None = None
recovery_journal = ScanRecoveryJournal()


class ArtifactImportRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32_768)


class ApplicationChatHistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=1_200)


class ApplicationChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4_000)
    lm_url: str = Field(default="http://localhost:1234", max_length=2_048)
    model: str = Field(min_length=1, max_length=256)
    include_private: bool = False
    stream: bool = False
    history: list[ApplicationChatHistoryMessage] = Field(
        default_factory=list,
        max_length=8,
    )


class ApplicationAnalyzeRequest(BaseModel):
    profile: Literal["quick", "deep_firmware", "supply_chain", "deep_source"] = "quick"


class CiscoAdvisoryLookupRequest(BaseModel):
    # Validate after SecretStr extraction so a structured validation response
    # can never echo a malformed token value.
    access_token: SecretStr
    version: str | None = Field(default=None, min_length=1, max_length=80)


def _get_application_service() -> ApplicationResearchService:
    global _application_service
    if _application_service is None:
        _application_service = ApplicationResearchService()
    return _application_service


def _desktop_artifact_import_allowed(request: Request) -> bool:
    expected = os.environ.get("AEGIS_ARTIFACT_IMPORT_TOKEN", "")
    if not expected:
        return True
    supplied = request.headers.get("x-aegis-artifact-token", "")
    return bool(supplied) and secrets.compare_digest(supplied, expected)


def _desktop_private_action_allowed(request: Request) -> bool:
    """Require the main-process-only credential even in browser development."""
    expected = os.environ.get("AEGIS_ARTIFACT_IMPORT_TOKEN", "")
    supplied = request.headers.get("x-aegis-artifact-token", "")
    return bool(expected) and bool(supplied) and secrets.compare_digest(
        supplied, expected
    )


class LMStudioResourceError(RuntimeError):
    """LM Studio refused a model load to protect the host from memory pressure."""


def _track_scan_task(scan_id: str, task: asyncio.Task) -> asyncio.Task:
    """Register one active scan/resume task and remove only that exact task."""
    active_tasks[scan_id] = task
    task.add_done_callback(
        lambda done, sid=scan_id: active_tasks.pop(sid, None)
        if active_tasks.get(sid) is done
        else None
    )
    return task


def _scan_reconnect_snapshot(agent: PentestAgent) -> dict:
    """Reattach a local UI without replaying raw tool output or secret values."""
    state = agent.state
    if state is None:
        return {"status": "idle"}
    status = (
        state.outcome if state.is_complete and state.outcome in {"partial", "inconclusive"}
        else "complete" if state.is_complete
        else "paused" if state.is_paused
        else "running" if state.is_running
        else "stopped"
    )
    evidence = agent.evidence_snapshot()
    safe_findings = {item["id"]: item for item in evidence["findings"]}
    approved: dict[str, dict] = {}
    for approval in state.approved_for_exploitation.values():
        finding_id = str(approval.get("finding_id") or "")
        if finding_id:
            item = approved.setdefault(finding_id, {
                "id": finding_id,
                "title": str(approval.get("finding_title") or ""),
                "tools": [],
            })
            tool = str(approval.get("tool") or "")
            if tool and tool not in item["tools"]:
                item["tools"].append(tool)
    pending = state.pending_approval or {}
    exploit_decision = None
    if state.awaiting_exploit_decision:
        exploit_decision = {"findings": [
            {"id": finding.id, "title": finding.title,
             "target": safe_findings.get(finding.id, {}).get("target", ""), "tools": tools}
            for finding, tools in agent._unresolved_exploit_findings()
        ]}
    return {
        "status": status,
        "phase": state.current_phase,
        "findings": [{
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "description": "Open the redacted report for finding details.",
            "remediation": "",
            "phase": finding.phase,
            "target": safe_findings.get(finding.id, {}).get("target", ""),
            "permitted_tools": sorted(agent._permitted_exploit_tools(finding)),
        } for finding in state.findings],
        "coverage": evidence["coverage"],
        "evidence": evidence,
        "report": agent.generate_report() if state.is_complete else "",
        "discovery_decision": {
            "coverage": evidence["coverage"],
            "can_retry": state.discovery_window_attempt_limit < 3,
        } if state.awaiting_discovery_decision else None,
        "exploit_decision": exploit_decision,
        "approval": {
            "tool": str(pending.get("tool") or ""),
            "reasoning": str(pending.get("reasoning") or ""),
            "params": {key: value for key, value in (pending.get("params") or {}).items() if key != "password"},
        } if pending else None,
        "exploitation_approved": list(approved.values()),
    }


async def _expire_disconnected_scan(scan_id: str, agent: PentestAgent, emitter) -> None:
    """Stop unattended work if the operator UI does not reconnect promptly."""
    try:
        await asyncio.sleep(DISCONNECT_GRACE_SECONDS)
        if active_agents.get(scan_id) is agent and agent.emit is emitter:
            if agent.state and agent.state.is_running:
                await agent.stop_scan()
            active_agents.pop(scan_id, None)
    except asyncio.CancelledError:
        return
    finally:
        if orphan_scan_tasks.get(scan_id) is asyncio.current_task():
            orphan_scan_tasks.pop(scan_id, None)

_BREW_PACKAGE_BY_TOOL = {
    "osv_scanner": "osv-scanner",
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "nmap_quick": "nmap", "nmap_targeted": "nmap", "nmap_ping_sweep": "nmap", "nmap_full": "nmap",
    "nmap_udp": "nmap", "nmap_vuln": "nmap", "ssl_check": "nmap",
    "naabu_quick": "naabu", "naabu_full": "naabu", "naabu_range": "naabu",
    "httpx_probe": "httpx", "katana_crawl": "katana",
    "nuclei_scan": "nuclei",
    "testssl_tls": "testssl", "dalfox_scan": "dalfox", "amass_passive": "amass",
    "slowloris_test": "nmap", "gobuster_dir": "gobuster", "ffuf_fuzz": "ffuf",
    "nikto": "nikto", "sqlmap_test": "sqlmap", "sqlmap_forms": "sqlmap",
    "hydra_ssh": "hydra", "hydra_telnet": "hydra", "hydra_ftp": "hydra",
    "subfinder": "subfinder", "theharvester": "theharvester",
    "ssh_audit": "ssh-audit", "creds_ssh_exec": "sshpass",
    "snmp_enum": "net-snmp", "whois_lookup": "whois",
}
_WINGET_PACKAGE_BY_TOOL = {
    "osv_scanner": "Google.OSVScanner",
    "nmap_quick": "Insecure.Nmap", "nmap_targeted": "Insecure.Nmap",
    "nmap_ping_sweep": "Insecure.Nmap", "nmap_full": "Insecure.Nmap",
    "nmap_udp": "Insecure.Nmap", "nmap_vuln": "Insecure.Nmap",
    "ssl_check": "Insecure.Nmap", "slowloris_test": "Insecure.Nmap",
    "whois_lookup": "Microsoft.Sysinternals.Whois",
    "zap_recon": "ZAP.ZAP",
}


def _tool_install_guidance(name: str) -> dict:
    """Return UI-safe automatic support and manual recovery instructions."""
    if sys.platform == "darwin":
        special = {
            "whatweb": {
                "command": "brew install ruby && \"$(brew --prefix ruby)/bin/gem\" install --user-install addressable ipaddr nokogiri rake",
                "note": "AEGIS uses Homebrew Ruby (including its compatible bundled JSON gem); the obsolete macOS system Ruby is not modified.",
            },
            "dnsrecon": {
                "command": "python3 -m venv \"$HOME/.aegis/tools/dnsrecon/.aegis-venv\" && \"$HOME/.aegis/tools/dnsrecon/.aegis-venv/bin/python\" -m pip install -r \"$HOME/.aegis/tools/dnsrecon/requirements.txt\"",
                "note": "AEGIS installs dependencies in its own virtual environment, avoiding PEP 668 and Homebrew Python changes.",
            },
            "smb_enum": {
                "command": "brew install samba",
                "note": "AEGIS supplies enum4linux; Samba provides the SMB client commands it needs.",
            },
            "nuclei_scan": {
                "command": "brew install nuclei && nuclei -update-templates",
                "note": "Installs Nuclei and its official template set before a scan; AEGIS disables template updates during engagements.",
            },
            "waf_detect": {
                "command": "python3 -m venv \"$HOME/.aegis/tools/wafw00f/.aegis-venv\" && \"$HOME/.aegis/tools/wafw00f/.aegis-venv/bin/python\" -m pip install \"wafw00f==2.4.2\"",
                "note": "AEGIS installs the pinned WAFW00F release in an isolated virtual environment.",
            },
            "netexec_smb": {
                "command": "brew install rust && python3 -m venv \"$HOME/.aegis/tools/netexec/.aegis-venv\" && \"$HOME/.aegis/tools/netexec/.aegis-venv/bin/python\" -m pip install \"git+https://github.com/Pennyw0rth/NetExec@v1.5.1\"",
                "note": "AEGIS installs NetExec v1.5.1 in an isolated environment; Rust is required by its current macOS dependencies.",
            },
        }
        if name in special:
            item = special[name]
            return {"automatic": True, "manual_command": item["command"], "note": item["note"]}
        if name == "zap_recon":
            return {
                "automatic": False,
                "manual_command": "Download the current macOS package from https://www.zaproxy.org/download/, move ZAP.app to /Applications, then press Refresh.",
                "note": "The Homebrew ZAP cask is currently disabled because it fails Gatekeeper checks, so AEGIS will not bypass macOS security controls. A native official ZAP.app is detected automatically.",
            }
        if package := _BREW_PACKAGE_BY_TOOL.get(name):
            return {
                "automatic": True,
                "manual_command": f"brew install {package}",
                "note": "Run this in Terminal if automatic installation fails, then press Refresh.",
            }
    if sys.platform == "win32":
        if package := _WINGET_PACKAGE_BY_TOOL.get(name):
            return {
                "automatic": True,
                "manual_command": f"winget install --id {package} --exact",
                "note": "AEGIS uses Windows Package Manager. Restart AEGIS after installation so the updated PATH is inherited.",
            }
        special = {
            "dnsrecon": "py -m pip install --user dnsrecon",
            "waf_detect": "py -m pip install --user wafw00f==2.4.2",
            "netexec_smb": "py -m pip install --user git+https://github.com/Pennyw0rth/NetExec@v1.5.1",
            "ssh_audit": "py -m pip install --user ssh-audit",
            "sqlmap_test": "py -m pip install --user sqlmap",
            "sqlmap_forms": "py -m pip install --user sqlmap",
            "semgrep": "py -m pip install --user semgrep",
            "gitleaks": "Download the current Windows archive from https://github.com/gitleaks/gitleaks/releases, place gitleaks.exe on PATH, then restart AEGIS.",
        }
        if command := special.get(name):
            return {
                "automatic": False,
                "manual_command": command,
                "note": "Install a current Python from python.org first if the Windows `py` launcher is unavailable, then restart AEGIS.",
            }
    if sys.platform.startswith("linux"):
        special = {
            "osv_scanner": {
                "command": "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.6.0",
                "note": "Install a current Go toolchain first and ensure $HOME/go/bin is on PATH, then restart AEGIS.",
            },
            "semgrep": {
                "command": "pipx install semgrep",
                "note": "Install pipx from your distribution first if needed; pipx keeps Semgrep isolated from the system Python.",
            },
            "gitleaks": {
                "command": "Download the current Linux archive from https://github.com/gitleaks/gitleaks/releases, place gitleaks on PATH, then restart AEGIS.",
                "note": "Use the official Gitleaks release matching the machine architecture.",
            },
        }
        if name in special:
            item = special[name]
            return {"automatic": False, "manual_command": item["command"], "note": item["note"]}
    binary = name
    try:
        from tools.definitions import get_tool_binary
        binary = get_tool_binary(name)
    except Exception:
        pass
    return {
        "automatic": False,
        "manual_command": f"Install '{binary}' with your system package manager and ensure it is on PATH.",
        "note": "AEGIS does not have a safe automatic installer for this tool on this platform.",
    }


def _validate_model_id(value: object) -> str:
    model = str(value or "").strip()
    if model and not _MODEL_ID_RE.fullmatch(model):
        raise ValueError("Invalid local model identifier")
    return model


def _find_lms_cli() -> str | None:
    import os
    import shutil
    candidates = [
        "lms",
        os.path.expanduser("~/.lmstudio/bin/lms"),
        "/opt/homebrew/bin/lms",
        "/usr/local/bin/lms",
        os.path.expanduser("~/Library/Application Support/LM Studio/bin/lms"),
        # Linux fallbacks (LM Studio has limited native Linux support; prefer Ollama or manual server)
        os.path.expanduser("~/.local/bin/lms"),
        "/usr/local/bin/lms",
        "/usr/bin/lms",
        os.path.expanduser("~/.lmstudio/bin/lms.exe"),
        os.path.expanduser("~/.lmstudio/bin/lms.cmd"),
    ]
    for c in candidates:
        if not c:
            continue
        if os.path.isabs(c):
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        else:
            p = shutil.which(c)
            if p:
                return p
    return None


def _loaded_lm_instances(payload: object) -> list[tuple[str, str]]:
    """Return (model key, instance id) pairs from LM Studio's native listing."""
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        return []
    instances: list[tuple[str, str]] = []
    for model in payload["models"]:
        if not isinstance(model, dict):
            continue
        model_key = str(model.get("key") or model.get("id") or "").strip()
        loaded = model.get("loaded_instances")
        if not model_key or not isinstance(loaded, list):
            continue
        for instance in loaded:
            if isinstance(instance, dict):
                instance_id = str(instance.get("id") or "").strip()
                if instance_id:
                    instances.append((model_key, instance_id))
    return instances


def _loaded_lm_instance_details(payload: object) -> list[tuple[str, str, dict]]:
    """Return model key, instance id, and effective load config."""
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        return []
    instances: list[tuple[str, str, dict]] = []
    for model in payload["models"]:
        if not isinstance(model, dict):
            continue
        model_key = str(model.get("key") or model.get("id") or "").strip()
        loaded = model.get("loaded_instances")
        if not model_key or not isinstance(loaded, list):
            continue
        for instance in loaded:
            if not isinstance(instance, dict):
                continue
            instance_id = str(instance.get("id") or "").strip()
            if instance_id:
                config = instance.get("config")
                instances.append((model_key, instance_id, config if isinstance(config, dict) else {}))
    return instances


def _lm_response_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return str(payload.get("error") or payload.get("message") or payload)
    except ValueError:
        pass
    return str(getattr(response, "text", "") or f"HTTP {response.status_code}")[:1200]


async def _set_exclusive_lm_model_via_api(
    client: httpx.AsyncClient,
    lm_url: str,
    desired_model: str,
):
    """Unload every LM Studio instance, load one selected model, and verify."""
    response = await client.get(f"{lm_url}/api/v1/models")
    response.raise_for_status()
    details = _loaded_lm_instance_details(response.json())
    loaded = [(model_key, instance_id) for model_key, instance_id, _config in details]
    selected_context = details[0][2].get("context_length") if len(details) == 1 else None
    selected_parallel = details[0][2].get("parallel") if len(details) == 1 else None
    if (
        len(loaded) == 1
        and loaded[0][0] == desired_model
        and isinstance(selected_context, int)
        and selected_context <= _LM_CONTEXT_LENGTH
        and selected_parallel == _LM_PARALLEL_PREDICTIONS
    ):
        logger.info("✓ Only selected LM Studio model is loaded: %s", desired_model)
        return

    for _model_key, instance_id in loaded:
        response = await client.post(
            f"{lm_url}/api/v1/models/unload",
            json={"instance_id": instance_id},
        )
        response.raise_for_status()

    # The unload response can arrive before Metal/MLX has released all model
    # allocations. Loading immediately is what made even a 9B model fail
    # intermittently after switching from another model.
    for _attempt in range(40):
        response = await client.get(f"{lm_url}/api/v1/models")
        response.raise_for_status()
        if not _loaded_lm_instances(response.json()):
            break
        await asyncio.sleep(0.25)
    else:
        raise RuntimeError("LM Studio did not finish unloading the previous model")
    if loaded:
        await asyncio.sleep(1.0)

    response = await client.post(
        f"{lm_url}/api/v1/models/load",
        json={
            "model": desired_model,
            "context_length": _LM_CONTEXT_LENGTH,
            "eval_batch_size": 256,
            "parallel": _LM_PARALLEL_PREDICTIONS,
            "flash_attention": True,
            "echo_load_config": True,
        },
    )
    if getattr(response, "status_code", 200) >= 400:
        detail = _lm_response_error(response)
        if "insufficient system resources" in detail.lower():
            raise LMStudioResourceError(
                "LM Studio's memory guardrail rejected this model even with an "
                f"{_LM_CONTEXT_LENGTH:,}-token context. Select a smaller model or close "
                "memory-heavy applications; AEGIS will not disable the safety guardrail. "
                f"LM Studio: {detail[:600]}"
            )
    response.raise_for_status()

    for _attempt in range(10):
        response = await client.get(f"{lm_url}/api/v1/models")
        response.raise_for_status()
        verified = _loaded_lm_instance_details(response.json())
        effective_context = verified[0][2].get("context_length") if len(verified) == 1 else None
        effective_parallel = verified[0][2].get("parallel") if len(verified) == 1 else None
        if (
            len(verified) == 1
            and verified[0][0] == desired_model
            and isinstance(effective_context, int)
            and effective_context <= _LM_CONTEXT_LENGTH
            and effective_parallel == _LM_PARALLEL_PREDICTIONS
        ):
            logger.info("✓ Exclusively loaded LM Studio model: %s", desired_model)
            return
        await asyncio.sleep(0.2)
    raise RuntimeError("LM Studio did not confirm that only the selected model is loaded")


async def _ensure_lm_model_loaded(
    desired_model: str | None,
    lm_url: str,
):
    """Make the selected model the sole model loaded in LM Studio."""
    if not desired_model:
        return
    async with model_switch_lock:
        api_error: Exception | None = None
        try:
            timeout = httpx.Timeout(180.0, connect=5.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                await _set_exclusive_lm_model_via_api(
                    client,
                    lm_url,
                    desired_model,
                )
                return
        except LMStudioResourceError:
            raise
        except Exception as exc:
            api_error = exc
            logger.warning("Native LM Studio model switch failed; trying CLI: %s", exc)

        lms = _find_lms_cli()
        if not lms:
            raise RuntimeError(f"Could not switch LM Studio models: {api_error}") from api_error
        try:
            await _ensure_lm_model_loaded_locked(lms, desired_model)
        except Exception as cli_error:
            raise RuntimeError(
                f"Could not exclusively load '{desired_model}' (API: {api_error}; CLI: {cli_error})"
            ) from cli_error


async def _run_lms(lms: str, *args: str, timeout: float = 30.0) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        lms, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"lms {' '.join(args)} timed out")
    return proc.returncode or 0, out.decode(errors="replace")


async def _communicate_with_timeout(
    proc: asyncio.subprocess.Process, timeout: float = 600.0
) -> bytes:
    """Collect an installer process without allowing a package manager to hang forever."""
    try:
        output, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return output
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise RuntimeError("Installer timed out") from exc


async def _ensure_lm_model_loaded_locked(lms: str, desired_model: str):
    """CLI fallback: unload all model instances, then load exactly one."""
    code, output = await _run_lms(lms, "unload", "--all", timeout=60)
    if code != 0:
        raise RuntimeError(f"lms unload --all failed: {output[-500:]}")
    logger.info("✓ Unloaded existing LM Studio models")
    await asyncio.sleep(1.0)

    code, output = await _run_lms(
        lms,
        "load",
        desired_model,
        "--context-length",
        str(_LM_CONTEXT_LENGTH),
        "--parallel",
        str(_LM_PARALLEL_PREDICTIONS),
        "--gpu",
        "max",
        timeout=180,
    )
    if code != 0:
        raise RuntimeError(f"Model load failed: {output[-500:]}")
    logger.info("✓ Exclusively loaded model for scan: %s", desired_model)

@asynccontextmanager
async def lifespan(app: FastAPI):
    import json
    import os

    # Log exact build identity so users (and support) can tell "is this the new installer with my fix?"
    try:
        build_candidates = []
        if getattr(sys, "frozen", False):
            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                build_candidates.append(os.path.join(meipass, "build-info.json"))
            build_candidates.append(os.path.join(os.path.dirname(sys.executable), "build-info.json"))
        else:
            build_candidates.append(os.path.join(os.path.dirname(__file__), "build-info.json"))
            build_candidates.append(os.path.join(os.path.dirname(__file__), "dist", "build-info.json"))

        for bc in build_candidates:
            if os.path.exists(bc):
                with open(bc) as f:
                    bi = json.load(f)
                logger.info(f"✓ AEGIS build: {bi.get('buildId')} (version {bi.get('version')}, built {bi.get('buildDate')})")
                break
    except Exception:
        pass

    # Never start, stop, or unload a user's model server as a startup side
    # effect. The Diagnostics controls make those actions explicit.
    def prepare_assets():
        try:
            from tools.definitions import ensure_script_tools, ensure_wordlist
            for wl in ("common.txt", "directories.txt", "subdomains.txt"):
                ensure_wordlist(wl)
            ensure_script_tools()
        except Exception as exc:
            logger.warning("Optional asset preparation failed: %s", exc)

    # Health becomes available immediately; optional downloads/copies cannot make
    # Electron declare startup failure.
    asset_task = asyncio.create_task(asyncio.to_thread(prepare_assets))

    yield
    for agent in list(active_agents.values()):
        await agent.stop_scan()
    for task in list(active_tasks.values()):
        task.cancel()
    for task in list(orphan_scan_tasks.values()):
        task.cancel()
    if not asset_task.done():
        asset_task.cancel()


app = FastAPI(title="AEGIS", version="2.1.0", lifespan=lifespan)
# SECURITY: restrict CORS even on localhost. The desktop UI is served from the same origin or 127.
# This reduces risk if the port is accidentally reachable.
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(allowed_origins()),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.middleware("http")
async def authenticate_local_api(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        supplied = request.headers.get("authorization", "")
        if supplied.lower().startswith("bearer "):
            supplied = supplied[7:]
        else:
            supplied = ""
        if not token_matches(supplied):
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    return response


@app.get("/api/health")
async def health():
    return {"status": "ok", "agents": len(active_agents), "instance_id": INSTANCE_ID}


@app.get("/api/scan/recovery")
async def list_interrupted_scans():
    """Show historical scan metadata only; it is never executable coverage."""
    try:
        return {"interrupted": recovery_journal.list_interrupted(set(active_agents))}
    except OSError as exc:
        logger.warning("Could not read scan recovery metadata: %s", exc)
        raise HTTPException(500, "Could not read interrupted scan notices") from exc


@app.delete("/api/scan/recovery/{scan_id}")
async def dismiss_interrupted_scan(scan_id: str):
    try:
        recovery_journal.remove(scan_id)
    except OSError as exc:
        logger.warning("Could not clear scan recovery metadata: %s", exc)
        raise HTTPException(500, "Could not clear interrupted scan notice") from exc
    return {"dismissed": True}


@app.post("/api/application/import")
async def import_application_artifact(payload: ArtifactImportRequest, request: Request):
    """Import a native-picker selection into an AEGIS-owned snapshot."""
    if not _desktop_artifact_import_allowed(request):
        raise HTTPException(403, "Artifact import is restricted to the desktop picker")
    try:
        return await asyncio.to_thread(_get_application_service().import_path, payload.path)
    except IntakeLimitError as exc:
        raise HTTPException(413, str(exc)) from exc
    except IntakeError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        logger.exception("Application artifact import failed")
        raise HTTPException(500, "Artifact import failed") from exc


@app.get("/api/application/projects")
async def list_application_projects(limit: int = 100):
    try:
        return {"projects": await asyncio.to_thread(
            _get_application_service().list_projects, limit
        )}
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Invalid project-list limit") from exc


@app.get("/api/application/projects/{project_id}")
async def get_application_project(project_id: str):
    try:
        return await asyncio.to_thread(
            _get_application_service().get_project, project_id
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc


@app.get("/api/application/projects/{project_id}/findings")
async def list_application_findings(project_id: str, offset: int = 0, limit: int = 100):
    try:
        return await asyncio.to_thread(
            _get_application_service().list_findings_page, project_id, offset, limit
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.delete("/api/application/projects/{project_id}")
async def delete_application_project(project_id: str, request: Request):
    if not _desktop_private_action_allowed(request):
        raise HTTPException(403, "Project removal requires desktop confirmation")
    try:
        return await asyncio.to_thread(
            _get_application_service().delete_project,
            project_id,
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except RuntimeError as exc:
        if "running" in str(exc):
            raise HTTPException(409, str(exc)) from exc
        logger.exception("Application project removal failed")
        raise HTTPException(500, "Project removal failed") from exc


@app.post("/api/application/projects/{project_id}/analyze")
async def analyze_application_project(
    project_id: str,
    payload: ApplicationAnalyzeRequest | None = None,
):
    try:
        return await asyncio.to_thread(
            _get_application_service().analyze_project,
            project_id,
            payload.profile if payload is not None else "quick",
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except AnalysisCancelled as exc:
        raise HTTPException(409, str(exc)) from exc
    except RuntimeError as exc:
        if "already running" in str(exc):
            raise HTTPException(409, str(exc)) from exc
        logger.exception("Application analysis failed")
        raise HTTPException(500, "Static analysis failed") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        logger.exception("Application analysis failed")
        raise HTTPException(500, "Static analysis failed") from exc


@app.get("/api/application/projects/{project_id}/analysis-job")
async def get_application_analysis_job(project_id: str):
    try:
        return {"job": await asyncio.to_thread(
            _get_application_service().get_analysis_job, project_id
        )}
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc


@app.post("/api/application/projects/{project_id}/analysis-job/cancel")
async def cancel_application_analysis_job(project_id: str):
    try:
        return {"job": await asyncio.to_thread(
            _get_application_service().cancel_analysis, project_id
        )}
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/application/projects/{project_id}/sbom")
async def download_application_sbom(project_id: str):
    try:
        path, filename = await asyncio.to_thread(
            _get_application_service().get_sbom_path,
            project_id,
        )
        return FileResponse(
            path,
            media_type="application/vnd.cyclonedx+json",
            filename=filename,
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/application/projects/{project_id}/cisco-advisories")
async def lookup_application_cisco_advisories(
    project_id: str,
    payload: CiscoAdvisoryLookupRequest,
):
    """Correlate one locally detected version with Cisco's fixed PSIRT API."""
    try:
        project = await asyncio.to_thread(
            _get_application_service().get_project,
            project_id,
        )
        firmware = project.get("summary", {}).get("firmware")
        if not isinstance(firmware, dict) or firmware.get("vendor") != "Cisco":
            raise ValueError("Analyze recognized Cisco firmware before advisory lookup")
        versions = [str(item) for item in firmware.get("versions", []) if str(item)]
        version = str(payload.version or (versions[0] if versions else "")).strip()
        if not version or version not in versions:
            raise ValueError("Select a version detected in this firmware snapshot")
        os_type = cisco_os_type(str(firmware.get("platform_family") or ""))
        lookup = await fetch_cisco_advisories(
            access_token=payload.access_token.get_secret_value(),
            version=version,
            os_type=os_type,
        )
        return await asyncio.to_thread(
            _get_application_service().record_firmware_advisory_lookup,
            project_id,
            lookup,
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except (ValueError, CiscoPsirtError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        if "already running" in str(exc):
            raise HTTPException(409, str(exc)) from exc
        logger.exception("Cisco advisory result storage failed")
        raise HTTPException(500, "Could not store Cisco advisory results") from exc
    except Exception as exc:
        logger.exception("Cisco advisory lookup failed")
        raise HTTPException(500, "Cisco advisory lookup failed") from exc


@app.get(
    "/api/application/projects/{project_id}/findings/{finding_id}/private-evidence"
)
async def get_application_private_evidence(
    project_id: str,
    finding_id: str,
    request: Request,
):
    if not _desktop_private_action_allowed(request):
        raise HTTPException(403, "Private evidence requires desktop confirmation")
    try:
        return await asyncio.to_thread(
            _get_application_service().get_private_finding,
            project_id,
            finding_id,
        )
    except KeyError as exc:
        raise HTTPException(404, "Private evidence not found") from exc


@app.get("/api/application/projects/{project_id}/private-evidence/export")
async def export_application_private_evidence(project_id: str, request: Request):
    if not _desktop_private_action_allowed(request):
        raise HTTPException(403, "Private evidence export requires desktop confirmation")
    try:
        first = await asyncio.to_thread(
            _get_application_service().private_evidence_page, project_id, 0, 1
        )
        if int(first["total"]) > 500:
            raise HTTPException(
                413, "Use the paged private-evidence endpoint for large exports"
            )
        return await asyncio.to_thread(
            _get_application_service().private_evidence_export,
            project_id,
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc


@app.get("/api/application/projects/{project_id}/private-evidence/page")
async def page_application_private_evidence(
    project_id: str, request: Request, offset: int = 0, limit: int = 100
):
    if not _desktop_private_action_allowed(request):
        raise HTTPException(403, "Private evidence page requires desktop confirmation")
    try:
        return await asyncio.to_thread(
            _get_application_service().private_evidence_page,
            project_id,
            offset,
            limit,
        )
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


async def _application_chat_event_stream(
    *,
    project: dict,
    question: str,
    lm_url: str,
    model: str,
    private_evidence: list[dict] | None,
    private_evidence_total: int | None,
    history: list[dict[str, str]],
) -> AsyncIterator[str]:
    """Bridge LM Studio progress and answer deltas to one renderer request."""
    queue: asyncio.Queue[dict | None] = asyncio.Queue()

    def publish(event: dict) -> None:
        queue.put_nowait(event)

    async def run() -> None:
        try:
            publish({"type": "progress", "stage": "model"})
            await _prepare_application_llm(lm_url, model)
            answer = await ask_application_llm(
                project=project,
                question=question,
                lm_url=lm_url,
                model=model,
                private_evidence=private_evidence,
                private_evidence_total=private_evidence_total,
                history=history,
                on_event=publish,
            )
            publish({
                "type": "complete",
                "answer": answer,
                "model": model,
                "included_private_evidence": private_evidence is not None,
            })
        except ApplicationLLMPartialAnswer as exc:
            publish({
                "type": "complete",
                "answer": exc.partial_answer,
                "model": model,
                "included_private_evidence": private_evidence is not None,
                "truncated": True,
                "notice": str(exc),
            })
        except ApplicationLLMError as exc:
            publish({"type": "error", "message": str(exc)})
        except Exception:
            logger.exception("Application local-model stream failed")
            publish({
                "type": "error",
                "message": "The local-model request failed unexpectedly. Retry after "
                "confirming that LM Studio is running.",
            })
        finally:
            queue.put_nowait(None)

    task = asyncio.create_task(run())
    try:
        while True:
            event = await queue.get()
            if event is None:
                break
            yield json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
    finally:
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@app.post("/api/application/projects/{project_id}/chat")
async def chat_about_application_project(
    project_id: str,
    payload: ApplicationChatRequest,
    request: Request,
):
    if payload.include_private and not _desktop_private_action_allowed(request):
        raise HTTPException(
            403,
            "Sharing exact evidence with the local model requires desktop confirmation",
        )
    try:
        project = await asyncio.to_thread(
            _get_application_service().get_project,
            project_id,
        )
        private_evidence = None
        private_evidence_total = None
        if payload.include_private:
            private_page = await asyncio.to_thread(
                _get_application_service().store.list_private_evidence_for_model,
                project_id, payload.question, 500,
            )
            private_evidence = private_page["evidence"]
            private_evidence_total = private_page["total"]
            if private_page["analysis_job_id"] != project.get("summary", {}).get("analysis_job_id"):
                raise HTTPException(409, "Analysis changed while preparing private evidence; retry")
        lm_url = validate_provider_url(payload.lm_url)
        model = _validate_model_id(payload.model)
        if not model:
            raise ValueError("Select an installed local model")
        history = [
            {"role": item.role, "content": item.content}
            for item in payload.history
        ]
        if payload.stream:
            return StreamingResponse(
                _application_chat_event_stream(
                    project=project,
                    question=payload.question,
                    lm_url=lm_url,
                    model=model,
                    private_evidence=private_evidence,
                    private_evidence_total=private_evidence_total,
                    history=history,
                ),
                media_type="application/x-ndjson",
                headers={"Cache-Control": "no-store"},
            )
        await _prepare_application_llm(lm_url, model)
        try:
            answer = await ask_application_llm(
                project=project,
                question=payload.question,
                lm_url=lm_url,
                model=model,
                private_evidence=private_evidence,
                private_evidence_total=private_evidence_total,
                history=history,
            )
        except ApplicationLLMPartialAnswer as exc:
            return {
                "answer": exc.partial_answer,
                "model": model,
                "included_private_evidence": payload.include_private,
                "truncated": True,
                "notice": str(exc),
            }
        return {
            "answer": answer,
            "model": model,
            "included_private_evidence": payload.include_private,
        }
    except KeyError as exc:
        raise HTTPException(404, "Application project not found") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ApplicationLLMError as exc:
        raise HTTPException(502, str(exc)) from exc


def _normalize_lm_models(payload: object) -> list[dict]:
    """Normalize LM Studio native and OpenAI-compatible model listings."""
    if not isinstance(payload, dict):
        return []
    raw_models = payload.get("models")
    if not isinstance(raw_models, list):
        raw_models = payload.get("data")
    if not isinstance(raw_models, list):
        return []

    models: dict[str, dict] = {}
    for raw in raw_models:
        if not isinstance(raw, dict):
            continue
        model_type = str(raw.get("type") or "").lower()
        model_id = str(raw.get("key") or raw.get("id") or "").strip()
        if (
            not model_id
            or model_type in {"embedding", "embeddings"}
            or "embedding" in model_id.lower()
        ):
            continue
        loaded_instances = raw.get("loaded_instances")
        loaded = bool(loaded_instances) or str(raw.get("state") or "").lower() == "loaded"
        capabilities = raw.get("capabilities") if isinstance(raw.get("capabilities"), dict) else {}
        models[model_id] = {
            "id": model_id,
            "display_name": str(raw.get("display_name") or model_id),
            "loaded": loaded,
            "trained_for_tool_use": bool(capabilities.get("trained_for_tool_use")),
            "architecture": raw.get("architecture") or raw.get("arch"),
            "quantization": raw.get("quantization"),
        }
    return sorted(
        models.values(),
        key=lambda item: (not item["loaded"], item["display_name"].lower()),
    )


async def _fetch_lm_models(url: str) -> list[dict]:
    """List available LLMs, preferring LM Studio's native v1 API."""
    errors: list[str] = []
    async with httpx.AsyncClient(timeout=5.0) as client:
        for path in ("/api/v1/models", "/api/v0/models", "/v1/models"):
            try:
                response = await client.get(f"{url}{path}")
                if response.status_code == 200:
                    return _normalize_lm_models(response.json())
                errors.append(f"{path}: HTTP {response.status_code}")
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"{path}: {exc}")
    raise RuntimeError("; ".join(errors) or "Local LLM provider did not return a model list")


async def _uses_lm_studio_model_management(url: str) -> bool:
    """Return whether the provider exposes LM Studio's native model API."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{url}/api/v1/models")
            if response.status_code != 200:
                return False
            payload = response.json()
            return isinstance(payload, dict) and isinstance(payload.get("models"), list)
    except (httpx.HTTPError, ValueError):
        return False


async def _prepare_application_llm(lm_url: str, model: str) -> None:
    """Prepare one selected LM Studio instance before application Q&A.

    OpenAI-compatible local providers manage their own lifecycle. LM Studio's
    native API is different: a request with a new load configuration can create
    a second instance, so normalize it through the same exclusive loader used
    by live engagements.
    """
    if not await _uses_lm_studio_model_management(lm_url):
        return
    try:
        await _ensure_lm_model_loaded(model, lm_url)
    except Exception as exc:
        detail = str(exc).strip() or type(exc).__name__
        raise ApplicationLLMError(
            f"Could not prepare the selected LM Studio model: {detail}"
        ) from exc


@app.get("/api/models")
async def list_models(lm_url: str = ""):
    try:
        url = validate_provider_url(lm_url or os.getenv("LM_STUDIO_URL", "http://localhost:1234"))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    try:
        return {"data": await _fetch_lm_models(url)}
    except Exception as e:
        return {"data": [], "error": str(e)}


@app.get("/api/tools")
async def list_tools():
    from tools.definitions import TOOLS, is_tool_available
    return {
        name: {"description": tool["description"], "phase": tool["phase"], "available": is_tool_available(name)}
        for name, tool in TOOLS.items()
        if tool.get("diagnostics", True)
    }

@app.get("/api/environment")
async def environment_status(lm_url: str = ""):
    """Reports what the app can actually use right now.
    Useful for desktop app to show friendly warnings instead of silent failures.
    """
    from tools.definitions import TOOLS, is_tool_available
    try:
        url = validate_provider_url(lm_url or os.getenv("LM_STUDIO_URL", "http://localhost:1234"))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    lm_info = {"reachable": False, "models": [], "error": None}
    try:
        models = await _fetch_lm_models(url)
        lm_info["models"] = [model["id"] for model in models]
        lm_info["reachable"] = True
    except Exception as e:
        lm_info["error"] = str(e)

    tools_status = {}
    for name, tool in TOOLS.items():
        if not tool.get("diagnostics", True):
            continue
        tools_status[name] = is_tool_available(name)

    missing_tools = [name for name, ok in tools_status.items() if not ok]
    install_guidance = {name: _tool_install_guidance(name) for name in missing_tools}

    wordlist_dir = os.path.expanduser("~/.aegis/wordlists")
    wordlists = {}
    for fname in ("common.txt", "directories.txt", "subdomains.txt"):
        wordlists[fname] = os.path.exists(os.path.join(wordlist_dir, fname))

    # Include exact build metadata (so user can tell "is the installer different?")
    build_info = {"buildId": "dev", "buildDate": None, "version": "2.1.0"}
    try:
        # When running the frozen onefile server, build-info.json is placed next to the binary or in the temp extract root.
        candidates = []
        if getattr(sys, "frozen", False):
            # PyInstaller onefile: files added with --add-data "xxx:." end up in sys._MEIPASS
            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                candidates.append(os.path.join(meipass, "build-info.json"))
            # Also try sibling to the executable
            candidates.append(os.path.join(os.path.dirname(sys.executable), "build-info.json"))
        else:
            candidates.append(os.path.join(os.path.dirname(__file__), "dist", "build-info.json"))
            candidates.append(os.path.join(os.path.dirname(__file__), "build-info.json"))

        for cand in candidates:
            if os.path.exists(cand):
                with open(cand) as f:
                    build_info = json.load(f)
                break
    except Exception:
        pass

    return {
        "lm_studio": lm_info,
        "tools": tools_status,
        "missing_tools": missing_tools,
        "install_guidance": install_guidance,
        "wordlists": wordlists,
        "wordlist_dir": wordlist_dir,
        "build": build_info,
    }

@app.post("/api/install-tool")
async def install_tool(name: str = ""):
    """Install an allowlisted tool or return platform-specific manual guidance.

    macOS uses Homebrew plus isolated managed runtimes, Windows uses fixed
    WinGet package IDs where available, and Linux uses fixed apt package names.
    User-controlled values are never interpolated into a shell command.
    """
    import os
    import platform
    if not name:
        return {"success": False, "error": "No tool name"}
    from tools.definitions import TOOLS, is_tool_available
    if name not in set(TOOLS) | {"enum4linux"}:
        raise HTTPException(400, "Unknown or unsupported tool")

    if platform.system() == "Windows" and name in {
        "whatweb", "dnsrecon", "smb_enum", "enum4linux", "waf_detect", "netexec_smb",
        "semgrep", "gitleaks",
    }:
        guidance = _tool_install_guidance("smb_enum" if name == "enum4linux" else name)
        return {
            "success": False,
            "error": guidance["note"],
            "manual_command": guidance["manual_command"],
            "command": "manual installation required",
        }

    if platform.system() == "Linux" and name in {"osv_scanner", "semgrep", "gitleaks"}:
        guidance = _tool_install_guidance(name)
        return {
            "success": False,
            "error": guidance["note"],
            "manual_command": guidance["manual_command"],
            "command": "manual installation required",
        }

    # Python CLIs without a dependable Homebrew formula are installed in
    # AEGIS-owned virtual environments.  This avoids PEP 668, never modifies
    # Homebrew's Python, and gives the desktop app a stable launcher path.
    python_tool_setup = {
        "waf_detect": {
            "dest": "wafw00f",
            "package": "wafw00f==2.4.2",
            "entry": "wafw00f",
            "wrapper": "aegis-wafw00f",
        },
        "netexec_smb": {
            "dest": "netexec",
            "package": "git+https://github.com/Pennyw0rth/NetExec@v1.5.1",
            "entry": "nxc",
            "wrapper": "aegis-nxc",
            "prebrew": "rust",
        },
    }
    if name in python_tool_setup:
        cfg = python_tool_setup[name]
        logs: list[str] = []
        try:
            if platform.system() == "Darwin" and cfg.get("prebrew"):
                dependency = cfg["prebrew"]
                logs.append(f"brew install {dependency}  (required build dependency)")
                dependency_proc = await asyncio.create_subprocess_exec(
                    "brew", "install", dependency,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                dependency_out = await _communicate_with_timeout(dependency_proc)
                logs.append(dependency_out.decode(errors="replace")[-1800:])
                if dependency_proc.returncode != 0:
                    raise RuntimeError(f"Homebrew installation failed for {dependency}")

            import shutil
            system_python = shutil.which("python3")
            if not system_python:
                raise RuntimeError("python3 is required to create the isolated tool environment")
            destination = os.path.expanduser(f"~/.aegis/tools/{cfg['dest']}")
            os.makedirs(destination, exist_ok=True)
            venv_dir = os.path.join(destination, ".aegis-venv")
            venv_python = os.path.join(venv_dir, "bin", "python")
            if not os.path.isfile(venv_python):
                command = [system_python, "-m", "venv", venv_dir]
                logs.append(" ".join(command))
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                output = await _communicate_with_timeout(proc)
                logs.append(output.decode(errors="replace")[-1800:])
                if proc.returncode != 0:
                    raise RuntimeError("Could not create the isolated Python environment")

            install_command = [
                venv_python, "-m", "pip", "install", "--disable-pip-version-check",
                "--upgrade", cfg["package"],
            ]
            logs.append(" ".join(install_command) + "  (isolated AEGIS environment)")
            proc = await asyncio.create_subprocess_exec(
                *install_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output = await _communicate_with_timeout(proc)
            logs.append(output.decode(errors="replace")[-2600:])
            if proc.returncode != 0:
                raise RuntimeError("Python tool installation failed")

            entrypoint = os.path.join(venv_dir, "bin", cfg["entry"])
            if not os.path.isfile(entrypoint):
                raise RuntimeError(f"Installed package did not provide {cfg['entry']}")
            wrapper_path = os.path.join(destination, cfg["wrapper"])
            with open(wrapper_path, "w", encoding="utf-8") as wrapper_file:
                wrapper_file.write(f"#!/bin/sh\nexec {shlex.quote(entrypoint)} \"$@\"\n")
            os.chmod(wrapper_path, 0o755)
            logs.append(f"[setup] created isolated launcher: {wrapper_path}")
            if not is_tool_available(name):
                raise RuntimeError("Setup finished, but the AEGIS runtime check still fails")
            return {
                "success": True,
                "output": "\n".join(logs),
                "package": cfg["package"],
                "command": f"isolated setup {name}",
            }
        except Exception as exc:
            logs.append(f"ERROR: {exc}")
            return {
                "success": False,
                "output": "\n".join(logs),
                "error": str(exc),
                "command": f"isolated setup {name}",
                "manual_command": _tool_install_guidance(name)["manual_command"],
            }

    # 1. Git-based tools with no Homebrew formula.
    #    We prefer vendored sources from the DMG if present (ensured at startup into ~/.aegis/tools).
    #    Then we run the language-specific setup (pip/gem) so that on "Install all" the user sees
    #    real progress and the tools become runnable.
    git_setup = {
        "whatweb": {
            "dest": "whatweb",
            "repo": "https://github.com/urbanadventurer/WhatWeb.git",
            "commit": "d279d93042d034f3fd29d5a893d44ccc0595d3f8",
            "entry": "whatweb",
            "brew_runtime": "ruby",
            "gem_steps": [
                # Homebrew Ruby already supplies a compatible JSON gem. Asking
                # Ruby 4 to compile the newest separate json release can fail
                # on preview macOS SDKs even though WhatWeb is fully runnable.
                ["gem", "install", "--user-install", "addressable", "ipaddr", "nokogiri", "rake"],
            ],
            "note": "Ruby web fingerprinter. If ruby/gem step shows errors you may need to `gem install ...` manually or ensure Xcode CLT.",
        },
        "dnsrecon": {
            "dest": "dnsrecon",
            "repo": "https://github.com/darkoperator/dnsrecon.git",
            "commit": "d9633804a3035a2e44ad326b55fcf767819ab809",
            "entry": "dnsrecon.py",
            "pip_steps": True,
            "note": "Python DNS recon tool. Dependencies are isolated in an AEGIS-owned virtual environment.",
        },
        "smb_enum": {
            "dest": "enum4linux",
            "repo": "https://github.com/CiscoCXSecurity/enum4linux.git",
            "commit": "e6fe887710f72ab4620580cb841eb29296e38211",
            "entry": "enum4linux.pl",
            "extra_brew": "samba",
            "note": "Perl SMB enum (vendored script). Also installs 'samba' (provides nmblookup/smbclient/rpcclient/net that the script requires).",
        },
        "enum4linux": {  # alias if old name somehow appears in missing list
            "dest": "enum4linux",
            "repo": "https://github.com/CiscoCXSecurity/enum4linux.git",
            "commit": "e6fe887710f72ab4620580cb841eb29296e38211",
            "entry": "enum4linux.pl",
            "extra_brew": "samba",
            "note": "Alias for smb_enum tool.",
        },
    }
    if name in git_setup:
        cfg = git_setup[name]
        dst = os.path.expanduser(f"~/.aegis/tools/{cfg['dest']}")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        logs = []
        used_bundled = False

        # Prefer bundled sources (from DMG) - no net required for the code itself.
        bundled_src = None
        try:
            from tools.definitions import _get_bundled_script_sources_dir
            bdir = _get_bundled_script_sources_dir()
            if bdir:
                cand = os.path.join(bdir, cfg["dest"])
                if os.path.isdir(cand):
                    bundled_src = cand
        except Exception:
            pass

        try:
            was_already = False
            entry_rel = cfg.get("entry", "")
            entry_path = os.path.join(dst, entry_rel)
            entry_present = bool(entry_rel and os.path.isfile(entry_path))
            if os.path.isdir(dst) and entry_present:
                was_already = True
                logs.append(f"[setup] target already present with entrypoint: {dst} (from DMG bundle or previous setup) — keeping source and repairing dependencies.")
            elif bundled_src:
                logs.append(f"[setup] using vendored sources from DMG bundle: {bundled_src}")
                import shutil
                if os.path.isdir(dst):
                    shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(bundled_src, dst)
                logs.append("[setup] copied sources to user dir (offline)")
                used_bundled = True
                entry_present = os.path.isfile(entry_path)
            else:
                import shutil
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                os.makedirs(dst, exist_ok=True)
                commands = [
                    ["git", "-C", dst, "init", "-q"],
                    ["git", "-C", dst, "remote", "add", "origin", cfg["repo"]],
                    ["git", "-C", dst, "fetch", "--depth", "1", "origin", cfg["commit"]],
                    ["git", "-C", dst, "checkout", "-q", "--detach", cfg["commit"]],
                ]
                for command in commands:
                    logs.append(" ".join(command))
                    p = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                    try:
                        out, _ = await asyncio.wait_for(p.communicate(), timeout=180)
                    except asyncio.TimeoutError:
                        p.kill()
                        await p.wait()
                        return {"success": False, "output": "\n".join(logs), "command": "git fetch pinned source", "package": cfg["dest"], "error": "git operation timed out"}
                    logs.append(out.decode(errors="replace")[-2200:])
                    if p.returncode != 0:
                        return {"success": False, "output": "\n".join(logs), "command": "git fetch pinned source", "package": cfg["dest"], "error": "pinned git checkout failed"}
                entry_present = os.path.isfile(entry_path)

            if not entry_present:
                raise RuntimeError(f"Expected tool entrypoint was not found: {entry_path}")

            # Make executable (idempotent)
            if os.path.isfile(entry_path):
                try:
                    os.chmod(entry_path, 0o755)
                    logs.append(f"[setup] chmod +x {entry_path}")
                except Exception:
                    pass

            # Explicit setup requests also repair missing language dependencies
            # when the pinned source was already copied on an earlier launch.
            if cfg.get("pip_steps"):
                req = os.path.join(dst, "requirements.txt")
                pyproject = os.path.join(dst, "pyproject.toml")
                import shutil
                system_python = shutil.which("python3")
                if not system_python:
                    raise RuntimeError("python3 is required to create the dnsrecon virtual environment")
                venv_dir = os.path.join(dst, ".aegis-venv")
                venv_python = os.path.join(venv_dir, "bin", "python")
                if not os.path.isfile(venv_python):
                    venv_cmd = [system_python, "-m", "venv", venv_dir]
                    logs.append(" ".join(venv_cmd) + "  (isolated AEGIS environment)")
                    vp = await asyncio.create_subprocess_exec(
                        *venv_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    vout = await _communicate_with_timeout(vp)
                    logs.append(vout.decode(errors="replace")[-1500:])
                    if vp.returncode != 0:
                        raise RuntimeError("Could not create the dnsrecon virtual environment")
                if os.path.exists(req):
                    pipc = [venv_python, "-m", "pip", "install", "--disable-pip-version-check", "-r", req]
                elif os.path.exists(pyproject):
                    pipc = [venv_python, "-m", "pip", "install", "--disable-pip-version-check", dst]
                else:
                    pipc = []
                if pipc:
                    logs.append(" ".join(pipc) + "  (this may take a minute and requires net)")
                    pp = await asyncio.create_subprocess_exec(
                        *pipc,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    pout = await _communicate_with_timeout(pp)
                    logs.append(pout.decode(errors="replace")[-2000:])
                    if pp.returncode != 0:
                        raise RuntimeError("Python dependency installation failed")
                else:
                    logs.append("[setup] no Python package metadata found, skipping pip")

                wrapper_path = os.path.join(dst, "aegis-dnsrecon")
                wrapper = (
                    "#!/bin/sh\n"
                    f"exec {shlex.quote(venv_python)} {shlex.quote(entry_path)} \"$@\"\n"
                )
                with open(wrapper_path, "w", encoding="utf-8") as wrapper_file:
                    wrapper_file.write(wrapper)
                os.chmod(wrapper_path, 0o755)
                logs.append(f"[setup] created isolated launcher: {wrapper_path}")

            if cfg.get("gem_steps"):
                gem_binary = "gem"
                if platform.system() == "Darwin" and cfg.get("brew_runtime") == "ruby":
                    brew_cmd = ["brew", "install", "ruby"]
                    logs.append(" ".join(brew_cmd) + "  (modern Ruby; macOS system Ruby is left untouched)")
                    rp = await asyncio.create_subprocess_exec(
                        *brew_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    rout = await _communicate_with_timeout(rp)
                    logs.append(rout.decode(errors="replace")[-1800:])
                    if rp.returncode != 0:
                        raise RuntimeError("Homebrew Ruby installation failed")
                    prefix_proc = await asyncio.create_subprocess_exec(
                        "brew", "--prefix", "ruby",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    prefix_out = await _communicate_with_timeout(prefix_proc, timeout=30)
                    if prefix_proc.returncode != 0:
                        raise RuntimeError("Could not locate Homebrew Ruby")
                    ruby_prefix = prefix_out.decode(errors="replace").strip()
                    gem_binary = os.path.join(ruby_prefix, "bin", "gem")
                    os.environ["PATH"] = os.path.join(ruby_prefix, "bin") + os.pathsep + os.environ.get("PATH", "")
                for gcmd in cfg["gem_steps"]:
                    resolved_gcmd = [gem_binary, *gcmd[1:]]
                    logs.append(" ".join(resolved_gcmd) + "  (ruby gems, --user-install, may need net)")
                    gp = await asyncio.create_subprocess_exec(
                        *resolved_gcmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    gout = await _communicate_with_timeout(gp)
                    logs.append(gout.decode(errors="replace")[-1500:])
                    if gp.returncode != 0:
                        raise RuntimeError("Ruby dependency installation failed")

            # Extra brew packages required by some vendored scripts (e.g. samba for enum4linux.pl clients)
            if cfg.get("extra_brew") and platform.system() == "Darwin":
                eb = cfg["extra_brew"]
                logs.append(f"brew install {eb}  (required by the vendored script)")
                try:
                    bp = await asyncio.create_subprocess_exec("brew", "install", eb, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                    bout = await _communicate_with_timeout(bp)
                    logs.append(bout.decode(errors="replace")[-1500:])
                    if bp.returncode != 0:
                        raise RuntimeError(f"Homebrew installation failed for {eb}")
                    prefix_proc = await asyncio.create_subprocess_exec(
                        "brew", "--prefix", eb,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    prefix_out = await _communicate_with_timeout(prefix_proc, timeout=30)
                    if prefix_proc.returncode == 0:
                        prefix = prefix_out.decode(errors="replace").strip()
                        os.environ["PATH"] = os.path.join(prefix, "bin") + os.pathsep + os.path.join(prefix, "sbin") + os.pathsep + os.environ.get("PATH", "")
                except Exception as e:
                    logs.append(f"(extra brew step for {eb} failed: {e})")
                    raise RuntimeError(f"Required dependency '{eb}' could not be installed") from e

            runtime_name = "smb_enum" if name == "enum4linux" else name
            if not is_tool_available(runtime_name):
                raise RuntimeError(
                    "Setup finished, but the tool failed its runtime check. "
                    "Review the dependency output below or use the manual command."
                )

            logs.append("[setup] done. Re-check environment to see updated availability.")
            return {
                "success": True,
                "output": "\n".join(logs),
                "package": cfg["dest"],
                "command": "bundled-copy" if used_bundled else ("already-present" if was_already else "git+setup"),
            }
        except Exception as e:
            logs.append(f"ERROR: {e}")
            guidance = _tool_install_guidance("smb_enum" if name == "enum4linux" else name)
            return {
                "success": False,
                "output": "\n".join(logs),
                "error": str(e),
                "command": "setup " + name,
                "manual_command": guidance["manual_command"],
            }

    # 3. Brew-mapped tools (real formulas that exist).
    #    Keep the map small and only for things that have `brew install <pkg>` that works.
    pkg = _BREW_PACKAGE_BY_TOOL.get(name)
    if not pkg:
        guidance = _tool_install_guidance(name)
        return {
            "success": False,
            "error": guidance["note"],
            "manual_command": guidance["manual_command"],
            "command": "manual installation required",
        }

    try:
        if platform.system() == "Darwin":
            proc = await asyncio.create_subprocess_exec(
                "brew", "install", pkg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out = await _communicate_with_timeout(proc)
            cmd = f"brew install {pkg}"
            output = out.decode(errors="replace")
            success = proc.returncode == 0
            if pkg == "nuclei" and success:
                from tools.definitions import _find_external_tool
                nuclei_binary = _find_external_tool("nuclei")
                if not nuclei_binary:
                    success = False
                    output += "\nHomebrew completed, but the Nuclei executable could not be located."
                else:
                    template_proc = await asyncio.create_subprocess_exec(
                        nuclei_binary,
                        "-update-templates",
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    template_out = await _communicate_with_timeout(template_proc)
                    output += "\n\n[nuclei templates]\n" + template_out.decode(errors="replace")
                    if template_proc.returncode != 0:
                        success = False
            if success and not is_tool_available(name):
                success = False
                output += "\nAEGIS runtime check still cannot locate or execute this tool."
            if pkg == "net-snmp" and success:
                output += (
                    "\n\n[NOTE for snmp_enum] net-snmp is keg-only on Homebrew. "
                    "AEGIS checks /opt/homebrew/opt/net-snmp/bin at runtime, but for your shell you may want:\n"
                    "  echo 'export PATH=\"/opt/homebrew/opt/net-snmp/bin:/opt/homebrew/opt/net-snmp/sbin:$PATH\"' >> ~/.zshrc\n"
                )
            result = {"success": success, "output": output[:4500], "package": pkg, "command": cmd}
            if not success:
                result["manual_command"] = _tool_install_guidance(name)["manual_command"]
            return result
        elif platform.system() == "Windows":
            package_id = _WINGET_PACKAGE_BY_TOOL.get(name)
            if not package_id:
                guidance = _tool_install_guidance(name)
                return {
                    "success": False,
                    "error": guidance["note"],
                    "manual_command": guidance["manual_command"],
                    "command": "manual installation required",
                }
            argv = [
                "winget", "install", "--id", package_id, "--exact", "--silent",
                "--accept-package-agreements", "--accept-source-agreements",
            ]
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out = await _communicate_with_timeout(proc)
            output = out.decode(errors="replace")[:3500]
            success = proc.returncode == 0
            if success:
                output += "\nRestart AEGIS so the installed tool and updated PATH are detected."
            result = {
                "success": success,
                "output": output,
                "package": package_id,
                "command": " ".join(argv),
            }
            if not success:
                result["manual_command"] = f"winget install --id {package_id} --exact"
            return result
        else:
            # Linux path: fixed allowlist and argv execution; never interpolate into a shell.
            apt_map = {
                "net-snmp": "snmp", "sshpass": "sshpass", "ssh-audit": "ssh-audit",
                "theharvester": "theharvester", "subfinder": "subfinder", "gobuster": "gobuster",
                "ffuf": "ffuf", "nikto": "nikto", "sqlmap": "sqlmap", "hydra": "hydra",
                "nmap": "nmap", "whois": "whois",
            }
            apt_pkg = apt_map.get(pkg)
            if not apt_pkg:
                raise HTTPException(400, f"No supported Linux package mapping for {name}")
            argv = ["apt-get", "install", "-y", apt_pkg]
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out = await _communicate_with_timeout(proc)
            output = out.decode(errors="replace")[:3500]
            if proc.returncode != 0:
                output += f"\nInstall may require a terminal: sudo apt-get install -y {apt_pkg}"
            success = proc.returncode == 0
            result = {"success": success, "output": output, "package": apt_pkg, "command": " ".join(argv)}
            if not success:
                result["manual_command"] = f"sudo apt-get install -y {apt_pkg}"
            return result
    except Exception as e:
        guidance = _tool_install_guidance(name)
        return {
            "success": False,
            "error": str(e),
            "command": "automatic installation failed",
            "manual_command": guidance["manual_command"],
        }

@app.post("/api/lm/launch-app")
async def launch_lm_app():
    """Try to open the LM Studio desktop app on supported desktop platforms."""
    import platform
    import shutil
    try:
        if platform.system() == "Darwin":
            proc = await asyncio.create_subprocess_exec("open", "-a", "LM Studio")
            await proc.wait()
            return {"success": True}
        if platform.system() == "Windows":
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            candidates = [
                os.path.join(local_app_data, "Programs", "LM Studio", "LM Studio.exe"),
                os.path.join(local_app_data, "LM Studio", "LM Studio.exe"),
                shutil.which("LM Studio.exe") or "",
            ]
            executable = next((item for item in candidates if item and os.path.isfile(item)), "")
            if not executable:
                return {"success": False, "error": "LM Studio was not found. Install it or launch it manually, then start its local server."}
            await asyncio.create_subprocess_exec(
                executable,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            return {"success": True}
        return {"success": False, "error": "Launch LM Studio manually and start its local server, or set LM_STUDIO_URL to a compatible endpoint."}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/lm/start-server")
async def start_lm_server():
    """Use the lms CLI to start the server without changing loaded models."""
    lms = _find_lms_cli()
    if not lms:
        return {"success": False, "error": "lms CLI not found"}
    try:
        code, output = await _run_lms(lms, "server", "start", timeout=20)
        if code != 0:
            return {"success": False, "error": output[-500:]}
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    await agent.stop_scan()
    return {"status": "stopped"}


@app.post("/api/scan/{scan_id}/approve")
async def approve_tool(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    await agent.approve_tool()
    return {"status": "approved"}


@app.post("/api/scan/{scan_id}/reject")
async def reject_tool(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    await agent.reject_tool()
    return {"status": "rejected"}

@app.post("/api/scan/{scan_id}/approve_exploitation")
async def approve_exploitation(scan_id: str, finding_id: str = "", tool: str = ""):
    """Explicit gate: User must call this (from UI) to allow any real exploitation on a specific finding.
    This enforces the separation between investigation and exploitation.
    Nothing in the 'exploit' phase or exploit tools will run until this is called for relevant findings.
    """
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    if not finding_id:
        raise HTTPException(400, "finding_id required")
    try:
        resume_needed = await agent.approve_finding_for_exploitation(finding_id, tool)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if resume_needed:
        _track_scan_task(
            scan_id,
            asyncio.create_task(agent.resume_exploitation(), name=f"aegis-resume-{scan_id}"),
        )
    return {"status": "exploitation_approved", "finding_id": finding_id, "tool": tool or None}


@app.post("/api/scan/{scan_id}/skip_exploitation")
async def skip_exploitation(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    if not await agent.skip_exploitation():
        raise HTTPException(409, "The scan is not waiting for an exploitation decision")
    return {"status": "exploitation_skipped"}


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    return {"report": agent.generate_report()}


@app.get("/api/scan/{scan_id}/evidence")
async def get_scan_evidence(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    return agent.evidence_snapshot()


@app.post("/api/scan/{scan_id}/retry_discovery")
async def retry_scan_discovery(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    if not await agent.retry_incomplete_discovery():
        raise HTTPException(409, "No incomplete discovery window is awaiting a retry")
    return {"status": "retrying_incomplete_discovery"}


@app.post("/api/scan/{scan_id}/continue_partial")
async def continue_partial_scan(scan_id: str):
    agent = active_agents.get(scan_id)
    if not agent:
        raise HTTPException(404, "Not found")
    if not await agent.continue_with_partial_discovery():
        raise HTTPException(409, "The scan is not waiting on incomplete discovery")
    return {"status": "continuing_with_partial_coverage"}


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(ws: WebSocket, scan_id: str):
    if not re.fullmatch(r"scan_[A-Za-z0-9_-]{16,96}", scan_id):
        await ws.close(code=1008, reason="Invalid scan id")
        return
    protocols = {
        item.strip()
        for item in ws.headers.get("sec-websocket-protocol", "").split(",")
        if item.strip()
    }
    auth_protocol = next((item for item in protocols if item.startswith("aegis.auth.")), "")
    ws_token = auth_protocol.removeprefix("aegis.auth.") or None
    if "aegis.v1" not in protocols or not token_matches(ws_token) or not origin_allowed(ws.headers.get("origin")):
        await ws.close(code=1008, reason="Unauthorized")
        return
    await ws.accept(subprotocol="aegis.v1")
    logger.info(f"WS connected: {scan_id}")
    send_lock = asyncio.Lock()

    async def emit(event: str, data: dict):
        if event in {"scan_started", "coverage_update", "discovery_decision_needed", "phase_change", "scan_complete", "scan_stopped"}:
            try:
                if event in {"scan_complete", "scan_stopped"}:
                    recovery_journal.remove(scan_id)
                elif current_agent := active_agents.get(scan_id):
                    recovery_journal.record(scan_id, current_agent)
            except (OSError, ValueError) as exc:
                logger.warning("Could not update scan recovery metadata: %s", exc)
        try:
            async with send_lock:
                await ws.send_json({"event": event, **data})
        except Exception:
            pass

    async def run_agent(agent: PentestAgent, message: dict):
        try:
            await agent.start_scan(
                target=message.get("target", ""),
                scope=message.get("scope", ""),
                mode=message.get("mode", "supervised"),
                phases=message.get("phases", ["recon", "web", "network", "osint", "exploit"]),
                llm_enabled=message.get("llm_enabled", True),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Scan task failed: %s", scan_id)
            await agent.emit("error", {"message": str(exc)})
            await agent.stop_scan()

    if orphan := orphan_scan_tasks.pop(scan_id, None):
        orphan.cancel()
    if existing := active_agents.get(scan_id):
        existing.emit = emit
        await emit("scan_snapshot", {"snapshot": _scan_reconnect_snapshot(existing)})
    else:
        await emit("scan_missing", {})

    try:
        while True:
            raw = await ws.receive_text()
            if len(raw) > 65536:
                await ws.close(code=1009, reason="Message too large")
                return
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await emit("error", {"message": "Invalid JSON message"})
                continue
            if not isinstance(msg, dict):
                await emit("error", {"message": "Message must be a JSON object"})
                continue
            action = msg.get("action")

            if action == "start_scan":
                try:
                    lm_url = validate_provider_url(msg.get("lm_studio_url") or os.getenv("LM_STUDIO_URL", "http://localhost:1234"))
                    model = _validate_model_id(msg.get("model") or os.getenv("LM_STUDIO_MODEL", ""))
                except ValueError as exc:
                    await emit("error", {"message": str(exc)})
                    continue
                llm_enabled = msg.get("llm_enabled", True)
                uses_lm_studio = False
                if not isinstance(llm_enabled, bool):
                    await emit("error", {"message": "llm_enabled must be a boolean"})
                    continue
                if llm_enabled:
                    if not model:
                        await emit("error", {"message": "Select a local LLM model before starting AI mode"})
                        continue
                    try:
                        available_models = await _fetch_lm_models(lm_url)
                        uses_lm_studio = await _uses_lm_studio_model_management(lm_url)
                    except Exception as exc:
                        await emit("error", {"message": f"Could not list local LLM models: {exc}"})
                        continue
                    if model not in {item["id"] for item in available_models}:
                        await emit("error", {"message": "The selected model is no longer available from the local LLM provider; refresh the model list"})
                        continue

                # Validation happens before replacing an existing scan, so a
                # stale dropdown selection cannot terminate active work.
                old = active_agents.pop(scan_id, None)
                if old:
                    await old.stop_scan()
                if old_task := active_tasks.pop(scan_id, None):
                    old_task.cancel()
                if llm_enabled:
                    if uses_lm_studio:
                        await emit("log", {"type": "agent", "message": f"Loading only the selected LM Studio model: {model}"})
                        try:
                            await _ensure_lm_model_loaded(model, lm_url)
                        except Exception as exc:
                            await emit("error", {"message": f"Could not activate the selected LM Studio model: {exc}"})
                            continue
                    else:
                        await emit("log", {"type": "agent", "message": f"Using provider-managed local model: {model}"})
                agent = PentestAgent(lm_studio_url=lm_url, model=model, emit=emit)
                active_agents[scan_id] = agent
                task = asyncio.create_task(run_agent(agent, msg), name=f"aegis-{scan_id}")
                _track_scan_task(scan_id, task)
                logger.info(f"Scan started: {scan_id} model={model}")

            elif action == "approve":
                if a := active_agents.get(scan_id):
                    await a.approve_tool()
            elif action == "reject":
                if a := active_agents.get(scan_id):
                    await a.reject_tool()
            elif action == "approve_exploitation":
                if a := active_agents.get(scan_id):
                    finding_id = msg.get("finding_id", "")
                    if finding_id:
                        try:
                            resume_needed = await a.approve_finding_for_exploitation(
                                finding_id,
                                msg.get("tool", ""),
                            )
                            if resume_needed:
                                task = asyncio.create_task(
                                    a.resume_exploitation(),
                                    name=f"aegis-resume-{scan_id}",
                                )
                                _track_scan_task(scan_id, task)
                        except ValueError as exc:
                            await emit("error", {"message": str(exc)})
            elif action == "skip_exploitation":
                if a := active_agents.get(scan_id):
                    if not await a.skip_exploitation():
                        await emit(
                            "error",
                            {"message": "The scan is not waiting for an exploitation decision"},
                        )
            elif action == "retry_discovery":
                if a := active_agents.get(scan_id):
                    if not await a.retry_incomplete_discovery():
                        await emit("error", {"message": "No incomplete discovery window is awaiting a retry"})
            elif action == "continue_partial":
                if a := active_agents.get(scan_id):
                    if not await a.continue_with_partial_discovery():
                        await emit("error", {"message": "The scan is not waiting on incomplete discovery"})
            elif action == "stop":
                if a := active_agents.get(scan_id):
                    await a.stop_scan()
            elif action == "message":
                if a := active_agents.get(scan_id):
                    message = str(msg.get("message", ""))[:4000]
                    await a.user_message(message)
            elif action == "report":
                if a := active_agents.get(scan_id):
                    await emit("report", {"markdown": a.generate_report()})
            elif action == "evidence":
                if a := active_agents.get(scan_id):
                    await emit("evidence", {"snapshot": a.evidence_snapshot()})
            else:
                await emit("error", {"message": "Unknown action"})

    except WebSocketDisconnect:
        logger.info(f"WS disconnected: {scan_id}")
    except Exception as e:
        disconnected = isinstance(e, RuntimeError) and any(
            marker in str(e).lower()
            for marker in (
                "websocket is not connected",
                "cannot call receive once a disconnect message has been received",
            )
        )
        if disconnected:
            logger.info(f"WS disconnected: {scan_id}")
            return
        logger.error(f"WS error {scan_id}: {e}")
        try:
            await ws.send_json({"event": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        current = active_agents.get(scan_id)
        if current is not None and current.emit is emit:
            if orphan := orphan_scan_tasks.pop(scan_id, None):
                orphan.cancel()
            orphan_scan_tasks[scan_id] = asyncio.create_task(
                _expire_disconnected_scan(scan_id, current, emit),
                name=f"aegis-disconnect-grace-{scan_id}",
            )


def _get_frontend_dist() -> pathlib.Path:
    """Resolve the built React UI.
    - Normal source tree: ../frontend/dist relative to backend/
    - PyInstaller frozen (desktop .app): the dist is bundled via --add-data as frontend/dist inside the bundle.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # Running inside a PyInstaller onefile / onedir bundle
        base = pathlib.Path(sys._MEIPASS)
        return base / "frontend" / "dist"
    return pathlib.Path(__file__).parent.parent / "frontend" / "dist"

frontend_build = _get_frontend_dist()
if frontend_build.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(frontend_build), html=True), name="frontend")
else:
    logging.getLogger("aegis").info(f"No frontend dist found at {frontend_build} (running API-only or dev mode)")

if __name__ == "__main__":
    import argparse

    import uvicorn
    from security import AUTH_TOKEN

    parser = argparse.ArgumentParser(description="AEGIS Pentest Backend")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (desktop uses internal port)")
    parser.add_argument("--desktop", action="store_true", help="Desktop app mode (quieter logs, no auto-reload, localhost only)")
    args = parser.parse_args()

    host = "127.0.0.1"
    log_level = "warning" if args.desktop else "info"
    if not args.desktop:
        print(f"AEGIS_AUTH_TOKEN={AUTH_TOKEN}")
    uvicorn.run(app, host=host, port=args.port, reload=False, log_level=log_level)
