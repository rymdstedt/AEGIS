"""Small, redacted restart notice for interrupted network scans.

This is deliberately *not* a resumable scan state. Scanner observations,
findings, credentials, raw scope notes, and approval decisions stay in memory.
After a process restart, the operator must authorize a fresh scan; old port
results are never treated as current coverage.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlunsplit

from agent.scope import parse_target

_SCAN_ID = re.compile(r"scan_[A-Za-z0-9_-]{16,96}\Z")
_VALID_PHASES = frozenset({"recon", "web", "network", "osint", "exploit"})
_VALID_MODES = frozenset({"supervised", "manual", "autonomous"})
_VALID_COVERAGE = frozenset({"not_started", "not_requested", "pending", "partial", "bounded", "complete"})
_MAX_BYTES = 16_384
_MAX_ENTRIES = 8
_MAX_AGE = timedelta(days=7)


def default_recovery_root() -> Path:
    configured = os.environ.get("AEGIS_DATA_DIR", "").strip()
    base = Path(configured).expanduser().absolute() if configured else Path.home() / ".aegis"
    return base / "scan-recovery"


def _public_target(agent) -> str:
    """Keep only canonical network authority, never URL paths or query data."""
    target = agent.scope_policy.primary
    if target.kind == "network":
        return target.network_target
    if target.kind == "url":
        host = f"[{target.host}]" if ":" in target.host else target.host
        authority = f"{host}:{target.port}" if target.port else host
        return urlunsplit((target.scheme or "http", authority, "", "", ""))
    host = f"[{target.host}]" if ":" in target.host and target.port else target.host
    return f"{host}:{target.port}" if target.port else host


def _validated_entry(raw: object) -> dict | None:
    if not isinstance(raw, dict) or not _SCAN_ID.fullmatch(str(raw.get("scan_id", ""))):
        return None
    target = str(raw.get("target", ""))
    try:
        parsed = parse_target(target)
    except ValueError:
        return None
    if parsed.kind == "url" and parsed.path_query:
        return None
    phases = raw.get("phases")
    if not isinstance(phases, list) or not phases or len(phases) > 5 or any(phase not in _VALID_PHASES for phase in phases):
        return None
    mode = str(raw.get("mode", ""))
    coverage = str(raw.get("coverage", ""))
    if mode not in _VALID_MODES or coverage not in _VALID_COVERAGE:
        return None
    try:
        updated = datetime.fromisoformat(str(raw.get("updated_at", "")))
        completed = int(raw.get("completed_ports"))
        requested = int(raw.get("requested_ports"))
    except (TypeError, ValueError):
        return None
    if updated.tzinfo is None or updated < datetime.now(UTC) - _MAX_AGE:
        return None
    if not 0 <= completed <= requested <= 65_535 * 256:
        return None
    return {
        "scan_id": str(raw["scan_id"]),
        "target": target,
        "phases": phases,
        "mode": mode,
        "coverage": coverage,
        "completed_ports": completed,
        "requested_ports": requested,
        "updated_at": updated.astimezone(UTC).isoformat(timespec="seconds"),
    }


class ScanRecoveryJournal:
    def __init__(self, root: Path | None = None):
        self.root = (root or default_recovery_root()).absolute()
        self.path = self.root / "scan-recovery.json"
        self._lock = threading.RLock()

    def _ensure_root(self) -> None:
        if self.root.is_symlink():
            raise OSError("Recovery data root cannot be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.root.is_dir():
            raise OSError("Recovery data root is not a directory")
        self.root.chmod(0o700)

    def _read(self) -> list[dict]:
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags)
        except FileNotFoundError:
            return []
        with os.fdopen(fd, "rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                return []
            payload = file.read(_MAX_BYTES + 1)
        if len(payload) > _MAX_BYTES:
            return []
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return []
        if not isinstance(document, dict) or document.get("version") != 1:
            return []
        entries = document.get("entries")
        if not isinstance(entries, list):
            return []
        return [entry for raw in entries[:_MAX_ENTRIES] if (entry := _validated_entry(raw))]

    def _write(self, entries: list[dict]) -> None:
        self._ensure_root()
        if not entries:
            self.path.unlink(missing_ok=True)
            return
        encoded = json.dumps({"version": 1, "entries": entries[:_MAX_ENTRIES]}, separators=(",", ":")).encode()
        if len(encoded) > _MAX_BYTES:
            raise ValueError("Recovery metadata exceeds its size limit")
        fd, name = tempfile.mkstemp(prefix=".scan-recovery-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as file:
                os.fchmod(file.fileno(), 0o600)
                file.write(encoded)
                file.flush()
                os.fsync(file.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def record(self, scan_id: str, agent) -> None:
        if not _SCAN_ID.fullmatch(scan_id) or not agent.state or not agent.scope_policy:
            return
        state = agent.state
        if not state.is_running or state.is_complete:
            self.remove(scan_id)
            return
        coverage = agent.discovery_coverage()
        rows = coverage.get("hosts", [])
        entry = {
            "scan_id": scan_id,
            "target": _public_target(agent),
            "phases": list(state.phases),
            "mode": state.mode.value,
            "coverage": coverage["status"],
            "completed_ports": sum(int(row.get("completed_port_count", 0)) for row in rows),
            "requested_ports": sum(int(row.get("requested_port_count", 0)) for row in rows),
            "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        checked = _validated_entry(entry)
        if not checked:
            return
        with self._lock:
            current = [item for item in self._read() if item["scan_id"] != scan_id]
            self._write([checked, *current][:_MAX_ENTRIES])

    def remove(self, scan_id: str) -> None:
        if not _SCAN_ID.fullmatch(scan_id):
            return
        with self._lock:
            current = self._read()
            if any(item["scan_id"] == scan_id for item in current):
                self._write([item for item in current if item["scan_id"] != scan_id])

    def list_interrupted(self, active_scan_ids: set[str] | None = None) -> list[dict]:
        with self._lock:
            return [item for item in self._read() if item["scan_id"] not in (active_scan_ids or set())]
