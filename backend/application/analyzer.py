"""Bounded, read-only static analysis for imported application artifacts."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit

from .firmware import analyze_firmware_snapshot
from .firmware_deep import analyze_firmware_deep

MAX_TEXT_FILE_BYTES = 1024 * 1024  # Historical limit retained for regression fixtures.
# Quick findings are staged to SQLite per file instead of being cut off at
# this historical in-memory limit.
MAX_FINDINGS = 500
MAX_TEXT_SEGMENT_BYTES = 64 * 1024
MAX_TEXT_PATTERN_OVERLAP_BYTES = 1024
# Keep pathological per-file matches bounded and report the omission explicitly.
MAX_FINDINGS_PER_RULE_FILE = 64
MAX_PRIVATE_EVIDENCE_BYTES = 16 * 1024


class AnalysisCancelled(RuntimeError):
    """An operator cancelled a read-only analysis before its result committed."""

LANGUAGES = {
    ".c": "C", ".h": "C/C++", ".cc": "C++", ".cpp": "C++", ".hpp": "C/C++",
    ".cs": "C#", ".go": "Go", ".java": "Java", ".js": "JavaScript",
    ".jsx": "JavaScript", ".kt": "Kotlin", ".kts": "Kotlin", ".m": "Objective-C",
    ".mm": "Objective-C++", ".php": "PHP", ".pl": "Perl", ".ps1": "PowerShell",
    ".py": "Python", ".rb": "Ruby", ".rs": "Rust", ".sh": "Shell",
    ".swift": "Swift", ".ts": "TypeScript", ".tsx": "TypeScript",
}
TEXT_SUFFIXES = set(LANGUAGES) | {
    ".cfg", ".conf", ".config", ".env", ".gradle", ".html", ".htm", ".ini", ".json",
    ".md", ".plist", ".properties", ".toml", ".txt", ".xml", ".yaml", ".yml",
}
MANIFEST_NAMES = {
    "build.gradle", "build.gradle.kts", "cargo.lock", "cargo.toml", "composer.json",
    "composer.lock", "gemfile", "gemfile.lock", "go.mod", "go.sum", "package-lock.json",
    "package.json", "packages.lock.json", "pipfile", "pipfile.lock", "pnpm-lock.yaml",
    "poetry.lock", "pom.xml", "pyproject.toml", "requirements.txt", "setup.cfg",
    "setup.py", "swift.resolved", "yarn.lock",
}


def _always(_line: str) -> bool:
    return True


_PLACEHOLDER_VALUE = re.compile(
    r"(?i)(?:\[?redacted\]?|example|placeholder|your[_ -]|change[_ -]?me|"
    r"dummy|not[_ -]?a[_ -]?real|test[_ -]?only|none|null)$"
)
_FLAG_TOKEN = re.compile(
    r"\b[A-Z][A-Z0-9_-]{1,47}\{[A-Za-z0-9_.:@/+~=!-]{4,256}\}"
)
_LABELED_SECRET = re.compile(
    r"(?i)^\s*(?P<label>(?:(?:temporary|backup|emergency|administrator|admin|"
    r"database|service(?:[- ]account)?)\s+)?(?:password|passphrase|recovery\s+phrase|"
    r"api[_ -]?key|access[_ -]?token|auth[_ -]?token|client[_ -]?secret))"
    r"\s*[:=]\s*(?P<value>\S(?:.*\S)?)\s*$"
)
_ACCOUNT_IDENTIFIER = re.compile(
    r"(?i)^\s*(?P<label>emergency\s+administrator|administrator(?:\s+account)?|"
    r"admin(?:istrator)?\s+account|backup\s+service\s+account|service[- ]account|"
    r"user(?:name)?)\s*[:=]\s*(?P<value>[A-Za-z0-9_.@-]{3,160})\s*$"
)
_CONTEXT_IDENTIFIER = re.compile(
    r"(?i)^\s*(?P<label>internal\s+project\s+codename|project\s+codename|codename|"
    r"confidential\s+acquisition\s+target|acquisition\s+target)\s*[:=]\s*"
    r"(?P<value>\S(?:.*\S)?)\s*$"
)
_CONNECTION_URI_CREDENTIALS = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@"
)
_ENDPOINT_URI = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+"
)


def _match_has_real_value(pattern: re.Pattern[str], line: str) -> bool:
    match = pattern.search(line)
    if not match:
        return False
    value = str(match.groupdict().get("value") or "").strip()
    return len(value) >= 3 and not _PLACEHOLDER_VALUE.fullmatch(value)


def _is_internal_hostname(hostname: str) -> bool:
    candidate = hostname.strip("[]").casefold().rstrip(".")
    if candidate in {"localhost", "localhost.localdomain"}:
        return True
    try:
        address = ipaddress.ip_address(candidate)
        return not address.is_global
    except ValueError:
        return candidate.endswith((
            ".internal", ".local", ".lan", ".home", ".invalid", ".test",
        ))


def _contains_internal_endpoint(line: str) -> bool:
    for match in _ENDPOINT_URI.finditer(line):
        candidate = match.group(0).rstrip("),.;]}")
        try:
            hostname = urlsplit(candidate).hostname
        except ValueError:
            hostname = None
        if hostname and _is_internal_hostname(hostname):
            return True
    return False


RULES: tuple[dict[str, object], ...] = (
    {
        "id": "secret.private-key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "suffixes": None,
        "severity": "high",
        "confidence": "high",
        "title": "Private Key Material Present",
        "description": "A private-key marker is present in the imported artifact. Confirm whether the key is real, active, and intended for distribution.",
        "remediation": "Remove private keys from source and packages, revoke exposed keys, and load replacements from an approved secret store.",
        "predicate": _always,
    },
    {
        "id": "secret.hardcoded-assignment",
        "pattern": re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']"
        ),
        "suffixes": TEXT_SUFFIXES,
        "severity": "high",
        "confidence": "medium",
        "title": "Potential Hard-Coded Credential",
        "description": "A credential-like name is assigned a non-trivial literal. Static evidence alone cannot establish whether it is live.",
        "remediation": "Verify the value, rotate it if real, remove it from the artifact and history, and retrieve secrets at runtime from a secret manager.",
        "predicate": lambda line: not re.search(
            r"(?i)(example|placeholder|your[_ -]|change[_ -]?me|dummy|not[_ -]?a[_ -]?real|test[_ -]?only)",
            line,
        ),
    },
    {
        "id": "secret.environment-value",
        "pattern": re.compile(
            r"(?i)^\s*(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)\s*=\s*[^\s#\"']{8,}\s*(?:#.*)?$"
        ),
        "suffixes": None,
        "path_predicate": lambda path: Path(path).name.casefold() == ".env"
        or Path(path).name.casefold().startswith(".env."),
        "severity": "high",
        "confidence": "high",
        "title": "Credential Value Present in Environment File",
        "description": "An imported .env file contains a credential-like value. Public evidence is redacted; the exact match requires explicit desktop confirmation.",
        "remediation": "Remove environment files from distributed artifacts and version control, rotate real values, and provide secrets through a protected deployment channel.",
        "predicate": lambda line: not re.search(
            r"(?i)(example|placeholder|change[_ -]?me|dummy|test[_ -]?only)", line
        ),
    },
    {
        "id": "secret.connection-uri-credentials",
        "pattern": _CONNECTION_URI_CREDENTIALS,
        "suffixes": TEXT_SUFFIXES,
        "severity": "high",
        "confidence": "high",
        "title": "Credentials Embedded in Connection URI",
        "description": "A connection URI contains both a username and password. Public evidence hides the URI; exact local evidence requires explicit desktop confirmation.",
        "remediation": "Remove credentials from connection strings, rotate real values, and retrieve them from an approved secret store at runtime.",
        "predicate": _always,
    },
    {
        "id": "secret.labeled-value",
        "pattern": _LABELED_SECRET,
        "suffixes": TEXT_SUFFIXES,
        "severity": "high",
        "confidence": "medium",
        "status": "extracted_evidence",
        "title": "Labeled Secret Value Present",
        "description": "A human-readable note or configuration entry labels a non-placeholder secret value. Exact local evidence requires explicit desktop confirmation.",
        "remediation": "Verify and rotate real values, remove them from distributable artifacts, and store operational secrets in a protected secret manager.",
        "predicate": lambda line: (
            _match_has_real_value(_LABELED_SECRET, line)
            and not re.search(r"^\s*[A-Za-z_][A-Za-z0-9_-]*\s*[:=]\s*[\"']", line)
        ),
    },
    {
        "id": "identity.account-identifier",
        "pattern": _ACCOUNT_IDENTIFIER,
        "suffixes": TEXT_SUFFIXES,
        "severity": "info",
        "confidence": "high",
        "status": "extracted_evidence",
        "title": "Operational Account Identifier Extracted",
        "description": "The artifact names an administrator, user, or service account. This is contextual intelligence, not proof that the account is active.",
        "remediation": "Remove unnecessary operational identities from distributed material and review the referenced account if the artifact was exposed.",
        "predicate": lambda line: _match_has_real_value(_ACCOUNT_IDENTIFIER, line),
    },
    {
        "id": "intelligence.context-identifier",
        "pattern": _CONTEXT_IDENTIFIER,
        "suffixes": TEXT_SUFFIXES,
        "severity": "info",
        "confidence": "high",
        "status": "extracted_evidence",
        "title": "Sensitive Project or Organization Context Extracted",
        "description": "The artifact contains a labeled project codename or organization target. This is extracted context rather than a software vulnerability.",
        "remediation": "Remove confidential organizational context from distributable artifacts and review the exposure with the information owner.",
        "predicate": lambda line: _match_has_real_value(_CONTEXT_IDENTIFIER, line),
    },
    {
        "id": "evidence.scoring-flag",
        "pattern": _FLAG_TOKEN,
        "suffixes": TEXT_SUFFIXES,
        "severity": "info",
        "confidence": "high",
        "status": "extracted_evidence",
        "title": "Evidence or Scoring Flag Extracted",
        "description": "A brace-delimited flag token was found. It proves static evidence discovery only and does not demonstrate execution or exploitation.",
        "remediation": "Remove scoring flags or comparable sensitive markers from production artifacts when they are not intentionally distributed.",
        "predicate": _always,
    },
    {
        "id": "network.internal-endpoint",
        "pattern": _ENDPOINT_URI,
        "suffixes": TEXT_SUFFIXES,
        "severity": "info",
        "confidence": "high",
        "status": "extracted_evidence",
        "title": "Internal Service Endpoint Extracted",
        "description": "The artifact references a loopback, non-public, or explicitly internal service endpoint. This is architecture intelligence, not proof the service is reachable.",
        "remediation": "Avoid exposing unnecessary internal topology in distributed artifacts and validate that referenced services enforce authentication and network restrictions.",
        "predicate": _contains_internal_endpoint,
    },
    {
        "id": "cisco.config-plaintext-password",
        "pattern": re.compile(
            r"(?i)^\s*(?:username\s+\S+\s+(?:password|secret)\s+0\s+\S+|"
            r"enable\s+(?:password|secret)\s+0\s+\S+)"
        ),
        "suffixes": TEXT_SUFFIXES,
        "severity": "high",
        "confidence": "high",
        "title": "Cisco Type 0 Plaintext Credential Present",
        "description": "A Cisco configuration line stores a username or enable credential as plaintext type 0.",
        "remediation": "Rotate the credential and use a supported one-way secret format or centralized authentication.",
        "predicate": _always,
    },
    {
        "id": "cisco.config-type7-password",
        "pattern": re.compile(
            r"(?i)^\s*(?:username\s+\S+\s+(?:password|secret)\s+7\s+[0-9A-F]{4,}|"
            r"enable\s+(?:password|secret)\s+7\s+[0-9A-F]{4,}|"
            r"password\s+7\s+[0-9A-F]{4,})"
        ),
        "suffixes": TEXT_SUFFIXES,
        "severity": "high",
        "confidence": "high",
        "title": "Reversible Cisco Type 7 Credential Present",
        "description": "A Cisco configuration line uses reversible type 7 password obfuscation.",
        "remediation": "Rotate the credential and migrate to a supported one-way secret format or centralized authentication.",
        "predicate": _always,
    },
    {
        "id": "cisco.config-default-snmp-community",
        "pattern": re.compile(
            r"(?i)^\s*snmp-server\s+community\s+(?:public|private)\b"
        ),
        "suffixes": TEXT_SUFFIXES,
        "severity": "high",
        "confidence": "high",
        "title": "Default SNMP Community Present",
        "description": "A Cisco configuration uses the well-known SNMP community name 'public' or 'private'.",
        "remediation": "Remove default communities, rotate values, restrict management sources, and prefer SNMPv3.",
        "predicate": _always,
    },
    {
        "id": "cisco.config-telnet-vty",
        "pattern": re.compile(
            r"(?i)^\s*transport\s+input\s+[^\r\n]{0,80}\btelnet\b"
        ),
        "suffixes": TEXT_SUFFIXES,
        "severity": "medium",
        "confidence": "high",
        "title": "Telnet Permitted on Cisco VTY Lines",
        "description": "A Cisco configuration permits unencrypted Telnet remote management.",
        "remediation": "Remove Telnet from VTY transports and permit SSH only.",
        "predicate": _always,
    },
    {
        "id": "cisco.config-ssh-v1",
        "pattern": re.compile(r"(?i)^\s*ip\s+ssh\s+version\s+1\b"),
        "suffixes": TEXT_SUFFIXES,
        "severity": "high",
        "confidence": "high",
        "title": "Cisco SSH Protocol Version 1 Enabled",
        "description": "A Cisco configuration explicitly enables obsolete SSH protocol version 1.",
        "remediation": "Require SSH version 2 and remove version-1-only algorithms and keys.",
        "predicate": _always,
    },
    {
        "id": "cisco.config-password-encryption-disabled",
        "pattern": re.compile(
            r"(?i)^\s*no\s+service\s+password-encryption\b"
        ),
        "suffixes": TEXT_SUFFIXES,
        "severity": "medium",
        "confidence": "high",
        "title": "Cisco Password Encryption Explicitly Disabled",
        "description": "A Cisco configuration explicitly disables legacy password obfuscation.",
        "remediation": "Use supported one-way secret formats and avoid plaintext credentials in configuration exports.",
        "predicate": _always,
    },
    {
        "id": "electron.node-integration",
        "pattern": re.compile(r"\bnodeIntegration\s*:\s*true\b", re.IGNORECASE),
        "suffixes": {".js", ".jsx", ".ts", ".tsx", ".json"},
        "severity": "high",
        "confidence": "high",
        "title": "Electron Renderer Node Integration Enabled",
        "description": "Electron configuration enables Node.js in a renderer. A renderer compromise can then gain substantially more local capability.",
        "remediation": "Disable nodeIntegration, keep contextIsolation enabled, and expose only narrowly validated operations through a sandboxed preload bridge.",
        "predicate": _always,
    },
    {
        "id": "electron.context-isolation-disabled",
        "pattern": re.compile(r"\bcontextIsolation\s*:\s*false\b", re.IGNORECASE),
        "suffixes": {".js", ".jsx", ".ts", ".tsx", ".json"},
        "severity": "high",
        "confidence": "high",
        "title": "Electron Context Isolation Disabled",
        "description": "Electron configuration disables separation between preload APIs and page JavaScript.",
        "remediation": "Enable contextIsolation and expose a small, typed API with contextBridge instead of renderer-wide privileged objects.",
        "predicate": _always,
    },
    {
        "id": "electron.renderer-sandbox-disabled",
        "pattern": re.compile(r"\bsandbox\s*:\s*false\b", re.IGNORECASE),
        "suffixes": {".js", ".jsx", ".ts", ".tsx", ".json"},
        "severity": "medium",
        "confidence": "high",
        "title": "Electron Renderer Sandbox Disabled",
        "description": "An Electron BrowserWindow explicitly disables its renderer sandbox.",
        "remediation": "Enable the renderer sandbox unless a documented compatibility requirement prevents it, and minimize preload privileges.",
        "predicate": _always,
    },
    {
        "id": "python.subprocess-shell",
        "pattern": re.compile(r"\bshell\s*=\s*True\b"),
        "suffixes": {".py"},
        "severity": "high",
        "confidence": "medium",
        "title": "Python Subprocess Uses a Shell",
        "description": "A Python process invocation enables shell parsing. It becomes command injection when untrusted data reaches the command string.",
        "remediation": "Pass an argument vector with shell=False and strictly validate any value that crosses a process boundary.",
        "predicate": lambda line: "subprocess" in line,
    },
    {
        "id": "python.os-system",
        "pattern": re.compile(r"\bos\.system\s*\("),
        "suffixes": {".py"},
        "severity": "high",
        "confidence": "medium",
        "title": "Shell Command Execution Requires Data-Flow Review",
        "description": "os.system invokes a command through the platform shell. Static matching does not prove that attacker-controlled input reaches it.",
        "remediation": "Replace shell commands with direct library calls or subprocess argument arrays and validate all externally influenced arguments.",
        "predicate": _always,
    },
    {
        "id": "python.unsafe-deserialization",
        "pattern": re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "suffixes": {".py"},
        "severity": "high",
        "confidence": "medium",
        "title": "Python Pickle Deserialization Present",
        "description": "Pickle can execute code while deserializing. This is exploitable when the serialized bytes are untrusted.",
        "remediation": "Do not unpickle untrusted data; use a non-executable format with schema validation and integrity protection.",
        "predicate": _always,
    },
    {
        "id": "python.yaml-unsafe-load",
        "pattern": re.compile(r"\byaml\.load\s*\("),
        "suffixes": {".py"},
        "severity": "medium",
        "confidence": "medium",
        "title": "YAML Load Requires Safe Loader Review",
        "description": "yaml.load is present without a safe loader on the matched line. Unsafe object construction may be possible for untrusted YAML.",
        "remediation": "Use yaml.safe_load or explicitly use SafeLoader, and validate the resulting data structure.",
        "predicate": lambda line: "SafeLoader" not in line and "safe_load" not in line,
    },
    {
        "id": "code.dynamic-eval",
        "pattern": re.compile(r"(?<![A-Za-z0-9_.])(?:eval|exec)\s*\("),
        "suffixes": {".js", ".jsx", ".py", ".ts", ".tsx"},
        "severity": "medium",
        "confidence": "low",
        "title": "Dynamic Code Evaluation Present",
        "description": "The artifact contains a dynamic code-evaluation call. Exploitability depends on whether untrusted data reaches it.",
        "remediation": "Replace dynamic evaluation with explicit parsing or dispatch; otherwise enforce a strict allowlist and prove the input is trusted.",
        "predicate": lambda line: not line.lstrip().startswith(("//", "#", "*"))
        and "re.compile" not in line
        and "new RegExp" not in line,
    },
    {
        "id": "node.child-process-exec",
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_.])(?:child_process\.exec|exec)(?:Sync)?\s*\("
        ),
        "suffixes": {".js", ".jsx", ".ts", ".tsx"},
        "severity": "high",
        "confidence": "medium",
        "title": "Node.js Shell Command Execution Present",
        "description": "A Node.js exec-style process call is present. It may allow command injection when a command includes untrusted input.",
        "remediation": "Prefer execFile/spawn with an argument array and validate values before invoking external programs.",
        "predicate": lambda line: "exec" in line and not line.lstrip().startswith(("//", "*")),
    },
    {
        "id": "tls.verification-disabled",
        "pattern": re.compile(r"\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0"),
        "suffixes": {".js", ".jsx", ".py", ".ts", ".tsx"},
        "severity": "medium",
        "confidence": "high",
        "title": "TLS Certificate Verification Disabled",
        "description": "The matched configuration disables TLS peer verification, which can permit interception of supposedly secure connections.",
        "remediation": "Restore certificate verification and configure the intended trust roots or development certificate explicitly.",
        "predicate": _always,
    },
    {
        "id": "flask.debug-enabled",
        "pattern": re.compile(r"\bdebug\s*=\s*True\b"),
        "suffixes": {".py"},
        "severity": "medium",
        "confidence": "medium",
        "title": "Application Debug Mode Enabled",
        "description": "A Python application appears to enable debug mode. Exposure of an interactive debugger can have severe consequences.",
        "remediation": "Disable debug mode in deployed builds and keep development servers inaccessible from untrusted networks.",
        "predicate": lambda line: ".run(" in line or "flask" in line.lower(),
    },
)

_SECRET_VALUE = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)\b\s*[:=]\s*)([\"']?)([^\s,;\"']+)([\"']?)"
)
_BEARER = re.compile(r"(?i)(authorization\s*[:=]\s*[\"']?bearer\s+)[^\s\"']+")
_URL_CREDENTIALS = re.compile(
    r"([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@",
    re.IGNORECASE,
)
_LABELED_SECRET_REDACTION = re.compile(
    _LABELED_SECRET.pattern,
    re.IGNORECASE,
)
_ACCOUNT_REDACTION = re.compile(_ACCOUNT_IDENTIFIER.pattern, re.IGNORECASE)
_CONTEXT_REDACTION = re.compile(_CONTEXT_IDENTIFIER.pattern, re.IGNORECASE)
_CISCO_CREDENTIALS = (
    re.compile(
        r"(?i)(\busername\s+\S+\s+(?:password|secret)\s+\d+\s+)\S+"
    ),
    re.compile(r"(?i)(\benable\s+(?:password|secret)\s+\d+\s+)\S+"),
    re.compile(r"(?i)(\bpassword\s+7\s+)\S+"),
    re.compile(r"(?i)(\bsnmp-server\s+community\s+)\S+"),
)


def _redact_evidence(line: str) -> str:
    if "PRIVATE KEY-----" in line:
        return "[REDACTED PRIVATE KEY MARKER]"
    value = _LABELED_SECRET_REDACTION.sub(
        lambda match: f"{match.group('label')}: [REDACTED]",
        line,
    )
    value = _ACCOUNT_REDACTION.sub(
        lambda match: f"{match.group('label')}: [REDACTED ACCOUNT]",
        value,
    )
    value = _CONTEXT_REDACTION.sub(
        lambda match: f"{match.group('label')}: [REDACTED CONTEXT]",
        value,
    )
    value = _FLAG_TOKEN.sub("[REDACTED FLAG]", value)
    value = _SECRET_VALUE.sub(r"\1\2[REDACTED]\4", value)
    value = _BEARER.sub(r"\1[REDACTED]", value)
    value = _ENDPOINT_URI.sub(
        lambda match: (
            "[REDACTED INTERNAL ENDPOINT]"
            if _contains_internal_endpoint(match.group(0))
            else match.group(0)
        ),
        value,
    )
    value = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    for pattern in _CISCO_CREDENTIALS:
        value = pattern.sub(r"\1[REDACTED]", value)
    value = value.strip().replace("\x00", "")
    return value[:400] + ("…" if len(value) > 400 else "")


def redact_source_evidence(value: str) -> str:
    """Return the same bounded public redaction used by built-in findings.

    External read-only analyzers use this public wrapper so their source
    excerpts can never bypass the Application Research evidence boundary.
    Exact matches belong in ``private_evidence`` and remain confirmation-gated.
    """
    return _redact_evidence(str(value))


def _private_evidence(lines: list[str], index: int, rule_id: str) -> str:
    """Return bounded exact evidence for the private operator-only vault.

    Public finding records always receive ``_redact_evidence`` instead. Private
    keys need the complete PEM block to be useful, while other rules retain the
    exact matching source line only.
    """
    if rule_id != "secret.private-key":
        evidence = lines[index].replace("\x00", "").strip()
        return evidence[:MAX_PRIVATE_EVIDENCE_BYTES]

    block: list[str] = []
    size = 0
    for line in lines[index:]:
        safe_line = line.replace("\x00", "")
        encoded_size = len(safe_line.encode("utf-8", errors="replace")) + 1
        if size + encoded_size > MAX_PRIVATE_EVIDENCE_BYTES:
            break
        block.append(safe_line)
        size += encoded_size
        if re.fullmatch(
            r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            safe_line.strip(),
        ):
            break
    return "\n".join(block).strip()


def _iter_files(root: Path) -> Iterable[tuple[Path, str]]:
    if root.is_file():
        yield root, root.name
        return
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory for directory in directories
            if not (Path(current) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_symlink() or not path.is_file():
                continue
            yield path, path.relative_to(root).as_posix()


def _file_format(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            header = stream.read(8)
    except OSError:
        return "unreadable"
    if header.startswith(b"MZ"):
        return "PE"
    if header.startswith(b"\x7fELF"):
        return "ELF"
    if header[:4] in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    }:
        return "Mach-O"
    if header.startswith(b"PK\x03\x04"):
        return "ZIP"
    if b"\x00" not in header:
        return "text-or-data"
    return "binary-data"


def _iter_text_segments(path: Path) -> Iterable[tuple[int, str, str, bool, int]]:
    """Read a text candidate with fixed memory, even for a very long line.

    The overlapping view lets non-anchored patterns span segment boundaries.
    ``fresh`` excludes overlap so private PEM blocks do not duplicate bytes.
    A match remains keyed to its actual line, even when that line is segmented.
    """
    with path.open("rb") as stream:
        line_number = 1
        overlap = b""
        first_segment = True
        while chunk := stream.readline(MAX_TEXT_SEGMENT_BYTES):
            view = (overlap + chunk).decode("utf-8", errors="replace").rstrip("\r\n")
            fresh = chunk.decode("utf-8", errors="replace")
            yield line_number, view, fresh, first_segment, len(chunk)
            if chunk.endswith(b"\n"):
                line_number += 1
                overlap = b""
                first_segment = True
            else:
                overlap = (overlap + chunk)[-MAX_TEXT_PATTERN_OVERLAP_BYTES:]
                first_segment = False


def _bounded_exact(value: str) -> str:
    """Keep exact private evidence inside its byte ceiling."""
    return value.replace("\x00", "").encode("utf-8", errors="replace")[
        :MAX_PRIVATE_EVIDENCE_BYTES
    ].decode("utf-8", errors="ignore").strip()


def analyze_snapshot(
    root: Path,
    project_id: str,
    artifact_kind: str,
    profile: str = "quick",
    progress: Callable[[dict[str, object]], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_findings: Callable[[list[dict[str, object]], list[dict[str, str]]], None] | None = None,
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, str]],
]:
    """Inventory and statically inspect an imported snapshot without execution."""
    if not root.exists():
        raise FileNotFoundError("The imported artifact snapshot is missing")
    started_at = time.perf_counter()

    extensions: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    formats: Counter[str] = Counter()
    manifests: list[str] = []
    findings: list[dict[str, object]] = []
    private_evidence: list[dict[str, str]] = []
    severities: Counter[str] = Counter()
    total_findings = 0
    existing_rule_paths: set[tuple[str, str]] = set()
    files = 0
    total_bytes = 0
    analyzed_text_files = 0
    analyzed_text_bytes = 0
    text_candidates_considered = 0
    binary_or_unreadable_candidates = 0
    inventory_only_non_text_files = 0
    skipped_large_text_candidates = 0
    segmented_long_lines = 0
    changed_during_scan_files = 0
    rule_evaluations = 0
    per_rule_file_omission_count = 0
    per_rule_file_omission_examples: list[dict[str, str]] = []
    progress_last_at = 0.0

    def report_progress(current_file: str, *, force: bool = False) -> None:
        nonlocal progress_last_at
        if progress is None:
            return
        now = time.monotonic()
        if force or now - progress_last_at >= 0.2:
            progress({
                "files_visited": files,
                "text_bytes_inspected": analyzed_text_bytes,
                "current_file": current_file[:500],
            })
            progress_last_at = now

    for path, relative_path in _iter_files(root):
        if cancelled is not None and cancelled():
            raise AnalysisCancelled("Analysis cancelled by operator")
        try:
            size = path.stat(follow_symlinks=False).st_size
        except OSError:
            continue
        files += 1
        total_bytes += size
        report_progress(relative_path)
        suffix = path.suffix.lower()
        extensions[suffix or "[none]"] += 1
        if suffix in LANGUAGES:
            languages[LANGUAGES[suffix]] += 1
        formats[_file_format(path)] += 1
        if path.name.casefold() in MANIFEST_NAMES:
            manifests.append(relative_path)

        text_candidate = suffix in TEXT_SUFFIXES or size <= 64 * 1024
        if not text_candidate:
            inventory_only_non_text_files += 1
            continue
        text_candidates_considered += 1
        try:
            with path.open("rb") as probe:
                binary_prefix = b"\x00" in probe.read(8192)
        except OSError:
            binary_prefix = True
        if binary_prefix:
            binary_or_unreadable_candidates += 1
            continue
        analyzed_text_files += 1
        file_findings: list[dict[str, object]] = []
        file_private_evidence: list[dict[str, str]] = []
        rule_file_counts: Counter[str] = Counter()
        rule_file_overflow: set[str] = set()
        matched_on_line: set[str] = set()
        previous_line_number = 0
        last_segmented_line = 0
        file_text_bytes = 0
        pending_pem: dict[str, object] | None = None
        for line_number, line, fresh, first_segment, bytes_read in _iter_text_segments(path):
            if cancelled is not None and cancelled():
                raise AnalysisCancelled("Analysis cancelled by operator")
            analyzed_text_bytes += bytes_read
            file_text_bytes += bytes_read
            report_progress(relative_path)
            if not first_segment and line_number != last_segmented_line:
                segmented_long_lines += 1
                last_segmented_line = line_number
            if line_number != previous_line_number:
                matched_on_line.clear()
                previous_line_number = line_number
            if pending_pem is not None:
                pending_text = str(pending_pem["text"]) + fresh
                row = pending_pem["row"]
                if isinstance(row, dict):
                    row["raw_evidence"] = _bounded_exact(pending_text)
                if (
                    "-----END PRIVATE KEY-----" in fresh
                    or len(pending_text.encode("utf-8", errors="replace")) >= MAX_PRIVATE_EVIDENCE_BYTES
                ):
                    pending_pem = None
                else:
                    pending_pem["text"] = pending_text
            for rule in RULES:
                rule_id = str(rule["id"])
                if rule_id in matched_on_line:
                    continue
                suffixes = rule["suffixes"]
                if suffixes is not None and suffix not in suffixes:
                    continue
                path_predicate = rule.get("path_predicate")
                if callable(path_predicate) and not path_predicate(relative_path):
                    continue
                # Check for one additional match after the cap, then stop
                # evaluating this rule in this file. This establishes a real
                # omission without scanning an unbounded number of extras.
                if rule_id in rule_file_overflow:
                    continue
                pattern = rule["pattern"]
                predicate = rule["predicate"]
                if not isinstance(pattern, re.Pattern) or not callable(predicate):
                    continue
                if not first_segment and re.match(r"(?:\(\?[a-z]+\))?\^", pattern.pattern):
                    continue
                rule_evaluations += 1
                match = pattern.search(line)
                if not match or not predicate(line):
                    continue
                matched_on_line.add(rule_id)
                if rule_file_counts[rule_id] >= MAX_FINDINGS_PER_RULE_FILE:
                    rule_file_overflow.add(rule_id)
                    per_rule_file_omission_count += 1
                    if len(per_rule_file_omission_examples) < 20:
                        per_rule_file_omission_examples.append({
                            "file_path": relative_path,
                            "rule_id": rule_id,
                        })
                    continue
                identity = f"{project_id}\x00{rule_id}\x00{relative_path}\x00{line_number}"
                finding_id = "appf_" + hashlib.sha256(identity.encode()).hexdigest()[:20]
                snippet = (
                    line if len(line) <= MAX_PRIVATE_EVIDENCE_BYTES
                    else line[
                        max(0, match.start() - 160):
                        min(len(line), match.end() + MAX_PRIVATE_EVIDENCE_BYTES - 160)
                    ]
                )
                finding = {
                    "id": finding_id,
                    "rule_id": rule_id,
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "status": rule.get("status", "static_evidence"),
                    "title": rule["title"],
                    "description": rule["description"],
                    "file_path": relative_path,
                    "line": line_number,
                    "evidence": _redact_evidence(snippet),
                    "remediation": rule["remediation"],
                }
                file_findings.append(finding)
                total_findings += 1
                severities[str(rule["severity"])] += 1
                existing_rule_paths.add((rule_id, relative_path))
                private_row = {
                    "finding_id": finding_id,
                    "raw_evidence": _bounded_exact(snippet),
                }
                file_private_evidence.append(private_row)
                if rule_id == "secret.private-key":
                    key_text = line[match.start():]
                    private_row["raw_evidence"] = _bounded_exact(key_text)
                    if "-----END PRIVATE KEY-----" not in key_text:
                        pending_pem = {"row": private_row, "text": key_text + ("\n" if fresh.endswith("\n") else "")}
                rule_file_counts[rule_id] += 1
        if on_findings is not None:
            on_findings(file_findings, file_private_evidence)
        else:
            findings.extend(file_findings)
            private_evidence.extend(file_private_evidence)
        if file_text_bytes != size:
            changed_during_scan_files += 1

    if cancelled is not None and cancelled():
        raise AnalysisCancelled("Analysis cancelled by operator")
    report_progress("", force=True)

    if profile not in {"quick", "deep_firmware"}:
        raise ValueError("Unsupported application-analysis profile")

    firmware = analyze_firmware_snapshot(root, artifact_kind)
    if profile == "deep_firmware" and firmware is None:
        raise ValueError("Deep firmware analysis requires a recognized firmware artifact")
    if profile == "deep_firmware" and firmware is not None:
        deep_summary, deep_findings, deep_private = analyze_firmware_deep(
            root,
            project_id,
            firmware,
        )
        accepted_ids: set[str] = set()
        accepted_deep: list[dict[str, object]] = []
        for finding in deep_findings:
            key = (
                str(finding["rule_id"]),
                str(finding.get("file_path") or "").split("@", 1)[0],
            )
            if key in existing_rule_paths:
                continue
            accepted_deep.append(finding)
            total_findings += 1
            severities[str(finding["severity"])] += 1
            accepted_ids.add(str(finding["id"]))
        accepted_private = [
            item for item in deep_private if str(item.get("finding_id")) in accepted_ids
        ]
        if on_findings is not None:
            on_findings(accepted_deep, accepted_private)
        else:
            findings.extend(accepted_deep)
            private_evidence.extend(accepted_private)
        deep_summary["security_indicators_detected"] = deep_summary.get(
            "security_indicators", 0
        )
        deep_summary["security_indicators"] = len(accepted_ids)
        firmware["deep_analysis"] = deep_summary

    summary: dict[str, object] = {
        "engine": "aegis-static-v1",
        "analysis_profile": (
            "deep_firmware_static" if profile == "deep_firmware"
            else "quick_static_triage"
        ),
        "artifact_kind": artifact_kind,
        "completed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "duration_seconds": round(time.perf_counter() - started_at, 3),
        "inventory": {
            "files": files,
            "bytes": total_bytes,
            "analyzed_text_files": analyzed_text_files,
            "analyzed_text_bytes": analyzed_text_bytes,
            "text_candidates_considered": text_candidates_considered,
            "binary_or_unreadable_candidates": binary_or_unreadable_candidates,
            "inventory_only_non_text_files": inventory_only_non_text_files,
            "skipped_large_text_candidates": skipped_large_text_candidates,
            "segmented_long_lines": segmented_long_lines,
            "changed_during_scan_files": changed_during_scan_files,
            "languages": [
                {"name": name, "files": count}
                for name, count in languages.most_common()
            ],
            "formats": dict(formats.most_common()),
            "extensions": [
                {"extension": extension, "files": count}
                for extension, count in extensions.most_common(20)
            ],
            "manifests": sorted(manifests)[:100],
            "manifests_truncated": max(0, len(manifests) - 100),
        },
        "finding_counts": {
            severity: severities.get(severity, 0)
            for severity in ("critical", "high", "medium", "low", "info")
        },
        "finding_total": total_findings,
        "findings_truncated": per_rule_file_omission_count > 0,
        "global_finding_limit_reached": False,
        "findings_omitted_lower_bound": per_rule_file_omission_count,
        "per_rule_file_omission_count": per_rule_file_omission_count,
        "per_rule_file_omission_examples": per_rule_file_omission_examples,
        "max_findings_per_rule_file": MAX_FINDINGS_PER_RULE_FILE,
        "rules_checked": len(RULES),
        "rule_evaluations": rule_evaluations,
        "source_text_limit_bytes_per_file": None,
        "streamed_text_segment_bytes": MAX_TEXT_SEGMENT_BYTES,
        "pattern_overlap_bytes": MAX_TEXT_PATTERN_OVERLAP_BYTES,
        "coverage_incomplete": bool(segmented_long_lines or changed_during_scan_files),
        "max_findings": None,
        "artifact_executed": False,
        "external_analyzers": [],
        "limitations": [
            "Quick triage is static and pattern-based; a match is evidence for review, not proof of exploitability.",
            "Text candidates are streamed in bounded segments; binary and unsupported formats remain inventory-only.",
            "Patterns spanning more than the segment overlap may be missed in unusually long lines.",
            "Dependency vulnerability and SBOM analysis has not run for this pass.",
            "Data-flow SAST, binary decompilation, signing, and dynamic sandbox analyzers are not enabled yet.",
        ],
    }
    if firmware is not None:
        summary["firmware"] = firmware
        summary["limitations"].append(
            "Firmware triage inventories images and embedded format signatures. "
            "Cisco advisory correlation is a separate explicit lookup; cryptographic "
            "signature verification, filesystem extraction, and binary decompilation "
            "have not run."
        )
    if per_rule_file_omission_count:
        summary["limitations"].append(
            f"At least {per_rule_file_omission_count} additional matching evidence "
            "item(s) were omitted by the per-rule-per-file finding cap; the "
            "saved findings are not a complete enumeration."
        )
    return summary, findings, private_evidence
