"""Extended, read-only security analysis for recognized firmware images.

The deep pass still never executes or mounts imported content.  It scans the
same bounded byte ranges used by the firmware inventory, extracts only small
evidence matches, and parses embedded ELF headers defensively.  Compressed or
encrypted filesystems remain opaque until a separately isolated extractor is
configured.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import struct
from pathlib import Path
from typing import Any

from .firmware import _iter_chunks

MAX_MATCHES_PER_RULE_IMAGE = 8
MAX_COMPONENTS = 256
MAX_ELF_OBJECTS = 128
MAX_DEEP_FINDINGS = 500
MAX_PRIVATE_EVIDENCE_BYTES = 16 * 1024


FIRMWARE_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "firmware.private-key",
        "pattern": re.compile(
            rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        "severity": "high",
        "confidence": "high",
        "title": "Private Key Material Embedded in Firmware",
        "description": (
            "An uncompressed private-key marker is present in the firmware bytes. "
            "Determine whether the key is active, shared between devices, or usable "
            "outside its intended trust boundary."
        ),
        "remediation": (
            "Remove private keys from distributable images, rotate affected keys, "
            "and provision device-unique keys through a protected process."
        ),
    },
    {
        "id": "cisco.config-plaintext-password",
        "pattern": re.compile(
            rb"(?i)(?:username[ \t]+[^\s\x00]+[ \t]+(?:password|secret)[ \t]+0"
            rb"[ \t]+[^\s\x00]+|enable[ \t]+(?:password|secret)[ \t]+0[ \t]+"
            rb"[^\s\x00]+)"
        ),
        "severity": "high",
        "confidence": "high",
        "title": "Cisco Type 0 Plaintext Credential Embedded",
        "description": (
            "Firmware-accessible configuration text contains a Cisco type 0 "
            "plaintext username or enable credential."
        ),
        "remediation": (
            "Remove the plaintext value, rotate it, and use a supported one-way "
            "secret format or centralized authentication."
        ),
    },
    {
        "id": "cisco.config-type7-password",
        "pattern": re.compile(
            rb"(?i)(?:username[ \t]+[^\s\x00]+[ \t]+(?:password|secret)[ \t]+7"
            rb"[ \t]+[0-9A-F]{4,}|enable[ \t]+(?:password|secret)[ \t]+7[ \t]+"
            rb"[0-9A-F]{4,}|password[ \t]+7[ \t]+[0-9A-F]{4,})"
        ),
        "severity": "high",
        "confidence": "high",
        "title": "Reversible Cisco Type 7 Credential Embedded",
        "description": (
            "Firmware-accessible configuration text contains a Cisco type 7 "
            "credential, which is obfuscation rather than secure password hashing."
        ),
        "remediation": (
            "Rotate the credential and migrate to a supported one-way secret format "
            "or centralized authentication."
        ),
    },
    {
        "id": "cisco.config-default-snmp-community",
        "pattern": re.compile(
            rb"(?i)snmp-server[ \t]+community[ \t]+(?:public|private)\b"
        ),
        "severity": "high",
        "confidence": "high",
        "title": "Default SNMP Community Embedded",
        "description": (
            "Configuration text contains the well-known SNMP community name "
            "'public' or 'private'."
        ),
        "remediation": (
            "Remove default communities, rotate community values, restrict management "
            "sources, and prefer authenticated and encrypted SNMPv3."
        ),
    },
    {
        "id": "cisco.config-telnet-vty",
        "pattern": re.compile(
            rb"(?i)transport[ \t]+input[ \t]+[^\r\n\x00]{0,80}\btelnet\b"
        ),
        "severity": "medium",
        "confidence": "high",
        "title": "Telnet Permitted on Cisco VTY Lines",
        "description": (
            "Configuration text permits Telnet on remote-management lines, exposing "
            "credentials and sessions without transport encryption."
        ),
        "remediation": "Remove Telnet from VTY transports and permit SSH only.",
    },
    {
        "id": "cisco.config-ssh-v1",
        "pattern": re.compile(rb"(?i)ip[ \t]+ssh[ \t]+version[ \t]+1\b"),
        "severity": "high",
        "confidence": "high",
        "title": "Cisco SSH Protocol Version 1 Enabled",
        "description": "Configuration text explicitly enables obsolete SSH protocol version 1.",
        "remediation": "Require SSH version 2 and remove version-1-only algorithms and keys.",
    },
    {
        "id": "cisco.config-password-encryption-disabled",
        "pattern": re.compile(
            rb"(?i)no[ \t]+service[ \t]+password-encryption\b"
        ),
        "severity": "medium",
        "confidence": "high",
        "title": "Cisco Password Encryption Explicitly Disabled",
        "description": (
            "Configuration text explicitly disables the legacy password-obfuscation "
            "service. This does not secure credentials that use stronger secret formats."
        ),
        "remediation": (
            "Use supported one-way secret formats for all credentials and avoid storing "
            "plaintext passwords in configuration exports."
        ),
    },
    {
        "id": "firmware.elf-executable-stack",
        "severity": "high",
        "confidence": "high",
        "title": "Embedded ELF Requests an Executable Stack",
        "description": (
            "An embedded ELF program header marks the process stack executable, "
            "removing an important exploitation mitigation."
        ),
        "remediation": (
            "Rebuild the component with a non-executable stack and investigate source "
            "or assembly objects that require executable-stack markings."
        ),
    },
    {
        "id": "firmware.elf-non-pie",
        "severity": "low",
        "confidence": "high",
        "title": "Embedded ELF Executable Is Not Position Independent",
        "description": (
            "An embedded ET_EXEC binary is not position independent, limiting the "
            "effectiveness of address-space randomization."
        ),
        "remediation": (
            "Rebuild executable components as PIE where the platform supports it and "
            "verify ASLR remains enabled at runtime."
        ),
    },
)

_COMPONENT_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("OpenSSL", re.compile(rb"\bOpenSSL[ /]([0-9]+\.[0-9]+\.[0-9A-Za-z.+_-]+)")),
    ("BusyBox", re.compile(rb"\bBusyBox[ \t]+v([0-9]+\.[0-9]+\.[0-9A-Za-z.+_-]+)")),
    ("Linux kernel", re.compile(rb"\bLinux version[ \t]+([0-9]+\.[0-9]+\.[0-9A-Za-z.+_-]+)")),
    ("Dropbear SSH", re.compile(rb"\bDropbear[_ /-]?([0-9]{4}\.[0-9]+(?:\.[0-9]+)?)")),
    ("dnsmasq", re.compile(rb"\bdnsmasq[- /]([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("lighttpd", re.compile(rb"\blighttpd[- /]([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("nginx", re.compile(rb"\bnginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
)

_CISCO_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)(\busername\s+\S+\s+(?:password|secret)\s+\d+\s+)\S+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\benable\s+(?:password|secret)\s+\d+\s+)\S+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\bpassword\s+7\s+)\S+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\bsnmp-server\s+community\s+)\S+"),
        r"\1[REDACTED]",
    ),
)

_ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}


def _redact(value: str, rule_id: str) -> str:
    if rule_id == "firmware.private-key":
        return "[REDACTED PRIVATE KEY MARKER]"
    result = value.replace("\x00", " ").strip()
    for pattern, replacement in _CISCO_REDACTIONS:
        result = pattern.sub(replacement, result)
    return result[:500] + ("…" if len(result) > 500 else "")


def _exact_private_evidence(data: bytes, start: int, rule_id: str) -> str:
    if rule_id == "firmware.private-key":
        end_match = re.search(
            rb"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            data[start : start + MAX_PRIVATE_EVIDENCE_BYTES],
        )
        end = (
            start + end_match.end()
            if end_match is not None
            else min(len(data), start + 512)
        )
        raw = data[start:end]
    else:
        raw = data[start : start + 1024].split(b"\x00", 1)[0].splitlines()[0]
    return raw[:MAX_PRIVATE_EVIDENCE_BYTES].decode("utf-8", errors="replace").strip()


def _finding(
    project_id: str,
    rule: dict[str, Any],
    relative_path: str,
    offset: int,
    exact_evidence: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    rule_id = str(rule["id"])
    identity = f"{project_id}\x00{rule_id}\x00{relative_path}\x00{offset}"
    finding_id = "appf_" + hashlib.sha256(identity.encode()).hexdigest()[:20]
    return (
        {
            "id": finding_id,
            "rule_id": rule_id,
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "status": "static_evidence",
            "title": rule["title"],
            "description": rule["description"],
            "file_path": f"{relative_path}@0x{offset:x}",
            "line": None,
            "evidence": _redact(exact_evidence, rule_id),
            "remediation": rule["remediation"],
        },
        {"finding_id": finding_id, "raw_evidence": exact_evidence},
    )


def _safe_image_path(root: Path, relative_path: str) -> Path | None:
    path = root if root.is_file() and root.name == relative_path else root / relative_path
    try:
        resolved = path.resolve(strict=True)
        if root.is_dir():
            resolved.relative_to(root.resolve(strict=True))
        if not resolved.is_file() or resolved.is_symlink():
            return None
        return resolved
    except (OSError, ValueError):
        return None


def _parse_elf(path: Path, offset: int, relative_path: str) -> dict[str, Any] | None:
    try:
        file_size = path.stat(follow_symlinks=False).st_size
        if offset < 0 or offset + 52 > file_size:
            return None
        with path.open("rb") as stream:
            stream.seek(offset)
            header = stream.read(64)
            if not header.startswith(b"\x7fELF") or header[4] not in {1, 2} or header[5] not in {1, 2}:
                return None
            bits = 32 if header[4] == 1 else 64
            endian = "<" if header[5] == 1 else ">"
            encoding = "little" if header[5] == 1 else "big"
            if bits == 32:
                fields = struct.unpack(f"{endian}HHIIIIIHHHHHH", header[16:52])
            else:
                fields = struct.unpack(f"{endian}HHIQQQIHHHHHH", header[16:64])
            elf_type, machine = fields[0], fields[1]
            program_offset = int(fields[4])
            program_entry_size = int(fields[8])
            program_count = min(int(fields[9]), 256)
            minimum_entry_size = 32 if bits == 32 else 56
            stack_executable: bool | None = None
            interpreter: str | None = None
            if program_entry_size >= minimum_entry_size and program_count:
                table_end = offset + program_offset + program_entry_size * program_count
                if table_end <= file_size:
                    for index in range(program_count):
                        stream.seek(offset + program_offset + index * program_entry_size)
                        entry = stream.read(minimum_entry_size)
                        if len(entry) != minimum_entry_size:
                            break
                        if bits == 32:
                            values = struct.unpack(f"{endian}IIIIIIII", entry)
                            segment_type, segment_file_offset = values[0], values[1]
                            segment_file_size, flags = values[4], values[6]
                        else:
                            values = struct.unpack(f"{endian}IIQQQQQQ", entry)
                            segment_type, flags = values[0], values[1]
                            segment_file_offset, segment_file_size = values[2], values[5]
                        if segment_type == 0x6474E551:
                            stack_executable = bool(flags & 0x1)
                        elif segment_type == 3 and 0 < segment_file_size <= 512:
                            location = offset + int(segment_file_offset)
                            if location + int(segment_file_size) <= file_size:
                                current = stream.tell()
                                stream.seek(location)
                                interpreter = stream.read(int(segment_file_size)).split(b"\x00", 1)[0].decode(
                                    "utf-8", errors="replace"
                                )
                                stream.seek(current)
            return {
                "path": relative_path,
                "offset": offset,
                "bits": bits,
                "endianness": encoding,
                "machine": _ELF_MACHINES.get(machine, f"ELF machine {machine}"),
                "type": {2: "executable", 3: "shared-or-pie"}.get(elf_type, f"type-{elf_type}"),
                "position_independent": elf_type == 3,
                "stack_executable": stack_executable,
                "interpreter": interpreter,
            }
    except (OSError, struct.error, IndexError):
        return None


def analyze_firmware_deep(
    root: Path,
    project_id: str,
    firmware_summary: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    """Return deep-pass metadata, public findings, and private evidence."""
    findings: list[dict[str, Any]] = []
    private_evidence: list[dict[str, str]] = []
    components: list[dict[str, Any]] = []
    elf_objects: list[dict[str, Any]] = []
    seen_components: set[tuple[str, str, str]] = set()
    seen_matches: set[tuple[str, str, int]] = set()
    images_scanned = 0
    bytes_covered = 0

    indicator_rules = [rule for rule in FIRMWARE_RULES if "pattern" in rule]
    elf_stack_rule = next(rule for rule in FIRMWARE_RULES if rule["id"] == "firmware.elf-executable-stack")
    elf_pie_rule = next(rule for rule in FIRMWARE_RULES if rule["id"] == "firmware.elf-non-pie")

    for image in firmware_summary.get("images", []):
        if not isinstance(image, dict) or not isinstance(image.get("path"), str):
            continue
        relative_path = str(image["path"])
        path = _safe_image_path(root, relative_path)
        if path is None:
            continue
        images_scanned += 1
        bytes_covered += int(image.get("scan_bytes") or 0)
        per_rule_counts: dict[str, int] = {}
        size = path.stat(follow_symlinks=False).st_size
        for base_offset, data in _iter_chunks(path, size):
            for rule in indicator_rules:
                if len(findings) >= MAX_DEEP_FINDINGS:
                    break
                rule_id = str(rule["id"])
                if per_rule_counts.get(rule_id, 0) >= MAX_MATCHES_PER_RULE_IMAGE:
                    continue
                pattern = rule["pattern"]
                for match in pattern.finditer(data):
                    absolute = max(0, base_offset + match.start())
                    match_key = (rule_id, relative_path, absolute)
                    if match_key in seen_matches:
                        continue
                    seen_matches.add(match_key)
                    exact = _exact_private_evidence(data, match.start(), rule_id)
                    public, private = _finding(
                        project_id, rule, relative_path, absolute, exact
                    )
                    findings.append(public)
                    private_evidence.append(private)
                    per_rule_counts[rule_id] = per_rule_counts.get(rule_id, 0) + 1
                    if per_rule_counts[rule_id] >= MAX_MATCHES_PER_RULE_IMAGE:
                        break

            if len(components) < MAX_COMPONENTS:
                for component_name, pattern in _COMPONENT_PATTERNS:
                    for match in pattern.finditer(data):
                        version = match.group(1).decode("ascii", errors="ignore")
                        component_key = (component_name, version, relative_path)
                        if not version or component_key in seen_components:
                            continue
                        seen_components.add(component_key)
                        components.append({
                            "name": component_name,
                            "version": version,
                            "path": relative_path,
                            "offset": max(0, base_offset + match.start()),
                        })
                        if len(components) >= MAX_COMPONENTS:
                            break

        for embedded_format in image.get("embedded_formats", []):
            if not isinstance(embedded_format, dict) or embedded_format.get("name") != "ELF executable":
                continue
            for raw_offset in embedded_format.get("offsets", []):
                if len(elf_objects) >= MAX_ELF_OBJECTS:
                    break
                try:
                    offset = int(raw_offset)
                except (TypeError, ValueError):
                    continue
                elf = _parse_elf(path, offset, relative_path)
                if elf is None:
                    continue
                elf_objects.append(elf)
                if (
                    elf["stack_executable"] is True
                    and len(findings) < MAX_DEEP_FINDINGS
                ):
                    public, private = _finding(
                        project_id,
                        elf_stack_rule,
                        relative_path,
                        offset,
                        "ELF PT_GNU_STACK flags include PF_X (executable stack)",
                    )
                    findings.append(public)
                    private_evidence.append(private)
                if (
                    elf["type"] == "executable"
                    and elf["position_independent"] is False
                    and len(findings) < MAX_DEEP_FINDINGS
                ):
                    public, private = _finding(
                        project_id,
                        elf_pie_rule,
                        relative_path,
                        offset,
                        "ELF type ET_EXEC (not position independent)",
                    )
                    findings.append(public)
                    private_evidence.append(private)

    return (
        {
            "status": "complete",
            "engine": "aegis-firmware-deep-v1",
            "images_scanned": images_scanned,
            "bytes_covered": bytes_covered,
            "binary_scan_coverage": firmware_summary.get("binary_scan_coverage", "unknown"),
            "indicator_rules_checked": len(indicator_rules) + 2,
            "security_indicators": len(findings),
            "security_indicators_truncated": len(findings) >= MAX_DEEP_FINDINGS,
            "components": components,
            "components_truncated": len(components) >= MAX_COMPONENTS,
            "elf_objects": elf_objects,
            "elf_objects_truncated": len(elf_objects) >= MAX_ELF_OBJECTS,
            "extractors": {
                "unblob": {"available": shutil.which("unblob") is not None, "executed": False},
                "binwalk": {"available": shutil.which("binwalk") is not None, "executed": False},
                "unsquashfs": {"available": shutil.which("unsquashfs") is not None, "executed": False},
            },
            "limitations": [
                "Only uncompressed bytes in the reported full or sampled ranges were inspected.",
                "Component version strings are inventory clues and were not matched to vulnerabilities.",
                "External extractors were detected but not executed inside the desktop process.",
            ],
        },
        findings,
        private_evidence,
    )
