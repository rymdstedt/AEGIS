"""Read-only firmware recognition and bounded binary inventory.

This module never executes, mounts, or loads code from an imported image.  It
only reads bytes from the private AEGIS snapshot and records bounded format and
vendor hints.  Proprietary containers remain explicitly unextracted until a
separately isolated extractor is available.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Iterable

FIRMWARE_SUFFIXES = {
    ".bin",
    ".chk",
    ".elf",
    ".firmware",
    ".fls",
    ".fw",
    ".img",
    ".rom",
    ".squashfs",
    ".trx",
    ".ubi",
}
TAR_FAMILY_ENDINGS = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
)

MAX_FIRMWARE_CANDIDATES = 64
MAX_SEQUENTIAL_SCAN_BYTES = 512 * 1024 * 1024
LARGE_IMAGE_SAMPLE_WINDOW = 32 * 1024 * 1024
SCAN_CHUNK_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_OFFSETS = 12
MAX_PACKAGE_REFERENCES = 256

_CISCO_FILENAME = re.compile(
    r"(?i)(?:"
    r"cat\d+[a-z0-9_-]*_iosxe|"
    r"cat\d+[a-z0-9_-]*|"
    r"c\d{4,}[a-z0-9_-]*-(?:lanbase|lanlite|ipbase|ipservices|universalk9)|"
    r"cat3k_caa-universalk9|"
    r"(?:asr|csr|isr|ie)\d+[a-z0-9_-]*|"
    r"universalk9|lanbasek9|lanlitek9|ipbasek9|ipservicesk9|iosxe"
    r")"
)
_CISCO_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"cisco ios xe software", "Cisco IOS XE software marker"),
    (b"cisco ios software", "Cisco IOS software marker"),
    (b"cisco systems", "Cisco Systems marker"),
    (b"ios-xe", "IOS-XE marker"),
    (b"packages.conf", "IOS XE packages.conf marker"),
    (b"cat9k_iosxe", "Catalyst IOS XE image marker"),
    (b"universalk9", "Cisco universal image marker"),
)
_VERSION_PATTERNS = (
    re.compile(
        rb"(?i)Cisco IOS XE Software[^\r\n]{0,120}?\bVersion\s+"
        rb"([A-Za-z0-9][A-Za-z0-9()._-]{1,31})"
    ),
    re.compile(
        rb"(?i)Cisco IOS Software[^\r\n]{0,160}?\bVersion\s+"
        rb"([A-Za-z0-9][A-Za-z0-9()._-]{1,31})"
    ),
)
_FILENAME_VERSION = re.compile(
    r"(?i)(?:iosxe|universalk9)[._-]"
    r"([0-9]{2}\.[0-9]{1,2}\.[0-9A-Za-z()_-]{1,24})"
)
_CISCO_PACKAGE_VERSION = re.compile(
    r"(?i)(?:cat\d+[a-z0-9_-]*|(?:asr|csr|isr|ie)\d+[a-z0-9_-]*)\."
    r"([0-9]{2}\.[0-9]{1,2}\.[0-9A-Za-z()_-]{1,24})(?:\.|$)"
)
_PACKAGE_REFERENCE = re.compile(
    rb"(?i)([A-Za-z0-9][A-Za-z0-9._/-]{1,255}\.pkg)\b"
)

_MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"hsqs", "SquashFS filesystem"),
    (b"sqsh", "SquashFS filesystem (big-endian)"),
    (b"UBI#", "UBI erase-count header"),
    (b"\x45\x3d\xcd\x28", "CramFS filesystem"),
    (b"\x28\xcd\x3d\x45", "CramFS filesystem (big-endian)"),
    (b"\x27\x05\x19\x56", "U-Boot uImage"),
    (b"\xd0\x0d\xfe\xed", "Flattened device tree / FIT image"),
    (b"\x7fELF", "ELF executable"),
    (b"070701", "CPIO newc archive"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"\xfd7zXZ\x00", "XZ stream"),
    (b"PK\x03\x04", "ZIP archive"),
)
_FIRMWARE_CONTAINER_MAGICS = tuple(
    signature for signature, label in _MAGIC_SIGNATURES
    if any(token in label for token in ("SquashFS", "UBI ", "CramFS", "U-Boot", "device tree"))
)


def is_tar_family_name(name: str) -> bool:
    return name.casefold().endswith(TAR_FAMILY_ENDINGS)


def is_cisco_firmware_name(name: str) -> bool:
    lowered = name.casefold()
    if lowered == "packages.conf":
        return True
    supported_name = (
        lowered.endswith(tuple(FIRMWARE_SUFFIXES))
        or lowered.endswith(".pkg")
        or is_tar_family_name(lowered)
    )
    return supported_name and bool(_CISCO_FILENAME.search(lowered))


def is_firmware_candidate_name(name: str) -> bool:
    lowered = name.casefold()
    return (
        lowered == "packages.conf"
        or lowered.endswith(tuple(FIRMWARE_SUFFIXES))
        or lowered.endswith(".pkg")
        or is_tar_family_name(lowered)
    )


def _bounded_edge_bytes(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    """Read small leading/trailing regions for intake-time classification."""
    try:
        size = path.stat(follow_symlinks=False).st_size
        with path.open("rb") as stream:
            leading = stream.read(maximum // 2)
            if size <= maximum:
                return leading
            stream.seek(max(0, size - maximum // 2))
            return leading + stream.read(maximum // 2)
    except OSError:
        return b""


def classify_firmware_path(path: Path) -> str | None:
    """Return a conservative firmware artifact kind, or ``None``."""
    name = path.name.casefold()
    sample = _bounded_edge_bytes(path)
    lowered = sample.lower()
    cisco_content = any(marker in lowered for marker, _label in _CISCO_MARKERS)
    cisco_name = is_cisco_firmware_name(name)

    if cisco_name or cisco_content:
        if is_tar_family_name(name):
            return "cisco_ios_firmware_bundle"
        if name == "packages.conf":
            return "cisco_ios_xe_provisioning"
        if name.endswith(".pkg"):
            return "cisco_ios_xe_package"
        return "cisco_ios_firmware"

    header = sample[:8]
    known_magic = any(signature in sample for signature in _FIRMWARE_CONTAINER_MAGICS)
    if path.suffix.casefold() in FIRMWARE_SUFFIXES or known_magic:
        if header.startswith(b"\x7fELF"):
            return None
        return "firmware_image"
    return None


def _candidate_paths(root: Path, artifact_kind: str) -> tuple[list[Path], int]:
    if root.is_file():
        return ([root], 0) if (
            "firmware" in artifact_kind or classify_firmware_path(root)
        ) else ([], 0)

    candidates: list[Path] = []
    truncated = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            item for item in directories
            if not (Path(current) / item).is_symlink()
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_symlink() or not path.is_file():
                continue
            if not is_firmware_candidate_name(filename):
                continue
            if classify_firmware_path(path) is None:
                continue
            if len(candidates) >= MAX_FIRMWARE_CANDIDATES:
                truncated += 1
                continue
            candidates.append(path)
    return candidates, truncated


def _scan_ranges(size: int) -> list[tuple[int, int]]:
    if size <= MAX_SEQUENTIAL_SCAN_BYTES:
        return [(0, size)]
    window = min(LARGE_IMAGE_SAMPLE_WINDOW, size)
    ranges = [
        (0, window),
        (max(0, (size // 2) - (window // 2)), window),
        (max(0, size - window), window),
    ]
    merged: list[tuple[int, int]] = []
    for start, length in sorted(ranges):
        end = min(size, start + length)
        if merged and start <= merged[-1][0] + merged[-1][1]:
            previous_start, previous_length = merged[-1]
            merged[-1] = (previous_start, max(previous_start + previous_length, end) - previous_start)
        else:
            merged.append((start, end - start))
    return merged


def _iter_chunks(path: Path, size: int) -> Iterable[tuple[int, bytes]]:
    overlap_size = max(
        max(len(signature) for signature, _label in _MAGIC_SIGNATURES),
        max(len(marker) for marker, _label in _CISCO_MARKERS),
        256,
    )
    with path.open("rb") as stream:
        for range_start, range_length in _scan_ranges(size):
            stream.seek(range_start)
            remaining = range_length
            previous = b""
            cursor = range_start
            while remaining > 0:
                chunk = stream.read(min(SCAN_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                yield cursor - len(previous), previous + chunk
                cursor += len(chunk)
                remaining -= len(chunk)
                previous = chunk[-overlap_size:]


def _entropy(counts: list[int], total: int) -> float:
    if total <= 0:
        return 0.0
    result = 0.0
    for count in counts:
        if count:
            probability = count / total
            result -= probability * math.log2(probability)
    return round(result, 3)


def _scan_candidate(path: Path, relative_path: str) -> dict[str, object]:
    size = path.stat(follow_symlinks=False).st_size
    signatures: dict[str, list[int]] = {}
    markers: set[str] = set()
    versions: set[str] = set()
    byte_counts = [0] * 256
    entropy_bytes = 0
    content_digest = hashlib.sha256()
    hashed_end = 0
    package_references: set[str] = set()
    scanned_ranges = _scan_ranges(size)
    scanned_bytes = sum(length for _start, length in scanned_ranges)

    for base_offset, data in _iter_chunks(path, size):
        unique_start = max(0, hashed_end - base_offset)
        if unique_start < len(data):
            content_digest.update(data[unique_start:])
            hashed_end = max(hashed_end, base_offset + len(data))
        lowered = data.lower()
        for marker, label in _CISCO_MARKERS:
            if marker in lowered:
                markers.add(label)
        for pattern in _VERSION_PATTERNS:
            for match in pattern.finditer(data):
                versions.add(match.group(1).decode("ascii", errors="ignore"))
        if path.name.casefold() == "packages.conf":
            for match in _PACKAGE_REFERENCE.finditer(data):
                if len(package_references) >= MAX_PACKAGE_REFERENCES:
                    break
                package_references.add(
                    match.group(1).decode("utf-8", errors="replace")
                )
        for signature, label in _MAGIC_SIGNATURES:
            offsets = signatures.setdefault(label, [])
            search_from = 0
            while len(offsets) < MAX_SIGNATURE_OFFSETS:
                position = data.find(signature, search_from)
                if position < 0:
                    break
                absolute = max(0, base_offset + position)
                if absolute not in offsets:
                    offsets.append(absolute)
                search_from = position + 1
        if entropy_bytes < 1024 * 1024:
            entropy_sample = data[: (1024 * 1024) - entropy_bytes]
            for value in entropy_sample:
                byte_counts[value] += 1
            entropy_bytes += len(entropy_sample)

    filename_version = _FILENAME_VERSION.search(path.name)
    if filename_version:
        versions.add(filename_version.group(1).rstrip("."))
    package_version = _CISCO_PACKAGE_VERSION.search(path.name)
    if package_version:
        versions.add(package_version.group(1).rstrip("."))
    artifact_kind = classify_firmware_path(path) or "firmware_image"
    scan_complete = scanned_bytes >= size
    return {
        "path": relative_path,
        "artifact_kind": artifact_kind,
        "size_bytes": size,
        "scan_bytes": min(size, scanned_bytes),
        "scan_complete": scan_complete,
        "sha256": content_digest.hexdigest() if scan_complete else None,
        "sample_entropy_bits_per_byte": _entropy(byte_counts, entropy_bytes),
        "vendor_markers": sorted(markers),
        "versions": sorted(value for value in versions if value),
        "package_references": sorted(package_references),
        "package_references_truncated": len(package_references) >= MAX_PACKAGE_REFERENCES,
        "embedded_formats": [
            {"name": label, "offsets": sorted(offsets)}
            for label, offsets in sorted(signatures.items())
            if offsets
        ],
    }


def analyze_firmware_snapshot(
    root: Path,
    artifact_kind: str,
) -> dict[str, object] | None:
    """Describe firmware candidates in a snapshot without executing them."""
    candidates, candidates_truncated = _candidate_paths(root, artifact_kind)
    if not candidates:
        return None

    records: list[dict[str, object]] = []
    for path in candidates:
        try:
            relative = path.name if root.is_file() else path.relative_to(root).as_posix()
            records.append(_scan_candidate(path, relative))
        except OSError:
            continue
    if not records:
        return None

    marker_text = " ".join(
        str(marker)
        for record in records
        for marker in record.get("vendor_markers", [])
    ).casefold()
    name_text = " ".join(str(record["path"]) for record in records).casefold()
    is_cisco = (
        "cisco" in marker_text
        or "ios xe" in marker_text
        or any(is_cisco_firmware_name(str(record["path"])) for record in records)
    )
    is_ios_xe = is_cisco and (
        "ios xe" in marker_text
        or "ios-xe" in marker_text
        or "iosxe" in name_text
        or "packages.conf" in name_text
        or any("_package" in str(record["artifact_kind"]) for record in records)
    )
    versions = sorted({
        str(version)
        for record in records
        for version in record.get("versions", [])
    })
    embedded_formats = sorted({
        str(item["name"])
        for record in records
        for item in record.get("embedded_formats", [])
        if isinstance(item, dict) and item.get("name")
    })
    package_references = sorted({
        str(reference)
        for record in records
        for reference in record.get("package_references", [])
    })
    available_package_names = {
        Path(str(record["path"])).name.casefold()
        for record in records
        if str(record["path"]).casefold().endswith(".pkg")
    }
    missing_package_references = sorted(
        reference for reference in package_references
        if Path(reference).name.casefold() not in available_package_names
    )
    return {
        "recognized": True,
        "assessment_scope": "firmware_structure_and_metadata_triage",
        "vendor": "Cisco" if is_cisco else "Unknown",
        "platform_family": (
            "Cisco IOS XE" if is_ios_xe else "Cisco IOS" if is_cisco else "Generic firmware"
        ),
        "versions": versions,
        "candidate_files": len(records),
        "candidates_truncated": candidates_truncated,
        "binary_scan_coverage": (
            "complete" if all(bool(record["scan_complete"]) for record in records)
            else "sampled"
        ),
        "embedded_formats": embedded_formats,
        "package_references": package_references,
        "missing_package_references": missing_package_references,
        "images": records,
        "authenticity": "not_verified_offline",
        "advisory_lookup_performed": False,
        "signature_verification_performed": False,
        "artifact_executed": False,
        "notes": [
            "Vendor and version values are local byte/filename hints, not an authenticity guarantee.",
            "AEGIS did not boot, mount, or execute this firmware.",
            "Proprietary or encrypted image regions may require an isolated firmware extractor before deeper analysis.",
        ],
    }
