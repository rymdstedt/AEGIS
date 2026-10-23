"""Hostile-artifact intake for local application research.

The routines here copy inputs without executing them, do not follow symbolic
links, and extract ZIP-family containers entry-by-entry with explicit limits.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tarfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .firmware import classify_firmware_path, is_tar_family_name


class IntakeError(ValueError):
    """The selected artifact could not be imported safely."""


class IntakeLimitError(IntakeError):
    """An intake quota was exceeded."""


@dataclass(frozen=True)
class IntakeLimits:
    # These are safety ceilings, not analyzer batch sizes. Analysis itself is
    # streaming and keeps one logical project even for multi-gigabyte inputs.
    max_single_file_bytes: int = 8 * 1024 * 1024 * 1024
    max_directory_files: int = 100_000
    max_directory_bytes: int = 8 * 1024 * 1024 * 1024
    max_archive_entries: int = 50_000
    max_archive_uncompressed_bytes: int = 8 * 1024 * 1024 * 1024
    max_archive_entry_bytes: int = 2 * 1024 * 1024 * 1024
    max_archive_ratio: int = 250


ZIP_FAMILY_SUFFIXES = {".zip", ".apk", ".ipa", ".jar", ".aab"}
EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
WINDOWS_RESERVED_NAMES = {
    "aux", "clock$", "con", "nul", "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


def _display_name(value: str) -> str:
    cleaned = "".join(character for character in value if character.isprintable()).strip()
    return (cleaned or "Untitled artifact")[:160]


def _human_size(value: int) -> str:
    amount = float(max(0, value))
    for unit in ("bytes", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "bytes" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} bytes"


def _limit_profile(limits: IntakeLimits) -> dict[str, int]:
    return {
        "max_single_file_bytes": limits.max_single_file_bytes,
        "max_directory_files": limits.max_directory_files,
        "max_directory_bytes": limits.max_directory_bytes,
        "max_archive_entries": limits.max_archive_entries,
        "max_archive_uncompressed_bytes": limits.max_archive_uncompressed_bytes,
        "max_archive_entry_bytes": limits.max_archive_entry_bytes,
        "max_archive_ratio": limits.max_archive_ratio,
    }


def _artifact_filename(source: Path) -> str:
    # Retain the leaf name inside AEGIS-owned private storage. Path-sensitive
    # analyzers need names such as `.env.production`, while the original parent
    # directory is never stored in a public record or returned to the renderer.
    candidate = "".join(
        character
        if character.isprintable() and character not in {"/", "\\", ":", "\x00"}
        else "_"
        for character in source.name
    ).strip()
    reserved = candidate.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
    if (
        candidate not in {"", ".", ".."}
        and len(candidate) <= 255
        and not candidate.endswith((" ", "."))
        and not reserved
    ):
        return candidate
    suffixes = "".join(source.suffixes[-2:])
    if not suffixes or len(suffixes) > 24 or not re.fullmatch(r"[A-Za-z0-9._+-]+", suffixes):
        suffixes = ".bin"
    return f"original{suffixes.lower()}"


def _sha256_stream(stream: BinaryIO, destination: BinaryIO | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
    return digest.hexdigest(), total


def _copy_regular_file(source: Path, destination: Path, maximum: int) -> tuple[str, int]:
    try:
        source_info = source.lstat()
    except OSError as exc:
        raise IntakeError("The selected file cannot be read") from exc
    if not stat.S_ISREG(source_info.st_mode):
        raise IntakeError("Only regular files can be imported")
    if source_info.st_size > maximum:
        raise IntakeLimitError(
            f"The selected file exceeds the {_human_size(maximum)} intake ceiling"
        )

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise IntakeError("The selected file could not be opened safely") from exc

    try:
        opened_info = os.fstat(descriptor)
        if not stat.S_ISREG(opened_info.st_mode):
            raise IntakeError("The selected artifact changed during intake")
        if hasattr(source_info, "st_ino") and (
            source_info.st_ino != opened_info.st_ino
            or source_info.st_dev != opened_info.st_dev
        ):
            raise IntakeError("The selected artifact changed during intake")
        with os.fdopen(descriptor, "rb", closefd=False) as input_stream:
            with destination.open("xb") as output_stream:
                digest, copied = _sha256_stream(input_stream, output_stream)
        if copied != opened_info.st_size or copied > maximum:
            destination.unlink(missing_ok=True)
            raise IntakeError("The selected artifact changed size during intake")
        destination.chmod(stat.S_IRUSR)
        return digest, copied
    finally:
        os.close(descriptor)


def _classify_file(path: Path) -> str:
    suffix = path.suffix.lower()
    try:
        with path.open("rb") as stream:
            header = stream.read(512)
    except OSError:
        return "unknown_file"

    firmware_kind = classify_firmware_path(path)
    if firmware_kind and firmware_kind.startswith("cisco_"):
        return firmware_kind
    if suffix in ZIP_FAMILY_SUFFIXES:
        return {
            ".apk": "android_package",
            ".ipa": "ios_package",
            ".jar": "java_archive",
            ".aab": "android_bundle",
        }.get(suffix, "zip_archive")
    if header.startswith(b"PK\x03\x04"):
        return "zip_archive"
    if is_tar_family_name(path.name) or header[257:262] == b"ustar":
        return "tar_archive"
    if suffix in {".exe", ".dll", ".sys", ".msi"} or header.startswith(b"MZ"):
        return "windows_binary"
    if suffix == ".dmg":
        return "macos_disk_image"
    if suffix == ".pkg" and header.startswith(b"xar!"):
        return "macos_installer"
    if header.startswith(b"\x7fELF"):
        return "elf_binary"
    if header[:4] in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    }:
        return "mach_o_binary"
    if firmware_kind:
        return firmware_kind
    if suffix == ".pkg":
        return "package_file"
    return "source_file" if suffix in {
        ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java",
        ".js", ".jsx", ".kt", ".kts", ".m", ".mm", ".php", ".pl",
        ".ps1", ".py", ".rb", ".rs", ".sh", ".swift", ".ts", ".tsx",
    } else "unknown_file"


def _safe_archive_member(filename: str) -> PurePosixPath | None:
    normalized = filename.replace("\\", "/")
    if "\x00" in normalized or normalized.startswith("/") or len(normalized) > 4096:
        return None
    path = PurePosixPath(normalized)
    if (
        not path.parts
        or len(path.parts) > 64
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    for part in path.parts:
        if (
            len(part) > 255
            or not part.isprintable()
            or ":" in part
            or part.endswith((" ", "."))
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
        ):
            return None
    return path


def _extract_zip_safely(
    archive: Path,
    snapshot: Path,
    limits: IntakeLimits,
) -> tuple[int, int, list[dict[str, str]]]:
    warnings: list[dict[str, str]] = []
    extracted_files = 0
    extracted_bytes = 0
    seen: set[str] = set()
    snapshot.mkdir(parents=True, exist_ok=False, mode=0o700)

    try:
        container = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise IntakeError("The selected ZIP-family artifact is invalid") from exc

    with container:
        entries = container.infolist()
        if len(entries) > limits.max_archive_entries:
            raise IntakeLimitError(
                "The archive exceeds the "
                f"{limits.max_archive_entries:,}-entry extraction ceiling"
            )

        approved: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        declared_total = 0
        for entry in entries:
            relative = _safe_archive_member(entry.filename)
            if relative is None:
                warnings.append({"entry": "[unsafe path]", "reason": "path rejected"})
                continue
            relative_text = relative.as_posix()
            collision_key = unicodedata.normalize("NFC", relative_text).casefold()
            unix_mode = (entry.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(unix_mode):
                warnings.append({"entry": relative_text[:240], "reason": "symbolic link skipped"})
                continue
            file_type = stat.S_IFMT(unix_mode)
            if file_type and not (stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode)):
                warnings.append({"entry": relative_text[:240], "reason": "special file skipped"})
                continue
            if entry.flag_bits & 0x1:
                warnings.append({"entry": relative_text[:240], "reason": "encrypted entry skipped"})
                continue
            if collision_key in seen:
                warnings.append({"entry": relative_text[:240], "reason": "duplicate path skipped"})
                continue
            seen.add(collision_key)
            if entry.is_dir():
                approved.append((entry, relative))
                continue
            if entry.file_size > limits.max_archive_entry_bytes:
                raise IntakeLimitError(
                    "An archive entry exceeds the "
                    f"{_human_size(limits.max_archive_entry_bytes)} per-file ceiling"
                )
            if entry.file_size > 1024 * 1024:
                ratio = entry.file_size / max(1, entry.compress_size)
                if ratio > limits.max_archive_ratio:
                    raise IntakeLimitError("The archive has a suspicious compression ratio")
            declared_total += entry.file_size
            if declared_total > limits.max_archive_uncompressed_bytes:
                raise IntakeLimitError(
                    "The archive exceeds the "
                    f"{_human_size(limits.max_archive_uncompressed_bytes)} "
                    "expanded-size ceiling"
                )
            approved.append((entry, relative))

        for entry, relative in approved:
            target = snapshot.joinpath(*relative.parts)
            try:
                target.relative_to(snapshot)
            except ValueError as exc:
                raise IntakeError("An archive entry escaped the snapshot directory") from exc
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            entry_bytes = 0
            try:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with container.open(entry, "r") as input_stream, target.open("xb") as output_stream:
                    while True:
                        chunk = input_stream.read(1024 * 1024)
                        if not chunk:
                            break
                        entry_bytes += len(chunk)
                        extracted_bytes += len(chunk)
                        if entry_bytes > limits.max_archive_entry_bytes:
                            raise IntakeLimitError("An archive entry exceeded its extraction limit")
                        if extracted_bytes > limits.max_archive_uncompressed_bytes:
                            raise IntakeLimitError("The archive exceeded its extraction limit")
                        output_stream.write(chunk)
            except IntakeLimitError:
                raise
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise IntakeError("The archive contains conflicting paths") from exc
            target.chmod(stat.S_IRUSR)
            extracted_files += 1
    return extracted_files, extracted_bytes, warnings


def _extract_tar_safely(
    archive: Path,
    snapshot: Path,
    limits: IntakeLimits,
) -> tuple[int, int, list[dict[str, str]]]:
    """Extract regular TAR members without links, devices, or path traversal."""
    warnings: list[dict[str, str]] = []
    extracted_files = 0
    extracted_bytes = 0
    seen: set[str] = set()
    snapshot.mkdir(parents=True, exist_ok=False, mode=0o700)

    try:
        container = tarfile.open(archive, mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        raise IntakeError("The selected TAR-family artifact is invalid") from exc

    with container:
        approved: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        declared_total = 0
        entry_count = 0
        for entry in container:
            entry_count += 1
            if entry_count > limits.max_archive_entries:
                raise IntakeLimitError(
                    "The archive exceeds the "
                    f"{limits.max_archive_entries:,}-entry extraction ceiling"
                )
            relative = _safe_archive_member(entry.name)
            if relative is None:
                warnings.append({"entry": "[unsafe path]", "reason": "path rejected"})
                continue
            relative_text = relative.as_posix()
            collision_key = unicodedata.normalize("NFC", relative_text).casefold()
            if entry.issym() or entry.islnk():
                warnings.append({
                    "entry": relative_text[:240],
                    "reason": "symbolic or hard link skipped",
                })
                continue
            if not (entry.isfile() or entry.isdir()):
                warnings.append({
                    "entry": relative_text[:240],
                    "reason": "special file skipped",
                })
                continue
            if collision_key in seen:
                warnings.append({
                    "entry": relative_text[:240],
                    "reason": "duplicate path skipped",
                })
                continue
            seen.add(collision_key)
            if entry.isdir():
                approved.append((entry, relative))
                continue
            if entry.size > limits.max_archive_entry_bytes:
                raise IntakeLimitError(
                    "An archive entry exceeds the "
                    f"{_human_size(limits.max_archive_entry_bytes)} per-file ceiling"
                )
            declared_total += entry.size
            if declared_total > limits.max_archive_uncompressed_bytes:
                raise IntakeLimitError(
                    "The archive exceeds the "
                    f"{_human_size(limits.max_archive_uncompressed_bytes)} "
                    "expanded-size ceiling"
                )
            approved.append((entry, relative))

        try:
            archive_size = max(1, archive.stat(follow_symlinks=False).st_size)
        except OSError as exc:
            raise IntakeError("The TAR artifact changed during intake") from exc
        if (
            declared_total > 1024 * 1024
            and declared_total / archive_size > limits.max_archive_ratio
        ):
            raise IntakeLimitError("The archive has a suspicious compression ratio")

        for entry, relative in approved:
            target = snapshot.joinpath(*relative.parts)
            try:
                target.relative_to(snapshot)
            except ValueError as exc:
                raise IntakeError("An archive entry escaped the snapshot directory") from exc
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            input_stream = container.extractfile(entry)
            if input_stream is None:
                raise IntakeError("A TAR member could not be read")
            entry_bytes = 0
            try:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with input_stream, target.open("xb") as output_stream:
                    while True:
                        chunk = input_stream.read(1024 * 1024)
                        if not chunk:
                            break
                        entry_bytes += len(chunk)
                        extracted_bytes += len(chunk)
                        if entry_bytes > limits.max_archive_entry_bytes:
                            raise IntakeLimitError(
                                "An archive entry exceeded its extraction limit"
                            )
                        if extracted_bytes > limits.max_archive_uncompressed_bytes:
                            raise IntakeLimitError(
                                "The archive exceeded its extraction limit"
                            )
                        output_stream.write(chunk)
            except IntakeLimitError:
                raise
            except (OSError, EOFError, tarfile.TarError) as exc:
                raise IntakeError("The TAR archive contains conflicting data") from exc
            if entry_bytes != entry.size:
                raise IntakeError("A TAR member changed size during extraction")
            target.chmod(stat.S_IRUSR)
            extracted_files += 1
    return extracted_files, extracted_bytes, warnings


def _snapshot_directory(
    source: Path,
    snapshot: Path,
    limits: IntakeLimits,
) -> tuple[str, int, int, list[dict[str, str]]]:
    try:
        source_info = source.lstat()
    except OSError as exc:
        raise IntakeError("The selected directory cannot be read") from exc
    if not stat.S_ISDIR(source_info.st_mode):
        raise IntakeError("The selected directory is not a real directory")

    snapshot.mkdir(parents=True, exist_ok=False, mode=0o700)
    manifest_digest = hashlib.sha256()
    total_bytes = 0
    total_files = 0
    warnings: list[dict[str, str]] = []

    def visit(current_source: Path, current_destination: Path, relative_root: Path) -> None:
        nonlocal total_bytes, total_files
        try:
            entries = sorted(os.scandir(current_source), key=lambda item: item.name.casefold())
        except OSError:
            warnings.append({"entry": relative_root.as_posix() or ".", "reason": "unreadable directory skipped"})
            return
        for entry in entries:
            relative = relative_root / entry.name
            relative_text = relative.as_posix()
            try:
                if entry.is_symlink():
                    warnings.append({"entry": relative_text[:240], "reason": "symbolic link skipped"})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() in EXCLUDED_DIRECTORIES:
                        warnings.append({"entry": relative_text[:240], "reason": "generated/dependency directory excluded"})
                        continue
                    child_destination = current_destination / entry.name
                    child_destination.mkdir(mode=0o700)
                    visit(Path(entry.path), child_destination, relative)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    warnings.append({"entry": relative_text[:240], "reason": "non-regular file skipped"})
                    continue
                size = entry.stat(follow_symlinks=False).st_size
                if total_files + 1 > limits.max_directory_files:
                    raise IntakeLimitError(
                        "The selected directory exceeds the "
                        f"{limits.max_directory_files:,}-file project ceiling"
                    )
                if total_bytes + size > limits.max_directory_bytes:
                    raise IntakeLimitError(
                        "The selected directory exceeds the "
                        f"{_human_size(limits.max_directory_bytes)} project ceiling"
                    )
                digest, copied = _copy_regular_file(
                    Path(entry.path), current_destination / entry.name,
                    limits.max_single_file_bytes,
                )
                total_files += 1
                total_bytes += copied
                manifest_digest.update(relative_text.encode("utf-8", errors="surrogateescape"))
                manifest_digest.update(b"\x00")
                manifest_digest.update(digest.encode("ascii"))
                manifest_digest.update(b"\n")
            except IntakeLimitError:
                raise
            except OSError:
                warnings.append({"entry": relative_text[:240], "reason": "unreadable entry skipped"})

    visit(source, snapshot, Path())
    return manifest_digest.hexdigest(), total_bytes, total_files, warnings


def import_artifact(
    source_path: str,
    project_id: str,
    project_directory: Path,
    limits: IntakeLimits | None = None,
) -> dict[str, object]:
    """Copy one operator-selected file or directory into a private project."""
    limits = limits or IntakeLimits()
    if not source_path or "\x00" in source_path:
        raise IntakeError("A valid artifact path is required")
    source = Path(source_path).expanduser()
    if not source.is_absolute():
        raise IntakeError("Artifact paths must be absolute")
    if project_directory.exists():
        raise IntakeError("The destination project already exists")
    project_directory.mkdir(parents=True, mode=0o700)

    if source.is_symlink():
        raise IntakeError("Symbolic-link selections are not accepted")
    if source.is_dir():
        snapshot = project_directory / "snapshot"
        digest, size, file_count, warnings = _snapshot_directory(source, snapshot, limits)
        return {
            "id": project_id,
            "name": _display_name(source.name),
            "source_type": "directory",
            "artifact_kind": "macos_app_bundle"
            if source.suffix.casefold() == ".app"
            else "source_directory",
            "sha256": digest,
            "size_bytes": size,
            "artifact_relpath": "snapshot",
            "snapshot_relpath": "snapshot",
            "metadata": {
                "copied_files": file_count,
                "extracted_files": 0,
                "warnings": warnings[:200],
                "truncated_warnings": max(0, len(warnings) - 200),
                "executed": False,
                "limits": _limit_profile(limits),
            },
        }
    if not source.is_file():
        raise IntakeError("The selected artifact does not exist or is not a regular file")

    artifact_directory = project_directory / "artifact"
    artifact_directory.mkdir(mode=0o700)
    artifact = artifact_directory / _artifact_filename(source)
    digest, size = _copy_regular_file(source, artifact, limits.max_single_file_bytes)
    artifact_kind = _classify_file(artifact)
    snapshot_relpath = artifact.relative_to(project_directory).as_posix()
    metadata: dict[str, object] = {
        "copied_files": 1,
        "extracted_files": 0,
        "warnings": [],
        "truncated_warnings": 0,
        "executed": False,
        "limits": _limit_profile(limits),
    }

    if source.suffix.lower() in ZIP_FAMILY_SUFFIXES or zipfile.is_zipfile(artifact):
        snapshot = project_directory / "snapshot"
        extracted_files, extracted_bytes, warnings = _extract_zip_safely(
            artifact, snapshot, limits
        )
        snapshot_relpath = "snapshot"
        metadata.update({
            "extracted_files": extracted_files,
            "extracted_bytes": extracted_bytes,
            "warnings": warnings[:200],
            "truncated_warnings": max(0, len(warnings) - 200),
        })
    elif is_tar_family_name(source.name) or tarfile.is_tarfile(artifact):
        snapshot = project_directory / "snapshot"
        extracted_files, extracted_bytes, warnings = _extract_tar_safely(
            artifact, snapshot, limits
        )
        snapshot_relpath = "snapshot"
        metadata.update({
            "extracted_files": extracted_files,
            "extracted_bytes": extracted_bytes,
            "warnings": warnings[:200],
            "truncated_warnings": max(0, len(warnings) - 200),
        })

    return {
        "id": project_id,
        "name": _display_name(source.name),
        "source_type": "file",
        "artifact_kind": artifact_kind,
        "sha256": digest,
        "size_bytes": size,
        "artifact_relpath": artifact.relative_to(project_directory).as_posix(),
        "snapshot_relpath": snapshot_relpath,
        "metadata": metadata,
    }
