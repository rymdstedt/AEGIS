"""Read-only OSV dependency analysis and CycloneDX SBOM generation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from agent.risk import enrich_cve_items

MAX_SCANNER_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_COMPONENTS = 10_000
MAX_VULNERABILITIES = 2_000


def find_osv_scanner() -> str | None:
    candidates = [
        shutil.which("osv-scanner"),
        "/opt/homebrew/bin/osv-scanner",
        "/usr/local/bin/osv-scanner",
        str(Path.home() / ".local" / "bin" / "osv-scanner"),
    ]
    if os.name == "nt":
        candidates.extend([
            shutil.which("osv-scanner.exe"),
            str(Path.home() / "scoop" / "shims" / "osv-scanner.exe"),
        ])
    return next(
        (str(path) for path in candidates if path and Path(path).is_file()),
        None,
    )


def _relative_source(source: object, root: Path) -> str:
    raw = Path(str(source or ""))
    source_root = root.parent if root.is_file() else root
    try:
        return raw.resolve().relative_to(source_root.resolve()).as_posix()
    except (OSError, ValueError):
        return raw.name[:500]


def _purl(ecosystem: str, name: str, version: str) -> str:
    types = {
        "pypi": "pypi", "npm": "npm", "go": "golang", "gomod": "golang",
        "maven": "maven", "nuget": "nuget", "crates.io": "cargo",
        "rubygems": "gem", "packagist": "composer", "pub": "pub",
    }
    package_type = types.get(ecosystem.casefold())
    if not package_type or not name:
        return ""
    encoded_name = "/".join(quote(part, safe="._~-@") for part in name.split("/"))
    return f"pkg:{package_type}/{encoded_name}" + (
        f"@{quote(version, safe='._~+-')}" if version else ""
    )


def _severity(score: object, database_value: object = "") -> tuple[str, float | None]:
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        numeric = None
    if numeric is not None:
        return (
            "critical" if numeric >= 9 else "high" if numeric >= 7
            else "medium" if numeric >= 4 else "low",
            numeric,
        )
    value = str(database_value or "").casefold()
    return ({"moderate": "medium"}.get(value, value) if value in {
        "critical", "high", "medium", "moderate", "low"
    } else "medium", None)


def _normalize(payload: object, root: Path, project_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        raise ValueError("OSV-Scanner returned JSON without a results array")
    components: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    seen_components: set[str] = set()
    seen_vulnerabilities: set[tuple[str, str]] = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        source_obj = result.get("source") if isinstance(result.get("source"), dict) else {}
        source = _relative_source(source_obj.get("path"), root)
        for raw_package in result.get("packages") or []:
            if not isinstance(raw_package, dict):
                continue
            package = raw_package.get("package") if isinstance(raw_package.get("package"), dict) else {}
            name = str(package.get("name") or "")[:500]
            version = str(package.get("version") or "")[:200]
            ecosystem = str(package.get("ecosystem") or "")[:100]
            if not name:
                continue
            component_id = hashlib.sha256(
                f"{ecosystem.casefold()}\x00{name.casefold()}\x00{version}\x00{source}".encode()
            ).hexdigest()[:24]
            if component_id not in seen_components and len(components) < MAX_COMPONENTS:
                seen_components.add(component_id)
                groups = raw_package.get("dependency_groups") or raw_package.get("groups") or []
                dependency_groups = [
                    str(value)[:100] for value in groups if isinstance(value, str)
                ]
                components.append({
                    "component_id": component_id,
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "source": source,
                    "source_type": str(source_obj.get("type") or "")[:80],
                    "dependency_groups": dependency_groups[:20],
                    "purl": _purl(ecosystem, name, version),
                })

            raw_vulnerabilities = [
                item for item in raw_package.get("vulnerabilities") or []
                if isinstance(item, dict)
            ]
            by_id = {
                str(item.get("id") or ""): item for item in raw_vulnerabilities
                if item.get("id")
            }
            groups = raw_package.get("groups")
            if not isinstance(groups, list):
                groups = [
                    {"ids": [item.get("id")], "aliases": item.get("aliases") or []}
                    for item in raw_vulnerabilities
                ]
            for group in groups:
                if not isinstance(group, dict) or len(vulnerabilities) >= MAX_VULNERABILITIES:
                    continue
                ids = [str(item) for item in group.get("ids") or [] if item]
                aliases = [str(item) for item in group.get("aliases") or [] if item]
                all_ids = list(dict.fromkeys([*ids, *aliases]))
                canonical = next((item.upper() for item in all_ids if re.fullmatch(r"CVE-\d{4}-\d{4,}", item, re.I)), None)
                canonical = canonical or next((item for item in ids if item), None)
                if not canonical or (component_id, canonical) in seen_vulnerabilities:
                    continue
                seen_vulnerabilities.add((component_id, canonical))
                record = next((by_id[item] for item in ids if item in by_id), {})
                database_specific = record.get("database_specific") if isinstance(record.get("database_specific"), dict) else {}
                severity, score = _severity(group.get("max_severity"), database_specific.get("severity"))
                fixed_versions: list[str] = []
                for affected in record.get("affected") or []:
                    if not isinstance(affected, dict):
                        continue
                    for version_range in affected.get("ranges") or []:
                        if not isinstance(version_range, dict):
                            continue
                        for event in version_range.get("events") or []:
                            if isinstance(event, dict) and event.get("fixed"):
                                fixed_versions.append(str(event["fixed"])[:200])
                references = [
                    str(item.get("url"))[:1000]
                    for item in record.get("references") or []
                    if isinstance(item, dict) and str(item.get("url") or "").startswith("https://")
                ]
                vulnerabilities.append({
                    "id": canonical,
                    "aliases": all_ids[:40],
                    "component_id": component_id,
                    "component": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "source": source,
                    "summary": str(record.get("summary") or record.get("details") or "Known vulnerability in dependency")[:1000],
                    "severity": severity,
                    "cvss": score,
                    "fixed_versions": list(dict.fromkeys(fixed_versions))[:20],
                    "references": list(dict.fromkeys(references))[:12],
                })
    return components, vulnerabilities


def _finding(project_id: str, vulnerability: dict[str, Any]) -> dict[str, Any]:
    identity = "\x00".join((
        project_id,
        str(vulnerability["component_id"]),
        str(vulnerability["id"]),
    ))
    finding_id = "appf_" + hashlib.sha256(identity.encode()).hexdigest()[:20]
    fixed = vulnerability.get("fixed_versions") or []
    remediation = "Update or replace the affected dependency, then regenerate the lockfile and retest."
    if fixed:
        remediation = f"Upgrade to a non-affected release (fixed versions reported by OSV include {', '.join(fixed[:5])}), regenerate the lockfile, and retest."
    risk = "; ".join(vulnerability.get("risk_reasons") or [])
    return {
        "id": finding_id,
        "rule_id": f"dependency.osv.{str(vulnerability['id']).lower()}",
        "severity": vulnerability["severity"],
        "confidence": "high",
        "status": "affected_dependency",
        "title": f"{vulnerability['id']} affects {vulnerability['component']} {vulnerability['version']}",
        "description": (
            f"OSV-Scanner matched the locked {vulnerability['ecosystem']} package "
            f"{vulnerability['component']} {vulnerability['version']} to {vulnerability['id']}. "
            "This confirms an affected dependency version, not reachability or exploitability in this application."
            + (f" Risk context: {risk}." if risk else "")
        ),
        "file_path": vulnerability["source"],
        "line": None,
        "evidence": (
            f"{vulnerability['ecosystem']}:{vulnerability['component']}@{vulnerability['version']} "
            f"in {vulnerability['source']} matched {vulnerability['id']}"
        ),
        "remediation": remediation,
        "vulnerability_id": vulnerability["id"],
        "component_id": vulnerability["component_id"],
    }


def build_cyclonedx(
    project_id: str,
    project_name: str,
    components: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
) -> dict[str, Any]:
    serial = hashlib.sha256(project_id.encode()).hexdigest()
    component_refs: dict[str, str] = {}
    sbom_components = []
    for component in components:
        ref = component.get("purl") or f"urn:aegis:component:{component['component_id']}"
        component_refs[str(component["component_id"])] = ref
        item = {
            "type": "library",
            "bom-ref": ref,
            "name": component["name"],
            "version": component["version"],
            "properties": [
                {"name": "aegis:source", "value": component["source"]},
                {"name": "aegis:ecosystem", "value": component["ecosystem"]},
            ],
        }
        if component.get("purl"):
            item["purl"] = component["purl"]
        sbom_components.append(item)
    sbom_vulnerabilities = []
    for vulnerability in vulnerabilities:
        item: dict[str, Any] = {
            "id": vulnerability["id"],
            "source": {
                "name": "OSV",
                "url": "https://osv.dev/",
            },
            "ratings": [{
                "severity": vulnerability["severity"],
                **({"score": vulnerability["cvss"]} if vulnerability.get("cvss") is not None else {}),
            }],
            "description": vulnerability.get("summary") or "",
            "affects": [{"ref": component_refs.get(str(vulnerability["component_id"]), "")}],
            "properties": [
                {"name": "aegis:known_exploited", "value": str(bool(vulnerability.get("known_exploited"))).lower()},
                {"name": "aegis:status", "value": "affected_dependency"},
            ],
        }
        if vulnerability.get("aliases"):
            item["references"] = [
                {"id": alias, "source": {"name": "OSV"}}
                for alias in vulnerability["aliases"] if alias != vulnerability["id"]
            ][:20]
        sbom_vulnerabilities.append(item)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "AEGIS", "version": "1"}]},
            "component": {"type": "application", "bom-ref": f"urn:aegis:project:{project_id}", "name": project_name},
        },
        "components": sbom_components,
        "vulnerabilities": sbom_vulnerabilities,
    }


def analyze_supply_chain(
    root: Path,
    project_id: str,
    project_name: str,
    output_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    root = root.resolve()
    output_path = output_path.resolve()
    scanner = find_osv_scanner()
    if not scanner:
        return ({
            "status": "unavailable",
            "analyzer": "OSV-Scanner",
            "component_count": 0,
            "vulnerability_count": 0,
            "artifact_executed": False,
            "install_guidance": "Install OSV-Scanner from Diagnostics, then run Supply Chain Analysis again.",
            "limitations": ["Dependency resolution was not attempted because OSV-Scanner is unavailable."],
        }, [])

    started = time.perf_counter()
    environment = {
        key: value for key, value in os.environ.items()
        if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
    }
    command = [
        scanner, "scan", "source", "--recursive", "--no-resolve",
        "--allow-no-lockfiles", "--format", "json", "--all-packages",
        "--verbosity", "error", str(root),
    ]
    # A project snapshot may be either a copied directory or one copied file.
    # ``subprocess`` requires cwd to be a directory even though OSV-Scanner can
    # analyze either shape directly.
    working_directory = root if root.is_dir() else root.parent
    deadline = time.monotonic() + 180
    failure = ""
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(  # noqa: S603 - executable is resolved locally; argv is fixed and snapshot is AEGIS-owned
            command,
            cwd=working_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
        )
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "OSV-Scanner exceeded the 180 second analysis limit"
                process.kill()
                break
            if os.fstat(stdout_file.fileno()).st_size > MAX_SCANNER_OUTPUT_BYTES:
                failure = "OSV-Scanner JSON exceeded the 32 MiB result limit"
                process.kill()
                break
            if os.fstat(stderr_file.fileno()).st_size > 2 * 1024 * 1024:
                failure = "OSV-Scanner error output exceeded the 2 MiB result limit"
                process.kill()
                break
            time.sleep(0.05)
        process.wait(timeout=5)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(MAX_SCANNER_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(2 * 1024 * 1024 + 1)
    if failure:
        raise RuntimeError(failure)
    if len(stdout) > MAX_SCANNER_OUTPUT_BYTES:
        raise RuntimeError("OSV-Scanner JSON exceeded the 32 MiB result limit")
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        error = stderr.decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"OSV-Scanner returned invalid JSON: {error}") from exc
    components, vulnerabilities = _normalize(payload, root, project_id)
    enrichment = enrich_cve_items(vulnerabilities)
    findings = [_finding(project_id, item) for item in vulnerabilities]
    sbom = build_cyclonedx(project_id, project_name, components, vulnerabilities)
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(output_path)
    ecosystems = Counter(str(item.get("ecosystem") or "unknown") for item in components)
    return ({
        "status": "complete",
        "analyzer": "OSV-Scanner",
        "analyzer_path": Path(scanner).name,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "component_count": len(components),
        "vulnerability_count": len(vulnerabilities),
        "components_truncated": len(components) >= MAX_COMPONENTS,
        "vulnerabilities_truncated": len(vulnerabilities) >= MAX_VULNERABILITIES,
        "ecosystems": dict(sorted(ecosystems.items())),
        "components": components,
        "vulnerabilities": vulnerabilities,
        "risk_enrichment": enrichment,
        "sbom": {
            "available": True,
            "format": "CycloneDX",
            "spec_version": "1.6",
            "component_count": len(components),
            "vulnerability_count": len(vulnerabilities),
            "download_endpoint": f"/api/application/projects/{project_id}/sbom",
        },
        "artifact_executed": False,
        "dependency_build_scripts_executed": False,
        "network_lookup": True,
        "limitations": [
            "Only dependencies represented by supported package metadata are covered.",
            "An affected package version does not prove the vulnerable code path is reachable or exploitable.",
            "Transitive manifest resolution and Rust call analysis are disabled so imported project code is not executed.",
        ],
    }, findings)
