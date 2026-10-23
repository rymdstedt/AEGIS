#!/usr/bin/env python3
"""Measure selected Application Research controls using disposable synthetic data.

This is a known-answer regression benchmark, not an estimate of real-world
vulnerability recall or precision. It never executes imported artifacts and
never includes exact private evidence in its output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import struct
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from application import ApplicationResearchService  # noqa: E402
from application.analyzer import (  # noqa: E402
    MAX_FINDINGS_PER_RULE_FILE,
    MAX_TEXT_FILE_BYTES,
    AnalysisCancelled,
    analyze_snapshot,
)
from application.deep_source import (  # noqa: E402
    LOG4J_REQUEST_TO_LOG_RULE,
    correlate_vulnerabilities,
    map_component_references,
)
from application.supply_chain import _finding, _normalize, build_cyclonedx  # noqa: E402


@dataclass(frozen=True)
class Case:
    name: str
    source: Path
    expected_rules: dict[str, int]
    expected_inventory: dict[str, int]
    artifact_kind: str
    profile: str = "quick"
    exact_rules: bool = True
    expected_formats: dict[str, int] = field(default_factory=dict)
    private_present: tuple[str, ...] = ()
    private_absent: tuple[str, ...] = ()
    expected_truncated: bool = False
    expected_coverage_incomplete: bool = False
    min_omitted: int = 0
    planted_indicators: int = 0
    known_capped_indicators: int = 0
    known_uninspected_indicators: int = 0
    expected_firmware_version: str | None = None
    expected_warning_reasons: tuple[str, ...] = ()


V2_RULES = {
    "code.dynamic-eval": 1,
    "electron.context-isolation-disabled": 1,
    "electron.node-integration": 1,
    "electron.renderer-sandbox-disabled": 1,
    "evidence.scoring-flag": 3,
    "flask.debug-enabled": 1,
    "identity.account-identifier": 2,
    "intelligence.context-identifier": 2,
    "network.internal-endpoint": 4,
    "node.child-process-exec": 1,
    "python.os-system": 1,
    "python.subprocess-shell": 1,
    "python.unsafe-deserialization": 1,
    "python.yaml-unsafe-load": 1,
    "secret.connection-uri-credentials": 1,
    "secret.environment-value": 4,
    "secret.hardcoded-assignment": 3,
    "secret.labeled-value": 3,
    "secret.private-key": 1,
    "tls.verification-disabled": 1,
}
V2_PRIVATE_MARKERS = (
    "AEGIS{BOREALIS_STATIC_DISCOVERY_71C9}",
    "AEGIS{LOG4J_VERSION_CORRELATION_44228}",
    "AEGIS{CREDENTIAL_CHAIN_COMPLETE_90AF}",
    "research-admin",
    "GlacierConsole-71!",
    "PolarLedger-63!",
    "NIGHTJAR",
    "Example Meridian Labs",
)


def _write_synthetic_cases(root: Path) -> dict[str, Path]:
    """Create small nonfunctional controls inside the caller's temporary root."""
    root.mkdir(parents=True, exist_ok=True)
    controls = root / "negative-controls"
    controls.mkdir()
    (controls / "safe.py").write_text(
        "import yaml\n"
        "document = yaml.safe_load(data)\n"
        "password = 'placeholder'\n"
        "# eval(untrusted) is documentation, not executable code\n",
        encoding="utf-8",
    )
    (controls / "safe.js").write_text(
        'db.exec("SELECT 1");\n'
        'child_process.execFile("echo", ["synthetic"]);\n'
        "const document = JSON.parse(payload);\n",
        encoding="utf-8",
    )
    (controls / ".env.example").write_text(
        "API_KEY=placeholder\n", encoding="utf-8"
    )

    archive = root / "archive-boundaries.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as container:
        container.writestr("src/app.py", "eval(untrusted_input)\n")
        container.writestr("../escape.py", "eval(must_not_escape)\n")
        container.writestr("SRC/APP.PY", "eval(case_duplicate)\n")
        link = zipfile.ZipInfo("src/outside-link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        container.writestr(link, "../../outside")

    moderate = root / "moderate-flags"
    moderate.mkdir()
    (moderate / "flags.txt").write_text(
        "\n".join(f"AEGIS{{COVERAGE_MODERATE_{index:02d}}}" for index in range(15))
        + "\n",
        encoding="utf-8",
    )

    capped = root / "capped-flags"
    capped.mkdir()
    (capped / "flags.txt").write_text(
        "\n".join(
            f"AEGIS{{COVERAGE_LIMIT_{index:02d}}}"
            for index in range(MAX_FINDINGS_PER_RULE_FILE + 3)
        )
        + "\n",
        encoding="utf-8",
    )

    oversized = root / "oversized-source"
    oversized.mkdir()
    (oversized / "padded.py").write_text(
        "#" + ("x" * MAX_TEXT_FILE_BYTES) + "\nAEGIS{BEYOND_READ_CEILING}\n",
        encoding="utf-8",
    )

    paged = root / "paged-many-findings"
    paged.mkdir()
    for file_index in range(9):
        (paged / f"part-{file_index:02d}.txt").write_text(
            "\n".join(
                f"AEGIS{{PAGED_{file_index:02d}_{line_index:02d}_71A5}}"
                for line_index in range(60)
            ) + "\n",
            encoding="utf-8",
        )

    binary = root / "pe-stub.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 64)

    firmware = root / "cat9k_iosxe.17.12.04.SPA.bin"
    elf_ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    elf_header = struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0
    )
    executable_stack = struct.pack(
        "<IIQQQQQQ", 0x6474E551, 0x7, 0, 0, 0, 0, 0, 16
    )
    firmware.write_bytes(
        b"Cisco IOS XE Software, Version 17.12.04\n\x00"
        b"OpenSSL 1.1.1k\n"
        b"username admin password 0 SyntheticFirmwareOnlySecret\n"
        b"snmp-server community public RO\n"
        b"-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-real-key\n"
        b"-----END PRIVATE KEY-----\n\x00"
        + elf_ident + elf_header + executable_stack
    )
    return {
        "negative": controls,
        "archive": archive,
        "moderate": moderate,
        "capped": capped,
        "oversized": oversized,
        "paged": paged,
        "binary": binary,
        "firmware": firmware,
    }


def benchmark_cases(root: Path) -> list[Case]:
    generated = _write_synthetic_cases(root)
    planted_v2 = sum(V2_RULES.values())
    return [
        Case(
            "source-v2", REPO_ROOT / "lab/application_test_fixture_v2",
            V2_RULES, {"files": 9, "analyzed_text_files": 9,
                       "skipped_large_text_candidates": 0},
            "source_directory", private_present=V2_PRIVATE_MARKERS,
            planted_indicators=planted_v2,
        ),
        Case(
            "archive-v2", REPO_ROOT / "lab/AEGIS-Application-Research-Test-Fixture-v2.zip",
            V2_RULES, {"files": 19, "analyzed_text_files": 9,
                       "skipped_large_text_candidates": 0},
            "zip_archive", private_present=V2_PRIVATE_MARKERS,
            planted_indicators=planted_v2,
        ),
        Case(
            "negative-controls", generated["negative"], {},
            {"files": 3, "analyzed_text_files": 3,
             "skipped_large_text_candidates": 0},
            "source_directory",
        ),
        Case(
            "archive-boundaries", generated["archive"],
            {"code.dynamic-eval": 1},
            {"files": 1, "analyzed_text_files": 1,
             "skipped_large_text_candidates": 0},
            "zip_archive", planted_indicators=1,
            expected_warning_reasons=(
                "path rejected", "duplicate path skipped", "symbolic link skipped"
            ),
        ),
        Case(
            "moderate-multi-value", generated["moderate"],
            {"evidence.scoring-flag": 15},
            {"files": 1, "analyzed_text_files": 1,
             "skipped_large_text_candidates": 0},
            "source_directory",
            private_present=(
                "AEGIS{COVERAGE_MODERATE_00}",
                "AEGIS{COVERAGE_MODERATE_14}",
            ),
            planted_indicators=15,
        ),
        Case(
            "per-file-cap", generated["capped"],
            {"evidence.scoring-flag": MAX_FINDINGS_PER_RULE_FILE},
            {"files": 1, "analyzed_text_files": 1,
             "skipped_large_text_candidates": 0},
            "source_directory",
            private_present=("AEGIS{COVERAGE_LIMIT_00}",),
            private_absent=(
                f"AEGIS{{COVERAGE_LIMIT_{MAX_FINDINGS_PER_RULE_FILE + 2:02d}}}",
            ),
            expected_truncated=True, min_omitted=1,
            planted_indicators=MAX_FINDINGS_PER_RULE_FILE + 3,
            known_capped_indicators=3,
        ),
        Case(
            "oversized-source", generated["oversized"],
            {"evidence.scoring-flag": 1},
            {"files": 1, "analyzed_text_files": 1,
             "skipped_large_text_candidates": 0,
             "segmented_long_lines": 1},
            "source_directory", planted_indicators=1,
            private_present=("AEGIS{BEYOND_READ_CEILING}",),
            expected_coverage_incomplete=True,
        ),
        Case(
            "paged-many-findings", generated["paged"],
            {"evidence.scoring-flag": 540},
            {"files": 9, "analyzed_text_files": 9,
             "skipped_large_text_candidates": 0},
            "source_directory", planted_indicators=540,
            private_present=("AEGIS{PAGED_00_00_71A5}", "AEGIS{PAGED_08_59_71A5}"),
        ),
        Case(
            "pe-inventory-only", generated["binary"], {},
            {"files": 1, "analyzed_text_files": 0,
             "binary_or_unreadable_candidates": 1},
            "windows_binary", expected_formats={"PE": 1},
        ),
        Case(
            "cisco-firmware-deep", generated["firmware"],
            {"cisco.config-plaintext-password": 1,
             "cisco.config-default-snmp-community": 1,
             "firmware.private-key": 1,
             "firmware.elf-executable-stack": 1,
             "firmware.elf-non-pie": 1},
            {"files": 1, "analyzed_text_files": 0},
            "cisco_ios_firmware", profile="deep_firmware", exact_rules=False,
            private_present=("SyntheticFirmwareOnlySecret",),
            expected_firmware_version="17.12.04", planted_indicators=5,
        ),
    ]


def _source_digest(path: Path) -> str:
    """Ensure the import left its source unchanged without exporting contents."""
    digest = hashlib.sha256()
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    for file in files:
        digest.update(file.relative_to(path).as_posix().encode() if path.is_dir() else file.name.encode())
        with file.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def run_case(case: Case, data_root: Path) -> dict[str, object]:
    """Run one case and return public metrics plus safe mismatch descriptions."""
    problems: list[str] = []
    started = time.perf_counter()
    before = _source_digest(case.source)
    service = ApplicationResearchService(data_root / case.name)
    imported = service.import_path(str(case.source))
    analyzed = service.analyze_project(str(imported["id"]), case.profile)
    source_unchanged = before == _source_digest(case.source)

    summary = analyzed["summary"]
    inventory = summary["inventory"]
    findings: list[dict[str, object]] = []
    total = int(analyzed.get("findings_total") or 0)
    for offset in range(0, total, 500):
        page = service.list_findings_page(str(imported["id"]), offset, 500)
        findings.extend(page["findings"])
    if len(findings) != total:
        problems.append(f"finding pages: expected {total}, received {len(findings)}")
    counts = dict(sorted(Counter(str(item["rule_id"]) for item in findings).items()))
    if case.exact_rules and counts != case.expected_rules:
        problems.append(f"finding counts differ: expected {case.expected_rules}, observed {counts}")
    if not case.exact_rules:
        for rule_id, minimum in case.expected_rules.items():
            if counts.get(rule_id, 0) < minimum:
                problems.append(
                    f"{rule_id}: expected at least {minimum}, observed {counts.get(rule_id, 0)}"
                )
    for key, expected in case.expected_inventory.items():
        if inventory.get(key) != expected:
            problems.append(f"inventory.{key}: expected {expected}, observed {inventory.get(key)}")
    for name, expected in case.expected_formats.items():
        if inventory.get("formats", {}).get(name) != expected:
            problems.append(f"format {name}: expected {expected}, observed {inventory.get('formats', {}).get(name)}")
    if imported.get("artifact_kind") != case.artifact_kind:
        problems.append(f"artifact kind: expected {case.artifact_kind}, observed {imported.get('artifact_kind')}")
    if bool(summary.get("findings_truncated")) != case.expected_truncated:
        problems.append("finding truncation indicator does not match the known control")
    if bool(summary.get("coverage_incomplete")) != case.expected_coverage_incomplete:
        problems.append("coverage completeness indicator does not match the known control")
    if int(summary.get("findings_omitted_lower_bound") or 0) < case.min_omitted:
        problems.append("finding omissions were not reported")
    if case.expected_firmware_version:
        firmware = summary.get("firmware") or {}
        if case.expected_firmware_version not in firmware.get("versions", []):
            problems.append("expected firmware version was not identified")
    observed_warning_reasons = {
        str(item.get("reason") or "")
        for item in (imported.get("intake") or {}).get("warnings", [])
    }
    for reason in case.expected_warning_reasons:
        if reason not in observed_warning_reasons:
            problems.append(f"intake warning missing: {reason}")

    private_json = json.dumps(service.private_evidence_export(str(imported["id"])))
    public_json = json.dumps({"project": analyzed, "all_paged_findings": findings})
    found_private = sum(marker in private_json for marker in case.private_present)
    if found_private != len(case.private_present):
        problems.append(
            f"private evidence: found {found_private}/{len(case.private_present)} known markers"
        )
    if any(marker in private_json for marker in case.private_absent):
        problems.append("an intentionally capped marker appeared in private evidence")
    if any(marker in public_json for marker in case.private_present):
        problems.append("exact private marker leaked into the public project record")
    if summary.get("artifact_executed") is not False:
        problems.append("artifact execution boundary was not reported as false")
    if any(str(item.get("status")) in {"exploited", "confirmed_exploit"} for item in findings):
        problems.append("static analysis reported a confirmed exploit")
    if not source_unchanged:
        problems.append("import or analysis modified the source fixture")

    captured = min(
        case.planted_indicators,
        sum(min(counts.get(rule_id, 0), required) for rule_id, required in case.expected_rules.items()),
    )
    return {
        "name": case.name,
        "passed": not problems,
        "problems": problems,
        "profile": case.profile,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "source_unchanged": source_unchanged,
        "artifact_executed": summary.get("artifact_executed"),
        "observed_findings": len(findings),
        "import_warning_reasons": sorted(observed_warning_reasons),
        "observed_rule_counts": counts,
        "inventory": {
            "files": inventory.get("files"),
            "analyzed_text_files": inventory.get("analyzed_text_files"),
            "analyzed_text_bytes": inventory.get("analyzed_text_bytes"),
            "skipped_large_text_candidates": inventory.get("skipped_large_text_candidates"),
            "segmented_long_lines": inventory.get("segmented_long_lines"),
            "changed_during_scan_files": inventory.get("changed_during_scan_files"),
            "binary_or_unreadable_candidates": inventory.get("binary_or_unreadable_candidates"),
        },
        "finding_results_truncated": summary.get("findings_truncated"),
        "coverage_incomplete": summary.get("coverage_incomplete"),
        "findings_omitted_lower_bound": summary.get("findings_omitted_lower_bound", 0),
        "planted_indicators": case.planted_indicators,
        "captured_indicators": captured,
        "known_capped_indicators": case.known_capped_indicators,
        "known_uninspected_indicators": case.known_uninspected_indicators,
        "private_markers_found": found_private,
        "private_markers_expected": len(case.private_present),
    }


def run_correlation_controls(root: Path) -> list[dict[str, object]]:
    """Exercise OSV normalization and static correlation without network/tools.

    The taint-path records below are synthetic *analyzer output*, not proof that
    Semgrep ran or that a deployed Log4j instance is vulnerable.
    """
    root.mkdir(parents=True, exist_ok=True)
    source = root / "synthetic-source"
    source.mkdir()
    (source / "pom.xml").write_text("<project/>", encoding="utf-8")
    (source / "Controller.java").write_text(
        "import org.apache.logging.log4j.LogManager;\n", encoding="utf-8"
    )
    project_id = "app_" + "a" * 32
    package = {
        "package": {
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "ecosystem": "Maven",
        },
        "groups": [{
            "ids": ["GHSA-synthetic-log4j"],
            "aliases": ["CVE-2021-44228"],
            "max_severity": "10.0",
        }],
        "vulnerabilities": [{
            "id": "GHSA-synthetic-log4j",
            "aliases": ["CVE-2021-44228"],
            "summary": "Synthetic affected-version control",
        }],
    }

    def normalize(current_package: dict[str, object]):
        return _normalize({"results": [{
            "source": {"path": str(source / "pom.xml"), "type": "lockfile"},
            "packages": [current_package],
        }]}, source, project_id)

    components, vulnerabilities = normalize(package)
    supply = {"components": components, "vulnerabilities": vulnerabilities}
    references, coverage = map_component_references(source, supply)
    static_path = {
        "finding_id": "appf_" + "b" * 20,
        "rule_id": LOG4J_REQUEST_TO_LOG_RULE,
        "validation": "static_taint_path",
        "component_hint": "log4j-core",
    }
    correlated = correlate_vulnerabilities(supply, references, [static_path])
    sbom = build_cyclonedx(project_id, "synthetic", components, vulnerabilities)
    public_finding = _finding(project_id, vulnerabilities[0]) if vulnerabilities else {}
    controls: list[dict[str, object]] = []

    def record(name: str, ok: bool, problems: list[str]) -> None:
        controls.append({
            "name": name,
            "passed": ok,
            "problems": problems,
            "artifact_executed": False,
            "external_scanner_invoked": False,
        })

    positive = correlated[0] if len(correlated) == 1 else {}
    conditions = [
        len(components) == len(vulnerabilities) == 1,
        vulnerabilities[0].get("id") == "CVE-2021-44228" if vulnerabilities else False,
        len(references) >= 1 and coverage.get("files") == 1,
        len(sbom.get("vulnerabilities", [])) == 1,
        public_finding.get("status") == "affected_dependency",
        "not reachability or exploitability" in str(public_finding.get("description", "")),
        positive.get("state") == "cve_specific_sink_path_observed",
        positive.get("validation") == "static_cve_specific_sink_candidate",
        positive.get("cve_preconditions_confirmed") is False,
        positive.get("exploitation_demonstrated") is False,
    ]
    record("affected-log4j-static-sink", all(conditions), [
        "OSV alias, SBOM, import reference, or static-only correlation differed"
    ] if not all(conditions) else [])

    reference_only = correlate_vulnerabilities(supply, references, [])[0]
    ok = (reference_only.get("state") == "referenced_by_code"
          and reference_only.get("exploitation_demonstrated") is False)
    record("import-is-not-input-reachability", ok, [
        "an import reference was promoted to input reachability"
    ] if not ok else [])

    unrelated_cve = {
        **vulnerabilities[0], "id": "CVE-2021-45046",
        "aliases": ["CVE-2021-45046"],
    }
    other = correlate_vulnerabilities(
        {"components": components, "vulnerabilities": [unrelated_cve]},
        references, [static_path],
    )[0]
    ok = (other.get("state") == "affected_component_reachable_from_input"
          and other.get("cve_specific_sink_path_observed") is False)
    record("other-cve-not-log4shell-specific", ok, [
        "a Log4Shell-specific static sink was attributed to another CVE"
    ] if not ok else [])

    unrelated = {**components[0],
                 "name": "example:unrelated-log4j-core-wrapper",
                 "purl": "pkg:maven/example/unrelated-log4j-core-wrapper@1.0"}
    wrapper = correlate_vulnerabilities(
        {"components": [unrelated], "vulnerabilities": vulnerabilities},
        [], [static_path],
    )[0]
    ok = wrapper.get("cve_specific_sink_path_observed") is False
    record("same-name-wrapper-not-log4shell-core", ok, [
        "an unrelated package name was treated as Log4j Core"
    ] if not ok else [])

    safe_package = {**package, "package": {**package["package"], "version": "9.9.9"},
                    "groups": [], "vulnerabilities": []}
    _safe_components, safe_vulnerabilities = normalize(safe_package)
    ok = not safe_vulnerabilities
    record("unaffected-locked-version", ok, [
        "a no-advisory package was reported as vulnerable"
    ] if not ok else [])
    return controls


def run_cancellation_control(root: Path) -> dict[str, object]:
    """Cancel a paused synthetic rerun and verify the prior commit survives."""
    root.mkdir(parents=True, exist_ok=True)
    source = root / "source"
    source.mkdir()
    (source / "flags.txt").write_text(
        "AEGIS{CANCEL_PRESERVE_SYNTHETIC_71C9}\n", encoding="utf-8"
    )
    service = ApplicationResearchService(root / "private-data")
    imported = service.import_path(str(source))
    original = service.analyze_project(str(imported["id"]))
    began = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def paused_scan(*args, **kwargs):
        normal_progress = kwargs["progress"]

        def pause(progress):
            normal_progress(progress)
            if not began.is_set():
                began.set()
                if not release.wait(5):
                    raise RuntimeError("Synthetic cancellation barrier timed out")

        kwargs["progress"] = pause
        return analyze_snapshot(*args, **kwargs)

    def rerun() -> None:
        try:
            service.analyze_project(str(imported["id"]))
        except BaseException as exc:
            errors.append(exc)

    with patch("application.service.analyze_snapshot", side_effect=paused_scan):
        worker = threading.Thread(target=rerun, daemon=True)
        worker.start()
        try:
            if began.wait(5):
                requested = service.cancel_analysis(str(imported["id"]))
            else:
                requested = None
        finally:
            release.set()
            worker.join(5)
    preserved = service.get_project(str(imported["id"]))
    last_job = service.get_analysis_job(str(imported["id"]))
    ok = (
        not worker.is_alive()
        and len(errors) == 1 and isinstance(errors[0], AnalysisCancelled)
        and bool(requested and requested.get("progress", {}).get("cancel_requested"))
        and last_job is not None and last_job.get("status") == "cancelled"
        and preserved.get("status") == "complete"
        and preserved.get("findings_total") == original.get("findings_total") == 1
        and preserved.get("findings") == original.get("findings")
    )
    return {
        "name": "cancelled-rerun-retains-last-result",
        "passed": ok,
        "problems": [] if ok else ["cancellation or prior committed result did not match"],
        "artifact_executed": False,
    }


def run_suite(cases: Iterable[Case], data_root: Path) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for case in cases:
        try:
            results.append(run_case(case, data_root))
        except Exception as exc:
            # Never include exception text: third-party parser errors can contain
            # exact source snippets or private values.
            results.append({
                "name": case.name,
                "passed": False,
                "problems": [f"case raised {type(exc).__name__}; inspect locally"],
            })
    planted = sum(int(item.get("planted_indicators", 0)) for item in results)
    captured = sum(int(item.get("captured_indicators", 0)) for item in results)
    try:
        correlation_controls = run_correlation_controls(data_root / "correlation-controls")
    except Exception as exc:
        correlation_controls = [{
            "name": "deep-source-cve-controls", "passed": False,
            "problems": [f"control raised {type(exc).__name__}; inspect locally"],
            "artifact_executed": False, "external_scanner_invoked": False,
        }]
    try:
        cancellation_control = run_cancellation_control(data_root / "cancellation-control")
    except Exception as exc:
        cancellation_control = {
            "name": "cancelled-rerun-retains-last-result", "passed": False,
            "problems": [f"control raised {type(exc).__name__}; inspect locally"],
            "artifact_executed": False,
        }
    return {
        "schema_version": 1,
        "scope": "selected synthetic known-answer controls only; not real-world recall or precision",
        "platform": {"system": platform.system(), "architecture": platform.machine()},
        "passed": all(bool(item["passed"]) for item in [*results, *correlation_controls, cancellation_control]),
        "cases_passed": sum(bool(item["passed"]) for item in results),
        "cases_total": len(results),
        "deep_source_cve_controls": correlation_controls,
        "deep_source_cve_controls_passed": sum(bool(item["passed"]) for item in correlation_controls),
        "cancellation_control": cancellation_control,
        "planted_indicator_instances": planted,
        "captured_indicator_instances": captured,
        "known_capped_indicator_instances": sum(
            int(item.get("known_capped_indicators", 0)) for item in results
        ),
        "known_uninspected_indicator_instances": sum(
            int(item.get("known_uninspected_indicators", 0)) for item in results
        ),
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-output", type=Path, help="write a redacted JSON report")
    parser.add_argument("--case", action="append", help="run only named case(s)")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aegis-coverage-") as temporary:
        root = Path(temporary)
        cases = benchmark_cases(root / "fixtures")
        available = {case.name for case in cases}
        unknown = set(args.case or []) - available
        if unknown:
            parser.error("unknown case(s): " + ", ".join(sorted(unknown)))
        selected = [case for case in cases if not args.case or case.name in args.case]
        report = run_suite(selected, root / "private-data")
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for result in report["cases"]:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"{status:4} {result['name']}: {result.get('observed_findings', '?')} findings; "
              f"{result.get('duration_seconds', '?')} s")
        for problem in result["problems"]:
            print(f"  {problem}")
    print(
        f"Known synthetic indicator instances captured: "
        f"{report['captured_indicator_instances']}/{report['planted_indicator_instances']} "
        f"(case-weighted; {report['known_capped_indicator_instances']} capped and "
        f"{report['known_uninspected_indicator_instances']} known uninspected)."
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
