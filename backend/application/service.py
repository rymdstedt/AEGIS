"""Orchestration boundary for application artifact intake and analysis."""

from __future__ import annotations

import re
import shutil
import threading
import uuid
from collections import Counter
from pathlib import Path

from evidence_graph import build_application_evidence_graph

from .analyzer import AnalysisCancelled, analyze_snapshot
from .deep_source import analyze_deep_source
from .intake import IntakeLimits, import_artifact
from .store import ApplicationStore
from .supply_chain import analyze_supply_chain

PROJECT_ID_PATTERN = re.compile(r"app_[0-9a-f]{32}")
FINDING_ID_PATTERN = re.compile(r"appf_[0-9a-f]{20}")


class ApplicationResearchService:
    """Small synchronous service intended to run through ``asyncio.to_thread``."""

    def __init__(
        self,
        root: Path | None = None,
        limits: IntakeLimits | None = None,
    ):
        self.store = ApplicationStore(root)
        self.limits = limits or IntakeLimits()
        self._locks_guard = threading.Lock()
        self._project_locks: dict[str, threading.Lock] = {}
        self._active_jobs: dict[str, tuple[str, threading.Event]] = {}

    def import_path(self, source_path: str) -> dict[str, object]:
        project_id = "app_" + uuid.uuid4().hex
        project_directory = self.store.project_directory(project_id)
        try:
            record = import_artifact(
                source_path,
                project_id,
                project_directory,
                self.limits,
            )
            return self.store.create_project(record)
        except Exception:
            # This directory was generated above and is always a direct child of
            # the private project root. Never remove the operator's source path.
            if project_directory.parent == self.store.projects_root:
                shutil.rmtree(project_directory, ignore_errors=True)
            raise

    def list_projects(self, limit: int = 100) -> list[dict[str, object]]:
        return self.store.list_projects(limit)

    def get_project(self, project_id: str) -> dict[str, object]:
        self._validate_project_id(project_id)
        return self.store.get_project(project_id)

    def list_findings_page(
        self, project_id: str, offset: int = 0, limit: int = 100
    ) -> dict[str, object]:
        self._validate_project_id(project_id)
        return self.store.list_findings_page(project_id, offset, limit)

    def private_evidence_page(
        self, project_id: str, offset: int = 0, limit: int = 100
    ) -> dict[str, object]:
        self._validate_project_id(project_id)
        result = self.store.list_private_evidence_page(project_id, offset, limit)
        record = self.store.get_internal_project(project_id)
        result["project"] = {
            "id": record["id"],
            "name": record["name"],
            "artifact_kind": record["artifact_kind"],
            "sha256": record["sha256"],
            "analyzed_at": record.get("summary", {}).get("completed_at"),
            "analysis_job_id": result.get("analysis_job_id"),
        }
        return result

    def get_analysis_job(self, project_id: str) -> dict[str, object] | None:
        self._validate_project_id(project_id)
        return self.store.get_latest_job(project_id)

    def cancel_analysis(self, project_id: str) -> dict[str, object] | None:
        self._validate_project_id(project_id)
        with self._locks_guard:
            active = self._active_jobs.get(project_id)
            if active is None:
                raise RuntimeError("No analysis is running for this project")
            job_id, event = active
            event.set()
        self.store.request_job_cancel(job_id, project_id)
        return self.store.get_latest_job(project_id)

    def analyze_project(
        self,
        project_id: str,
        profile: str = "quick",
    ) -> dict[str, object]:
        self._validate_project_id(project_id)
        if profile not in {"quick", "deep_firmware", "supply_chain", "deep_source"}:
            raise ValueError("Unsupported application-analysis profile")
        lock = self._lock_for(project_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("Analysis is already running for this project")
        job_id = "job_" + uuid.uuid4().hex
        cancel_event = threading.Event()
        with self._locks_guard:
            self._active_jobs[project_id] = (job_id, cancel_event)
        try:
            record = self.store.get_internal_project(project_id)
            project_directory = self.store.project_directory(project_id)
            snapshot = project_directory / record["snapshot_relpath"]
            try:
                snapshot.resolve().relative_to(project_directory.resolve())
            except ValueError as exc:
                raise RuntimeError("The stored snapshot path is invalid") from exc
            self.store.start_job(
                job_id,
                project_id,
                "firmware-deep-analysis" if profile == "deep_firmware"
                else "supply-chain-analysis" if profile == "supply_chain"
                else "deep-source-analysis" if profile == "deep_source"
                else "static-analysis",
            )
            try:
                def check_cancelled() -> bool:
                    return cancel_event.is_set()

                def report_progress(progress: dict[str, object]) -> None:
                    with self._locks_guard:
                        self.store.update_job_progress(
                            job_id, project_id, {
                                "phase": "quick_static", **progress,
                                "cancel_requested": cancel_event.is_set(),
                            }
                        )

                def stage_findings(
                    quick_findings: list[dict[str, object]],
                    quick_private: list[dict[str, str]],
                ) -> None:
                    self.store.append_job_findings(
                        job_id, project_id, quick_findings, quick_private
                    )

                summary, _, _ = analyze_snapshot(
                    snapshot,
                    project_id,
                    str(record["artifact_kind"]),
                    profile="quick" if profile in {"supply_chain", "deep_source"} else profile,
                    progress=report_progress,
                    cancelled=check_cancelled,
                    on_findings=stage_findings,
                )
                if cancel_event.is_set():
                    raise AnalysisCancelled("Analysis cancelled by operator")
                findings: list[dict[str, object]] = []
                private_evidence: list[dict[str, str]] = []
                supply_summary: dict[str, object] | None = None
                if profile in {"supply_chain", "deep_source"}:
                    self.store.update_job_progress(
                        job_id, project_id, {"phase": "supply_chain"}
                    )
                    try:
                        supply_summary, dependency_findings = analyze_supply_chain(
                            snapshot,
                            project_id,
                            str(record["name"]),
                            project_directory / "reports" / "sbom.cdx.json",
                        )
                    except Exception as exc:
                        safe_error = re.sub(r"\s+", " ", str(exc)).replace(
                            str(snapshot), "[project snapshot]"
                        )[:500]
                        supply_summary = {
                            "status": "error",
                            "analyzer": "OSV-Scanner",
                            "component_count": 0,
                            "vulnerability_count": 0,
                            "artifact_executed": False,
                            "error": safe_error,
                            "limitations": [
                                "Dependency analysis failed; built-in static findings are still complete for this pass."
                            ],
                        }
                        dependency_findings = []
                    findings.extend(dependency_findings)
                    summary["analysis_profile"] = (
                        "deep_source_and_supply_chain"
                        if profile == "deep_source"
                        else "static_and_supply_chain"
                    )
                    summary["supply_chain"] = supply_summary
                    external = summary.get("external_analyzers")
                    if isinstance(external, list):
                        external.append({
                            "name": "OSV-Scanner",
                            "status": supply_summary.get("status", "unknown"),
                            "artifact_executed": False,
                        })
                    if supply_summary.get("status") == "complete":
                        limitations = summary.get("limitations")
                        if isinstance(limitations, list):
                            summary["limitations"] = [
                                item for item in limitations
                                if not str(item).startswith("Dependency vulnerability")
                            ] + list(supply_summary.get("limitations") or [])

                if profile == "deep_source":
                    if cancel_event.is_set():
                        raise AnalysisCancelled("Analysis cancelled by operator")
                    self.store.update_job_progress(
                        job_id, project_id, {"phase": "deep_source"}
                    )
                    try:
                        deep_summary, deep_findings, deep_private = analyze_deep_source(
                            snapshot,
                            project_id,
                            project_directory / "reports",
                            [
                                *self.store.list_staged_findings(
                                    job_id, limit=100_000, secret_only=True
                                ),
                                *findings,
                            ],
                            supply_summary,
                        )
                    except Exception as exc:
                        safe_error = re.sub(r"\s+", " ", str(exc)).replace(
                            str(snapshot), "[project snapshot]"
                        )[:500]
                        deep_summary = {
                            "status": "error",
                            "artifact_executed": False,
                            "finding_count": 0,
                            "reachability_path_count": 0,
                            "component_reference_count": 0,
                            "error": safe_error,
                            "limitations": [
                                "Deep source analysis failed; built-in and supply-chain findings are still complete for this pass."
                            ],
                        }
                        deep_findings = []
                        deep_private = []
                    findings.extend(deep_findings)
                    private_evidence.extend(deep_private)
                    summary["deep_source"] = deep_summary
                    external = summary.get("external_analyzers")
                    if isinstance(external, list):
                        analyzers = deep_summary.get("analyzers")
                        if isinstance(analyzers, dict):
                            for item in analyzers.values():
                                if isinstance(item, dict):
                                    external.append({
                                        "name": item.get("analyzer", "Deep source analyzer"),
                                        "status": item.get("status", "unknown"),
                                        "artifact_executed": False,
                                    })
                    limitations = summary.get("limitations")
                    if isinstance(limitations, list):
                        summary["limitations"] = [
                            item for item in limitations
                            if not str(item).startswith("Data-flow SAST")
                        ] + list(deep_summary.get("limitations") or [])

                severities = Counter(summary.get("finding_counts") or {})
                severities.update(
                    str(finding.get("severity") or "info") for finding in findings
                )
                summary["finding_counts"] = {
                    severity: severities.get(severity, 0)
                    for severity in ("critical", "high", "medium", "low", "info")
                }
                summary["finding_total"] = int(summary.get("finding_total") or 0) + len(findings)
                summary["analysis_job_id"] = job_id
                graph_findings = self.store.list_staged_findings(job_id, limit=5000)
                summary["evidence_graph_finding_sample"] = {
                    "included": len(graph_findings),
                    "quick_findings_total": int(summary["finding_total"]) - len(findings),
                }
                summary["evidence_graph"] = build_application_evidence_graph(
                    project_id,
                    str(record["name"]),
                    str(record["artifact_kind"]),
                    summary,
                    [*graph_findings, *findings],
                )
                previous_firmware = record.get("summary", {}).get("firmware")
                next_firmware = summary.get("firmware")
                if isinstance(previous_firmware, dict) and isinstance(next_firmware, dict):
                    lookup = previous_firmware.get("advisory_lookup")
                    lookup_version = (
                        str(lookup.get("version") or "")
                        if isinstance(lookup, dict)
                        else ""
                    )
                    if lookup_version in {
                        str(item) for item in next_firmware.get("versions", [])
                    }:
                        next_firmware["advisory_lookup_performed"] = True
                        next_firmware["advisory_lookup"] = lookup
                if cancel_event.is_set():
                    raise AnalysisCancelled("Analysis cancelled by operator")
                return self.store.complete_job(
                    job_id,
                    project_id,
                    summary,
                    findings,
                    private_evidence,
                )
            except AnalysisCancelled:
                self.store.cancel_job(job_id, project_id)
                raise
            except Exception as exc:
                self.store.fail_job(job_id, project_id, str(exc))
                raise
        finally:
            with self._locks_guard:
                self._active_jobs.pop(project_id, None)
            lock.release()

    def get_sbom_path(self, project_id: str) -> tuple[Path, str]:
        """Resolve the generated project SBOM without exposing storage paths."""
        self._validate_project_id(project_id)
        project = self.store.get_internal_project(project_id)
        supply = project.get("summary", {}).get("supply_chain")
        if not isinstance(supply, dict) or not isinstance(supply.get("sbom"), dict) or not supply["sbom"].get("available"):
            raise FileNotFoundError("No CycloneDX SBOM has been generated for this project")
        project_directory = self.store.project_directory(project_id).resolve()
        sbom = (project_directory / "reports" / "sbom.cdx.json").resolve()
        try:
            sbom.relative_to(project_directory)
        except ValueError as exc:
            raise RuntimeError("The stored SBOM path is invalid") from exc
        if not sbom.is_file():
            raise FileNotFoundError("The generated CycloneDX SBOM is missing")
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", str(project.get("name") or "application"))[:80]
        return sbom, f"AEGIS-{safe_name or 'application'}-sbom.cdx.json"

    def record_firmware_advisory_lookup(
        self,
        project_id: str,
        lookup: dict[str, object],
    ) -> dict[str, object]:
        self._validate_project_id(project_id)
        lock = self._lock_for(project_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("Analysis is already running for this project")
        try:
            return self.store.record_firmware_advisory_lookup(project_id, lookup)
        finally:
            lock.release()

    def get_private_finding(
        self, project_id: str, finding_id: str
    ) -> dict[str, object]:
        self._validate_project_id(project_id)
        self._validate_finding_id(finding_id)
        return self.store.get_private_finding(project_id, finding_id)

    def private_evidence_export(self, project_id: str) -> dict[str, object]:
        self._validate_project_id(project_id)
        project = self.store.get_project(project_id)
        return {
            "project": {
                "id": project["id"],
                "name": project["name"],
                "artifact_kind": project["artifact_kind"],
                "sha256": project["sha256"],
                "analyzed_at": project["summary"].get("completed_at"),
            },
            "evidence": self.store.list_private_evidence(project_id),
            "warning": (
                "Sensitive local evidence. Store securely and rotate any real "
                "credentials before sharing."
            ),
        }

    def delete_project(self, project_id: str) -> dict[str, object]:
        """Remove exactly one AEGIS-owned project and its copied snapshot."""
        self._validate_project_id(project_id)
        lock = self._lock_for(project_id)
        if not lock.acquire(blocking=False):
            raise RuntimeError("Analysis is running; wait before removing this project")
        project_directory = self.store.project_directory(project_id)
        tombstone = self.store.projects_root / (
            f".deleting-{project_id}-{uuid.uuid4().hex}"
        )
        try:
            self.store.get_internal_project(project_id)
            if (
                project_directory.parent != self.store.projects_root
                or project_directory.name != project_id
            ):
                raise RuntimeError("The stored project path is invalid")
            moved = False
            if project_directory.exists():
                project_directory.rename(tombstone)
                moved = True
            try:
                self.store.delete_project_record(project_id)
            except Exception:
                if moved and tombstone.exists() and not project_directory.exists():
                    tombstone.rename(project_directory)
                raise

            cleanup_pending = False
            if moved:
                try:
                    shutil.rmtree(tombstone)
                except OSError:
                    cleanup_pending = True
            return {
                "deleted": True,
                "project_id": project_id,
                "cleanup_pending": cleanup_pending,
            }
        finally:
            lock.release()

    def _lock_for(self, project_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._project_locks.setdefault(project_id, threading.Lock())

    @staticmethod
    def _validate_project_id(project_id: str) -> None:
        if not PROJECT_ID_PATTERN.fullmatch(str(project_id or "")):
            raise KeyError(project_id)

    @staticmethod
    def _validate_finding_id(finding_id: str) -> None:
        if not FINDING_ID_PATTERN.fullmatch(str(finding_id or "")):
            raise KeyError(finding_id)
