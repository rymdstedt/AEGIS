"""Deterministic, redacted evidence graphs shared by AEGIS workflows.

The graph is deliberately a derived view of persisted scan/project state.  It
contains relationships and compact metadata, never raw secrets or response
bodies.  Stable IDs make repeated analyses comparable without introducing a
second mutable source of truth.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

SCHEMA = "aegis-evidence-graph/v1"


def _stable_id(kind: str, *parts: object) -> str:
    material = "\x00".join(str(part or "") for part in parts)
    digest = hashlib.sha256(f"{kind}\x00{material}".encode()).hexdigest()[:20]
    return f"eg_{kind}_{digest}"


class EvidenceGraphBuilder:
    """Small deduplicating graph builder with deterministic ordering."""

    def __init__(self, root_kind: str, root_key: str, root_label: str):
        self.root_id = _stable_id(root_kind, root_key)
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[str, dict[str, str]] = {}
        self.add_node(root_kind, root_key, root_label, status="observed")

    def add_node(
        self,
        kind: str,
        key: str,
        label: str,
        *,
        status: str = "observed",
        properties: dict[str, Any] | None = None,
    ) -> str:
        node_id = _stable_id(kind, key)
        node = {
            "id": node_id,
            "kind": str(kind),
            "label": str(label)[:500],
            "status": str(status)[:40],
            "properties": properties or {},
        }
        existing = self._nodes.get(node_id)
        if existing:
            existing["properties"].update(node["properties"])
            if existing["status"] == "candidate" and status != "candidate":
                existing["status"] = status
        else:
            self._nodes[node_id] = node
        return node_id

    def add_edge(self, source: str, target: str, relationship: str) -> None:
        edge_id = _stable_id("edge", source, relationship, target)
        self._edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "relationship": str(relationship)[:80],
        }

    def build(self) -> dict[str, Any]:
        nodes = sorted(self._nodes.values(), key=lambda item: item["id"])
        edges = sorted(self._edges.values(), key=lambda item: item["id"])
        kinds = Counter(str(node["kind"]) for node in nodes)
        statuses = Counter(str(node["status"]) for node in nodes)
        return {
            "schema": SCHEMA,
            "root_id": self.root_id,
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "nodes": len(nodes),
                "edges": len(edges),
                "kinds": dict(sorted(kinds.items())),
                "statuses": dict(sorted(statuses.items())),
            },
        }


def build_application_evidence_graph(
    project_id: str,
    project_name: str,
    artifact_kind: str,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a bounded project -> component -> vulnerability/finding graph."""
    graph = EvidenceGraphBuilder("project", project_id, project_name)
    artifact_id = graph.add_node(
        "artifact",
        f"{project_id}:{artifact_kind}",
        artifact_kind.replace("_", " "),
        properties={"artifact_kind": artifact_kind},
    )
    graph.add_edge(graph.root_id, artifact_id, "contains")

    inventory = summary.get("inventory")
    if isinstance(inventory, dict):
        for manifest in (inventory.get("manifests") or [])[:500]:
            manifest_path = str(manifest)[:1000]
            manifest_id = graph.add_node(
                "manifest",
                f"{project_id}:{manifest_path}",
                manifest_path,
            )
            graph.add_edge(artifact_id, manifest_id, "contains")

    supply = summary.get("supply_chain")
    component_nodes: dict[str, str] = {}
    vulnerability_nodes: dict[str, str] = {}
    if isinstance(supply, dict):
        for component in (supply.get("components") or [])[:10_000]:
            if not isinstance(component, dict):
                continue
            component_key = str(component.get("component_id") or "")
            if not component_key:
                continue
            label = "@".join(
                part for part in (
                    str(component.get("name") or "unknown"),
                    str(component.get("version") or ""),
                ) if part
            )
            node_id = graph.add_node(
                "component",
                f"{project_id}:{component_key}",
                label,
                properties={
                    "ecosystem": str(component.get("ecosystem") or ""),
                    "version": str(component.get("version") or ""),
                    "source": str(component.get("source") or "")[:500],
                    "purl": str(component.get("purl") or "")[:500],
                },
            )
            component_nodes[component_key] = node_id
            graph.add_edge(artifact_id, node_id, "contains")

        for vulnerability in (supply.get("vulnerabilities") or [])[:2_000]:
            if not isinstance(vulnerability, dict):
                continue
            vulnerability_id = str(vulnerability.get("id") or "")
            component_key = str(vulnerability.get("component_id") or "")
            if not vulnerability_id:
                continue
            node_id = graph.add_node(
                "vulnerability",
                vulnerability_id,
                vulnerability_id,
                status="affected_dependency",
                properties={
                    "severity": str(vulnerability.get("severity") or ""),
                    "cvss": vulnerability.get("cvss"),
                    "known_exploited": bool(vulnerability.get("known_exploited")),
                    "epss": vulnerability.get("epss"),
                    "epss_percentile": vulnerability.get("epss_percentile"),
                },
            )
            vulnerability_nodes[vulnerability_id] = node_id
            if component_key in component_nodes:
                graph.add_edge(component_nodes[component_key], node_id, "affected_by")

    finding_nodes: dict[str, str] = {}
    for finding in findings[:5_000]:
        finding_id = str(finding.get("id") or "")
        if not finding_id:
            continue
        node_id = graph.add_node(
            "finding",
            f"{project_id}:{finding_id}",
            str(finding.get("title") or finding.get("rule_id") or "Finding"),
            status=str(finding.get("status") or "observed"),
            properties={
                "severity": str(finding.get("severity") or "info"),
                "confidence": str(finding.get("confidence") or "unknown"),
                "rule_id": str(finding.get("rule_id") or ""),
                "file_path": str(finding.get("file_path") or "")[:1000],
                "line": finding.get("line"),
            },
        )
        finding_nodes[finding_id] = node_id
        graph.add_edge(artifact_id, node_id, "supports")
        vulnerability_id = str(finding.get("vulnerability_id") or "")
        if vulnerability_id:
            graph.add_edge(node_id, _stable_id("vulnerability", vulnerability_id), "reports")

    deep_source = summary.get("deep_source")
    if isinstance(deep_source, dict):
        source_file_nodes: dict[tuple[str, int], str] = {}
        for reference in (deep_source.get("component_references") or [])[:2_000]:
            if not isinstance(reference, dict):
                continue
            component_key = str(reference.get("component_id") or "")
            file_path = str(reference.get("file_path") or "")[:1000]
            try:
                line = int(reference.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            if not component_key or not file_path:
                continue
            source_file_id = graph.add_node(
                "source_file",
                f"{project_id}:{file_path}:{line}",
                f"{file_path}:{line}" if line else file_path,
                status="referenced_by_code",
                properties={"file_path": file_path, "line": line or None},
            )
            source_file_nodes[(file_path, line)] = source_file_id
            graph.add_edge(artifact_id, source_file_id, "contains")
            if component_key in component_nodes:
                graph.add_edge(component_nodes[component_key], source_file_id, "referenced_by")

        sink_nodes: dict[str, str] = {}
        for path in (deep_source.get("reachability") or [])[:500]:
            if not isinstance(path, dict):
                continue
            finding_id = str(path.get("finding_id") or "")
            file_path = str(path.get("file_path") or "")[:1000]
            try:
                line = int(path.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            source_label = str(path.get("source") or "untrusted input")[:200]
            sink_label = str(path.get("sink") or "security-sensitive operation")[:200]
            input_id = graph.add_node(
                "input",
                f"{project_id}:{finding_id}:input",
                source_label,
                status="untrusted",
                properties={"file_path": file_path, "line": line or None},
            )
            sink_id = graph.add_node(
                "sink",
                f"{project_id}:{finding_id}:sink",
                sink_label,
                status="statically_reachable",
                properties={
                    "file_path": file_path,
                    "line": line or None,
                    "validation": str(path.get("validation") or "static_taint_path")[:80],
                    "dynamically_validated": False,
                },
            )
            sink_nodes[finding_id] = sink_id
            graph.add_edge(artifact_id, input_id, "contains")
            graph.add_edge(input_id, sink_id, "may_reach")
            if finding_id in finding_nodes:
                graph.add_edge(sink_id, finding_nodes[finding_id], "supports")

        for item in (deep_source.get("vulnerability_reachability") or [])[:2_000]:
            if not isinstance(item, dict):
                continue
            vulnerability_id = str(item.get("vulnerability_id") or "")
            component_key = str(item.get("component_id") or "")
            state = str(item.get("state") or "affected_dependency_only")[:80]
            if vulnerability_id:
                graph.add_node(
                    "vulnerability",
                    vulnerability_id,
                    vulnerability_id,
                    status="affected_dependency",
                    properties={
                        "reachability_state": state,
                        "cve_specific_sink_path_observed": bool(
                            item.get("cve_specific_sink_path_observed", False)
                        ),
                        "cve_specific_path_confirmed": bool(
                            item.get("cve_specific_path_confirmed", False)
                        ),
                        "cve_preconditions_confirmed": bool(
                            item.get("cve_preconditions_confirmed", False)
                        ),
                        "dynamically_validated": False,
                        "exploitation_demonstrated": False,
                    },
                )
            for reference in (item.get("references") or [])[:5]:
                if not isinstance(reference, dict):
                    continue
                file_path = str(reference.get("file_path") or "")[:1000]
                try:
                    line = int(reference.get("line") or 0)
                except (TypeError, ValueError):
                    line = 0
                source_file_id = source_file_nodes.get((file_path, line))
                if source_file_id and vulnerability_id in vulnerability_nodes:
                    graph.add_edge(source_file_id, vulnerability_nodes[vulnerability_id], "references_affected_component")
            for finding_id in (item.get("reachability_finding_ids") or [])[:5]:
                sink_id = sink_nodes.get(str(finding_id))
                if sink_id and component_key in component_nodes:
                    graph.add_edge(sink_id, component_nodes[component_key], "invokes")
    return graph.build()


def build_scan_evidence_graph(state: object) -> dict[str, Any]:
    """Build a redacted graph from a live ``ScanState`` without importing it."""
    target = str(getattr(state, "target", "unknown"))
    graph = EvidenceGraphBuilder("scan", target, target)
    host_nodes: dict[str, str] = {}
    service_nodes: dict[tuple[str, int], str] = {}
    hosts = list(getattr(state, "discovered_hosts", []) or [])
    host_ports = getattr(state, "host_ports", {}) or {}
    for host in dict.fromkeys([*hosts, *host_ports.keys()]):
        host_id = graph.add_node("host", host, host)
        host_nodes[host] = host_id
        graph.add_edge(graph.root_id, host_id, "contains")
        services = (getattr(state, "host_services", {}) or {}).get(host, {})
        confirmed = (getattr(state, "confirmed_service_ports", {}) or {}).get(host, set())
        for port in sorted(host_ports.get(host, set())):
            service = str(services.get(port) or "unknown")
            service_id = graph.add_node(
                "service",
                f"{host}:{port}/tcp",
                f"{host}:{port}/tcp {service}",
                status="confirmed" if port in confirmed else "observed",
                properties={"host": host, "port": port, "protocol": "tcp", "service": service},
            )
            service_nodes[(host, port)] = service_id
            graph.add_edge(host_id, service_id, "exposes")

    finding_nodes: list[tuple[str, object]] = []
    for finding in list(getattr(state, "findings", []) or [])[:5_000]:
        finding_id = graph.add_node(
            "finding",
            str(getattr(finding, "id", "")),
            str(getattr(finding, "title", "Finding")),
            status="confirmed" if str(getattr(finding, "phase", "")) == "exploit" else "observed",
            properties={
                "severity": str(getattr(finding, "severity", "info")),
                "phase": str(getattr(finding, "phase", "")),
                "tool": str(getattr(finding, "tool", "")),
                "target": str(getattr(finding, "target", "")),
            },
        )
        finding_nodes.append((finding_id, finding))
        graph.add_edge(graph.root_id, finding_id, "reports")

    product_nodes: dict[str, str] = {}
    profile = getattr(state, "profile", {}) or {}
    for product in (profile.get("products") or [])[:200]:
        if not isinstance(product, dict):
            continue
        key = "\x00".join(str(product.get(field) or "") for field in ("vendor", "product", "version"))
        if not key.strip("\x00"):
            continue
        label = " ".join(
            part for part in (
                str(product.get("vendor") or ""),
                str(product.get("product") or ""),
                str(product.get("version") or ""),
            ) if part
        )
        product_id = graph.add_node(
            "product",
            key,
            label,
            status="identified",
            properties={
                "vendor": str(product.get("vendor") or "")[:200],
                "product": str(product.get("product") or "")[:300],
                "version": str(product.get("version") or "")[:120],
                "confidence": str(product.get("confidence") or "unknown")[:40],
                "source": str(product.get("source") or "")[:120],
            },
        )
        product_nodes[key] = product_id
        graph.add_edge(graph.root_id, product_id, "identified_as")

    for cve_id, record in (getattr(state, "cve_research", {}) or {}).items():
        correlation = record.get("correlation") if isinstance(record, dict) else {}
        vulnerability_id = graph.add_node(
            "vulnerability",
            str(cve_id),
            str(cve_id),
            status=str((correlation or {}).get("status") or "candidate"),
            properties={
                "cvss": (record.get("cvss") or {}).get("score")
                if isinstance(record, dict) and isinstance(record.get("cvss"), dict)
                else None,
                "known_exploited": bool(record.get("known_exploited")) if isinstance(record, dict) else False,
                "epss": record.get("epss") if isinstance(record, dict) else None,
            },
        )
        graph.add_edge(graph.root_id, vulnerability_id, "researched")

    for search in (getattr(state, "cve_product_searches", {}) or {}).values():
        if not isinstance(search, dict):
            continue
        fingerprint = search.get("fingerprint") if isinstance(search.get("fingerprint"), dict) else {}
        product_key = "\x00".join(
            str(fingerprint.get(field) or "") for field in ("vendor", "product", "version")
        )
        product_id = product_nodes.get(product_key, graph.root_id)
        for candidate in (search.get("candidates") or [])[:50]:
            if not isinstance(candidate, dict) or not candidate.get("cve_id"):
                continue
            vulnerability_id = graph.add_node(
                "vulnerability",
                str(candidate["cve_id"]),
                str(candidate["cve_id"]),
                status="candidate",
                properties={
                    "cvss": (candidate.get("cvss") or {}).get("score")
                    if isinstance(candidate.get("cvss"), dict) else None,
                    "known_exploited": bool(candidate.get("known_exploited")),
                    "epss": candidate.get("epss"),
                    "match": str(candidate.get("match") or "candidate")[:80],
                },
            )
            graph.add_edge(product_id, vulnerability_id, "candidate_exposure")

    run_nodes: dict[int, str] = {}
    for index, run in enumerate((getattr(state, "tool_history", []) or [])[:1_000]):
        if not isinstance(run, dict):
            continue
        tool = str(run.get("tool") or "unknown")
        run_id = graph.add_node(
            "tool_run",
            f"{target}:{index}:{tool}",
            tool,
            status="timed_out" if run.get("timed_out") else (
                "complete" if run.get("succeeded", run.get("exit_code") == 0) else "failed"
            ),
            properties={"tool": tool, "phase": str(run.get("phase") or "")[:40]},
        )
        run_nodes[index] = run_id
        graph.add_edge(graph.root_id, run_id, "executed")
        run_target = str(run.get("target") or "")
        for port in run.get("observed_ports") or []:
            try:
                service_id = service_nodes.get((run_target, int(port)))
            except (TypeError, ValueError):
                service_id = None
            if service_id:
                graph.add_edge(run_id, service_id, "observed")

    for finding_id, finding in finding_nodes:
        for index in getattr(finding, "source_run_indices", []) or []:
            if isinstance(index, int) and index in run_nodes:
                graph.add_edge(run_nodes[index], finding_id, "supports")

    for index, artifact in enumerate((getattr(state, "loot", []) or [])[:500]):
        if not isinstance(artifact, dict):
            continue
        access_id = graph.add_node(
            "access_artifact",
            f"{target}:{index}:{artifact.get('type')}:{artifact.get('source')}",
            str(artifact.get("type") or "access artifact"),
            status="obtained",
            properties={
                "service": str(artifact.get("service") or "")[:100],
                "host": str(artifact.get("host") or "")[:200],
                "port": artifact.get("port"),
                "source": str(artifact.get("source") or "")[:120],
                "contains_secret": any(artifact.get(key) not in (None, "") for key in ("password", "token", "session")),
            },
        )
        graph.add_edge(graph.root_id, access_id, "produced")
    return graph.build()


def graph_digest(graph: dict[str, Any]) -> str:
    """Useful in tests/exports to detect meaningful deterministic changes."""
    encoded = json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
