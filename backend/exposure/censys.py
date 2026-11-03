"""Summarize operator-supplied Censys host exports without contacting hosts."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from agent.fingerprints import identify_product_fingerprints, identify_vendor

MAX_EXPORT_BYTES = 2_000_000
MAX_RECORDS = 5_000
MAX_OBSERVATIONS = 500
MAX_SCANNED_OBSERVATIONS = 20_000
MAX_SCOPE_ENTRIES = 64

_IP = ("ip", "host.ip", "ip.address", "asset.id")
_TITLE = (
    "host.services.endpoints.http.html.title",
    "host.services.http.response.html.title",
    "services.http.response.html.title",
    "web.entity.instances.http.response.html.title",
    "http.html.title", "http.title", "html.title", "title",
)
_PORT = ("host.services.port", "services.port", "service.port", "port")
_PROTOCOL = (
    "host.services.service.name", "services.service.name", "service.name",
    "host.services.protocol", "services.protocol", "service.protocol", "protocol", "service",
)
_PRODUCT = ("host.services.software.product", "services.software.product", "software.product", "product", "software")
_VENDOR = ("host.services.software.vendor", "services.software.vendor", "software.vendor", "vendor")
_VERSION = ("host.services.software.version", "services.software.version", "software.version", "version")
_SCAN_TIME = ("host.services.scan.time", "services.scan.time", "scan.time", "last.observed")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_MANAGEMENT_TITLE = re.compile(r"\b(?:admin(?:istration)?|management|control\s+panel|dashboard|login)\b", re.IGNORECASE)
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._()+-]{0,79}")
# Explicit Censys Critical Infrastructure protocol labels; never infer these from a port.
_OT_PROTOCOLS = frozenset({
    "BACNET", "CIMON_PLC", "CMORE", "CMORE_HMI", "CODESYS", "DNP3", "EIP",
    "FINS", "FOX", "GE_SRTP", "HART", "IEC60870_5_104", "MELSEC", "MMS",
    "MODBUS", "OPC_UA", "PCOM", "PCWORX", "PROFINET", "S7",
    "REDLION_CRIMSON", "REDLION_WEB", "SCADA_VIEW",
})


def _clean(value: object, limit: int = 200) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    return re.sub(r"\s+", " ", _CONTROL.sub(" ", str(value))).strip()[:limit]


def _scope_networks(scope: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    entries = [item for item in re.split(r"[\s,]+", scope.strip()) if item]
    if not 1 <= len(entries) <= MAX_SCOPE_ENTRIES:
        raise ValueError("Enter 1 to 64 owned IP addresses or CIDR ranges")
    networks = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError("Scope accepts IP addresses and CIDR ranges only") from exc
        if (network.version == 4 and network.prefixlen < 16) or (
            network.version == 6 and network.prefixlen < 64
        ):
            raise ValueError("A scope range is too broad; use /16 or narrower for IPv4, /64 or narrower for IPv6")
        if network not in networks:
            networks.append(network)
    return networks


def _header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", ".", str(value or "").lower()).strip(".")


def _column(fieldnames: list[str], aliases: tuple[str, ...]) -> str | None:
    normalized = {_header(name): name for name in fieldnames}
    return next((normalized[name] for name in aliases if name in normalized), None)


def _field(record: dict[str, Any], aliases: tuple[str, ...]) -> object:
    key = _column(list(record), aliases)
    return record.get(key) if key else None


def _csv_rows(content: str) -> list[dict[str, Any]]:
    try:
        reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")))
        names = reader.fieldnames or []
        if len(names) > 100:
            raise ValueError("Censys CSV has too many columns")
        if not _column(names, _IP) or not any(
            _column(names, aliases) for aliases in (_TITLE, _PORT, _PROTOCOL, _PRODUCT)
        ):
            raise ValueError("Censys CSV needs an IP column and at least one service, port, product, or HTTP title column")
        rows = []
        for row in reader:
            if len(rows) >= MAX_RECORDS:
                raise ValueError("Censys export exceeds the 5,000-record limit")
            rows.append(row)
        if not rows:
            raise ValueError("Censys CSV contains no host records")
        return rows
    except csv.Error as exc:
        raise ValueError("Censys CSV could not be parsed") from exc


def _json_rows(filename: str, content: str) -> list[dict[str, Any]]:
    try:
        if filename.endswith(".jsonl"):
            rows = [json.loads(line) for line in content.splitlines() if line.strip()]
        else:
            payload = json.loads(content)
            if isinstance(payload, list):
                rows = payload
            elif isinstance(payload, dict):
                result = payload.get("result")
                rows = next((value for value in (
                    payload.get("hits"), payload.get("results"), payload.get("hosts"),
                    result.get("hits") if isinstance(result, dict) else None,
                ) if isinstance(value, list)), None)
                if rows is None:
                    rows = [payload]
            else:
                rows = []
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Censys JSON could not be parsed") from exc
    if not rows or len(rows) > MAX_RECORDS or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Censys JSON must contain 1 to 5,000 host records")
    return rows


def _port(value: object) -> int | None:
    try:
        parsed = int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None
    return parsed if parsed is not None and 1 <= parsed <= 65535 else None


def _title(value: object) -> str:
    if isinstance(value, list):
        candidates = [_clean(item) for item in value if isinstance(item, str) and item.strip()]
        return next((item for item in candidates if identify_product_fingerprints(
            item, source="Censys title"
        )), candidates[0] if candidates else "")
    if isinstance(value, str) and value.lstrip().startswith("["):
        try:
            return _title(json.loads(value))
        except (json.JSONDecodeError, RecursionError):
            pass
    return _clean(value)


def _http_title(http: object) -> str:
    if not isinstance(http, dict):
        return ""
    response = http.get("response")
    if isinstance(response, dict) and response.get("html_title") is not None:
        return _title(response["html_title"])
    return _title(http.get("html_title"))


def _software(value: object) -> tuple[str, str, str]:
    if isinstance(value, list):
        value = next((item for item in value if isinstance(item, (str, dict))), None)
    if isinstance(value, dict):
        return (_clean(value.get("vendor"), 80), _clean(value.get("product") or value.get("name"), 120),
                _clean(value.get("version"), 80))
    return ("", _clean(value, 120), "")


def _observation(port: object = None, protocol: object = None, title: object = None,
                 software: object = None, scan_time: object = None) -> dict[str, Any] | None:
    vendor, product, version = _software(software)
    observed_at = _clean(scan_time, 40)
    item = {
        "port": _port(port), "protocol": _clean(protocol, 40), "title": _title(title),
        "reported_vendor": vendor, "reported_product": product,
        "reported_version": version if _SAFE_VERSION.fullmatch(version) else "",
        "scan_time": observed_at if re.match(r"^\d{4}-\d{2}-\d{2}", observed_at) else "",
    }
    return item if any(item[key] for key in ("port", "protocol", "title", "reported_product")) else None


def _service_observations(service: object) -> list[dict[str, Any]]:
    if not isinstance(service, dict):
        return []
    base = {
        "port": service.get("port"),
        "protocol": service.get("service_name") or service.get("protocol"),
        "software": service.get("software"), "scan_time": service.get("scan_time"),
    }
    direct_title = _http_title(service.get("http")) or service.get("html_title")
    endpoint_observations = []
    endpoints = service.get("endpoints")
    if isinstance(endpoints, list):
        if len(endpoints) > 100:
            raise ValueError("A Censys service has too many endpoints for a complete import")
        for endpoint in endpoints[:100]:
            if not isinstance(endpoint, dict):
                continue
            title = _http_title(endpoint.get("http"))
            if title:
                detail = _observation(**{**base, "port": endpoint.get("port") or base["port"]}, title=title)
                if detail:
                    endpoint_observations.append(detail)
    direct = _observation(**base, title=direct_title)
    return ([direct] if direct and (direct_title or not endpoint_observations) else []) + endpoint_observations


def _record_ip(record: dict[str, Any]) -> object:
    host = record.get("host") if isinstance(record.get("host"), dict) else {}
    return _field(record, _IP) or host.get("ip")


def _record_observations(record: dict[str, Any]) -> list[dict[str, Any]]:
    host = record.get("host") if isinstance(record.get("host"), dict) else {}
    observations = []
    flat = _observation(
        port=_field(record, _PORT), protocol=_field(record, _PROTOCOL),
        title=_field(record, _TITLE),
        software={"vendor": _field(record, _VENDOR), "product": _field(record, _PRODUCT),
                  "version": _field(record, _VERSION)},
        scan_time=_field(record, _SCAN_TIME),
    )
    if flat:
        observations.append(flat)
    for container in (record, host):
        for key in ("services", "matched_services"):
            services = container.get(key)
            if isinstance(services, list):
                if len(services) > 100:
                    raise ValueError("A Censys host has too many services for a complete import")
                for service in services[:100]:
                    observations.extend(_service_observations(service))
    return observations


def _present_observation(ip: str, item: dict[str, Any]) -> dict[str, Any]:
    evidence_text = " ".join((item["title"], item["reported_vendor"], item["reported_product"],
                              item["reported_version"]))
    identities = identify_product_fingerprints(evidence_text, source="Censys export")
    identity = identities[0] if identities else None
    vendor = identity["vendor"] if identity else (item["reported_vendor"] or identify_vendor(evidence_text))
    product = identity["product"] if identity else item["reported_product"]
    version = identity["version"] if identity and identity["version"] else item["reported_version"]
    category = identity["category"] if identity else "unclassified"
    protocol_key = re.sub(r"[^A-Z0-9]+", "_", item["protocol"].upper()).strip("_")
    if category == "industrial_control" or (identity and identity["fingerprint_id"] == "siemens-industrial"):
        group, review_basis = "OT / control", "AEGIS signature"
    elif protocol_key in _OT_PROTOCOLS:
        group, review_basis = "OT / control", "Censys protocol"
    elif category in {"bmc", "cloud_management", "hypervisor", "hypervisor_management",
                      "network_appliance", "server_management", "storage_management"}:
        group, review_basis = "Management candidate", "AEGIS category"
    elif _MANAGEMENT_TITLE.search(item["title"]):
        group, review_basis = "Management candidate", "Page title"
    else:
        group, review_basis = "Other service", ""
    return {
        "ip": ip, "port": item["port"], "protocol": item["protocol"],
        "title": item["title"], "vendor": vendor, "product": product,
        "version": version, "category": category, "review_group": group,
        "review_basis": review_basis,
        "identity_source": "AEGIS signature" if identity else (
            "Censys software field" if item["reported_product"] else "unclassified"
        ),
        "scan_time": item["scan_time"], "patch_status": "unknown",
    }


def analyze_censys_export(filename: str, content: str, scope: str) -> dict[str, Any]:
    """Return bounded in-scope observations; never resolve names or make requests."""
    networks = _scope_networks(scope)
    try:
        content_bytes = len(content.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("Censys export contains invalid text") from exc
    if content_bytes > MAX_EXPORT_BYTES:
        raise ValueError("Censys export exceeds the 2 MB limit")
    suffix = Path(filename).suffix.lower()
    if suffix == ".csv":
        rows = _csv_rows(content)
    elif suffix in {".json", ".jsonl"}:
        rows = _json_rows(filename.lower(), content)
    else:
        raise ValueError("Choose a Censys .csv, .json, or .jsonl export")

    counts = {"records_total": len(rows), "records_in_scope": 0,
              "records_out_of_scope": 0, "records_invalid_ip": 0,
              "records_without_service": 0}
    observed: dict[tuple[str, int | None, str, str], dict[str, Any]] = {}
    scanned_observations = 0
    for record in rows:
        raw_ip = _record_ip(record)
        try:
            address = ipaddress.ip_address(str(raw_ip or ""))
        except ValueError:
            counts["records_invalid_ip"] += 1
            continue
        if not any(address in network for network in networks if address.version == network.version):
            counts["records_out_of_scope"] += 1
            continue
        counts["records_in_scope"] += 1
        observations = _record_observations(record)
        scanned_observations += len(observations)
        if scanned_observations > MAX_SCANNED_OBSERVATIONS:
            raise ValueError("Censys export has too many service observations for a complete import")
        if not observations:
            counts["records_without_service"] += 1
        for item in observations:
            candidate = _present_observation(str(address), item)
            key = (candidate["ip"], candidate["port"], candidate["protocol"], candidate["title"])
            existing = observed.get(key)
            if not existing or (existing["identity_source"] == "unclassified" and
                                candidate["identity_source"] != "unclassified"):
                observed[key] = candidate
    if counts["records_in_scope"] and not observed:
        raise ValueError("In-scope Censys records have no service data; include port, protocol, product, or HTTP title fields")
    priority = {"OT / control": 0, "Management candidate": 1, "Other service": 2}
    ordered = sorted(observed.values(), key=lambda item: (
        priority[item["review_group"]], ipaddress.ip_address(item["ip"]).version,
        int(ipaddress.ip_address(item["ip"])), item["port"] or 0,
    ))
    returned = ordered[:MAX_OBSERVATIONS]
    return {
        **counts, "scope": [str(network) for network in networks],
        "observations_total": len(ordered), "observations_returned": len(returned),
        "observations_omitted": max(0, len(ordered) - MAX_OBSERVATIONS),
        "identified_total": sum(bool(item["product"]) for item in ordered),
        "ot_total": sum(item["review_group"] == "OT / control" for item in ordered),
        "observations": returned, "network_requests": 0,
        "interpretation": "Imported exposure observations only. Current reachability, support status, patch state, vulnerability, and compromise are unverified.",
    }
