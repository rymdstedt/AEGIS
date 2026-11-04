"""Bounded passive lookups against fixed public-index APIs; never contact assets."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from agent.risk import _kev_catalog

from exposure.censys import (
    _clean,
    _http_title,
    _observation,
    _present_observation,
    _record_observations,
)

SHODAN_URL = "https://internetdb.shodan.io"
CENSYS_URL = "https://api.platform.censys.io/v3/global/asset"
NETLAS_URL = "https://app.netlas.io/api/responses/"
NETLAS_HOST_URL = "https://app.netlas.io/api/host"
NETLAS_FIELDS = "ip,host,port,protocol,prot7,http.title,last_updated"
NETLAS_HOST_FIELDS = "ip,domain,ports"
MAX_TARGETS = 16
MAX_GUEST_TARGETS = 5
MAX_PROVIDER_BYTES = 2_000_000
MAX_WORLD_RESULTS = 20
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(8.0, connect=4.0),
        follow_redirects=False,
        headers={"User-Agent": "AEGIS passive exposure inventory/1"},
    )


def _secret(value: str, label: str) -> str:
    if value and (not 10 <= len(value) <= 512 or any(ord(ch) < 33 or ord(ch) > 126 for ch in value)):
        raise ValueError(f"{label} must be a single printable token of 10 to 512 characters")
    return value


def _targets(text: str) -> list[tuple[str, str]]:
    raw = [entry for entry in re.split(r"[\s,]+", text.strip()) if entry]
    if not raw or len(raw) > MAX_TARGETS:
        raise ValueError("Enter 1 to 16 public IPs, small CIDR ranges, or domains")
    targets: list[tuple[str, str]] = []
    for entry in raw:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            try:
                domain = entry.encode("idna").decode("ascii").lower().rstrip(".")
            except UnicodeError as exc:
                raise ValueError("Enter valid IP addresses, CIDRs, or domain names") from exc
            labels = domain.split(".")
            if (len(domain) > 253 or len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
                    or labels[-1].isdigit()):
                raise ValueError("Enter valid public domain names without URLs or wildcards")
            item = ("domain", domain)
            if item not in targets:
                targets.append(item)
            continue
        if network.num_addresses > MAX_TARGETS:
            raise ValueError("A CIDR range may contain at most 16 addresses per check")
        for address in network:
            if not address.is_global:
                raise ValueError("Automatic lookup accepts public IP addresses only")
            item = ("ip", str(address))
            if item not in targets:
                targets.append(item)
        if len(targets) > MAX_TARGETS:
            raise ValueError("A check may include at most 16 distinct targets")
    if len(targets) > MAX_TARGETS:
        raise ValueError("A check may include at most 16 distinct targets")
    return targets


def _get_json(client: httpx.Client, url: str, *, headers: dict[str, str] | None = None,
              params: dict[str, str] | None = None) -> tuple[int, Any]:
    body = bytearray()
    with client.stream("GET", url, headers=headers, params=params) as response:
        status = response.status_code
        if status != 200:
            return status, None
        for chunk in response.iter_bytes(65_536):
            body.extend(chunk)
            if len(body) > MAX_PROVIDER_BYTES:
                raise ValueError("Provider response exceeded the 2 MB safety limit")
    try:
        return 200, httpx.Response(200, content=bytes(body)).json()
    except ValueError as exc:
        raise ValueError("Provider returned invalid JSON") from exc


def _failure(source: str, status: int | None = None) -> str:
    if status == 404:
        return "No indexed record"
    if status == 401:
        return f"{source} rejected the API token"
    if status == 402:
        return f"{source} credits are exhausted"
    if status == 403:
        return f"{source} access is not available to this account"
    if status == 429:
        return f"{source} rate or daily limit reached"
    return f"{source} lookup unavailable"


def _record(target: str, kind: str, source: str, status: str,
            observations: list[dict[str, Any]] | None = None, *,
            cve_candidates: list[str] | None = None, note: str = "") -> dict[str, Any]:
    return {
        "target": target, "kind": kind, "source": source, "status": status,
        "observations": observations or [], "cve_candidates": cve_candidates or [],
        "kev_matches": [], "note": note,
    }


def _shodan_lookup(client: httpx.Client, ip: str) -> dict[str, Any]:
    source = "Shodan InternetDB"
    try:
        status, payload = _get_json(client, f"{SHODAN_URL}/{ip}")
    except (httpx.HTTPError, ValueError):
        return _record(ip, "ip", source, "unavailable", note=_failure(source))
    if status != 200:
        return _record(ip, "ip", source, "no_record" if status == 404 else "unavailable",
                       note=_failure(source, status))
    if not isinstance(payload, dict) or payload.get("ip") != ip:
        return _record(ip, "ip", source, "unavailable", note="Shodan returned an invalid host record")
    ports = payload.get("ports")
    if not isinstance(ports, list):
        return _record(ip, "ip", source, "unavailable", note="Shodan returned an invalid port list")
    observations = []
    for port in ports[:128]:
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            item = _observation(port=port)
            if item:
                observations.append(_present_observation(ip, item, source))
    candidates = sorted({str(value).upper() for value in (payload.get("vulns") or [])[:128]
                         if isinstance(value, str) and _CVE.fullmatch(value)}) if isinstance(payload.get("vulns"), list) else []
    note = "Host-level CVE suggestions can be unverified; ports do not identify protocols."
    if len(ports) > 128:
        note += f" {len(ports) - 128} additional ports omitted."
    if isinstance(payload.get("vulns"), list) and len(payload["vulns"]) > 128:
        note += f" {len(payload['vulns']) - 128} additional CVE suggestions omitted."
    return _record(ip, "ip", source, "observed", observations,
                   cve_candidates=candidates, note=note)


def _censys_lookup(client: httpx.Client, target: str, kind: str, port: int | None,
                   token: str) -> dict[str, Any]:
    source = "Censys Platform"
    path = f"host/{target}" if kind == "ip" else f"webproperty/{target}:{port}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": f"application/vnd.censys.api.v3.{'host' if kind == 'ip' else 'webproperty'}.v1+json",
    }
    try:
        status, payload = _get_json(client, f"{CENSYS_URL}/{path}", headers=headers)
    except (httpx.HTTPError, ValueError):
        return _record(target, kind, source, "unavailable", note=_failure(source))
    if status != 200:
        return _record(target, kind, source, "no_record" if status == 404 else "unavailable",
                       note=_failure(source, status))
    result = payload.get("result") if isinstance(payload, dict) else None
    resource = result.get("resource") if isinstance(result, dict) else None
    if not isinstance(resource, dict):
        return _record(target, kind, source, "unavailable", note="Censys returned an invalid asset record")
    observations: list[dict[str, Any]] = []
    note = "Censys observation; current reachability and patch state are unverified."
    if kind == "ip":
        if resource.get("ip") != target:
            return _record(target, kind, source, "unavailable", note="Censys returned a different IP")
        try:
            raw = _record_observations(resource)
            observations = [_present_observation(target, item, source) for item in raw[:100]]
            if len(raw) > 100:
                note += f" {len(raw) - 100} additional service observations omitted."
        except ValueError:
            return _record(target, kind, source, "unavailable", note="Censys host had too many services")
    else:
        if str(resource.get("hostname") or "").lower() != target or resource.get("port") != port:
            return _record(target, kind, source, "unavailable", note="Censys returned a different web property")
        endpoints = resource.get("endpoints")
        title = ""
        if isinstance(endpoints, list):
            for endpoint in endpoints[:20]:
                if isinstance(endpoint, dict):
                    title = _http_title(endpoint.get("http")) or title
                    if title:
                        break
            if len(endpoints) > 20:
                note += f" {len(endpoints) - 20} web endpoints were not reviewed."
        item = _observation(port=port, protocol="HTTPS" if port == 443 else "HTTP",
                            title=title, scan_time=resource.get("scan_time"))
        if item:
            observations = [_present_observation(target, item, source)]
    return _record(target, kind, source, "observed", observations, note=note)


def _netlas_observations(payload: Any, source: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("Netlas returned an invalid search result")
    observations = []
    for result in payload["items"][:MAX_WORLD_RESULTS]:
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            continue
        try:
            ip = ipaddress.ip_address(str(data.get("ip") or ""))
        except ValueError:
            continue
        if not ip.is_global:
            continue
        http = data.get("http")
        title = _clean(http.get("title")) if isinstance(http, dict) else ""
        item = _observation(port=data.get("port"), protocol=data.get("protocol") or data.get("prot7"),
                            title=title, scan_time=data.get("last_updated"))
        if not item:
            continue
        presented = _present_observation(str(ip), item, source)
        presented["host"] = _clean(data.get("host"), 253)
        observations.append(presented)
    return observations


def _netlas_search(client: httpx.Client, query: str, token: str) -> tuple[str, list[dict[str, Any]], str]:
    source = "Netlas Responses Search"
    try:
        status, payload = _get_json(client, NETLAS_URL,
                                    headers={"Authorization": f"Bearer {token}"} if token else None,
                                    params={"q": query, "start": "0", "fields": NETLAS_FIELDS,
                                            "source_type": "include"})
    except (httpx.HTTPError, ValueError):
        return "unavailable", [], _failure(source)
    if status != 200:
        return "unavailable", [], _failure(source, status)
    try:
        rows = _netlas_observations(payload, source)
    except ValueError:
        return "unavailable", [], "Netlas returned an invalid search result"
    count = len(payload["items"])
    note = "First 20 indexed responses only; no target was contacted."
    if count >= MAX_WORLD_RESULTS:
        note += " More results may exist."
    return "observed" if rows else "no_record", rows, note


def _netlas_host_lookup(client: httpx.Client, target: str, kind: str, token: str) -> dict[str, Any]:
    source = "Netlas Host Summary"
    try:
        status, payload = _get_json(
            client, f"{NETLAS_HOST_URL}/{target}/",
            headers={"Authorization": f"Bearer {token}"} if token else None,
            params={"fields": NETLAS_HOST_FIELDS, "source_type": "include",
                    "public_indices_only": "true"},
        )
    except (httpx.HTTPError, ValueError):
        return _record(target, kind, source, "unavailable", note=_failure(source))
    if status != 200:
        return _record(target, kind, source, "no_record" if status == 404 else "unavailable",
                       note=_failure(source, status))
    if (not isinstance(payload, dict) or payload.get("ip" if kind == "ip" else "domain") != target
            or not isinstance(payload.get("ports"), list)):
        return _record(target, kind, source, "unavailable", note="Netlas returned an invalid host summary")
    ports = payload["ports"]
    observations = []
    for service in ports[:128]:
        if not isinstance(service, dict):
            continue
        item = _observation(port=service.get("port"),
                            protocol=service.get("protocol") or service.get("prot7"))
        if item:
            observations.append(_present_observation(target, item, source))
    note = "Public index summary; current reachability and patch state are unverified."
    if len(ports) > 128:
        note += f" {len(ports) - 128} additional services omitted."
    return _record(target, kind, source, "observed" if observations else "no_record",
                   observations, note=note)


def check_owned(targets: str, *, censys_pat: str = "", netlas_key: str = "",
                client: httpx.Client | None = None) -> dict[str, Any]:
    """Look up up to 16 operator-supplied assets in passive indexes."""
    parsed = _targets(targets)
    censys_pat = _secret(censys_pat, "Censys PAT")
    netlas_key = _secret(netlas_key, "Netlas API key")
    if not netlas_key and len(parsed) > MAX_GUEST_TARGETS:
        raise ValueError("Guest Netlas checks are limited to five targets; use a Netlas key for up to 16")
    censys_calls = sum(1 if kind == "ip" else 2 for kind, _ in parsed) if censys_pat else 0
    if censys_calls > 10:
        raise ValueError("This check would spend more than 10 Censys lookup credits; reduce the target list")
    records: list[dict[str, Any]] = []
    owns_client = client is None
    client = client if client is not None else _client()
    try:
        for kind, target in parsed:
            records.append(_netlas_host_lookup(client, target, kind, netlas_key))
            if kind == "ip":
                records.append(_shodan_lookup(client, target))
                if censys_pat:
                    records.append(_censys_lookup(client, target, kind, None, censys_pat))
            else:
                if censys_pat:
                    for port in (80, 443):
                        record = _censys_lookup(client, target, kind, port, censys_pat)
                        record["web_port"] = port
                        records.append(record)
        cves = sorted({cve for record in records for cve in record["cve_candidates"]})
        kev_status = "not_applicable"
        if cves:
            try:
                catalog = _kev_catalog(client)
                kev_status = "complete"
                for record in records:
                    record["kev_matches"] = [cve for cve in record["cve_candidates"] if cve in catalog]
            except (httpx.HTTPError, ValueError):
                kev_status = "unavailable"
        return {
            "mode": "owned", "checked_at": datetime.now(timezone.utc).isoformat(),
            "targets_total": len(parsed), "records": records,
            "cve_candidates_total": len(cves),
            "kev_matches_total": len({cve for record in records for cve in record["kev_matches"]}),
            "kev_status": kev_status, "censys_credits_planned": censys_calls,
            "interpretation": "Passive index observations and CVE suggestions only; asset vulnerability, patch state, and compromise are unverified.",
        }
    finally:
        if owns_client:
            client.close()


def search_world(query: str, *, netlas_key: str = "", client: httpx.Client | None = None) -> dict[str, Any]:
    """Read one Netlas search page without following up against discovered assets."""
    query = query.strip()
    if (not 3 <= len(query) <= 160 or query in {"*", "*:*"}
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in query)):
        raise ValueError("Enter a specific Netlas query of 3 to 160 characters")
    netlas_key = _secret(netlas_key, "Netlas API key")
    owns_client = client is None
    client = client if client is not None else _client()
    try:
        status, observations, note = _netlas_search(client, query, netlas_key)
        return {
            "mode": "world", "checked_at": datetime.now(timezone.utc).isoformat(),
            "source": "Netlas Responses Search", "status": status,
            "query": query, "observations": observations, "note": note,
            "interpretation": "Passive search leads only. These assets may belong to others; exposure does not prove vulnerability or compromise.",
        }
    finally:
        if owns_client:
            client.close()
