"""Bounded passive lookups against fixed public-index APIs; never contact assets."""
from __future__ import annotations

import asyncio
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from agent.cve import search_cve_candidates
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
MAX_WORLD_START = 9_980
MAX_VULNERABILITY_ROWS = 256
MAX_CVE_PRODUCT_SEARCHES = 3
MAX_CVES_PER_PRODUCT = 8
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
            cve_candidates: list[str] | None = None,
            vulnerabilities: list[dict[str, Any]] | None = None,
            cve_data_status: str = "not_applicable", note: str = "") -> dict[str, Any]:
    return {
        "target": target, "kind": kind, "source": source, "status": status,
        "observations": observations or [], "cve_candidates": cve_candidates or [],
        "vulnerabilities": vulnerabilities or [], "cve_data_status": cve_data_status,
        "kev_matches": [], "note": note,
    }


def _cve_id(value: Any) -> str:
    candidate = str(value or "").upper()
    return candidate if _CVE.fullmatch(candidate) else ""


def _cvss_score(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return round(score, 1) if 0 <= score <= 10 else None


def _censys_cvss(vulnerability: dict[str, Any]) -> tuple[float | None, str]:
    metrics = vulnerability.get("metrics")
    if not isinstance(metrics, dict):
        return None, ""
    versions = (
        ("cvss_v40", "4.0"), ("cvss_v31", "3.1"),
        ("cvss_v30", "3.0"), ("cvss_v3_1", "3.1"),
        ("cvss_v3_0", "3.0"), ("cvss_v2", "2.0"),
    )
    for key, label in versions:
        metric = metrics.get(key)
        candidates = metric if isinstance(metric, list) else [metric]
        for candidate in candidates:
            score = _cvss_score(candidate.get("score") if isinstance(candidate, dict) else candidate)
            if score is not None:
                return score, label
    return None, ""


def _censys_vulnerability_entries(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item if isinstance(item, dict) else {"id": item}
                for item in value if isinstance(item, (dict, str))]
    if not isinstance(value, dict):
        return []
    if _cve_id(value.get("id")):
        return [value]
    entries = []
    for key, item in value.items():
        cve = _cve_id(key)
        if not cve:
            continue
        entries.append({**item, "id": cve} if isinstance(item, dict) else {"id": cve})
    return entries


def _censys_vulnerabilities(resource: dict[str, Any], source: str) -> tuple[
    list[dict[str, Any]], str, int,
]:
    services = resource.get("services")
    if not isinstance(services, list):
        return [], "not_provided", 0
    rows: list[dict[str, Any]] = []
    field_present = False
    omitted = 0
    seen: set[tuple[str, int | None, str]] = set()
    for service in services[:100]:
        if not isinstance(service, dict) or "vulns" not in service:
            continue
        field_present = True
        port = service.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            representative = service.get("representative_info")
            port = representative.get("sampled_port") if isinstance(representative, dict) else None
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            port = None
        protocol = _clean(service.get("protocol"), 40).upper()
        entries = _censys_vulnerability_entries(service.get("vulns"))
        for entry in entries:
            cve = _cve_id(entry.get("id"))
            key = (cve, port, protocol)
            if not cve or key in seen:
                continue
            seen.add(key)
            if len(rows) >= MAX_VULNERABILITY_ROWS:
                omitted += 1
                continue
            score, version = _censys_cvss(entry)
            severity = _clean(entry.get("severity"), 20).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                severity = ""
            rows.append({
                "id": cve,
                "source": source,
                "service_port": port,
                "service_protocol": protocol,
                "severity": severity,
                "cvss_score": score,
                "cvss_version": version,
                "provider_kev": (entry.get("kev") is True
                                 or isinstance(entry.get("kev"), dict)
                                 or str(entry.get("kev") or "").lower() in {"yes", "true", "1"}),
                "cisa_kev": None,
                "basis": "Censys associated the observed service software with this CVE by CPE.",
            })
    status = "reported" if rows else "no_matches" if field_present else "not_provided"
    return rows, status, omitted


def _cve_products(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for record_index, record in enumerate(records):
        if (record.get("source") != "Censys Platform"
                or record.get("kind") != "ip"
                or record.get("cve_data_status") == "reported"):
            continue
        for observation in record.get("observations") or []:
            if (not isinstance(observation, dict)
                    or observation.get("identity_source") != "Censys Platform software field"):
                continue
            vendor = _clean(observation.get("vendor"), 120)
            product = _clean(observation.get("product"), 200)
            if not vendor or not product:
                continue
            key = (str(record.get("target") or ""), vendor.lower(), product.lower())
            if key in seen:
                continue
            seen.add(key)
            products.append({
                "record_index": record_index, "vendor": vendor, "product": product,
                "version": _clean(observation.get("version"), 80),
                "port": observation.get("port"),
                "protocol": _clean(observation.get("protocol"), 40).upper(),
            })
            if len(products) >= MAX_CVE_PRODUCT_SEARCHES:
                return products
    return products


async def _search_product_cves(products: list[dict[str, Any]]) -> tuple[
    list[tuple[dict[str, Any], dict[str, Any]]], list[str],
]:
    results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    warnings: list[str] = []
    for product in products:
        try:
            response = await search_cve_candidates(
                f"{product['vendor']} {product['product']}",
                vendor=product["vendor"], product=product["product"],
                limit=MAX_CVES_PER_PRODUCT,
            )
            results.append((product, response))
        except (httpx.HTTPError, RuntimeError, ValueError):
            warnings.append(
                f"CVE index lookup unavailable for {product['vendor']} {product['product']}"
            )
    return results, warnings


def _enrich_product_cves(records: list[dict[str, Any]]) -> dict[str, Any]:
    products = _cve_products(records)
    if not products:
        return {"status": "not_applicable", "products_checked": 0, "candidates_added": 0}
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        results, warnings = asyncio.run(_search_product_cves(products))
    else:
        return {
            "status": "unavailable", "products_checked": 0, "candidates_added": 0,
            "warning": "CVE product enrichment requires the worker-thread lookup path",
        }
    added = 0
    for product, response in results:
        record = records[product["record_index"]]
        existing = {
            (item.get("id"), item.get("service_port"), item.get("service_protocol"))
            for item in record["vulnerabilities"]
        }
        product_added = 0
        for candidate in response.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            cve = _cve_id(candidate.get("cve_id"))
            key = (cve, product["port"], product["protocol"])
            if not cve or key in existing or len(record["vulnerabilities"]) >= MAX_VULNERABILITY_ROWS:
                continue
            existing.add(key)
            cvss = candidate.get("cvss") if isinstance(candidate.get("cvss"), dict) else {}
            severity = _clean(cvss.get("severity"), 20).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                severity = ""
            database = _clean(candidate.get("database") or response.get("source"), 160)
            record["vulnerabilities"].append({
                "id": cve, "source": database or "CVE product index",
                "service_port": product["port"],
                "service_protocol": product["protocol"],
                "severity": severity, "cvss_score": _cvss_score(cvss.get("score")),
                "cvss_version": _clean(cvss.get("version"), 20),
                "provider_kev": False, "cisa_kev": None,
                "basis": (
                    f"The CVE index matched Censys-reported {product['vendor']} "
                    f"{product['product']}; installed-version applicability is unverified."
                ),
            })
            record["cve_candidates"].append(cve)
            product_added += 1
            added += 1
        record["cve_candidates"] = sorted(set(record["cve_candidates"]))
        if product_added:
            record["cve_data_status"] = "reported"
            record["note"] += (
                f" AEGIS added {product_added} bounded CVE-index candidates for the "
                "provider-reported product."
            )
    status = "partial" if warnings else "complete"
    if not results:
        status = "unavailable"
    return {
        "status": status, "products_checked": len(results),
        "candidates_added": added, "warnings": warnings,
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
    raw_vulns = payload.get("vulns")
    candidates = sorted({_cve_id(value) for value in (raw_vulns or [])[:128]
                         if isinstance(value, str) and _cve_id(value)}) if isinstance(raw_vulns, list) else []
    vulnerabilities = [{
        "id": cve, "source": source, "service_port": None,
        "service_protocol": "", "severity": "", "cvss_score": None,
        "cvss_version": "", "provider_kev": False, "cisa_kev": None,
        "basis": "Shodan reported a host-level CVE suggestion without a service match.",
    } for cve in candidates]
    note = "Host-level CVE suggestions can be unverified; ports do not identify protocols."
    if len(ports) > 128:
        note += f" {len(ports) - 128} additional ports omitted."
    if isinstance(payload.get("vulns"), list) and len(payload["vulns"]) > 128:
        note += f" {len(payload['vulns']) - 128} additional CVE suggestions omitted."
    return _record(
        ip, "ip", source, "observed", observations,
        cve_candidates=candidates, vulnerabilities=vulnerabilities,
        cve_data_status=("reported" if candidates else "no_matches"
                         if isinstance(raw_vulns, list) else "not_provided"),
        note=note,
    )


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
        vulnerabilities, cve_data_status, omitted = _censys_vulnerabilities(resource, source)
        candidates = sorted({item["id"] for item in vulnerabilities})
        if omitted:
            note += f" {omitted} additional service/CVE associations omitted."
        if cve_data_status == "not_provided":
            note += " CVE fields were not included in this API response; access can depend on the Censys plan and record."
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
        vulnerabilities = []
        candidates = []
        cve_data_status = "not_applicable"
    return _record(
        target, kind, source, "observed", observations,
        cve_candidates=candidates, vulnerabilities=vulnerabilities,
        cve_data_status=cve_data_status, note=note,
    )


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


def _netlas_search(client: httpx.Client, query: str, token: str,
                   start: int) -> tuple[str, list[dict[str, Any]], str, int]:
    source = "Netlas Responses Search"
    try:
        status, payload = _get_json(client, NETLAS_URL,
                                    headers={"Authorization": f"Bearer {token}"} if token else None,
                                    params={"q": query, "start": str(start), "fields": NETLAS_FIELDS,
                                            "source_type": "include"})
    except (httpx.HTTPError, ValueError):
        return "unavailable", [], _failure(source), 0
    if status != 200:
        return "unavailable", [], _failure(source, status), 0
    try:
        rows = _netlas_observations(payload, source)
    except ValueError:
        return "unavailable", [], "Netlas returned an invalid search result", 0
    count = len(payload["items"])
    note = f"Page {start // MAX_WORLD_RESULTS + 1}; up to 20 indexed responses per page. No target was contacted."
    if count >= MAX_WORLD_RESULTS and start < MAX_WORLD_START:
        note += " More results may exist."
    return "observed" if rows else "no_record", rows, note, count


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
        product_enrichment = _enrich_product_cves(records)
        cves = sorted({cve for record in records for cve in record["cve_candidates"]})
        kev_status = "not_applicable"
        if cves:
            try:
                catalog = _kev_catalog(client)
                kev_status = "complete"
                for record in records:
                    record["kev_matches"] = [cve for cve in record["cve_candidates"] if cve in catalog]
                    for vulnerability in record["vulnerabilities"]:
                        vulnerability["cisa_kev"] = vulnerability["id"] in catalog
            except (httpx.HTTPError, ValueError):
                kev_status = "unavailable"
        return {
            "mode": "owned", "checked_at": datetime.now(timezone.utc).isoformat(),
            "targets_total": len(parsed), "records": records,
            "cve_candidates_total": len(cves),
            "kev_matches_total": len({cve for record in records for cve in record["kev_matches"]}),
            "kev_status": kev_status, "censys_credits_planned": censys_calls,
            "cve_product_enrichment": product_enrichment,
            "interpretation": "Passive index observations and CVE suggestions only; asset vulnerability, patch state, and compromise are unverified.",
        }
    finally:
        if owns_client:
            client.close()


def search_world(query: str, *, netlas_key: str = "", start: int = 0,
                 client: httpx.Client | None = None) -> dict[str, Any]:
    """Read one requested Netlas page without following up against discovered assets."""
    query = query.strip()
    if (not 3 <= len(query) <= 160 or query in {"*", "*:*"}
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in query)):
        raise ValueError("Enter a specific Netlas query of 3 to 160 characters")
    netlas_key = _secret(netlas_key, "Netlas API key")
    if (not isinstance(start, int) or isinstance(start, bool) or start < 0
            or start > MAX_WORLD_START or start % MAX_WORLD_RESULTS):
        raise ValueError("Netlas page offset must be 0 to 9980 in steps of 20")
    owns_client = client is None
    client = client if client is not None else _client()
    try:
        status, observations, note, provider_count = _netlas_search(client, query, netlas_key, start)
        return {
            "mode": "world", "checked_at": datetime.now(timezone.utc).isoformat(),
            "source": "Netlas Responses Search", "status": status,
            "query": query, "observations": observations, "note": note,
            "start": start, "page": start // MAX_WORLD_RESULTS + 1,
            "page_size": MAX_WORLD_RESULTS, "has_previous": start > 0,
            "has_next": provider_count >= MAX_WORLD_RESULTS and start < MAX_WORLD_START,
            "interpretation": "Passive search leads only. These assets may belong to others; exposure does not prove vulnerability or compromise.",
        }
    finally:
        if owns_client:
            client.close()
