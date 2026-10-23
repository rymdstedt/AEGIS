"""Bounded CVE retrieval, product fingerprinting, and correlation helpers.

The scanner treats public vulnerability records as reference data, never as
proof that a target is vulnerable.  A CVE becomes a target finding only when
an observed vendor/product identity overlaps an affected product entry.  Even
then, the result remains *potentially affected* until the installed version is
known and can be compared with the vendor's affected-version rules.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

import httpx

from agent.fingerprints import identify_product_fingerprints

CVE_ID_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)
CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_PRODUCT_SEARCH_URL = (
    "https://vulnerability.circl.lu/api/vulnerability/search/{vendor}/{product}"
)
CIRCL_API_DOCS_URL = "https://vulnerability.circl.lu/api/"
MAX_CVE_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_AFFECTED_PRODUCTS = 800
MAX_REFERENCES = 24


def extract_cve_ids(value: str, *, limit: int = 20) -> list[str]:
    """Return unique, canonical CVE IDs in their original order."""
    found: list[str] = []
    for match in CVE_ID_RE.finditer(str(value or "")):
        cve_id = match.group(0).upper()
        if cve_id not in found:
            found.append(cve_id)
        if len(found) >= limit:
            break
    return found


def validate_cve_id(value: str) -> str:
    cve_id = str(value or "").strip().upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        raise ValueError("CVE ID must use the form CVE-YYYY-NNNN")
    return cve_id


def _clean_text(value: object, limit: int) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _english_description(items: object) -> str:
    if not isinstance(items, list):
        return ""
    for item in items:
        if isinstance(item, dict) and str(item.get("lang") or "").lower().startswith("en"):
            return _clean_text(item.get("value"), 2400)
    for item in items:
        if isinstance(item, dict) and item.get("value"):
            return _clean_text(item.get("value"), 2400)
    return ""


def _cvss_from_containers(containers: list[dict[str, Any]]) -> dict[str, object]:
    choices: list[dict[str, object]] = []
    for container in containers:
        metrics = container.get("metrics")
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                value = metric.get(key)
                if not isinstance(value, dict):
                    continue
                try:
                    score = float(value.get("baseScore"))
                except (TypeError, ValueError):
                    continue
                choices.append({
                    "version": key.replace("cvssV", "").replace("_", "."),
                    "score": score,
                    "severity": _clean_text(value.get("baseSeverity"), 20).lower(),
                    "vector": _clean_text(value.get("vectorString"), 320),
                })
    if not choices:
        return {}
    # Prefer CVSS v4 for equal/higher-quality records, then the highest score.
    return max(choices, key=lambda item: (str(item["version"]).startswith("4"), float(item["score"])))


def _problem_types(containers: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for container in containers:
        groups = container.get("problemTypes")
        if not isinstance(groups, list):
            continue
        for group in groups:
            descriptions = group.get("descriptions") if isinstance(group, dict) else None
            if not isinstance(descriptions, list):
                continue
            for item in descriptions:
                if not isinstance(item, dict):
                    continue
                value = _clean_text(item.get("cweId") or item.get("description"), 160)
                if value and value not in values:
                    values.append(value)
    return values[:20]


def _affected_products(containers: list[dict[str, Any]]) -> list[dict[str, object]]:
    affected: list[dict[str, object]] = []
    seen: set[str] = set()
    for container in containers:
        entries = container.get("affected")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            versions: list[dict[str, str]] = []
            for raw_version in entry.get("versions") or []:
                if not isinstance(raw_version, dict):
                    continue
                version = {
                    key: _clean_text(raw_version.get(key), 120)
                    for key in (
                        "version", "status", "lessThan", "lessThanOrEqual",
                        "versionType", "changes",
                    )
                    if raw_version.get(key) not in (None, "")
                }
                if version:
                    versions.append(version)
            normalized = {
                "vendor": _clean_text(entry.get("vendor"), 160),
                "product": _clean_text(entry.get("product"), 240),
                "default_status": _clean_text(entry.get("defaultStatus"), 40).lower(),
                "versions": versions[:40],
            }
            key = json.dumps(normalized, sort_keys=True)
            if key in seen or not (normalized["vendor"] or normalized["product"]):
                continue
            seen.add(key)
            affected.append(normalized)
            if len(affected) >= MAX_AFFECTED_PRODUCTS:
                return affected
    return affected


def normalize_cve_record(payload: object) -> dict[str, object]:
    """Normalize a CVE JSON 5.x record from the official CVE Services API."""
    if not isinstance(payload, dict):
        raise ValueError("CVE service returned a non-object record")
    metadata = payload.get("cveMetadata")
    containers_object = payload.get("containers")
    if not isinstance(metadata, dict) or not isinstance(containers_object, dict):
        raise ValueError("CVE service response does not use the CVE JSON 5 schema")
    cve_id = validate_cve_id(metadata.get("cveId"))
    cna = containers_object.get("cna") if isinstance(containers_object.get("cna"), dict) else {}
    adp = [item for item in containers_object.get("adp") or [] if isinstance(item, dict)]
    containers = [cna, *adp]
    description = _english_description(cna.get("descriptions"))
    if not description:
        description = next(
            (_english_description(container.get("descriptions")) for container in adp
             if _english_description(container.get("descriptions"))),
            "",
        )
    references: list[str] = []
    for container in containers:
        for item in container.get("references") or []:
            if not isinstance(item, dict):
                continue
            url = _clean_text(item.get("url"), 1000)
            if url.startswith("https://") and url not in references:
                references.append(url)
            if len(references) >= MAX_REFERENCES:
                break
    cvss = _cvss_from_containers(containers)
    lowered_description = description.lower()
    availability_only = bool(
        re.search(r"\bdenial[- ]of[- ]service\b|\bavailability\b|\bcrash(?:es|ed|ing)?\b", lowered_description)
        and not re.search(r"\bcode execution\b|\bauthentication bypass\b|\bprivilege escalation\b", lowered_description)
    )
    affected = _affected_products(containers)
    return {
        "cve_id": cve_id,
        "state": _clean_text(metadata.get("state"), 40).lower(),
        "published": _clean_text(metadata.get("datePublished"), 80),
        "updated": _clean_text(metadata.get("dateUpdated"), 80),
        "assigner": _clean_text((cna.get("providerMetadata") or {}).get("shortName"), 120),
        "description": description,
        "cvss": cvss,
        "weaknesses": _problem_types(containers),
        "affected": affected,
        "affected_count": len(affected),
        "references": references,
        "availability_impact": availability_only,
        "source": "CVE Services API",
        "source_url": CVE_RECORD_URL.format(cve_id=quote(cve_id, safe="-")),
    }


def _normalize_nvd_record(payload: object, requested_id: str) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("NVD returned a non-object response")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD response did not contain vulnerabilities")
    selected: dict[str, Any] | None = None
    for wrapper in vulnerabilities:
        item = wrapper.get("cve") if isinstance(wrapper, dict) else None
        if isinstance(item, dict) and str(item.get("id") or "").upper() == requested_id:
            selected = item
            break
    if selected is None:
        raise LookupError(f"{requested_id} was not found in NVD")
    metrics: list[dict[str, object]] = []
    for values in (selected.get("metrics") or {}).values():
        for wrapper in values if isinstance(values, list) else []:
            cvss_data = wrapper.get("cvssData") if isinstance(wrapper, dict) else None
            if not isinstance(cvss_data, dict):
                continue
            try:
                score = float(cvss_data.get("baseScore"))
            except (TypeError, ValueError):
                continue
            metrics.append({
                "version": _clean_text(cvss_data.get("version"), 20),
                "score": score,
                "severity": _clean_text(cvss_data.get("baseSeverity"), 20).lower(),
                "vector": _clean_text(cvss_data.get("vectorString"), 320),
            })
    description = _english_description(selected.get("descriptions"))
    references = [
        _clean_text(item.get("url"), 1000)
        for item in selected.get("references") or []
        if isinstance(item, dict) and str(item.get("url") or "").startswith("https://")
    ][:MAX_REFERENCES]
    weaknesses: list[str] = []
    for group in selected.get("weaknesses") or []:
        for item in group.get("description") or [] if isinstance(group, dict) else []:
            value = _clean_text(item.get("value"), 160) if isinstance(item, dict) else ""
            if value and value not in weaknesses:
                weaknesses.append(value)
    return {
        "cve_id": requested_id,
        "state": "published",
        "published": _clean_text(selected.get("published"), 80),
        "updated": _clean_text(selected.get("lastModified"), 80),
        "assigner": _clean_text(selected.get("sourceIdentifier"), 120),
        "description": description,
        "cvss": max(metrics, key=lambda item: (str(item["version"]).startswith("4"), float(item["score"]))) if metrics else {},
        "weaknesses": weaknesses[:20],
        "affected": [],
        "affected_count": 0,
        "references": references,
        "availability_impact": bool(re.search(r"denial[- ]of[- ]service|availability|crash", description, re.IGNORECASE)),
        "source": "NVD CVE API 2.0 (fallback)",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{requested_id}",
    }


async def _read_json_limited(response: httpx.Response) -> object:
    body = bytearray()
    async for chunk in response.aiter_bytes(chunk_size=65536):
        body.extend(chunk)
        if len(body) > MAX_CVE_RESPONSE_BYTES:
            raise ValueError("CVE database response exceeded the 2 MB safety limit")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("CVE database returned invalid JSON") from exc


async def fetch_cve_record(
    cve_id: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, object]:
    """Fetch one CVE from fixed official endpoints with a bounded response."""
    canonical = validate_cve_id(cve_id)
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(12.0, connect=6.0),
            follow_redirects=False,
            headers={"User-Agent": "AEGIS CVE correlation/1"},
        )
    try:
        try:
            async with client.stream("GET", CVE_RECORD_URL.format(cve_id=canonical)) as response:
                if response.status_code == 404:
                    raise LookupError(f"{canonical} was not found in the CVE List")
                response.raise_for_status()
                payload = await _read_json_limited(response)
            return normalize_cve_record(payload)
        except (httpx.HTTPError, ValueError, LookupError) as primary_error:
            # NVD is a second official source and often remains available when
            # the CVE Services mirror is transiently unavailable.
            try:
                async with client.stream(
                    "GET",
                    NVD_CVE_API_URL,
                    params={"cveId": canonical, "resultsPerPage": "1"},
                ) as response:
                    response.raise_for_status()
                    payload = await _read_json_limited(response)
                return _normalize_nvd_record(payload, canonical)
            except (httpx.HTTPError, ValueError, LookupError) as fallback_error:
                raise RuntimeError(
                    f"official CVE sources failed ({primary_error}; {fallback_error})"
                ) from fallback_error
    finally:
        if owns_client:
            await client.aclose()


def _nvd_candidates(payload: object, *, limit: int) -> list[dict[str, object]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("NVD product search returned an invalid response")
    candidates: list[dict[str, object]] = []
    for wrapper in payload["vulnerabilities"]:
        item = wrapper.get("cve") if isinstance(wrapper, dict) else None
        if not isinstance(item, dict):
            continue
        try:
            cve_id = validate_cve_id(item.get("id"))
        except ValueError:
            continue
        scores: list[dict[str, object]] = []
        for metric_values in (item.get("metrics") or {}).values():
            for metric in metric_values if isinstance(metric_values, list) else []:
                cvss = metric.get("cvssData") if isinstance(metric, dict) else None
                if not isinstance(cvss, dict):
                    continue
                try:
                    score = float(cvss.get("baseScore"))
                except (TypeError, ValueError):
                    continue
                scores.append({
                    "version": _clean_text(cvss.get("version"), 20),
                    "score": score,
                    "severity": _clean_text(cvss.get("baseSeverity"), 20).lower(),
                    "vector": _clean_text(cvss.get("vectorString"), 320),
                })
        candidates.append({
            "cve_id": cve_id,
            "description": _english_description(item.get("descriptions"))[:700],
            "cvss": max(
                scores,
                key=lambda score: (
                    str(score["version"]).startswith("4"),
                    float(score["score"]),
                ),
            ) if scores else {},
            "published": _clean_text(item.get("published"), 80),
            "updated": _clean_text(item.get("lastModified"), 80),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "match": "keyword",
            "database": "NVD",
        })
    candidates.sort(
        key=lambda item: (
            str(item.get("published") or ""),
            float((item.get("cvss") or {}).get("score") or 0)
            if isinstance(item.get("cvss"), dict)
            else 0,
        ),
        reverse=True,
    )
    return candidates[:limit]


def _circl_candidates(payload: object, *, limit: int) -> list[dict[str, object]]:
    """Normalize an exact vendor/product result from Vulnerability-Lookup.

    Vulnerability-Lookup may return the same CVE from several upstream feeds.
    Prefer CVE List records, deduplicate by CVE ID, and retain only the compact
    metadata needed by the report.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        raise ValueError("CIRCL product search returned an invalid response")
    results = payload["results"]
    ordered_sources = [
        source for source in ("cvelistv5", "nvd") if isinstance(results.get(source), list)
    ]
    ordered_sources.extend(
        source for source, values in results.items()
        if source not in ordered_sources and isinstance(values, list)
    )
    candidates: list[dict[str, object]] = []
    seen: set[str] = set()
    for source in ordered_sources:
        for entry in results[source]:
            record_payload = (
                entry[1]
                if isinstance(entry, list) and len(entry) >= 2 and isinstance(entry[1], dict)
                else entry if isinstance(entry, dict) else None
            )
            if record_payload is None:
                continue
            try:
                record = normalize_cve_record(record_payload)
            except (ValueError, TypeError):
                continue
            cve_id = str(record.get("cve_id") or "")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            candidates.append({
                "cve_id": cve_id,
                "description": _clean_text(record.get("description"), 700),
                "cvss": record.get("cvss") if isinstance(record.get("cvss"), dict) else {},
                "published": record.get("published", ""),
                "updated": record.get("updated", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "match": "exact_vendor_product_index",
                "database": f"CIRCL Vulnerability-Lookup ({source})",
            })
            if len(candidates) >= limit:
                return candidates
    return candidates


async def search_cve_candidates(
    query: str,
    *,
    vendor: str = "",
    product: str = "",
    client: httpx.AsyncClient | None = None,
    limit: int = 10,
) -> dict[str, object]:
    """Search fixed CVE indexes for a high-confidence observed product.

    CIRCL's exact vendor/product index complements NVD keyword search because
    NVD does not always expose vendor product mappings for CNA records. Results
    remain candidates: neither kind of database hit proves the scanned target's
    installed version is vulnerable.
    """
    cleaned_query = _clean_text(query, 160)
    if len(cleaned_query) < 4 or not re.fullmatch(r"[A-Za-z0-9 ._+()&/-]+", cleaned_query):
        raise ValueError("CVE product search requires a bounded vendor/product query")
    cleaned_vendor = _clean_text(vendor, 120)
    cleaned_product = _clean_text(product, 200)
    for label, value in (("vendor", cleaned_vendor), ("product", cleaned_product)):
        if value and not re.fullmatch(r"[A-Za-z0-9 ._+()&/-]+", value):
            raise ValueError(f"CVE product search {label} contains unsupported characters")
    if bool(cleaned_vendor) != bool(cleaned_product):
        raise ValueError("CVE exact product search requires both vendor and product")
    result_limit = max(1, min(int(limit), 20))
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(12.0, connect=6.0),
            follow_redirects=False,
            headers={"User-Agent": "AEGIS CVE candidate search/1"},
        )
    nvd_payload: object | None = None
    circl_payload: object | None = None
    nvd: list[dict[str, object]] = []
    circl: list[dict[str, object]] = []
    errors: list[str] = []
    try:
        if cleaned_vendor and cleaned_product:
            exact_url = CIRCL_PRODUCT_SEARCH_URL.format(
                vendor=quote(cleaned_vendor.lower(), safe=""),
                product=quote(cleaned_product.lower(), safe=""),
            )
            try:
                async with client.stream(
                    "GET",
                    exact_url,
                    params={"page": "1", "per_page": str(min(80, result_limit * 4))},
                ) as response:
                    response.raise_for_status()
                    circl_payload = await _read_json_limited(response)
                circl = _circl_candidates(circl_payload, limit=result_limit)
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"CIRCL: {_clean_text(exc, 240)}")
                circl_payload = None

        # Exact indexed matches are both more precise and substantially less
        # likely to hit NVD's unauthenticated rate limit. NVD remains the
        # fallback for unindexed products and older callers without aliases.
        if not circl:
            try:
                async with client.stream(
                    "GET",
                    NVD_CVE_API_URL,
                    params={
                        "keywordSearch": cleaned_query,
                        "resultsPerPage": str(min(100, max(40, result_limit * 4))),
                    },
                ) as response:
                    response.raise_for_status()
                    nvd_payload = await _read_json_limited(response)
                nvd = _nvd_candidates(nvd_payload, limit=result_limit)
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"NVD: {_clean_text(exc, 240)}")
                nvd_payload = None
    finally:
        if owns_client:
            await client.aclose()

    if nvd_payload is None and circl_payload is None:
        raise RuntimeError("CVE candidate sources failed: " + "; ".join(errors))

    merged: list[dict[str, object]] = []
    seen: set[str] = set()
    # Exact indexed product matches are materially stronger than keywords, so
    # show them first while still making their candidate status explicit.
    for item in [*circl, *nvd]:
        cve_id = str(item.get("cve_id") or "")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        merged.append(item)
        if len(merged) >= result_limit:
            break
    sources = []
    if circl_payload is not None:
        sources.append("CIRCL Vulnerability-Lookup exact product index")
    if nvd_payload is not None:
        sources.append("NVD CVE API 2.0 keyword search")
    nvd_total = (
        int(nvd_payload.get("totalResults") or len(nvd))
        if isinstance(nvd_payload, dict)
        else 0
    )
    circl_total = (
        int(circl_payload.get("total_count") or len(circl))
        if isinstance(circl_payload, dict)
        else 0
    )
    result: dict[str, object] = {
        "type": "cve_candidate_search",
        "query": cleaned_query,
        "vendor": cleaned_vendor,
        "product": cleaned_product,
        "total_results": max(nvd_total, circl_total, len(merged)),
        "candidates": merged,
        "source": " + ".join(sources),
        "source_url": CIRCL_API_DOCS_URL if circl_payload is not None else "https://nvd.nist.gov/developers/vulnerabilities",
        "candidate_only": True,
    }
    if errors:
        result["source_warnings"] = errors
    return result


async def search_nvd_candidates(
    query: str,
    *,
    client: httpx.AsyncClient | None = None,
    limit: int = 10,
) -> dict[str, object]:
    """Backward-compatible NVD-only candidate search used by older callers."""
    return await search_cve_candidates(query, client=client, limit=limit)


def summarize_cve_record(record: dict[str, object], *, max_products: int = 18) -> dict[str, object]:
    """Return a compact, UI-safe audit record while retaining full data in state."""
    affected = record.get("affected") if isinstance(record.get("affected"), list) else []
    products = [
        {
            "vendor": item.get("vendor", ""),
            "product": item.get("product", ""),
            "versions": item.get("versions", [])[:4] if isinstance(item.get("versions"), list) else [],
        }
        for item in affected[:max_products]
        if isinstance(item, dict)
    ]
    return {
        "type": "cve_record",
        "cve_id": record.get("cve_id"),
        "state": record.get("state"),
        "assigner": record.get("assigner"),
        "description": record.get("description"),
        "cvss": record.get("cvss"),
        "weaknesses": record.get("weaknesses"),
        "availability_impact": bool(record.get("availability_impact")),
        "affected_product_count": record.get("affected_count", len(affected)),
        "affected_sample": products,
        "references": record.get("references", [])[:8] if isinstance(record.get("references"), list) else [],
        "source": record.get("source"),
        "source_url": record.get("source_url"),
        "known_exploited": bool(record.get("known_exploited")),
        "kev_date_added": record.get("kev_date_added"),
        "epss": record.get("epss"),
        "epss_percentile": record.get("epss_percentile"),
        "risk_priority": record.get("risk_priority"),
        "risk_reasons": record.get("risk_reasons", []),
    }


def _normalized_product(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _version_tuple(value: str) -> tuple[int, ...] | None:
    cleaned = str(value or "").strip().lower().lstrip("v")
    match = re.fullmatch(r"(\d+(?:\.\d+){0,5})(?:[-+_].*)?", cleaned)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    size = max(len(left), len(right))
    padded_left = left + (0,) * (size - len(left))
    padded_right = right + (0,) * (size - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _version_affected(observed: str, rules: object, default_status: str) -> bool | None:
    if not isinstance(rules, list) or not rules:
        return True if default_status == "affected" else None
    if any(
        isinstance(rule, dict)
        and str(rule.get("status") or "").lower() == "affected"
        and (
            str(rule.get("lessThan") or "") == "*"
            or str(rule.get("lessThanOrEqual") or "") == "*"
            or str(rule.get("version") or "") == "*"
        )
        for rule in rules
    ):
        return True
    if not observed:
        return None
    observed_tuple = _version_tuple(observed)
    indeterminate = False
    for rule in rules:
        if not isinstance(rule, dict) or str(rule.get("status") or "").lower() != "affected":
            continue
        version = str(rule.get("version") or "")
        less_than = str(rule.get("lessThan") or "")
        less_equal = str(rule.get("lessThanOrEqual") or "")
        if less_than == "*" or (version in {"*", "0"} and not less_than and not less_equal):
            return True
        if observed_tuple is None:
            indeterminate = True
            continue
        lower_tuple = _version_tuple(version)
        upper_tuple = _version_tuple(less_than or less_equal)
        if upper_tuple is None:
            if lower_tuple and _compare_versions(observed_tuple, lower_tuple) == 0:
                return True
            indeterminate = True
            continue
        above_lower = lower_tuple is None or _compare_versions(observed_tuple, lower_tuple) >= 0
        below_upper = _compare_versions(observed_tuple, upper_tuple) <= (0 if less_equal else -1)
        if above_lower and below_upper:
            return True
    if indeterminate:
        return None
    return False


def correlate_cve(
    record: dict[str, object],
    fingerprints: list[dict[str, object]],
) -> dict[str, object]:
    """Correlate observed identities with vendor affected-product records."""
    if not any(
        isinstance(item, dict) and str(item.get("product") or "").strip()
        for item in fingerprints
    ):
        return {"status": "no_identity", "matches": [], "vendor_overlap": []}
    matches: list[dict[str, object]] = []
    affected = record.get("affected") if isinstance(record.get("affected"), list) else []
    for fingerprint in fingerprints:
        if not isinstance(fingerprint, dict):
            continue
        observed_vendor = _normalized_product(fingerprint.get("vendor"))
        observed_product = _normalized_product(fingerprint.get("product"))
        observed_evidence = _clean_text(fingerprint.get("evidence"), 500)
        if not observed_product:
            continue
        for item in affected:
            if not isinstance(item, dict):
                continue
            affected_vendor = _normalized_product(item.get("vendor"))
            affected_product = _normalized_product(item.get("product"))
            vendor_matches = bool(
                not observed_vendor
                or not affected_vendor
                or observed_vendor == affected_vendor
                or observed_vendor in affected_vendor
                or affected_vendor in observed_vendor
            )
            product_match_score = (
                3 if observed_product == affected_product
                else 2 if affected_product and len(observed_product) >= 7 and observed_product in affected_product
                else 2 if affected_product and len(affected_product) >= 7 and affected_product in observed_product
                else 0
            )
            product_matches = product_match_score > 0
            if not (vendor_matches and product_matches):
                continue
            observed_version = _clean_text(fingerprint.get("version"), 120)
            affected_status = _version_affected(
                observed_version,
                item.get("versions"),
                str(item.get("default_status") or ""),
            )
            matches.append({
                "observed_vendor": fingerprint.get("vendor", ""),
                "observed_product": fingerprint.get("product", ""),
                "observed_version": observed_version,
                "observed_evidence": observed_evidence,
                "affected_vendor": item.get("vendor", ""),
                "affected_product": item.get("product", ""),
                "affected_versions": item.get("versions", []),
                "version_affected": affected_status,
                "product_match_score": product_match_score,
            })
    if not matches:
        observed_vendors = {
            _normalized_product(item.get("vendor"))
            for item in fingerprints
            if isinstance(item, dict) and item.get("vendor")
        }
        affected_vendors = {
            _normalized_product(item.get("vendor"))
            for item in affected
            if isinstance(item, dict) and item.get("vendor")
        }
        vendor_overlap = sorted(observed_vendors.intersection(affected_vendors))
        return {
            "status": "vendor_only" if vendor_overlap else "no_product_match",
            "matches": [],
            "vendor_overlap": vendor_overlap,
        }
    # If an exact model exists in the advisory, do not let broader substring
    # matches (for example X204-2 vs X204-2FM) influence its version result.
    best_score = max(int(item.get("product_match_score") or 0) for item in matches)
    matches = [item for item in matches if int(item.get("product_match_score") or 0) == best_score]
    affected_matches = [item for item in matches if item["version_affected"] is not False]
    if not affected_matches:
        status = "observed_version_not_affected"
    elif any(item["version_affected"] is True for item in affected_matches):
        status = "potentially_affected"
    else:
        status = "version_unverified"
    return {"status": status, "matches": affected_matches or matches, "vendor_overlap": []}


def extract_product_fingerprints(tool_name: str, output: str) -> list[dict[str, object]]:
    """Extract only evidence-backed vendor/product identities from tool output."""
    text = str(output or "")
    fingerprints: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        vendor: str,
        product: str,
        version: str,
        evidence: str,
        confidence: str = "high",
        metadata: dict[str, object] | None = None,
    ) -> None:
        key = (_normalized_product(vendor), _normalized_product(product), version.lower())
        if (not key[0] and not key[1]) or key in seen:
            return
        seen.add(key)
        fingerprint = {
            "vendor": _clean_text(vendor, 120),
            "product": _clean_text(product, 200),
            "version": _clean_text(version, 120),
            "evidence": _clean_text(evidence, 500),
            "source": tool_name,
            "confidence": confidence,
        }
        if metadata:
            for field in (
                "fingerprint_id", "category", "priority", "search_vendor",
                "search_product", "cve_searchable", "version_caveat",
            ):
                if field in metadata:
                    fingerprint[field] = metadata[field]
        fingerprints.append(fingerprint)

    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            item = None
        if isinstance(item, dict) and item.get("type") == "web_identity":
            add(
                str(item.get("vendor") or ""),
                str(item.get("product") or ""),
                str(item.get("version") or ""),
                line,
                str(item.get("confidence") or "high"),
                item,
            )
        if isinstance(item, dict) and tool_name == "httpx_probe":
            identity_text = " ".join(
                str(value or "")
                for value in (item.get("title"), item.get("webserver"), item.get("tech"))
            )
            text += "\n" + identity_text

    for match in re.finditer(
        r"cpe:/[aho]:([^:\s]+):([^:\s]+):([^:\s]+)",
        text,
        re.IGNORECASE,
    ):
        vendor = match.group(1).replace("_", " ")
        product = match.group(2).replace("_", " ")
        version = "" if match.group(3) in {"*", "-"} else match.group(3)
        add(vendor, product, version, match.group(0))

    for fingerprint in identify_product_fingerprints(
        text,
        source=tool_name,
        body_context=False,
        limit=30,
    ):
        add(
            str(fingerprint.get("vendor") or ""),
            str(fingerprint.get("product") or ""),
            str(fingerprint.get("version") or ""),
            str(fingerprint.get("evidence") or ""),
            str(fingerprint.get("confidence") or "high"),
            fingerprint,
        )

    return fingerprints[:40]
