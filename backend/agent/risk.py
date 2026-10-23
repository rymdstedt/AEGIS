"""Optional CISA KEV and FIRST EPSS enrichment for canonical CVE IDs."""

from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_KEV_BYTES = 16 * 1024 * 1024
MAX_EPSS_BYTES = 2 * 1024 * 1024
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_cache_lock = threading.Lock()
_kev_cache: tuple[float, dict[str, dict[str, Any]]] | None = None
_epss_cache: dict[str, tuple[float, dict[str, float]]] = {}


def _bounded_get_json(
    client: httpx.Client,
    url: str,
    maximum: int,
    *,
    params: dict[str, str] | None = None,
) -> Any:
    body = bytearray()
    with client.stream("GET", url, params=params) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes(65_536):
            body.extend(chunk)
            if len(body) > maximum:
                raise ValueError("risk feed exceeded its response safety limit")
    try:
        return httpx.Response(200, content=bytes(body)).json()
    except ValueError as exc:
        raise ValueError("risk feed returned invalid JSON") from exc


def _kev_catalog(client: httpx.Client) -> dict[str, dict[str, Any]]:
    global _kev_cache
    with _cache_lock:
        if _kev_cache and time.monotonic() - _kev_cache[0] < 6 * 60 * 60:
            return _kev_cache[1]
    payload = _bounded_get_json(client, KEV_URL, MAX_KEV_BYTES)
    entries: dict[str, dict[str, Any]] = {}
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("CISA KEV returned an invalid catalog")
    for item in payload["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").upper()
        if _CVE_RE.fullmatch(cve_id):
            entries[cve_id] = {
                "known_exploited": True,
                "kev_date_added": str(item.get("dateAdded") or "")[:20],
                "kev_due_date": str(item.get("dueDate") or "")[:20],
                "kev_ransomware_use": str(item.get("knownRansomwareCampaignUse") or "")[:80],
                "kev_required_action": str(item.get("requiredAction") or "")[:500],
            }
    with _cache_lock:
        _kev_cache = (time.monotonic(), entries)
    return entries


def _epss_scores(client: httpx.Client, cve_ids: list[str]) -> dict[str, dict[str, float]]:
    now = time.monotonic()
    with _cache_lock:
        scores = {
            cve_id: value
            for cve_id in cve_ids
            if (cached := _epss_cache.get(cve_id)) and now - cached[0] < 6 * 60 * 60
            for value in [cached[1]]
        }
    missing = [cve_id for cve_id in cve_ids if cve_id not in scores]
    for start in range(0, len(missing), 100):
        chunk = missing[start:start + 100]
        payload = _bounded_get_json(
            client,
            EPSS_URL,
            MAX_EPSS_BYTES,
            params={"cve": ",".join(chunk)},
        )
        rows = payload.get("data") if isinstance(payload, dict) else None
        for item in rows if isinstance(rows, list) else []:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve") or "").upper()
            try:
                epss = float(item.get("epss"))
                percentile = float(item.get("percentile"))
            except (TypeError, ValueError):
                continue
            if cve_id in chunk:
                scores[cve_id] = {"epss": epss, "epss_percentile": percentile}
    with _cache_lock:
        for cve_id, value in scores.items():
            _epss_cache[cve_id] = (now, value)
    return scores


def _new_client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(8.0, connect=4.0),
        follow_redirects=False,
        headers={"User-Agent": "AEGIS risk enrichment/1"},
    )


def enrich_cve_items(
    items: list[dict[str, Any]],
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Mutate CVE-bearing items with best-effort risk metadata.

    Feed failures are returned as warnings and never erase primary OSV/CVE data.
    An item can use ``cve_id`` or an ``aliases`` array.
    """
    ids: list[str] = []
    item_ids: list[list[str]] = []
    for item in items:
        candidates = [str(item.get("cve_id") or ""), str(item.get("id") or "")]
        aliases = item.get("aliases")
        if isinstance(aliases, list):
            candidates.extend(str(alias) for alias in aliases)
        canonical = list(dict.fromkeys(
            value.upper() for value in candidates if _CVE_RE.fullmatch(value.upper())
        ))
        item_ids.append(canonical)
        for cve_id in canonical:
            if cve_id not in ids:
                ids.append(cve_id)
    if not ids:
        return {"status": "not_applicable", "cve_count": 0, "warnings": []}

    owns_client = client is None
    warnings: list[str] = []
    kev: dict[str, dict[str, Any]] = {}
    epss: dict[str, dict[str, float]] = {}
    if owns_client:
        def fetch_kev() -> dict[str, dict[str, Any]]:
            with _new_client() as feed_client:
                return _kev_catalog(feed_client)

        def fetch_epss() -> dict[str, dict[str, float]]:
            with _new_client() as feed_client:
                return _epss_scores(feed_client, ids)

        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="aegis-risk") as pool:
            kev_future = pool.submit(fetch_kev)
            epss_future = pool.submit(fetch_epss)
            try:
                kev = kev_future.result()
            except Exception as exc:
                warnings.append(f"CISA KEV unavailable: {str(exc)[:240]}")
            try:
                epss = epss_future.result()
            except Exception as exc:
                warnings.append(f"FIRST EPSS unavailable: {str(exc)[:240]}")
    else:
        try:
            kev = _kev_catalog(client)
        except Exception as exc:  # best-effort secondary metadata
            warnings.append(f"CISA KEV unavailable: {str(exc)[:240]}")
        try:
            epss = _epss_scores(client, ids)
        except Exception as exc:  # best-effort secondary metadata
            warnings.append(f"FIRST EPSS unavailable: {str(exc)[:240]}")

    for item, canonical in zip(items, item_ids, strict=True):
        kev_match = next((kev[cve_id] for cve_id in canonical if cve_id in kev), None)
        epss_match = next((epss[cve_id] for cve_id in canonical if cve_id in epss), None)
        if kev_match:
            item.update(kev_match)
        else:
            item["known_exploited"] = False
        if epss_match:
            item.update(epss_match)
        reasons: list[str] = []
        if item.get("known_exploited"):
            reasons.append("listed in CISA KEV")
        if isinstance(item.get("epss"), float) and item["epss"] >= 0.1:
            reasons.append(f"EPSS {item['epss']:.1%}")
        score = item.get("cvss")
        if isinstance(score, dict):
            score = score.get("score")
        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            numeric_score = 0.0
        if numeric_score >= 9:
            reasons.append(f"CVSS {numeric_score:g}")
        item["risk_reasons"] = reasons
        item["risk_priority"] = (
            "urgent" if item.get("known_exploited")
            else "high" if (item.get("epss") or 0) >= 0.1 or numeric_score >= 9
            else "normal"
        )
    return {
        "status": "partial" if warnings else "complete",
        "cve_count": len(ids),
        "kev_matches": sum(bool(item.get("known_exploited")) for item in items),
        "epss_matches": sum(item.get("epss") is not None for item in items),
        "warnings": warnings,
        "sources": ["CISA Known Exploited Vulnerabilities", "FIRST EPSS"],
    }
