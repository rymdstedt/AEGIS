"""Bounded Cisco PSIRT advisory lookup for recognized IOS/IOS XE firmware.

The caller supplies an already-issued Cisco API access token.  AEGIS sends it
only to Cisco's fixed HTTPS API host, never persists it, and stores a compact,
sanitized subset of the response alongside the local firmware inventory.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

PSIRT_API_ROOT = "https://apix.cisco.com/security/advisories/v2"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_ADVISORIES = 100
MAX_CVES_PER_ADVISORY = 100
MAX_FIXED_RELEASES = 100

_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9()._+\-/]{0,79}")
_TOKEN_RE = re.compile(r"[^\x00-\x1f\x7f]{20,16384}")
_ALLOWED_PUBLICATION_HOSTS = {
    "sec.cloudapps.cisco.com",
    "tools.cisco.com",
    "www.cisco.com",
}


class CiscoPsirtError(RuntimeError):
    """A safe, user-facing Cisco advisory lookup failure."""


def cisco_os_type(platform_family: str) -> str:
    """Map the locally inferred platform family to a Cisco PSIRT OS type."""
    normalized = str(platform_family or "").casefold()
    if "ios xe" in normalized:
        return "iosxe"
    if normalized == "cisco ios" or " ios" in normalized:
        return "ios"
    raise ValueError("Cisco advisory lookup supports recognized IOS and IOS XE firmware")


def _clean_text(value: Any, limit: int = 500) -> str:
    text = " ".join(str(value or "").replace("\x00", " ").split())
    return text[:limit]


def _string_list(value: Any, limit: int) -> list[str]:
    if isinstance(value, str):
        source = re.split(r"[,\s]+", value)
    elif isinstance(value, list):
        source = value
    else:
        source = []
    result: list[str] = []
    seen: set[str] = set()
    for item in source:
        cleaned = _clean_text(item, 160)
        if not cleaned or cleaned.casefold() in seen:
            continue
        seen.add(cleaned.casefold())
        result.append(cleaned)
        if len(result) >= limit:
            break
    return result


def _publication_url(value: Any) -> str | None:
    candidate = _clean_text(value, 2_048)
    if not candidate:
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").casefold()
    if parsed.scheme != "https" or host not in _ALLOWED_PUBLICATION_HOSTS:
        return None
    return candidate


def _score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= score <= 10:
        return None
    return round(score, 1)


def _sanitize_advisory(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    advisory_id = _clean_text(item.get("advisoryId"), 80)
    title = _clean_text(item.get("advisoryTitle"), 500)
    if not advisory_id or not title:
        return None
    return {
        "advisory_id": advisory_id,
        "title": title,
        "severity": _clean_text(item.get("sir"), 40).casefold() or "unknown",
        "cvss_base_score": _score(item.get("cvssBaseScore")),
        "cves": _string_list(item.get("cves"), MAX_CVES_PER_ADVISORY),
        "first_fixed": _string_list(item.get("firstFixed"), MAX_FIXED_RELEASES),
        "first_published": _clean_text(item.get("firstPublished"), 80) or None,
        "last_updated": _clean_text(item.get("lastUpdated"), 80) or None,
        "publication_url": _publication_url(item.get("publicationUrl")),
    }


def sanitize_psirt_response(
    payload: Any,
    *,
    version: str,
    os_type: str,
) -> dict[str, Any]:
    """Reduce an untrusted API document to the fields AEGIS displays."""
    if not isinstance(payload, dict):
        raise CiscoPsirtError("Cisco PSIRT returned an invalid response document")
    raw_advisories = payload.get("advisories")
    if raw_advisories is None:
        raw_advisories = []
    if not isinstance(raw_advisories, list):
        raise CiscoPsirtError("Cisco PSIRT returned an invalid advisory list")

    advisories: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_advisories:
        advisory = _sanitize_advisory(raw)
        if advisory is None or advisory["advisory_id"] in seen:
            continue
        seen.add(advisory["advisory_id"])
        advisories.append(advisory)
        if len(advisories) >= MAX_ADVISORIES:
            break

    severity_counts = {
        severity: sum(1 for item in advisories if item["severity"] == severity)
        for severity in ("critical", "high", "medium", "low")
    }
    total_count = payload.get("totalCount", payload.get("count"))
    try:
        total_count = max(len(raw_advisories), int(total_count))
    except (TypeError, ValueError):
        total_count = len(raw_advisories)
    return {
        "status": "complete",
        "source": "Cisco PSIRT openVuln API",
        "queried_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "os_type": os_type,
        "version": version,
        "advisory_count": len(advisories),
        "source_count": total_count,
        "truncated": total_count > len(advisories),
        "severity_counts": severity_counts,
        "advisories": advisories,
        "access_token_stored": False,
        "notes": [
            "Results are Cisco's version-query response, not proof that every advisory is exploitable on this exact device configuration.",
            "Review Cisco's publication and fixed-release guidance before changing production firmware.",
        ],
    }


async def fetch_cisco_advisories(
    *,
    access_token: str,
    version: str,
    os_type: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Query one Cisco OS/version with strict bounds and no redirects."""
    token = str(access_token or "").strip()
    clean_version = str(version or "").strip()
    clean_os_type = str(os_type or "").strip().casefold()
    if not _TOKEN_RE.fullmatch(token):
        raise ValueError("Cisco access token is missing or malformed")
    if not _VERSION_RE.fullmatch(clean_version):
        raise ValueError("Detected Cisco version is not safe to query")
    if clean_os_type not in {"ios", "iosxe"}:
        raise ValueError("Unsupported Cisco PSIRT operating-system type")

    timeout = httpx.Timeout(20.0, connect=10.0)
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            response = await client.get(
                f"{PSIRT_API_ROOT}/OSType/{clean_os_type}",
                params={"version": clean_version},
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "AEGIS-Firmware-Research/1",
                },
            )
    except httpx.TimeoutException as exc:
        raise CiscoPsirtError("Cisco PSIRT lookup timed out") from exc
    except httpx.HTTPError as exc:
        raise CiscoPsirtError("Could not connect securely to Cisco PSIRT") from exc

    if response.status_code in {301, 302, 303, 307, 308}:
        raise CiscoPsirtError("Cisco PSIRT unexpectedly redirected the request")
    if response.status_code in {401, 403}:
        raise CiscoPsirtError("Cisco PSIRT rejected the access token")
    if response.status_code == 429:
        raise CiscoPsirtError("Cisco PSIRT rate limit reached; wait and retry")
    if response.status_code >= 400:
        raise CiscoPsirtError(f"Cisco PSIRT request failed (HTTP {response.status_code})")
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise CiscoPsirtError("Cisco PSIRT response exceeded the safe size limit")
    try:
        payload = response.json()
    except ValueError as exc:
        raise CiscoPsirtError("Cisco PSIRT returned invalid JSON") from exc
    return sanitize_psirt_response(
        payload,
        version=clean_version,
        os_type=clean_os_type,
    )
