"""Security primitives shared by the HTTP and agent layers.

The desktop process supplies a fresh bearer token and instance id for every
launch.  The backend never persists either value.
"""
from __future__ import annotations

import ipaddress
import os
import secrets
from urllib.parse import urlsplit, urlunsplit

AUTH_TOKEN = os.environ.get("AEGIS_AUTH_TOKEN") or secrets.token_urlsafe(32)
INSTANCE_ID = os.environ.get("AEGIS_INSTANCE_ID") or secrets.token_urlsafe(18)
DESKTOP_PORT = int(os.environ.get("AEGIS_PORT", "0") or 0)


def token_matches(candidate: str | None) -> bool:
    return bool(candidate) and secrets.compare_digest(candidate, AUTH_TOKEN)


def allowed_origins() -> set[str]:
    origins = {
        f"http://127.0.0.1:{DESKTOP_PORT}" if DESKTOP_PORT else "",
        f"http://localhost:{DESKTOP_PORT}" if DESKTOP_PORT else "",
    }
    configured = os.environ.get("AEGIS_ALLOWED_ORIGINS", "")
    origins.update(item.strip().rstrip("/") for item in configured.split(",") if item.strip())
    return {origin for origin in origins if origin}


def origin_allowed(origin: str | None) -> bool:
    if not origin:
        return False
    return origin.rstrip("/") in allowed_origins()


def validate_provider_url(raw_url: str) -> str:
    """Allow only loopback OpenAI-compatible providers.

    AEGIS is a local-LLM application.  Restricting this setting prevents the
    localhost control service from becoming an SSRF primitive or silently
    exfiltrating scan data to an arbitrary server.
    """
    value = (raw_url or "http://127.0.0.1:1234").strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("LLM URL must be an http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("LLM URL cannot contain credentials, query parameters, or fragments")

    host = parsed.hostname.rstrip(".").lower()
    is_loopback = host == "localhost"
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if not is_loopback:
        raise ValueError("AEGIS only permits local LLM providers (localhost/loopback)")

    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid LLM provider port")
    path = parsed.path.rstrip("/")
    if path in {"/v1", "/api/v0", "/api/v1"}:
        path = ""
    elif path:
        raise ValueError("LLM URL must be the LM Studio server address, without an API path")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def redact_secret(value: str, secrets_to_hide: list[str] | tuple[str, ...]) -> str:
    redacted = value
    for secret in secrets_to_hide:
        if secret:
            redacted = redacted.replace(str(secret), "[REDACTED]")
    return redacted
