from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import subprocess
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from agent.fingerprints import identify_product_fingerprints, identify_vendor

from tools.definitions import CommandSpec


class _WebEndpointParser(HTMLParser):
    """Collect navigation and form targets from one bounded HTML response."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []
        self.forms: list[dict[str, object]] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value for name, value in attrs if value}
        if tag.lower() in {"a", "area"} and attributes.get("href"):
            self.references.append(("link", attributes["href"]))
        elif tag.lower() == "form":
            action = attributes.get("action") or ""
            if action:
                self.references.append(("form", action))
            self._finish_form()
            self._current_form = {
                "action": action,
                "method": (attributes.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag.lower() in {"input", "textarea", "select"} and self._current_form is not None:
            name = attributes.get("name") or ""
            if not name:
                return
            inputs = self._current_form.get("inputs")
            if not isinstance(inputs, list):
                return
            inputs.append({
                "name": name[:160],
                "type": (attributes.get("type") or "text").lower()[:40],
                "value": (attributes.get("value") or "")[:500],
            })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._finish_form()

    def close(self) -> None:
        super().close()
        self._finish_form()

    def _finish_form(self) -> None:
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


_SIDE_EFFECT_GET_PATH = re.compile(
    r"/(?:logout|signout|delete|remove|destroy|transfer|payment|pay|purchase|"
    r"checkout|order|send|reset|reboot|shutdown|restart|update|edit|create|"
    r"upload|import)(?:/|$)",
    re.IGNORECASE,
)
_REDIRECT_PARAMETERS = {
    "continue", "dest", "destination", "next", "redirect", "redirect_uri",
    "return", "return_to", "return_url", "url",
}
_SENSITIVE_RESOURCE_PATH = re.compile(
    r"(?:^|/)(?:\.env(?:\.[^/?]+)?|\.git/config|credentials|settings\.json|"
    r"[^/?]+\.map|[^/?]+\.(?:bak|backup|old|sql|sqlite|db|log|gz|zip|tar)|"
    r"debug(?:/|$)|config(?:/|$)|logs?(?:/|$)|backups?(?:/|$))",
    re.IGNORECASE,
)
_SECRET_KEY = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|database[_-]?url|authorization)",
    re.IGNORECASE,
)
_AUTH_FORM_PATH = re.compile(r"/(?:login|signin|sign-in|auth|session)(?:/|$)", re.IGNORECASE)
_PRIVATE_ARTIFACT_BODY_LIMIT = 65536
_PRIVATE_ARTIFACT_LIMIT = 40


def _compact_identity_text(value: object, limit: int = 240) -> str:
    """Return printable single-line metadata, never arbitrary page content."""
    text = re.sub(r"(?is)<[^>]+>", " ", str(value or ""))
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _web_identity_records(body: str, headers: dict[str, object]) -> list[dict[str, object]]:
    """Extract bounded vendor/product metadata from a fetched management page.

    Only the title, generator, Server header, and known product signatures are
    emitted.  This deliberately avoids copying page text, credentials, or
    configuration values into the public scan log.
    """
    title_match = re.search(r"(?is)<title\b[^>]*>(.*?)</title>", body[:262144])
    title = _compact_identity_text(title_match.group(1) if title_match else "")
    generator = ""
    for meta in re.finditer(r"(?is)<meta\b[^>]*>", body[:262144]):
        tag = meta.group(0)
        if not re.search(r"\bname\s*=\s*['\"]?generator\b", tag, re.IGNORECASE):
            continue
        content = re.search(r"\bcontent\s*=\s*(['\"])(.*?)\1", tag, re.IGNORECASE | re.DOTALL)
        if content:
            generator = _compact_identity_text(content.group(2))
            break
    server = _compact_identity_text(headers.get("server"), 160)
    safe_header_names = (
        "server", "x-powered-by", "x-aspnet-version", "x-owa-version",
        "x-feserver", "x-grafana-version", "x-jenkins", "x-gitlab-meta",
        "x-vmware-vcenter-version",
    )
    safe_headers = [
        f"{name}: {_compact_identity_text(headers.get(name), 160)}"
        for name in safe_header_names
        if headers.get(name)
    ]
    cookie_names: list[str] = []
    set_cookie = str(headers.get("set-cookie") or "")
    for match in re.finditer(r"(?:^|,\s*)([A-Za-z0-9!#$%&'*+.^_`|~-]{1,80})=", set_cookie):
        if match.group(1) not in cookie_names:
            cookie_names.append(match.group(1))
    metadata_source = "\n".join(
        [title, generator, server, *safe_headers, *[f"cookie: {name}" for name in cookie_names]]
    )
    metadata_fingerprints = identify_product_fingerprints(
        metadata_source,
        source="web metadata",
        body_context=False,
    )
    body_fingerprints = identify_product_fingerprints(
        body[:131072],
        source="management page signature",
        body_context=True,
    )
    by_id: dict[str, dict[str, object]] = {}
    for fingerprint in [*metadata_fingerprints, *body_fingerprints]:
        key = str(fingerprint.get("fingerprint_id") or "")
        existing = by_id.get(key)
        if existing and not existing.get("version") and fingerprint.get("version"):
            existing["version"] = fingerprint["version"]
            existing["source"] = fingerprint["source"]
        elif not existing:
            by_id[key] = dict(fingerprint)

    common = {
        "title": title,
        "generator": generator,
        "server": server,
        "cookie_names": cookie_names[:12],
    }
    records = [
        {
            "type": "web_identity",
            **common,
            **{key: value for key, value in fingerprint.items() if key != "evidence"},
            "signature": fingerprint.get("evidence", ""),
        }
        for fingerprint in by_id.values()
    ]
    if not records and (title or generator or server):
        vendor = identify_vendor(metadata_source + "\n" + body[:131072])
        records.append({
            "type": "web_identity",
            **common,
            "vendor": vendor,
            "product": "",
            "version": "",
            "category": "unclassified",
            "confidence": "medium" if vendor else "low",
        })
    return records


def _normalized_same_origin_url(base_url: str, reference: str) -> str | None:
    """Resolve a reference while refusing cross-origin or credential-bearing URLs."""
    try:
        base = urlsplit(base_url)
        resolved = urlsplit(urljoin(base_url, reference))
        base_scheme = base.scheme.lower()
        scheme = resolved.scheme.lower()
        base_port = base.port or (443 if base_scheme == "https" else 80)
        port = resolved.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    if (
        base_scheme not in {"http", "https"}
        or scheme != base_scheme
        or not base.hostname
        or not resolved.hostname
        or resolved.hostname.lower() != base.hostname.lower()
        or port != base_port
        or resolved.username
        or resolved.password
    ):
        return None
    host = resolved.hostname.lower()
    display_host = f"[{host}]" if ":" in host else host
    suffix = "" if (scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
    return urlunsplit((scheme, f"{display_host}{suffix}", resolved.path or "/", resolved.query, ""))


def _json_field_names(value: object, *, limit: int = 80) -> list[str]:
    """Return field names only; values may contain credentials and never leave the executor."""
    names: list[str] = []

    def visit(item: object) -> None:
        if len(names) >= limit:
            return
        if isinstance(item, dict):
            for key, nested in item.items():
                name = str(key)[:120]
                if name not in names:
                    names.append(name)
                visit(nested)
        elif isinstance(item, list):
            for nested in item[:12]:
                visit(nested)

    visit(value)
    return names


def _redacted_resource_markers(body: str) -> list[str]:
    """Extract safe key/format markers without returning any discovered secret value."""
    markers: list[str] = []
    for match in re.finditer(r"(?m)^\s*([A-Za-z][A-Za-z0-9_.-]{1,80})\s*[=:]", body[:262144]):
        key = match.group(1)
        if key not in markers:
            markers.append(key)
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if parsed is not None:
        for key in _json_field_names(parsed):
            if key not in markers:
                markers.append(key)
    if re.search(r"(?im)^\s*\[core\]\s*$", body):
        markers.append("git-core-config")
    if re.search(r"(?is)<title>\s*index of\s+", body):
        markers.append("directory-index")
    return markers[:40]


@dataclass
class ExecutionResult:
    exit_code: int | None
    timed_out: bool = False
    cancelled: bool = False
    duration: float = 0.0
    error: str = ""


class ToolExecutor:
    def __init__(self, default_timeout: int = 300):
        self.default_timeout = default_timeout
        self.active_processes: dict[str, asyncio.subprocess.Process] = {}
        self.last_result = ExecutionResult(exit_code=None)
        # Raw response evidence is never yielded into ordinary tool output.
        # The agent may copy this bounded, per-run collection into its
        # process-local operator evidence vault after the tool finishes.
        self.last_private_artifacts: list[dict[str, object]] = []

    def _retain_private_artifact(
        self,
        *,
        category: str,
        url: str,
        body: object,
        content_type: str = "",
    ) -> None:
        if len(self.last_private_artifacts) >= _PRIVATE_ARTIFACT_LIMIT:
            return
        if isinstance(body, (dict, list)):
            original = json.dumps(body, ensure_ascii=False, indent=2)
        else:
            original = str(body or "")
        serialized = original[:_PRIVATE_ARTIFACT_BODY_LIMIT]
        if not serialized.strip():
            return
        identity = (category, url, serialized)
        if any(
            (item.get("category"), item.get("url"), item.get("body")) == identity
            for item in self.last_private_artifacts
        ):
            return
        self.last_private_artifacts.append({
            "category": str(category)[:120],
            "url": str(url)[:2048],
            "content_type": str(content_type)[:160],
            "body": serialized,
            "truncated": len(original) > _PRIVATE_ARTIFACT_BODY_LIMIT,
        })

    async def run_stream(self, tool_name: str, spec: CommandSpec) -> AsyncGenerator[str, None]:
        timeout = spec.timeout or self.default_timeout
        started = time.monotonic()
        overall_code = 0
        self.last_result = ExecutionResult(exit_code=None)
        self.last_private_artifacts = []

        for index, argv in enumerate(spec.commands, 1):
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                self.last_result = ExecutionResult(None, timed_out=True, duration=time.monotonic() - started)
                yield "[TIMEOUT]\n"
                return
            if len(spec.commands) > 1:
                yield f"[step {index}/{len(spec.commands)}]\n"
            if argv and argv[0] == "__aegis_internal__":
                self._internal_exit_code = 0
                iterator = self._run_internal(argv[1], argv[2:])
                try:
                    while True:
                        remaining = timeout - (time.monotonic() - started)
                        if remaining <= 0:
                            raise asyncio.TimeoutError
                        try:
                            line = await asyncio.wait_for(anext(iterator), timeout=remaining)
                        except StopAsyncIteration:
                            break
                        yield line
                except asyncio.TimeoutError:
                    await iterator.aclose()
                    self.last_result = ExecutionResult(None, timed_out=True, duration=time.monotonic() - started)
                    yield "[TIMEOUT]\n"
                    return
                except asyncio.CancelledError:
                    await iterator.aclose()
                    self.last_result = ExecutionResult(None, cancelled=True, duration=time.monotonic() - started)
                    raise
                except Exception as exc:
                    self._internal_exit_code = 1
                    yield f"[ERROR: {exc}]\n"
                if self._internal_exit_code:
                    overall_code = self._internal_exit_code
                continue
            try:
                kwargs = {
                    "stdin": asyncio.subprocess.DEVNULL,
                    "stdout": asyncio.subprocess.PIPE,
                    "stderr": asyncio.subprocess.STDOUT,
                }
                if os.name == "posix":
                    kwargs["start_new_session"] = True
                elif os.name == "nt":
                    kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
                proc = await asyncio.create_subprocess_exec(*argv, **kwargs)
            except Exception as exc:
                self.last_result = ExecutionResult(None, duration=time.monotonic() - started, error=str(exc))
                yield f"[ERROR starting process: {exc}]\n"
                return

            task_id = f"{tool_name}_{id(proc)}"
            self.active_processes[task_id] = proc
            timed_out = False
            try:
                while True:
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        timed_out = True
                        await self._terminate(proc)
                        yield "[TIMEOUT]\n"
                        break
                    try:
                        line = await asyncio.wait_for(proc.stdout.readline(), timeout=min(remaining, 5.0))
                    except asyncio.TimeoutError:
                        if proc.returncode is not None:
                            break
                        continue
                    if not line:
                        break
                    text = line.decode(errors="replace")
                    for secret in spec.secrets:
                        if secret:
                            text = text.replace(secret, "[REDACTED]")
                    yield text
            except asyncio.CancelledError:
                await self._terminate(proc)
                self.last_result = ExecutionResult(proc.returncode, cancelled=True, duration=time.monotonic() - started)
                raise
            finally:
                # stdout can reach EOF a moment before asyncio publishes the
                # child's return code. Give a normally exiting process a brief
                # chance to settle instead of sending it a signal after it has
                # already completed (which produced intermittent EPERM errors
                # on macOS).
                if proc.returncode is None:
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=0.5)
                    except asyncio.TimeoutError:
                        pass
                if proc.returncode is None:
                    await self._terminate(proc)
                if proc.returncode is None:
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.5)
                    except asyncio.TimeoutError:
                        pass
                self.active_processes.pop(task_id, None)

            if timed_out:
                self.last_result = ExecutionResult(proc.returncode, timed_out=True, duration=time.monotonic() - started)
                return
            if proc.returncode:
                overall_code = proc.returncode

        self.last_result = ExecutionResult(overall_code, duration=time.monotonic() - started)

    async def _run_internal(self, name: str, args: list[str]) -> AsyncGenerator[str, None]:
        if name == "web_discover":
            target = args[0]
            try:
                target_parts = urlsplit(target)
            except ValueError:
                target_parts = None
            if (
                not target_parts
                or target_parts.scheme.lower() not in {"http", "https"}
                or not target_parts.hostname
                or target_parts.username
                or target_parts.password
            ):
                self._internal_exit_code = 2
                yield "Endpoint discovery requires an HTTP(S) URL without user information\n"
                return

            target_scheme = target_parts.scheme.lower()
            target_host = target_parts.hostname.lower()
            target_port = target_parts.port or (443 if target_scheme == "https" else 80)
            request_url = urlunsplit(
                (
                    target_scheme,
                    target_parts.netloc,
                    target_parts.path or "/",
                    target_parts.query,
                    "",
                )
            )
            body = bytearray()
            content_type = ""
            try:
                async with httpx.AsyncClient(
                    timeout=8.0,
                    follow_redirects=False,
                    verify=False,  # noqa: S501 - authorized scanners must support self-signed targets
                    headers={"User-Agent": "AEGIS bounded endpoint discovery"},
                ) as client:
                    async with client.stream("GET", request_url) as response:
                        content_type = response.headers.get("content-type", "").lower()
                        if response.status_code >= 400:
                            yield f"Endpoint discovery received HTTP {response.status_code}\n"
                            return
                        async for chunk in response.aiter_bytes(chunk_size=16384):
                            remaining = 262144 - len(body)
                            if remaining <= 0:
                                break
                            body.extend(chunk[:remaining])
                            if len(body) >= 262144:
                                break
                        encoding = response.encoding or "utf-8"
            except (httpx.HTTPError, UnicodeError) as exc:
                self._internal_exit_code = 1
                yield f"Endpoint discovery request failed: {exc}\n"
                return

            document = body.decode(encoding, errors="replace")
            if "html" not in content_type and not re.search(
                r"(?is)^\s*(?:<!doctype\s+html|<html\b)", document[:2048]
            ):
                yield "Response was not HTML; no page links or forms to discover\n"
                return

            parser = _WebEndpointParser()
            try:
                parser.feed(document)
                parser.close()
            except (ValueError, UnicodeError):
                # HTMLParser is deliberately forgiving, but malformed character
                # references should not fail the whole scan.
                pass

            emitted: set[str] = set()
            for source, reference in parser.references:
                reference = reference.strip()
                if not reference or reference.startswith("#"):
                    continue
                try:
                    resolved = urlsplit(urljoin(request_url, reference))
                    scheme = resolved.scheme.lower()
                    host = (resolved.hostname or "").lower()
                    port = resolved.port or (443 if scheme == "https" else 80)
                except ValueError:
                    continue
                if (
                    scheme != target_scheme
                    or host != target_host
                    or port != target_port
                    or resolved.username
                    or resolved.password
                ):
                    continue
                display_host = f"[{host}]" if ":" in host else host
                suffix = "" if (scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
                normalized = urlunsplit(
                    (scheme, f"{display_host}{suffix}", resolved.path or "/", resolved.query, "")
                )
                if len(normalized) > 2048 or normalized in emitted:
                    continue
                emitted.add(normalized)
                yield json.dumps(
                    {
                        "type": "web_endpoint",
                        "source": source,
                        "url": normalized,
                        "has_query": bool(resolved.query),
                    },
                    sort_keys=True,
                ) + "\n"
                if len(emitted) >= 100:
                    break
            for form in parser.forms[:20]:
                action = _normalized_same_origin_url(
                    request_url,
                    str(form.get("action") or request_url),
                )
                if not action:
                    continue
                inputs = form.get("inputs")
                safe_inputs = [
                    {
                        "name": str(item.get("name") or "")[:160],
                        "type": str(item.get("type") or "text")[:40],
                        # Preserve whether a default exists, never its value.
                        "has_default": bool(item.get("value")),
                    }
                    for item in (inputs if isinstance(inputs, list) else [])[:20]
                    if isinstance(item, dict) and item.get("name")
                ]
                yield json.dumps(
                    {
                        "type": "web_form",
                        "url": request_url,
                        "action": action,
                        "method": str(form.get("method") or "get")[:20],
                        "inputs": safe_inputs,
                    },
                    sort_keys=True,
                ) + "\n"
            if not emitted:
                yield "No same-origin links or form actions discovered\n"
            return

        if name == "web_assess":
            async for line in self._run_web_assessment(args[0]):
                yield line
            return

        if name == "csrf_get_check":
            async for line in self._run_csrf_get_check(args[0]):
                yield line
            return

        if name == "cookie_auth_check":
            async for line in self._run_cookie_auth_check(args[0]):
                yield line
            return

        if name == "unauthenticated_write_check":
            async for line in self._run_unauthenticated_write_check(args[0]):
                yield line
            return

        if name == "default_web_login":
            async for line in self._run_default_web_login(args[0]):
                yield line
            return

        if name == "tech_detect":
            base = args[0].rstrip("/")
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
                for path in ("wp-login.php", "wp-admin", "readme.html", "administrator", "joomla", "drupal"):
                    try:
                        response = await client.get(f"{base}/{path}")
                    except httpx.HTTPError:
                        continue
                    if response.status_code not in {404, 400, 500, 501, 502, 503}:
                        yield f"FOUND ({response.status_code}): {base}/{path}\n"
            return

        if name == "xss_probe":
            target = args[0]
            parts = urlsplit(target)
            query = parse_qsl(parts.query, keep_blank_values=True) or [("aegis_probe", "")]
            payload = '<aegis-xss-probe data-token="7f31"></aegis-xss-probe>'
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=False,
                # Pentest targets commonly use self-signed certificates. This
                # is a scanner request, not an authenticated trust decision.
                verify=False,  # noqa: S501
                headers={"User-Agent": "AEGIS bounded HTML-reflection probe"},
            ) as client:
                for index, (parameter, _value) in enumerate(query[:5]):
                    mutated = list(query)
                    mutated[index] = (parameter, payload)
                    url = urlunsplit(
                        (parts.scheme, parts.netloc, parts.path, urlencode(mutated), "")
                    )
                    try:
                        response = await client.get(url)
                    except httpx.HTTPError as exc:
                        self._internal_exit_code = 1
                        yield f"Probe request failed: {exc}\n"
                        return
                    content_type = response.headers.get("content-type", "").lower()
                    if (
                        response.status_code < 400
                        and "html" in content_type
                        and payload in response.text[:131072]
                    ):
                        yield json.dumps(
                            {
                                "type": "xss_probe",
                                "indicator": "unescaped-html-reflection",
                                "parameter": parameter,
                                "status": response.status_code,
                                "url": url,
                                "payload": payload,
                            },
                            sort_keys=True,
                        ) + "\n"
                        return
            yield "No unescaped HTML reflection detected\n"
            return

        if name == "sqli_probe":
            target = args[0]
            parts = urlsplit(target)
            query = parse_qsl(parts.query, keep_blank_values=True)
            if not query:
                self._internal_exit_code = 2
                yield "SQLi probe requires a URL with at least one existing GET parameter\n"
                return

            def mutated_url(index: int, value: str) -> str:
                mutated = list(query)
                mutated[index] = (mutated[index][0], value)
                return urlunsplit(
                    (parts.scheme, parts.netloc, parts.path, urlencode(mutated), "")
                )

            def normalized_body(response: httpx.Response) -> str:
                body = response.text[:65536]
                body = re.sub(r"\b\d{10,}\b", "<dynamic-number>", body)
                return re.sub(r"\s+", " ", body).strip()

            sql_error_markers = (
                "sql syntax",
                "sqlstate",
                "sqlite3.",
                "mysql_fetch",
                "postgresql",
                "unterminated quoted string",
                "unclosed quotation mark",
                "odbc sql",
                "ora-",
            )
            async with httpx.AsyncClient(
                timeout=12.0,
                follow_redirects=False,
                # Pentest targets commonly use self-signed certificates. This
                # is a scanner request, not an authenticated trust decision.
                verify=False,  # noqa: S501
                headers={"User-Agent": "AEGIS bounded SQLi indicator probe"},
            ) as client:
                try:
                    baseline = await client.get(target)
                except httpx.HTTPError as exc:
                    self._internal_exit_code = 1
                    yield f"Baseline request failed: {exc}\n"
                    return
                baseline_body = normalized_body(baseline)
                for index, (parameter, value) in enumerate(query[:5]):
                    try:
                        error_response = await client.get(mutated_url(index, value + "'"))
                    except httpx.HTTPError:
                        continue
                    error_body = normalized_body(error_response)
                    marker = next(
                        (
                            item
                            for item in sql_error_markers
                            if item in error_body.lower() and item not in baseline_body.lower()
                        ),
                        "",
                    )
                    if marker:
                        yield json.dumps(
                            {
                                "type": "sqli_probe",
                                "indicator": "database-error-differential",
                                "parameter": parameter,
                                "baseline_status": baseline.status_code,
                                "probe_status": error_response.status_code,
                                "error_marker": marker,
                                "url": target,
                            },
                            sort_keys=True,
                        ) + "\n"
                        return

                    numeric = bool(re.fullmatch(r"-?\d+(?:\.\d+)?", value.strip()))
                    if numeric:
                        true_value = f"{value} AND 1=1"
                        false_value = f"{value} AND 1=2"
                    else:
                        true_value = f"{value}' AND '1'='1' -- "
                        false_value = f"{value}' AND '1'='2' -- "
                    try:
                        true_response = await client.get(mutated_url(index, true_value))
                        false_response = await client.get(mutated_url(index, false_value))
                    except httpx.HTTPError:
                        continue
                    true_body = normalized_body(true_response)
                    false_body = normalized_body(false_response)
                    baseline_true = SequenceMatcher(None, baseline_body, true_body).ratio()
                    true_false = SequenceMatcher(None, true_body, false_body).ratio()
                    length_delta = abs(len(true_body) - len(false_body))
                    if (
                        baseline.status_code == true_response.status_code
                        and baseline_true >= 0.97
                        and (true_false <= 0.85 or length_delta >= 40)
                    ):
                        yield json.dumps(
                            {
                                "type": "sqli_probe",
                                "indicator": "boolean-response-differential",
                                "parameter": parameter,
                                "baseline_status": baseline.status_code,
                                "true_status": true_response.status_code,
                                "false_status": false_response.status_code,
                                "baseline_true_similarity": round(baseline_true, 3),
                                "true_false_similarity": round(true_false, 3),
                                "response_length_delta": length_delta,
                                "url": target,
                            },
                            sort_keys=True,
                        ) + "\n"
                        return
            yield "No strong SQL injection indicator detected\n"
            return

        if name == "zone_transfer":
            target = args[0]
            # Contact only the authorized target. Automatically pivoting to a
            # discovered authoritative server could cross the engagement scope.
            code, output = await self._capture_exec("dig", "axfr", target, "@" + target, timeout=30)
            self._internal_exit_code = code
            yield output
            return

        self._internal_exit_code = 2
        yield f"Unknown internal tool: {name}\n"

    async def _run_web_assessment(self, target: str) -> AsyncGenerator[str, None]:
        """Assess one web application with bounded, same-origin, read-only requests.

        This pass deliberately avoids GET routes whose names imply a state change.
        It emits candidates for those routes so a separately approved exploit-phase
        check can validate them. Response bodies are analyzed in memory and only
        field names/format markers are emitted, preventing discovered secrets from
        leaking into logs and reports.
        """
        try:
            parts = urlsplit(target)
            scheme = parts.scheme.lower()
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            parts = None
            scheme = ""
            port = 0
        if (
            not parts
            or scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            self._internal_exit_code = 2
            yield "Web assessment requires an HTTP(S) URL without user information\n"
            return

        host = parts.hostname.lower()
        display_host = f"[{host}]" if ":" in host else host
        suffix = "" if (scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
        origin = f"{scheme}://{display_host}{suffix}"
        root_url = origin + "/"
        request_count = 0
        request_limit = 48

        async with httpx.AsyncClient(
            timeout=8.0,
            follow_redirects=False,
            verify=False,  # noqa: S501 - authorized scanner supports self-signed targets
            headers={"User-Agent": "AEGIS bounded web assessment"},
        ) as client:
            async def request(
                method: str,
                url: str,
                *,
                headers: dict[str, str] | None = None,
                data: dict[str, str] | None = None,
            ) -> dict[str, object] | None:
                nonlocal request_count
                if request_count >= request_limit:
                    return None
                request_count += 1
                client.cookies.clear()
                try:
                    async with client.stream(
                        method,
                        url,
                        headers=headers,
                        data=data,
                    ) as response:
                        body = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=16384):
                            remaining = 262144 - len(body)
                            if remaining <= 0:
                                break
                            body.extend(chunk[:remaining])
                        encoding = response.encoding or "utf-8"
                        result = {
                            "status": response.status_code,
                            "headers": {key.lower(): value for key, value in response.headers.items()},
                            "set_cookies": response.headers.get_list("set-cookie"),
                            "body": body.decode(encoding, errors="replace"),
                            "content_type": response.headers.get("content-type", "").lower(),
                        }
                    client.cookies.clear()
                    return result
                except (httpx.HTTPError, UnicodeError):
                    client.cookies.clear()
                    return None

            baseline_404 = await request("GET", origin + "/.aegis-not-found-7f31")
            root = await request("GET", root_url)
            if root is None:
                self._internal_exit_code = 1
                yield "Web assessment could not fetch the application root\n"
                return

            root_status = int(root["status"])
            root_body = str(root["body"])
            root_type = str(root["content_type"])
            root_is_html = "html" in root_type or bool(
                re.search(r"(?is)^\s*(?:<!doctype\s+html|<html\b)", root_body[:2048])
            )
            root_headers = root.get("headers") if isinstance(root.get("headers"), dict) else {}
            for identity in _web_identity_records(root_body, root_headers):
                yield json.dumps(identity, sort_keys=True) + "\n"

            # Arbitrary-origin credentialed CORS is safe to validate with a
            # header-only variation and must run before expensive scanners.
            cors = await request(
                "GET",
                root_url,
                headers={"Origin": "https://aegis.invalid"},
            )
            if cors:
                cors_headers = cors["headers"]
                if not isinstance(cors_headers, dict):
                    cors_headers = {}
                if (
                    str(cors_headers.get("access-control-allow-origin", "")).strip()
                    == "https://aegis.invalid"
                    and str(cors_headers.get("access-control-allow-credentials", "")).lower()
                    == "true"
                ):
                    yield json.dumps({
                        "type": "credentialed_cors",
                        "url": root_url,
                        "origin": "https://aegis.invalid",
                        "allow_credentials": True,
                    }, sort_keys=True) + "\n"

            queue: list[tuple[str, str]] = [(root_url, "root")]
            queued = {root_url}
            processed: set[str] = set()
            forms: list[tuple[str, dict[str, object]]] = []
            default_credentials_advertised = bool(
                re.search(r"\bdefault\s+credentials?\b", root_body, re.IGNORECASE)
            )

            def add_candidate(reference: str, source: str) -> None:
                normalized = _normalized_same_origin_url(root_url, reference)
                if not normalized or normalized in queued or len(queued) >= 100:
                    return
                queued.add(normalized)
                queue.append((normalized, source))

            if root_is_html and root_status < 400:
                parser = _WebEndpointParser()
                try:
                    parser.feed(root_body)
                    parser.close()
                except (ValueError, UnicodeError):
                    pass
                for source, reference in parser.references:
                    add_candidate(reference, source)
                for form in parser.forms:
                    forms.append((root_url, form))
                for path in (
                    "/.env", "/.env.production", "/.git/config", "/.aws/credentials",
                    "/config/settings.json", "/debug/config", "/backup/",
                    "/logs/application.log", "/static/app.js", "/static/app.js.map",
                ):
                    add_candidate(path, "bounded-sensitive-path-check")

                robots = await request("GET", origin + "/robots.txt")
                if robots and int(robots["status"]) < 400:
                    self._retain_private_artifact(
                        category="discovery-file",
                        url=origin + "/robots.txt",
                        body=robots["body"],
                        content_type=str(robots["content_type"]),
                    )
                    for match in re.finditer(
                        r"(?im)^\s*(?:allow|disallow):\s*([^\s#]+)",
                        str(robots["body"]),
                    ):
                        add_candidate(match.group(1), "robots")
                sitemap = await request("GET", origin + "/sitemap.xml")
                if sitemap and int(sitemap["status"]) < 400:
                    self._retain_private_artifact(
                        category="discovery-file",
                        url=origin + "/sitemap.xml",
                        body=sitemap["body"],
                        content_type=str(sitemap["content_type"]),
                    )
                    for match in re.finditer(r"(?is)<loc>\s*([^<]+?)\s*</loc>", str(sitemap["body"])):
                        add_candidate(match.group(1), "sitemap")

            emitted_endpoints: set[str] = set()
            emitted_candidates: set[tuple[str, str]] = set()

            def is_soft_404(status: int, body: str) -> bool:
                if status == 404:
                    return True
                if not baseline_404 or status != int(baseline_404["status"]):
                    return False
                baseline_body = re.sub(r"\s+", " ", str(baseline_404["body"])).strip()
                candidate_body = re.sub(r"\s+", " ", body).strip()
                if not baseline_body or not candidate_body:
                    return baseline_body == candidate_body
                return SequenceMatcher(None, baseline_body[:65536], candidate_body[:65536]).ratio() >= 0.97

            while queue and len(processed) < 42 and request_count < request_limit:
                url, source = queue.pop(0)
                if url in processed:
                    continue
                processed.add(url)
                try:
                    url_parts = urlsplit(url)
                except ValueError:
                    continue

                if url != root_url and url not in emitted_endpoints:
                    emitted_endpoints.add(url)
                    yield json.dumps({
                        "type": "web_endpoint",
                        "source": source,
                        "url": url,
                        "has_query": bool(url_parts.query),
                    }, sort_keys=True) + "\n"

                if _SIDE_EFFECT_GET_PATH.search(url_parts.path):
                    key = ("state-changing-get", url)
                    if key not in emitted_candidates:
                        emitted_candidates.add(key)
                        yield json.dumps({
                            "type": "state_changing_get_candidate",
                            "url": url,
                            "reason": "path-name-indicates-state-change",
                        }, sort_keys=True) + "\n"
                    continue

                response = root if url == root_url else await request("GET", url)
                if not response:
                    continue
                status = int(response["status"])
                body = str(response["body"])
                content_type = str(response["content_type"])
                headers = response["headers"]
                set_cookies = response["set_cookies"]
                if not isinstance(headers, dict):
                    headers = {}
                if not isinstance(set_cookies, list):
                    set_cookies = []

                for cookie in set_cookies:
                    name = str(cookie).split("=", 1)[0].strip()[:120]
                    low_cookie = str(cookie).lower()
                    if not re.search(r"(?:session|auth|token|jwt|sid|role)", name, re.IGNORECASE):
                        continue
                    missing = [
                        flag
                        for flag, marker in (
                            ("HttpOnly", "httponly"),
                            ("Secure", "secure"),
                            ("SameSite", "samesite="),
                        )
                        if marker not in low_cookie
                    ]
                    if missing:
                        yield json.dumps({
                            "type": "insecure_cookie",
                            "url": url,
                            "cookie_name": name,
                            "missing": missing,
                        }, sort_keys=True) + "\n"

                query = parse_qsl(url_parts.query, keep_blank_values=True)
                for index, (parameter, _value) in enumerate(query[:8]):
                    if parameter.lower() not in _REDIRECT_PARAMETERS:
                        continue
                    mutated = list(query)
                    proof_url = "https://aegis.invalid/aegis-open-redirect"
                    mutated[index] = (parameter, proof_url)
                    probe_url = urlunsplit((
                        url_parts.scheme,
                        url_parts.netloc,
                        url_parts.path,
                        urlencode(mutated),
                        "",
                    ))
                    redirect_response = await request("GET", probe_url)
                    if not redirect_response:
                        continue
                    redirect_headers = redirect_response["headers"]
                    if not isinstance(redirect_headers, dict):
                        redirect_headers = {}
                    location = str(redirect_headers.get("location", ""))
                    if int(redirect_response["status"]) in {301, 302, 303, 307, 308} and location.startswith(proof_url):
                        yield json.dumps({
                            "type": "open_redirect",
                            "url": url,
                            "parameter": parameter,
                            "status": int(redirect_response["status"]),
                            "location_origin": "https://aegis.invalid",
                        }, sort_keys=True) + "\n"
                    break

                cookie_pairs: dict[str, str] = {}
                for cookie in set_cookies:
                    pair = str(cookie).split(";", 1)[0]
                    if "=" in pair:
                        cookie_name, cookie_value = pair.split("=", 1)
                        cookie_pairs[cookie_name.strip()] = cookie_value.strip()
                privileged = [
                    name
                    for name, value in cookie_pairs.items()
                    if (
                        re.search(r"(?:role|admin|privilege|is_admin)", name, re.IGNORECASE)
                        and value.lower() in {"1", "true", "admin", "administrator", "root", "superuser"}
                    )
                ]
                if privileged:
                    validation_url = _normalized_same_origin_url(
                        root_url,
                        str(headers.get("location") or "/admin"),
                    )
                    yield json.dumps({
                        "type": "privileged_cookie_candidate",
                        "url": url,
                        "cookie_names": privileged,
                        "validation_url": validation_url or origin + "/admin",
                        "status": status,
                    }, sort_keys=True) + "\n"

                looks_html = "html" in content_type or bool(
                    re.search(r"(?is)^\s*(?:<!doctype\s+html|<html\b)", body[:2048])
                )
                is_directory_listing = bool(
                    re.search(r"(?is)<title>\s*index of\s+|<h1>\s*index of\s+", body)
                )
                if looks_html and status < 400:
                    parser = _WebEndpointParser()
                    try:
                        parser.feed(body)
                        parser.close()
                    except (ValueError, UnicodeError):
                        pass
                    for link_source, reference in parser.references:
                        add_candidate(reference, link_source)
                    for form in parser.forms:
                        forms.append((url, form))
                    if is_directory_listing:
                        self._retain_private_artifact(
                            category="directory-listing",
                            url=url,
                            body=body,
                            content_type=content_type,
                        )
                        yield json.dumps({
                            "type": "directory_listing",
                            "url": url,
                            "status": status,
                        }, sort_keys=True) + "\n"
                    source_map = re.search(r"(?m)sourceMappingURL\s*=\s*([^\s*]+)", body)
                    if source_map:
                        add_candidate(source_map.group(1), "source-map-reference")

                parsed_json: object | None = None
                if "json" in content_type or body.lstrip().startswith(("{", "[")):
                    try:
                        parsed_json = json.loads(body)
                    except json.JSONDecodeError:
                        parsed_json = None
                fields = _json_field_names(parsed_json) if parsed_json is not None else []
                sensitive_fields = sorted({field for field in fields if _SECRET_KEY.search(field)})
                if (
                    status < 400
                    and url_parts.path.startswith("/api/")
                    and sensitive_fields
                ):
                    self._retain_private_artifact(
                        category="unauthenticated-sensitive-data",
                        url=url,
                        body=body,
                        content_type=content_type,
                    )
                    yield json.dumps({
                        "type": "unauthenticated_sensitive_data",
                        "url": url,
                        "status": status,
                        "sensitive_fields": sensitive_fields,
                    }, sort_keys=True) + "\n"

                if isinstance(parsed_json, dict):
                    records = parsed_json.get("records")
                    if parsed_json.get("authenticated") is False and isinstance(records, list) and records:
                        tenants = {
                            str(item.get("tenant"))
                            for item in records
                            if isinstance(item, dict) and item.get("tenant") is not None
                        }
                        has_tenant_filter = query and any(key.lower() == "tenant" for key, _ in query)
                        if len(tenants) > 1 or not has_tenant_filter:
                            self._retain_private_artifact(
                                category="cross-tenant-data",
                                url=url,
                                body=body,
                                content_type=content_type,
                            )
                            yield json.dumps({
                                "type": "cross_tenant_data_exposure" if len(tenants) > 1 else "unauthenticated_sensitive_data",
                                "url": url,
                                "status": status,
                                "record_count": len(records),
                                "tenant_count": len(tenants),
                                "fields": _json_field_names(records),
                            }, sort_keys=True) + "\n"
                        # A filtered request can hide the breadth of the leak.
                        if has_tenant_filter:
                            unfiltered = [(key, value) for key, value in query if key.lower() != "tenant"]
                            unfiltered_url = urlunsplit((
                                url_parts.scheme,
                                url_parts.netloc,
                                url_parts.path,
                                urlencode(unfiltered),
                                "",
                            ))
                            broad = await request("GET", unfiltered_url)
                            if broad:
                                try:
                                    broad_json = json.loads(str(broad["body"]))
                                except json.JSONDecodeError:
                                    broad_json = None
                                broad_records = broad_json.get("records") if isinstance(broad_json, dict) else None
                                broad_tenants = {
                                    str(item.get("tenant"))
                                    for item in (broad_records if isinstance(broad_records, list) else [])
                                    if isinstance(item, dict) and item.get("tenant") is not None
                                }
                                if isinstance(broad_json, dict) and broad_json.get("authenticated") is False and len(broad_tenants) > 1:
                                    self._retain_private_artifact(
                                        category="cross-tenant-data",
                                        url=unfiltered_url,
                                        body=broad["body"],
                                        content_type=str(broad["content_type"]),
                                    )
                                    yield json.dumps({
                                        "type": "cross_tenant_data_exposure",
                                        "url": url,
                                        "status": int(broad["status"]),
                                        "record_count": len(broad_records),
                                        "tenant_count": len(broad_tenants),
                                        "fields": _json_field_names(broad_records),
                                    }, sort_keys=True) + "\n"

                    for key, value in parsed_json.items():
                        if "path" not in str(key).lower() and "endpoint" not in str(key).lower():
                            continue
                        values = value if isinstance(value, list) else [value]
                        for candidate_path in values[:20]:
                            if (
                                isinstance(candidate_path, str)
                                and candidate_path.startswith("/")
                                and not candidate_path.startswith(("/opt/", "/usr/", "/var/", "/etc/"))
                            ):
                                add_candidate(candidate_path, "response-path")

                record_list: list[object] = []
                if isinstance(parsed_json, list):
                    record_list = parsed_json
                elif isinstance(parsed_json, dict):
                    for key in ("notes", "items", "users", "data"):
                        value = parsed_json.get(key)
                        if isinstance(value, list):
                            record_list = value
                            break
                record_fields = _json_field_names(record_list)
                if (
                    status < 400
                    and url_parts.path.startswith("/api/")
                    and record_list
                    and not sensitive_fields
                    and any(field in record_fields for field in ("owner", "tenant", "username"))
                    and any(field in record_fields for field in ("body", "subject", "password", "contract_value", "email"))
                ):
                    self._retain_private_artifact(
                        category="unauthenticated-object-data",
                        url=url,
                        body=body,
                        content_type=content_type,
                    )
                    yield json.dumps({
                        "type": "unauthenticated_object_data",
                        "url": url,
                        "status": status,
                        "record_count": len(record_list),
                        "fields": record_fields,
                    }, sort_keys=True) + "\n"

                if (
                    status < 400
                    and not is_soft_404(status, body)
                    and (
                        _SENSITIVE_RESOURCE_PATH.search(url_parts.path)
                        or (_SECRET_KEY.search(body) and re.search(r"\.(?:js|json|map|txt|log|bak)$", url_parts.path, re.IGNORECASE))
                    )
                    and not is_directory_listing
                ):
                    markers = _redacted_resource_markers(body)
                    if _SECRET_KEY.search(body) and "secret-like-keyword" not in markers:
                        markers.append("secret-like-keyword")
                    if url_parts.path.endswith(".map"):
                        category = "source-map"
                    elif url_parts.path.startswith("/.git"):
                        category = "version-control-metadata"
                    elif re.search(r"/(?:backup|backups?)/?$", url_parts.path, re.IGNORECASE):
                        category = "backup-directory"
                    elif re.search(r"\.(?:bak|backup|old|sql|sqlite|db|gz|zip|tar)$", url_parts.path, re.IGNORECASE):
                        category = "backup-file"
                    elif "debug" in url_parts.path.lower():
                        category = "debug-configuration"
                    elif url_parts.path.lower().endswith(".log"):
                        category = "log-file"
                    else:
                        category = "secret-or-configuration"
                    self._retain_private_artifact(
                        category=category,
                        url=url,
                        body=body,
                        content_type=content_type,
                    )
                    yield json.dumps({
                        "type": "exposed_sensitive_resource",
                        "url": url,
                        "status": status,
                        "category": category,
                        "markers": markers[:24],
                        "content_type": content_type[:120],
                    }, sort_keys=True) + "\n"

                if (
                    status < 400
                    and not query
                    and url_parts.path.startswith("/api/")
                    and record_list
                    and "id" in record_fields
                ):
                    options = await request("OPTIONS", url)
                    if options:
                        option_headers = options["headers"]
                        if not isinstance(option_headers, dict):
                            option_headers = {}
                        allow_methods = str(
                            option_headers.get("allow")
                            or option_headers.get("access-control-allow-methods")
                            or ""
                        )
                        if "POST" in allow_methods.upper():
                            yield json.dumps({
                                "type": "unauthenticated_write_candidate",
                                "url": url,
                                "status": status,
                                "advertised_methods": sorted({
                                    method.strip().upper()
                                    for method in allow_methods.split(",")
                                    if method.strip()
                                }),
                                "fields": record_fields,
                            }, sort_keys=True) + "\n"

            # Reuse one low-risk identifier parameter observed elsewhere on the
            # same application to uncover a root handler that accepts the same
            # input but did not advertise it. The existing bounded SQLi/XSS
            # probes will decide whether the parameter is meaningful.
            root_query_names = {
                key.lower(): value
                for endpoint in emitted_endpoints
                for key, value in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True)
                if key.lower() in {"id", "item", "product", "record"}
            }
            if root_query_names:
                parameter = next(iter(root_query_names))
                value = root_query_names[parameter] or "1"
                derived = root_url + "?" + urlencode([(parameter, value)])
                if derived not in emitted_endpoints:
                    yield json.dumps({
                        "type": "web_endpoint",
                        "source": "same-origin-parameter-discovery",
                        "url": derived,
                        "has_query": True,
                    }, sort_keys=True) + "\n"

            # Probe only authentication forms, with one intentionally invalid
            # request and one quote variation. This cannot create an account or
            # modify application data, and avoids credential guessing.
            seen_forms: set[str] = set()
            for page_url, form in forms[:20]:
                action = _normalized_same_origin_url(
                    root_url,
                    str(form.get("action") or page_url),
                )
                method = str(form.get("method") or "get").lower()
                if not action or action in seen_forms or method != "post":
                    continue
                seen_forms.add(action)
                if not _AUTH_FORM_PATH.search(urlsplit(action).path):
                    continue
                inputs = [
                    item
                    for item in (form.get("inputs") if isinstance(form.get("inputs"), list) else [])
                    if isinstance(item, dict)
                    and item.get("name")
                    and str(item.get("type") or "text").lower() not in {"submit", "button", "image", "file"}
                ][:12]
                if not inputs:
                    continue
                base_data = {
                    str(item["name"]): (
                        str(item.get("value") or "")
                        if str(item.get("type") or "").lower() == "hidden"
                        else "aegis-invalid-7f31"
                    )
                    for item in inputs
                }
                baseline = await request("POST", action, data=base_data)
                injectable = next(
                    (
                        item
                        for item in inputs
                        if str(item.get("type") or "text").lower() in {"text", "email", "password", "search", ""}
                    ),
                    None,
                )
                if not baseline or not injectable:
                    continue
                probe_data = dict(base_data)
                parameter = str(injectable["name"])
                probe_data[parameter] = "aegis-invalid-7f31'"
                probe = await request("POST", action, data=probe_data)
                if not probe:
                    continue
                baseline_body = str(baseline["body"]).lower()
                probe_body = str(probe["body"]).lower()
                marker = next((
                    item for item in (
                        "sql syntax", "sqlstate", "sqlite3.", "mysql_fetch", "postgresql",
                        "unterminated quoted string", "unclosed quotation mark", "odbc sql", "ora-",
                    )
                    if item in probe_body and item not in baseline_body
                ), "")
                if marker:
                    yield json.dumps({
                        "type": "form_sqli_probe",
                        "url": action,
                        "page_url": page_url,
                        "method": "POST",
                        "parameter": parameter,
                        "baseline_status": int(baseline["status"]),
                        "probe_status": int(probe["status"]),
                        "error_marker": marker,
                    }, sort_keys=True) + "\n"

                default_user = next((
                    str(item.get("value") or "")
                    for item in inputs
                    if str(item.get("name") or "").lower() in {"username", "user", "login", "email"}
                    and item.get("value")
                ), "")
                if default_credentials_advertised and default_user:
                    yield json.dumps({
                        "type": "default_login_candidate",
                        "url": action,
                        "username": default_user[:120],
                        "basis": "application-advertises-default-credentials-and-prefills-account",
                    }, sort_keys=True) + "\n"

        if request_count >= request_limit:
            yield json.dumps({
                "type": "web_assessment_limit",
                "url": root_url,
                "requests": request_count,
            }, sort_keys=True) + "\n"

    async def _run_csrf_get_check(self, target: str) -> AsyncGenerator[str, None]:
        try:
            parts = urlsplit(target)
        except ValueError:
            parts = None
        if not parts or parts.scheme not in {"http", "https"} or not parts.hostname or not parts.query:
            self._internal_exit_code = 2
            yield "CSRF GET validation requires an HTTP(S) URL with query parameters\n"
            return
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=False, verify=False) as client:  # noqa: S501
                response = await client.get(target, headers={"User-Agent": "AEGIS approved CSRF validation"})
        except httpx.HTTPError as exc:
            self._internal_exit_code = 1
            yield f"Approved validation request failed: {exc}\n"
            return
        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError):
            payload = None
        fields = _json_field_names(payload) if payload is not None else []
        accepted = isinstance(payload, dict) and any(
            payload.get(key) is True for key in ("accepted", "updated", "success", "completed")
        )
        csrf_absent = isinstance(payload, dict) and (
            payload.get("csrf_token_checked") is False
            or not any("csrf" in field.lower() for field in fields)
        )
        if response.status_code < 400 and accepted and csrf_absent:
            self._retain_private_artifact(
                category="approved-state-change-response",
                url=target,
                body=response.text,
                content_type=response.headers.get("content-type", ""),
            )
            yield json.dumps({
                "type": "csrf_get_confirmation",
                "url": target,
                "status": response.status_code,
                "result_fields": fields,
                "csrf_token_checked": False,
            }, sort_keys=True) + "\n"
        else:
            yield "The approved GET request did not provide strong evidence of a state change without CSRF validation\n"

    async def _run_cookie_auth_check(self, target: str) -> AsyncGenerator[str, None]:
        try:
            target_parts = urlsplit(target)
        except ValueError:
            target_parts = None
        if not target_parts or target_parts.scheme not in {"http", "https"} or not target_parts.hostname:
            self._internal_exit_code = 2
            yield "Cookie authorization validation requires an HTTP(S) URL\n"
            return
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=False, verify=False) as client:  # noqa: S501
            try:
                client.cookies.clear()
                issuer = await client.get(target, headers={"User-Agent": "AEGIS approved cookie authorization validation"})
            except httpx.HTTPError as exc:
                self._internal_exit_code = 1
                yield f"Cookie issuer request failed: {exc}\n"
                return
            cookie_pairs = {
                cookie.name: cookie.value
                for cookie in issuer.cookies.jar
                if cookie.name and cookie.value
            }
            privileged_names = [
                name for name, value in cookie_pairs.items()
                if re.search(r"(?:role|admin|privilege|is_admin)", name, re.IGNORECASE)
                and value.lower() in {"1", "true", "admin", "administrator", "root", "superuser"}
            ]
            validation_url = _normalized_same_origin_url(
                target,
                issuer.headers.get("location") or "/admin",
            )
            if not privileged_names or not validation_url:
                yield "The endpoint did not issue a recognizable privileged cookie and same-origin validation target\n"
                return
            try:
                client.cookies.clear()
                baseline = await client.get(validation_url)
                client.cookies.clear()
                cookie_header = "; ".join(f"{name}={value}" for name, value in cookie_pairs.items())
                authorized = await client.get(validation_url, headers={"Cookie": cookie_header})
            except httpx.HTTPError as exc:
                self._internal_exit_code = 1
                yield f"Authorization comparison failed: {exc}\n"
                return
        if baseline.status_code in {401, 403} and authorized.status_code < 400:
            try:
                authorized_body: object = authorized.json()
            except (json.JSONDecodeError, ValueError):
                authorized_body = authorized.text
            self._retain_private_artifact(
                category="approved-authorization-bypass-response",
                url=validation_url,
                body={"cookies": cookie_pairs, "response": authorized_body},
                content_type=authorized.headers.get("content-type", ""),
            )
            yield json.dumps({
                "type": "cookie_auth_bypass_confirmation",
                "url": target,
                "validation_url": validation_url,
                "cookie_names": sorted(cookie_pairs),
                "privileged_cookie_names": sorted(privileged_names),
                "baseline_status": baseline.status_code,
                "authorized_status": authorized.status_code,
            }, sort_keys=True) + "\n"
        else:
            yield "The privileged-cookie request did not bypass an unauthenticated authorization failure\n"

    async def _run_unauthenticated_write_check(self, target: str) -> AsyncGenerator[str, None]:
        try:
            parts = urlsplit(target)
        except ValueError:
            parts = None
        if not parts or parts.scheme not in {"http", "https"} or not parts.hostname:
            self._internal_exit_code = 2
            yield "Write validation requires an HTTP(S) URL\n"
            return
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=False, verify=False) as client:  # noqa: S501
            try:
                client.cookies.clear()
                baseline = await client.get(target)
                payload = baseline.json()
            except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
                self._internal_exit_code = 1
                yield f"Could not obtain a structured baseline for write validation: {exc}\n"
                return
            records = payload if isinstance(payload, list) else None
            if isinstance(payload, dict):
                records = next((
                    value for value in payload.values()
                    if isinstance(value, list) and value and isinstance(value[0], dict)
                ), None)
            first = records[0] if isinstance(records, list) and records and isinstance(records[0], dict) else None
            if not first or "id" not in first:
                yield "No record-shaped object was available for an idempotent write validation\n"
                return
            form_data = {
                str(key): str(value)
                for key, value in first.items()
                if isinstance(value, (str, int, float, bool))
            }
            try:
                client.cookies.clear()
                response = await client.post(target, data=form_data)
            except httpx.HTTPError as exc:
                self._internal_exit_code = 1
                yield f"Approved write validation failed: {exc}\n"
                return
        try:
            result = response.json()
        except (json.JSONDecodeError, ValueError):
            result = None
        confirmed = response.status_code < 400 and isinstance(result, dict) and any(
            result.get(key) is True for key in ("updated", "created", "success", "accepted")
        )
        if confirmed:
            self._retain_private_artifact(
                category="approved-unauthenticated-write-response",
                url=target,
                body=response.text,
                content_type=response.headers.get("content-type", ""),
            )
            yield json.dumps({
                "type": "unauthenticated_write_confirmation",
                "url": target,
                "status": response.status_code,
                "record_id": str(first.get("id"))[:120],
                "submitted_fields": sorted(form_data),
                "idempotent_same_value_write": True,
            }, sort_keys=True) + "\n"
        else:
            yield "The approved unauthenticated write was rejected or did not report a state change\n"

    async def _run_default_web_login(self, target: str) -> AsyncGenerator[str, None]:
        try:
            parts = urlsplit(target)
        except ValueError:
            parts = None
        if not parts or parts.scheme not in {"http", "https"} or not parts.hostname:
            self._internal_exit_code = 2
            yield "Default-login validation requires an HTTP(S) form URL\n"
            return
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=False, verify=False) as client:  # noqa: S501
            try:
                client.cookies.clear()
                page = await client.get(target)
            except httpx.HTTPError as exc:
                self._internal_exit_code = 1
                yield f"Login form request failed: {exc}\n"
                return
            parser = _WebEndpointParser()
            try:
                parser.feed(page.text[:262144])
                parser.close()
            except (ValueError, UnicodeError):
                pass
            form = next((
                item for item in parser.forms
                if str(item.get("method") or "get").lower() == "post"
            ), None)
            if not form:
                yield "No POST login form was available for the approved check\n"
                return
            action = _normalized_same_origin_url(target, str(form.get("action") or target))
            inputs = form.get("inputs") if isinstance(form.get("inputs"), list) else []
            username_item = next((
                item for item in inputs
                if isinstance(item, dict)
                and str(item.get("name") or "").lower() in {"username", "user", "login", "email"}
                and item.get("value")
            ), None)
            password_item = next((
                item for item in inputs
                if isinstance(item, dict)
                and (
                    str(item.get("type") or "").lower() == "password"
                    or "password" in str(item.get("name") or "").lower()
                )
            ), None)
            if not action or not username_item or not password_item:
                yield "The form did not expose a prefilled account and password field\n"
                return
            username = str(username_item.get("value"))
            username_name = str(username_item.get("name"))
            password_name = str(password_item.get("name"))
            invalid = {username_name: "aegis-invalid-7f31", password_name: "aegis-invalid-7f31"}
            candidate = {username_name: username, password_name: username}
            try:
                client.cookies.clear()
                baseline = await client.post(action, data=invalid)
                client.cookies.clear()
                response = await client.post(action, data=candidate)
            except httpx.HTTPError as exc:
                self._internal_exit_code = 1
                yield f"Approved login comparison failed: {exc}\n"
                return
        success = (
            baseline.status_code in {400, 401, 403}
            and response.status_code in {200, 201, 202, 301, 302, 303, 307, 308}
            and (
                bool(response.headers.get_list("set-cookie"))
                or bool(response.headers.get("location"))
            )
        )
        if success:
            self._retain_private_artifact(
                category="approved-default-login-access",
                url=action,
                body={
                    "username": username,
                    "password": username,
                    "status": response.status_code,
                    "location": response.headers.get("location", ""),
                    "set_cookie": response.headers.get_list("set-cookie"),
                },
                content_type=response.headers.get("content-type", ""),
            )
            yield json.dumps({
                "type": "default_web_login_confirmation",
                "url": action,
                "username": username[:120],
                "baseline_status": baseline.status_code,
                "candidate_status": response.status_code,
                "session_cookie_names": sorted(cookie.name for cookie in response.cookies.jar if cookie.name),
                "redirect_path": urlsplit(response.headers.get("location") or "").path,
                "password_strategy": "same-as-prefilled-username",
            }, sort_keys=True) + "\n"
        else:
            yield "The approved default-credential candidate did not authenticate\n"

    async def _capture_exec(self, *argv: str, timeout: float) -> tuple[int, str]:
        kwargs = {
            "stdin": asyncio.subprocess.DEVNULL,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.STDOUT,
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        elif os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = await asyncio.create_subprocess_exec(*argv, **kwargs)
        task_id = f"internal_{id(proc)}"
        self.active_processes[task_id] = proc
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            await self._terminate(proc)
            if proc.returncode is None:
                await proc.wait()
            return 124, "[TIMEOUT]\n"
        except asyncio.CancelledError:
            await self._terminate(proc)
            raise
        finally:
            self.active_processes.pop(task_id, None)
        return proc.returncode or 0, output.decode(errors="replace")

    async def _terminate(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        if os.name == "nt":
            # CREATE_NEW_PROCESS_GROUP does not make Process.terminate() kill
            # descendants on Windows. taskkill /T prevents timed-out scanners
            # from surviving after their AEGIS tool run has ended.
            try:
                taskkill = os.path.join(
                    os.environ.get("SystemRoot", r"C:\Windows"),
                    "System32",
                    "taskkill.exe",
                )
                killer = await asyncio.create_subprocess_exec(
                    taskkill, "/PID", str(proc.pid), "/T", "/F",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(killer.wait(), timeout=3.0)
                await asyncio.wait_for(proc.wait(), timeout=2.0)
                return
            except (OSError, asyncio.TimeoutError):
                # Fall back to terminating the direct child if taskkill is
                # unavailable or Windows has already reaped part of the tree.
                pass
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
        except ProcessLookupError:
            return
        except (PermissionError, OSError):
            try:
                proc.terminate()
            except (ProcessLookupError, PermissionError, OSError):
                return
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            return
        except asyncio.TimeoutError:
            pass
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError, OSError):
                pass

    def kill_all(self):
        for proc in list(self.active_processes.values()):
            if proc.returncode is not None:
                continue
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                elif os.name == "nt":
                    taskkill = os.path.join(
                        os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32",
                        "taskkill.exe",
                    )
                    subprocess.run(  # noqa: S603 -- fixed system binary and child PID
                        [taskkill, "/PID", str(proc.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=3,
                        check=False,
                    )
                else:
                    proc.kill()
            except (ProcessLookupError, PermissionError, OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except (ProcessLookupError, PermissionError, OSError):
                    pass
        self.active_processes.clear()
