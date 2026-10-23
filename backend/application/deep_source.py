"""Bounded deep source analysis for imported Application Research snapshots.

The stage deliberately remains static and read-only.  It invokes Semgrep with
AEGIS-owned local taint rules and Gitleaks with an AEGIS-owned configuration,
normalizes their output, stores exact secret evidence only in the private
vault, and correlates dependency records with source imports.  Imported code,
build scripts, package managers, and project-supplied analyzer configuration
are never executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .analyzer import MAX_PRIVATE_EVIDENCE_BYTES, redact_source_evidence

MAX_TOOL_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_TOOL_ERROR_BYTES = 2 * 1024 * 1024
MAX_DEEP_FINDINGS = 500
MAX_COMPONENT_REFERENCES = 2_000
MAX_REFERENCE_FILES = 20_000
MAX_REFERENCE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 1024 * 1024
MAX_REFERENCES_PER_COMPONENT = 5
LOG4SHELL_CVE_ID = "CVE-2021-44228"
LOG4J_REQUEST_TO_LOG_RULE = "semgrep.aegis.java.log4j-request-to-log"

PACKAGE_IMPORT_ALIASES = {
    "beautifulsoup4": "bs4",
    "opencv_python": "cv2",
    "pillow": "pil",
    "pyyaml": "yaml",
    "python_dateutil": "dateutil",
    "scikit_learn": "sklearn",
}

SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".jsx",
    ".kt", ".kts", ".php", ".py", ".rb", ".rs", ".swift", ".ts",
    ".tsx",
}

# These rules are intentionally local.  A deep scan never uploads source or
# silently downloads a mutable registry ruleset.  Semgrep's taint engine adds
# source-to-sink evidence beyond the built-in line-oriented triage.
SEMGREP_RULES = r"""
rules:
  - id: aegis.python.request-to-command
    languages: [python]
    message: Attacker-controlled web request data may reach operating-system command execution.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: web request input
        sink: operating-system command execution
        severity: critical
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
          - pattern: request.values.get(...)
          - pattern: request.get_json(...)
          - pattern: request.json
          - pattern: $REQ.query_params.get(...)
          - pattern: $REQ.path_params.get(...)
    pattern-sinks:
      - pattern-either:
          - pattern: os.system(...)
          - pattern: subprocess.$FUNC(..., shell=True, ...)
          - pattern: subprocess.$FUNC(..., shell = True, ...)

  - id: aegis.python.request-to-eval
    languages: [python]
    message: Attacker-controlled web request data may reach dynamic evaluation.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: web request input
        sink: Python eval or exec
        severity: critical
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
          - pattern: request.values.get(...)
          - pattern: request.get_json(...)
          - pattern: request.json
    pattern-sinks:
      - pattern-either:
          - pattern: eval(...)
          - pattern: exec(...)

  - id: aegis.python.request-to-unsafe-deserialization
    languages: [python]
    message: Attacker-controlled web request data may reach an unsafe deserializer.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: web request input
        sink: unsafe Python deserialization
        severity: high
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: request.get_data(...)
          - pattern: request.data
          - pattern: request.get_json(...)
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
    pattern-sinks:
      - pattern-either:
          - pattern: pickle.loads(...)
          - pattern: pickle.load(...)
          - pattern: yaml.load(...)

  - id: aegis.python.request-to-sql
    languages: [python]
    message: Attacker-controlled web request data may reach a SQL query string.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: web request input
        sink: SQL query execution
        severity: high
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
          - pattern: request.values.get(...)
          - pattern: request.get_json(...)
          - pattern: request.json
    pattern-sinks:
      - patterns:
          - pattern: $CURSOR.execute($QUERY, ...)
          - focus-metavariable: $QUERY
      - patterns:
          - pattern: $CURSOR.executescript($QUERY, ...)
          - focus-metavariable: $QUERY

  - id: aegis.python.request-to-template
    languages: [python]
    message: Attacker-controlled web request data may reach an inline template renderer.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: web request input
        sink: server-side template rendering
        severity: high
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
          - pattern: request.values.get(...)
    pattern-sinks:
      - pattern: render_template_string(...)

  - id: aegis.javascript.request-to-command
    languages: [javascript, typescript]
    message: Attacker-controlled HTTP request data may reach operating-system command execution.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: HTTP request input
        sink: Node.js command execution
        severity: critical
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.query
          - pattern: $REQ.query.$KEY
          - pattern: $REQ.body
          - pattern: $REQ.body.$KEY
          - pattern: $REQ.params
          - pattern: $REQ.params.$KEY
    pattern-sinks:
      - pattern-either:
          - pattern: child_process.exec(...)
          - pattern: child_process.execSync(...)
          - pattern: require("child_process").exec(...)
          - pattern: require("child_process").execSync(...)

  - id: aegis.javascript.request-to-eval
    languages: [javascript, typescript]
    message: Attacker-controlled HTTP request data may reach dynamic JavaScript evaluation.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: HTTP request input
        sink: JavaScript eval or Function
        severity: critical
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.query
          - pattern: $REQ.query.$KEY
          - pattern: $REQ.body
          - pattern: $REQ.body.$KEY
          - pattern: $REQ.params
          - pattern: $REQ.params.$KEY
    pattern-sinks:
      - pattern-either:
          - pattern: eval(...)
          - pattern: Function(...)
          - pattern: new Function(...)

  - id: aegis.javascript.request-to-sql
    languages: [javascript, typescript]
    message: Attacker-controlled HTTP request data may reach a SQL query string.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: HTTP request input
        sink: SQL query execution
        severity: high
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.query
          - pattern: $REQ.query.$KEY
          - pattern: $REQ.body
          - pattern: $REQ.body.$KEY
          - pattern: $REQ.params
          - pattern: $REQ.params.$KEY
    pattern-sinks:
      - pattern-either:
          - pattern: $DB.query(...)
          - pattern: $DB.execute(...)

  - id: aegis.java.request-to-command
    languages: [java]
    message: Attacker-controlled servlet request data may reach command execution.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: servlet request parameter
        sink: Java process execution
        severity: critical
    mode: taint
    pattern-sources:
      - pattern: $REQ.getParameter(...)
    pattern-sinks:
      - pattern-either:
          - pattern: Runtime.getRuntime().exec(...)
          - pattern: new ProcessBuilder(...)

  - id: aegis.java.log4j-request-to-log
    languages: [java]
    message: Attacker-controlled servlet request data may reach a Log4j logging call.
    severity: WARNING
    metadata:
      aegis:
        kind: reachability
        source: servlet request parameter
        sink: Log4j logging call
        severity: high
        component_hint: log4j-core
    mode: taint
    pattern-sources:
      - pattern: $REQ.getParameter(...)
    pattern-sinks:
      - patterns:
          - pattern: $LOGGER.$METHOD(...)
          - pattern-inside: |
              import org.apache.logging.log4j.Logger;
              ...
              class $CLASS {
                ...
                Logger $LOGGER = LogManager.getLogger(...);
                ...
              }
          - metavariable-regex:
              metavariable: $METHOD
              regex: '^(?:trace|debug|info|warn|error|fatal|log)$'

  - id: aegis.php.request-to-command
    languages: [php]
    message: Attacker-controlled request data may reach PHP command execution.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: PHP request input
        sink: operating-system command execution
        severity: critical
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
    pattern-sinks:
      - pattern-either:
          - pattern: system(...)
          - pattern: exec(...)
          - pattern: shell_exec(...)
          - pattern: passthru(...)

  - id: aegis.php.request-to-deserialization
    languages: [php]
    message: Attacker-controlled request data may reach PHP object deserialization.
    severity: ERROR
    metadata:
      aegis:
        kind: reachability
        source: PHP request input
        sink: PHP unserialize
        severity: high
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
    pattern-sinks:
      - pattern: unserialize(...)
""".strip() + "\n"

GITLEAKS_CONFIG = """title = \"AEGIS private artifact scan\"\n\n[extend]\nuseDefault = true\n"""


@dataclass(frozen=True)
class ToolRun:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float


def _find_tool(name: str) -> str | None:
    candidates = [
        shutil.which(name),
        "/opt/homebrew/bin/" + name,
        "/usr/local/bin/" + name,
        str(Path.home() / ".local" / "bin" / name),
    ]
    if os.name == "nt":
        candidates.extend([
            shutil.which(name + ".exe"),
            str(Path.home() / "scoop" / "shims" / (name + ".exe")),
        ])
    return next(
        (
            str(Path(candidate)) for candidate in candidates
            if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK)
        ),
        None,
    )


def find_semgrep() -> str | None:
    return _find_tool("semgrep")


def find_gitleaks() -> str | None:
    return _find_tool("gitleaks")


def _tool_environment() -> dict[str, str]:
    allowed = {
        "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL",
        "SYSTEMROOT", "WINDIR", "PATHEXT", "USERPROFILE", "APPDATA",
        "LOCALAPPDATA", "SSL_CERT_FILE", "SSL_CERT_DIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["NO_COLOR"] = "1"
    return environment


def _run_bounded(
    command: list[str],
    working_directory: Path,
    timeout_seconds: int,
    watched_paths: Iterable[Path] = (),
    environment_overrides: dict[str, str] | None = None,
) -> ToolRun:
    """Run a fixed argv with bounded disk-backed output and no stdin/shell."""
    started = time.perf_counter()
    deadline = time.monotonic() + timeout_seconds
    failure = ""
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        environment = _tool_environment()
        environment.update(environment_overrides or {})
        process = subprocess.Popen(  # noqa: S603 - executable is resolved locally and argv is fixed
            command,
            cwd=working_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
        )
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = f"Analyzer exceeded the {timeout_seconds} second limit"
                process.kill()
                break
            if os.fstat(stdout_file.fileno()).st_size > MAX_TOOL_OUTPUT_BYTES:
                failure = "Analyzer output exceeded the 32 MiB limit"
                process.kill()
                break
            if os.fstat(stderr_file.fileno()).st_size > MAX_TOOL_ERROR_BYTES:
                failure = "Analyzer error output exceeded the 2 MiB limit"
                process.kill()
                break
            for path in watched_paths:
                try:
                    if path.is_file() and path.stat().st_size > MAX_TOOL_OUTPUT_BYTES:
                        failure = "Analyzer report exceeded the 32 MiB limit"
                        process.kill()
                        break
                except OSError:
                    continue
            if failure:
                break
            time.sleep(0.05)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(MAX_TOOL_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(MAX_TOOL_ERROR_BYTES + 1)
    if failure:
        raise RuntimeError(failure)
    if len(stdout) > MAX_TOOL_OUTPUT_BYTES or len(stderr) > MAX_TOOL_ERROR_BYTES:
        raise RuntimeError("Analyzer output exceeded its bounded result limit")
    return ToolRun(
        returncode=int(process.returncode or 0),
        stdout=stdout,
        stderr=stderr,
        duration_seconds=round(time.perf_counter() - started, 3),
    )


def _scan_target(root: Path) -> tuple[Path, str]:
    return (root, ".") if root.is_dir() else (root.parent, root.name)


def _safe_relative(raw_path: object, root: Path, working_directory: Path) -> str:
    candidate = Path(str(raw_path or ""))
    if not candidate.is_absolute():
        candidate = working_directory / candidate
    try:
        resolved = candidate.resolve()
        if root.is_file():
            if resolved != root.resolve():
                raise ValueError
            return root.name
        return resolved.relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return Path(str(raw_path or "unknown")).name[:500] or "unknown"


def _safe_error(value: bytes | str, root: Path) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = text.replace(str(root), "[project snapshot]")
    text = re.sub(r"\s+", " ", text).strip()
    if "Traceback" in text and len(text) > 380:
        text = text[-380:]
    elif len(text) > 1_200:
        text = text[-1_200:]
    return redact_source_evidence(text)[:500]


def _severity(value: object, metadata: dict[str, Any]) -> str:
    aegis = metadata.get("aegis") if isinstance(metadata.get("aegis"), dict) else {}
    configured = str(aegis.get("severity") or "").casefold()
    if configured in {"critical", "high", "medium", "low", "info"}:
        return configured
    return {
        "error": "high", "warning": "medium", "info": "low",
        "critical": "critical", "high": "high", "medium": "medium", "low": "low",
    }.get(str(value or "").casefold(), "medium")


def _finding_id(project_id: str, analyzer: str, rule_id: str, path: str, line: object) -> str:
    identity = "\x00".join((project_id, analyzer, rule_id, path, str(line or "")))
    return "appf_" + hashlib.sha256(identity.encode()).hexdigest()[:20]


def _local_source_line(
    root: Path,
    relative: str,
    line: int | None,
) -> str:
    if not line or line < 1:
        return ""
    path = root if root.is_file() else root / relative
    try:
        resolved = path.resolve()
        if root.is_file():
            if resolved != root.resolve():
                return ""
        else:
            resolved.relative_to(root.resolve())
        size = resolved.stat(follow_symlinks=False).st_size
        if size > MAX_SOURCE_FILE_BYTES or resolved.is_symlink():
            return ""
        for number, value in enumerate(
            resolved.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if number == line:
                return value.replace("\x00", "").strip()
    except (OSError, ValueError):
        return ""
    return ""


def normalize_semgrep(
    payload: object,
    root: Path,
    working_directory: Path,
    project_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[dict[str, Any]]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Semgrep returned JSON without a results array")
    findings: list[dict[str, Any]] = []
    private: list[dict[str, str]] = []
    reachability: list[dict[str, Any]] = []
    for result in payload["results"][:MAX_DEEP_FINDINGS]:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        aegis = metadata.get("aegis") if isinstance(metadata.get("aegis"), dict) else {}
        raw_check_id = str(result.get("check_id") or "unknown").casefold()
        local_rule = re.search(r"(aegis\.[a-z0-9_.-]+)$", raw_check_id)
        normalized_check_id = local_rule.group(1) if local_rule else raw_check_id
        rule_id = "semgrep." + re.sub(
            r"[^a-z0-9_.-]+", "-", normalized_check_id
        )[:180]
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        line = int(start.get("line") or 0) or None
        relative = _safe_relative(result.get("path"), root, working_directory)
        exact = _local_source_line(root, relative, line)
        if not exact:
            candidate_lines = str(extra.get("lines") or "").replace("\x00", "").strip()
            exact = "" if candidate_lines.casefold() == "requires login" else candidate_lines
        finding_id = _finding_id(project_id, "semgrep", rule_id, relative, line)
        is_reachable = str(aegis.get("kind") or "") == "reachability"
        source = str(aegis.get("source") or "untrusted input")[:200]
        sink = str(aegis.get("sink") or "security-sensitive operation")[:200]
        message = str(extra.get("message") or "Semgrep matched a security rule.")[:1000]
        title = (
            f"Static input path to {sink}"
            if is_reachable else message.split(".", 1)[0][:200]
        )
        findings.append({
            "id": finding_id,
            "rule_id": rule_id,
            "severity": _severity(extra.get("severity"), metadata),
            "confidence": str(metadata.get("confidence") or "high").casefold()
            if str(metadata.get("confidence") or "").casefold() in {"high", "medium", "low"}
            else "high",
            "status": "reachable_from_input" if is_reachable else "static_evidence",
            "title": title,
            "description": (
                f"Semgrep statically traced {source} to {sink}. This is a source-level "
                "candidate path; it does not prove that the path executes in a deployed build or that exploitation succeeded."
                if is_reachable else
                f"Semgrep reported: {message} Static source evidence is not proof of runtime exploitability."
            ),
            "file_path": relative,
            "line": line,
            "evidence": redact_source_evidence(exact or f"{rule_id} matched at {relative}:{line or '?'}"),
            "remediation": (
                f"Treat {source} as untrusted, validate or constrain it before {sink}, use a safe API, and add a regression test for this path."
                if is_reachable else
                "Review the matched code, remove the unsafe construct or add the required validation, and add a regression test."
            ),
        })
        if exact:
            private.append({
                "finding_id": finding_id,
                "raw_evidence": exact[:MAX_PRIVATE_EVIDENCE_BYTES],
            })
        if is_reachable:
            reachability.append({
                "finding_id": finding_id,
                "rule_id": rule_id,
                "file_path": relative,
                "line": line,
                "source": source,
                "sink": sink,
                "state": "reachable_from_input",
                "validation": "static_taint_path",
                "component_hint": str(aegis.get("component_hint") or "")[:200],
                "evidence": redact_source_evidence(exact or message),
                "dynamically_validated": False,
            })
    return findings, private, reachability


def _secret_duplicate(
    existing_findings: list[dict[str, Any]], path: str, line: int | None
) -> bool:
    return any(
        str(item.get("rule_id") or "").startswith("secret.")
        and str(item.get("file_path") or "") == path
        and item.get("line") == line
        for item in existing_findings
    )


def normalize_gitleaks(
    payload: object,
    root: Path,
    working_directory: Path,
    project_id: str,
    existing_findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], int]:
    if not isinstance(payload, list):
        raise ValueError("Gitleaks returned JSON without a findings array")
    findings: list[dict[str, Any]] = []
    private: list[dict[str, str]] = []
    duplicates = 0
    for item in payload[:MAX_DEEP_FINDINGS]:
        if not isinstance(item, dict):
            continue
        relative = _safe_relative(item.get("File"), root, working_directory)
        try:
            line = int(item.get("StartLine") or 0) or None
        except (TypeError, ValueError):
            line = None
        if _secret_duplicate(existing_findings, relative, line):
            duplicates += 1
            continue
        upstream_rule = str(item.get("RuleID") or "secret")
        safe_rule = re.sub(r"[^a-z0-9_.-]+", "-", upstream_rule.casefold())[:160]
        rule_id = f"secret.gitleaks.{safe_rule}"
        finding_id = _finding_id(project_id, "gitleaks", rule_id, relative, line)
        description = str(item.get("Description") or "Credential-like value detected")[:500]
        exact = str(item.get("Match") or item.get("Secret") or "").replace("\x00", "").strip()
        findings.append({
            "id": finding_id,
            "rule_id": rule_id,
            "severity": "high",
            "confidence": "high",
            "status": "secret_detected",
            "title": f"Gitleaks: {description}",
            "description": (
                "Gitleaks detected a credential-shaped value in the private snapshot. "
                "The public report is redacted; static presence does not establish whether the value is active."
            ),
            "file_path": relative,
            "line": line,
            "evidence": f"{upstream_rule}: [REDACTED SECRET] at {relative}:{line or '?'}",
            "remediation": (
                "Verify and rotate the value if real, remove it from distributed artifacts and history, "
                "and retrieve the replacement from an approved secret store."
            ),
        })
        if exact:
            private.append({
                "finding_id": finding_id,
                "raw_evidence": exact[:MAX_PRIVATE_EVIDENCE_BYTES],
            })
    return findings, private, duplicates


def _iter_source_files(root: Path) -> Iterable[tuple[Path, str]]:
    if root.is_file():
        if root.suffix.casefold() in SOURCE_SUFFIXES:
            yield root, root.name
        return
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file() or path.suffix.casefold() not in SOURCE_SUFFIXES:
                continue
            yield path, path.relative_to(root).as_posix()


def _imports(line: str, suffix: str) -> list[str]:
    patterns: list[re.Pattern[str]] = []
    if suffix == ".py":
        patterns = [re.compile(r"^\s*(?:from|import)\s+([A-Za-z0-9_.-]+)")]
    elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
        patterns = [re.compile(r"(?:from\s+|require\s*\(|import\s*\()\s*['\"]([^'\"]+)")]
    elif suffix in {".java", ".kt", ".kts"}:
        patterns = [re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z0-9_.]+)")]
    elif suffix == ".go":
        patterns = [re.compile(r"['\"]([^'\"]+/[^'\"]+)['\"]")]
    elif suffix == ".rb":
        patterns = [re.compile(r"^\s*require(?:_relative)?\s*\(?\s*['\"]([^'\"]+)")]
    elif suffix == ".php":
        patterns = [re.compile(r"^\s*(?:use|require|include)(?:_once)?\s*\(?\s*['\"]?([^;'\")]+)")]
    elif suffix == ".cs":
        patterns = [re.compile(r"^\s*using\s+([A-Za-z0-9_.]+)")]
    values: list[str] = []
    for pattern in patterns:
        values.extend(match.group(1).strip() for match in pattern.finditer(line))
    return values


def _component_terms(component: dict[str, Any]) -> set[str]:
    name = str(component.get("name") or "").casefold().strip()
    ecosystem = str(component.get("ecosystem") or "").casefold()
    terms = {name} if name else set()
    if ":" in name:
        group, artifact = name.rsplit(":", 1)
        terms.update({group, artifact})
    if name.startswith("@") and "/" in name:
        terms.add(name.split("/", 1)[1])
    if ecosystem in {"pypi", "python"}:
        terms.update({item.replace("-", "_") for item in list(terms)})
    terms.update({item.replace("-", "_") for item in list(terms) if len(item) >= 3})
    terms.update(
        PACKAGE_IMPORT_ALIASES[item]
        for item in list(terms)
        if item in PACKAGE_IMPORT_ALIASES
    )
    return {item.strip("./") for item in terms if len(item.strip("./")) >= 3}


def _import_lookup_terms(imported: str) -> set[str]:
    """Build bounded module/package prefixes for indexed component matching."""
    value = imported.casefold().replace("\\", "/").strip("./")
    values = {value, value.replace("-", "_")}
    for separator in ("/", "."):
        pieces = value.split(separator)
        values.update(separator.join(pieces[:index]) for index in range(1, len(pieces) + 1))
    values.update(item.replace("-", "_") for item in list(values))
    return {item for item in values if len(item) >= 3}


def map_component_references(
    root: Path,
    supply_summary: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    components = (
        supply_summary.get("components")
        if isinstance(supply_summary, dict) and isinstance(supply_summary.get("components"), list)
        else []
    )
    indexed: dict[str, list[dict[str, Any]]] = {}
    for component in components[:10_000]:
        if not isinstance(component, dict) or not component.get("component_id"):
            continue
        for term in _component_terms(component):
            indexed.setdefault(term.casefold().replace("-", "_"), []).append(component)
    references: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    reference_counts: Counter[str] = Counter()
    scanned_files = 0
    scanned_bytes = 0
    skipped_large_files = 0
    limit_reached = False
    for path, relative in _iter_source_files(root):
        if scanned_files >= MAX_REFERENCE_FILES or scanned_bytes >= MAX_REFERENCE_BYTES:
            limit_reached = True
            break
        try:
            size = path.stat(follow_symlinks=False).st_size
        except OSError:
            continue
        if size > MAX_SOURCE_FILE_BYTES:
            skipped_large_files += 1
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned_files += 1
        scanned_bytes += size
        for line_number, line in enumerate(content.splitlines(), 1):
            imports = _imports(line, path.suffix.casefold())
            if not imports:
                continue
            matching_components: dict[str, dict[str, Any]] = {}
            for imported in imports:
                for term in _import_lookup_terms(imported):
                    for component in indexed.get(term, []):
                        matching_components[str(component["component_id"])] = component
            for component in matching_components.values():
                component_id = str(component["component_id"])
                key = (component_id, relative, line_number)
                if key in seen or reference_counts[component_id] >= MAX_REFERENCES_PER_COMPONENT:
                    continue
                seen.add(key)
                reference_counts[component_id] += 1
                references.append({
                    "component_id": component_id,
                    "component": str(component.get("name") or "unknown")[:300],
                    "version": str(component.get("version") or "")[:120],
                    "ecosystem": str(component.get("ecosystem") or "")[:80],
                    "file_path": relative,
                    "line": line_number,
                    "evidence": redact_source_evidence(line),
                    "state": "referenced_by_code",
                })
                if len(references) >= MAX_COMPONENT_REFERENCES:
                    limit_reached = True
                    return references, {
                        "files": scanned_files,
                        "bytes": scanned_bytes,
                        "skipped_large_files": skipped_large_files,
                        "limit_reached": int(limit_reached),
                    }
    return references, {
        "files": scanned_files,
        "bytes": scanned_bytes,
        "skipped_large_files": skipped_large_files,
        "limit_reached": int(limit_reached),
    }


def _component_hint_matches(component: dict[str, Any], hint: str) -> bool:
    if not hint:
        return False
    value = " ".join((
        str(component.get("name") or ""),
        str(component.get("purl") or ""),
    )).casefold().replace("-", "_")
    return hint.casefold().replace("-", "_") in value


def _log4shell_static_sink_paths(
    vulnerability: dict[str, Any],
    component: dict[str, Any],
    paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Identify only AEGIS's CVE-specific request-to-Log4j logging rule.

    The OSV record establishes the affected version. This path establishes a
    possible input-to-logging sink, not the deployed Log4j configuration,
    mitigation state, JNDI behavior, or a runtime exploit.
    """
    identifiers = {
        str(value).upper()
        for value in [vulnerability.get("id"), *(vulnerability.get("aliases") or [])]
        if value
    }
    name = str(component.get("name") or "").casefold()
    purl = str(component.get("purl") or "").casefold()
    if (
        LOG4SHELL_CVE_ID not in identifiers
        or str(component.get("ecosystem") or "").casefold() != "maven"
        or not (
            name in {"log4j-core", "org.apache.logging.log4j:log4j-core"}
            or purl.startswith("pkg:maven/org.apache.logging.log4j/log4j-core@")
        )
    ):
        return []
    return [
        path for path in paths
        if path.get("rule_id") == LOG4J_REQUEST_TO_LOG_RULE
        and path.get("validation") == "static_taint_path"
    ]


def correlate_vulnerabilities(
    supply_summary: dict[str, Any] | None,
    component_references: list[dict[str, Any]],
    reachability: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(supply_summary, dict):
        return []
    components = {
        str(item.get("component_id")): item
        for item in supply_summary.get("components") or []
        if isinstance(item, dict) and item.get("component_id")
    }
    refs_by_component: dict[str, list[dict[str, Any]]] = {}
    for reference in component_references:
        refs_by_component.setdefault(str(reference.get("component_id") or ""), []).append(reference)
    correlated: list[dict[str, Any]] = []
    for vulnerability in (supply_summary.get("vulnerabilities") or [])[:2_000]:
        if not isinstance(vulnerability, dict):
            continue
        component_id = str(vulnerability.get("component_id") or "")
        component = components.get(component_id, {})
        references = refs_by_component.get(component_id, [])[:5]
        matching_paths = [
            item for item in reachability
            if _component_hint_matches(component, str(item.get("component_hint") or ""))
        ]
        cve_sink_paths = _log4shell_static_sink_paths(
            vulnerability, component, matching_paths
        )
        sink_path_ids = {id(item) for item in cve_sink_paths}
        paths = [
            *cve_sink_paths,
            *(item for item in matching_paths if id(item) not in sink_path_ids),
        ][:5]
        state = (
            "cve_specific_sink_path_observed" if cve_sink_paths
            else "affected_component_reachable_from_input" if paths
            else "referenced_by_code" if references
            else "affected_dependency_only"
        )
        correlated.append({
            "vulnerability_id": str(vulnerability.get("id") or "")[:100],
            "component_id": component_id,
            "component": str(vulnerability.get("component") or component.get("name") or "unknown")[:300],
            "version": str(vulnerability.get("version") or component.get("version") or "")[:120],
            "state": state,
            "references": references,
            "reachability_finding_ids": [str(item.get("finding_id") or "") for item in paths],
            "cve_specific_sink_finding_ids": [str(item.get("finding_id") or "") for item in cve_sink_paths[:5]],
            "cve_specific_sink_path_count": len(cve_sink_paths),
            "validation": (
                "static_cve_specific_sink_candidate" if cve_sink_paths
                else "static_component_taint_path" if paths
                else "static_reference" if references else "version_match_only"
            ),
            "reachability_scope": (
                "cve_specific_sink_candidate" if cve_sink_paths
                else "component_level" if paths
                else "source_reference" if references else "version_only"
            ),
            "cve_specific_sink_path_observed": bool(cve_sink_paths),
            "preconditions_not_verified": (
                ["deployed Log4j Core and effective lookup configuration", "runtime reachability and mitigation state"]
                if cve_sink_paths else []
            ),
            "cve_specific_path_confirmed": False,
            "cve_preconditions_confirmed": False,
            "dynamically_validated": False,
            "exploitation_demonstrated": False,
        })
    return correlated


def _tool_summary(status: str, analyzer: str, **values: Any) -> dict[str, Any]:
    return {
        "status": status,
        "analyzer": analyzer,
        "artifact_executed": False,
        **values,
    }


def analyze_deep_source(
    root: Path,
    project_id: str,
    reports_directory: Path,
    existing_findings: list[dict[str, Any]],
    supply_summary: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    """Run static deep analyzers and dependency/source correlation."""
    root = root.resolve()
    reports_directory = reports_directory.resolve()
    reports_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    working_directory, target = _scan_target(root)
    all_findings: list[dict[str, Any]] = []
    all_private: list[dict[str, str]] = []
    reachability: list[dict[str, Any]] = []
    analyzers: dict[str, dict[str, Any]] = {}

    with tempfile.TemporaryDirectory(prefix="deep-source-", dir=reports_directory) as temporary_name:
        temporary = Path(temporary_name)
        try:
            temporary.chmod(0o700)
        except OSError:
            pass

        semgrep = find_semgrep()
        if not semgrep:
            analyzers["semgrep"] = _tool_summary(
                "unavailable", "Semgrep CE", finding_count=0, reachability_paths=0,
                install_guidance="Install Semgrep from Diagnostics, then run Deep source analysis again.",
            )
        else:
            rules_path = temporary / "aegis-semgrep.yml"
            rules_path.write_text(SEMGREP_RULES, encoding="utf-8")
            rules_path.chmod(0o600)
            run: ToolRun | None = None
            try:
                run = _run_bounded([
                    semgrep, "scan", "--config", str(rules_path), "--json", "--quiet",
                    "--metrics=off", "--disable-version-check", target,
                ], working_directory, 180, environment_overrides={
                    "SEMGREP_LOG_FILE": str(temporary / "semgrep.log"),
                    "SEMGREP_SETTINGS_FILE": str(temporary / "semgrep-settings.yml"),
                    "SEMGREP_VERSION_CACHE_PATH": str(temporary / "semgrep-version-cache"),
                })
                payload = json.loads(run.stdout.decode("utf-8"))
                semgrep_findings, semgrep_private, semgrep_paths = normalize_semgrep(
                    payload, root, working_directory, project_id
                )
                all_findings.extend(semgrep_findings)
                all_private.extend(semgrep_private)
                reachability.extend(semgrep_paths)
                errors = payload.get("errors") if isinstance(payload, dict) else []
                status = "partial" if errors or run.returncode not in {0, 1} else "complete"
                analyzers["semgrep"] = _tool_summary(
                    status, "Semgrep CE", analyzer_path=Path(semgrep).name,
                    duration_seconds=run.duration_seconds,
                    finding_count=len(semgrep_findings),
                    reachability_paths=len(semgrep_paths),
                    engine_errors=len(errors) if isinstance(errors, list) else 0,
                    rule_source="AEGIS-owned local taint rules",
                    network_rules_downloaded=False,
                )
                if status == "partial":
                    analyzers["semgrep"]["error"] = (
                        _safe_error(json.dumps((errors or [])[:3]), root)
                        if errors else _safe_error(run.stderr, root)
                    ) or "Semgrep completed with parser or rule errors."
            except Exception as exc:
                analyzer_error = _safe_error(run.stderr, root) if run else ""
                analyzers["semgrep"] = _tool_summary(
                    "error", "Semgrep CE", finding_count=0, reachability_paths=0,
                    error=analyzer_error or _safe_error(str(exc), root),
                    install_guidance="Review Diagnostics and retry Deep source analysis.",
                )

        gitleaks = find_gitleaks()
        if not gitleaks:
            analyzers["gitleaks"] = _tool_summary(
                "unavailable", "Gitleaks", finding_count=0, deduplicated_count=0,
                install_guidance="Install Gitleaks from Diagnostics, then run Deep source analysis again.",
            )
        else:
            config_path = temporary / "gitleaks.toml"
            report_path = temporary / "gitleaks.json"
            config_path.write_text(GITLEAKS_CONFIG, encoding="utf-8")
            config_path.chmod(0o600)
            run = None
            try:
                run = _run_bounded([
                    gitleaks, "dir", target, "--config", str(config_path),
                    "--report-format", "json", "--report-path", str(report_path),
                    "--exit-code", "0", "--no-banner", "--no-color",
                    "--log-level", "error", "--max-target-megabytes", "1",
                ], working_directory, 120, (report_path,))
                raw = report_path.read_bytes() if report_path.is_file() else b"[]"
                if len(raw) > MAX_TOOL_OUTPUT_BYTES:
                    raise RuntimeError("Gitleaks report exceeded the 32 MiB limit")
                payload = json.loads(raw.decode("utf-8"))
                gitleaks_findings, gitleaks_private, duplicates = normalize_gitleaks(
                    payload, root, working_directory, project_id,
                    [*existing_findings, *all_findings],
                )
                all_findings.extend(gitleaks_findings)
                all_private.extend(gitleaks_private)
                analyzers["gitleaks"] = _tool_summary(
                    "complete" if run.returncode == 0 else "partial",
                    "Gitleaks", analyzer_path=Path(gitleaks).name,
                    duration_seconds=run.duration_seconds,
                    finding_count=len(gitleaks_findings),
                    detections_total=len(payload), deduplicated_count=duplicates,
                    project_configuration_ignored=True,
                )
            except Exception as exc:
                analyzer_error = _safe_error(run.stderr, root) if run else ""
                analyzers["gitleaks"] = _tool_summary(
                    "error", "Gitleaks", finding_count=0, deduplicated_count=0,
                    error=analyzer_error or _safe_error(str(exc), root),
                    install_guidance="Review Diagnostics and retry Deep source analysis.",
                )

    component_references, reference_coverage = map_component_references(root, supply_summary)
    vulnerability_reachability = correlate_vulnerabilities(
        supply_summary, component_references, reachability
    )
    states = Counter(str(item.get("state") or "unknown") for item in vulnerability_reachability)
    summary = {
        "status": (
            "complete" if all(item.get("status") == "complete" for item in analyzers.values())
            else "partial" if any(item.get("status") in {"complete", "partial"} for item in analyzers.values())
            else "unavailable"
        ),
        "artifact_executed": False,
        "project_build_scripts_executed": False,
        "project_analyzer_configuration_used": False,
        "analyzers": analyzers,
        "finding_count": len(all_findings),
        "private_evidence_count": len(all_private),
        "reachability_path_count": len(reachability),
        "reachability": reachability,
        "component_reference_count": len(component_references),
        "component_references": component_references,
        "component_reference_coverage": reference_coverage,
        "vulnerability_reachability": vulnerability_reachability,
        "vulnerability_states": dict(sorted(states.items())),
        "dynamic_validation_performed": False,
        "limitations": [
            "Reachability is static taint and import evidence; it does not prove a path executes in a deployed build.",
            "A static CVE-specific sink candidate, when reported, does not confirm deployment, lookup configuration, mitigation state, runtime reachability, or exploitation.",
            "Component-to-import mapping is heuristic and may miss aliases, reflection, generated code, native linking, and dependency injection.",
            "Semgrep uses AEGIS-owned local rules only; no project-supplied analyzer configuration or remote ruleset is trusted.",
            "Gitleaks detects credential shapes; a detected value may be synthetic, revoked, or otherwise inactive.",
            "No imported code, build script, package manager, binary, container, or firmware image was executed.",
        ],
    }
    return summary, all_findings, all_private
