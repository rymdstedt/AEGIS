"""Typed engagement targets and deterministic authorization checks."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$")


@dataclass(frozen=True)
class TargetSpec:
    raw: str
    host: str
    kind: str
    port: int | None = None
    scheme: str | None = None
    path_query: str = ""
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    @property
    def network_target(self) -> str:
        if self.kind == "network" and self.network:
            return str(self.network)
        return self.host

    @property
    def base_url(self) -> str:
        scheme = self.scheme or ("https" if self.port == 443 else "http")
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        authority = f"{host}:{self.port}" if self.port and self.port != {"http": 80, "https": 443}[scheme] else host
        return urlunsplit((scheme, authority, self.path_query or "", "", ""))


def is_natural_language_target(raw: str) -> bool:
    value = (raw or "").strip()
    return bool(re.search(r"\s", value)) and not value.lower().startswith(("http://", "https://"))


def parse_target(raw: str) -> TargetSpec:
    value = (raw or "").strip()
    if not value or len(value) > 2048 or any(ord(ch) < 32 for ch in value):
        raise ValueError("A valid target is required")
    if is_natural_language_target(value):
        raise ValueError("Natural-language target must be resolved before validation")

    if value.lower().startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise ValueError("Invalid target URL")
        host = _normalize_host(parsed.hostname)
        port = parsed.port
        path_query = parsed.path or ""
        if parsed.query:
            path_query += "?" + parsed.query
        return TargetSpec(value, host, "url", port, parsed.scheme, path_query)

    try:
        network = ipaddress.ip_network(value, strict=False)
        if "/" in value:
            return TargetSpec(value, str(network.network_address), "network", network=network)
        address = ipaddress.ip_address(value)
        return TargetSpec(value, str(address), "ip")
    except ValueError:
        pass

    host_part, port = _split_host_port(value)
    host = _normalize_host(host_part)
    return TargetSpec(value, host, "domain", port=port)


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.startswith("["):
        parsed = urlsplit(f"//{value}")
        if not parsed.hostname:
            raise ValueError("Invalid IPv6 target")
        return parsed.hostname, parsed.port
    if value.count(":") == 1:
        host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            port = int(maybe_port)
            if not 1 <= port <= 65535:
                raise ValueError("Target port is out of range")
            return host, port
    return value, None


def _normalize_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname") from exc
    if not _HOST_RE.fullmatch(ascii_host):
        raise ValueError("Invalid hostname")
    return ascii_host


@dataclass
class ScopePolicy:
    primary: TargetSpec
    notes: str = ""
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    excluded_hosts: set[str] = field(default_factory=set)
    excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    allowed_ports: set[int] = field(default_factory=set)
    ports_restricted: bool = False
    allow_subdomains: bool = False

    @classmethod
    def from_notes(cls, target: TargetSpec, notes: str) -> ScopePolicy:
        policy = cls(primary=target, notes=notes or "")
        if target.network:
            policy.allowed_networks.append(target.network)
        else:
            policy.allowed_hosts.add(target.host)
        if target.port:
            policy.allowed_ports.add(target.port)

        low = policy.notes.lower()
        policy.allow_subdomains = "allow subdomains" in low or "include subdomains" in low

        # The scope field also acts as the port selector. A bare value such as
        # "443", a list, or a range means exactly those TCP ports. Positive
        # "port(s) ..." phrases behave the same way; negative phrases are not
        # accidentally converted into an allowlist.
        numeric_scope = None
        if re.fullmatch(r"\s*all\s+(?:tcp\s+)?ports\s*", low):
            policy.allowed_ports.update(range(1, 65536))
            policy.ports_restricted = True
        else:
            numeric_scope = re.fullmatch(r"\s*([0-9][0-9,\-\s]*)\s*", low)
        if not policy.ports_restricted and numeric_scope:
            parsed_ports = _parse_ports(numeric_scope.group(1))
            if not parsed_ports:
                raise ValueError("Port scope must contain values from 1 to 65535")
            policy.allowed_ports.update(parsed_ports)
            policy.ports_restricted = True
        elif not policy.ports_restricted:
            for port_match in re.finditer(r"\bports?\b\s*[:=]?\s*([0-9,\-\s]+)", low):
                prefix = low[max(0, port_match.start() - 16):port_match.start()]
                if re.search(r"\b(?:exclude|deny|except)\s*$", prefix):
                    continue
                parsed_ports = _parse_ports(port_match.group(1))
                if parsed_ports:
                    policy.allowed_ports.update(parsed_ports)
                    policy.ports_restricted = True

        for match in re.finditer(r"\b(?:exclude|deny|except)\s+([^\s,;]+)", policy.notes, re.IGNORECASE):
            policy._add_rule(match.group(1), excluded=True)
        for match in re.finditer(r"\b(?:include|allow)\s+(?!subdomains\b)([^\s,;]+)", policy.notes, re.IGNORECASE):
            policy._add_rule(match.group(1), excluded=False)
        return policy

    def add_resolved_address(self, address: str) -> None:
        parsed = ipaddress.ip_address(address)
        self.allowed_hosts.add(str(parsed))

    def _add_rule(self, raw: str, excluded: bool) -> None:
        cleaned = raw.strip().strip(".()[]")
        try:
            network = ipaddress.ip_network(cleaned, strict=False)
            if "/" in cleaned:
                (self.excluded_networks if excluded else self.allowed_networks).append(network)
            else:
                (self.excluded_hosts if excluded else self.allowed_hosts).add(str(network.network_address))
            return
        except ValueError:
            pass
        try:
            host = parse_target(cleaned).host
        except ValueError:
            return
        (self.excluded_hosts if excluded else self.allowed_hosts).add(host)

    def authorize(self, raw_target: str, port: int | None = None) -> TargetSpec:
        candidate = parse_target(raw_target)
        effective_port = port or candidate.port
        if self._excluded(candidate):
            raise PermissionError(f"Target {candidate.raw} is explicitly excluded from scope")
        if not self._allowed(candidate):
            raise PermissionError(f"Target {candidate.raw} is outside the authorized engagement scope")
        if self.ports_restricted and effective_port and effective_port not in self.allowed_ports:
            raise PermissionError(f"Port {effective_port} is outside the authorized engagement scope")
        return candidate

    def _excluded(self, candidate: TargetSpec) -> bool:
        host = candidate.host
        if host in self.excluded_hosts:
            return True
        if candidate.network:
            return any(candidate.network.subnet_of(network) for network in self.excluded_networks if candidate.network.version == network.version)
        try:
            address = ipaddress.ip_address(host)
            return any(address in network for network in self.excluded_networks if address.version == network.version)
        except ValueError:
            return False

    def _allowed(self, candidate: TargetSpec) -> bool:
        host = candidate.host
        if host in self.allowed_hosts:
            return True
        if candidate.network:
            return any(candidate.network.subnet_of(network) for network in self.allowed_networks if candidate.network.version == network.version)
        try:
            address = ipaddress.ip_address(host)
            return any(address in network for network in self.allowed_networks if address.version == network.version)
        except ValueError:
            pass
        if self.allow_subdomains:
            return any(host.endswith("." + allowed) for allowed in self.allowed_hosts if not _looks_like_ip(allowed))
        return False


def _parse_ports(raw: str) -> set[int]:
    result: set[int] = set()
    for part in re.split(r"[\s,]+", raw.strip()):
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            if start_text.isdigit() and end_text.isdigit():
                start, end = int(start_text), int(end_text)
                if 1 <= start <= end <= 65535:
                    result.update(range(start, end + 1))
        elif part.isdigit() and 1 <= int(part) <= 65535:
            result.add(int(part))
    return result


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses
