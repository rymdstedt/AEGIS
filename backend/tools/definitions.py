import hashlib
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import httpx

_HOME = os.path.expanduser("~")
_WL_DIRS = [
    f"{_HOME}/.aegis/wordlists",
    "/usr/local/share/wordlists/dirb",
    "/usr/share/wordlists/dirb",
    "/opt/homebrew/share/wordlists/dirb",
    f"{_HOME}/wordlists",
]

_WORDLIST_URLS = {
    "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/Web-Content/common.txt",
    "directories.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "subdomains.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/DNS/subdomains-top1million-5000.txt",
}
_WORDLIST_SHA256 = {
    "common.txt": "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a",
    "directories.txt": "d7619fe257485f3be56316c888e7392b2a0b1d4fce3593d298e8ab604118eaa7",
    "subdomains.txt": "e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19",
}

def _get_bundled_wordlists_dir() -> str | None:
    """When running inside the packaged .dmg (PyInstaller onefile), wordlists are bundled
    next to the binary via --add-data during the build. This lets a completely clean Mac
    (no prior installs, no internet on first launch) still have working dirbusting etc.
    """
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            bundled = os.path.join(meipass, "wordlists")
            if os.path.isdir(bundled):
                return bundled
        # Fallback: next to the executable (some extraction layouts)
        exe_dir = os.path.dirname(sys.executable)
        bundled = os.path.join(exe_dir, "wordlists")
        if os.path.isdir(bundled):
            return bundled
    # In dev after `npm run build:server` the files are in backend/dist/wordlists
    here = os.path.dirname(__file__)
    for candidate in (
        os.path.join(here, "dist", "wordlists"),
        os.path.join(here, "..", "dist", "wordlists"),
    ):
        if os.path.isdir(candidate):
            return candidate
    return None

def _find_wordlist(name):
    # 1. User dir first (persisted, user can override)
    user_p = os.path.join(f"{_HOME}/.aegis/wordlists", name)
    if os.path.exists(user_p):
        return user_p

    # 2. Bundled inside the app (critical for "drag dmg to clean Mac and it works")
    bundled_dir = _get_bundled_wordlists_dir()
    if bundled_dir:
        bundled_p = os.path.join(bundled_dir, name)
        if os.path.exists(bundled_p):
            return bundled_p

    for d in _WL_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    # last resort
    return user_p

def ensure_wordlist(name: str = "common.txt") -> str:
    """Return path. If the primary wordlist is missing, attempt to copy from the bundle
    (preferred for packaged clean installs) or download from SecLists.
    This makes the desktop .dmg much more self-contained.
    """
    p = _find_wordlist(name)
    user_target = os.path.join(f"{_HOME}/.aegis/wordlists", name)

    if not os.path.exists(user_target):
        os.makedirs(os.path.dirname(user_target), exist_ok=True)

        # If _find_wordlist gave us a bundled copy, copy it to the persistent user location
        # so future runs + external tools see it in the usual place, and user can manage it.
        bundled_dir = _get_bundled_wordlists_dir()
        if bundled_dir:
            bundled_src = os.path.join(bundled_dir, name)
            if os.path.exists(bundled_src):
                try:
                    shutil.copy2(bundled_src, user_target)
                    return user_target
                except Exception:
                    pass  # fall through to use bundled path directly or network

        # If we still don't have it in user dir, try network (old behavior)
        if not os.path.exists(user_target):
            url = _WORDLIST_URLS.get(name)
            if url:
                try:
                    resp = httpx.get(url, timeout=45.0, follow_redirects=True)
                    expected = _WORDLIST_SHA256.get(name)
                    if (
                        resp.status_code == 200
                        and resp.content
                        and expected
                        and hashlib.sha256(resp.content).hexdigest() == expected
                    ):
                        with open(user_target, "wb") as f:
                            f.write(resp.content)
                except Exception:
                    pass

    # Return user location if it now exists, otherwise whatever _find gave us (bundled is fine)
    if os.path.exists(user_target):
        return user_target
    return p if os.path.exists(p) else user_target

def get_tool_binary(tool_name: str) -> str:
    """Best guess first argv[0] for the tool (for shutil.which)."""
    mapping = {
        "nmap_ping_sweep": "nmap", "nmap_quick": "nmap", "nmap_targeted": "nmap",
        "nmap_full": "nmap", "nmap_udp": "nmap", "nmap_vuln": "nmap",
        "naabu_quick": "naabu", "naabu_full": "naabu", "naabu_range": "naabu",
        "httpx_probe": "httpx", "katana_crawl": "katana",
        "nuclei_scan": "nuclei",
        "testssl_tls": "testssl.sh",
        "dalfox_scan": "dalfox",
        "zap_recon": "zap.sh",
        "netexec_smb": "nxc",
        "amass_passive": "amass",
        "waf_detect": "wafw00f",
        "gobuster_dir": "gobuster", "ffuf_fuzz": "ffuf",
        "sqlmap_test": "sqlmap", "sqlmap_forms": "sqlmap",
        "hydra_ssh": "hydra", "hydra_telnet": "hydra", "hydra_ftp": "hydra",
        "theharvester": "theHarvester",
        "smb_enum": "enum4linux",
        "ssh_audit": "ssh-audit",
        "snmp_enum": "snmpwalk",
        "dig_records": "dig",
        "dns_zone_transfer": "dig",
        "whois_lookup": "whois",
        "subfinder": "subfinder",
        "robots_sitemap": "curl",
        "curl_headers": "curl",
        "ssl_check": "nmap",
        "cors_check": "curl",
        "security_headers": "curl",
        "web_discover": "internal",
        "web_assess": "internal",
        "csrf_get_check": "internal",
        "cookie_auth_check": "internal",
        "unauthenticated_write_check": "internal",
        "default_web_login": "internal",
        "tech_detect": "curl",
        "xss_check": "curl",
        "nikto": "nikto",
        "slowloris_test": "nmap",
        "creds_ssh_exec": "sshpass",
        "osv_scanner": "osv-scanner",
        "semgrep": "semgrep",
        "gitleaks": "gitleaks",
    }
    base = tool_name.split("_")[0]
    return mapping.get(tool_name, base)


def _get_bundled_tools_dir() -> str | None:
    """Location of vendored portable tools inside the packaged app (see build-server.sh)."""
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            d = os.path.join(meipass, "tools")
            if os.path.isdir(d):
                return d
        exe_dir = os.path.dirname(sys.executable)
        d = os.path.join(exe_dir, "tools")
        if os.path.isdir(d):
            return d
    # dev builds
    here = os.path.dirname(__file__)
    for cand in (os.path.join(here, "dist", "tools"), os.path.join(here, "..", "dist", "tools")):
        if os.path.isdir(cand):
            return cand
    return None


def _get_managed_tools_dir() -> str:
    """User-writable location where in-app 'Install' (or first-run from vendored sources) places
    git-based tools like whatweb/dnsrecon/enum4linux. We look here before falling back to brew PATH.
    """
    return os.path.expanduser("~/.aegis/tools")


def _find_external_tool(bin_name: str) -> str | None:
    """Resolve CLI tools consistently in shells and GUI-launched macOS apps."""
    # ``httpx`` is also the name of an unrelated Python client. Prefer the
    # ProjectDiscovery binary installed by Homebrew when it is present.
    if bin_name == "httpx":
        for candidate in ("/opt/homebrew/bin/httpx", "/usr/local/bin/httpx"):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    if bin_name == "zap.sh":
        for candidate in (
            "/Applications/ZAP.app/Contents/Java/zap.sh",
            os.path.expanduser("~/Applications/ZAP.app/Contents/Java/zap.sh"),
        ):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    if found := shutil.which(bin_name):
        return found
    search_dirs = [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/opt/homebrew/opt/ruby/bin",
        "/opt/homebrew/opt/samba/bin",
        "/opt/homebrew/opt/samba/sbin",
        "/opt/homebrew/opt/net-snmp/bin",
        "/opt/homebrew/opt/net-snmp/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/local/opt/ruby/bin",
        "/usr/local/opt/samba/bin",
        "/usr/local/opt/samba/sbin",
        "/usr/local/opt/net-snmp/bin",
        "/usr/local/opt/net-snmp/sbin",
        f"{_HOME}/.local/bin",
        f"{_HOME}/.cargo/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        local_app_data = os.environ.get("LOCALAPPDATA", os.path.join(_HOME, "AppData", "Local"))
        search_dirs = [
            os.path.join(program_files, "Nmap"),
            os.path.join(program_files_x86, "Nmap"),
            os.path.join(program_files, "Git", "cmd"),
            r"C:\ProgramData\chocolatey\bin",
            os.path.join(_HOME, "scoop", "shims"),
            os.path.join(local_app_data, "Microsoft", "WindowsApps"),
            os.path.join(_HOME, ".lmstudio", "bin"),
            *search_dirs,
        ]
    for directory in search_dirs:
        variants = [bin_name]
        if os.name == "nt" and not os.path.splitext(bin_name)[1]:
            variants = [bin_name + suffix for suffix in (".exe", ".cmd", ".bat")] + variants
        for variant in variants:
            candidate = os.path.join(directory, variant)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def _find_managed_tool(bin_name: str) -> str | None:
    """Return full path to a vendored/manually 'installed' script tool if present in ~/.aegis/tools.
    Supports flat, subdir, and common entrypoint names for the non-brew tools.
    """
    base = _get_managed_tools_dir()
    if bin_name == "dnsrecon":
        wrapper = os.path.join(base, "dnsrecon", "aegis-dnsrecon")
        if os.path.isfile(wrapper) and os.access(wrapper, os.X_OK):
            return wrapper
    managed_wrappers = {
        "wafw00f": os.path.join(base, "wafw00f", "aegis-wafw00f"),
        "nxc": os.path.join(base, "netexec", "aegis-nxc"),
    }
    if wrapper := managed_wrappers.get(bin_name):
        if os.path.isfile(wrapper) and os.access(wrapper, os.X_OK):
            return wrapper
    candidates = [
        os.path.join(base, bin_name),
        os.path.join(base, bin_name, bin_name),
        os.path.join(base, bin_name, bin_name + ".py"),
        os.path.join(base, bin_name, bin_name + ".pl"),
    ]
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Special layouts after clone (only return if we are actually looking for that tool)
    if bin_name == "whatweb":
        ww = os.path.join(base, "whatweb", "whatweb")
        if os.path.isfile(ww) and os.access(ww, os.X_OK):
            return ww
    if bin_name == "dnsrecon":
        dr = os.path.join(base, "dnsrecon", "dnsrecon.py")
        if os.path.isfile(dr):
            return dr  # even if not yet +x, caller can handle; we +x on install
    if bin_name == "enum4linux":
        e4 = os.path.join(base, "enum4linux", "enum4linux.pl")
        if os.path.isfile(e4) and os.access(e4, os.X_OK):
            return e4
    return None


def _get_bundled_script_sources_dir() -> str | None:
    """Vendored sources for git-only tools (whatweb, dnsrecon, enum4linux) baked into the DMG
    at build time via build-server.sh. Lets a brand-new Mac have the *sources* immediately
    after dragging the .app from DMG, satisfying "installed when installing the program".
    """
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            d = os.path.join(meipass, "tools-sources")
            if os.path.isdir(d):
                return d
        exe_dir = os.path.dirname(sys.executable)
        d = os.path.join(exe_dir, "tools-sources")
        if os.path.isdir(d):
            return d
    # dev after npm run build:server
    here = os.path.dirname(__file__)
    for cand in (
        os.path.join(here, "dist", "tools-sources"),
        os.path.join(here, "..", "dist", "tools-sources"),
    ):
        if os.path.isdir(cand):
            return cand
    return None


def is_tool_available(tool_name: str) -> bool:
    import os
    import shutil

    if tool_name in {
        "web_discover", "web_assess", "tech_detect", "xss_check", "sqli_probe",
        "csrf_get_check", "cookie_auth_check", "unauthenticated_write_check",
        "default_web_login",
    }:
        # Implemented inside the frozen backend; no external interpreter required.
        return True

    bin_name = get_tool_binary(tool_name)

    # 0. Bundled / vendored Go tools inside the .dmg (highest priority for clean Mac installs)
    bundled_dir = _get_bundled_tools_dir()
    if bundled_dir:
        variants = [bin_name]
        if os.name == "nt" and not os.path.splitext(bin_name)[1]:
            variants.insert(0, bin_name + ".exe")
        for variant in variants:
            bundled_bin = os.path.join(bundled_dir, variant)
            if os.path.isfile(bundled_bin) and os.access(bundled_bin, os.X_OK):
                return True
        # Some tools ship with slightly different casing (theHarvester)
        for variant in (bin_name, bin_name.lower(), "theharvester"):
            p = os.path.join(bundled_dir, variant)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return True

    # 1. Managed tools in ~/.aegis/tools (populated at first launch from DMG-bundled sources,
    #    or by clicking "Install all missing" which does git+setup or brew). This is how
    #    whatweb/dnsrecon/enum4linux become available "when you install the program".
    managed = _find_managed_tool(bin_name)
    if managed:
        # Source presence alone is insufficient: probe the entrypoint so missing
        # Python/Ruby dependencies are surfaced in Diagnostics before a scan.
        if bin_name == "enum4linux":
            # enum4linux exits non-zero for help/no-target invocations. Source
            # presence plus its required Samba clients is the reliable check.
            required = ("nmblookup", "smbclient", "rpcclient")
            return all(_find_external_tool(command) for command in required)
        probe = [managed, "--version"] if bin_name == "whatweb" else [managed, "--help"]
        try:
            result = subprocess.run(  # noqa: S603 - managed is a validated, AEGIS-owned entrypoint
                probe,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    # 2. Standard PATH lookup (preferred — the desktop app now injects Homebrew paths)
    if _find_external_tool(bin_name):
        return True

    # 4. Known variant names
    if bin_name == "theHarvester" and _find_external_tool("theharvester"):
        return True
    if bin_name == "ssh-audit" and _find_external_tool("ssh-audit"):
        return True

    # 5. slowloris_test is satisfied exactly when nmap (which carries the http-slowloris-check script) is.
    if tool_name == "slowloris_test":
        return is_tool_available("nmap_quick") or bool(shutil.which("nmap"))

    return False


def ensure_script_tools() -> None:
    """Copy vendored script sources (whatweb/dnsrecon/enum4linux) from inside the DMG/bundle
    into the user managed dir ~/.aegis/tools/ on first launch. This is analogous to how
    wordlists are ensured. After this, the script files exist locally even on a completely
    clean Mac with no network and no prior brew/git.

    Runtime deps (gems for whatweb, pip packages for dnsrecon) are *not* auto-installed here
    (to keep app startup fast and avoid blocking/hanging on net). Instead, when the user
    clicks "Install all missing" (or we call install for them), the /api/install-tool will
    run the pip/gem steps with full visible output in the diagnostics panel.

    If the sources are missing from bundle (dev or old build), this is a no-op.
    """
    import os
    import shutil
    src_dir = _get_bundled_script_sources_dir()
    if not src_dir:
        return
    dst_base = _get_managed_tools_dir()
    try:
        os.makedirs(dst_base, exist_ok=True)
    except Exception:
        return
    for tool in ("whatweb", "dnsrecon", "enum4linux"):
        src = os.path.join(src_dir, tool)
        dst = os.path.join(dst_base, tool)
        if os.path.isdir(src) and not os.path.isdir(dst):
            try:
                shutil.copytree(src, dst)
                # Ensure entry points are executable
                for root, _dirs, files in os.walk(dst):
                    for f in files:
                        if f in ("whatweb", "dnsrecon.py", "enum4linux.pl") or f.endswith((".py", ".pl")):
                            try:
                                os.chmod(os.path.join(root, f), 0o755)
                            except Exception:
                                pass
            except Exception:
                # Non-fatal; install button can still git clone if net available later.
                pass
        elif tool == "whatweb" and os.path.isdir(src) and os.path.isdir(dst):
            # The managed directory is AEGIS-owned, but normally persists across
            # upgrades. Refresh only our compatibility shim so existing installs
            # receive the Ruby/OpenSSL fix without a manual reinstall.
            relative_path = os.path.join("lib", "target.rb")
            source_file = os.path.join(src, relative_path)
            target_file = os.path.join(dst, relative_path)
            if os.path.isfile(source_file):
                try:
                    os.makedirs(os.path.dirname(target_file), exist_ok=True)
                    shutil.copy2(source_file, target_file)
                except Exception:
                    pass


_COMMON_WL = _find_wordlist("common.txt")

TOOLS = {
    "semgrep": {
        "description": "Read-only local taint/data-flow analysis for Application Research deep source scans",
        "phase": "application",
        "planner": False,
        "command": "semgrep scan --config [AEGIS local rules] --json {target}",
        "timeout": 180,
    },
    "gitleaks": {
        "description": "Private credential-shape scanning for Application Research; exact matches stay confirmation-gated",
        "phase": "application",
        "planner": False,
        "command": "gitleaks dir {target} --report-format json",
        "timeout": 120,
    },
    "osv_scanner": {
        "description": "Read-only dependency and lockfile vulnerability analysis for Application Research",
        "phase": "application",
        "planner": False,
        "command": "osv-scanner scan source --recursive --no-resolve --allow-no-lockfiles --format json {target}",
        "timeout": 180,
    },
    "ping": {
        "description": "Simple ICMP ping to check if a host is alive",
        "phase": "recon",
        "planner": False,
        "command": "ping -c 4 -W 2 {target}",
        "timeout": 15,
    },
    "nmap_ping_sweep": {
        "description": "Network host discovery — find alive hosts on a subnet (no port scan)",
        "phase": "recon",
        "planner": False,
        "command": "nmap -n -sn -T4 {target}",
        "timeout": 180,
    },
    "nmap_quick": {
        "description": "Fast Nmap top-1000 discovery fallback when Naabu is unavailable or finds no ports",
        "phase": "recon",
        "planner": False,
        "command": "nmap -n -Pn -sT -T4 --top-ports 1000 --reason --max-retries 2 --host-timeout 90s {target}",
        "timeout": 100,
    },
    "naabu_quick": {
        "description": "Fast unprivileged TCP connect discovery of the top 1000 ports; follow with nmap_targeted",
        "phase": "recon",
        "planner": False,
        "command": "naabu -host {target} -top-ports 1000 -scan-type c -Pn -retries 2 -timeout 1500 -warm-up-time 0 -rate 1000 -silent -json -disable-update-check -no-stdin",
        "timeout": 20,
    },
    "naabu_full": {
        "description": "Full unprivileged TCP connect discovery of all 65535 ports on one host; follow with nmap_targeted",
        "phase": "recon",
        "planner": False,
        "diagnostics": False,
        "command": "naabu -host {target} -top-ports full -scan-type c -Pn -retries 2 -timeout 1200 -warm-up-time 0 -rate 3000 -silent -json -disable-update-check -no-stdin",
        "timeout": 90,
    },
    "naabu_range": {
        "description": "Retry one bounded TCP port window after incomplete full-host discovery",
        "phase": "recon",
        "planner": False,
        "diagnostics": False,
        "command": "naabu -host {target} -p {port_start}-{port_end} -scan-type c -Pn -retries 2 -timeout 1200 -warm-up-time 0 -rate 3000 -silent -json -disable-update-check -no-stdin",
        "timeout": 35,
    },
    "nmap_targeted": {
        "description": "Bounded medium-depth Nmap service classification on Naabu-discovered ports; protocol-specific tools perform deeper checks",
        "phase": "recon",
        "planner": False,
        "command": "nmap -n -Pn -sV --version-intensity 5 -T4 --open --max-retries 1 --host-timeout 35s -p {ports} {target}",
        "timeout": 42,
    },
    "nmap_full": {
        "description": "Full TCP port scan of all 65535 ports (slow)",
        "phase": "recon",
        "planner": False,
        "command": "nmap -n -Pn -sV -sC -p- -T4 --open {target}",
        "timeout": 1800,
    },
    "nmap_udp": {
        "description": "UDP scan of top 100 ports",
        "phase": "recon",
        "planner": False,
        "command": "nmap -n -Pn -sU --top-ports 100 -T4 --open {target}",
        "timeout": 600,
    },
    "nmap_vuln": {
        "description": "Operator-requested broad Nmap vulnerability scripts scan",
        "phase": "recon",
        "planner": False,
        "command": "nmap -n -Pn --script vuln -T4 --script-timeout 15s --host-timeout 180s {target}",
        "timeout": 190,
    },
    "whois_lookup": {
        "description": "WHOIS domain registration lookup",
        "phase": "recon",
        "command": "whois {target}",
        "timeout": 30,
    },
    "dig_records": {
        "description": "DNS record enumeration (A, MX, NS, TXT)",
        "phase": "recon",
        "command": "dig {target} ANY +noall +answer && dig {target} MX +short && dig {target} TXT +short && dig {target} NS +short",
        "timeout": 30,
    },
    "subfinder": {
        "description": "Passive subdomain enumeration",
        "phase": "recon",
        "command": "subfinder -d {target} -silent",
        "timeout": 120,
    },
    "dns_zone_transfer": {
        "description": "Attempt a DNS zone transfer against the authorized target DNS service",
        "phase": "recon",
        "command": "dig axfr {target} @{target}",
        "timeout": 30,
    },
    "whatweb": {
        "description": "Web technology fingerprinting",
        "phase": "web",
        "command": "whatweb -a 3 {target}",
        "timeout": 60,
    },
    "httpx_probe": {
        "description": "Structured HTTP/HTTPS probing and technology metadata without following redirects",
        "phase": "web",
        "command": "httpx -u {target} -silent -json -status-code -title -tech-detect -web-server -ip -no-color -omit-body -threads 10 -rate-limit 20 -timeout 4 -retries 0 -disable-update-check -no-stdin",
        "timeout": 30,
    },
    "web_discover": {
        "description": "Fetch one confirmed origin and extract bounded same-origin links and form actions",
        "phase": "web",
        "planner": False,
        "command": "internal bounded same-origin endpoint discovery {target}",
        "timeout": 15,
    },
    "web_assess": {
        "description": "Bounded same-origin assessment of discovered routes, data exposure, access-control indicators, forms, redirects, CORS, cookies, and sensitive resources",
        "phase": "web",
        "planner": False,
        "command": "internal bounded same-origin web assessment {target}",
        "timeout": 45,
    },
    "katana_crawl": {
        "description": "Bounded JavaScript-aware web crawl for endpoints on the authorized host",
        "phase": "web",
        "command": "katana -u {target} -silent -jsonl -depth 2 -js-crawl -field-scope fqdn -disable-redirects -crawl-duration 2m -max-domain-pages 250 -concurrency 5 -parallelism 5 -rate-limit 25 -omit-body -no-color -disable-update-check",
        "timeout": 150,
    },
    "nuclei_scan": {
        "description": "Bounded automatic signed-template vulnerability scan with interaction, fuzzing, active-code, intrusive, and DoS checks disabled",
        "phase": "web",
        "command": "nuclei -u {target} -automatic-scan -severity low,medium,high,critical -silent -jsonl -no-color -omit-raw -disable-update-check -disable-unsigned-templates -disable-redirects -no-interactsh -exclude-tags dos,fuzz,intrusive -exclude-type headless,code,javascript -rate-limit 25 -concurrency 10 -bulk-size 10 -timeout 5 -retries 0 -max-host-error 10 -max-time 90s -no-stdin",
        "timeout": 100,
    },
    "waf_detect": {
        "description": "Identify a web application firewall without following redirects",
        "phase": "web",
        "command": "wafw00f --noredirect {target}",
        "timeout": 45,
    },
    "zap_recon": {
        "description": "OWASP ZAPit one-request reconnaissance and passive alert summary",
        "phase": "web",
        "planner": False,
        "command": "zap.sh -cmd -silent -loglevel WARN -zapit {target}",
        "timeout": 120,
    },
    "nikto": {
        "description": "Web server vulnerability scanner",
        "phase": "web",
        "command": "nikto -h {target} -Tuning 123be -maxtime 60s -timeout 5 -nocheck -nointeractive -nolookup",
        "timeout": 75,
    },
    "gobuster_dir": {
        "description": "Directory/file brute force on web server",
        "phase": "web",
        "command": "gobuster dir -u {target} -w {wordlist} -t 30 -q --no-error -b 404,400,500,501,502,503 --wildcard",
        "timeout": 300,
    },
    "ffuf_fuzz": {
        "description": "Web fuzzing for hidden content",
        "phase": "web",
        "command": "ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403 -t 50 -s",
        "timeout": 300,
    },
    "curl_headers": {
        "description": "HTTP header analysis for security misconfigurations",
        "phase": "web",
        "command": "curl -sS --insecure --max-time 15 -D - -o /dev/null {target}",
        "timeout": 15,
    },
    "ssl_check": {
        "description": "SSL/TLS configuration analysis",
        "phase": "web",
        "command": "nmap -n -Pn --script ssl-enum-ciphers --script-timeout 15s --host-timeout 55s -p {port} {target}",
        "timeout": 60,
    },
    "testssl_tls": {
        "description": "Focused testssl.sh protocol, cipher-category, and certificate audit",
        "phase": "web",
        "planner": False,
        "command": "testssl.sh --protocols --categories --server-defaults --ids-friendly --nodns none {target}:{port}",
        "timeout": 120,
    },
    "cors_check": {
        "description": "CORS misconfiguration check",
        "phase": "web",
        "command": 'curl -sS --insecure --max-time 15 -D - -o /dev/null -H "Origin: https://aegis.invalid" {target}',
        "timeout": 15,
    },
    "security_headers": {
        "description": "Check for missing security headers",
        "phase": "web",
        "planner": False,
        "command": "curl -sS --insecure --max-time 15 -D - -o /dev/null {target} (internal alias; not separately scheduled)",
        "timeout": 15,
    },
    "robots_sitemap": {
        "description": "Fetch robots.txt and sitemap.xml",
        "phase": "web",
        "command": "curl -fsS --insecure --max-time 15 {target}/robots.txt; repeat for /sitemap.xml",
        "timeout": 12,
    },
    "tech_detect": {
        "description": "Detect CMS and technologies via common paths",
        "phase": "web",
        "command": "for path in wp-login.php wp-admin readme.html administrator joomla drupal; do code=$(curl -s -o /dev/null -w '%{http_code}' {target}/$path); if [ \"$code\" != \"404\" ] && [ \"$code\" != \"000\" ]; then echo \"FOUND ($code): {target}/$path\"; fi; done",
        "timeout": 30,
    },
    "sqlmap_test": {
        "description": "SQL injection testing on a URL",
        "phase": "exploit",
        "command": 'sqlmap -u "{target}" --batch --level 3 --risk 2 --random-agent --threads 5',
        "timeout": 600,
    },
    "sqlmap_forms": {
        "description": "SQL injection testing on forms",
        "phase": "exploit",
        "command": 'sqlmap -u "{target}" --forms --batch --level 3 --risk 2 --random-agent',
        "timeout": 600,
    },
    "dalfox_scan": {
        "description": "Active XSS confirmation on an approved reflected-HTML finding",
        "phase": "exploit",
        "planner": False,
        "command": "dalfox scan {target} --format jsonl --only-poc v --scan-timeout 60",
        "timeout": 75,
    },
    "hydra_ssh": {
        "description": "SSH brute force with common credentials",
        "phase": "exploit",
        "command": "hydra -L {wordlist} -P {wordlist} ssh://{target} -t 4 -f -e nsr",
        "timeout": 600,
    },
    "hydra_telnet": {
        "description": "Telnet brute force (use after discovering open telnet)",
        "phase": "exploit",
        "command": "hydra -L {wordlist} -P {wordlist} telnet://{target} -t 4 -f -e nsr",
        "timeout": 600,
    },
    "hydra_ftp": {
        "description": "FTP brute force",
        "phase": "exploit",
        "command": "hydra -L {wordlist} -P {wordlist} ftp://{target} -t 4 -f -e nsr",
        "timeout": 600,
    },
    "creds_ssh_exec": {
        "description": "Use previously looted creds to execute a command over SSH (post-exploitation)",
        "phase": "exploit",
        "command": 'sshpass -p "{password}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {username}@{target} "{command}"',
        "timeout": 120,
    },
    "xss_check": {
        "description": "Non-executable HTML-injection probe for one URL's query parameters",
        "phase": "web",
        "command": "internal reflected marker probe {target}",
        "timeout": 30,
    },
    "sqli_probe": {
        "description": "Bounded non-destructive SQL-injection indicator probe for one URL's existing GET parameters",
        "phase": "web",
        "command": "internal SQL error and boolean-differential probe {target}",
        "timeout": 45,
    },
    "csrf_get_check": {
        "description": "Approved one-request validation of a suspected state-changing GET without CSRF protection",
        "phase": "exploit",
        "planner": False,
        "command": "internal approved CSRF GET validation {target}",
        "timeout": 20,
    },
    "cookie_auth_check": {
        "description": "Approved authorization comparison using a privilege cookie issued without authentication",
        "phase": "exploit",
        "planner": False,
        "command": "internal approved cookie authorization validation {target}",
        "timeout": 25,
    },
    "unauthenticated_write_check": {
        "description": "Approved idempotent same-value write proving that an API accepts modification without authentication",
        "phase": "exploit",
        "planner": False,
        "command": "internal approved unauthenticated write validation {target}",
        "timeout": 25,
    },
    "default_web_login": {
        "description": "Approved single default-credential candidate check against a discovered web login form",
        "phase": "exploit",
        "planner": False,
        "command": "internal approved default web login validation {target}",
        "timeout": 25,
    },
    "slowloris_test": {
        "description": "Safely check for Slowloris exposure with Nmap's non-destructive detection script",
        "phase": "exploit",
        "command": "nmap -n -Pn --script http-slowloris-check -p 80 {target}",
        "timeout": 120,
    },
    "smb_enum": {
        "description": "SMB enumeration (shares, users, OS info)",
        "phase": "network",
        "command": "enum4linux -a {target}",
        "timeout": 120,
    },
    "netexec_smb": {
        "description": "Bounded NetExec SMB host, dialect, domain, and signing discovery without credentials",
        "phase": "network",
        "planner": False,
        "command": "nxc --timeout 5 --no-progress smb {target}",
        "timeout": 30,
    },
    "ssh_audit": {
        "description": "SSH configuration and algorithm audit",
        "phase": "network",
        "command": "ssh-audit {target}",
        "timeout": 30,
    },
    "snmp_enum": {
        "description": "SNMP enumeration with common community strings",
        "phase": "network",
        "command": "snmpwalk -v2c -c public {target}",
        "timeout": 60,
    },
    "theharvester": {
        "description": "Email and subdomain harvesting from public sources",
        "phase": "osint",
        "command": "theHarvester -d {target} -b google,bing,linkedin -l 200",
        "timeout": 120,
    },
    "dnsrecon": {
        "description": "DNS reconnaissance and enumeration",
        "phase": "osint",
        "command": "dnsrecon -d {target} -t std",
        "timeout": 120,
    },
    "amass_passive": {
        "description": "Passive OWASP Amass attack-surface and subdomain discovery",
        "phase": "osint",
        "command": "amass enum -passive -silent -nocolor -timeout 2 -d {target}",
        "timeout": 150,
    },
}


def get_tool_descriptions() -> str:
    return "\n".join(
        f"- {name} [{tool['phase']}]: {tool['description']}"
        for name, tool in TOOLS.items()
        if tool.get("planner", True)
    )


@dataclass(frozen=True)
class CommandSpec:
    commands: list[list[str]]
    timeout: int
    display: str
    secrets: tuple[str, ...] = field(default_factory=tuple)


def _tool_executable(tool_name: str, fallback: str) -> str:
    bundled_dir = _get_bundled_tools_dir()
    if bundled_dir:
        variants = [fallback]
        if os.name == "nt" and not os.path.splitext(fallback)[1]:
            variants.insert(0, fallback + ".exe")
        for variant in variants:
            candidate = os.path.join(bundled_dir, variant)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    managed = _find_managed_tool(fallback)
    return managed or _find_external_tool(fallback) or fallback


def _validated_wordlist(raw_path: str) -> str:
    path = os.path.realpath(os.path.expanduser(raw_path))
    roots = [os.path.realpath(os.path.expanduser(item)) for item in _WL_DIRS]
    bundled = _get_bundled_wordlists_dir()
    if bundled:
        roots.append(os.path.realpath(bundled))
    def is_within_root(root: str) -> bool:
        try:
            # Windows raises ValueError when the paths are on different drives.
            return os.path.commonpath([path, root]) == root
        except ValueError:
            return False

    if not any(is_within_root(root) for root in roots):
        raise ValueError("Wordlist must be inside an AEGIS or system wordlist directory")
    if not os.path.isfile(path):
        raise ValueError("Wordlist is missing; prepare bundled assets or install a wordlist first")
    if os.path.getsize(path) > 25 * 1024 * 1024:
        raise ValueError("Wordlist exceeds the 25 MB safety limit")
    return path


def _web_origin(target: str) -> str:
    """Return an HTTP(S) origin, never a resource path or query string."""
    try:
        parts = urlsplit(target)
    except ValueError:
        return target.rstrip("/")
    if parts.scheme.lower() in {"http", "https"} and parts.netloc:
        return urlunsplit((parts.scheme.lower(), parts.netloc, "", "", ""))
    return target.rstrip("/")


def _tls_endpoint(target: str, port: int) -> str:
    """Return the host:port form testssl.sh expects.

    Direct operator commands may supply either a bare host or an HTTP(S) URL.
    Resource paths and query strings must never leak into a TLS authority, and
    IPv6 literals need brackets before a port can be appended.
    """
    host = target
    try:
        parts = urlsplit(target)
    except ValueError:
        parts = None
    if parts and parts.scheme.lower() in {"http", "https"} and parts.hostname:
        host = parts.hostname
    else:
        host = target.strip().strip("[]")
    authority = f"[{host}]" if ":" in host else host
    return f"{authority}:{port}"


def build_command(tool_name: str, params: dict) -> CommandSpec:
    """Build shell-free argv for a known tool.

    Request and LLM values are always individual argv elements.  No generated
    string is ever evaluated by a shell.
    """
    tool = TOOLS.get(tool_name)
    if not tool:
        raise ValueError(f"Unknown tool: {tool_name}")
    allowed_params = {"target", "wordlist", "username", "password", "command"}
    if tool_name in {"nmap_targeted", "httpx_probe"}:
        allowed_params.add("ports")
    if tool_name == "naabu_range":
        allowed_params.update({"port_start", "port_end"})
    if tool_name in {"ssl_check", "testssl_tls", "ssh_audit"}:
        allowed_params.add("port")
    unknown = set(params) - allowed_params
    if unknown:
        raise ValueError(f"Unsupported parameters for {tool_name}: {', '.join(sorted(unknown))}")
    target = str(params.get("target", ""))
    if not target:
        raise ValueError(f"target is required for {tool_name}")
    origin_target = _web_origin(target)
    port_list: list[int] = []
    httpx_ports: list[int] = []
    ssl_port = 443
    ssh_port = 22
    port_start = port_end = 0
    if tool_name == "naabu_range":
        try:
            port_start = int(params.get("port_start"))
            port_end = int(params.get("port_end"))
        except (TypeError, ValueError) as exc:
            raise ValueError("naabu_range requires integer port_start and port_end") from exc
        if not 1 <= port_start <= port_end <= 65535 or port_end - port_start >= 16384:
            raise ValueError("naabu_range must cover at most 16384 valid TCP ports")
    if tool_name == "nmap_targeted":
        raw_ports = params.get("ports", [])
        if isinstance(raw_ports, str):
            raw_ports = [item.strip() for item in raw_ports.split(",") if item.strip()]
        if not isinstance(raw_ports, (list, tuple, set)):
            raise ValueError("nmap_targeted ports must be a list or comma-separated string")
        for raw_port in raw_ports:
            try:
                port = int(raw_port)
            except (TypeError, ValueError) as exc:
                raise ValueError("nmap_targeted ports must contain only integers") from exc
            if not 1 <= port <= 65535:
                raise ValueError("nmap_targeted port is outside 1-65535")
            port_list.append(port)
        port_list = sorted(set(port_list))
        if not port_list:
            raise ValueError("nmap_targeted requires at least one discovered port")
        if len(port_list) > 1000:
            raise ValueError("nmap_targeted accepts at most 1000 discovered ports")
    if tool_name == "httpx_probe" and params.get("ports") is not None:
        raw_ports = params.get("ports", [])
        if isinstance(raw_ports, str):
            raw_ports = [item.strip() for item in raw_ports.split(",") if item.strip()]
        if not isinstance(raw_ports, (list, tuple, set)):
            raise ValueError("httpx_probe ports must be a list or comma-separated string")
        for raw_port in raw_ports:
            try:
                port = int(raw_port)
            except (TypeError, ValueError) as exc:
                raise ValueError("httpx_probe ports must contain only integers") from exc
            if not 1 <= port <= 65535:
                raise ValueError("httpx_probe port is outside 1-65535")
            httpx_ports.append(port)
        httpx_ports = sorted(set(httpx_ports))
        if not httpx_ports:
            raise ValueError("httpx_probe ports cannot be empty when supplied")
        if len(httpx_ports) > 1000:
            raise ValueError("httpx_probe accepts at most 1000 ports")
    if tool_name in {"ssl_check", "testssl_tls"}:
        try:
            ssl_port = int(params.get("port", 443))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{tool_name} port must be an integer") from exc
        if not 1 <= ssl_port <= 65535:
            raise ValueError(f"{tool_name} port is outside 1-65535")
    if tool_name == "ssh_audit":
        try:
            ssh_port = int(params.get("port", 22))
        except (TypeError, ValueError) as exc:
            raise ValueError("ssh_audit port must be an integer") from exc
        if not 1 <= ssh_port <= 65535:
            raise ValueError("ssh_audit port is outside 1-65535")
    wordlist = str(params.get("wordlist") or _COMMON_WL)
    if tool_name in {"gobuster_dir", "ffuf_fuzz", "hydra_ssh", "hydra_telnet", "hydra_ftp"}:
        wordlist = _validated_wordlist(wordlist)

    def binary(fallback: str) -> str:
        return _tool_executable(tool_name, fallback)

    httpx_command = [binary("httpx"), "-u", target]
    if httpx_ports:
        httpx_command.extend(["-ports", ",".join(map(str, httpx_ports))])
    httpx_command.extend([
        "-silent", "-json", "-status-code", "-title", "-tech-detect",
        "-web-server", "-ip", "-no-color", "-omit-body", "-threads", "10",
        "-rate-limit", "20", "-timeout", "4", "-retries", "0",
        "-disable-update-check", "-no-stdin",
    ])

    ping_command = (
        [binary("ping"), "-n", "4", "-w", "2000", target]
        if sys.platform == "win32"
        else [binary("ping"), "-c", "4", "-W", "2", target]
    )
    builders: dict[str, list[list[str]]] = {
        "ping": [ping_command],
        "nmap_ping_sweep": [[binary("nmap"), "-n", "-sn", "-T4", target]],
        "nmap_quick": [[binary("nmap"), "-n", "-Pn", "-sT", "-T4", "--top-ports", "1000", "--reason", "--max-retries", "2", "--host-timeout", "90s", target]],
        "naabu_quick": [[binary("naabu"), "-host", target, "-top-ports", "1000", "-scan-type", "c", "-Pn", "-retries", "2", "-timeout", "1500", "-warm-up-time", "0", "-rate", "1000", "-silent", "-json", "-disable-update-check", "-no-stdin"]],
        "naabu_full": [[binary("naabu"), "-host", target, "-top-ports", "full", "-scan-type", "c", "-Pn", "-retries", "2", "-timeout", "1200", "-warm-up-time", "0", "-rate", "3000", "-silent", "-json", "-disable-update-check", "-no-stdin"]],
        "naabu_range": [[binary("naabu"), "-host", target, "-p", f"{port_start}-{port_end}", "-scan-type", "c", "-Pn", "-retries", "2", "-timeout", "1200", "-warm-up-time", "0", "-rate", "3000", "-silent", "-json", "-disable-update-check", "-no-stdin"]],
        "nmap_targeted": [[binary("nmap"), "-n", "-Pn", "-sV", "--version-intensity", "5", "-T4", "--open", "--max-retries", "1", "--host-timeout", "35s", "-p", ",".join(map(str, port_list)), target]],
        "nmap_full": [[binary("nmap"), "-n", "-Pn", "-sV", "-sC", "-p-", "-T4", "--open", target]],
        "nmap_udp": [[binary("nmap"), "-n", "-Pn", "-sU", "--top-ports", "100", "-T4", "--open", target]],
        "nmap_vuln": [[binary("nmap"), "-n", "-Pn", "--script", "vuln", "-T4", "--script-timeout", "15s", "--host-timeout", "180s", target]],
        "whois_lookup": [[binary("whois"), target]],
        "dig_records": [[binary("dig"), target, record, "+noall", "+answer"] for record in ("A", "AAAA", "MX", "TXT", "NS")],
        "subfinder": [[binary("subfinder"), "-d", target, "-silent"]],
        "dns_zone_transfer": [["__aegis_internal__", "zone_transfer", target]],
        "whatweb": [[binary("whatweb"), "-a", "3", "--max-redirects", "0", target]],
        "httpx_probe": [httpx_command],
        "web_discover": [["__aegis_internal__", "web_discover", origin_target]],
        "web_assess": [["__aegis_internal__", "web_assess", origin_target]],
        "katana_crawl": [[binary("katana"), "-u", target, "-silent", "-jsonl", "-depth", "2", "-js-crawl", "-field-scope", "fqdn", "-disable-redirects", "-crawl-duration", "2m", "-max-domain-pages", "250", "-concurrency", "5", "-parallelism", "5", "-rate-limit", "25", "-omit-body", "-no-color", "-disable-update-check"]],
        "nuclei_scan": [[binary("nuclei"), "-u", target, "-automatic-scan", "-severity", "low,medium,high,critical", "-silent", "-jsonl", "-no-color", "-omit-raw", "-disable-update-check", "-disable-unsigned-templates", "-disable-redirects", "-no-interactsh", "-exclude-tags", "dos,fuzz,intrusive", "-exclude-type", "headless,code,javascript", "-rate-limit", "25", "-concurrency", "10", "-bulk-size", "10", "-timeout", "5", "-retries", "0", "-max-host-error", "10", "-max-time", "90s", "-no-stdin"]],
        "waf_detect": [[binary("wafw00f"), "--noredirect", origin_target]],
        "zap_recon": [[binary("zap.sh"), "-cmd", "-silent", "-loglevel", "WARN", "-zapit", origin_target]],
        "nikto": [[
            binary("nikto"), "-h", origin_target, "-Tuning", "123be",
            "-maxtime", "60s", "-timeout", "5", "-nocheck",
            "-nointeractive", "-nolookup", "-ask", "no",
        ]],
        "gobuster_dir": [[binary("gobuster"), "dir", "-u", target, "-w", wordlist, "-t", "30", "-q", "--no-error", "-b", "404,400,500,501,502,503", "--wildcard"]],
        "ffuf_fuzz": [[binary("ffuf"), "-u", target.rstrip("/") + "/FUZZ", "-w", wordlist, "-mc", "200,301,302,403", "-t", "50", "-s"]],
        "curl_headers": [[binary("curl"), "-sS", "--insecure", "--max-time", "15", "-D", "-", "-o", os.devnull, target]],
        "ssl_check": [[binary("nmap"), "-n", "-Pn", "--script", "ssl-enum-ciphers", "--script-timeout", "15s", "--host-timeout", "55s", "-p", str(ssl_port), target]],
        "testssl_tls": [[
            binary("testssl.sh"), "--quiet", "--warnings", "off", "--color", "0",
            "--nodns", "none", "--ids-friendly", "--protocols", "--categories",
            "--server-defaults", _tls_endpoint(target, ssl_port),
        ]],
        "cors_check": [[binary("curl"), "-sS", "--insecure", "--max-time", "15", "-D", "-", "-o", os.devnull, "-H", "Origin: https://aegis.invalid", target]],
        "security_headers": [[binary("curl"), "-sS", "--insecure", "--max-time", "15", "-D", "-", "-o", os.devnull, target]],
        "robots_sitemap": [[binary("curl"), "-fsS", "--insecure", "--max-time", "5", origin_target + path] for path in ("/robots.txt", "/sitemap.xml")],
        "tech_detect": [["__aegis_internal__", "tech_detect", target]],
        "sqlmap_test": [[binary("sqlmap"), "-u", target, "--batch", "--ignore-redirects", "--flush-session", "--fresh-queries", "--level", "3", "--risk", "2", "--random-agent", "--threads", "5"]],
        "sqlmap_forms": [[binary("sqlmap"), "-u", target, "--forms", "--batch", "--ignore-redirects", "--ignore-code", "401", "--flush-session", "--fresh-queries", "--level", "3", "--risk", "2", "--random-agent"]],
        "dalfox_scan": [[
            binary("dalfox"), "scan", target, "--format", "jsonl", "--silence",
            "--no-color", "--only-poc", "v", "--timeout", "5", "--scan-timeout", "60",
            "--workers", "10", "--rate-limit", "25", "--max-payloads-per-param", "250",
            "--skip-mining", "--skip-waf-probe",
        ]],
        "hydra_ssh": [[binary("hydra"), "-L", wordlist, "-P", wordlist, f"ssh://{target}", "-t", "4", "-f", "-e", "nsr"]],
        "hydra_telnet": [[binary("hydra"), "-L", wordlist, "-P", wordlist, f"telnet://{target}", "-t", "4", "-f", "-e", "nsr"]],
        "hydra_ftp": [[binary("hydra"), "-L", wordlist, "-P", wordlist, f"ftp://{target}", "-t", "4", "-f", "-e", "nsr"]],
        "xss_check": [["__aegis_internal__", "xss_probe", target]],
        "sqli_probe": [["__aegis_internal__", "sqli_probe", target]],
        "csrf_get_check": [["__aegis_internal__", "csrf_get_check", target]],
        "cookie_auth_check": [["__aegis_internal__", "cookie_auth_check", target]],
        "unauthenticated_write_check": [["__aegis_internal__", "unauthenticated_write_check", target]],
        "default_web_login": [["__aegis_internal__", "default_web_login", target]],
        "slowloris_test": [[binary("nmap"), "-n", "-Pn", "--script", "http-slowloris-check", "-p", "80", target]],
        "smb_enum": [[binary("enum4linux"), "-a", target]],
        "netexec_smb": [[binary("nxc"), "--timeout", "5", "--no-progress", "smb", target]],
        "ssh_audit": [[
            binary("ssh-audit"), "--skip-rate-test", "--no-colors", "-jj",
            "--timeout", "5", "--port", str(ssh_port), target,
        ]],
        "snmp_enum": [[binary("snmpwalk"), "-v2c", "-c", "public", target]],
        "theharvester": [[binary("theHarvester"), "-d", target, "-b", "google,bing", "-l", "200"]],
        "dnsrecon": [[binary("dnsrecon"), "-d", target, "-t", "std"]],
        "amass_passive": [[binary("amass"), "enum", "-passive", "-silent", "-nocolor", "-timeout", "2", "-d", target]],
    }
    if tool_name == "creds_ssh_exec":
        username = str(params.get("username", ""))
        password = str(params.get("password", ""))
        remote_command = str(params.get("command", "id"))
        if not username or not password:
            raise ValueError("creds_ssh_exec requires approved username and password loot")
        if remote_command not in {"id", "whoami", "uname -a"}:
            raise ValueError("Remote command is not in the read-only post-exploitation allowlist")
        commands = [[binary("sshpass"), "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}", f"{username}@{target}", remote_command]]
        secrets_to_hide = (password,)
    else:
        commands = builders.get(tool_name)
        secrets_to_hide = ()
    if not commands:
        raise ValueError(f"No argv builder for {tool_name}")
    display = " && ".join(shlex.join((["aegis-internal"] + argv[1:]) if argv and argv[0] == "__aegis_internal__" else argv) for argv in commands)
    for secret in secrets_to_hide:
        display = display.replace(secret, "[REDACTED]")
    return CommandSpec(commands=commands, timeout=int(tool["timeout"]), display=display, secrets=secrets_to_hide)
