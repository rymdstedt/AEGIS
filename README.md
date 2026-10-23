# AEGIS — local-LLM penetration-testing assistant

AEGIS is a desktop application for authorized security assessments. It combines a React/Electron interface, a local FastAPI control service, deterministic scope and approval controls, and an OpenAI-compatible local LLM for planning and analysis.

The model advises; Python code remains authoritative. Targets are parsed into typed IP, CIDR, hostname, or URL values, scope is enforced before every tool run, and commands are launched without a shell. Supervised and Manual modes require approval of a real finding plus a separate confirmation for each exploit action. Autonomous mode is an explicit opt-in that automatically runs evidence-mapped actions while retaining scope enforcement and tool allowlists.

> Use AEGIS only on systems you own or have explicit written permission to test.

## Recommended local model

Use **Qwen3.5-9B** as the default AEGIS model in LM Studio. It is small enough to run responsively on typical Apple Silicon hardware, is trained for agentic/tool-oriented work, and supports a long context. AEGIS uses its OpenAI-compatible chat endpoint with JSON Schema output and includes a compatibility path for Qwen's prompt template.

Use **gpt-oss-20b with medium reasoning** as the strongest conservative alternative when your machine can run the larger model without memory pressure. OpenAI documents it specifically for local/specialized workloads and confirms support for agentic capabilities and structured outputs. Use **gpt-oss-120b** only on server-class hardware.

- [Qwen3.5-9B model card](https://huggingface.co/Qwen/Qwen3.5-9B)
- [OpenAI gpt-oss-20b documentation](https://developers.openai.com/api/docs/models/gpt-oss-20b)
- [OpenAI gpt-oss-120b documentation](https://developers.openai.com/api/docs/models/gpt-oss-120b)

AEGIS accepts only a loopback model-provider URL, such as `http://127.0.0.1:1234` for LM Studio or `http://127.0.0.1:11434` for an OpenAI-compatible Ollama server. This is intentional: scan data cannot be sent to an arbitrary remote model endpoint through the app.

AI mode is optional. **Preset Tools Only** runs a smaller deterministic playbook without an LLM.

## Security properties

- The desktop backend binds to `127.0.0.1` on a random free port.
- Every launch receives a new cryptographically random bearer token and instance ID.
- REST and WebSocket control messages require that token; the WebSocket credential is carried in a subprotocol header, not a URL.
- Browser origins, navigation, popups, permissions, CSP, and external links are restricted.
- Provider URLs are limited to localhost/loopback addresses.
- Tool arguments are fixed argv arrays passed to shell-free child processes.
- Tool processes run in their own process group and are terminated on timeout, cancellation, or shutdown.
- Wordlists are restricted to approved wordlist directories; arbitrary local files cannot be supplied by the LLM.
- Single-host engagements cannot silently expand into subnet scans. Discovered names and addresses are evidence only unless the operator explicitly included them.
- Excluded hosts/networks and restricted ports are checked deterministically.
- LLM findings must quote exact evidence from the most recent successful tool output.
- Tool output is treated as untrusted prompt content, and retained output is bounded and credential-redacted.
- Exploit authorization is bound to the finding, target, and exact mapped tool. Supervised and Manual modes require immediate confirmation; explicitly selected Autonomous mode queues and runs mapped actions without UI confirmation.
- Credentials may be retained in memory for an approved follow-up but are redacted from events, commands, logs, and reports.
- Application Research imports use Electron's native picker and a second main-process-only credential. The renderer never receives the operator's original path.
- Imported files are copied into private AEGIS storage, directory imports do not follow symbolic links, and ZIP/TAR-family extraction enforces path, link, special-file, duplicate-name, entry-count, size, and compression-ratio limits.
- The initial application analyzer is read-only: it does not launch artifacts, load libraries, or run package lifecycle scripts. Public evidence is always redacted; bounded exact evidence is kept in a separate private table and is available only through explicit desktop confirmation.
- Dependency analysis invokes OSV-Scanner with transitive manifest resolution and Rust call analysis disabled. Imported build scripts are never run; matched lockfile versions remain affected-dependency evidence rather than exploit proof.
- CVE records can be enriched with CISA Known Exploited Vulnerabilities and FIRST EPSS data. Those feeds change prioritization only; they never bypass target correlation, scope, or exploitation gates.
- Dependencies, vendored source commits, binaries, and bundled wordlists are pinned; downloaded build assets are checksum-verified.
- macOS release builds require code-signing and notarization credentials.

No control plane can prove that an operator has legal authorization. AEGIS therefore relies on the operator to define a correct engagement target and scope.

## Requirements

For source development and packaging:

- Node.js 22.12 or newer
- Python 3.12
- A local OpenAI-compatible model server for AI mode
- The security tools needed by the selected phases

The packaged backend contains Python and the web UI. Gobuster, ffuf, subfinder, and selected wordlists are bundled by current release builds. Naabu, Nmap, httpx, and other tools such as Katana, Nuclei, testssl.sh, Dalfox, OWASP ZAP, NetExec, OWASP Amass, WAFW00F, curl, dig, Nikto, SQLMap, Hydra, SNMP utilities, OSV-Scanner, Semgrep CE, and Gitleaks are detected on the host. The **Diagnostics & Tools** tab is available from the start menu, before an engagement begins. It reports missing tools, installs allowlisted dependencies supported by the current OS, streams setup output, and shows an exact platform-specific manual command whenever automatic setup is unavailable or fails. **Install / setup all missing tools** skips manual-only tools instead of pretending they can be installed automatically.

The default single-host port workflow is **Naabu all-65,535 TCP discovery → targeted Nmap service/metadata scan**. If the full pass times out or fails, AEGIS retains independently observed open ports and retries the full TCP space in four fixed 16,384-port (or smaller) windows before service classification. A successful window is recorded as completed coverage; a failed window remains unfinished even if it emitted some open ports. In supervised mode the scan pauses after the first window pass so you can retry only unfinished windows or continue with a **PARTIAL** outcome. Autonomous mode makes up to two more bounded retry passes, then continues with observed ports and marks the final outcome **PARTIAL** if coverage is still incomplete. A brief UI reload/disconnect can reattach to the same in-memory scan; if no UI reconnects within 60 seconds, AEGIS stops the unattended scan. After a full backend restart, a small owner-only, redacted interrupted-scan notice can show the previous target authority and coverage counts. **It is not a resumable scan:** AEGIS does not persist port observations, findings, raw scope notes, secrets, or approvals there. Preparing a new scan clears the scope field and requires explicit target/scope confirmation; discovery runs again from the beginning. The Evidence tab and report show requested/completed ranges, observed ports, tool-run provenance, protocol verification, and finding stage without exposing raw secrets. A successful scanner exit records the requested port set as attempted; it cannot prove every packet reached the target.

Subnet engagements first discover live hosts and use a bounded top-1,000 pass per host to avoid multiplying a full scan across an entire CIDR; that result is labeled **BOUNDED**, not full-port coverage. The automatic Nmap pass is limited to discovered ports and bounded protocol metadata. If Naabu is unavailable or finds no ports, AEGIS falls back to a bounded Nmap top-port discovery scan, which does not silently complete an interrupted full-range pass. Broader vulnerability-script and UDP scans remain operator-requested tools.

Product identification and CVE correlation are also deterministic and do not depend on the selected LLM. A shared registry currently recognizes 60+ concrete signatures across hypervisors and control planes (including ESXi/vCenter, Hyper-V, Proxmox, Nutanix, XCP-ng/XenServer, OpenStack, oVirt/RHV, and libvirt), BMC/server controllers, network appliances, NAS/storage managers, container/cloud consoles, server-management consoles, and common network-facing server software. The registry separates the observed display identity from the canonical vendor/product aliases used by vulnerability databases. Exact-product CVE indexes are queried first and NVD keyword search is only a fallback; results remain candidates until the observed version/range and patch state support a match. Banner-only versions with common distribution backports are explicitly caveated rather than reported as confirmed vulnerabilities.

## Application Research

The start menu now includes **Application Research** alongside live network engagements and Diagnostics. In the packaged desktop app, select an application file or a source directory; AEGIS immediately creates a persistent private project and analyzes its copied snapshot.

The current slice supports source trees, individual source files, ZIP/TAR bundles, Cisco IOS/IOS XE `.bin`/`.pkg` images, APK, AAB, IPA, JAR, EXE/DLL/SYS/MSI, ELF, Mach-O, DMG, and PKG intake. ZIP- and TAR-family formats are safely unpacked for static inspection. Other native containers are identified and inventoried but are not mounted or executed. Directory snapshots exclude symbolic links, VCS metadata, common dependency/build caches, and enforce file-count and byte quotas; every exclusion is visible in the project. The default safety envelope is 8 GiB for a selected file or directory, 100,000 directory files, and 8 GiB expanded across 50,000 archive entries. Archive entry and compression-ratio guards remain enforced. Large selections stay one logical project and are copied/analyzed sequentially; users do not need to split them into unrelated projects.

The built-in `aegis-static-v1` pass is explicitly presented as **quick static triage**. It records its duration and coverage, including file/language/manifest/binary-format inventory and evidence for high-signal patterns including private-key material, hard-coded credentials, unsafe Electron renderer options, shell-backed process calls, unsafe Python deserialization, dynamic evaluation, disabled TLS verification, and deployed debug mode. Text candidates now stream in bounded 64 KiB segments instead of stopping at 1 MiB per file; long lines use a 1 KiB matching overlap and are flagged as partially covered because longer cross-boundary patterns may still be missed. Binary/unsupported formats remain inventory-only. File and byte progress is persisted per job; the operator can cancel a scan, and a cancelled or failed rerun retains the last completed result. Results are deliberately labeled **static evidence** with a confidence value. A fast or zero-match result is not described as a comprehensive assessment, confirmed vulnerability, or exploit.

Projects persist under `~/.aegis/application-research/` (or beneath `AEGIS_DATA_DIR` when configured). The original selected item is never modified and original paths are not returned by the API. A project can be removed from its project header after native confirmation; this deletes the AEGIS-owned copied snapshot, findings, jobs, and private evidence while leaving the imported original untouched. Routine project responses and redacted exports never contain exact secret values. A bounded exact match is retained in a separate SQLite evidence table so the operator can inspect it, export a plaintext private JSON ledger, or let the selected local model summarize it. Every one of those paths requires an explicit native desktop confirmation; the renderer cannot call the private backend route with its normal API credential. The data directory and database use owner-only filesystem permissions and secure SQLite deletion, but AEGIS does not separately encrypt this evidence at rest. Native selection, deletion, and private-evidence actions are intentionally unavailable in the browser-only Vite preview.

Application Research includes a project-scoped LM Studio chat. It answers from the persisted project record, treats artifact text as untrusted data, and cannot execute the artifact or mutate findings. Chat is redacted by default. Selecting **Include exact extracted values** requires a native confirmation before up to 500 private-evidence rows are included in that one loopback-only model request. Requested evidence categories are ranked before that retrieval limit, so a late flag is not displaced by hundreds of unrelated credentials; if a project has more rows, the model receives the total and a partial-results warning, not an implicit claim that every exact value was reviewed. The model receives up to 100 public findings with the authoritative total and explicit non-retrieved count. For questions naming a CVE or component, AEGIS prioritizes relevant supply-chain/deep-source records within its bounded context, but this is not exhaustive retrieval over an unlimited project. The Application Research panels provide paginated access to all stored public findings and confirmation-gated private evidence. Native redacted and private exports write bounded result pages to a temporary file and replace the chosen destination only after every page succeeds. Importer- and analyzer-enforced truncation is reported separately.

**Analyze dependencies + SBOM** runs the built-in static pass and OSV-Scanner against supported package metadata. AEGIS groups OSV aliases so a CVE/GHSA/PYSEC record is not counted several times, associates each issue with its exact ecosystem, package, locked version, and source file, and generates a downloadable CycloneDX 1.6 SBOM. CISA KEV and FIRST EPSS are fetched as optional risk context; an unavailable feed is shown as a warning and does not discard the primary dependency result. The scanner is available through Diagnostics (`brew install osv-scanner` on macOS or `winget install --id Google.OSVScanner --exact` on Windows). Dependency findings confirm an affected package version, not that its vulnerable code path is reachable.

**Deep source analysis** combines quick static triage and dependency/SBOM analysis with local Semgrep taint rules, private Gitleaks secret scanning, source-level component reference mapping, and vulnerability reachability correlation. It distinguishes five materially different claims: a package version is affected, the component is referenced by project source, attacker-controlled input statically reaches that component, the specific CVE sink and trigger preconditions are reachable, and runtime exploitation was demonstrated. The stage establishes the first three and can additionally identify a **static CVE-specific sink candidate** for `CVE-2021-44228` when an affected Maven `log4j-core` record is correlated with AEGIS's local servlet-request-to-Log4j-logging taint rule. The rule requires a direct Log4j `Logger` import, preventing same-named classes from another logging library from becoming this candidate; indirect wrappers may therefore remain undetected. This candidate does **not** establish effective JNDI lookup configuration, deployment or mitigation state, runtime reachability, or successful exploitation; those fields remain explicitly unconfirmed. Other component-level input paths are not relabeled as CVE-specific. Dynamic validation/exploitation remain not performed. Imported code, build scripts, package managers, binaries, containers, and firmware are never executed. Exact secret matches remain in the confirmation-gated private evidence store while routine findings, the evidence graph, and local-model context stay redacted. Semgrep and Gitleaks are available from Diagnostics on macOS and receive platform-specific manual guidance elsewhere.

Every completed Application Research pass now persists a redacted evidence graph relating the project, artifact, manifests, components, vulnerabilities, and findings. Live engagements derive the same graph shape from hosts, services, product fingerprints, CVE candidates, tool runs, findings, and secret-presence metadata. Raw credentials and response bodies are deliberately excluded. Reports and the local-model context receive the graph summary so later analyzers can build on stable relationships instead of reinterpreting disconnected text logs.

Application Research also accepts Cisco IOS/IOS XE-style `.bin`/`.pkg` images and TAR-family software bundles. It safely expands regular TAR members into the private snapshot, rejects traversal paths, links, devices, duplicates, decompression bombs, and quota overages, then inventories Cisco/version markers and common embedded firmware formats without mounting, booting, or executing the image. **Run deep firmware analysis** additionally scans the bounded uncompressed byte coverage for embedded private keys, Cisco type 0/type 7 credentials, default SNMP communities, Telnet/SSHv1 configuration, component version strings, and embedded ELF architecture, PIE, interpreter, and executable-stack metadata. Exact credential evidence stays behind the same private-evidence confirmation gate. Raw proprietary, encrypted, or compressed filesystem contents remain unextracted and firmware authenticity is explicitly reported as unverified offline.

For recognized Cisco firmware with a recovered version, the firmware panel can query Cisco's version-specific PSIRT openVuln endpoint. This is an explicit online action requiring an operator-supplied Cisco API access token. AEGIS restricts the request to `https://apix.cisco.com`, disables redirects and proxy inheritance, bounds and sanitizes the response, stores only advisory IDs/titles/severity/CVEs/fixed-release metadata, and never writes the access token to project storage. Advisory matches are correlation data rather than proof of exploitability on a particular device configuration.

This is the foundation, not the finished research engine. The implemented deep-source stage is intentionally a bounded rule set and heuristic dependency mapper, not whole-program proof: reflection, generated code, dependency injection, native linking, unusual aliases, and inter-service flows can still be missed. Signing and entitlement inspection, LIEF/capa binary analysis, isolated unblob/firmware extraction, Ghidra/MobSF adapters, broader language/framework rules, and separately gated isolated dynamic validation remain follow-on stages. The UI states those limitations instead of treating a zero-match result as a clean bill of health.

### Repeatable coverage checks

Run the synthetic, read-only known-answer benchmark in disposable private storage:

```bash
backend/.venv/bin/python scripts/application_coverage.py --json-output /tmp/aegis-application-coverage.json
```

It checks source-folder and ZIP equivalence, expected and prohibited findings, archive traversal/symlink/duplicate rejection, private-ledger membership versus public redaction, a source file above the former 1 MiB limit, more than 500 persisted findings, cancellation with prior-result retention, the per-rule-per-file finding cap, PE inventory-only behavior, Cisco-style firmware deep inspection, and offline synthetic CVE/static-path correlation with negative controls. It reports timings, inspected/skipped files, and planted indicator instances captured. The numbers are **case-weighted controls, not real-world recall or precision**. The CVE controls normalize synthetic OSV output and synthetic static-path records without invoking external scanners or proving runtime exploitation. A rule can save at most 64 findings per file; AEGIS confirms and reports at least one additional omitted match when that cap hides results. Quick findings no longer have a global 500-record cutoff; public results are served in 100-item UI pages and private evidence is paged behind desktop confirmation.

An optional live local-model check asks nine fixed questions about synthetic, nonfunctional fixtures. It requires a model already loaded in LM Studio; it does not load or unload models and writes only a redacted scorecard, not raw answers or exact fixture values:

```bash
backend/.venv/bin/python scripts/application_llm_coverage.py --model qwen/qwen3.5-9b --json-output /tmp/aegis-application-llm-coverage.json
```

The model check is heuristic and can fail because of wording despite a substantively correct answer; inspect such failures before changing the application. It tests exact requested flags, consent, brevity, execution/credential claims, capped and paged findings, long-line coverage, and static CVE versus runtime-exploitation claims, using only loopback and repository-generated synthetic data.

## Development setup

```bash
python3.12 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.txt

npm install
npm --prefix frontend install

./start.sh
```

`start.sh` creates a temporary development credential, starts the backend on loopback port 8000, and starts Vite on port 3000. Open `http://localhost:3000`.

For a backend-only development run:

```bash
cd backend
source .venv/bin/activate
python server.py --port 8000
```

The generated bearer token is printed to that terminal. Normal desktop launches inject the token automatically and never persist it.

## Intentionally vulnerable test lab

The repository includes a loopback-only [AEGIS VulnLab](lab/README.md) with synthetic data and contained SQL injection, unescaped HTML reflection, credentialed CORS, broken access control, unsafe state changes, default credentials, weak session handling, and exposed test files. Start it without dependencies using:

```bash
python3 lab/vulnerable_app.py
```

Then scan `http://127.0.0.1:18080` with scope restricted to TCP port 18080. AEGIS performs bounded same-origin discovery before deep scanners, so one base application entry point can cover multiple linked forms, APIs, query parameters, and sensitive resources without treating the first URL as the only application route. Read-only investigation detects exposed secret material while keeping raw values out of routine logs, reports, and persisted scan state. The raw responses are held only in the running backend's bounded evidence vault. Natural post-scan questions are answered by the selected local LLM using the completed scan record; when the operator explicitly asks about extracted information, a bounded question-relevant evidence ledger is included so the model can summarize actual values. `show all raw extracted credentials and evidence` remains an exact non-LLM export. Potentially state-changing checks remain gated.

When mapped actions are found, the scan pauses once in the Exploit phase. Approving a finding does not execute it: AEGIS presents a second immediate confirmation for each concrete action. Confirmed results replace their preliminary findings instead of creating a new candidate or re-entering the exploit loop. The lab exercises cover SQLMap and Dalfox as well as focused confirmation of default credentials, a client-controlled authorization cookie, unauthenticated API modification, and a state-changing GET without CSRF protection.

## Tests and audits

```bash
npm test
npm audit --audit-level=high
npm --prefix frontend audit --audit-level=high
backend/.venv/bin/python -m pip_audit -r backend/requirements.txt
```

The regression suite covers target parsing, scope containment, provider URL restrictions, shell-free command construction, wordlist isolation, credential redaction, process timeouts, evidence grounding, multi-entry application discovery, finding/tool approval binding, exploit-decision pauses, active-confirmation replacement, and loop prevention. Application tests additionally cover durable projects, desktop-only import authorization, directory/symlink handling, ZIP/TAR traversal and quota defenses, Cisco IOS/IOS XE recognition, firmware signature inventory, deep firmware credential/component/ELF inspection, bounded PSIRT response handling and token non-retention, public redaction, private evidence membership and export gates, complete PEM retention, local-LLM private-context authorization, and non-executing binary inventory. A loopback VulnLab acceptance run additionally exercises the complete scan lifecycle with real Nmap, HTTPx, SQLMap, and Dalfox executions when those host tools are installed.

To exercise the *packaged backend* full-range timeout path without scanning any device, build a dev app and run `backend/.venv/bin/python scripts/discovery_recovery_acceptance.py --backend dist-electron/<build>/mac-arm64/AEGIS.app/Contents/Resources/aegis-server/aegis-server`. The test uses a temporary loopback-only Naabu substitute that deliberately exceeds the actual 90-second full-scan deadline, then verifies retry-to-COMPLETE and continue-as-PARTIAL decisions through the authenticated WebSocket, Evidence endpoint, report, and exact scanner window calls. It also simulates an abrupt backend restart, checks that only a historical notice survives, and proves that a new scoped scan actually reruns discovery. The packaged UI is served; use `--scenario ui` to keep it open for a manual rendered-control check. The automated test itself does not click Electron controls or test macOS permission dialogs. The timeout scenarios take several minutes by design.

## Packaging

Build a locally signed macOS app directory while developing:

```bash
npm run dist:dev
```

For a one-off verification build while the normal development app is running,
set a distinct `coverage-*` output subdirectory. This preserves
`dist-electron/mac-arm64/AEGIS.app` and writes the new bundle under the named
directory instead:

```bash
AEGIS_DEV_OUTPUT_SUBDIR=coverage-check npm run dist:dev
```

The development build uses an installed Apple Development or Developer ID
identity when available, so macOS Local Network privacy can track AEGIS by its
real bundle identity. If no Apple identity exists it falls back to an ad-hoc
signature and prints a warning; Apple documents that Local Network permission
tracking can be unreliable for unsigned or ad-hoc builds.

The embedded Python backend is packaged in one-directory mode so its runtime
libraries stay inside the signed app bundle. This avoids temporary extraction
at startup and lets Hardened Runtime validate the complete backend consistently.

Build a signed and notarized Apple Silicon release:

```bash
export CSC_LINK=/path/to/developer-id-certificate.p12
export CSC_KEY_PASSWORD='...'
export APPLE_ID='...'
export APPLE_APP_SPECIFIC_PASSWORD='...'
export APPLE_TEAM_ID='...'
npm run dist
```

Apple API-key notarization is also supported through `APPLE_API_KEY`, `APPLE_API_KEY_ID`, and `APPLE_API_ISSUER`. The release preflight refuses to make an unsigned, unnotarized artifact. Signing secrets belong in the release environment, never in this repository.

Linux packages must be built on the matching Linux architecture because PyInstaller produces a native backend executable:

```bash
npm run build:ui
npm run build:server
npm run dist:linux
```

From macOS or another Docker host, build an Ubuntu 24.04 LTS x64 package set in an isolated Linux container:

```bash
npm run dist:linux:container
```

The container builder accepts `x64` or `arm64` (`bash scripts/build-linux-container.sh arm64`) and exports an AppImage, Debian package, tarball, and checksums under `dist-linux/`. A single format can be built or retried independently, for example `bash scripts/build-linux-container.sh x64 deb`; valid format arguments are `deb`, `AppImage`, and `tar.gz`.

The Linux `.deb` declares core runtime packages. AppImage users must install missing host tools themselves. The in-app Linux installer uses a fixed package allowlist and may require system privileges that are better supplied from a terminal.

Windows packages must also be built on their matching native architecture; the
embedded PyInstaller backend is not cross-compiled. On a Windows x64 machine:

```powershell
py -3.12 -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
npm.cmd ci --ignore-scripts
npm.cmd --prefix frontend ci --ignore-scripts
npm run dist:win:x64
```

Use the same commands on Windows 11 ARM64 and finish with
`npm run dist:win:arm64`. The build verifies that Python matches the requested
architecture, bundles native Windows scanner helpers, produces an assisted NSIS
installer plus a portable ZIP, and writes `SHA256SUMS` under `dist-windows/`.
Stale helpers are removed before every build so binaries from another OS or CPU
architecture cannot leak into the package.

The `Windows release` GitHub Actions workflow builds and smoke-tests x64 on
`windows-2025` and ARM64 on `windows-11-arm`. Configure `WINDOWS_CSC_LINK` and
`WINDOWS_CSC_KEY_PASSWORD` repository secrets to Authenticode-sign release
artifacts; unsigned local builds will trigger the normal Windows SmartScreen
warning. AEGIS can install its allowlisted WinGet tools from Diagnostics. Tools
without a safe automated Windows package show a concrete manual command instead.

## Agent modes

| Mode | Investigation | Exploitation |
|---|---|---|
| Autonomous | Runs authorized investigation tools automatically | Automatically queues and runs every available action mapped to a real finding; no approval dialogs |
| Supervised | Plans and runs investigation tools automatically | Requires finding approval and per-action confirmation |
| Manual | Confirms every tool | Also requires finding approval and per-action confirmation |

The phase order is Recon, Web, Network, OSINT, and finally Exploit. Keeping Exploit last ensures all investigation findings are available before any approved exploitation is considered. When one or more findings map to a gated action, the scan pauses in Exploit until the operator approves a finding or explicitly chooses **Finish without exploitation**. Approval then opens a separate per-action confirmation; approving a finding after an older completed scan reopens only the Exploit phase. Profiles may remove irrelevant phases—for example, OSINT for a private IP or heavy web checks for a confirmed embedded management interface.

## Project structure

```text
AEGIS/
├── backend/
│   ├── agent/
│   │   ├── core.py          agent loop, evidence checks, approvals, reporting
│   │   └── scope.py         typed targets and deterministic scope policy
│   ├── tools/
│   │   ├── definitions.py   tool metadata and fixed argv builders
│   │   └── executor.py      streaming process execution and termination
│   ├── application/
│   │   ├── intake.py        hostile-file copying and safe archive extraction
│   │   ├── analyzer.py      bounded read-only static evidence engine
│   │   ├── deep_source.py   local taint, secret, reference, and reachability analysis
│   │   ├── supply_chain.py  OSV normalization and CycloneDX generation
│   │   ├── llm.py           grounded project-scoped local-model analyst
│   │   ├── store.py         persistent project/job/finding database
│   │   └── service.py       application-research orchestration boundary
│   ├── tests/               backend regression tests
│   ├── main.py              authenticated REST/WebSocket application
│   ├── evidence_graph.py    stable redacted relationships across workflows
│   ├── security.py          launch token, origin, and provider URL checks
│   └── server.py            secure backend entry point
├── electron/main.js         desktop lifecycle, picker IPC, private backend launch
├── electron/preload.js      narrow sandboxed desktop bridge
├── frontend/src/App.jsx     live-engagement UI and workspace switcher
├── frontend/src/ApplicationResearch.jsx  local artifact projects and findings UI
├── scripts/build-server.sh  pinned macOS/Linux backend packaging
├── scripts/build-server-windows.ps1  native Windows backend packaging
├── scripts/build-windows.ps1         Windows installer/ZIP packaging
├── scripts/release-preflight.js
└── start.sh                 authenticated local development launcher
```

## User data and uninstalling

Dragging the macOS application to Trash removes the application, but not operator data. AEGIS-managed tools, wordlists, Application Research snapshots, and its private exact-evidence table may exist under `~/.aegis/`; saved reports remain wherever they were downloaded. Remove `~/.aegis` separately if you want to erase that data. Application Research projects can contain sensitive source, binaries, credentials, or key material even though routine findings and reports are redacted.

## Legal

Unauthorized access and testing can be illegal and disruptive. Obtain written authorization, state the exact systems and ports in scope, define exclusions and test windows, and use destructive checks only when the engagement explicitly permits them.
