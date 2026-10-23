# AEGIS VulnLab

AEGIS VulnLab is an intentionally vulnerable web application containing only synthetic data. It exists to test AEGIS discovery, evidence handling, post-scan questions, and exploitation approval gates.

Never modify it to bind directly to a LAN address. The direct runner hard-codes `127.0.0.1`; Docker Compose publishes the container only on host loopback and gives it an internal-only network.

## Start without Docker

From the AEGIS repository:

```bash
python3 lab/vulnerable_app.py
```

Open <http://127.0.0.1:18080>. Stop it with Ctrl-C; all database and transfer state is in memory and disappears on shutdown.

## Start with Docker

Start Docker Desktop, then run:

```bash
docker compose -f lab/compose.yaml up --build
```

Stop and remove the lab container with:

```bash
docker compose -f lab/compose.yaml down
```

## Scan it with AEGIS

For a general discovery scan, use:

- Target: `http://127.0.0.1:18080`
- Scope: `Only TCP port 18080 on 127.0.0.1. This is AEGIS VulnLab; active web testing is authorized.`
- Mode: supervised
- Phases: recon, web, exploit

The general base-URL scan now discovers the linked query endpoints and login
form automatically. To isolate only the SQL-injection approval-gate exercise,
you can instead use this target in a new scan:

```text
http://127.0.0.1:18080/api/products?id=1
```

AEGIS automatically runs its bounded SQL-injection and HTML-reflection investigation probes against query URLs discovered anywhere in the application. You can also repeat the SQL probe explicitly after the scan:

```text
run sqli_probe http://127.0.0.1:18080/api/products?id=1
```

AEGIS should record an evidence-backed SQL-injection finding without extracting data. When the scan reaches Exploit it waits for a decision instead of completing. Then:

1. Open the Investigation/Findings area.
2. Approve that finding for the mapped SQLMap tool.
3. Accept the separate immediate execution confirmation when AEGIS offers the mapped SQLMap action. You can also explicitly enter `run sqlmap_test http://127.0.0.1:18080/api/products?id=1` after approving the finding.

For the non-executable HTML-reflection exercise, start a new scan with `http://127.0.0.1:18080/search?q=hello`, or run this explicit post-scan command:

```text
run xss_check http://127.0.0.1:18080/search?q=hello
```

After AEGIS records **Unescaped HTML Reflection Detected**, approve that finding for `dalfox_scan` and accept the separate immediate execution confirmation. You can also explicitly enter `run dalfox_scan http://127.0.0.1:18080/search?q=hello` after approving it. Dalfox is an optional external tool installed from **Diagnostics & Tools**.

The same base-URL scan offers focused gated checks for the state-changing GET,
client-controlled role cookie, unauthenticated notes write, and documented
default login. Each action is independently confirmed and the final report
separates vulnerability validation, demonstrated authorization/state impact,
and any reusable credential or session artifact retained in memory.

## Deliberate vulnerabilities

- GET SQL injection in `/api/products?id=1` and `/?id=1`
- POST login SQL injection and default `admin:admin` credentials
- Raw HTML reflection in `/search?q=...`
- Arbitrary credentialed CORS origin reflection
- Broken access control and IDOR via `/api/user?id=...` and `/api/notes`
- Cross-tenant customer-record exposure via `/api/v1/customers?tenant=...`
- Unsigned `role=admin` authorization cookie
- Unauthenticated privilege manipulation in `/impersonate`
- State-changing GET endpoint without a CSRF token
- Open redirect
- Exposed synthetic `.env`, `.git/config`, and backup files
- Planted fictional-company secrets in `/.env.production`, `/.aws/credentials`,
  `/config/settings.json`, `/static/app.js.map`, and `/logs/application.log`
- Directory listing and synthetic database backup under `/backup/`
- Runtime credentials and internal hostnames exposed by `/debug/config`
- Session cookies without Secure, HttpOnly, or SameSite
- Missing browser defense-in-depth headers

There is deliberately no command execution, host-file read, host-file write, SSRF, denial-of-service endpoint, or connection to production data.

All company names, people, domains, credentials, tokens, customer records, and
financial values in the lab are fictional or explicitly nonfunctional. The
recognizable AWS values are AWS's published example credentials.

## Application Research reachability fixture

The repository also includes the inert
[`application_reachability_fixture`](application_reachability_fixture/README.md)
source tree for **Application Research → Deep source analysis**. Import that
directory; do not start it as a server. A correct result contains two static
input-to-sink paths: Flask request input to an OS-command sink and Java servlet
input to a Log4j call. The constant-command worker may be reported by quick
triage but must not be promoted to `reachable_from_input`. The Maven manifest
declares Log4j Core 2.14.1, allowing OSV dependency evidence to be correlated
with the Java source reference and taint path. This fixture proves analyzer
classification only; it contains no working exploit and AEGIS must continue to
report dynamic validation and exploitation as not performed.
