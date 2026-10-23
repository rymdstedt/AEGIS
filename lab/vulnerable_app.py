#!/usr/bin/env python3
"""AEGIS VulnLab: an intentionally vulnerable, loopback-only web target.

This application is deliberately insecure. It contains only synthetic data
and binds to 127.0.0.1 unless it is running in the hardened Docker Compose
service supplied next to this file.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

# Direct execution is always loopback-only. The all-interface bind exists only
# inside the locked-down container; Compose publishes it on host loopback.
_CONTAINER_MODE = (
    os.environ.get("AEGIS_LAB_CONTAINER") == "1" and Path("/.dockerenv").is_file()
)
LAB_HOST = (
    "0.0.0.0"  # noqa: S104
    if _CONTAINER_MODE
    else "127.0.0.1"
)
DEFAULT_PORT = 18080
MAX_REQUEST_BODY = 8192

_DATABASE = sqlite3.connect(":memory:", check_same_thread=False)
_DATABASE.row_factory = sqlite3.Row
_DATABASE_LOCK = threading.Lock()
_TRANSFER_LOG: list[dict[str, str]] = []
_TRANSFER_LOCK = threading.Lock()
_NOTES: dict[str, dict[str, str]] = {
    "1": {
        "id": "1",
        "owner": "admin",
        "subject": "Payroll reconciliation",
        "body": "Q3 admin seed file: payroll-raw-2026.csv",
    },
    "2": {
        "id": "2",
        "owner": "analyst",
        "subject": "Client shortlist",
        "body": "Blue Team is in training; red flags around DNS wildcard cert.",
    },
    "3": {
        "id": "3",
        "owner": "analyst",
        "subject": "Incident draft",
        "body": "<script>document.body.innerText='xss in stored note';</script>",
    },
}

# Synthetic "Northstar Dynamics" material planted for secret-discovery tests.
# None of these values authenticate to a real service or leave this process.
_COMPANY_FILES: dict[str, tuple[str, str]] = {
    "/.env.production": (
        "text/plain; charset=utf-8",
        """# NORTHSTAR DYNAMICS - SYNTHETIC AEGIS LAB DATA ONLY
APP_ENV=production
DATABASE_URL=postgres://northstar_app:PolarNight-LAB-2026@db.prod.northstar.invalid:5432/customer_portal
REDIS_URL=redis://:AuroraCache-LAB@cache.prod.northstar.invalid:6379/0
JWT_SIGNING_SECRET=AEGIS-LAB-JWT-DO-NOT-USE-7f81c2d9
INTERNAL_API_KEY=northstar_lab_live_51M3SyntheticOnly
ADMIN_USERNAME=portal-admin
ADMIN_PASSWORD=MidnightSun-LAB-2026!
BACKUP_BUCKET=s3://northstar-prod-backups-lab-only
""",
    ),
    "/.aws/credentials": (
        "text/plain; charset=utf-8",
        """# Synthetic AWS documentation credential; intentionally nonfunctional
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = eu-north-1
""",
    ),
    "/config/settings.json": (
        "application/json; charset=utf-8",
        json.dumps(
            {
                "company": "Northstar Dynamics",
                "environment": "production-lab",
                "adminApi": "http://admin-api.prod.northstar.invalid/v1",
                "supportToken": "ghp_AEGISLAB_SYNTHETIC_TOKEN_NOT_VALID",
                "featureFlags": {"debugConsole": True, "legacyAuth": True},
            },
            indent=2,
        ),
    ),
    "/static/app.js": (
        "application/javascript; charset=utf-8",
        """// Northstar customer portal bundle - synthetic lab artifact
window.__BUILD__ = {version: "3.14.7", env: "production"};
window.__API_BASE__ = "/api/v1";
// TODO(security): remove before release
window.__LEGACY_ADMIN_TOKEN__ = "Bearer AEGIS-LAB-ADMIN-8d91f4c0";
//# sourceMappingURL=app.js.map
""",
    ),
    "/static/app.js.map": (
        "application/json; charset=utf-8",
        json.dumps(
            {
                "version": 3,
                "file": "app.js",
                "sources": ["webpack:///src/config/production.js"],
                "sourcesContent": [
                    "export const serviceUser='svc-deploy';\n"
                    "export const servicePassword='DeployPipeline-LAB!';\n"
                    "export const internalHost='jenkins.prod.northstar.invalid';"
                ],
                "names": [],
                "mappings": "AAAA",
            },
            indent=2,
        ),
    ),
    "/logs/application.log": (
        "text/plain; charset=utf-8",
        """2026-09-12T08:14:22Z INFO northstar-portal build=3.14.7
2026-09-12T08:15:03Z WARN legacy login enabled for user=contractor
2026-09-12T08:15:03Z DEBUG temporary_password=Contractor-LAB-90days!
2026-09-12T09:01:44Z ERROR backup failed host=backup01.prod.northstar.invalid user=svc_backup password=ColdStorage-LAB!
2026-09-12T09:02:01Z INFO reset_link=https://portal.northstar.invalid/reset?token=AEGIS-LAB-RESET-e7219c
""",
    ),
    "/backup/portal-2026-09-12.sql.gz": (
        "application/gzip",
        "AEGIS-LAB synthetic backup placeholder\n"
        "INSERT INTO employees VALUES (7, 'CFO', 'cfo@northstar.invalid');\n"
        "-- encryption_key=AEGIS-LAB-BACKUP-KEY-44c9\n",
    ),
}

_CUSTOMER_RECORDS = [
    {"tenant": "acme-lab", "contact": "alice@acme.invalid", "contract_value": 240000, "renewal": "2027-01-15"},
    {"tenant": "globex-lab", "contact": "bob@globex.invalid", "contract_value": 510000, "renewal": "2026-11-30"},
    {"tenant": "internal", "contact": "cfo@northstar.invalid", "contract_value": 999999, "note": "Project Aurora acquisition - confidential lab data"},
]


def _reset_database() -> None:
    with _DATABASE_LOCK:
        _DATABASE.executescript(
            """
            DROP TABLE IF EXISTS products;
            DROP TABLE IF EXISTS users;
            CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
            INSERT INTO products VALUES
                (1, 'Packet Lantern', 19.95),
                (2, 'Cipher Mug', 12.50),
                (3, 'Red Team Notebook', 8.75);
            INSERT INTO users VALUES
                (1, 'admin', 'admin'),
                (2, 'analyst', 'lab-only');
            """
        )
        _DATABASE.commit()


_reset_database()


def _query_products(raw_id: str) -> tuple[list[dict], str]:
    """Deliberately vulnerable SQL query used only against the in-memory DB."""
    statement = f"SELECT id, name, price FROM products WHERE id = {raw_id}"  # noqa: S608
    with _DATABASE_LOCK:
        rows = _DATABASE.execute(statement).fetchall()
    return [dict(row) for row in rows], statement


def _query_user(raw_id: str) -> tuple[list[dict], str]:
    """Deliberately vulnerable user lookup used only against the in-memory DB."""
    statement = f"SELECT id, username, password FROM users WHERE id = {raw_id}"  # noqa: S608
    with _DATABASE_LOCK:
        rows = _DATABASE.execute(statement).fetchall()
    return [dict(row) for row in rows], statement


def _safe_log_text(value: str) -> str:
    return re.sub(r"[^\x20-\x7e]", "?", value)[:500]


class VulnLabHandler(BaseHTTPRequestHandler):
    server_version = "AEGIS-VulnLab/1.0"
    sys_version = ""

    def log_message(self, template: str, *args: object) -> None:
        try:
            rendered = template % args
        except (TypeError, ValueError):
            rendered = " ".join((template, *(str(item) for item in args)))
        print(f"[vulnlab] {self.client_address[0]} {_safe_log_text(rendered)}")

    def _send(
        self,
        status: int,
        body: str | bytes = b"",
        content_type: str = "text/html; charset=utf-8",
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-AEGIS-Lab", "intentionally-vulnerable")
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and data:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                # Port scanners routinely close after reading just enough of
                # a fingerprint.  That is expected traffic, not a lab crash.
                pass

    def _json(
        self,
        status: int,
        payload: object,
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self._send(
            status,
            json.dumps(payload, indent=2, sort_keys=True),
            "application/json; charset=utf-8",
            headers,
        )

    def _cors_headers(self) -> list[tuple[str, str]]:
        origin = self.headers.get("Origin")
        if not origin:
            return []
        # Deliberately vulnerable: arbitrary Origin reflection with credentials.
        return [
            ("Access-Control-Allow-Origin", origin),
            ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Origin"),
        ]

    def _parsed(self):
        parsed = urlsplit(self.path)
        return parsed, parse_qs(parsed.query, keep_blank_values=True)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        headers = self._cors_headers() + [
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type, Authorization"),
        ]
        self._send(HTTPStatus.NO_CONTENT, headers=headers)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed, query = self._parsed()
        path = parsed.path
        cors = self._cors_headers()

        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "intentionally vulnerable and ready"})
            return

        if path == "/":
            product_html = ""
            if "id" in query:
                try:
                    products, statement = _query_products(query["id"][0])
                    product_html = (
                        f"<h2>Product query</h2><pre>{statement}</pre>"
                        f"<pre>{json.dumps(products, indent=2)}</pre>"
                    )
                except sqlite3.Error as exc:
                    product_html = f"<h2>Database error</h2><pre>sqlite3.{type(exc).__name__}: {exc}</pre>"
            # Deliberately vulnerable non-executable probe sink. The custom
            # element used by AEGIS is reflected without HTML encoding.
            reflected_probe = query.get("aegis_probe", [""])[0]
            body = f"""<!doctype html>
<html><head><title>AEGIS Vulnerable Lab</title></head>
<body>
  <h1>AEGIS VulnLab</h1>
  <p><strong>Intentionally vulnerable. Synthetic data only. Loopback use only.</strong></p>
  {reflected_probe}
  {product_html}
    <ul>
    <li><a href="/api/products?id=1">SQL injection target</a></li>
    <li><a href="/search?q=hello">Reflected HTML/XSS target</a></li>
    <li><a href="/api/user?id=1">User lookup endpoint with SQL injection</a></li>
    <li><a href="/login">Default credentials and SQL-injectable login</a></li>
    <li><a href="/admin">Unsigned role-cookie authorization</a></li>
    <li><a href="/impersonate?role=admin&amp;user=admin">Unauthenticated role impersonation</a></li>
    <li><a href="/api/notes">Insecure notes API (IDOR + missing auth)</a></li>
    <li><a href="/api/notes?id=1">Insecure note object access</a></li>
    <li><a href="/api/v1/customers?tenant=acme-lab">Cross-tenant customer data</a></li>
    <li><a href="/debug/config">Exposed runtime configuration</a></li>
    <li><a href="/backup/">Browsable backup directory</a></li>
    <li><a href="/api/profile">Credentialed CORS target</a></li>
    <li><a href="/api/transfer?to=lab-user&amp;amount=10">CSRF/state-change target</a></li>
    <li><a href="/redirect?next=https://example.invalid">Open redirect target</a></li>
    <li><a href="/backup/config.bak">Exposed backup</a></li>
  </ul>
</body></html>"""
            self._send(
                HTTPStatus.OK,
                body,
                headers=cors + [("Set-Cookie", "lab_session=guest; Path=/")],
            )
            return

        if path == "/api/products":
            raw_id = query.get("id", ["1"])[0]
            try:
                products, statement = _query_products(raw_id)
                self._json(
                    HTTPStatus.OK,
                    {"query": statement, "count": len(products), "products": products},
                    cors,
                )
            except sqlite3.Error as exc:
                self._json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "error": f"sqlite3.{type(exc).__name__}: {exc}",
                        "parameter": raw_id,
                    },
                    cors,
                )
            return

        if path == "/api/user":
            raw_id = query.get("id", ["1"])[0]
            try:
                users, statement = _query_user(raw_id)
                self._json(
                    HTTPStatus.OK,
                    {"query": statement, "users": users},
                    cors,
                )
            except sqlite3.Error as exc:
                self._json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "error": f"sqlite3.{type(exc).__name__}: {exc}",
                        "parameter": raw_id,
                    },
                    cors,
                )
            return

        if path == "/api/notes":
            # Deliberately vulnerable: no auth and no object-owner checks.
            note_id = query.get("id", [None])[0]
            owner = query.get("owner", [None])[0]

            if note_id is not None:
                note = _NOTES.get(note_id)
                if note is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "note not found"}, cors)
                else:
                    self._json(HTTPStatus.OK, note, cors)
                return

            if owner is not None:
                visible = [note for note in _NOTES.values() if note["owner"] == owner]
                self._json(HTTPStatus.OK, visible, cors)
                return

            self._json(HTTPStatus.OK, list(_NOTES.values()), cors)
            return

        if path == "/api/v1/customers":
            # Deliberately vulnerable: trusts caller-controlled tenant selection.
            tenant = query.get("tenant", [None])[0]
            records = _CUSTOMER_RECORDS
            if tenant:
                records = [record for record in records if record["tenant"] == tenant]
            self._json(
                HTTPStatus.OK,
                {"authenticated": False, "tenant_filter": tenant, "records": records},
                cors,
            )
            return

        if path == "/debug/config":
            self._json(
                HTTPStatus.OK,
                {
                    "company": "Northstar Dynamics",
                    "debug": True,
                    "cwd": "/opt/northstar/portal",
                    "database_host": "db.prod.northstar.invalid",
                    "database_user": "northstar_app",
                    "database_password": "PolarNight-LAB-2026",
                    "admin_token": "AEGIS-LAB-ADMIN-8d91f4c0",
                    "interesting_paths": ["/.env.production", "/.aws/credentials", "/logs/application.log"],
                },
                cors,
            )
            return

        if path == "/backup/":
            self._send(
                HTTPStatus.OK,
                """<!doctype html><title>Index of /backup/</title>
<h1>Index of /backup/</h1><pre>
<a href="/backup/config.bak">config.bak</a>                 2026-09-12 08:00
<a href="/backup/portal-2026-09-12.sql.gz">portal-2026-09-12.sql.gz</a> 2026-09-12 09:00
</pre>""",
                headers=cors,
            )
            return

        if path in _COMPANY_FILES:
            content_type, planted_body = _COMPANY_FILES[path]
            self._send(HTTPStatus.OK, planted_body, content_type, cors)
            return

        if path == "/impersonate":
            role = query.get("role", ["admin"])[0]
            user = query.get("user", ["admin"])[0][:40]
            self._send(
                HTTPStatus.FOUND,
                headers=[
                    ("Location", "/admin"),
                    ("Set-Cookie", f"role={role}; Path=/"),
                    ("Set-Cookie", f"lab_session={user}; Path=/"),
                ],
            )
            return

        if path == "/search":
            # Deliberately vulnerable: raw user input is inserted into HTML.
            value = query.get("q", query.get("aegis_probe", [""]))[0]
            self._send(
                HTTPStatus.OK,
                f"<!doctype html><title>Search</title><h1>Results for {value}</h1>",
                headers=cors,
            )
            return

        if path == "/login":
            self._send(
                HTTPStatus.OK,
                """<!doctype html><title>Lab login</title>
<form method="post" action="/login">
  <input name="username" value="admin">
  <input name="password" type="password">
  <button>Sign in</button>
</form>""",
                headers=cors,
            )
            return

        if path == "/admin":
            cookie = self.headers.get("Cookie", "")
            if "role=admin" not in cookie:
                self._send(HTTPStatus.FORBIDDEN, "Admin role required", "text/plain; charset=utf-8", cors)
                return
            self._json(
                HTTPStatus.OK,
                {"flag": "AEGIS-LAB{unsigned-role-cookie}", "message": "Synthetic admin data"},
                cors,
            )
            return

        if path == "/api/profile":
            self._json(
                HTTPStatus.OK,
                {"user": "lab-user", "email": "lab-user@example.invalid", "token": "LAB-ONLY-TOKEN"},
                cors,
            )
            return

        if path == "/api/transfer":
            transfer = {
                "to": query.get("to", ["unknown"])[0][:80],
                "amount": query.get("amount", ["0"])[0][:20],
            }
            with _TRANSFER_LOCK:
                _TRANSFER_LOG.append(transfer)
                del _TRANSFER_LOG[:-100]
            self._json(
                HTTPStatus.OK,
                {"accepted": True, "transfer": transfer, "csrf_token_checked": False},
                cors,
            )
            return

        if path == "/redirect":
            destination = query.get("next", ["/"])[0].replace("\r", "").replace("\n", "")
            self._send(HTTPStatus.FOUND, headers=[("Location", destination)])
            return

        if path == "/robots.txt":
            self._send(
                HTTPStatus.OK,
                "User-agent: *\nDisallow: /admin\nDisallow: /backup/\nDisallow: /.env\nDisallow: /.env.production\nDisallow: /debug/\nDisallow: /logs/\nDisallow: /config/\n",
                "text/plain; charset=utf-8",
            )
            return

        if path == "/sitemap.xml":
            self._send(
                HTTPStatus.OK,
                """<?xml version="1.0"?><urlset>
<url><loc>http://127.0.0.1:18080/</loc></url>
<url><loc>http://127.0.0.1:18080/search?q=hello</loc></url>
<url><loc>http://127.0.0.1:18080/api/products?id=1</loc></url>
</urlset>""",
                "application/xml; charset=utf-8",
            )
            return

        if path == "/.env":
            self._send(
                HTTPStatus.OK,
                "AEGIS_LAB_ONLY=true\nDATABASE_URL=sqlite://memory\nADMIN_PASSWORD=admin\n",
                "text/plain; charset=utf-8",
            )
            return

        if path == "/.git/config":
            self._send(
                HTTPStatus.OK,
                "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.invalid/aegis-lab.git\n",
                "text/plain; charset=utf-8",
            )
            return

        if path == "/backup/config.bak":
            self._send(
                HTTPStatus.OK,
                "# synthetic lab backup\nadmin_user=admin\nadmin_password=admin\n",
                "text/plain; charset=utf-8",
            )
            return

        self._send(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8", cors)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        if parsed.path == "/api/notes":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length < 0 or length > MAX_REQUEST_BODY:
                self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body too large")
                return
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
            note_id = form.get("id", [None])[0]
            if note_id is None:
                self._send(HTTPStatus.BAD_REQUEST, "Missing note id", "text/plain; charset=utf-8")
                return
            note = _NOTES.get(note_id)
            if note is None:
                self._send(HTTPStatus.NOT_FOUND, "Unknown note", "text/plain; charset=utf-8")
                return
            note["subject"] = form.get("subject", [note["subject"]])[0]
            note["body"] = form.get("body", [note["body"]])[0]
            self._json(
                HTTPStatus.OK,
                {"updated": True, "id": note_id, "note": note},
            )
            return

        if parsed.path != "/login":
            self._send(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length < 0 or length > MAX_REQUEST_BODY:
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body too large")
            return
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        # Deliberately vulnerable: raw string construction permits login SQLi.
        statement = (
            "SELECT id, username FROM users WHERE username = "  # noqa: S608
            f"'{username}' AND password = '{password}'"
        )
        try:
            with _DATABASE_LOCK:
                row = _DATABASE.execute(statement).fetchone()
        except sqlite3.Error as exc:
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"sqlite3.{type(exc).__name__}: {exc}", "query": statement},
            )
            return
        if not row:
            self._send(HTTPStatus.UNAUTHORIZED, "Invalid credentials", "text/plain; charset=utf-8")
            return
        self._send(
            HTTPStatus.FOUND,
            headers=[
                ("Location", "/admin"),
                ("Set-Cookie", f"lab_session={row['username']}; Path=/"),
                ("Set-Cookie", "role=user; Path=/"),
            ],
        )


class VulnLabServer(ThreadingHTTPServer):
    """Quietly tolerate the early disconnects produced by port scanners."""

    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


def run(port: int = DEFAULT_PORT) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("Choose an unprivileged TCP port from 1024 to 65535")
    server = VulnLabServer((LAB_HOST, port), VulnLabHandler)
    print("=" * 72)
    print("AEGIS VulnLab — INTENTIONALLY VULNERABLE; SYNTHETIC DATA ONLY")
    print(f"Listening on http://{LAB_HOST}:{port}")
    if LAB_HOST == "127.0.0.1":
        print("Safety boundary: loopback only (not reachable from the LAN).")
    else:
        print("Container mode: rely on compose.yaml's 127.0.0.1-only port mapping.")
    print("Press Ctrl-C to stop and erase all in-memory lab state.")
    print("=" * 72)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the loopback-only AEGIS vulnerable lab")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    run(args.port)


if __name__ == "__main__":
    main()
