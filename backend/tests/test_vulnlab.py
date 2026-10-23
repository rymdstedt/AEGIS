import asyncio
import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from tools.definitions import build_command
from tools.executor import ToolExecutor

from lab.vulnerable_app import VulnLabHandler, VulnLabServer, _reset_database


class VulnLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _reset_database()
        cls.server = VulnLabServer(("127.0.0.1", 0), VulnLabHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path, *, headers=None, data=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            headers=headers or {},
            data=data,
        )
        try:
            # The URL is constructed above from a fixed loopback origin; tests
            # never accept an arbitrary scheme or remote host.
            return urllib.request.urlopen(request, timeout=2)  # noqa: S310
        except urllib.error.HTTPError as exc:
            return exc

    def test_sql_injection_changes_the_result_set(self):
        true_path = "/api/products?id=" + urllib.parse.quote("1 AND 1=1")
        false_path = "/api/products?id=" + urllib.parse.quote("1 AND 1=2")
        with self.request(true_path) as response:
            true_result = json.load(response)
        with self.request(false_path) as response:
            false_result = json.load(response)
        self.assertEqual(true_result["count"], 1)
        self.assertEqual(false_result["count"], 0)

    def test_union_injection_can_read_only_synthetic_users(self):
        payload = "-1 UNION SELECT id, username, password FROM users"
        with self.request("/api/products?id=" + urllib.parse.quote(payload)) as response:
            result = json.load(response)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["products"][0]["name"], "admin")
        self.assertEqual(result["products"][0]["price"], "admin")

    def test_html_input_is_reflected_without_encoding(self):
        payload = '<aegis-xss-probe data-token="7f31"></aegis-xss-probe>'
        with self.request("/search?q=" + urllib.parse.quote(payload)) as response:
            body = response.read().decode()
        self.assertIn(payload, body)

    def test_cors_reflects_untrusted_origin_with_credentials(self):
        with self.request(
            "/api/profile",
            headers={"Origin": "https://aegis.invalid"},
        ) as response:
            self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://aegis.invalid")
            self.assertEqual(response.headers["Access-Control-Allow-Credentials"], "true")

    def test_root_sets_an_intentionally_unprotected_cookie(self):
        with self.request("/") as response:
            cookie = response.headers["Set-Cookie"]
        self.assertIn("lab_session=guest", cookie)
        self.assertNotIn("HttpOnly", cookie)
        self.assertNotIn("Secure", cookie)
        self.assertNotIn("SameSite", cookie)

    def test_unsigned_role_cookie_controls_admin_access(self):
        with self.request("/admin") as response:
            self.assertEqual(response.status, 403)
        with self.request("/admin", headers={"Cookie": "role=admin"}) as response:
            result = json.load(response)
        self.assertEqual(result["flag"], "AEGIS-LAB{unsigned-role-cookie}")

    def test_aegis_internal_probes_detect_the_lab_without_executing_script(self):
        async def collect(tool_name, target):
            executor = ToolExecutor()
            spec = build_command(tool_name, {"target": target})
            output = "".join([line async for line in executor.run_stream(tool_name, spec)])
            return executor.last_result, output

        base = f"http://127.0.0.1:{self.port}"
        sql_result, sql_output = asyncio.run(
            collect("sqli_probe", f"{base}/api/products?id=1")
        )
        sql_negative_result, sql_negative_output = asyncio.run(
            collect("sqli_probe", f"{base}/search?q=hello")
        )
        xss_result, xss_output = asyncio.run(
            collect("xss_check", f"{base}/search?q=hello")
        )

        self.assertEqual(sql_result.exit_code, 0)
        self.assertIn('"type": "sqli_probe"', sql_output)
        self.assertIn("database-error-differential", sql_output)
        self.assertEqual(sql_negative_result.exit_code, 0)
        self.assertEqual(
            sql_negative_output,
            "No strong SQL injection indicator detected\n",
        )
        self.assertEqual(xss_result.exit_code, 0)
        self.assertIn('"type": "xss_probe"', xss_output)
        self.assertIn("unescaped-html-reflection", xss_output)

    def test_bounded_endpoint_discovery_finds_real_query_entries(self):
        async def collect():
            executor = ToolExecutor()
            spec = build_command(
                "web_discover",
                {"target": f"http://127.0.0.1:{self.port}"},
            )
            output = "".join([
                line async for line in executor.run_stream("web_discover", spec)
            ])
            return executor.last_result, output

        result, output = asyncio.run(collect())

        self.assertEqual(result.exit_code, 0)
        records = [json.loads(line) for line in output.splitlines()]
        urls = {record["url"] for record in records}
        self.assertIn(
            f"http://127.0.0.1:{self.port}/api/products?id=1",
            urls,
        )
        self.assertIn(
            f"http://127.0.0.1:{self.port}/search?q=hello",
            urls,
        )
        self.assertTrue(all(record["type"] == "web_endpoint" for record in records))

    def test_bounded_web_assessment_covers_the_intentional_attack_surface(self):
        async def collect():
            executor = ToolExecutor()
            spec = build_command(
                "web_assess",
                {"target": f"http://127.0.0.1:{self.port}"},
            )
            output = "".join([
                line async for line in executor.run_stream("web_assess", spec)
            ])
            return executor.last_result, output, executor.last_private_artifacts

        result, output, private_artifacts = asyncio.run(collect())
        records = [
            json.loads(line)
            for line in output.splitlines()
            if line.startswith("{")
        ]
        types = {record["type"] for record in records}
        urls = {record.get("url") for record in records}

        self.assertEqual(result.exit_code, 0)
        self.assertTrue({
            "credentialed_cors",
            "insecure_cookie",
            "form_sqli_probe",
            "privileged_cookie_candidate",
            "unauthenticated_object_data",
            "cross_tenant_data_exposure",
            "directory_listing",
            "open_redirect",
            "state_changing_get_candidate",
            "unauthenticated_write_candidate",
            "default_login_candidate",
            "exposed_sensitive_resource",
        }.issubset(types))
        self.assertIn(f"http://127.0.0.1:{self.port}/debug/config", urls)
        self.assertIn(f"http://127.0.0.1:{self.port}/.env.production", urls)
        self.assertIn(f"http://127.0.0.1:{self.port}/static/app.js.map", urls)
        self.assertIn(f"http://127.0.0.1:{self.port}/?id=1", urls)
        # Secret values are inspected in memory but never copied into logs.
        self.assertNotIn("PolarNight-LAB-2026", output)
        self.assertNotIn("MidnightSun-LAB-2026", output)
        self.assertNotIn("DeployPipeline-LAB", output)
        private_bodies = "\n".join(str(item.get("body") or "") for item in private_artifacts)
        self.assertIn("PolarNight-LAB-2026", private_bodies)
        self.assertIn("MidnightSun-LAB-2026", private_bodies)
        self.assertIn("DeployPipeline-LAB", private_bodies)

    def test_approved_internal_validations_confirm_impact_without_loops(self):
        async def collect(tool_name, target):
            executor = ToolExecutor()
            spec = build_command(tool_name, {"target": target})
            output = "".join([
                line async for line in executor.run_stream(tool_name, spec)
            ])
            return executor.last_result, output, executor.last_private_artifacts

        base = f"http://127.0.0.1:{self.port}"
        cases = {
            "csrf_get_check": (
                f"{base}/api/transfer?to=lab-user&amount=10",
                "csrf_get_confirmation",
            ),
            "cookie_auth_check": (
                f"{base}/impersonate?role=admin&user=admin",
                "cookie_auth_bypass_confirmation",
            ),
            "unauthenticated_write_check": (
                f"{base}/api/notes",
                "unauthenticated_write_confirmation",
            ),
            "default_web_login": (
                f"{base}/login",
                "default_web_login_confirmation",
            ),
        }
        for tool_name, (target, expected_type) in cases.items():
            with self.subTest(tool=tool_name):
                result, output, private_artifacts = asyncio.run(collect(tool_name, target))
                self.assertEqual(result.exit_code, 0)
                self.assertIn(f'"type": "{expected_type}"', output)
                self.assertTrue(private_artifacts)
                if tool_name == "cookie_auth_check":
                    private_bodies = "\n".join(
                        str(item.get("body") or "") for item in private_artifacts
                    )
                    self.assertIn("AEGIS-LAB{unsigned-role-cookie}", private_bodies)

    def test_logger_preserves_numeric_format_arguments(self):
        handler = object.__new__(VulnLabHandler)
        handler.client_address = ("127.0.0.1", 12345)
        with unittest.mock.patch("builtins.print") as output:
            handler.log_message("code %d, message %s", 400, "Bad request")
        output.assert_called_once_with(
            "[vulnlab] 127.0.0.1 code 400, message Bad request"
        )


if __name__ == "__main__":
    unittest.main()
