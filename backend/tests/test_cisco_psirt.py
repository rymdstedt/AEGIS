import unittest

import httpx
from application.cisco_psirt import (
    CiscoPsirtError,
    cisco_os_type,
    fetch_cisco_advisories,
    sanitize_psirt_response,
)


class CiscoPsirtTests(unittest.IsolatedAsyncioTestCase):
    def test_response_is_bounded_and_external_links_are_restricted(self):
        result = sanitize_psirt_response(
            {
                "count": 2,
                "advisories": [
                    {
                        "advisoryId": "cisco-sa-fixture",
                        "advisoryTitle": " Synthetic advisory \n title ",
                        "sir": "High",
                        "cvssBaseScore": "8.8",
                        "cves": ["CVE-2099-0001", "CVE-2099-0001"],
                        "firstFixed": ["17.12.5"],
                        "publicationUrl": (
                            "https://sec.cloudapps.cisco.com/security/center/"
                            "content/CiscoSecurityAdvisory/cisco-sa-fixture"
                        ),
                    },
                    {
                        "advisoryId": "cisco-sa-untrusted-link",
                        "advisoryTitle": "Untrusted publication location",
                        "sir": "Medium",
                        "publicationUrl": "https://example.invalid/not-cisco",
                    },
                ],
            },
            version="17.12.04",
            os_type="iosxe",
        )

        self.assertEqual(result["advisory_count"], 2)
        self.assertEqual(result["severity_counts"]["high"], 1)
        self.assertEqual(result["advisories"][0]["cves"], ["CVE-2099-0001"])
        self.assertIsNotNone(result["advisories"][0]["publication_url"])
        self.assertIsNone(result["advisories"][1]["publication_url"])
        self.assertFalse(result["access_token_stored"])

    async def test_fetch_uses_only_fixed_cisco_endpoint_and_does_not_return_token(self):
        fixture_access_value = "synthetic-token-value-1234567890"

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.host, "apix.cisco.com")
            self.assertEqual(request.url.path, "/security/advisories/v2/OSType/iosxe")
            self.assertEqual(request.url.params["version"], "17.12.04")
            self.assertEqual(
                request.headers["authorization"], f"Bearer {fixture_access_value}"
            )
            return httpx.Response(
                200,
                json={
                    "count": 1,
                    "advisories": [
                        {
                            "advisoryId": "cisco-sa-fixture",
                            "advisoryTitle": "Fixture advisory",
                            "sir": "Critical",
                        }
                    ],
                },
            )

        result = await fetch_cisco_advisories(
            access_token=fixture_access_value,
            version="17.12.04",
            os_type="iosxe",
            transport=httpx.MockTransport(handler),
        )

        self.assertEqual(result["advisory_count"], 1)
        self.assertNotIn(fixture_access_value, str(result))

    async def test_authentication_failure_has_safe_error(self):
        fixture_access_value = "synthetic-token-value-1234567890"
        transport = httpx.MockTransport(
            lambda _request: httpx.Response(401, json={"message": "bad token"})
        )
        with self.assertRaisesRegex(CiscoPsirtError, "rejected") as raised:
            await fetch_cisco_advisories(
                access_token=fixture_access_value,
                version="15.2(4)E",
                os_type="ios",
                transport=transport,
            )
        self.assertNotIn(fixture_access_value, str(raised.exception))

    def test_platform_mapping_is_explicit(self):
        self.assertEqual(cisco_os_type("Cisco IOS XE"), "iosxe")
        self.assertEqual(cisco_os_type("Cisco IOS"), "ios")
        with self.assertRaises(ValueError):
            cisco_os_type("Generic firmware")
