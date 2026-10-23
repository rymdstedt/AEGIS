import unittest

from security import AUTH_TOKEN, token_matches, validate_provider_url


class SecurityTests(unittest.TestCase):
    def test_bearer_token_comparison(self):
        self.assertTrue(token_matches(AUTH_TOKEN))
        self.assertFalse(token_matches(None))
        self.assertFalse(token_matches(AUTH_TOKEN + "x"))

    def test_only_loopback_model_providers_are_allowed(self):
        self.assertEqual(validate_provider_url("http://localhost:1234/"), "http://localhost:1234")
        self.assertEqual(validate_provider_url("http://127.0.0.1:11434/v1"), "http://127.0.0.1:11434")
        self.assertEqual(validate_provider_url("http://[::1]:1234"), "http://[::1]:1234")
        for url in (
            "https://example.com/v1",
            "http://169.254.169.254/latest",
            "file:///etc/passwd",
            "http://user:pass@localhost:1234",
            "http://localhost:1234?v=secret",
            "http://localhost:1234/custom/path",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_provider_url(url)


if __name__ == "__main__":
    unittest.main()
