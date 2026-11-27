# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Three ways a credential used to leave the agent intact.

- A PEM private key: only its first 64 characters of body were redacted.
- A URL credential parameter whose value carried `%` or `!` (`p%40ss`): the
  value class stopped at the character, so nothing matched.
- An operator's own `--header` (a tenant key, an API token under a custom
  name): only the built-in sensitive header names were redacted.
"""

from __future__ import annotations

import unittest

from sekuscan.agent import redaction
from sekuscan.agent.redaction import redact_headers, redact_text


class TestNothingOfTheCredentialSurvives(unittest.TestCase):

    def test_a_whole_private_key_is_redacted(self):
        body = "\n".join(["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" + str(i) * 13 for i in range(8)])
        pem = "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\ntail" % body
        out = redact_text(pem)
        self.assertNotIn("MIIEvQ", out)
        self.assertNotIn("7777777", out)
        self.assertTrue(out.endswith("tail"))

    def test_a_truncated_private_key_is_redacted_to_the_end(self):
        out = redact_text("x -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "Q" * 200)
        self.assertNotIn("MIIEvQ", out)

    def test_percent_and_bang_values_of_a_credential_parameter(self):
        for value in ("p%40ss1234", "abc!defgh"):
            out = redact_text("https://h/login?password=%s&next=1" % value)
            self.assertNotIn(value, out)
            self.assertIn("&next=1", out)

    def test_an_operator_header_value_is_redacted(self):
        redaction.register_operator_headers({"X-Tenant-Key": "v"})
        self.addCleanup(redaction._OPERATOR_HEADERS.discard, "x-tenant-key")
        out = redact_headers({"X-Tenant-Key": "secret-tenant-123", "Accept": "text/html"})
        self.assertNotIn("secret-tenant-123", str(out))
        self.assertEqual(out["Accept"], "text/html")


if __name__ == "__main__":
    unittest.main()
