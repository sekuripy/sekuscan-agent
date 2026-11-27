# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Format-specific regression pins for `agent/redaction._PATTERNS` - no
existing test file exercised these patterns one by one before this. Added
while closing a real gap: Stripe secret/restricted keys (`sk_live_`/
`sk_test_`/`rk_live_`) and Google API keys (`AIza...`, 39 chars total) both
passed through `redact_text()` completely unredacted - neither is caught by
the JWT/bearer/AWS/GitHub/Slack-specific patterns, and both are short enough
(well under 48 chars) to miss the generic base64-blob catch-all too.
"""

from __future__ import annotations

import unittest

from sekuscan.agent.redaction import redact_text

# A syntactically valid but non-functional example, same shape as Stripe's
# own published test-key documentation (test-mode keys are meant to be
# shared in examples) - not a real credential.
STRIPE_TEST_SECRET = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"  # split: secret scanners block the literal
STRIPE_LIVE_SECRET = "sk_live_" + "1" * 24
STRIPE_RESTRICTED = "rk_live_" + "2" * 24
STRIPE_PUBLISHABLE = "pk_live_" + "3" * 24
GOOGLE_API_KEY = "AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"
assert len(GOOGLE_API_KEY) == 39, "keep this fixture at the real key length"


class TestKnownSecretFormats(unittest.TestCase):

    def test_stripe_test_secret_key_is_redacted(self):
        self.assertIn("<redacted:stripe-key>", redact_text(STRIPE_TEST_SECRET))
        self.assertNotIn("4eC39Hq", redact_text(STRIPE_TEST_SECRET))

    def test_stripe_live_secret_key_is_redacted(self):
        self.assertIn("<redacted:stripe-key>", redact_text(STRIPE_LIVE_SECRET))

    def test_stripe_restricted_key_is_redacted(self):
        self.assertIn("<redacted:stripe-key>", redact_text(STRIPE_RESTRICTED))

    def test_stripe_publishable_key_is_left_alone(self):
        """Documented by Stripe as safe for client-side/public use - hiding
        it would remove evidence a reader needs for no security benefit."""
        self.assertEqual(redact_text(STRIPE_PUBLISHABLE), STRIPE_PUBLISHABLE)

    def test_google_api_key_is_redacted(self):
        self.assertIn("<redacted:google-api-key>", redact_text(GOOGLE_API_KEY))
        self.assertNotIn(GOOGLE_API_KEY, redact_text(GOOGLE_API_KEY))

    def test_a_google_api_key_shaped_string_one_char_short_does_not_match(self):
        """The format is exactly 39 chars; guards against the regex being
        loosened into a generic 'AIza-prefixed blob' matcher."""
        short = GOOGLE_API_KEY[:-1]
        self.assertEqual(redact_text(short), short)

    def test_a_secret_embedded_in_a_larger_body_is_still_caught(self):
        body = '{"stripe_key": "%s", "note": "do not share"}' % STRIPE_LIVE_SECRET
        redacted = redact_text(body)
        self.assertIn("<redacted:stripe-key>", redacted)
        self.assertIn("do not share", redacted)


if __name__ == "__main__":
    unittest.main()
