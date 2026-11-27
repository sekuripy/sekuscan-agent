# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""`redact_text` skips a pattern whose literals are absent from the body.

The literals are paired with `_PATTERNS` by position, so an entry inserted
in the middle would shift them and silently skip a pattern that can match -
a secret leaving the agent. Every guarded pattern must therefore still
redact a real example, and every pattern must be accounted for.
"""
import unittest

from sekuscan.agent import redaction

EXAMPLES = [
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlc2ln",
    "AKIAABCDEFGHIJKLMNOP",
    "sk_live_" + "a" * 24,
    "AIza" + "B" * 35,
    "ghp_" + "c" * 30,
    "sk-" + "d" * 30,
    "xoxb-1234567890-abc",
    "github_pat_" + "e" * 30,
    "gho_" + "f" * 36,
    "npm_" + "g" * 36,
    "SG." + "h" * 22 + "." + "i" * 43,
    '{"type": "service_account"}',
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow",
]


class RedactionSkipsOnlyWhatCannotMatch(unittest.TestCase):
    def test_every_guarded_pattern_still_redacts_its_example(self):
        self.assertEqual(len(redaction._NEEDLES), len(EXAMPLES))
        for pattern, example in zip(redaction._NEEDLES, EXAMPLES):
            with self.subTest(pattern=pattern.pattern[:40]):
                self.assertTrue(pattern.search(example), "example is wrong")
                self.assertNotIn(example, redaction.redact_text(
                    "<p>leak: %s </p>" % example))

    def test_every_needle_occurs_in_every_match(self):
        for pattern, needles in redaction._NEEDLES.items():
            for example in EXAMPLES:
                for match in pattern.finditer(example):
                    self.assertTrue(any(n in match.group(0) for n in needles),
                                    pattern.pattern)

    def test_the_unguarded_rule_still_runs(self):
        self.assertIn("password=<redacted>",
                      redaction.redact_text("?password=hunter2abc&x=1"))


if __name__ == "__main__":
    unittest.main()
