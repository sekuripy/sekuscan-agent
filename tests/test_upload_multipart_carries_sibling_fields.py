# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""The raw-socket upload transport (`probe_http` + `upload_fixture=`) used to
build a multipart body carrying ONLY the file part - `kwargs["multipart"] =
{field: part}` - with no way to also send a form's OTHER required fields.

A target: `name`/`surname`/`address` are all `Form(...)` (required)
alongside the `image` file field; a multipart body missing them 422s before
the uploaded file - and whatever XXE payload it carries - is ever parsed at
all. `upload_multipart` merges `directive.extra_values` (plain strings) in
beside the file part.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from sekuscan.agent.execute import upload_multipart


def directive(extra_values=None):
    return SimpleNamespace(extra_values=extra_values)


PART = {"name": "sekuscan-probe.svg", "mimeType": "image/svg+xml",
        "buffer": b"<svg/>"}


class TestUploadMultipart(unittest.TestCase):

    def test_the_file_part_is_always_present(self):
        result = upload_multipart(directive(), PART, "image")
        self.assertEqual(result["image"], PART)

    def test_no_extra_values_sends_only_the_file(self):
        result = upload_multipart(directive(), PART, "image")
        self.assertEqual(result, {"image": PART})

    def test_sibling_required_fields_ride_along(self):
        result = upload_multipart(
            directive({"name": "1", "surname": "1", "address": "1"}),
            PART, "image")
        self.assertEqual(result, {"name": "1", "surname": "1",
                                  "address": "1", "image": PART})

    def test_values_are_coerced_to_strings(self):
        result = upload_multipart(directive({"count": 1}), PART, "image")
        self.assertEqual(result["count"], "1")

    def test_an_implausible_field_name_is_dropped_not_sent(self):
        result = upload_multipart(
            directive({"ok": "1", "bad name;here": "x"}), PART, "image")
        self.assertEqual(result, {"ok": "1", "image": PART})

    def test_an_extra_value_cannot_overwrite_the_file_part(self):
        """If a check ever accidentally names an extra value the same as
        the upload field, the FILE must still win - an attacker-irrelevant
        safety property, but a silent swap would be a confusing bug."""
        result = upload_multipart(directive({"image": "not a file"}),
                                  PART, "image")
        self.assertEqual(result["image"], PART)

    def test_none_extra_values_is_a_safe_no_op(self):
        result = upload_multipart(directive(None), PART, "image")
        self.assertEqual(result, {"image": PART})


if __name__ == "__main__":
    unittest.main()
