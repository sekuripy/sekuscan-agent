"""Lets a module of bare `test_*` functions run under unittest as well as pytest."""

from __future__ import annotations

import inspect
import pathlib
import tempfile
import unittest
from typing import Any


def collect(namespace: dict[str, Any], name: str = "TestCollected",
            doc: str = "") -> type[unittest.TestCase]:
    """Return a `TestCase` running every `test_*` function in `namespace`.

    Pass `globals()`. Only functions DEFINED in that module are taken, so an
    imported helper named `test_something` is not collected twice.
    """
    module = namespace.get("__name__")

    def setUp(self):  # noqa: N802 - unittest's own spelling
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.tmp_path = pathlib.Path(holder.name)

    body: dict[str, Any] = {"setUp": setUp, "__doc__": doc or None}
    found = 0
    for attr, value in sorted(namespace.items()):
        if not attr.startswith("test_") or not inspect.isfunction(value):
            continue
        if value.__module__ != module:
            continue
        params = list(inspect.signature(value).parameters)
        if not set(params) <= {"tmp_path", "monkeypatch"}:
            raise TypeError(
                "%s.%s takes %r; this shim supplies only `tmp_path` and `monkeypatch`"
                % (module, attr, params))
        body[attr] = _bind(value, params)
        found += 1

    if not found:
        raise TypeError("no test functions found in %s" % module)
    return type(name, (unittest.TestCase,), body)


def _bind(fn, params: list[str]):
    def method(self):
        import pytest
        mp = pytest.MonkeyPatch()
        self.addCleanup(mp.undo)
        fn(*[self.tmp_path if p == "tmp_path" else mp for p in params])
    method.__name__ = fn.__name__
    method.__doc__ = fn.__doc__
    return method
