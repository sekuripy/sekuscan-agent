"""A populated type=password field must never reach the engine as raw text."""
from sekuscan.agent.redaction import redact_value_sample
from sekuscan.protocol.models import PRESERVE_DOM_VALUE


def test_password_value_becomes_handle():
    assert redact_value_sample("hunter2", name="pw", input_type="password") \
        == PRESERVE_DOM_VALUE


def test_empty_password_and_other_types_unchanged():
    assert redact_value_sample("", name="pw", input_type="password") == ""
    assert redact_value_sample("alice", name="user", input_type="text") == "alice"
    assert redact_value_sample("short", name="csrf_token", hidden=True,
                               input_type="hidden") == PRESERVE_DOM_VALUE


def test_observe_passes_the_input_type():
    import inspect
    from sekuscan.agent import observe
    assert "input_type=" in inspect.getsource(observe)


# pytest-style module-level functions are invisible to `unittest discover`;
# see tests/pytest_style.py.
from tests import pytest_style  # noqa: E402

TestPasswordValueSampleIsAHandle = pytest_style.collect(globals(), "TestPasswordValueSampleIsAHandle", __doc__)
