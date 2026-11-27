# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Which elements are actually controls, asked of the browser rather than the HTML.

An HTTP scanner reads markup and finds `<a href>` and `<form>`. On a large share
of the modern web that finds almost nothing: the control is a `<div>` with a
click listener attached by script, the "form" is three inputs and a button that
share a parent, and the request is built by hand in JS. There is no `action`
attribute to submit and no `href` to follow.

Being a real browser is what makes this answerable instead of guessable. Two
signals, in order of strength:

**A registered listener.** `EventTarget.prototype.addEventListener` is wrapped
before any page script runs, and every element that registers an interaction
listener is remembered. This is not a heuristic - the element is a control
because the application said so, in the only place it ever says so.

**A pointer cursor.** Frameworks that delegate - one listener on `document`, a
dispatch table keyed on the event target - register nothing per element, so the
listener signal misses them entirely. But a delegated control is still styled
like a control, because a human has to be able to tell. `cursor: pointer` on an
element with text and no interactive ancestor is the fallback, and it is a
heuristic: it is used to *offer* a click, never to claim a finding.

The wrapper must be transparent. It forwards `this`, every argument and the
return value, and reports the original's source from `toString`, so a page
that inspects its own listeners keeps working. A page that looks harder can
still tell it is wrapped.
"""

from __future__ import annotations

# The global the collector reads. The name is prefixed to make a clash with a
# page's own globals unlikely.
REGISTRY = "__sksControls"

# Event types that mean "a human operates this". `change`/`input` are absent on
# purpose: they fire on fields, and a field is not a control to be clicked.
_TYPES = ("click", "mousedown", "mouseup", "pointerdown", "pointerup",
          "touchstart", "keydown", "keypress")


def registry_script() -> str:
    """The init script. Runs before page script, once per document."""
    return """
(() => {
  const KEY = %(key)r;
  if (window[KEY]) return;
  const flagged = new WeakSet();
  const TYPES = new Set(%(types)s);
  try {
    Object.defineProperty(window, KEY, {
      value: {
        has: (el) => { try { return flagged.has(el); } catch (e) { return false; } }
      },
      enumerable: false, configurable: false, writable: false
    });
  } catch (e) { return; }
  const original = EventTarget.prototype.addEventListener;
  const wrapper = function (type, listener, options) {
    try {
      if (typeof type === "string" && TYPES.has(type.toLowerCase()) &&
          this && this.nodeType === 1) {
        flagged.add(this);
      }
    } catch (e) {}
    return original.apply(this, arguments);
  };
  try {
    wrapper.toString = () => original.toString();
    EventTarget.prototype.addEventListener = wrapper;
  } catch (e) {}
})();
""" % {"key": REGISTRY, "types": list(_TYPES)}
