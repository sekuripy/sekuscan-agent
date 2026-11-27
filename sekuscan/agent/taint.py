# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""DOM observation: an init script that watches the page's DOM sinks.

The script wraps the browser APIs that turn a string into markup or code and
reports when the value passed to one contains a URL-derived value (the URL,
`window.name`, the referrer). Each report names the sink that received the
value and carries a JS stack trace.

It wraps page APIs (sinks, `postMessage`, `addEventListener`, timers) and
passes every call through unchanged; it does not alter requests or what the
page renders. Wrapping is best-effort and every hook is individually
try/caught, so a failing hook cannot break the page.
"""

from __future__ import annotations

# `%(cap)d` is the per-page cap on reports.
PAGE_HOOKS = r"""
(() => {
  const CAP = %(cap)d;
  const MIN = 6;          /* minimum value length */
  const STRUCTURED_MIN = 8; /* minimum decoded parameter value length */
  let reported = 0;

  const say = (payload) => {
    if (reported >= CAP) { return; }
    reported += 1;
    try { console.log('[sekuscan:taint] ' + JSON.stringify(payload)); } catch (e) {}
  };

  /* Query-string object-key observation. If the page URL carries a
     bracketed key of a form this agent was given, report whether a fresh
     object exposes it. An init script runs before the page's own scripts,
     so the check runs once immediately, then on DOMContentLoaded, on load
     and after a few short timeouts. */
  let pollutionReported = false;
  const checkPollution = () => {
    if (pollutionReported) { return; }
    try {
      const qs = String(location.search || '');
      const m = qs.match(/[?&](__proto__|constructor(?:%%5B|\[)prototype(?:%%5D|\]))(?:%%5B|\[)(sks[a-z0-9]+)(?:%%5D|\])=([^&]*)/);
      if (!m) { return; }
      const technique = m[1].indexOf('constructor') === 0 ? 'constructor_prototype' : 'proto';
      const marker = m[2];
      const expected = decodeURIComponent(m[3] || '');
      let actual;
      try { actual = ({})[marker]; } catch (e) { actual = undefined; }
      if (actual !== undefined && String(actual) === expected) {
        pollutionReported = true;
        try {
          console.log('[sekuscan:pollution] ' + JSON.stringify({
            marker: marker, value: expected, technique: technique,
            url: String(location.href).slice(0, 300)}));
        } catch (e) {}
      }
    } catch (e) {}
  };
  checkPollution();
  try { document.addEventListener('DOMContentLoaded', checkPollution); } catch (e) {}
  try { window.addEventListener('load', checkPollution); } catch (e) {}
  for (const delay of [50, 200, 500, 1000]) { try { setTimeout(checkPollution, delay); } catch (e) {} }

  /* Handler (re)binding, because a rebind is a state change the DOM does not
     show. For example, a button may replace its own onclick with a different
     handler when pressed: nothing appears or moves, yet the control now does
     something else. Rebinding on interaction is ordinary in frameworks that
     re-render.

     Both binding routes are wrapped
     (`addEventListener` and the `on*` property) and each report names the
     element and the event. */
  const sayHandler = (payload) => {
    try { console.log('[sekuscan:handler] ' + JSON.stringify(payload)); } catch (e) {}
  };
  const elementRef = (el) => {
    try {
      /* `window` and `document` bindings are not reported: they are
         overwhelmingly the automation harness's own listeners rather than the
         page rebinding one of its controls, and a signal that fires on every
         press is worse than none. */
      if (!el || !el.tagName) { return ''; }
      const bits = [el.tagName.toLowerCase()];
      if (el.id) { bits.push('#' + el.id); }
      const name = el.getAttribute && el.getAttribute('name');
      if (name) { bits.push('[name=' + name + ']'); }
      const type = el.getAttribute && el.getAttribute('type');
      if (type) { bits.push('[type=' + type + ']'); }
      return bits.join('');
    } catch (e) { return 'unknown'; }
  };
  /* Only the events a user (or crawler) can actually cause. A page that
     binds `scroll` or `resize` on every render would otherwise produce a
     record for every interaction. */
  const PRESSABLE_EVENTS = new Set(['click', 'mousedown', 'mouseup',
                                    'submit', 'change', 'input', 'keydown',
                                    'keyup', 'keypress', 'dblclick']);
  try {
    const nativeAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, listener, options) {
      try {
        const ref = elementRef(this);
        if (ref && PRESSABLE_EVENTS.has(String(type))) {
          sayHandler({kind: 'bound', how: 'addEventListener',
                      event: String(type), element: ref,
                      url: String(location.href).slice(0, 300)});
        }
      } catch (e) {}
      return nativeAdd.call(this, type, listener, options);
    };
  } catch (e) {}
  try {
    /* The `on*` property route. The descriptor lives on
       HTMLElement.prototype (or GlobalEventHandlers), so wrapping the setter
       there covers every element. */
    for (const event of ['click', 'submit', 'change', 'mousedown']) {
      const prop = 'on' + event;
      let descriptor = null;
      for (const proto of [HTMLElement.prototype, Element.prototype]) {
        descriptor = Object.getOwnPropertyDescriptor(proto, prop);
        if (descriptor && descriptor.set) {
          const nativeSet = descriptor.set;
          Object.defineProperty(proto, prop, Object.assign({}, descriptor, {
            set: function (value) {
              try {
                const ref = elementRef(this);
                if (ref && typeof value === 'function') {
                  sayHandler({kind: 'bound', how: prop, event: event,
                              element: ref,
                              url: String(location.href).slice(0, 300)});
                }
              } catch (e) {}
              return nativeSet.call(this, value);
            }}));
          break;
        }
      }
    }
  } catch (e) {}

  /* postMessage instrumentation. Two observations: an outbound call with
     `targetOrigin === '*'`, and an inbound 'message' listener whose
     function text contains neither `.origin` nor `.source`. */
  const sayMessaging = (payload) => {
    try { console.log('[sekuscan:postmessage] ' + JSON.stringify(payload)); } catch (e) {}
  };

  /* What was sent is described, not captured: the message's type, its key
     names, and a per-key flag for whether the value looks like a credential.
     Values are never recorded. */
  const SENSITIVE_NAME = /(?:token|secret|password|passwd|auth|apikey|api_key|credential|bearer|jwt|session|cookie|signature|private)/i;
  const looksLikeACredential = (text) => {
    try {
      if (typeof text !== 'string' || text.length < 16) { return false; }
      if (/^ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./.test(text)) { return true; }
      /* long, opaque, no spaces: the shape of an issued token rather than
         of a sentence or a URL */
      return text.length >= 24 && /^[A-Za-z0-9+/=_.-]+$/.test(text)
             && !/^https?:/.test(text);
    } catch (e) { return false; }
  };
  const describeMessage = (message) => {
    try {
      if (message === null) { return {type: 'null'}; }
      const type = typeof message;
      if (type !== 'object') {
        const text = String(message);
        return {type: type, length: text.length,
                credential_shaped: looksLikeACredential(text)};
      }
      if (Array.isArray(message)) {
        return {type: 'array', length: message.length};
      }
      const keys = Object.keys(message).slice(0, 20);
      const sensitive = [];
      for (const key of keys) {
        let value;
        try { value = message[key]; } catch (e) { value = undefined; }
        if (SENSITIVE_NAME.test(key) || looksLikeACredential(value)) {
          sensitive.push(key);
        }
      }
      return {type: 'object', keys: keys,
              key_count: Object.keys(message).length,
              sensitive_keys: sensitive};
    } catch (e) { return {type: 'unknown'}; }
  };
  try {
    /* A JS wrapper around `postMessage` is not transparent across frames:
       when an embedded frame calls `parent.postMessage(...)`, the native
       method would run with this window as the incumbent global, and the
       receiver's `event.source` would be this window instead of the iframe.
       Single-sign-on flows that compare `event.source` with
       `iframe.contentWindow` would then fail. So the wrapper lives only in a
       top frame and puts the native function back as soon as any child
       frame appears. (`postMessage` is an own property of the window:
       restore it by assignment, since `delete` would remove it
       altogether.) */
    const originalPostMessage = window.postMessage;
    if (typeof originalPostMessage === 'function' && window === window.top) {
      const wrapper = function (message, targetOrigin) {
        try {
          if (targetOrigin === '*') {
            sayMessaging({
              kind: 'wildcard_target',
              url: String(location.href).slice(0, 300),
              stack: trace(),
              message: describeMessage(message),
            });
          }
        } catch (e) {}
        return originalPostMessage.apply(this, arguments);
      };
      window.postMessage = wrapper;
      const restore = () => {
        try { if (window.postMessage === wrapper) { window.postMessage = originalPostMessage; } } catch (e) {}
      };
      try {
        new MutationObserver(() => {
          if (window.frames.length > 0 || document.querySelector('iframe,frame')) { restore(); }
        }).observe(document, {childList: true, subtree: true});
      } catch (e) {}
    }
  } catch (e) {}
  try {
    const reportedListeners = new WeakSet();
    const checkListener = (listener) => {
      try {
        if (typeof listener !== 'function' || reportedListeners.has(listener)) { return; }
        reportedListeners.add(listener);
        const src = Function.prototype.toString.call(listener);
        /* Either `.origin` or `.source` in the listener text counts as a
           sender check. */
        if (src.indexOf('.origin') < 0 && src.indexOf('.source') < 0) {
          sayMessaging({
            kind: 'listener_no_origin_check',
            url: String(location.href).slice(0, 300),
            excerpt: src.slice(0, 240),
          });
        }
      } catch (e) {}
    };
    const originalAddEventListener = window.addEventListener;
    window.addEventListener = function (type, listener) {
      try {
        if (type === 'message') { checkListener(listener); }
      } catch (e) {}
      return originalAddEventListener.apply(this, arguments);
    };
    try {
      /* The native setter is captured first and still called, so
         `window.onmessage = fn` registers the handler with the browser as
         usual. */
      const nativeOnMessage =
        Object.getOwnPropertyDescriptor(window, 'onmessage') ||
        Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
      Object.defineProperty(window, 'onmessage', {
        configurable: true,
        get: function () {
          if (nativeOnMessage && nativeOnMessage.get) {
            return nativeOnMessage.get.call(this);
          }
          return this.__sksOnMessage;
        },
        set: function (listener) {
          checkListener(listener);
          this.__sksOnMessage = listener;
          if (nativeOnMessage && nativeOnMessage.set) {
            nativeOnMessage.set.call(this, listener);
          }
        },
      });
    } catch (e) {}
  } catch (e) {}

  /* Drop this script's own frames (they have no source URL, being
     injected) and keep the first six of the page's call chain. */
  const trace = () => {
    try {
      return (new Error().stack || '').split('\n')
        .map(s => s.trim())
        .filter(s => s && s.indexOf('<anonymous>') < 0 &&
                     s.indexOf('Error') !== 0)
        .slice(0, 6);
    } catch (e) { return []; }
  };

  /* Sources, most specific first: `hash` and `search` come before `href`
     so a match is attributed to the narrowest source. */
  const sources = () => {
    const out = [];
    const add = (name, raw) => {
      try {
        const value = String(raw || '');
        if (value.length >= MIN) { out.push([name, value]); }
      } catch (e) {}
    };
    const addStructured = (name, raw) => {
      try {
        const params = new URLSearchParams(raw);
        for (const [key, value] of params.entries()) {
          /* Short decoded values are skipped. */
          if (String(value).length >= STRUCTURED_MIN) {
            out.push([name + '[' + String(key).slice(0, 40) + ']',
                      String(value)]);
          }
        }
      } catch (e) {}
    };
    try {
      const raw = location.hash.replace(/^#/, '');
      add('location.hash', raw);
      addStructured('location.hash', raw);
    } catch (e) {}
    try {
      const raw = location.search.replace(/^\?/, '');
      add('location.search', raw);
      addStructured('location.search', raw);
    } catch (e) {}
    try { add('window.name', window.name); } catch (e) {}
    try { add('document.referrer', document.referrer); } catch (e) {}
    try { add('location.pathname', location.pathname); } catch (e) {}
    try { add('location.href', location.href); } catch (e) {}
    return out;
  };

  /* The value handed to the sink must contain what a source currently
     holds. */
  const flowFrom = (value) => {
    if (typeof value !== 'string' || value.length < MIN) { return null; }
    for (const [name, held] of sources()) {
      if (value.indexOf(held) >= 0) { return {source: name, carried: held}; }
    }
    return null;
  };

  const hit = (sink, value, extra) => {
    let flow = null;
    try { flow = flowFrom(value); } catch (e) { return; }
    if (!flow) { return; }
    say({
      sink: sink,
      source: flow.source,
      carried: String(flow.carried).slice(0, 160),
      sample: String(value).slice(0, 240),
      stack: trace(),
      url: String(location.href).slice(0, 300),
      extra: extra || null,
    });
  };

  /* ---- property sinks: assignment turns a string into markup ---- */
  const wrapSetter = (owner, prop, label) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(owner, prop);
      if (!desc || !desc.set || !desc.configurable) { return; }
      Object.defineProperty(owner, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (value) {
          hit(label, value, null);
          return desc.set.call(this, value);
        },
      });
    } catch (e) {}
  };

  wrapSetter(Element.prototype, 'innerHTML', 'Element.innerHTML');
  wrapSetter(Element.prototype, 'outerHTML', 'Element.outerHTML');
  /* innerText and textContent are not sinks: they cannot introduce markup, so
     reporting them would produce false findings. */

  /* ---- method sinks ---- */
  const wrapMethod = (owner, name, label, pick) => {
    try {
      const original = owner[name];
      if (typeof original !== 'function') { return; }
      owner[name] = function () {
        try { hit(label, pick ? pick(arguments) : arguments[0], null); } catch (e) {}
        return original.apply(this, arguments);
      };
    } catch (e) {}
  };

  wrapMethod(Document.prototype, 'write', 'document.write');
  wrapMethod(Document.prototype, 'writeln', 'document.writeln');
  wrapMethod(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML',
             (a) => a[1]);
  /* setAttribute is a sink only for attributes that execute or navigate;
     reporting every data-* assignment would bury the ones that matter. */
  try {
    const setAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      try {
        const key = String(name).toLowerCase();
        if (key.startsWith('on') || key === 'href' || key === 'src' ||
            key === 'action' || key === 'formaction' || key === 'srcdoc') {
          hit('setAttribute(' + key + ')', value, null);
        }
      } catch (e) {}
      return setAttr.apply(this, arguments);
    };
  } catch (e) {}
  wrapMethod(window, 'eval', 'eval');
  wrapMethod(window, 'setTimeout', 'setTimeout');
  wrapMethod(window, 'setInterval', 'setInterval');
  /* `Function` is not wrapped: an apply-based wrapper breaks
     `new Function(...)`. */
  try { wrapMethod(window.location, 'assign', 'location.assign'); } catch (e) {}
  try { wrapMethod(window.location, 'replace', 'location.replace'); } catch (e) {}
  try { wrapMethod(DOMParser.prototype, 'parseFromString', 'DOMParser', (a) => a[0]); } catch (e) {}

  /* jQuery arrives after us, so it gets picked up when it shows up rather than
     at install time. */
  let jqTries = 0;
  const hookJquery = () => {
    jqTries += 1;
    try {
      const jq = window.jQuery || window.$;
      if (jq && jq.fn && !jq.fn.__sksWrapped) {
        jq.fn.__sksWrapped = true;
        for (const name of ['html', 'append', 'prepend', 'before', 'after',
                            'replaceWith', 'wrap']) {
          wrapMethod(jq.fn, name, 'jQuery.' + name);
        }
        return;
      }
    } catch (e) {}
    if (jqTries < 20) { setTimeout(hookJquery, 150); }
  };
  hookJquery();
})();
"""


def taint_script(cap: int = 12) -> str:
    """The observer, ready to install as a context init script."""
    return PAGE_HOOKS % {"cap": int(cap)}
