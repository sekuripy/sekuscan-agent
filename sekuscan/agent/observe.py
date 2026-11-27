# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""DOM/state observation.

One `page.evaluate` call collects the structure of the page (links, forms,
controls, cookies, scripts). The agent then trims, redacts and packages it as
a `StateSnapshot`.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Optional

from ..protocol.models import (
    ActionSpec,
    AnchorSpec,
    CaptureRules,
    CookieSpec,
    FormSpec,
    InputSpec,
    StateSnapshot,
    SubresourceSpec,
)
from .browser import BrowserSession
from .interaction import REGISTRY
from .redaction import (jwt_preview, redact_text, redact_value_sample,
                        value_fingerprint, value_shape)

log = logging.getLogger("sekuscan.agent.observe")

COLLECT_JS = r"""
(limits) => {
  // Fixed ceilings rather than extra `CaptureRules` settings: each is
  // generous enough that no ordinary page reaches it, and the true count is
  // reported beside each kept array. `max_links` and `max_forms` are
  // optional settings that default to null (no cap).
  const MAX_DOM_NODES = 25000;
  const MAX_ANCHORS = 500;
  const MAX_SCRIPT_SRCS = 400;
  const MAX_SUBRESOURCES = 400;
  // Web components and component libraries attach an OPEN shadow
  // root and put their markup there. A plain
  // `document.querySelectorAll` never sees inside one, so every
  // link, form and control rendered through it would be
  // invisible. Playwright's own locator engine already pierces
  // open shadow DOM when later asked to click or fill a `ref`
  // this collector returns, so a css path scoped within a shadow
  // root is enough; this walk only widens what is QUERIED, not
  // how it is ADDRESSED. Closed shadow roots have no DOM API
  // that reaches them, which is an unavoidable limitation. One
  // walk finds every shadow root to widen queries into AND
  // collects every element in the flattened tree, so a page
  // without shadow roots still costs a single
  // `querySelectorAll("*")`.
  const ROOTS = [document];
  const allNodes = [];
  // `allNodes` feeds `controlishNodes`, which calls `getComputedStyle` and
  // `matches` on every entry, so an enormous page would pay for every node
  // before any cap applied. The walk still has to iterate everything (that is
  // how shadow roots are found) but does not keep everything, and the true
  // count is reported beside the kept set, as `text_length` is beside
  // `text_sample`.
  let domNodesTotal = 0;
  (function collect(root, depth) {
    if (depth <= 0) return;
    let nodes;
    try { nodes = root.querySelectorAll("*"); } catch (e) { return; }
    for (const el of nodes) {
      domNodesTotal += 1;
      if (allNodes.length < MAX_DOM_NODES) allNodes.push(el);
      if (el.shadowRoot) {
        ROOTS.push(el.shadowRoot);
        collect(el.shadowRoot, depth - 1);
      }
    }
  })(document, 6);
  const queryAll = (selector) => {
    const out = [];
    for (const root of ROOTS) {
      try { out.push(...root.querySelectorAll(selector)); } catch (e) { /* invalid in this root */ }
    }
    return out;
  };

  const cssPath = (el) => {
    if (!el || el.nodeType !== 1) return "";
    if (el.id && /^[A-Za-z][\w-]*$/.test(el.id)) return "#" + el.id;
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 6) {
      let part = node.tagName.toLowerCase();
      const parent = node.parentElement;
      if (!parent) { parts.unshift(part); break; }
      const sibs = Array.from(parent.children).filter(c => c.tagName === node.tagName);
      if (sibs.length > 1) part += ":nth-of-type(" + (sibs.indexOf(node) + 1) + ")";
      parts.unshift(part);
      if (parent.id && /^[A-Za-z][\w-]*$/.test(parent.id)) {
        parts.unshift("#" + parent.id);
        break;
      }
      node = parent;
    }
    return parts.join(" > ");
  };

  const hash = (s) => {
    let h = 5381;
    for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
    return h.toString(16);
  };

  const isHidden = (el) => {
    if (!el) return true;
    // `el.type` is not always a string: a form control named `type`
    // shadows the property, so `el.type` can return an element and
    // `.toLowerCase` would throw.
    if (String(el.type || "").toLowerCase() === "hidden") return true;
    const style = window.getComputedStyle(el);
    return style.display === "none" || style.visibility === "hidden" ||
           (el.offsetParent === null && style.position !== "fixed");
  };

  const all = allNodes;
  const skeleton = all.map(e => e.tagName.toLowerCase()).join(",");

  // Every place HTML can name another resource, not just `<a href>`: the
  // HTML spec's list of URL-valued attributes.
  const URL_ATTRS = [
    ["a", "ping"], ["area", "href"], ["area", "ping"],
    ["applet", "archive"], ["applet", "codebase"],
    ["audio", "src"], ["source", "src"], ["track", "src"],
    ["video", "src"], ["video", "poster"],
    ["blockquote", "cite"], ["q", "cite"], ["del", "cite"], ["ins", "cite"],
    ["button", "formaction"], ["input", "formaction"], ["input", "src"],
    ["embed", "src"], ["frame", "src"], ["iframe", "src"],
    ["img", "src"], ["img", "longdesc"], ["img", "lowsrc"], ["img", "dynsrc"],
    ["object", "data"], ["object", "codebase"], ["param", "value"],
    ["base", "href"], ["link", "href"], ["script", "src"],
    ["body", "background"], ["table", "background"],
    ["td", "background"], ["th", "background"],
    ["isindex", "action"], ["form", "action"],
    ["html", "manifest"], ["import", "implementation"]
  ];

  // htmx puts the navigation in an attribute (`hx-get`, `hx-post`, ...),
  // which is accepted on any element rather than a fixed tag list.
  const HX_ATTRS = ["hx-get", "hx-post", "hx-put", "hx-patch", "hx-delete",
                    "data-hx-get", "data-hx-post", "data-hx-put",
                    "data-hx-patch", "data-hx-delete"];

  // A static asset with no query string cannot hide a parameter, and fetching
  // every logo on a large site would be needless load on the target. Anything
  // carrying a query is kept regardless of extension.
  const ASSET_RE = /\.(?:png|jpe?g|gif|webp|avif|bmp|ico|svg|woff2?|ttf|eot|otf|css|mp[34]|m4[av]|ogg|webm|wav|avi|mov|zip|gz|bz2|7z|rar|pdf|docx?|xlsx?|pptx?)$/i;
  const interesting = (raw) => {
    if (!raw) return false;
    const value = String(raw).trim();
    if (!value) return false;
    if (/^\s*(javascript:|mailto:|tel:|data:|blob:|about:|#)/i.test(value)) return false;
    const withoutQuery = value.split("?")[0].split("#")[0];
    if (value.indexOf("?") < 0 && ASSET_RE.test(withoutQuery)) return false;
    return true;
  };

  const refs = [];
  const pushRef = (raw) => { if (interesting(raw)) refs.push(String(raw).trim()); };

  // `<base href>` retargets every relative reference on the page, but
  // `getAttribute` returns the raw unresolved text. When a <base> exists,
  // the browser-resolved element PROPERTY (`a.href`, `img.src`) is read
  // instead. Only attributes with a resolving IDL property are mapped
  // (`ping`, `archive`, `value` and `background` have none), and a
  // fragment-only reference keeps its raw form, because `.href` would
  // expand `#tab` into a whole URL that `interesting()` no longer
  // recognises as a fragment.
  const BASE_EL = document.querySelector("base[href]");
  const RESOLVING_PROP = {
    href: "href", src: "src", action: "action", data: "data", cite: "cite",
    poster: "poster", formaction: "formAction", longdesc: "longDesc",
    manifest: "manifest", codebase: "codeBase"
  };
  const attrValue = (el, attr) => {
    const raw = el.getAttribute(attr);
    if (!BASE_EL || !raw || String(raw).trim().charAt(0) === "#") return raw;
    const prop = RESOLVING_PROP[attr];
    if (!prop) return raw;
    try {
      const value = el[prop];
      return (typeof value === "string" && value) ? value : raw;
    } catch (e) { return raw; }
  };

  const linkNodes = queryAll("a[href]");
  linkNodes.forEach(a => pushRef(attrValue(a, "href")));
  for (const pair of URL_ATTRS) {
    for (const el of queryAll(pair[0] + "[" + pair[1] + "]")) {
      pushRef(attrValue(el, pair[1]));
    }
  }
  // htmx: the attribute carries the URL and may sit on any element.
  for (const attr of HX_ATTRS) {
    for (const el of queryAll("[" + attr + "]")) {
      pushRef(el.getAttribute(attr));
    }
  }
  // A `data:` URI can be a whole DOCUMENT, and the browser will
  // not follow what is inside it.
  //
  // `<img src="data:image/svg+xml,<svg><image
  // xlink:href='/x'/></svg>">` is a real shape and the
  // reference inside it is real markup. Chromium never requests
  // it (SVG loaded through `<img>` runs in secure static mode),
  // so there is no network event and nothing in the DOM to
  // query. The only place that URL exists is the attribute's
  // own text.
  //
  // Scoped deliberately: only `href`/`src`/`xlink:href`
  // ATTRIBUTES inside the decoded payload, never any path-
  // shaped token in it. An attribute in markup is a reference;
  // a substring is a guess, and guesses are not followed.
  const __sksDataUriMax = 65536;
  for (const el of queryAll("[src],[href],[data]")) {
    for (const attr of ["src", "href", "data"]) {
      const raw = String(el.getAttribute(attr) || "");
      if (raw.slice(0, 5).toLowerCase() !== "data:") continue;
      /* Ceiling on the size of a `data:` attribute that is decoded and
         scanned. An inlined font or image can be megabytes, and decoding and
         regex-scanning it for every such element would cost CPU and memory
         for content unlikely to hold a reference worth following. A URL in an
         inlined blob is found in its first few KB or not at all; this bounds a
         pathological input and is not a sampling setting. */
      if (raw.length > __sksDataUriMax) continue;
      let payload = raw.slice(raw.indexOf(",") + 1);
      // Both spellings occur: `;base64,` and percent-encoded plain text.
      if (/;base64/i.test(raw.slice(0, raw.indexOf(",")))) {
        try { payload = atob(payload); } catch (e) { continue; }
      } else {
        try { payload = decodeURIComponent(payload); } catch (e) {}
      }
      // Percent-encoding inside these payloads is frequently partial (for
      // example `%68ttp:%2f/`), so decode once more per candidate rather than
      // trusting one pass over the whole blob.
      for (const m of payload.matchAll(
             /(?:xlink:href|href|src)\s*=\s*["']([^"']+)["']/gi)) {
        let value = m[1];
        try { value = decodeURIComponent(value); } catch (e) {}
        pushRef(value);
      }
    }
  }

  // `srcset` is a comma-separated candidate list with density descriptors, so
  // every candidate is its own URL and none of them parse as one on their own.
  for (const el of queryAll("img[srcset],source[srcset]")) {
    for (const part of String(el.getAttribute("srcset") || "").split(",")) {
      pushRef(part.trim().split(/\s+/)[0]);
    }
  }
  // `<meta>` hides URLs in several unrelated conventions: a refresh
  // destination, a CSP `report-uri`, and vendor config files. Rather than
  // encode each one, take any URL-shaped token out of a `content` attribute -
  // a meta tag has no other reason to contain a path.
  for (const el of queryAll("meta[content]")) {
    const content = String(el.getAttribute("content") || "");
    const refresh = content.match(/url\s*=\s*['"]?([^'";,]+)/i);
    if (refresh) pushRef(refresh[1]);
    const reportUri = content.match(/report-uri\s+([^;'"]+)/i);
    if (reportUri) pushRef(reportUri[1]);
    for (const m of content.matchAll(/(?:^|['"\s(])(\/[^\s'"<>)]{2,})/g)) pushRef(m[1]);
  }
  // A doctype may carry a SYSTEM identifier, and `<html manifest>` is read off
  // the element rather than from a normal attribute query on some documents.
  try {
    const dt = document.doctype;
    if (dt && dt.systemId) pushRef(dt.systemId);
  } catch (e) {}
  // A conditional comment is invisible to `querySelectorAll` because it is a
  // comment, but the markup inside it is what the browser it targets would
  // have loaded.
  try {
    const walker = document.createTreeWalker(document.documentElement,
                                             NodeFilter.SHOW_COMMENT);
    let seenComments = 0;
    while (walker.nextNode() && seenComments < 40) {
      seenComments += 1;
      const text = String(walker.currentNode.nodeValue || "");
      for (const m of text.matchAll(/(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
        pushRef(m[1]);
      }
    }
  } catch (e) {}

  const seenRefs = new Set();
  const deduped = refs.filter(h => {
    if (seenRefs.has(h)) return false;
    seenRefs.add(h);
    return true;
  });
  const links = limits.max_links == null ? deduped
                                         : deduped.slice(0, limits.max_links);

  const describeInput = (el) => {
    const tag = el.tagName.toLowerCase();
    const type = tag === "input" ? String(el.type || "text").toLowerCase() : tag;
    let options = [];
    if (tag === "select") {
      options = Array.from(el.options).map(o => o.value);
    }
    return {
      name: el.name || null,
      dom_id: el.id || null,
      type: type,
      value_sample: (el.value || "").slice(0, 240),
      placeholder: el.placeholder || null,
      required: !!el.required,
      accept: el.getAttribute ? (el.getAttribute("accept") || null) : null,
      hidden: isHidden(el),
      readonly: !!el.readOnly,
      maxlength: el.maxLength && el.maxLength > 0 ? el.maxLength : null,
      options: options
    };
  };

  const formNodes = queryAll("form");
  const forms = (limits.max_forms == null ? formNodes : formNodes.slice(0, limits.max_forms))
    .map(form => {
      const inputs = Array.from(form.querySelectorAll("input,select,textarea"))
        .map(describeInput);
      const submit = form.querySelector(
        "button[type=submit],input[type=submit],button:not([type]),button[type=button]");
      return {
        ref: cssPath(form),
        action: form.getAttribute("action"),
        method: (form.getAttribute("method") || "get").toLowerCase(),
        // Whether the author DECLARED a method, not what the browser
        // would default to. A form with no method attribute is typically
        // submitted by script, so the HTML default is not an
        // observation.
        method_declared: !!form.getAttribute("method"),
        enctype: form.getAttribute("enctype"),
        name: form.getAttribute("name"),
        dom_id: form.id || null,
        inputs: inputs,
        submit_selector: submit ? cssPath(submit) : null,
        synthetic: false
      };
    });

  // ---- controls the markup does not declare -----------------------------
  //
  // `window[REGISTRY]` knows which elements the application attached a click
  // listener to. Frameworks that delegate register nothing per element, so a
  // pointer cursor on an element with text is the fallback.
  const registry = window[limits.registry_key] || null;
  const wired = (el) => {
    try { return !!(registry && registry.has(el)); } catch (e) { return false; }
  };
  const DECLARED = "a[href], button, input[type=submit], input[type=button], " +
                   "input[type=reset], input[type=image], [role=button], [role=link], " +
                   "[role=tab], [role=menuitem], [onclick]";
  const declared = (el) => {
    try { return el.matches(DECLARED); } catch (e) { return false; }
  };

  const controlish = (el) => {
    if (declared(el)) return true;
    if (isHidden(el)) return false;
    if (wired(el)) return true;
    // delegated: styled as a control, carries a label, and is not just the
    // clickable wrapper of something already offered
    try {
      if (window.getComputedStyle(el).cursor !== "pointer") return false;
      const text = (el.innerText || "").trim();
      if (!text || text.length > 120) return false;
      return !el.querySelector(DECLARED);
    } catch (e) { return false; }
  };

  // A material-style field often contains its own help or password-visibility
  // button. That button is a control, but not the action that consumes the
  // loose inputs. Prefer a labelled submit-like control when a shared
  // container has several fields; fall back to the field-local control only
  // when there is no larger logical group.
  const controlLabel = (el) => ((el.getAttribute("aria-label") || "") + " " +
    (el.innerText || "")).trim().toLowerCase();
  const controlRank = (el) => {
    const label = controlLabel(el);
    if (!label) return 0;
    return /\b(search|submit|send|save|change|login|sign|continue|next|reset|update|apply|checkout|upload|filter|add|remove|delete|go)\b/.test(label) ? 2 : 1;
  };

  // Every controlish node in the document,
  // computed once and reused below, so the
  // ancestor walk in `nearestControl` and the
  // undeclared-controls pass do not each
  // repeat a full-document scan.
  // `Node.contains()` on this precomputed,
  // document-order list gives the same result
  // per ancestor level.
  const controlishNodes = all.filter(controlish);

  const nearestControl = (el) => {
    // the control a human would press to act on this field: the closest
    // ancestor's first controlish descendant, walking up a bounded distance
    let node = el.parentElement;
    let fallback = null;
    for (let up = 0; node && up < 6; up++, node = node.parentElement) {
      const candidates = controlishNodes
        .filter(c => c !== el && node.contains(c) && !isHidden(c) &&
                    !(c.tagName === "A" && c.getAttribute("href")));
      if (!candidates.length) continue;
      const preferred = candidates.filter(c => controlRank(c) >= 2);
      if (preferred.length) {
        preferred.sort((a, b) => controlRank(b) - controlRank(a));
        return {container: node, control: preferred[0]};
      }
      if (!fallback) fallback = {container: node, control: candidates[0]};
      // A field-local help/toggle control is not a useful group boundary. Keep
      // walking until the shared container (normally the component or panel)
      // is reached.
    }
    return fallback;
  };

  // Inputs living outside any `<form>`: grouped with the control that acts on
  // them, so they can be filled and pressed as a real form is.
  const loose = queryAll("input,select,textarea")
    .filter(el => !el.closest("form") && !isHidden(el) &&
                  !/^(submit|button|reset|image|hidden)$/.test(
                      String(el.type || "text").toLowerCase()))
    ;
  const groups = new Map();
  for (const el of loose) {
    const pair = nearestControl(el);
    if (!pair) continue;
    const key = cssPath(pair.container);
    if (!groups.has(key)) {
      groups.set(key, {container: pair.container, control: pair.control, inputs: []});
    }
    groups.get(key).inputs.push(el);
  }
  for (const [ref, group] of groups) {
    if (limits.max_forms != null && forms.length >= limits.max_forms) break;
    // a "group" of a dozen unrelated fields is a page, not a form
    if (!group.inputs.length || group.inputs.length > 12) continue;
    forms.push({
      ref: ref,
      action: null,
      method: "get",
      enctype: null,
      name: null,
      dom_id: group.container.id || null,
      inputs: group.inputs.map(describeInput),
      submit_selector: cssPath(group.control),
      // there is no <form> element, so no author declared anything
      method_declared: false,
      synthetic: true
    });
  }

  const actionNodes = [];
  const actionSeen = new Set();
  for (const el of queryAll(DECLARED)) {
    if (limits.max_actions != null && actionNodes.length >= limits.max_actions) break;
    const ref = cssPath(el);
    if (!ref || actionSeen.has(ref)) continue;
    actionSeen.add(ref); actionNodes.push(el);
  }
  // then the undeclared ones, which is where many applications keep their
  // navigation: a `<div>` with a listener and no attribute to find it by.
  // `controlishNodes` (computed once above) already holds these in document
  // order, so this filters that list rather than scanning the document
  // again.
  for (const el of controlishNodes) {
    if (limits.max_actions != null && actionNodes.length >= limits.max_actions) break;
    if (declared(el)) continue;
    const ref = cssPath(el);
    if (!ref || actionSeen.has(ref)) continue;
    actionSeen.add(ref); actionNodes.push(el);
  }
  const actions = actionNodes.map(el => {
    const tag = el.tagName.toLowerCase();
    let kind = "button";
    if (!declared(el)) kind = "control";
    else if (tag === "a") kind = "link";
    else if (tag === "input") kind = String(el.type || "").toLowerCase() === "submit" ? "submit" : "input";
    else if (tag === "button") kind = String(el.type || "").toLowerCase() === "submit" ? "submit" : "button";
    return {
      ref: cssPath(el),
      kind: kind,
      text: ((el.innerText || el.value || el.getAttribute("aria-label") || "") + "")
        .trim().slice(0, 120),
      href: el.getAttribute ? el.getAttribute("href") : null,
      disabled: !!el.disabled,
      hidden: isHidden(el)
    };
  });

  const inlineScript = queryAll("script:not([src])")
    .map(s => s.textContent || "").join("\n/*--*/\n")
    .slice(0, limits.text_sample_bytes);

  // Through `attrValue()`, not
  // `getAttribute()`, like every
  // other reference on the page
  // (see the <base href> note
  // above). Raw `getAttribute`
  // returns unresolved text that
  // would later be resolved
  // against the CURRENT PAGE URL
  // rather than the document's
  // <base>, which is wrong for
  // any client-side route served
  // below the base path: the
  // same bundles would appear to
  // live under every route's own
  // path.
  const scriptSrcNodes = queryAll("script[src]");
  const scriptSrcs = scriptSrcNodes.slice(0, MAX_SCRIPT_SRCS)
    .map(s => attrValue(s, "src"));

  // the same tags again, with the attributes that decide whether the browser
  // verifies what it executes.  `src` alone cannot answer that.
  const subresourceNodes = queryAll("script[src],link[rel~=stylesheet][href]");
  const subresources = subresourceNodes.slice(0, MAX_SUBRESOURCES)
    .map(el => ({
      tag: el.tagName.toLowerCase(),
      url: attrValue(el, "src") || attrValue(el, "href") || "",
      integrity: el.getAttribute("integrity") || null,
      crossorigin: el.getAttribute("crossorigin") || null
    }));

  const anchorNodes = queryAll("a[href][target]");
  const anchors = anchorNodes.slice(0, MAX_ANCHORS)
    .map(el => ({
      href: el.getAttribute("href") || "",
      target: el.getAttribute("target") || "",
      rel: el.getAttribute("rel") || "",
      text: (el.innerText || "").trim().slice(0, 120)
    }));

  // A small, URL-free computed-style fingerprint of the first 240
  // elements and of the body: rendering state only, no rules, URLs or
  // application data.
  const styleRows = all.slice(0, 240).map(el => {
    const s = window.getComputedStyle(el);
    return [el.tagName.toLowerCase(), s.display, s.visibility, s.position,
      s.color, s.backgroundColor, s.opacity].join("|");
  }).join("\n");
  const bodyStyle = document.body ? window.getComputedStyle(document.body) : null;
  const cssBody = bodyStyle ? [bodyStyle.display, bodyStyle.visibility,
    bodyStyle.color, bodyStyle.backgroundColor, bodyStyle.opacity].join("|") : "";

  const metas = {};
  queryAll("meta[name],meta[http-equiv]").slice(0, 25)
    .forEach(m => {
      const key = (m.getAttribute("name") || m.getAttribute("http-equiv") || "").toLowerCase();
      if (key) metas[key] = (m.getAttribute("content") || "").slice(0, 200);
    });

  const text = (document.body ? (document.body.innerText || "") : "");
  const html = document.documentElement ? document.documentElement.outerHTML : "";

  return {
    url: location.href,
    title: document.title || "",
    dom_signature: hash(skeleton),
    text_sample: text.slice(0, limits.text_sample_bytes),
    text_length: text.length,
    visible_text_length: text.trim().length,
    html_sample: html.slice(0, limits.html_sample_bytes),
    html_length: html.length,
    links: links,
    anchors: anchors,
    // The true sizes, beside the capped arrays, so a capped list is not
    // mistaken for the whole page (as `text_length` sits beside
    // `text_sample`).
    dom_nodes_total: domNodesTotal,
    anchors_total: anchorNodes.length,
    script_srcs_total: scriptSrcNodes.length,
    subresources_total: subresourceNodes.length,
    forms: forms,
    actions: actions,
    inline_script_sample: inlineScript,
    script_srcs: scriptSrcs,
    subresources: subresources,
    meta: metas,
    css_style_fingerprint: hash(styleRows),
    css_body_style: cssBody
  };
}
"""



# The shape of a token this scanner generates, used to flag cookie values that
# contain one.
COOKIE_MARKER_RE = re.compile(r"(?i)\bsks[a-z0-9]{4,}")

def observe_state(session: BrowserSession, capture: CaptureRules,
                  http_status: Optional[int] = None,
                  requested_url: Optional[str] = None,
                  load_error: Optional[str] = None) -> StateSnapshot:
    limits = {
        "max_links": capture.max_links,
        "max_forms": capture.max_forms,
        "max_actions": capture.max_actions,
        "html_sample_bytes": capture.html_sample_bytes,
        "text_sample_bytes": capture.text_sample_bytes,
        "registry_key": REGISTRY,
    }
    try:
        raw: dict[str, Any] = session.page.evaluate(COLLECT_JS, limits)
    except Exception as exc:
        log.debug("dom collection failed", exc_info=True)
        return StateSnapshot(
            requested_url=requested_url,
            url=_safe_url(session, requested_url), http_status=http_status,
            load_error=load_error or f"dom-collect-failed: {type(exc).__name__}",
            blank=True)

    text_sample = redact_text(raw.get("text_sample", ""), capture.text_sample_bytes)
    html_sample = redact_text(raw.get("html_sample", ""), capture.html_sample_bytes)
    inline = redact_text(raw.get("inline_script_sample", ""), capture.text_sample_bytes)

    forms = []
    for f in raw.get("forms", []):
        inputs = [
            InputSpec(
                name=i.get("name"), dom_id=i.get("dom_id"),
                type=i.get("type") or "text",
                # form values (including anti-CSRF tokens) are redacted by
                # `redact_value_sample`, which substitutes a handle for them
                value_sample=redact_value_sample(
                    i.get("value_sample"), keep=240,
                    name=i.get("name"), hidden=bool(i.get("hidden")),
                    input_type=str(i.get("type") or "").lower()),
                placeholder=(i.get("placeholder") or None),
                required=bool(i.get("required")), accept=i.get("accept"),
                hidden=bool(i.get("hidden")), readonly=bool(i.get("readonly")),
                maxlength=i.get("maxlength"),
                options=[str(o)[:40] for o in (i.get("options") or [])],
            ) for i in f.get("inputs", [])
        ]
        forms.append(FormSpec(
            ref=f.get("ref") or "form", action=f.get("action"),
            method=(f.get("method") or "get"), enctype=f.get("enctype"),
            # a synthetic group has no <form>, so nothing was declared
            method_declared=bool(f.get("method_declared", not f.get("synthetic"))),
            name=f.get("name"), dom_id=f.get("dom_id"), inputs=inputs,
            submit_selector=f.get("submit_selector"),
            synthetic=bool(f.get("synthetic"))))

    actions = [
        ActionSpec(ref=a.get("ref") or "", kind=a.get("kind") or "link",
                   text=redact_text(a.get("text") or "", 120),
                   href=a.get("href"), disabled=bool(a.get("disabled")),
                   hidden=bool(a.get("hidden")))
        for a in raw.get("actions", []) if a.get("ref")
    ]

    cookies = []
    for c in session.cookies():
        raw_value = str(c.get("value") or "")
        cookies.append(CookieSpec(
            name=c.get("name") or "", domain=c.get("domain"), path=c.get("path"),
            secure=bool(c.get("secure")), http_only=bool(c.get("httpOnly")),
            same_site=c.get("sameSite"), expires=c.get("expires"),
            value_len=len(raw_value), value_shape=value_shape(raw_value),
            value_preview=jwt_preview(raw_value),
            value_fingerprint=value_fingerprint(raw_value),
            # Our own tokens only - see `CookieSpec.carries_markers`. The
            # value itself is never recorded.
            carries_markers=sorted(set(
                m.lower() for m in COOKIE_MARKER_RE.findall(raw_value)))))

    visible = int(raw.get("visible_text_length") or 0)
    return StateSnapshot(
        requested_url=requested_url,
        url=raw.get("url") or _safe_url(session, requested_url),
        http_status=http_status,
        title=(raw.get("title") or "")[:300],
        dom_signature=str(raw.get("dom_signature") or "")[:32],
        # A stable digest, not `hash()`: Python randomises string hashing per
        # process, so `hash()` would differ between runs and break any
        # comparison that spans processes.
        text_hash=hashlib.sha1(
            text_sample.encode("utf-8", "replace")).hexdigest()[:16],
        text_sample=text_sample, text_length=int(raw.get("text_length") or 0),
        html_sample=html_sample, html_length=int(raw.get("html_length") or 0),
        visible_text_length=visible,
        links=[str(h)[:600] for h in raw.get("links", [])],
        anchors=[
            AnchorSpec(
                href=str(a.get("href") or "")[:600],
                target=(str(a.get("target") or "")[:40] or None),
                rel=(str(a.get("rel") or "")[:200] or None),
                text=(str(a.get("text") or "")[:120] or None))
            for a in (raw.get("anchors") or []) if a.get("href")],
        forms=forms, actions=actions, cookies=cookies,
        script_srcs=[str(s)[:400] for s in raw.get("script_srcs", []) if s],
        subresources=[
            SubresourceSpec(
                tag=str(s.get("tag") or "script")[:16],
                url=str(s.get("url") or "")[:400],
                integrity=(str(s["integrity"])[:200] if s.get("integrity") else None),
                crossorigin=(str(s["crossorigin"])[:32] if s.get("crossorigin") else None))
            for s in (raw.get("subresources") or []) if s.get("url")],
        dom_nodes_total=int(raw.get("dom_nodes_total") or 0),
        anchors_total=int(raw.get("anchors_total") or 0),
        script_srcs_total=int(raw.get("script_srcs_total") or 0),
        subresources_total=int(raw.get("subresources_total") or 0),
        inline_script_sample=inline,
        meta={
            **{str(k): str(v) for k, v in (raw.get("meta") or {}).items()},
            "css_style_fingerprint": str(raw.get("css_style_fingerprint") or ""),
            "css_body_style": str(raw.get("css_body_style") or ""),
        },
        load_error=load_error,
        blank=(visible < 10 and not forms and int(raw.get("html_length") or 0) < 2000),
    )


def _safe_url(session: BrowserSession, fallback: Optional[str]) -> str:
    try:
        return session.page.url
    except Exception:
        return fallback or ""
