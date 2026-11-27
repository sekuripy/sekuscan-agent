# SekuScan agent

The agent is the half of [SekuScan](https://sekuscan.com) that runs inside your
network. It drives a real Chromium browser against the applications you
authorised, performs the actions the SekuScan engine asks for, and sends back
what it observed. The engine - which decides what to test and judges the
results - runs on SekuScan's side and is not part of this repository.

This source is published so you can check what a component with this view
of your applications does, and what it sends out of your network.

### Scope

[`sekuscan/agent/scope.py`](sekuscan/agent/scope.py),
[`sekuscan/protocol/scoping.py`](sekuscan/protocol/scoping.py)

- The scope is what you pass on the command line (`--target`, `--scope`,
  `--deny`, `--max-depth`). The engine's copy of it must match: a wider one
  (an extra origin, subdomains, more depth, a missing `--deny` entry) and the
  agent refuses to run.
- Every navigation, form submission and request the agent sends itself
  (HTTP, literal-bytes HTTP, WebSocket), and every redirect it follows, is
  checked against that scope. An engine may lift its own default deny
  entries for one request (a test that logs out a throwaway session); it can
  never lift yours.
- What a page loads by itself is the page's business: off-scope images,
  scripts and fetches are allowed so the application renders, without your
  credentials. A page navigating off-scope is stopped. The page's own
  WebSocket connections and service workers are not intercepted.

### Credentials and what leaves your network

[`sekuscan/agent/redaction.py`](sekuscan/agent/redaction.py),
[`sekuscan/agent/api.py`](sekuscan/agent/api.py)

- Everything sent to the engine is scrubbed of every credential value you
  gave the agent (passwords, the MFA code, bearer tokens, cookie and header
  values, proxy and NTLM passwords), in plain, percent-encoded, JSON- and
  HTML-escaped form, also when cut off at the edge of a sample and inside
  compressed bodies. Not scrubbed: values under four characters and words
  found on every login page (`password`, `admin`, ...), which would erase the
  page rather than protect a secret.
- The engine refers to your password by a handle and the agent fills it in,
  only into a password field of a form POSTed to the target, or into the body
  of a request to the target - never into a URL or another host. Cookies you
  supplied are never read back for the engine.
- Request `Authorization` and `Cookie` headers, private keys, cloud keys, JWT
  signatures and credential-named URL parameters are also redacted.
- Not redacted: what the target itself sends back. Response bodies and
  headers are the evidence the engine judges, and they include the session
  cookie the application issues when the agent logs in.
- Your headers are attached only to the target's origins, never to a third
  party, and never carried across a redirect to a host that is not allowed
  them. (A target that answers the same page differently from one request
  to the next can defeat the redirect check once; it already holds your
  credentials.) Cookies you supply follow browser rules: they go to every
  port of their host.

### What the agent does

It navigates, clicks, fills and submits forms, sets cookies, loads a URL as
a script as a page would, sends HTTP and WebSocket requests, uploads one of a
fixed set of inert test files and deletes it again, and takes screenshots.
The only scripts it adds to a page are its own instrumentation. Test inputs
the engine chooses can contain markup or script; a page that executes one is
the vulnerability being tested.

### Risk levels the agent enforces itself

- Uploads need `--risk 2`; deleting an upload also needs
  `--allow-upload-cleanup` and the exact URL.
- Submitting a form with added fields or a changed method needs `--risk 2`
  or `--allow-destructive`.
- A DELETE, or a request body carrying a file, needs `--risk 2` whatever
  the engine declares.
- Another non-GET request the engine declares read-only (a GraphQL query, a
  search, an injection test against an API endpoint) is sent at any level;
  one it does not declare read-only needs `--risk 2`.
- At every level the agent crawls as a user would: it follows links, clicks
  controls and submits the forms it finds. Use `--deny` for anything that
  must never be pressed. `confirm()` dialogs are answered "no" unless
  `--allow-destructive` is set.
- `--max-rps` paces navigations and the agent's direct HTTP and WebSocket
  requests; form submissions, clicks and what a page loads on its own are
  not paced.

The agent connects outbound to the engine over HTTPS (verified against the
system and public trust stores); nothing connects in. Certificate errors on
the TARGET are ignored, as test systems often have none valid; `--ca-cert`
makes the agent's own requests verify against your CA.
More on the trust model: <https://sekuscan.com/security/>.

## Install

```
pip install git+https://github.com/sekuripy/sekuscan-agent
playwright install chromium
```

Or `pip install .` from a checkout or a release archive.

## Run

You need a SekuScan licence key, and the hosts you scan must be verified for
it. A loopback target (`127.0.0.1`, `[::1]`, say an application started in a
CI job) needs no verification; pass `--allow-internal-targets` for it.

```
export SEKUSCAN_API_KEY=...
sekuscan-agent run --engine https://api.sekuscan.com \
  --target https://app.example.com/ --out ./report
```

`sekuscan-agent run --help` lists every option: scope and deny rules,
authentication, proxies (including NTLM/Negotiate), client certificates,
request-rate limits, the risk level and CI exit codes.

### Environment

Secrets are better passed in the environment than on the command line, where
other local users can read them: `SEKUSCAN_API_KEY`, `SEKUSCAN_USERNAME`,
`SEKUSCAN_PASSWORD`, `SEKUSCAN_MFA_CODE`, `SEKUSCAN_BEARER`, `SEKUSCAN_COOKIE`,
`SEKUSCAN_HEADER`, `SEKUSCAN_LOGIN_URL` and `SEKUSCAN_ADDITIONAL_LOGIN_URLS`
stand in for the options of the same name; `SEKUSCAN_USERNAME2`,
`SEKUSCAN_PASSWORD2`, `SEKUSCAN_LOGIN_URL2` and
`SEKUSCAN_ADDITIONAL_LOGIN_URLS2` for the second identity.

Tuning knobs, none needed in normal use:

| Variable | Default | Effect |
|---|---|---|
| `SEKUSCAN_BROWSER_ISOLATION` | `1` | run the browser in a child process the agent can kill and restart; `0` keeps it in-process (debugging) |
| `SEKUSCAN_DIRECTIVE_CAP_S` | `130` | with isolation on, seconds one action may take before the browser is restarted |
| `SEKUSCAN_NO_PROGRESS_S` | `810` | seconds without a completed step before the run is ended |
| `SEKUSCAN_PIPELINE` | `1` | overlap sending one observation with running the next actions; `0` runs strictly in turn |
| `SEKUSCAN_FAST_SETTLE` | `1` | wait for a page to go quiet by watching its activity; `0` always waits for the network to be idle |
| `SEKUSCAN_FAST_MAX_MS` | `3000` | longest such wait, in milliseconds |
| `SEKUSCAN_LATE_TIMER_MAX_MS`, `SEKUSCAN_LATE_TIMER_BUDGET_MS` | `1500`, `1200` | how long a page's own short timers are waited for after load |

## Licence

[PolyForm Shield 1.0.0](LICENSE): you may read, audit, modify, build and run
this software, including in production. You may not use it to provide a
product that competes with SekuScan. It is source-available, not open source.

## Security

Report vulnerabilities to security@sekuscan.com - see [SECURITY.md](SECURITY.md).
