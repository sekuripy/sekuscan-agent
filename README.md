# SekuScan agent

The SekuScan agent is the customer-hosted scanning component of
[SekuScan](https://sekuscan.com). It drives a real browser inside your
network against the applications you authorised. Planning and analysis happen
in the remote SekuScan engine, which is not part of this repository.

The source is published so you can audit what runs in your infrastructure.
All connections are outbound from the agent; nothing connects in.

[Releases](https://github.com/sekuripy/sekuscan-agent/releases) ·
[Security model](https://sekuscan.com/security/) ·
[sekuscan.com](https://sekuscan.com)

## Install

Pinned release (recommended). Download the wheel and `SHA256SUMS` from the
[release page](https://github.com/sekuripy/sekuscan-agent/releases), then
verify and install:

```
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify sekuscan_agent-0.2.1-py3-none-any.whl --repo sekuripy/sekuscan-agent
pip install sekuscan_agent-0.2.1-py3-none-any.whl -c requirements.lock
playwright install chromium
```

Or directly, without the verification steps:

```
pip install https://github.com/sekuripy/sekuscan-agent/releases/download/v0.2.1/sekuscan_agent-0.2.1-py3-none-any.whl
```

`requirements.lock` (attached to each release) pins the exact versions of the
dependencies the release was built and tested with, Playwright included.

Developer option, the current default branch:

```
pip install git+https://github.com/sekuripy/sekuscan-agent
playwright install chromium
```

Container image, with Chromium included (`ghcr.io/sekuripy/sekuscan-agent`):

```
docker run --rm --ipc=host -e SEKUSCAN_API_KEY \
  ghcr.io/sekuripy/sekuscan-agent:v0.2.1 run --engine https://api.sekuscan.com \
  --target https://app.example.com/ --out /tmp/report
```

The image runs as the non-root user `pwuser`. Chromium's sandbox needs user
namespaces, which Docker's default seccomp profile blocks. Playwright's
[Docker guidance](https://playwright.dev/docs/docker) is to run as `pwuser`
with its seccomp profile (`--security-opt seccomp=seccomp_profile.json`,
[the profile](https://github.com/microsoft/playwright/blob/main/utils/docker/seccomp_profile.json)),
and `--ipc=host` so Chromium does not run out of shared memory. Without such a
profile, pass `--browser-sandbox off` and treat the container itself as the
isolation boundary.

## Quick start

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
request-rate limits (`--max-rps`), run limits (`--max-seconds`,
`--max-actions`), the risk level and CI exit codes. `sekuscan-agent --version`
prints the agent and protocol versions.

## Running in CI

GitHub Actions example. On `ubuntu-24.04` runners Chromium's sandbox cannot
start until unprivileged user namespaces are allowed:

```yaml
jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: |
          pip install https://github.com/sekuripy/sekuscan-agent/releases/download/v0.2.1/sekuscan_agent-0.2.1-py3-none-any.whl
          playwright install --with-deps chromium
          sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
      - run: ./start-the-app-under-test.sh &
      - run: |
          sekuscan-agent run --engine https://api.sekuscan.com \
            --target http://127.0.0.1:8080/ --allow-internal-targets \
            --out ./report
        env:
          SEKUSCAN_API_KEY: ${{ secrets.SEKUSCAN_API_KEY }}
```

A loopback target needs `--allow-internal-targets` and no host verification.

## Scope

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
- `--scope` is a scanning policy, not network containment. Where containment
  matters, add `--strict-egress` (the browser can reach only the hosts the
  scope allows) and firewall rules on the machine running the agent.

## Credentials and what leaves your network

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
  headers are the evidence the engine judges. They leave your network, and
  they include the session cookies the application issues when the agent logs
  in and any personal or business data the pages contain.
  `--max-capture-bytes` caps how much body is captured per response.
- Your headers are attached only to the target's origins, never to a third
  party, and never carried across a redirect to a host that is not allowed
  them. (A target that answers the same page differently from one request
  to the next can defeat the redirect check once; it already holds your
  credentials.) Cookies you supply follow browser rules: they go to every
  port of their host.
- `--verify-target-tls` makes the agent verify the target's TLS certificate;
  without it, certificate errors on the target are ignored. The browser
  trusts the system store only: a private CA must be installed there
  (`--ca-cert` covers the agent's own requests, not Chromium).

## What the agent does

It navigates, clicks, fills and submits forms, sets cookies, loads a URL as
a script as a page would, sends HTTP and WebSocket requests, uploads one of a
fixed set of inert test files and deletes it again, and takes screenshots.
The only scripts it adds to a page are its own instrumentation. Test inputs
the engine chooses can contain markup or script; a page that executes one is
the vulnerability being tested.

The browser runs in a child process the agent can kill and restart.
`--browser-sandbox {auto,on,off}` controls Chromium's own sandbox; the default
`auto` enables it where the host supports it.

## Risk levels the agent enforces itself

No level promises zero side effects against the target.

- Level 1 is not read-only. The agent browses, clicks controls and submits
  forms as a user would, and sends test inputs. It does not upload files, send
  DELETE requests or send writes the engine has not declared read-only.
- Uploads need `--risk 2`; deleting an upload also needs
  `--allow-upload-cleanup` and the exact URL.
- Submitting a form with added fields or a changed method needs `--risk 2`
  or `--allow-destructive`.
- A DELETE, or a request body carrying a file, needs `--risk 2` whatever
  the engine declares.
- Another non-GET request the engine declares read-only (a GraphQL query, a
  search, an injection test against an API endpoint) is sent at any level;
  one it does not declare read-only needs `--risk 2`.
- Use `--deny` for anything that must never be pressed. `confirm()` dialogs
  are answered "no" unless `--allow-destructive` is set.
- `--max-rps` paces navigations and the agent's direct HTTP and WebSocket
  requests; form submissions, clicks and what a page loads on its own are
  not paced. `--max-actions` and `--max-seconds` bound the run.

The agent connects outbound to the engine over HTTPS (verified against the
system and public trust stores). `--ca-cert` makes the agent's own requests
to the target verify against your CA.
More on the trust model: <https://sekuscan.com/security/>.

## Environment

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

## Compatibility

The agent sends its version and protocol version when a run starts. The
engine refuses an incompatible agent at run start with a message telling you
to upgrade, never in the middle of a scan. The current and the previous minor
release are supported. To upgrade, install the newer release; see the
[changelog](CHANGELOG.md).

## Licence

[PolyForm Shield 1.0.0](LICENSE): you may read, audit, modify, build and run
this software, including in production. You may not use it to provide a
product that competes with SekuScan. It is source-available, not open source.

## Security

Report vulnerabilities to security@sekuscan.com - see [SECURITY.md](SECURITY.md).
