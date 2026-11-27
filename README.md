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

## Requirements

| | |
|---|---|
| OS | Linux, macOS and Windows, x86_64 and arm64: anywhere Playwright's Chromium runs. Every release is tested on Ubuntu 22.04 and 24.04 (x86_64 and arm64), macOS and Windows. Anything else with Docker: the container image. |
| Python | 3.10 or newer (every release is tested on 3.10 and 3.14). |
| Browser | Chromium: `playwright install --with-deps chromium`, or use the container image, which includes it. |
| Network | Outbound HTTPS (443) to `api.sekuscan.com`, and reachability to the targets. Nothing inbound. |
| Resources | Guidance, not a guarantee: about 1-2 GB RAM and 2 CPUs; a few hundred MB of disk for reports. (An idle headless Chromium with one blank page measured about 0.6 GB resident; real applications use more.) |
| Privileges | A dedicated non-root user. Never run the agent as root. |
| Licence | A SekuScan API key. The hosts you scan must be verified for it; loopback targets need no verification. |

## Install

Pinned release (recommended). From the
[release page](https://github.com/sekuripy/sekuscan-agent/releases) download
the wheel, `requirements.lock`, `SHA256SUMS` and the SBOM
(`sbom.cdx.json`, CycloneDX), then verify and install:

```
sha256sum -c SHA256SUMS
gh attestation verify sekuscan_agent-0.2.3-py3-none-any.whl -R sekuripy/sekuscan-agent
gh attestation verify requirements.lock -R sekuripy/sekuscan-agent
pip install -c requirements.lock sekuscan_agent-0.2.3-py3-none-any.whl
playwright install --with-deps chromium
```

`requirements.lock` pins the exact versions of the dependencies the release
was built and tested with, Playwright included; the SBOM lists the same set.

Developer option, the current default branch:

```
pip install git+https://github.com/sekuripy/sekuscan-agent
playwright install chromium
```

Container image, with Chromium included (`ghcr.io/sekuripy/sekuscan-agent`).
Download [`seccomp_profile.json`](seccomp_profile.json) from this repository
(Playwright's own Docker profile, which lets Chromium's sandbox start), then:

```
mkdir report && chown 1001 report     # pwuser's uid in the image; or see below
docker run --rm --ipc=host -e SEKUSCAN_API_KEY \
  --security-opt seccomp=seccomp_profile.json \
  -v "$PWD/report:/report" \
  ghcr.io/sekuripy/sekuscan-agent:v0.2.3 run --engine https://api.sekuscan.com \
  --target https://app.example.com/ --verify-target-tls \
  --browser-sandbox on --out /report
```

The image runs as the non-root user `pwuser` (uid 1001), so the host
directory mounted at `/report` must be writable by that uid: `chown 1001` it
as above, or add `--user "$(id -u):$(id -g)"` to run as your own user, which
also works with the image and the seccomp profile. `--ipc=host` keeps Chromium
from running out of shared memory. Docker's default seccomp profile blocks the
user namespaces Chromium's sandbox needs; with the profile above and
`--browser-sandbox on` the sandbox is verified to start. Only if you cannot
use the profile, pass `--browser-sandbox off` and treat the container itself
as the isolation boundary.

## Quick start

You need a SekuScan licence key, and the hosts you scan must be verified for
it. A loopback target (`127.0.0.1`, `[::1]`, say an application started in a
CI job) needs no verification; pass `--allow-internal-targets` for it.

```
export SEKUSCAN_API_KEY=...
sekuscan-agent run --engine https://api.sekuscan.com \
  --target https://app.example.com/ --verify-target-tls --out ./report
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
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: |
          base=https://github.com/sekuripy/sekuscan-agent/releases/download/v0.2.3
          curl -fsSLO $base/requirements.lock -O $base/sekuscan_agent-0.2.3-py3-none-any.whl
          pip install -c requirements.lock sekuscan_agent-0.2.3-py3-none-any.whl
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

The `sysctl` step above is for disposable hosted runners only. Do not apply it
to a persistent host: there, use a dedicated user with an AppArmor profile
that permits user namespaces for Chromium, or the container with the seccomp
profile.

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
  WebSocket connections and service workers are not intercepted (unless
  `--strict-egress` is set).
- `--scope` is a scanning policy, not network containment. `--strict-egress`
  adds browser-level request filtering: the browser's requests to hosts the
  scope does not allow are blocked, service workers are disabled, and the
  agent refuses to start in this mode if the browser cannot intercept
  WebSockets (Playwright 1.48 or newer). An in-scope request is fetched by
  the agent itself so its redirect chain is checked hop by hop before the
  browser follows it; a chain it cannot verify (over 10 hops, or a hop it
  cannot fetch) and a 307/308 redirect of a form POST to an off-scope host
  are refused. Each in-scope GET navigation is requested twice. It is
  filtering inside the browser, not network containment: where containment
  matters, also use firewall rules on the machine running the agent.

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
`auto` enables it where the host supports it. `on` requires it and refuses
to run with a browser other than Chromium, where the sandbox is not requested.

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
  not paced. `--max-actions` and `--max-seconds` bound the run. The
  `--max-seconds N` clock starts when the agent starts: at N the engine is
  asked to finish, by N+30 s the agent ends the run at the next step, and by
  N+120 s the process exits with code 5 even if a step is blocked. Fetching
  the final report afterwards is bounded by the engine timeouts, not by N.

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
release are supported.

Support policy: security fixes are released as patch versions on the current
minor; the previous minor receives security fixes for 90 days after a new
minor ships. To upgrade, install the newer release; see the
[changelog](CHANGELOG.md).

## Licence

[PolyForm Shield 1.0.0](LICENSE): you may read, audit, modify, build and run
this software, including in production. You may not use it to provide a
product that competes with SekuScan. It is source-available, not open source.

## Security

Report vulnerabilities to security@sekuscan.com - see [SECURITY.md](SECURITY.md).
