# SekuScan agent

The SekuScan agent is the part of [SekuScan](https://sekuscan.com) that runs
inside your network. It drives a real browser against the applications you
authorised. The SekuScan engine decides what to test and judges the results.
The engine runs on our side and is not in this repository.

We publish this source so you can audit what runs in your infrastructure.
The agent only makes outbound connections. Nothing connects to it.

[Latest release](https://github.com/sekuripy/sekuscan-agent/releases/latest) ·
[Security model](https://sekuscan.com/security/) ·
[sekuscan.com](https://sekuscan.com)

## Requirements

| | |
|---|---|
| OS | Linux, macOS or Windows, on x86_64 or arm64. Every release is tested on Ubuntu 22.04 and 24.04 (x86_64 and arm64), macOS and Windows. The container image runs on any Docker host, x86_64 or arm64. |
| Python | 3.10 or newer. Every release is tested on 3.10 and 3.14. |
| Browser | Chromium. The install steps below fetch it. The container image already has it. |
| Network | Outbound HTTPS (port 443) to `api.sekuscan.com`, and access to the applications you scan. No inbound connections. |
| Resources | About 2 CPUs and 1-2 GB of RAM. Large applications need more. Reports take a few hundred MB of disk. |
| User | A normal user account. Do not run the agent as root. |
| Licence | A SekuScan API key. Each host you scan must be verified for your licence. Loopback targets (127.0.0.1) need no verification. |

## Install

Linux and macOS:

```
sudo apt install python3-venv libatomic1    # Ubuntu and Debian only
python3 -m venv ~/sekuscan-agent
~/sekuscan-agent/bin/pip install https://github.com/sekuripy/sekuscan-agent/releases/download/v0.2.6/sekuscan_agent-0.2.6-py3-none-any.whl
~/sekuscan-agent/bin/playwright install --with-deps chromium
```

Windows (PowerShell):

```
py -m venv sekuscan-agent
sekuscan-agent\Scripts\pip install https://github.com/sekuripy/sekuscan-agent/releases/download/v0.2.6/sekuscan_agent-0.2.6-py3-none-any.whl
sekuscan-agent\Scripts\playwright install chromium
```

That is all. Continue with [Quick start](#quick-start).

### Docker

The image includes everything and runs on x86_64 and arm64. These commands
run a scan and write the report to `./report`:

```
mkdir -p report
docker run --rm --user "$(id -u):$(id -g)" -e SEKUSCAN_API_KEY -v "$PWD/report:/report" \
  ghcr.io/sekuripy/sekuscan-agent:v0.2.6 run --engine https://api.sekuscan.com \
  --target https://app.example.com/ --verify-target-tls --out /report
```

`ghcr.io/sekuripy/sekuscan-agent:latest` always points to the newest release.

Inside Docker the browser runs without Chromium's own sandbox, and the
container is the isolation. To have both, save
[seccomp_profile.json](seccomp_profile.json) next to you and add
`--security-opt seccomp=seccomp_profile.json` to the command.

### Verifying a release

Optional, for security reviews. Each
[release](https://github.com/sekuripy/sekuscan-agent/releases) also has:

- `SHA256SUMS`, the checksums of all release files
- a GitHub build attestation for each file
- `requirements.lock`, the exact dependency versions the release was tested with
- `sbom.cdx.json`, a CycloneDX SBOM

Download them next to the wheel and run:

```
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify sekuscan_agent-0.2.6-py3-none-any.whl -R sekuripy/sekuscan-agent
pip install -c requirements.lock sekuscan_agent-0.2.6-py3-none-any.whl
```

`gh` is the [GitHub CLI](https://cli.github.com/).

### From source

```
pip install git+https://github.com/sekuripy/sekuscan-agent
```

## Quick start

Linux and macOS:

```
export SEKUSCAN_API_KEY=...
~/sekuscan-agent/bin/sekuscan-agent run --engine https://api.sekuscan.com \
  --target https://app.example.com/ --verify-target-tls --out ./report
```

Windows (PowerShell):

```
$env:SEKUSCAN_API_KEY = "..."
sekuscan-agent\Scripts\sekuscan-agent run --engine https://api.sekuscan.com `
  --target https://app.example.com/ --verify-target-tls --out .\report
```

The report is written to `./report`. To scan an application on the same
machine (127.0.0.1), add `--allow-internal-targets`.

For authenticated scans, use a dedicated test account with only the rights
the scan needs. Do not use an administrator's own account.

`sekuscan-agent run --help` lists every option. `sekuscan-agent --version`
prints the version.

## Running in CI

A GitHub Actions job that scans an application started in the same job:

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
          pip install https://github.com/sekuripy/sekuscan-agent/releases/download/v0.2.6/sekuscan_agent-0.2.6-py3-none-any.whl
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

The `sysctl` line lets Chromium's sandbox start on Ubuntu 24.04 runners. Use
it only on throwaway CI machines. On a permanent server, use the Docker image
or a dedicated user with an AppArmor profile that allows Chromium's sandbox.

## Scope

Code: [`sekuscan/agent/scope.py`](sekuscan/agent/scope.py),
[`sekuscan/protocol/scoping.py`](sekuscan/protocol/scoping.py)

- You set the scope on the command line with `--target`, `--scope`, `--deny`
  and `--max-depth`. If the engine asks for a wider scope, the agent refuses
  to run.
- The agent checks every navigation, form submission and request it sends
  against your scope. Redirects are checked too. The engine can relax its own
  deny rules for one request, for example to log out a throwaway session. It
  can never relax yours.
- A page may load images, scripts and data from other hosts, as it would for
  any user. The agent never sends your credentials to them. If a page tries to
  navigate to a host outside the scope, the agent stops it.
- `--strict-egress` also blocks everything the page itself requests from
  hosts outside the scope, including WebSockets, and turns off service
  workers. The agent fetches each in-scope request first and checks every
  redirect before the browser follows it. It refuses redirect chains longer
  than 10 hops, hops it cannot fetch, and a 307/308 redirect of a form POST to
  another host. In this mode each in-scope page load is requested twice.
  The check sees the first response. A target that answers the browser's
  request differently can still redirect it, so this is a best-effort guard.
  The agent will not start in this mode with Playwright older than 1.48.
- Scope settings and `--strict-egress` filter requests inside the browser.
  They do not replace a firewall. If you need hard network limits, add
  firewall rules on the machine running the agent.

## What leaves your network

Code: [`sekuscan/agent/redaction.py`](sekuscan/agent/redaction.py),
[`sekuscan/agent/api.py`](sekuscan/agent/api.py)

- Every credential you give the agent is removed before anything is sent to
  the engine. That covers passwords, MFA codes, bearer tokens, cookie and
  header values, and proxy passwords. It also covers their encoded forms
  (URL, JSON and HTML), values cut off at the end of a sample, and compressed
  bodies. Values shorter than four characters and common words like
  `password` or `admin` are not removed, since that would erase the page
  instead of protecting a secret.
- The engine never sees your password. It refers to it by a handle, and the
  agent fills it in. The agent only puts it into a password field of a form
  sent to the target, or into a request body sent to the target. It never
  puts it in a URL or sends it to another host.
- `Authorization` and `Cookie` request headers, private keys, cloud keys, JWT
  signatures and URL parameters with credential names are also removed.
- What the application sends back does leave your network. The engine needs
  response bodies and headers as evidence. They include the session cookies
  the application issues when the agent logs in, and any personal or business
  data on the pages. `--max-capture-bytes` limits how much of each response
  is sent.
- Your headers go only to the target's own hosts. The agent does not carry
  them across a redirect to another host. A target that answers the same
  request differently each time can get around this check once, but such a
  target already has your credentials. Cookies you supply follow normal
  browser rules and are sent to every port of their host.
- By default the agent ignores certificate errors on the target, because
  test systems often lack valid certificates. `--verify-target-tls` turns
  verification on. The browser trusts only the system certificate store, so
  a private CA must be installed there. `--ca-cert` applies to the agent's
  own requests only.

## What the agent does

The agent navigates, clicks, fills in and submits forms, sets cookies, sends
HTTP and WebSocket requests, uploads small harmless test files and deletes
them again, and takes screenshots. The only scripts it adds to a page are its
own instrumentation. Test inputs from the engine can contain markup or
script. If a page runs one, that is the vulnerability being reported.

The browser runs in a separate process that the agent can kill and restart.
`--browser-sandbox` controls Chromium's sandbox. The default, `auto`, turns it
on wherever the system allows it. `on` makes it mandatory and works only with
Chromium. `off` disables it.

## Risk levels

Every level can change data in the application you scan. Level 1 browses,
clicks and submits forms like a user, and sends test inputs. It does not
upload files, send DELETE requests, or send writes the engine has not
declared read-only.

- Uploads need `--risk 2`. Deleting an upload also needs
  `--allow-upload-cleanup` and the exact URL.
- Submitting a form with added fields or a changed method needs `--risk 2`
  or `--allow-destructive`.
- DELETE requests and request bodies carrying a file need `--risk 2`.
- Other non-GET requests the engine declares read-only, such as a GraphQL
  query or a search, are sent at any level. Undeclared ones need `--risk 2`.
- Use `--deny` for anything that must never be clicked. `confirm()` dialogs
  are answered "no" unless `--allow-destructive` is set.

## Limits

- `--max-rps` limits the agent's page loads and its own HTTP and WebSocket
  requests per second. Form submissions, clicks and what pages load by
  themselves are not limited.
- `--max-actions` limits the number of actions in a run.
- `--max-seconds N` limits the run time, counted from when the agent starts.
  Setup and the first request to the engine count too.
  At N seconds the engine is asked to finish. By N+30 seconds the agent stops
  after the current step. By N+120 seconds the agent exits with code 5, even
  if a step is stuck. Downloading the final report afterwards can take longer.

## Environment variables

Passing secrets in environment variables is safer than on the command line,
where other users of the machine can see them. These variables replace the
options of the same name: `SEKUSCAN_API_KEY`, `SEKUSCAN_USERNAME`,
`SEKUSCAN_PASSWORD`, `SEKUSCAN_MFA_CODE`, `SEKUSCAN_BEARER`,
`SEKUSCAN_COOKIE`, `SEKUSCAN_HEADER`, `SEKUSCAN_LOGIN_URL` and
`SEKUSCAN_ADDITIONAL_LOGIN_URLS`. For a second identity, use
`SEKUSCAN_USERNAME2`, `SEKUSCAN_PASSWORD2`, `SEKUSCAN_LOGIN_URL2` and
`SEKUSCAN_ADDITIONAL_LOGIN_URLS2`.

Tuning settings. Normal use needs none of them.

| Variable | Default | Effect |
|---|---|---|
| `SEKUSCAN_BROWSER_ISOLATION` | `1` | Run the browser in a separate process. `0` runs it inside the agent, for debugging. |
| `SEKUSCAN_DIRECTIVE_CAP_S` | `130` | Seconds one action may take before the browser is restarted. |
| `SEKUSCAN_NO_PROGRESS_S` | `810` | Seconds without progress before the run is ended. |
| `SEKUSCAN_PIPELINE` | `1` | Send results while the next actions run. `0` does one thing at a time. |
| `SEKUSCAN_FAST_SETTLE` | `1` | Detect when a page has finished loading by watching it. `0` waits for the network to go idle. |
| `SEKUSCAN_FAST_MAX_MS` | `3000` | Longest wait for a page to finish loading, in milliseconds. |
| `SEKUSCAN_LATE_TIMER_MAX_MS`, `SEKUSCAN_LATE_TIMER_BUDGET_MS` | `1500`, `1200` | How long to wait for a page's own short timers after it loads. |

## Versions and support

The agent reports its version when a run starts. If the engine no longer
supports that version, the run is refused at the start with a message to
upgrade. It never fails in the middle of a scan.

The current and previous minor versions are supported. Security fixes come
out as patch releases of the current minor version. After a new minor version
ships, the previous one gets security fixes for 90 more days. To upgrade,
install the newer release. See the [changelog](CHANGELOG.md).

## Licence

[PolyForm Shield 1.0.0](LICENSE). You may read, audit, modify, build and run
this software, also in production. You may not use it to build a product
that competes with SekuScan. The source is available, but it is not open
source.

## Security

Report vulnerabilities to security@sekuscan.com. See [SECURITY.md](SECURITY.md).
