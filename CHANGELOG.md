# Changelog

## 0.2.8

- A batch of requests runs requests without a session again. Each one gets
  its own empty browser context, so it carries no cookies. Agents 0.2.4 to
  0.2.7 refused these requests, and every check that compares a
  logged-in response with an anonymous one quietly found nothing.

## 0.2.7

- `sekuscan-agent vulnerableapp-findings` prints a report's findings in the
  format OWASP VulnerableApp's `/scanner/benchmark` endpoint grades.

## 0.2.6

- The container image is also tagged `latest`, which always points to the
  newest release.

## 0.2.5

Changes from a clean-machine install and scan, done the way a customer would.

- README: on Ubuntu and Debian, install `python3-venv` and `libatomic1` first.
  A fresh system lacks both, and the install stopped at the first line.
- CI runs the README's install lines on fresh Ubuntu 22.04, Ubuntu 24.04 and
  Debian 12 machines.
- The terminal no longer shows a line for every request to the engine.
- `engine ok` no longer prints `None` when the engine does not report a
  version.

## 0.2.4

Changes from a third external review.

- A redirect chain longer than 10 hops is refused. Before, the agent let
  the browser follow the rest of it unchecked.
- The `--max-seconds` hard limit now also covers setup and the first request
  to the engine.
- The container image is published for both x86_64 and arm64. Its base image
  is pinned by digest.
- README: the Docker example writes to `./report` only, a PowerShell quick
  start, how to verify only the files you downloaded, and advice to scan with
  a dedicated test account.

## 0.2.3

- Windows: credential commands (`cmd:`) now work with Windows paths.
- Every release is now tested on Ubuntu 22.04 and 24.04 (x86_64 and arm64),
  macOS and Windows, with Python 3.10 and 3.14.

## 0.2.2

Changes from a second external review.

- `--strict-egress` refuses to start if WebSockets cannot be intercepted, and
  blocks redirects from in-scope requests to other hosts.
- `--browser-sandbox on` works only with Chromium.
- `--max-seconds` is a hard limit. The agent exits at most 120 seconds after
  it.
- New tests check that your scope and risk settings apply on every execution
  path.
- Playwright 1.48 or newer is required.
- CI tests the exact dependency versions in `requirements.lock`.
- A release is published only after the tests pass and the built wheel and
  container image start correctly.
- Releases include a CycloneDX SBOM. Checksums and build attestations cover
  every release file. The container image has its own SBOM and attestation.
- GitHub Actions are pinned to commit SHAs.
- `seccomp_profile.json` lets Chromium's sandbox run inside Docker.
- README: requirements, simpler installation, support policy.

## 0.2.1

- Fixed the container image build. No change to the agent.

## 0.2.0

Changes from an external review.

- `--browser-sandbox auto|on|off`. Chromium's sandbox is on wherever the
  system allows it.
- `--verify-target-tls` verifies the target's certificate.
- `--strict-egress` blocks the browser from reaching hosts outside the scope.
- `--max-capture-bytes` limits how much of each response is sent to the
  engine.
- The agent enforces `--max-seconds` itself.
- `--version`.
- Risk level 1 is no longer described as read-only.
- The tests for scope, redaction, risk levels and credential handling are
  published in `tests/`.
- Releases include a wheel, source archive, checksums, `requirements.lock` and
  build attestations.
- Container image: `ghcr.io/sekuripy/sekuscan-agent`.

## 0.1.0

First public release.
