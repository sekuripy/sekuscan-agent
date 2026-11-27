# Changelog

## 0.2.2

Changes from a second external review.

- `--strict-egress` fails closed: it refuses to start without WebSocket
  interception, and blocks an off-scope redirect of an in-scope request.
- `--browser-sandbox on` refuses a browser other than Chromium.
- `--max-seconds` is a hard limit: the agent winds the run down at the limit
  and exits within a bounded margin after it.
- Policy-propagation tests: the customer's scope and risk policy is checked
  on every execution path.
- Playwright floor raised to 1.48 (`route_web_socket`, which `--strict-egress`
  requires).
- CI installs the locked dependency set (`requirements.lock`).
- The release is gated and smoke-tested: tests on Python 3.10 and 3.12, then
  the built wheel is installed in a fresh environment with the lock and must
  report the tag's version; the container image is smoke-tested the same way
  before it is pushed. Nothing is published unless all of it passes.
- Releases carry a CycloneDX SBOM of the dependency set; `SHA256SUMS` covers
  the wheel, sdist, `requirements.lock` and the SBOM, all with build
  provenance attestations. The image has an SBOM and max-mode provenance, and
  an attestation.
- Every GitHub Action is pinned to a commit SHA.
- Playwright's seccomp profile ships as `seccomp_profile.json`; the README
  recommends it for the container (Chromium's sandbox on).
- README: a Requirements section, the verified install procedure, Docker
  bind-mount and user guidance, and a support policy.

## 0.2.1

- The container image builds (0.2.0's did not); CI installs Chromium for the
  tests that drive it. No change to the agent itself.

## 0.2.0

Changes from an external review of the agent.

- Browser sandbox: Chromium's sandbox is used where the host supports it
  (`--browser-sandbox auto|on|off`, default `auto`).
- `--verify-target-tls`: verify the target's TLS certificate instead of
  ignoring certificate errors.
- `--strict-egress`: the browser can reach only the hosts the scope allows.
- `--max-capture-bytes`: caps the response-body evidence sent to the engine.
- `--max-seconds` is now enforced by the agent itself, not only requested from the engine.
- `--version` prints the agent and protocol versions.
- Risk-level wording: level 1 is not read-only; no level promises zero side
  effects. `--scope` is documented as a scanning policy, not network
  containment.
- Public tests: the tests that guard scope enforcement, redaction, the local
  risk gate and credential handling ship in `tests/`.
- Release artifacts: wheel, sdist, `SHA256SUMS` and `requirements.lock`, with
  build provenance attestations.
- Container image: `ghcr.io/sekuripy/sekuscan-agent`.

## 0.1.0

First public release.
