# Changelog

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
