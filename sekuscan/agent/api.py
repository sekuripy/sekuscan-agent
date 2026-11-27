# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Thin HTTP client for the engine."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import httpx

from .redaction import scrub_secrets
from ..protocol.models import (
    AGENT_VERSION,
    CompleteRequest,
    CompleteResponse,
    Observation,
    RunCreateRequest,
    RunCreateResponse,
    StepResponse,
    StopRequest,
    StopResponse,
)

log = logging.getLogger("sekuscan.agent.api")

# A ceiling no legitimate step approaches, but one that a permanently wedged
# socket cannot outlast. See `EngineClient.__init__`.
READ_CEILING_S = 600.0

#: No connection to the engine is reused past this age. Border equipment on
#: a strict client network may cut any TCP connection older than a minute or
#: two, and one keep-alive connection would otherwise carry a whole scan. A
#: cut mid-request is retried (`cli._call_with_retry`), but a connection that
#: is never that old is never cut.
MAX_CONNECTION_AGE_S = 60.0
#: Answers that mean "the engine is briefly not there", not "the engine said
#: no": a reverse proxy whose backend is restarting or unreachable. They are
#: retried exactly like a dropped connection.
TRANSIENT_STATUS = frozenset({502, 503, 504})
#: How often a `202 finishing` completion is asked again.
COMPLETE_POLL_S = 2.0


class _Unset:
    """Distinguishes "said nothing" from an explicit `None`."""

    def __repr__(self) -> str:                            # pragma: no cover
        return "<unset>"


_UNSET = _Unset()


class EngineError(RuntimeError):
    pass


class EngineUnreachable(EngineError):
    """The engine did not answer at all (connection/timeout/DNS).

    Distinct from a 4xx/5xx response, which is the engine answering with a
    real application-level rejection (bad token, unknown run, malformed
    body) that a retry cannot fix. Only this subclass is safe to retry.
    """


class EngineClient:
    def __init__(self, base_url: str, api_key: str,
                 timeout: Any = _UNSET, proxy: Optional[str] = None,
                 verify: Any = True):
        """Create a client.

        A step can legitimately take a long time, so the read timeout is
        generous, but an unbounded wait is not safe: if the engine hangs up
        and the agent never notices, the run would stall forever without an
        error or a report. The action watchdog in `cli.py` does not cover the
        POST that reports a result, so this call needs its own bound.

        * `connect`, `write` and `pool` are bounded tightly; a stalled connect
          or write is never legitimate work.
        * `read` keeps a ceiling generous enough that no real step reaches it
          (`READ_CEILING_S`), while turning a permanent silent hang into an
          error the run can report.

        Passing `None` explicitly selects an unlimited client.
        """
        if timeout is _UNSET:
            timeout = httpx.Timeout(connect=10.0, write=30.0, pool=10.0,
                                    read=READ_CEILING_S)
        elif timeout is not None and not isinstance(timeout, httpx.Timeout) \
                and timeout <= 0:
            raise ValueError("engine timeout must be positive or None")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.run_id: Optional[str] = None
        self.run_token: Optional[str] = None
        self._timeout = timeout
        # `proxy=None` leaves httpx reading HTTPS_PROXY/NO_PROXY itself.
        self._proxy = proxy
        self._verify = verify
        self._client = self._new_client()

    def _new_client(self) -> httpx.Client:
        self._born = time.monotonic()
        return httpx.Client(timeout=self._timeout, proxy=self._proxy,
                            verify=self._verify,
                            headers={"user-agent": f"sekuscan-agent/{AGENT_VERSION}"})

    def _fresh(self) -> httpx.Client:
        """The client, with its connections recycled once they are old."""
        if time.monotonic() - self._born > MAX_CONNECTION_AGE_S:
            self._client.close()
            self._client = self._new_client()
        return self._client

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "EngineClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- helpers -----------------------------------------------------------

    def _post(self, path: str, json_body: dict[str, Any],
              headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        return self._post_status(path, json_body, headers)[1]

    def _post_status(self, path: str, json_body: dict[str, Any],
                     headers: Optional[dict[str, str]] = None
                     ) -> tuple[int, dict[str, Any]]:
        try:
            # The one road to the engine: no operator secret travels it.
            resp = self._fresh().post(f"{self.base_url}{path}", json=scrub_secrets(json_body),
                                      headers=headers or {})
        except httpx.HTTPError as exc:
            raise EngineUnreachable(f"engine unreachable: {exc}") from exc
        if resp.status_code in TRANSIENT_STATUS:
            raise EngineUnreachable(f"engine unreachable: {resp.status_code} {path}")
        if resp.status_code >= 400:
            raise EngineError(f"{resp.status_code} {path}: {resp.text[:400]}")
        return resp.status_code, resp.json()

    def _run_headers(self) -> dict[str, str]:
        if not self.run_token:
            raise EngineError("no run token: create a run first")
        return {"X-Run-Token": self.run_token}

    # -- api ---------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        resp = self._fresh().get(f"{self.base_url}/health")
        resp.raise_for_status()
        return resp.json()

    def create_run(self, req: RunCreateRequest) -> RunCreateResponse:
        data = self._post("/v1/runs", req.model_dump(),
                          headers={"X-API-Key": self.api_key})
        out = RunCreateResponse(**data)
        self.run_id, self.run_token = out.run_id, out.run_token
        return out

    def step(self, obs: Observation) -> StepResponse:
        data = self._post(f"/v1/runs/{self.run_id}/step", obs.model_dump(),
                          headers=self._run_headers())
        return StepResponse(**data)

    def complete(self, reason: str = "agent-finished",
                 artifacts: Optional[list[str]] = None) -> CompleteResponse:
        # Asked asynchronously: the report build can outlast what a strict
        # gateway lets one connection live, so each call answers at once -
        # 202 while it runs. An engine that predates the header answers 200
        # with the result, exactly as before.
        body = CompleteRequest(reason=reason,
                               artifacts=artifacts or []).model_dump()
        headers = {**self._run_headers(), "X-Complete-Async": "1"}
        while True:
            status, data = self._post_status(
                f"/v1/runs/{self.run_id}/complete", body, headers)
            if status != 202:
                return CompleteResponse(**data)
            time.sleep(COMPLETE_POLL_S)

    def stop_run(self, run_id: str, reason: str = "") -> StopResponse:
        """Ask the engine to stop a run gracefully, by id, from any caller.

        Unlike `step`/`complete`, this is not scoped to the run this client
        instance created - the whole point is a caller (an operator's tool,
        a CI cancel button) that only has the run's id and an API key, not
        the agent's own short-lived run token or process access to kill it.
        """
        data = self._post(f"/v1/runs/{run_id}/stop",
                          StopRequest(reason=reason).model_dump(),
                          headers={"X-API-Key": self.api_key})
        return StopResponse(**data)

    def fetch_text(self, path: str) -> str:
        """Fetch a report file.

        Uses the same transport-failure classification as `_post`, so a
        connection reset or timeout surfaces as `EngineUnreachable` and the
        caller's retry applies. Otherwise one transient reset at the final
        handoff could lose the local report.
        """
        try:
            resp = self._fresh().get(f"{self.base_url}{path}", headers=self._run_headers())
        except httpx.HTTPError as exc:
            raise EngineUnreachable(f"engine unreachable: {exc}") from exc
        if resp.status_code in TRANSIENT_STATUS:
            raise EngineUnreachable(f"engine unreachable: {resp.status_code} {path}")
        if resp.status_code >= 400:
            raise EngineError(f"{resp.status_code} {path}: {resp.text[:200]}")
        return resp.text


def trust_context(ca_cert: Optional[str] = None) -> "ssl.SSLContext":
    """What the engine link verifies against: the OS store AND public roots.

    httpx's default is certifi alone, which knows nothing of the CA a
    corporate TLS-inspecting proxy re-signs every site with - IT installs
    that into the operating system's store, so a scan from inside such a
    network could not reach the engine at all. `--ca-cert` adds a private
    bundle on top.
    """
    import ssl

    import certifi

    context = ssl.create_default_context()
    context.load_verify_locations(certifi.where())
    if ca_cert:
        context.load_verify_locations(ca_cert)
    return context
