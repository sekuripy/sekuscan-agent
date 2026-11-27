# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Local scope enforcement.

The engine also decides scope, but the agent independently refuses any
out-of-scope directive. A faulty or compromised engine therefore cannot make
the local browser touch anything the operator did not authorise.

The decision logic is shared with the engine (`protocol/scoping.py`) so both
sides agree on origin, scheme and path boundaries; only the refusal happens
here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..protocol import scoping
from ..protocol.models import ScopeRules


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str = ""


class ScopeGuard:
    def __init__(self, rules: ScopeRules, operator_deny=()):
        self.rules = rules
        self.origins = [o for o in rules.origins if o]
        #: The operator's own `--deny` entries: no directive is exempt from them.
        self.operator_deny = tuple(d for d in operator_deny if d)

    def check(self, url: Optional[str],
              deny_exempt: bool = False) -> ScopeDecision:
        """Decide whether `url` may be requested.

        `deny_exempt` drops the deny entries the engine added for this one
        call and nothing else: the operator's own `--deny` entries, origin,
        scheme and depth are still enforced. It is set only from
        `Directive.deny_exemption`, which a directive must name explicitly."""
        decision = scoping.decide(
            url, self.origins,
            deny_substrings=self.operator_deny if deny_exempt else self.rules.deny_substrings,
            allow_subdomains=self.rules.allow_subdomains,
            max_depth=self.rules.max_depth)
        return ScopeDecision(decision.allowed, decision.reason)

    def allowed(self, url: Optional[str]) -> bool:
        return self.check(url).allowed
