# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Review finding - `--max-actions N` was not a limit.

The batch branch checked `steps >= limit` and then added the entire batch:

    steps = 99, limit = 100, batch of 4
    99 >= 100 is False  ->  all four execute  ->  steps = 103

so the real ceiling was `limit + len(batch) - 1`. An operator who passes
`--max-actions 100` because that is what the engagement authorises does not
get 100; they get however many the engine happened to put in the last batch.
This project has a whole section about caps that are not caps, and this is
the same shape one layer up: the comparison and the increment disagree.

Trimmed rather than refused. Dropping the whole batch at 99/100 would discard
a directive the budget can still afford, which is the opposite error; refusal
is kept for the case where there is no room at all.

Asserted against the arithmetic directly, because the step loop needs a live
engine and this is a bound the operator is entitled to regardless of what the
engine sends.
"""

from __future__ import annotations

import inspect
import unittest

from sekuscan.agent import cli


def admitted(steps: int, limit: int, batch: int) -> int:
    """What the loop now admits, by the same expression it uses."""
    room = limit - steps
    if room <= 0:
        return 0
    return min(batch, room)


class TheLimitIsActuallyALimit(unittest.TestCase):

    def test_the_reviewers_case(self):
        """steps=99, limit=100, batch of 4 used to run all four -> 103."""
        self.assertEqual(admitted(99, 100, 4), 1)
        self.assertEqual(99 + admitted(99, 100, 4), 100)

    def test_no_batch_size_can_overrun_the_ceiling(self):
        """From under the limit, no batch size can cross it.

        Starting AT or PAST the limit is a separate case: admitting nothing
        is all this can do, and no arithmetic here brings an already-spent
        counter back down. That case is `test_no_room_at_all_still_refuses`.
        """
        for limit in (1, 10, 100, 1000):
            for batch in (1, 2, 4, 8, 64):
                for steps in range(max(0, limit - 3), limit):
                    total = steps + admitted(steps, limit, batch)
                    self.assertLessEqual(
                        total, limit,
                        "steps=%d limit=%d batch=%d -> %d"
                        % (steps, limit, batch, total))

    def test_nothing_is_admitted_once_the_budget_is_spent(self):
        for limit in (1, 10, 100):
            for batch in (1, 4, 64):
                for steps in (limit, limit + 1, limit + 50):
                    self.assertEqual(admitted(steps, limit, batch), 0,
                                     "steps=%d limit=%d" % (steps, limit))

    def test_a_full_batch_still_runs_when_there_is_room(self):
        """The trim must not cost throughput when the budget can afford it."""
        self.assertEqual(admitted(0, 100, 4), 4)
        self.assertEqual(admitted(50, 100, 8), 8)

    def test_no_room_at_all_still_refuses(self):
        self.assertEqual(admitted(100, 100, 4), 0)
        self.assertEqual(admitted(101, 100, 4), 0)


class TheLoopUsesThatArithmetic(unittest.TestCase):
    """Wired at the call site, not just correct in the abstract."""

    def test_the_batch_branch_trims_to_the_remaining_room(self):
        source = inspect.getsource(cli)
        start = source.index("if len(directives) > 1:")
        window = source[start:start + 1800]
        self.assertIn("room = limit - steps", window)
        self.assertIn("directives = directives[:room]", window)

    def test_it_no_longer_adds_a_whole_batch_after_a_bare_ge_check(self):
        source = inspect.getsource(cli)
        start = source.index("if len(directives) > 1:")
        window = source[start:start + 1800]
        self.assertNotIn("if limit is not None and steps >= limit:", window,
                         "the comparison that disagreed with the increment")


if __name__ == "__main__":
    unittest.main()
