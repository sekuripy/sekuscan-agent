# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""Browser isolation is default-ON in production (`cli._isolation_enabled`), so
a real run drives the browser in a killable CHILD process. The unit suite,
however, injects a fake browser via `patch('...BrowserSession')` and drives
`run_agent`'s in-process loop - and a `patch` cannot reach a spawned child
(fresh interpreter). So force the in-process path for the whole suite here.

The isolated path has its own dedicated end-to-end tests that opt in explicitly
and are unaffected by this default: `test_browser_worker.py` (a real child +
real executor round trip) and `test_browser_isolation_flag.py` (which sets the
var to "1" via `patch.dict` inside the test, overriding this for that block).
"""

import os

os.environ["SEKUSCAN_BROWSER_ISOLATION"] = "0"
