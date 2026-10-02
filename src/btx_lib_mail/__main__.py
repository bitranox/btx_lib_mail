"""## btx_lib_mail.__main__ {#module-btx-lib-mail-main}

**Purpose:** Provide the `python -m btx_lib_mail` entry point. It runs
`btx_lib_mail.cli.main`, the function the console scripts run, so exit codes,
traceback handling and `--json` failure reports are identical however the CLI
is started.

**System Role:** Mirrors the description in
`docs/systemdesign/module_reference.md#__main__-module-module-entry-point`.
"""

from __future__ import annotations

from . import cli

if __name__ == "__main__":
    raise SystemExit(cli.main())
