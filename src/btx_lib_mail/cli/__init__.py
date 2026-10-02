"""## btx_lib_mail.cli {#module-btx-lib-mail-cli}

**Purpose:** Provide the rich-click adapter that exposes the behaviour helpers
to users and automation while keeping traceback handling consistent across
console scripts and `python -m` entry points.

**Contents:**
- `CLICK_CONTEXT_SETTINGS`, `TRACEBACK_SUMMARY_LIMIT`, `TRACEBACK_VERBOSE_LIMIT`
  - shared configuration constants.
- `CliContext` - the typed `ctx.obj`: output mode, traceback choice, and the
  transport seam for embedding.
- `apply_traceback_preferences`, `snapshot_traceback_state`,
  `restore_traceback_state` - shared traceback state helpers.
- `cli` and its subcommands (`cli_info`, `cli_hello`, `cli_send_mail`,
  `cli_validate_email`, `cli_validate_smtp_host`, `cli_fail`) plus `cli_main` -
  the public CLI surface.
- `main` - composition helper driving execution through `lib_cli_exit_tools`.

**Layout:** this package is the public surface; each concern lives in a
private submodule - `_settings_sources` (options > environment > env file),
`_output` (human or JSON output, skip collection), `_traceback` (traceback
state), `_commands` (the group and the small subcommands), `_send_command`
(`send`), `_dispatch` (`main` and the JSON failure handler).

**Output modes:** human-readable by default. `--json`/`-j` (on the group, so
it composes with every subcommand) prints one envelope
`{"ok", "command", "data", "skipped"}` on success and
`{"ok": false, "command", "error": {"type", "message"}, "skipped"}` on failure;
`--json-bare` prints the `data` (or the `error`) alone. Warnings stay on
stderr in every mode. Exit codes do not depend on the output mode.

**System Role:** Documented in
`docs/systemdesign/module_reference.md#core-components`; this module is
the primary adapter, ensuring every transport shares the same traceback and
delivery semantics.
"""

from __future__ import annotations

from ._commands import CLICK_CONTEXT_SETTINGS, cli, cli_fail, cli_hello, cli_info, cli_main, cli_validate_email, cli_validate_smtp_host
from ._dispatch import main
from ._output import CliContext
from ._send_command import cli_send_mail
from ._traceback import (
    TRACEBACK_SUMMARY_LIMIT,
    TRACEBACK_VERBOSE_LIMIT,
    TracebackState,
    apply_traceback_preferences,
    restore_traceback_state,
    snapshot_traceback_state,
)

__all__ = [
    "CLICK_CONTEXT_SETTINGS",
    "TRACEBACK_SUMMARY_LIMIT",
    "TRACEBACK_VERBOSE_LIMIT",
    "CliContext",
    "TracebackState",
    "apply_traceback_preferences",
    "cli",
    "cli_fail",
    "cli_hello",
    "cli_info",
    "cli_main",
    "cli_send_mail",
    "cli_validate_email",
    "cli_validate_smtp_host",
    "main",
    "restore_traceback_state",
    "snapshot_traceback_state",
]
