"""The traceback budget and the shared `lib_cli_exit_tools` traceback state helpers.

Private to btx_lib_mail.cli: import the public names from `btx_lib_mail.cli`.
"""

from __future__ import annotations

from typing import Final

import lib_cli_exit_tools

__all__ = [
    "TRACEBACK_SUMMARY_LIMIT",
    "TRACEBACK_VERBOSE_LIMIT",
    "TracebackState",
    "apply_traceback_preferences",
    "restore_traceback_state",
    "snapshot_traceback_state",
]


#: Character budget used when printing truncated tracebacks.
TRACEBACK_SUMMARY_LIMIT: Final[int] = 500
"""Character budget applied to compact traceback output."""


#: Character budget used when verbose tracebacks are enabled.
TRACEBACK_VERBOSE_LIMIT: Final[int] = 10_000
"""Character budget applied when verbose tracebacks are requested."""


TracebackState = tuple[bool, bool]


def apply_traceback_preferences(enabled: bool) -> None:  # noqa: FBT001 - public API (docs/systemdesign/module_reference.md), positional call sites exist
    """### apply_traceback_preferences(enabled: bool) -> None {#cli-apply-traceback-preferences}

    **Purpose:** Keep `lib_cli_exit_tools` configuration aligned with the CLI's
    `--traceback/--no-traceback` flag so console scripts and `python -m` runs
    present identical diagnostics.

    **Parameters:**
    - `enabled: bool` - `True` enables verbose, colourised tracebacks;
      `False` restores compact summaries.

    **Returns:** `None`.

    **Example:**
    >>> apply_traceback_preferences(True)
    >>> (lib_cli_exit_tools.config.traceback, lib_cli_exit_tools.config.traceback_force_color)
    (True, True)
    """

    lib_cli_exit_tools.config.traceback = bool(enabled)
    lib_cli_exit_tools.config.traceback_force_color = bool(enabled)


def snapshot_traceback_state() -> TracebackState:
    """### snapshot_traceback_state() -> TracebackState {#cli-snapshot-traceback-state}

    **Purpose:** Capture the current verbose/colour traceback settings so they
    can be restored after a CLI run modifies them.

    **Returns:** `TracebackState` - Tuple `(traceback_enabled, force_color)`
    describing the current configuration.

    **Example:**
    >>> snapshot_traceback_state() in [(False, False), (True, True)]
    True
    """

    return (
        bool(getattr(lib_cli_exit_tools.config, "traceback", False)),
        bool(getattr(lib_cli_exit_tools.config, "traceback_force_color", False)),
    )


def restore_traceback_state(state: TracebackState) -> None:
    """### restore_traceback_state(state: TracebackState) -> None {#cli-restore-traceback-state}

    **Purpose:** Reapply a previously captured traceback configuration so global
    state looks untouched to callers after CLI execution.

    **Parameters:**
    - `state: TracebackState` - Tuple produced by
      `snapshot_traceback_state()`.

    **Returns:** `None`.

    **Example:**
    >>> saved = snapshot_traceback_state()
    >>> apply_traceback_preferences(True)
    >>> restore_traceback_state(saved)
    >>> snapshot_traceback_state() == saved
    True
    """

    lib_cli_exit_tools.config.traceback = bool(state[0])
    lib_cli_exit_tools.config.traceback_force_color = bool(state[1])
