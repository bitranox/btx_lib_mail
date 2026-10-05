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
    """Align the `lib_cli_exit_tools` configuration with the `--traceback/--no-traceback` flag.

    Console scripts and `python -m` runs then present identical diagnostics.

    Args:
        enabled: `True` enables verbose, colourised tracebacks; `False` restores compact summaries.

    Examples:
        >>> saved = snapshot_traceback_state()
        >>> apply_traceback_preferences(True)
        >>> (lib_cli_exit_tools.config.traceback, lib_cli_exit_tools.config.traceback_force_color)
        (True, True)
        >>> restore_traceback_state(saved)
    """
    lib_cli_exit_tools.config.traceback = bool(enabled)
    lib_cli_exit_tools.config.traceback_force_color = bool(enabled)


def snapshot_traceback_state() -> TracebackState:
    """Capture the current verbose/colour traceback settings.

    They can then be restored after a CLI run modifies them.

    Returns:
        The tuple `(traceback_enabled, force_color)` describing the current configuration.

    Examples:
        >>> snapshot_traceback_state() in [(False, False), (True, True)]
        True
    """
    return (
        bool(getattr(lib_cli_exit_tools.config, "traceback", False)),
        bool(getattr(lib_cli_exit_tools.config, "traceback_force_color", False)),
    )


def restore_traceback_state(state: TracebackState) -> None:
    """Reapply a previously captured traceback configuration.

    Global state then looks untouched to callers after CLI execution.

    Args:
        state: The tuple produced by `snapshot_traceback_state()`.

    Examples:
        >>> saved = snapshot_traceback_state()
        >>> apply_traceback_preferences(True)
        >>> restore_traceback_state(saved)
        >>> snapshot_traceback_state() == saved
        True
    """
    lib_cli_exit_tools.config.traceback = bool(state[0])
    lib_cli_exit_tools.config.traceback_force_color = bool(state[1])
