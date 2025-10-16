"""## btx_lib_mail.__main__ {#module-btx-lib-mail-main}

**Purpose:** Provide the `python -m btx_lib_mail` entry point mandated by the
packaging guidelines, delegating to `btx_lib_mail.cli.main` so exit semantics
remain identical to the console script.

**Contents:** `_open_cli_session`, `_command_to_run`, `_command_name`, and
`_module_main` — the helpers that compose module execution with
`lib_cli_exit_tools`.

**System Role:** Mirrors the description in
`docs/systemdesign/module_reference.md#module-main-session-helpers`, ensuring
module execution shares the same traceback limits and command wiring as the CLI.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Final

from lib_cli_exit_tools import cli_session
import rich_click as click

from . import __init__conf__, cli

TRACEBACK_SUMMARY_LIMIT: Final[int] = cli.TRACEBACK_SUMMARY_LIMIT
"""Character budget for truncated tracebacks when running via module entry."""
TRACEBACK_VERBOSE_LIMIT: Final[int] = cli.TRACEBACK_VERBOSE_LIMIT
"""Character budget for verbose tracebacks when running via module entry."""


CommandRunner = Callable[..., int]


def _open_cli_session() -> AbstractContextManager[CommandRunner]:
    """### _open_cli_session() -> AbstractContextManager[CommandRunner] {#module-main-open-cli-session}

    **Purpose:** Provide a context manager wired with the agreed traceback
    limits so module execution mirrors the CLI.

    **Returns:** Context manager yielding the callable that invokes the Click
    command via `lib_cli_exit_tools.cli_session`.
    """

    return cli_session(
        summary_limit=TRACEBACK_SUMMARY_LIMIT,
        verbose_limit=TRACEBACK_VERBOSE_LIMIT,
    )


def _command_to_run() -> click.Command:
    """### _command_to_run() -> click.Command {#module-main-command-to-run}

    **Purpose:** Identify the root Click command used by module execution.

    **Returns:** `click.Command` referencing `btx_lib_mail.cli.cli`.
    """

    return cli.cli


def _command_name() -> str:
    """### _command_name() -> str {#module-main-command-name}

    **Purpose:** Provide the console-script name announced by the session so
    tests can assert against a single source of truth.

    **Returns:** `str` containing `__init__conf__.shell_command`.
    """

    return __init__conf__.shell_command


def _module_main() -> int:
    """### _module_main() -> int {#module-main-module-main}

    **Purpose:** Implement `python -m btx_lib_mail` by delegating to the CLI
    while preserving traceback limits.

    **Returns:** `int` exit code produced by the CLI run.
    """

    with _open_cli_session() as runner:
        return runner(
            _command_to_run(),
            prog_name=_command_name(),
        )


if __name__ == "__main__":
    raise SystemExit(_module_main())
