"""`main`: runs the group through `lib_cli_exit_tools`, prints failures (as JSON in JSON mode), restores traceback state.

Private to btx_lib_mail.cli: import the public names from `btx_lib_mail.cli`.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import lib_cli_exit_tools
import rich_click as click

from .. import __init__conf__

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
from ._commands import cli
from ._output import FAILED_RUN_SKIPPED, FailureEnvelope, dumps_json, error_payload
from ._traceback import (
    TRACEBACK_SUMMARY_LIMIT,
    TRACEBACK_VERBOSE_LIMIT,
    TracebackState,
    apply_traceback_preferences,
    restore_traceback_state,
    snapshot_traceback_state,
)

__all__ = ["main"]


def _invoke_cli(argv: Sequence[str] | None) -> int:
    """Ask ``lib_cli_exit_tools`` to execute the Click command.

    ``lib_cli_exit_tools`` normalises exit codes and exception handling; this
    centralises the call so tests can stub it cleanly.

    Args:
        argv: Optional sequence of command-line arguments. ``None`` delegates to
            ``sys.argv`` inside ``lib_cli_exit_tools``.

    Returns:
        Exit code returned by the CLI execution.
    """
    # Set by a failed send and read by the JSON failure handler; a later run in the same
    # process (an application embedding main()) must not report an earlier run's skips.
    FAILED_RUN_SKIPPED.set(())
    argv_list = list(argv) if argv is not None else None
    as_json, bare = _json_mode(argv_list if argv_list is not None else sys.argv[1:])
    if not as_json:
        return lib_cli_exit_tools.run_cli(cli, argv=argv_list, prog_name=__init__conf__.shell_command)
    return lib_cli_exit_tools.run_cli(
        cli,
        argv=argv_list,
        prog_name=__init__conf__.shell_command,
        exception_handler=_json_exception_handler(argv_list if argv_list is not None else sys.argv[1:], bare=bare),
    )


def _current_traceback_mode() -> bool:
    """Return the global traceback preference as a boolean.

    Error handling logic needs to know whether verbose tracebacks are active
    so it can pick the right character budget and ensure colouring is
    consistent.

    Returns:
        ``True`` when verbose tracebacks are enabled; ``False`` otherwise.
    """
    return bool(getattr(lib_cli_exit_tools.config, "traceback", False))


def _traceback_limit(*, tracebacks_enabled: bool, summary_limit: int, verbose_limit: int) -> int:
    """Return the character budget that matches the current traceback mode.

    Verbose tracebacks should show the full story while compact ones keep the
    terminal tidy. This helper makes that decision explicit.

    Args:
        tracebacks_enabled: ``True`` when verbose tracebacks are active.
        summary_limit: Character budget for truncated output.
        verbose_limit: Character budget for the full traceback.

    Returns:
        The applicable character limit.
    """
    return verbose_limit if tracebacks_enabled else summary_limit


def _print_exception(exc: BaseException, *, tracebacks_enabled: bool, length_limit: int) -> int:
    """Render the exception through ``lib_cli_exit_tools`` and return its exit code.

    All transports funnel errors through ``lib_cli_exit_tools`` so that exit
    codes and formatting stay consistent; this helper keeps the plumbing in
    one place. Writes the formatted exception to stderr via ``lib_cli_exit_tools``.

    Args:
        exc: Exception raised by the CLI.
        tracebacks_enabled: ``True`` when verbose tracebacks should be shown.
        length_limit: Maximum number of characters to print.

    Returns:
        Exit code to surface to the shell.
    """
    lib_cli_exit_tools.print_exception_message(
        trace_back=tracebacks_enabled,
        length_limit=length_limit,
    )
    return lib_cli_exit_tools.get_system_exit_code(exc)


def _run_cli_via_exit_tools(
    argv: Sequence[str] | None,
    *,
    summary_limit: int,
    verbose_limit: int,
) -> int:
    """Run the command while narrating the failure path with care.

    Consolidates the call to ``lib_cli_exit_tools`` so happy paths and error
    handling remain consistent across the application and tests. Delegates to
    ``lib_cli_exit_tools`` which may write to stderr.

    Args:
        argv: Optional sequence of CLI arguments.
        summary_limit: Character budget steering exception output length.
        verbose_limit: Character budget steering exception output length.

    Returns:
        Exit code produced by the command.
    """
    try:
        return _invoke_cli(argv)
    except BaseException as exc:
        tracebacks_enabled = _current_traceback_mode()
        apply_traceback_preferences(tracebacks_enabled)
        return _print_exception(
            exc,
            tracebacks_enabled=tracebacks_enabled,
            length_limit=_traceback_limit(
                tracebacks_enabled=tracebacks_enabled,
                summary_limit=summary_limit,
                verbose_limit=verbose_limit,
            ),
        )


def main(
    argv: Sequence[str] | None = None,
    *,
    restore_traceback: bool = True,
    summary_limit: int = TRACEBACK_SUMMARY_LIMIT,
    verbose_limit: int = TRACEBACK_VERBOSE_LIMIT,
) -> int:
    """Serve as the shared entry point for console scripts and `python -m` execution.

    Orchestrates error handling and traceback restoration. Temporarily mutates
    `lib_cli_exit_tools.config` while the CLI executes.

    Args:
        argv: Optional argument vector. `None` lets Click consume `sys.argv`.
        restore_traceback: `True` restores the prior traceback configuration after
            execution; set to `False` to leave modifications in place.
        summary_limit: Character budget applied when tracebacks are summarised.
        verbose_limit: Character budget applied when verbose tracebacks are enabled.

    Returns:
        Exit code produced by the CLI. With `--json` or `--json-bare`, a failure is
        printed as JSON on standard output and the exit code is the one the same
        failure has without them.
    """
    previous_state = snapshot_traceback_state()
    try:
        return _run_cli_via_exit_tools(
            argv,
            summary_limit=summary_limit,
            verbose_limit=verbose_limit,
        )
    finally:
        _restore_when_requested(state=previous_state, should_restore=restore_traceback)


def _split_at_command(argv: Sequence[str]) -> tuple[list[str], str | None]:
    """Return the group options, and the word in the subcommand's position.

    Every group option is a flag that takes no value, so the first argument that
    is not an option (or the one after ``--``) is where the subcommand goes,
    whether or not it names one.

    Args:
        argv: Command-line arguments, including the subcommand and its options.

    Returns:
        The arguments before that position, and the word in it (``None`` when there is none).

    Examples:
        >>> _split_at_command(["--json", "sned", "--json", "hello"])
        (['--json'], 'sned')
    """
    for index, argument in enumerate(argv):
        if argument == "--":
            return list(argv[:index]), argv[index + 1] if index + 1 < len(argv) else None
        if argument == "-" or not argument.startswith("-"):
            return list(argv[:index]), argument
    return list(argv), None


def _json_mode(argv: Sequence[str]) -> tuple[bool, bool]:
    """Return ``(as_json, bare)`` from the group options in *argv*, before the subcommand.

    Read from argv rather than the Click context: an error can escape before the
    context exists (a malformed option), and its report must still be JSON. Only
    the group options count, so an option VALUE spelled like the flag
    (``--body --json``), or a flag after a mistyped subcommand, does not switch JSON on.

    Args:
        argv: Command-line arguments, including the subcommand and its options.

    Returns:
        A tuple of ``(as_json, bare)``.
    """
    group_options, _word = _split_at_command(argv)
    bare = "--json-bare" in group_options
    return bare or "--json" in group_options or "-j" in group_options, bare


def _command_named(argv: Sequence[str]) -> str | None:
    """Return the subcommand name in *argv*, for the failure envelope.

    Args:
        argv: Command-line arguments, including the subcommand and its options.

    Returns:
        The word in the subcommand's position when it names a command, else ``None``.
    """
    _group_options, word = _split_at_command(argv)
    return word if word in cli.commands else None


def _json_exception_handler(argv: Sequence[str], *, bare: bool) -> Callable[[BaseException], int]:
    """Return a ``run_cli`` exception handler that reports failures as JSON on stdout.

    The exit code is resolved as ``lib_cli_exit_tools`` resolves it without
    JSON, so a caller may switch on it in either mode.

    Args:
        argv: Command-line arguments, for naming the failed command in the envelope.
        bare: ``True`` to print the error payload alone, without the envelope.

    Returns:
        A callable taking the raised exception and returning the exit code.
    """

    def handle(exc: BaseException) -> int:
        if isinstance(exc, BrokenPipeError):
            # The reader went away; there is nobody left to print the error to.
            return int(lib_cli_exit_tools.config.broken_pipe_exit_code)
        if isinstance(exc, SystemExit):
            return int(exc.code or 0) if isinstance(exc.code, int) or exc.code is None else 1
        error = error_payload(exc)
        click.echo(dumps_json(error if bare else FailureEnvelope(command=_command_named(argv), error=error, skipped=FAILED_RUN_SKIPPED.get())))
        if isinstance(exc, click.ClickException):
            return exc.exit_code
        return lib_cli_exit_tools.get_system_exit_code(exc)

    return handle


def _restore_when_requested(*, state: TracebackState, should_restore: bool) -> None:
    """Restore the prior traceback configuration when requested.

    CLI execution may toggle verbose tracebacks for the duration of the run.
    Once the command ends this restores the previous configuration so other
    code paths continue with their expected defaults. May mutate
    ``lib_cli_exit_tools.config``.

    Args:
        state: Tuple captured by :func:`snapshot_traceback_state` describing the
            prior configuration.
        should_restore: ``True`` to reapply the stored configuration; ``False`` to
            keep the current settings.
    """
    if should_restore:
        restore_traceback_state(state)
