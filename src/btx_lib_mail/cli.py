"""CLI adapter wiring the behavior helpers into a rich-click interface.

Purpose
-------
Expose a stable command-line surface so tooling, documentation, and packaging
automation can be exercised while the richer logging helpers are being built.
By delegating to :mod:`btx_lib_mail.behaviors` the transport stays
aligned with the Clean Code rules captured in
``docs/systemdesign/module_reference.md``.

Contents
--------
* :data:`CLICK_CONTEXT_SETTINGS` – shared Click settings ensuring consistent
  ``--help`` behavior across commands.
* :func:`apply_traceback_preferences` – helper that synchronises the shared
  traceback configuration flags.
* :func:`snapshot_traceback_state` / :func:`restore_traceback_state` – utilities
  for preserving and reapplying the global traceback preference.
* :func:`cli` – root command group wiring the global options.
* :func:`cli_main` – default action when no subcommand is provided.
* :func:`cli_info`, :func:`cli_hello`, :func:`cli_fail` – subcommands covering
  metadata printing, success path, and failure path.
* :func:`_record_traceback_choice`, :func:`_announce_traceback_choice` – persist
  traceback preferences across context and shared tooling.
* :func:`_invoke_cli`, :func:`_current_traceback_mode`, :func:`_traceback_limit`,
  :func:`_print_exception`, :func:`_run_cli_via_exit_tools` – isolate the error
  handling and delegation path.
* :func:`_restore_when_requested` – restores tracebacks when ``main`` finishes.
* :func:`main` – composition helper delegating to ``lib_cli_exit_tools`` while
  honouring the shared traceback preferences.

System Role
-----------
The CLI is the primary adapter for local development workflows; packaging
targets register the console script defined in :mod:`btx_lib_mail.__init__conf__`.
Other transports (including ``python -m`` execution) reuse the same helpers so
behaviour remains consistent regardless of entry point.
"""

from __future__ import annotations

from typing import Final, Optional, Sequence, Tuple

import rich_click as click

import lib_cli_exit_tools
from click.core import ParameterSource

from . import __init__conf__
from .behaviors import emit_greeting, noop_main, raise_intentional_failure

#: Shared Click context flags so help output stays consistent across commands.
CLICK_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}  # noqa: C408
#: Character budget used when printing truncated tracebacks.
TRACEBACK_SUMMARY_LIMIT: Final[int] = 500
#: Character budget used when verbose tracebacks are enabled.
TRACEBACK_VERBOSE_LIMIT: Final[int] = 10_000
TracebackState = Tuple[bool, bool]


def apply_traceback_preferences(enabled: bool) -> None:
    """Synchronise shared traceback flags with the requested preference.

    Why
        ``lib_cli_exit_tools`` inspects global flags to decide whether tracebacks
        should be truncated and whether colour should be forced. Updating both
        attributes together ensures the ``--traceback`` flag behaves the same for
        console scripts and ``python -m`` execution.

    Parameters
    ----------
    enabled:
        ``True`` enables full tracebacks with colour. ``False`` restores the
        compact summary mode.

    Examples
    --------
    >>> apply_traceback_preferences(True)
    >>> bool(lib_cli_exit_tools.config.traceback)
    True
    >>> bool(lib_cli_exit_tools.config.traceback_force_color)
    True
    """

    lib_cli_exit_tools.config.traceback = bool(enabled)
    lib_cli_exit_tools.config.traceback_force_color = bool(enabled)


def snapshot_traceback_state() -> TracebackState:
    """Capture the current traceback configuration for later restoration.

    Returns
    -------
    TracebackState
        Tuple of ``(traceback_enabled, force_color)``.

    Examples
    --------
    >>> snapshot = snapshot_traceback_state()
    >>> isinstance(snapshot, tuple)
    True
    """

    return (
        bool(getattr(lib_cli_exit_tools.config, "traceback", False)),
        bool(getattr(lib_cli_exit_tools.config, "traceback_force_color", False)),
    )


def restore_traceback_state(state: TracebackState) -> None:
    """Reapply a previously captured traceback configuration.

    Parameters
    ----------
    state:
        Tuple returned by :func:`snapshot_traceback_state`.

    Examples
    --------
    >>> prev = snapshot_traceback_state()
    >>> apply_traceback_preferences(True)
    >>> restore_traceback_state(prev)
    >>> snapshot_traceback_state() == prev
    True
    """

    lib_cli_exit_tools.config.traceback = bool(state[0])
    lib_cli_exit_tools.config.traceback_force_color = bool(state[1])


def _record_traceback_choice(ctx: click.Context, *, enabled: bool) -> None:
    """Remember the chosen traceback mode inside the Click context.

    Why
        Downstream commands need to know whether verbose tracebacks were
        requested so they can honour the user's preference without re-parsing
        flags.

    What
        Ensures the context has a dict backing store and persists the boolean
        under the ``"traceback"`` key.

    Inputs
        ctx:
            Click context associated with the current invocation.
        enabled:
            ``True`` when verbose tracebacks were requested; ``False`` otherwise.

    Side Effects
        Mutates ``ctx.obj``.
    """

    ctx.ensure_object(dict)
    ctx.obj["traceback"] = enabled


def _announce_traceback_choice(enabled: bool) -> None:
    """Keep ``lib_cli_exit_tools`` in sync with the selected traceback mode.

    Why
        ``lib_cli_exit_tools`` reads global configuration to decide how to print
        tracebacks; we mirror the user's choice into that configuration.

    Inputs
        enabled:
            ``True`` when verbose tracebacks should be shown; ``False`` when the
            summary view is desired.

    Side Effects
        Mutates ``lib_cli_exit_tools.config``.
    """

    apply_traceback_preferences(enabled)


def _no_subcommand_requested(ctx: click.Context) -> bool:
    """Return ``True`` when the invocation did not name a subcommand.

    Why
        The CLI defaults to calling ``noop_main`` when no subcommand appears; we
        need a readable predicate to capture that intent.

    Inputs
        ctx:
            Click context describing the current CLI invocation.

    Outputs
        bool:
            ``True`` when no subcommand was invoked; ``False`` otherwise.
    """

    return ctx.invoked_subcommand is None


def _invoke_cli(argv: Optional[Sequence[str]]) -> int:
    """Ask ``lib_cli_exit_tools`` to execute the Click command.

    Why
        ``lib_cli_exit_tools`` normalises exit codes and exception handling; we
        centralise the call so tests can stub it cleanly.

    Inputs
        argv:
            Optional sequence of command-line arguments. ``None`` delegates to
            ``sys.argv`` inside ``lib_cli_exit_tools``.

    Outputs
        int:
            Exit code returned by the CLI execution.
    """

    return lib_cli_exit_tools.run_cli(
        cli,
        argv=list(argv) if argv is not None else None,
        prog_name=__init__conf__.shell_command,
    )


def _current_traceback_mode() -> bool:
    """Return the global traceback preference as a boolean.

    Why
        Error handling logic needs to know whether verbose tracebacks are active
        so it can pick the right character budget and ensure colouring is
        consistent.

    Outputs
        bool:
            ``True`` when verbose tracebacks are enabled; ``False`` otherwise.
    """

    return bool(getattr(lib_cli_exit_tools.config, "traceback", False))


def _traceback_limit(tracebacks_enabled: bool, *, summary_limit: int, verbose_limit: int) -> int:
    """Return the character budget that matches the current traceback mode.

    Why
        Verbose tracebacks should show the full story while compact ones keep the
        terminal tidy. This helper makes that decision explicit.

    Inputs
        tracebacks_enabled:
            ``True`` when verbose tracebacks are active.
        summary_limit:
            Character budget for truncated output.
        verbose_limit:
            Character budget for the full traceback.

    Outputs
        int:
            The applicable character limit.
    """

    return verbose_limit if tracebacks_enabled else summary_limit


def _print_exception(exc: BaseException, *, tracebacks_enabled: bool, length_limit: int) -> int:
    """Render the exception through ``lib_cli_exit_tools`` and return its exit code.

    Why
        All transports funnel errors through ``lib_cli_exit_tools`` so that exit
        codes and formatting stay consistent; this helper keeps the plumbing in
        one place.

    Inputs
        exc:
            Exception raised by the CLI.
        tracebacks_enabled:
            ``True`` when verbose tracebacks should be shown.
        length_limit:
            Maximum number of characters to print.

    Outputs
        int:
            Exit code to surface to the shell.

    Side Effects
        Writes the formatted exception to stderr via ``lib_cli_exit_tools``.
    """

    lib_cli_exit_tools.print_exception_message(
        trace_back=tracebacks_enabled,
        length_limit=length_limit,
    )
    return lib_cli_exit_tools.get_system_exit_code(exc)


def _traceback_option_requested(ctx: click.Context) -> bool:
    """Return ``True`` when the user explicitly requested ``--traceback``.

    Why
        Determines whether a no-command invocation should run the default
        behaviour or display the help screen.

    Inputs
        ctx:
            Click context associated with the current invocation.

    Outputs
        bool:
            ``True`` when the user provided ``--traceback`` or ``--no-traceback``;
            ``False`` when the default value is in effect.
    """

    source = ctx.get_parameter_source("traceback")
    return source not in (ParameterSource.DEFAULT, None)


def _show_help(ctx: click.Context) -> None:
    """Render the command help to stdout."""

    click.echo(ctx.get_help())


def _run_cli_via_exit_tools(
    argv: Optional[Sequence[str]],
    *,
    summary_limit: int,
    verbose_limit: int,
) -> int:
    """Run the command while narrating the failure path with care.

    Why
        Consolidates the call to ``lib_cli_exit_tools`` so happy paths and error
        handling remain consistent across the application and tests.

    Inputs
        argv:
            Optional sequence of CLI arguments.
        summary_limit / verbose_limit:
            Character budgets steering exception output length.

    Outputs
        int:
            Exit code produced by the command.

    Side Effects
        Delegates to ``lib_cli_exit_tools`` which may write to stderr.
    """

    try:
        return _invoke_cli(argv)
    except BaseException as exc:  # noqa: BLE001 - handled by shared printers
        tracebacks_enabled = _current_traceback_mode()
        apply_traceback_preferences(tracebacks_enabled)
        return _print_exception(
            exc,
            tracebacks_enabled=tracebacks_enabled,
            length_limit=_traceback_limit(
                tracebacks_enabled,
                summary_limit=summary_limit,
                verbose_limit=verbose_limit,
            ),
        )


@click.group(
    help=__init__conf__.title,
    context_settings=CLICK_CONTEXT_SETTINGS,
    invoke_without_command=True,
)
@click.version_option(
    version=__init__conf__.version,
    prog_name=__init__conf__.shell_command,
    message=f"{__init__conf__.shell_command} version {__init__conf__.version}",
)
@click.option(
    "--traceback/--no-traceback",
    is_flag=True,
    default=False,
    help="Show full Python traceback on errors",
)
@click.pass_context
def cli(ctx: click.Context, traceback: bool) -> None:
    """Root command storing global flags and syncing shared traceback state.

    Why
        The CLI must provide a switch for verbose tracebacks so developers can
        toggle diagnostic depth without editing configuration files.

    What
        Ensures a dict-based context, stores the ``traceback`` flag, and mirrors
        the value into ``lib_cli_exit_tools.config`` so downstream helpers observe
        the preference. When no subcommand (or options) are provided, the command
        prints help instead of running the domain stub; otherwise the default
        action delegates to :func:`cli_main`.

    Side Effects
        Mutates :mod:`lib_cli_exit_tools.config` to reflect the requested
        traceback mode, including ``traceback_force_color`` when tracebacks are
        enabled.

    Examples
    --------
    >>> from click.testing import CliRunner
    >>> runner = CliRunner()
    >>> result = runner.invoke(cli, ["hello"])
    >>> result.exit_code
    0
    >>> "Hello World" in result.output
    True
    """

    _record_traceback_choice(ctx, enabled=traceback)
    _announce_traceback_choice(traceback)
    if _no_subcommand_requested(ctx):
        if _traceback_option_requested(ctx):
            cli_main()
        else:
            _show_help(ctx)


def cli_main() -> None:
    """Run the placeholder domain entry when callers opt into execution.

    Why
        Maintains compatibility with tooling that expects the original
        "do-nothing" behaviour by explicitly opting in via options (e.g.
        ``--traceback`` without subcommands).

    Side Effects
        Delegates to :func:`noop_main`.

    Examples
    --------
    >>> cli_main()
    """

    noop_main()


@cli.command("info", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_info() -> None:
    """Print resolved metadata so users can inspect installation details."""

    __init__conf__.print_info()


@cli.command("hello", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_hello() -> None:
    """Demonstrate the success path by emitting the canonical greeting."""

    emit_greeting()


@cli.command("fail", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_fail() -> None:
    """Trigger the intentional failure helper to test error handling."""

    raise_intentional_failure()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    restore_traceback: bool = True,
    summary_limit: int = TRACEBACK_SUMMARY_LIMIT,
    verbose_limit: int = TRACEBACK_VERBOSE_LIMIT,
) -> int:
    """Execute the CLI with deliberate error handling and return the exit code.

    Why
        Provides the single entry point used by console scripts and
        ``python -m`` execution so that behaviour stays identical across
        transports.

    Inputs
        argv:
            Optional sequence of CLI arguments. ``None`` lets Click consume
            ``sys.argv`` directly.
        restore_traceback:
            ``True`` to restore the prior ``lib_cli_exit_tools`` traceback
            configuration after execution.
        summary_limit / verbose_limit:
            Character budgets used when formatting exceptions.

    Outputs
        int:
            Exit code reported by the CLI run.

    Side Effects
        Mutates the global traceback configuration while the CLI runs.
    """

    previous_state = snapshot_traceback_state()
    try:
        return _run_cli_via_exit_tools(
            argv,
            summary_limit=summary_limit,
            verbose_limit=verbose_limit,
        )
    finally:
        _restore_when_requested(previous_state, restore_traceback)


def _restore_when_requested(state: TracebackState, should_restore: bool) -> None:
    """Restore the prior traceback configuration when requested.

    Why
        CLI execution may toggle verbose tracebacks for the duration of the run.
        Once the command ends we restore the previous configuration so other
        code paths continue with their expected defaults.

    Inputs
        state:
            Tuple captured by :func:`snapshot_traceback_state` describing the
            prior configuration.
        should_restore:
            ``True`` to reapply the stored configuration; ``False`` to keep the
            current settings.

    Side Effects
        May mutate ``lib_cli_exit_tools.config``.
    """

    if should_restore:
        restore_traceback_state(state)
