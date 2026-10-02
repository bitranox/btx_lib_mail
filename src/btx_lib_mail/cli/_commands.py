"""The `cli` group, its global options, and the small subcommands (`info`, `hello`, `validate-*`, `fail`).

Private to btx_lib_mail.cli: import the public names from `btx_lib_mail.cli`.
"""

from __future__ import annotations

import rich_click as click
from click.core import ParameterSource

from .. import __init__conf__
from ..behaviors import CANONICAL_GREETING, emit_greeting, noop_main, raise_intentional_failure
from ..lib_mail import validate_email_address, validate_smtp_host
from ..typed_click import argument, option, version_option
from ._output import CliContext, cli_context, emit
from ._traceback import apply_traceback_preferences

__all__ = ["CLICK_CONTEXT_SETTINGS", "cli", "cli_fail", "cli_hello", "cli_info", "cli_main", "cli_validate_email", "cli_validate_smtp_host"]


#: Shared Click context flags so help output stays consistent across commands.
CLICK_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}
"""Click context settings ensuring every command honours `-h/--help`."""


def _record_context(ctx: click.Context, *, traceback: bool, json_output: bool, json_bare: bool) -> None:
    """Store the group's options in the typed ``ctx.obj``, keeping a transport an embedding caller put there.

    Downstream commands read the output mode and traceback choice without
    re-parsing flags, and the transport seam must survive the group callback.

    Args:
        ctx: Click context whose ``ctx.obj`` is replaced.
        traceback: ``True`` when verbose tracebacks were requested.
        json_output: ``True`` to print the JSON envelope.
        json_bare: ``True`` to print the JSON payload alone.
    """
    previous = ctx.obj if isinstance(ctx.obj, CliContext) else CliContext()
    ctx.obj = CliContext(traceback=traceback, json_output=json_output, json_bare=json_bare, transport=previous.transport)


def _announce_traceback_choice(*, enabled: bool) -> None:
    """Keep ``lib_cli_exit_tools`` in sync with the selected traceback mode.

    ``lib_cli_exit_tools`` reads global configuration to decide how to print
    tracebacks; this mirrors the user's choice into that configuration.

    Args:
        enabled: ``True`` when verbose tracebacks should be shown; ``False`` when the
            summary view is desired.
    """
    apply_traceback_preferences(enabled)


def _no_subcommand_requested(ctx: click.Context) -> bool:
    """Return ``True`` when the invocation did not name a subcommand.

    The CLI defaults to calling ``noop_main`` when no subcommand appears; this
    gives a readable predicate to capture that intent.

    Args:
        ctx: Click context describing the current CLI invocation.

    Returns:
        ``True`` when no subcommand was invoked; ``False`` otherwise.
    """
    return ctx.invoked_subcommand is None


def _traceback_option_requested(ctx: click.Context) -> bool:
    """Return ``True`` when the user explicitly requested ``--traceback``.

    Determines whether a no-command invocation should run the default
    behaviour or display the help screen.

    Args:
        ctx: Click context associated with the current invocation.

    Returns:
        ``True`` when the user provided ``--traceback`` or ``--no-traceback``;
        ``False`` when the default value is in effect.
    """
    source = ctx.get_parameter_source("traceback")
    return source not in (ParameterSource.DEFAULT, None)


def _show_help(ctx: click.Context) -> None:
    """Render the command help to stdout."""
    click.echo(ctx.get_help())


@click.group(
    help=__init__conf__.title,
    context_settings=CLICK_CONTEXT_SETTINGS,
    invoke_without_command=True,
)
@version_option(
    version=__init__conf__.version,
    prog_name=__init__conf__.shell_command,
    message=f"{__init__conf__.shell_command} version {__init__conf__.version}",
)
@option(
    "--traceback/--no-traceback",
    is_flag=True,
    default=False,
    help="Show full Python traceback on errors",
)
@option("--json", "-j", "json_output", is_flag=True, default=False, help="Print a JSON envelope: {ok, command, data|error, skipped}.")
@option("--json-bare", "json_bare", is_flag=True, default=False, help="Print the JSON payload (or error) alone, without the envelope.")
@click.pass_context
def cli(ctx: click.Context, *, traceback: bool, json_output: bool, json_bare: bool) -> None:
    r"""Register the global CLI options and dispatch to subcommands.

    Registers `--traceback`, `--json`, `--json-bare` and ensures `lib_cli_exit_tools` reflects the
    caller's preference before dispatching to subcommands.

    Stores a `CliContext` in `ctx.obj` (keeping a transport an embedding caller put there) and
    mirrors the traceback choice into `lib_cli_exit_tools.config`. When invoked without a
    subcommand and without explicitly setting the traceback flag, the command prints help instead
    of executing the placeholder domain entry.

    Args:
        ctx: Click context initialised by Click.
        traceback: `True` to enable verbose tracebacks.
        json_output: `True` to print the JSON envelope.
        json_bare: `True` to print the JSON payload alone.

    Examples:
        >>> from click.testing import CliRunner
        >>> runner = CliRunner()
        >>> runner.invoke(cli, ["hello"]).exit_code
        0
        >>> runner.invoke(cli, ["--json", "hello"]).output
        '{"ok": true, "command": "hello", "data": {"greeting": "Hello World"}, "skipped": []}\n'
    """
    if json_output and json_bare:
        raise click.UsageError("--json and --json-bare are mutually exclusive; pick one output shape")
    _record_context(ctx, traceback=traceback, json_output=json_output, json_bare=json_bare)
    _announce_traceback_choice(enabled=traceback)
    if _no_subcommand_requested(ctx):
        if _traceback_option_requested(ctx):
            cli_main()
        else:
            _show_help(ctx)


def cli_main() -> None:
    """Run the placeholder domain action.

    Preserves the scaffold behaviour where the CLI performs the placeholder domain action when
    users opt into execution (e.g. `--traceback` without subcommands). Delegates to `noop_main()`.

    Examples:
        >>> cli_main()  # returns None
    """
    noop_main()


@cli.command("info", context_settings=CLICK_CONTEXT_SETTINGS, help="Show the package name, version, homepage and author.")
@click.pass_context
def cli_info(ctx: click.Context) -> None:
    """Surface the package metadata so operators can confirm version, homepage, and authorship information.

    Writes metadata to standard output.

    Args:
        ctx: Click context carrying the output mode.
    """
    if not cli_context(ctx).machine_readable:
        __init__conf__.print_info()
        return
    data = {
        "name": __init__conf__.name,
        "title": __init__conf__.title,
        "version": __init__conf__.version,
        "homepage": __init__conf__.homepage,
        "author": __init__conf__.author,
        "author_email": __init__conf__.author_email,
        "shell_command": __init__conf__.shell_command,
    }
    emit(ctx, "info", data, "")


@cli.command("hello", context_settings=CLICK_CONTEXT_SETTINGS, help="Print the greeting (a smoke test of the CLI).")
@click.pass_context
def cli_hello(ctx: click.Context) -> None:
    """Demonstrate the happy-path behaviour by emitting the canonical greeting used throughout the scaffold.

    Writes `Hello World` plus a newline to standard output.

    Args:
        ctx: Click context carrying the output mode.
    """
    if not cli_context(ctx).machine_readable:
        emit_greeting()
        return
    emit(ctx, "hello", {"greeting": CANONICAL_GREETING}, "")


@cli.command("validate-email", context_settings=CLICK_CONTEXT_SETTINGS, help="Check that ADDRESS is a syntactically valid email address.")
@argument("address")
@click.pass_context
def cli_validate_email(ctx: click.Context, address: str) -> None:
    """Validate that address is a syntactically correct email address.

    Exits successfully when the address is valid; raises when invalid. Reports the valid address
    on success.

    Args:
        ctx: Click context carrying the output mode.
        address: Email address to validate.
    """
    validate_email_address(address)
    emit(ctx, "validate-email", {"address": address, "valid": True}, f"Valid email address: {address}")


@cli.command("validate-smtp-host", context_settings=CLICK_CONTEXT_SETTINGS, help="Check that HOST is a valid host[:port] or [IPv6][:port].")
@argument("host")
@click.pass_context
def cli_validate_smtp_host(ctx: click.Context, host: str) -> None:
    """Validate that host is a syntactically correct SMTP host string, including IPv6 bracketed addresses.

    Exits successfully when valid; raises when invalid. Reports the valid host on success.

    Args:
        ctx: Click context carrying the output mode.
        host: SMTP host string to validate.
    """
    validate_smtp_host(host)
    emit(ctx, "validate-smtp-host", {"host": host, "valid": True}, f"Valid SMTP host: {host}")


@cli.command("fail", context_settings=CLICK_CONTEXT_SETTINGS, help="Raise an intentional error (to check traceback and exit-code handling).")
def cli_fail() -> None:
    """Trigger the intentional failure helper so developers can verify traceback and exit-code handling.

    This command never returns; it raises instead.

    Raises:
        RuntimeError: Propagated from `raise_intentional_failure()`.
    """
    raise_intentional_failure()
