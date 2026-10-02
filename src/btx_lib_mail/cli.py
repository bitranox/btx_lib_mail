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

**Output modes:** human-readable by default. `--json`/`-j` (on the group, so
it composes with every subcommand) prints one envelope
`{"ok", "command", "data", "skipped"}` on success and
`{"ok": false, "command", "error": {"type", "message"}, "skipped"}` on failure;
`--json-bare` prints the `data` (or the `error`) alone. Warnings stay on
stderr in every mode. Exit codes do not depend on the output mode.

**System Role:** Documented in
`docs/systemdesign/module_reference.md#feature-cli-components`; this module is
the primary adapter, ensuring every transport shares the same traceback and
delivery semantics.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Final, TypeVar

import lib_cli_exit_tools
import rich_click as click
from click.core import ParameterSource
from pydantic import SecretStr, ValidationError

from . import __init__conf__
from .behaviors import CANONICAL_GREETING, emit_greeting, noop_main, raise_intentional_failure
from .errors import InvalidInputError
from .lib_mail import ConfMail, Transport, conf, send, validate_email_address, validate_smtp_host
from .lib_mail import logger as mail_logger
from .typed_click import argument, option, version_option

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
_T = TypeVar("_T")

# An --env-file is a handful of KEY=value lines; anything larger is not one, and is
# refused before it is read rather than parsed into memory.
_ENV_FILE_MAX_BYTES: Final[int] = 64 * 1024
# A password file holds one line; more than this is not a password file.
_PASSWORD_FILE_MAX_CHARS: Final[int] = 4096


# ---------------------------------------------------------------------------
# Where unset options come from: the environment, then an explicit --env-file
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Sources:
    """The values a command may read for an option it was not given.

    The process environment wins over the ``--env-file``; a key set to an empty
    string in either counts as unset. No file is read unless it was named, so a
    ``.env`` that happens to sit in the working directory (a cloned repository,
    a shared folder) cannot redirect delivery or relax a security setting.
    """

    environ: Mapping[str, str]
    env_file: Mapping[str, str] = field(default_factory=lambda: {})

    def value(self, key: str) -> str | None:
        env_value = self.environ.get(key)
        if env_value not in (None, ""):
            return env_value
        return self.env_file.get(key) or None


def _read_env_file(path: Path | None) -> dict[str, str]:
    """Parse the named env file once into ``KEY -> value`` (first occurrence wins).

    Lines are ``KEY=value``; blank lines, ``#`` comments and lines without ``=``
    are skipped; a value is stripped of whitespace and one layer of quotes.

    Raises
    ------
    click.BadParameter
        The file is larger than ``_ENV_FILE_MAX_BYTES`` or not UTF-8.
    """
    if path is None:
        return {}
    size = path.stat().st_size
    if size > _ENV_FILE_MAX_BYTES:
        raise click.BadParameter(f"{path} is {size} bytes; an env file may be at most {_ENV_FILE_MAX_BYTES} bytes", param_hint="--env-file")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise click.BadParameter(f"{path} is not UTF-8 text", param_hint="--env-file") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        values.setdefault(key.strip(), _unquoted(raw_value))
    return values


def _split_values(values: Sequence[str]) -> list[str]:
    flattened: list[str] = []
    for raw in values:
        for item in raw.split(","):
            candidate = item.strip()
            if candidate:
                flattened.append(candidate)
    return flattened


def _resolve_list(cli_values: Sequence[str], env_key: str, *, label: str, sources: _Sources) -> list[str]:
    values = _split_values(cli_values)
    if not values:
        env_raw = sources.value(env_key)
        if env_raw:
            values = _split_values([env_raw])
    if not values:
        raise click.UsageError(f"Provide at least one {label} via options or {env_key}.")
    return values


def _parse_bool(env_raw: str | None, env_key: str) -> bool | None:
    """Return the boolean *env_raw* spells, or ``None`` when it is unset or blank.

    A blank value is "not set": reading it as False would let a stray space switch
    STARTTLS or certificate checks off, while an unset variable keeps them on.
    """
    if env_raw is None or env_raw.strip() == "":
        return None
    lowered = env_raw.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise click.BadParameter(f"Unrecognised boolean value for {env_key}: {env_raw!r}")


def _resolve_bool(*, cli_flag: bool | None, env_key: str, default: bool, sources: _Sources) -> bool:
    if cli_flag is not None:
        return cli_flag
    return _or_default(_parse_bool(sources.value(env_key), env_key), default)


def _resolve_optional_bool(*, cli_flag: bool | None, env_key: str, sources: _Sources) -> bool | None:
    """Return the bool value provided via CLI, the sources, or None for the config's own value."""
    if cli_flag is not None:
        return cli_flag
    return _parse_bool(sources.value(env_key), env_key)


def _or_default(value: _T | None, default: _T) -> _T:
    """Return *value*, or *default* when it is ``None`` (a falsy ``0`` is kept, so the model can refuse it)."""
    return default if value is None else value


def _refusal_message(error: ValidationError) -> str:
    """Return the validators' own reasons, one line each.

    Every ``ConfMail`` validator names its field in its message, so the text is
    the one ``send()`` raised for the same value. pydantic's own report adds its
    error-type tags and a versioned URL, which describe the library rather than
    the operator's input; ``--traceback`` still shows it through the chain.
    """
    return "\n".join(detail["msg"].removeprefix("Value error, ") for detail in error.errors())


@contextmanager
def _refusals_as_value_error() -> Generator[None, None, None]:
    """Raise a setting the model refuses as an ``InvalidInputError``, a ``ValueError`` (exit code 22)."""
    try:
        yield
    except ValidationError as exc:
        raise InvalidInputError(_refusal_message(exc)) from exc


def _unquoted(value: str) -> str:
    """Strip whitespace and one layer of surrounding quotes, as env-file values and hosts are read."""
    return value.strip().strip('"').strip("'")


def _checked_hosts(values: Sequence[str]) -> list[str]:
    """Return *values* unquoted, refusing a malformed one with ``validate_smtp_host``'s own message.

    ``ConfMail`` runs the same check, but its refusal hides the host (the field
    may carry a credential); checking first keeps the message quoting the host
    that the operator typed.
    """
    hosts = [_unquoted(value) for value in values]
    for host in hosts:
        if host:
            validate_smtp_host(host)
    return hosts


def _resolve_credentials(user: str | None, password: str | None) -> tuple[str, str] | None:
    if user and password:
        return user, password
    return None


def _read_password_file(handle: IO[str] | None) -> str | None:
    """Return the first line of the ``--password-file`` (``-`` reads stdin), without its line break."""
    if handle is None:
        return None
    content = handle.read(_PASSWORD_FILE_MAX_CHARS + 1)
    if len(content) > _PASSWORD_FILE_MAX_CHARS:
        raise click.BadParameter(f"a password file holds one line of at most {_PASSWORD_FILE_MAX_CHARS} characters", param_hint="--password-file")
    lines = content.splitlines()
    return lines[0] if lines else None


def _resolve_password(*, password: str | None, password_file: IO[str] | None, sources: _Sources) -> str | None:
    if password is not None and password_file is not None:
        raise click.UsageError(
            "--password and --password-file are mutually exclusive; prefer --password-file, which keeps the password out of the process list"
        )
    return password or _read_password_file(password_file) or sources.value("BTX_MAIL_SMTP_PASSWORD")


def _resolve_float(cli_value: float | None, env_key: str, *, sources: _Sources) -> float | None:
    """Return the float given on the CLI or in the sources, or ``None`` when neither set it.

    Raises :class:`click.BadParameter` when the source value is not a number.
    """
    if cli_value is not None:
        return cli_value
    env_raw = sources.value(env_key)
    if env_raw is None or env_raw.strip() == "":
        return None
    try:
        return float(env_raw.strip())
    except ValueError as exc:
        raise click.BadParameter(f"Unrecognised float value for {env_key}: {env_raw!r}") from exc


def _resolve_int(cli_value: int | None, env_key: str, *, sources: _Sources) -> int | None:
    """Return the int given on the CLI or in the sources, or ``None`` when neither set it.

    Raises :class:`click.BadParameter` when the source value is not an integer.
    """
    if cli_value is not None:
        return cli_value
    env_raw = sources.value(env_key)
    if env_raw is None or env_raw.strip() == "":
        return None
    try:
        return int(env_raw.strip())
    except ValueError as exc:
        raise click.BadParameter(f"Unrecognised int value for {env_key}: {env_raw!r}") from exc


def _resolve_extensions(cli_value: str | None, env_key: str, *, sources: _Sources) -> frozenset[str] | None:
    """Resolve a comma-separated extension list (lower-cased, dot-prefixed), or None for the config's own value."""
    raw = cli_value or sources.value(env_key)
    if raw is None or raw.strip() == "":
        return None

    extensions: set[str] = set()
    for raw_ext in raw.split(","):
        ext = raw_ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        extensions.add(ext)

    return frozenset(extensions) if extensions else None


def _resolve_directories(cli_values: Sequence[str], env_key: str, *, sources: _Sources) -> frozenset[Path] | None:
    """Resolve repeated or comma-separated directories, or None for the config's own value."""
    flattened = _split_values(cli_values)

    if not flattened:
        env_raw = sources.value(env_key)
        if env_raw:
            flattened = _split_values([env_raw])

    directories = {Path(raw_dir.strip()) for raw_dir in flattened if raw_dir.strip()}
    return frozenset(directories) if directories else None


# ---------------------------------------------------------------------------
# Output: one place decides human text or JSON, for success and failure alike
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CliContext:
    """### CliContext {#cli-clicontext}

    **Purpose:** The typed `ctx.obj` every command reads.

    **Fields:**
    - `traceback: bool` - Verbose tracebacks were requested.
    - `json_output: bool` - Print the JSON envelope.
    - `json_bare: bool` - Print the JSON payload without the envelope.
    - `transport: Transport | None` - Delivery adapter `send` hands to the
      library; `None` uses the SMTP transport. An application embedding the
      CLI, or a test, passes its own through `cli.main(obj=CliContext(transport=...))`
      or `CliRunner.invoke(cli, args, obj=...)`.
    """

    traceback: bool = False
    json_output: bool = False
    json_bare: bool = False
    transport: Transport | None = None

    @property
    def machine_readable(self) -> bool:
        return self.json_output or self.json_bare


def _context(ctx: click.Context) -> CliContext:
    """Return the typed context object, creating it when a command runs on its own."""
    if not isinstance(ctx.obj, CliContext):
        ctx.obj = CliContext()
    return ctx.obj


def _dumps(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False)


def _emit(ctx: click.Context, command: str, data: Mapping[str, Any], human: str, *, skipped: Sequence[Mapping[str, str]] = ()) -> None:
    """Print one command's result in the output mode the group was given."""
    state = _context(ctx)
    if state.json_bare:
        click.echo(_dumps(dict(data)))
    elif state.json_output:
        click.echo(_dumps({"ok": True, "command": command, "data": dict(data), "skipped": [dict(item) for item in skipped]}))
    else:
        click.echo(human)


def _error_payload(exc: BaseException) -> dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}


class _SkipCollector(logging.Filter):
    """Collect the library's "skipped" warnings while passing every record on unchanged.

    A filter on the library logger, not a handler: adding a handler would stop the
    warnings reaching stderr through logging's last-resort handler.
    """

    def __init__(self) -> None:
        super().__init__()
        self.skipped: list[dict[str, str]] = []

    def filter(self, record: logging.LogRecord) -> bool:
        kind = record.__dict__.get("skipped")
        if isinstance(kind, str):
            value = record.__dict__.get("attachment_path") or record.__dict__.get("recipient") or ""
            self.skipped.append({"kind": kind, "value": str(value), "reason": record.getMessage()})
        return True


@contextmanager
def _collect_skipped() -> Generator[_SkipCollector, None, None]:
    collector = _SkipCollector()
    mail_logger.addFilter(collector)
    try:
        yield collector
    finally:
        mail_logger.removeFilter(collector)


#: Shared Click context flags so help output stays consistent across commands.
CLICK_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}
"""Click context settings ensuring every command honours `-h/--help`."""
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


def _record_context(ctx: click.Context, *, traceback: bool, json_output: bool, json_bare: bool) -> None:
    """Store the group's options in the typed ``ctx.obj``, keeping a transport an embedding caller put there.

    Why
        Downstream commands read the output mode and traceback choice without
        re-parsing flags, and the transport seam must survive the group callback.

    Side Effects
        Replaces ``ctx.obj``.
    """

    previous = ctx.obj if isinstance(ctx.obj, CliContext) else CliContext()
    ctx.obj = CliContext(traceback=traceback, json_output=json_output, json_bare=json_bare, transport=previous.transport)


def _announce_traceback_choice(*, enabled: bool) -> None:
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


def _invoke_cli(argv: Sequence[str] | None) -> int:
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

    Why
        Error handling logic needs to know whether verbose tracebacks are active
        so it can pick the right character budget and ensure colouring is
        consistent.

    Outputs
        bool:
            ``True`` when verbose tracebacks are enabled; ``False`` otherwise.
    """

    return bool(getattr(lib_cli_exit_tools.config, "traceback", False))


def _traceback_limit(*, tracebacks_enabled: bool, summary_limit: int, verbose_limit: int) -> int:
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
    argv: Sequence[str] | None,
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
    """### cli(traceback: bool = False, json_output: bool = False, json_bare: bool = False) -> None {#cli-root}

    **Purpose:** Register global CLI options (`--traceback`, `--json`,
    `--json-bare`) and ensure `lib_cli_exit_tools` reflects the caller's
    preference before dispatching to subcommands.

    **Parameters:**
    - `ctx: click.Context` - Click context initialised by Click.
    - `traceback: bool = False` - `True` to enable verbose tracebacks.
    - `json_output: bool = False` - `True` to print the JSON envelope.
    - `json_bare: bool = False` - `True` to print the JSON payload alone.

    **Returns:** `None`.

    **Side Effects:** Stores a `CliContext` in `ctx.obj` (keeping a transport
    an embedding caller put there) and mirrors the traceback choice into
    `lib_cli_exit_tools.config`. When invoked without a subcommand and without
    explicitly setting the traceback flag, the command prints help instead of
    executing the placeholder domain entry.

    **Example:**
    >>> from click.testing import CliRunner
    >>> runner = CliRunner()
    >>> runner.invoke(cli, ["hello"]).exit_code
    0
    >>> runner.invoke(cli, ["--json", "hello"]).output
    '{"ok": true, "command": "hello", "data": {"greeting": "Hello World"}, "skipped": []}\\n'
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
    """### cli_main() -> None {#cli-main}

    **Purpose:** Preserve the scaffold behaviour where the CLI performs the
    placeholder domain action when users opt into execution (e.g. `--traceback`
    without subcommands).

    **Returns:** `None`.

    **Side Effects:** Delegates to `noop_main()`.

    **Example:**
    >>> cli_main()  # returns None
    """

    noop_main()


@cli.command("info", context_settings=CLICK_CONTEXT_SETTINGS)
@click.pass_context
def cli_info(ctx: click.Context) -> None:
    """### cli_info() -> None {#cli-info}

    **Purpose:** Surface the package metadata so operators can confirm version,
    homepage, and authorship information.

    **Returns:** `None`.

    **Side Effects:** Writes metadata to standard output.
    """

    if not _context(ctx).machine_readable:
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
    _emit(ctx, "info", data, "")


@cli.command("hello", context_settings=CLICK_CONTEXT_SETTINGS)
@click.pass_context
def cli_hello(ctx: click.Context) -> None:
    """### cli_hello() -> None {#cli-hello}

    **Purpose:** Demonstrate the happy-path behaviour by emitting the canonical
    greeting used throughout the scaffold.

    **Returns:** `None`.

    **Side Effects:** Writes `Hello World` plus newline to standard output.
    """

    if not _context(ctx).machine_readable:
        emit_greeting()
        return
    _emit(ctx, "hello", {"greeting": CANONICAL_GREETING}, "")


@cli.command("send", context_settings=CLICK_CONTEXT_SETTINGS)
@option(
    "--host",
    "hosts",
    multiple=True,
    help="SMTP host to use (repeat or provide comma-separated values).",
    metavar="HOST",
)
@option(
    "--recipient",
    "recipients",
    multiple=True,
    help="Recipient email address (repeat or provide comma-separated values).",
    metavar="EMAIL",
)
@option("--sender", help="Envelope sender address.")
@option("--subject", required=True, help="Mail subject line.")
@option("--body", required=True, help="Plain-text email body.")
@option("--html-body", help="Optional HTML body content.")
@option(
    "--attachment",
    "attachments",
    type=click.Path(path_type=Path),
    multiple=True,
    help="Attachment file path (repeat for multiple files).",
)
@option(
    "--env-file",
    "env_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="BTX_MAIL_ENV_FILE",
    default=None,
    help="Read unset BTX_MAIL_* settings from this KEY=value file (also BTX_MAIL_ENV_FILE). No file is read unless named.",
)
@option(
    "--starttls/--no-starttls",
    "starttls",
    default=None,
    help="Force STARTTLS negotiation (overrides environment).",
)
@option(
    "--starttls-verify/--no-starttls-verify",
    "starttls_verify",
    default=None,
    help="Verify the server certificate during STARTTLS (default: verify). Use --no-starttls-verify for internal self-signed relays.",
)
@option("--username", help="SMTP username.")
@option("--password", help="SMTP password. Visible in the process list; prefer --password-file or BTX_MAIL_SMTP_PASSWORD.")
@option(
    "--password-file",
    "password_file",
    type=click.File("r", encoding="utf-8"),
    default=None,
    help="Read the SMTP password from the first line of this file ('-' reads stdin).",
)
@option(
    "--timeout",
    type=float,
    default=None,
    help="Socket timeout in seconds (overrides environment).",
)
@option(
    "--delivery-deadline",
    "delivery_deadline",
    type=float,
    default=None,
    help="Upper bound in seconds for one SMTP session, which the socket timeout cannot give (default: none).",
    metavar="SECONDS",
)
@option(
    "--local-hostname",
    "local_hostname",
    default=None,
    help="Name announced in EHLO (default: this host's name, looked up once). Set it where reverse DNS is slow.",
    metavar="NAME",
)
# Attachment security options
@option(
    "--attachment-allowed-ext",
    "attachment_allowed_ext",
    default=None,
    help="Allowed extensions (comma-separated, e.g., .pdf,.txt). Enables whitelist mode.",
)
@option(
    "--attachment-blocked-ext",
    "attachment_blocked_ext",
    default=None,
    help="Blocked extensions (comma-separated). Overrides default dangerous extensions.",
)
@option(
    "--attachment-allowed-dir",
    "attachment_allowed_dirs",
    multiple=True,
    help="Allowed directories (repeat for multiple). Enables whitelist mode.",
)
@option(
    "--attachment-blocked-dir",
    "attachment_blocked_dirs",
    multiple=True,
    help="Blocked directories (repeat for multiple). Overrides default sensitive directories.",
)
@option(
    "--attachment-max-size",
    "attachment_max_size",
    type=int,
    default=None,
    help="Max attachment size in bytes (default: 25 MiB).",
)
@option(
    "--attachment-allow-symlinks/--attachment-no-symlinks",
    "attachment_allow_symlinks",
    default=None,
    help="Allow or reject symlinked attachments (default: reject).",
)
@option(
    "--attachment-strict/--attachment-warn",
    "attachment_raise_on_security",
    default=None,
    help="Raise on security violation (strict) or log warning and skip (warn).",
)
@click.pass_context
def cli_send_mail(  # noqa: PLR0913 - Click command surface; one option per setting, all keyword-only
    ctx: click.Context,
    *,
    hosts: Sequence[str],
    recipients: Sequence[str],
    sender: str | None,
    subject: str,
    body: str,
    html_body: str | None,
    attachments: Sequence[Path],
    env_file: Path | None,
    starttls: bool | None,
    starttls_verify: bool | None,
    username: str | None,
    password: str | None,
    password_file: IO[str] | None,
    timeout: float | None,
    delivery_deadline: float | None,
    local_hostname: str | None,
    attachment_allowed_ext: str | None,
    attachment_blocked_ext: str | None,
    attachment_allowed_dirs: Sequence[str],
    attachment_blocked_dirs: Sequence[str],
    attachment_max_size: int | None,
    attachment_allow_symlinks: bool | None,
    attachment_raise_on_security: bool | None,
) -> None:
    """### cli_send_mail(...) -> None {#cli-send-mail}

    **Purpose:** Provide a convenient SMTP smoke test that resolves CLI options,
    the environment and an optional `--env-file` into one validated `ConfMail`
    (a copy of the global `conf`, so settings without an option keep their
    value) and hands it to `btx_lib_mail.lib_mail.send` as `config=`. A value the
    model refuses is raised as `InvalidInputError` before any delivery.

    **Parameters:**
    - `hosts: Sequence[str]` - One or more `host[:port]` entries; defaults to
      `BTX_MAIL_SMTP_HOSTS` when omitted.
    - `recipients: Sequence[str]` - Recipient addresses; defaults to
      `BTX_MAIL_RECIPIENTS`.
    - `sender: str | None` - Optional envelope sender. Falls back to
      `BTX_MAIL_SENDER` or the first recipient.
    - `subject: str` - Required subject line.
    - `body: str` - Required plain-text body.
    - `html_body: str | None` - Optional HTML body.
    - `attachments: Sequence[Path]` - Zero or more filesystem paths to attach.
    - `env_file: Path | None` - `KEY=value` file read for settings neither an
      option nor the environment gave; also `BTX_MAIL_ENV_FILE`. No file is
      read unless it is named.
    - `starttls: bool | None` - Override for STARTTLS preference. When `None`,
      falls back to the sources, then `conf`.
    - `starttls_verify: bool | None` - Override for STARTTLS certificate
      verification. When `None`, falls back to `BTX_MAIL_SMTP_STARTTLS_VERIFY`
      or `conf.smtp_starttls_verify`. `--no-starttls-verify` keeps encryption
      but skips certificate validation for internal self-signed relays.
    - `username: str | None`, `password: str | None`, `password_file` -
      Optional credentials; both a username and a password are required to
      authenticate. `--password` and `--password-file` exclude each other.
    - `timeout: float | None` - Optional socket timeout override in seconds.
    - `delivery_deadline: float | None` - Optional bound in seconds for one
      SMTP session; also `BTX_MAIL_SMTP_DELIVERY_DEADLINE`.
    - `local_hostname: str | None` - Name announced in EHLO. Falls back to
      `BTX_MAIL_SMTP_LOCAL_HOSTNAME`, then `conf.smtp_local_hostname`.

    **Returns:** `None`.

    **Side Effects:** Calls `send()` and reports the result on standard output
    (a summary line, or the JSON envelope with the recipients, hosts and the
    attachments and recipients skipped in warn mode). Exceptions from `send()`
    propagate to the shared error handlers.
    """

    sources = _Sources(environ=os.environ, env_file=_read_env_file(env_file))
    requested_hosts = _resolve_list(hosts, "BTX_MAIL_SMTP_HOSTS", label="SMTP host", sources=sources)
    resolved_recipients = _resolve_list(recipients, "BTX_MAIL_RECIPIENTS", label="recipient", sources=sources)
    sender_value = sender or sources.value("BTX_MAIL_SENDER") or resolved_recipients[0]

    # One validated ConfMail is the boundary: every assignment below runs the
    # model's validators, and the copy keeps the global conf untouched while
    # carrying the settings this command has no option for.
    settings = conf.model_copy(deep=True)
    with _refusals_as_value_error():
        settings.smtphosts = _checked_hosts(requested_hosts)
        credentials = _resolve_credentials(
            username or sources.value("BTX_MAIL_SMTP_USERNAME"),
            _resolve_password(password=password, password_file=password_file, sources=sources),
        )
        if credentials is not None:
            user, secret = credentials
            settings.smtp_username, settings.smtp_password = user, SecretStr(secret)
        _apply_connection_settings(
            settings,
            _ConnectionOptions(
                starttls=starttls, starttls_verify=starttls_verify, timeout=timeout, delivery_deadline=delivery_deadline, local_hostname=local_hostname
            ),
            sources,
        )
        _apply_attachment_settings(
            settings,
            _AttachmentOptions(
                allowed_ext=attachment_allowed_ext,
                blocked_ext=attachment_blocked_ext,
                allowed_dirs=attachment_allowed_dirs,
                blocked_dirs=attachment_blocked_dirs,
                max_size=attachment_max_size,
                allow_symlinks=attachment_allow_symlinks,
                raise_on_security=attachment_raise_on_security,
            ),
            sources,
        )

    with _collect_skipped() as collector:
        send(
            mail_from=sender_value,
            mail_recipients=resolved_recipients,
            mail_subject=subject,
            mail_body=body,
            mail_body_html=html_body or "",
            attachment_file_paths=list(attachments),
            config=settings,
            transport=_context(ctx).transport,
        )

    skipped_recipients = {item["value"] for item in collector.skipped if item["kind"] == "recipient"}
    delivered = [recipient for recipient in resolved_recipients if recipient.lower() not in skipped_recipients]
    data = {"sender": sender_value, "recipients": delivered, "hosts": list(settings.smtphosts)}
    _emit(ctx, "send", data, f"Mail sent to {', '.join(delivered)} via {', '.join(settings.smtphosts)}", skipped=collector.skipped)


@dataclass(frozen=True)
class _ConnectionOptions:
    """The `send` options that shape the SMTP session."""

    starttls: bool | None
    starttls_verify: bool | None
    timeout: float | None
    delivery_deadline: float | None
    local_hostname: str | None


def _apply_connection_settings(settings: ConfMail, options: _ConnectionOptions, sources: _Sources) -> None:
    settings.smtp_use_starttls = _resolve_bool(
        cli_flag=options.starttls, env_key="BTX_MAIL_SMTP_USE_STARTTLS", default=settings.smtp_use_starttls, sources=sources
    )
    settings.smtp_starttls_verify = _resolve_bool(
        cli_flag=options.starttls_verify, env_key="BTX_MAIL_SMTP_STARTTLS_VERIFY", default=settings.smtp_starttls_verify, sources=sources
    )
    settings.smtp_timeout = _or_default(_resolve_float(options.timeout, "BTX_MAIL_SMTP_TIMEOUT", sources=sources), settings.smtp_timeout)
    settings.smtp_delivery_deadline = _or_default(
        _resolve_float(options.delivery_deadline, "BTX_MAIL_SMTP_DELIVERY_DEADLINE", sources=sources), settings.smtp_delivery_deadline
    )
    settings.smtp_local_hostname = options.local_hostname or sources.value("BTX_MAIL_SMTP_LOCAL_HOSTNAME") or settings.smtp_local_hostname


@dataclass(frozen=True)
class _AttachmentOptions:
    """The `send` options that shape attachment security."""

    allowed_ext: str | None
    blocked_ext: str | None
    allowed_dirs: Sequence[str]
    blocked_dirs: Sequence[str]
    max_size: int | None
    allow_symlinks: bool | None
    raise_on_security: bool | None


def _apply_attachment_settings(settings: ConfMail, options: _AttachmentOptions, sources: _Sources) -> None:
    settings.attachment_allowed_extensions = _or_default(
        _resolve_extensions(options.allowed_ext, "BTX_MAIL_ATTACHMENT_ALLOWED_EXT", sources=sources), settings.attachment_allowed_extensions
    )
    settings.attachment_blocked_extensions = _or_default(
        _resolve_extensions(options.blocked_ext, "BTX_MAIL_ATTACHMENT_BLOCKED_EXT", sources=sources), settings.attachment_blocked_extensions
    )
    settings.attachment_allowed_directories = _or_default(
        _resolve_directories(options.allowed_dirs, "BTX_MAIL_ATTACHMENT_ALLOWED_DIRS", sources=sources), settings.attachment_allowed_directories
    )
    settings.attachment_blocked_directories = _or_default(
        _resolve_directories(options.blocked_dirs, "BTX_MAIL_ATTACHMENT_BLOCKED_DIRS", sources=sources), settings.attachment_blocked_directories
    )
    settings.attachment_max_size_bytes = _or_default(
        _resolve_int(options.max_size, "BTX_MAIL_ATTACHMENT_MAX_SIZE", sources=sources), settings.attachment_max_size_bytes
    )
    settings.attachment_allow_symlinks = _or_default(
        _resolve_optional_bool(cli_flag=options.allow_symlinks, env_key="BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS", sources=sources),
        settings.attachment_allow_symlinks,
    )
    settings.attachment_raise_on_security_violation = _or_default(
        _resolve_optional_bool(cli_flag=options.raise_on_security, env_key="BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY", sources=sources),
        settings.attachment_raise_on_security_violation,
    )


@cli.command("validate-email", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("address")
@click.pass_context
def cli_validate_email(ctx: click.Context, address: str) -> None:
    """### cli_validate_email(address: str) -> None {#cli-validate-email}

    **Purpose:** Validate that *address* is a syntactically correct email
    address. Exits successfully when the address is valid; raises when invalid.

    **Parameters:**
    - `address: str` - Email address to validate.

    **Returns:** `None`.

    **Side Effects:** Reports the valid address on success.
    """

    validate_email_address(address)
    _emit(ctx, "validate-email", {"address": address, "valid": True}, f"Valid email address: {address}")


@cli.command("validate-smtp-host", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("host")
@click.pass_context
def cli_validate_smtp_host(ctx: click.Context, host: str) -> None:
    """### cli_validate_smtp_host(host: str) -> None {#cli-validate-smtp-host}

    **Purpose:** Validate that *host* is a syntactically correct SMTP host
    string, including IPv6 bracketed addresses. Exits successfully when valid;
    raises when invalid.

    **Parameters:**
    - `host: str` - SMTP host string to validate.

    **Returns:** `None`.

    **Side Effects:** Reports the valid host on success.
    """

    validate_smtp_host(host)
    _emit(ctx, "validate-smtp-host", {"host": host, "valid": True}, f"Valid SMTP host: {host}")


@cli.command("fail", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_fail() -> None:
    """### cli_fail() -> None {#cli-fail}

    **Purpose:** Trigger the intentional failure helper so developers can verify
    traceback and exit-code handling.

    **Returns:** This command never returns; it raises instead.

    **Raises:** `RuntimeError` propagated from `raise_intentional_failure()`.
    """

    raise_intentional_failure()


def main(
    argv: Sequence[str] | None = None,
    *,
    restore_traceback: bool = True,
    summary_limit: int = TRACEBACK_SUMMARY_LIMIT,
    verbose_limit: int = TRACEBACK_VERBOSE_LIMIT,
) -> int:
    """### main(...) -> int {#cli-main-entry}

    **Purpose:** Serve as the shared entry point for console scripts and
    `python -m` execution, orchestrating error handling and traceback
    restoration.

    **Parameters:**
    - `argv: Sequence[str] | None = None` - Optional argument vector. `None`
      lets Click consume `sys.argv`.
    - `restore_traceback: bool = True` - `True` restores the prior traceback
      configuration after execution; set to `False` to leave modifications in
      place.
    - `summary_limit: int = TRACEBACK_SUMMARY_LIMIT` - Character budget applied
      when tracebacks are summarised.
    - `verbose_limit: int = TRACEBACK_VERBOSE_LIMIT` - Character budget applied
      when verbose tracebacks are enabled.

    **Returns:** `int` - Exit code produced by the CLI. With `--json` or
    `--json-bare`, a failure is printed as JSON on standard output and the exit
    code is the one the same failure has without them.

    **Side Effects:** Temporarily mutates `lib_cli_exit_tools.config` while the
    CLI executes.
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


def _json_mode(argv: Sequence[str]) -> tuple[bool, bool]:
    """Return ``(as_json, bare)`` read from *argv*.

    Read from argv rather than the Click context: an error can escape before the
    context exists (a malformed option), and its report must still be JSON.
    """
    bare = "--json-bare" in argv
    return bare or "--json" in argv or "-j" in argv, bare


def _command_named(argv: Sequence[str]) -> str | None:
    """Return the first subcommand name in *argv*, for the failure envelope."""
    return next((token for token in argv if token in cli.commands), None)


def _json_exception_handler(argv: Sequence[str], *, bare: bool) -> Callable[[BaseException], int]:
    """Return a ``run_cli`` exception handler that reports failures as JSON on stdout.

    The exit code is resolved as ``lib_cli_exit_tools`` resolves it without
    JSON, so a caller may switch on it in either mode.
    """

    def handle(exc: BaseException) -> int:
        if isinstance(exc, BrokenPipeError):
            # The reader went away; there is nobody left to print the error to.
            return int(lib_cli_exit_tools.config.broken_pipe_exit_code)
        if isinstance(exc, SystemExit):
            return int(exc.code or 0) if isinstance(exc.code, int) or exc.code is None else 1
        error = _error_payload(exc)
        click.echo(_dumps(error if bare else {"ok": False, "command": _command_named(argv), "error": error, "skipped": []}))
        if isinstance(exc, click.ClickException):
            return exc.exit_code
        return lib_cli_exit_tools.get_system_exit_code(exc)

    return handle


def _restore_when_requested(*, state: TracebackState, should_restore: bool) -> None:
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
