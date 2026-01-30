"""## btx_lib_mail.cli {#module-btx-lib-mail-cli}

**Purpose:** Provide the rich-click adapter that exposes the behaviour helpers
to users and automation while keeping traceback handling consistent across
console scripts and `python -m` entry points.

**Contents:**
- `CLICK_CONTEXT_SETTINGS`, `TRACEBACK_SUMMARY_LIMIT`, `TRACEBACK_VERBOSE_LIMIT`
  — shared configuration constants.
- `apply_traceback_preferences`, `snapshot_traceback_state`,
  `restore_traceback_state` — shared traceback state helpers.
- `cli` and its subcommands (`cli_info`, `cli_hello`, `cli_send_mail`, `cli_fail`)
  plus `cli_main` — the public CLI surface.
- `main` — composition helper driving execution through `lib_cli_exit_tools`.

**System Role:** Documented in
`docs/systemdesign/module_reference.md#feature-cli-components`; this module is
the primary adapter, ensuring every transport shares the same traceback and
delivery semantics.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, Sequence

import rich_click as click

import lib_cli_exit_tools
from click.core import ParameterSource

from . import __init__conf__
from .behaviors import emit_greeting, noop_main, raise_intentional_failure
from .lib_mail import conf, send, validate_email_address, validate_smtp_host

_DOTENV_PATH = Path(".env")
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _dotenv_value(key: str) -> str | None:
    if not _DOTENV_PATH.is_file():
        return None
    for line in _DOTENV_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        candidate_key, candidate_value = stripped.split("=", 1)
        if candidate_key.strip() != key:
            continue
        return candidate_value.strip().strip('"').strip("'") or None
    return None


def _configured_value(key: str) -> str | None:
    env_value = os.getenv(key)
    if env_value not in (None, ""):
        return env_value
    return _dotenv_value(key)


def _split_values(values: Sequence[str]) -> list[str]:
    flattened: list[str] = []
    for raw in values:
        for item in raw.split(","):
            candidate = item.strip()
            if candidate:
                flattened.append(candidate)
    return flattened


def _resolve_list(cli_values: Sequence[str], env_key: str, *, label: str) -> list[str]:
    values = _split_values(cli_values)
    if not values:
        env_raw = _configured_value(env_key)
        if env_raw:
            values = _split_values([env_raw])
    if not values:
        raise click.UsageError(f"Provide at least one {label} via options or {env_key}.")
    return values


def _resolve_bool(cli_flag: bool | None, env_key: str, *, default: bool = False) -> bool:
    if cli_flag is not None:
        return cli_flag
    env_raw = _configured_value(env_key)
    if env_raw is None:
        return default
    lowered = env_raw.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES or lowered == "":
        return False
    raise click.BadParameter(f"Unrecognised boolean value for {env_key}: {env_raw!r}")


def _resolve_credentials(user: str | None, password: str | None) -> tuple[str, str] | None:
    if user and password:
        return user, password
    return None


def _resolve_float(cli_value: float | None, env_key: str, *, default: float) -> float:
    """Return the float value provided via CLI, environment, or default.

    Why
        Keeps timeout resolution readable while surfacing friendly errors.

    Inputs
    ------
    cli_value:
        Value supplied on the CLI (``None`` when flag omitted).
    env_key:
        Environment variable consulted when CLI value is absent.
    default:
        Fallback applied when neither CLI nor environment provided a value.

    Outputs
    -------
    float
        Parsed float value honouring the precedence chain.

    Side Effects
    ------------
    Raises :class:`click.BadParameter` when the environment variable cannot be
    parsed as a float.
    """

    if cli_value is not None:
        return cli_value
    env_raw = _configured_value(env_key)
    if env_raw is None or env_raw.strip() == "":
        return default
    try:
        return float(env_raw.strip())
    except ValueError as exc:
        raise click.BadParameter(f"Unrecognised float value for {env_key}: {env_raw!r}") from exc


def _resolve_int(cli_value: int | None, env_key: str) -> int | None:
    """Return the int value provided via CLI, environment, or None.

    Why
        Keeps size limit resolution readable while surfacing friendly errors.

    Inputs
    ------
    cli_value:
        Value supplied on the CLI (``None`` when flag omitted).
    env_key:
        Environment variable consulted when CLI value is absent.

    Outputs
    -------
    int | None
        Parsed int value honouring the precedence chain, or None if not set.
    """
    if cli_value is not None:
        return cli_value
    env_raw = _configured_value(env_key)
    if env_raw is None or env_raw.strip() == "":
        return None
    try:
        return int(env_raw.strip())
    except ValueError as exc:
        raise click.BadParameter(f"Unrecognised int value for {env_key}: {env_raw!r}") from exc


def _resolve_extensions(cli_value: str | None, env_key: str) -> frozenset[str] | None:
    """Resolve extension set from CLI, env, or return None for default.

    Why
        Handles comma-separated extension lists with proper normalisation.

    Inputs
    ------
    cli_value:
        Comma-separated extension string from CLI (``None`` when omitted).
    env_key:
        Environment variable consulted when CLI value is absent.

    Outputs
    -------
    frozenset[str] | None
        Normalised extension set, or None to use configuration default.
    """
    raw = cli_value or _configured_value(env_key)
    if raw is None or raw.strip() == "":
        return None

    extensions: set[str] = set()
    for ext in raw.split(","):
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        extensions.add(ext)

    return frozenset(extensions) if extensions else None


def _resolve_directories(cli_values: Sequence[str], env_key: str) -> frozenset[Path] | None:
    """Resolve directory set from CLI, env, or return None for default.

    Why
        Handles multiple directory options with proper path resolution.

    Inputs
    ------
    cli_values:
        Sequence of directory paths from CLI (repeat options or comma-separated).
    env_key:
        Environment variable consulted when CLI values are absent.

    Outputs
    -------
    frozenset[Path] | None
        Normalised directory set, or None to use configuration default.
    """
    # Flatten CLI values (support both repeat and comma-separated)
    flattened = _split_values(cli_values)

    if not flattened:
        env_raw = _configured_value(env_key)
        if env_raw:
            flattened = _split_values([env_raw])

    if not flattened:
        return None

    directories: set[Path] = set()
    for dir_str in flattened:
        dir_str = dir_str.strip()
        if dir_str:
            directories.add(Path(dir_str))

    return frozenset(directories) if directories else None


def _resolve_optional_bool(cli_flag: bool | None, env_key: str) -> bool | None:
    """Return the bool value provided via CLI, environment, or None for default.

    Why
        Similar to _resolve_bool but returns None instead of a default.

    Inputs
    ------
    cli_flag:
        Value supplied on the CLI (``None`` when flag omitted).
    env_key:
        Environment variable consulted when CLI value is absent.

    Outputs
    -------
    bool | None
        Parsed bool value, or None to use configuration default.
    """
    if cli_flag is not None:
        return cli_flag
    env_raw = _configured_value(env_key)
    if env_raw is None or env_raw.strip() == "":
        return None
    lowered = env_raw.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise click.BadParameter(f"Unrecognised boolean value for {env_key}: {env_raw!r}")


#: Shared Click context flags so help output stays consistent across commands.
CLICK_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}  # noqa: C408
"""Click context settings ensuring every command honours `-h/--help`."""
#: Character budget used when printing truncated tracebacks.
TRACEBACK_SUMMARY_LIMIT: Final[int] = 500
"""Character budget applied to compact traceback output."""
#: Character budget used when verbose tracebacks are enabled.
TRACEBACK_VERBOSE_LIMIT: Final[int] = 10_000
"""Character budget applied when verbose tracebacks are requested."""
TracebackState = tuple[bool, bool]


def apply_traceback_preferences(enabled: bool) -> None:
    """### apply_traceback_preferences(enabled: bool) -> None {#cli-apply-traceback-preferences}

    **Purpose:** Keep `lib_cli_exit_tools` configuration aligned with the CLI's
    `--traceback/--no-traceback` flag so console scripts and `python -m` runs
    present identical diagnostics.

    **Parameters:**
    - `enabled: bool` — `True` enables verbose, colourised tracebacks;
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

    **Returns:** `TracebackState` — Tuple `(traceback_enabled, force_color)`
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
    - `state: TracebackState` — Tuple produced by
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
    """### cli(traceback: bool = False) -> None {#cli-root}

    **Purpose:** Register global CLI options (notably `--traceback`) and ensure
    `lib_cli_exit_tools` reflects the caller's preference before dispatching to
    subcommands.

    **Parameters:**
    - `ctx: click.Context` — Click context initialised by Click.
    - `traceback: bool = False` — `True` to enable verbose tracebacks; defaults
      to `False`.

    **Returns:** `None`.

    **Side Effects:** Stores the traceback preference in `ctx.obj` and mirrors
    it into `lib_cli_exit_tools.config`. When invoked without a subcommand and
    without explicitly setting the traceback flag, the command prints help
    instead of executing the placeholder domain entry.

    **Example:**
    >>> from click.testing import CliRunner
    >>> runner = CliRunner()
    >>> runner.invoke(cli, ["hello"]).exit_code
    0
    """

    _record_traceback_choice(ctx, enabled=traceback)
    _announce_traceback_choice(traceback)
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
def cli_info() -> None:
    """### cli_info() -> None {#cli-info}

    **Purpose:** Surface the package metadata so operators can confirm version,
    homepage, and authorship information.

    **Returns:** `None`.

    **Side Effects:** Writes metadata to standard output.
    """

    __init__conf__.print_info()


@cli.command("hello", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_hello() -> None:
    """### cli_hello() -> None {#cli-hello}

    **Purpose:** Demonstrate the happy-path behaviour by emitting the canonical
    greeting used throughout the scaffold.

    **Returns:** `None`.

    **Side Effects:** Writes `Hello World` plus newline to standard output.
    """

    emit_greeting()


@cli.command("send", context_settings=CLICK_CONTEXT_SETTINGS)
@click.option(
    "--host",
    "hosts",
    multiple=True,
    help="SMTP host to use (repeat or provide comma-separated values).",
    metavar="HOST",
)
@click.option(
    "--recipient",
    "recipients",
    multiple=True,
    help="Recipient email address (repeat or provide comma-separated values).",
    metavar="EMAIL",
)
@click.option("--sender", help="Envelope sender address.")
@click.option("--subject", required=True, help="Mail subject line.")
@click.option("--body", required=True, help="Plain-text email body.")
@click.option("--html-body", help="Optional HTML body content.")
@click.option(
    "--attachment",
    "attachments",
    type=click.Path(path_type=Path),
    multiple=True,
    help="Attachment file path (repeat for multiple files).",
)
@click.option(
    "--starttls/--no-starttls",
    "starttls",
    default=None,
    help="Force STARTTLS negotiation (overrides environment).",
)
@click.option("--username", help="SMTP username.")
@click.option("--password", help="SMTP password.")
@click.option(
    "--timeout",
    type=float,
    default=None,
    help="Socket timeout in seconds (overrides environment).",
)
# Attachment security options
@click.option(
    "--attachment-allowed-ext",
    "attachment_allowed_ext",
    default=None,
    help="Allowed extensions (comma-separated, e.g., .pdf,.txt). Enables whitelist mode.",
)
@click.option(
    "--attachment-blocked-ext",
    "attachment_blocked_ext",
    default=None,
    help="Blocked extensions (comma-separated). Overrides default dangerous extensions.",
)
@click.option(
    "--attachment-allowed-dir",
    "attachment_allowed_dirs",
    multiple=True,
    help="Allowed directories (repeat for multiple). Enables whitelist mode.",
)
@click.option(
    "--attachment-blocked-dir",
    "attachment_blocked_dirs",
    multiple=True,
    help="Blocked directories (repeat for multiple). Overrides default sensitive directories.",
)
@click.option(
    "--attachment-max-size",
    "attachment_max_size",
    type=int,
    default=None,
    help="Max attachment size in bytes (default: 25 MiB).",
)
@click.option(
    "--attachment-allow-symlinks/--attachment-no-symlinks",
    "attachment_allow_symlinks",
    default=None,
    help="Allow or reject symlinked attachments (default: reject).",
)
@click.option(
    "--attachment-strict/--attachment-warn",
    "attachment_raise_on_security",
    default=None,
    help="Raise on security violation (strict) or log warning and skip (warn).",
)
def cli_send_mail(
    *,
    hosts: Sequence[str],
    recipients: Sequence[str],
    sender: str | None,
    subject: str,
    body: str,
    html_body: str | None,
    attachments: Sequence[Path],
    starttls: bool | None,
    username: str | None,
    password: str | None,
    timeout: float | None,
    attachment_allowed_ext: str | None,
    attachment_blocked_ext: str | None,
    attachment_allowed_dirs: Sequence[str],
    attachment_blocked_dirs: Sequence[str],
    attachment_max_size: int | None,
    attachment_allow_symlinks: bool | None,
    attachment_raise_on_security: bool | None,
) -> None:
    """### cli_send_mail(...) -> None {#cli-send-mail}

    **Purpose:** Provide a convenient SMTP smoke test that feeds resolved CLI
    and environment inputs into `btx_lib_mail.lib_mail.send`.

    **Parameters:**
    - `hosts: Sequence[str]` — One or more `host[:port]` entries; defaults to
      `BTX_MAIL_SMTP_HOSTS` when omitted.
    - `recipients: Sequence[str]` — Recipient addresses; defaults to
      `BTX_MAIL_RECIPIENTS`.
    - `sender: str | None` — Optional envelope sender. Falls back to
      `BTX_MAIL_SENDER` or the first recipient.
    - `subject: str` — Required subject line.
    - `body: str` — Required plain-text body.
    - `html_body: str | None` — Optional HTML body.
    - `attachments: Sequence[Path]` — Zero or more filesystem paths to attach.
    - `starttls: bool | None` — Override for STARTTLS preference. When `None`,
      falls back to configuration/environment.
    - `username: str | None`, `password: str | None` — Optional credentials.
      Both are required to enable authentication.
    - `timeout: float | None` — Optional socket timeout override in seconds.

    **Returns:** `None`.

    **Side Effects:** Calls `send()` and echoes a summary message to standard
    output. Exceptions from `send()` propagate to the shared error handlers.
    """

    resolved_hosts = _resolve_list(hosts, "BTX_MAIL_SMTP_HOSTS", label="SMTP host")
    resolved_recipients = _resolve_list(recipients, "BTX_MAIL_RECIPIENTS", label="recipient")

    sender_value = sender or _configured_value("BTX_MAIL_SENDER") or resolved_recipients[0]
    username_value = username or _configured_value("BTX_MAIL_SMTP_USERNAME")
    password_value = password or _configured_value("BTX_MAIL_SMTP_PASSWORD")
    use_starttls = _resolve_bool(starttls, "BTX_MAIL_SMTP_USE_STARTTLS", default=conf.smtp_use_starttls)
    credentials = _resolve_credentials(username_value, password_value)
    timeout_value = _resolve_float(timeout, "BTX_MAIL_SMTP_TIMEOUT", default=conf.smtp_timeout)

    # Resolve attachment security options
    resolved_allowed_ext = _resolve_extensions(attachment_allowed_ext, "BTX_MAIL_ATTACHMENT_ALLOWED_EXT")
    resolved_blocked_ext = _resolve_extensions(attachment_blocked_ext, "BTX_MAIL_ATTACHMENT_BLOCKED_EXT")
    resolved_allowed_dirs = _resolve_directories(attachment_allowed_dirs, "BTX_MAIL_ATTACHMENT_ALLOWED_DIRS")
    resolved_blocked_dirs = _resolve_directories(attachment_blocked_dirs, "BTX_MAIL_ATTACHMENT_BLOCKED_DIRS")
    resolved_max_size = _resolve_int(attachment_max_size, "BTX_MAIL_ATTACHMENT_MAX_SIZE")
    resolved_allow_symlinks = _resolve_optional_bool(attachment_allow_symlinks, "BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS")
    resolved_raise_on_security = _resolve_optional_bool(attachment_raise_on_security, "BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY")

    send(
        mail_from=sender_value,
        mail_recipients=resolved_recipients,
        mail_subject=subject,
        mail_body=body,
        mail_body_html=html_body or "",
        smtphosts=resolved_hosts,
        attachment_file_paths=list(attachments),
        credentials=credentials,
        use_starttls=use_starttls,
        timeout=timeout_value,
        attachment_allowed_extensions=resolved_allowed_ext,
        attachment_blocked_extensions=resolved_blocked_ext,
        attachment_allowed_directories=resolved_allowed_dirs,
        attachment_blocked_directories=resolved_blocked_dirs,
        attachment_max_size_bytes=resolved_max_size,
        attachment_allow_symlinks=resolved_allow_symlinks,
        attachment_raise_on_security_violation=resolved_raise_on_security,
    )

    click.echo(f"Mail sent to {', '.join(resolved_recipients)} via {', '.join(resolved_hosts)}")


@cli.command("validate-email", context_settings=CLICK_CONTEXT_SETTINGS)
@click.argument("address")
def cli_validate_email(address: str) -> None:
    """### cli_validate_email(address: str) -> None {#cli-validate-email}

    **Purpose:** Validate that *address* is a syntactically correct email
    address. Exits successfully when the address is valid; raises when invalid.

    **Parameters:**
    - `address: str` — Email address to validate.

    **Returns:** `None`.

    **Side Effects:** Echoes a confirmation message on success.
    """

    validate_email_address(address)
    click.echo(f"Valid email address: {address}")


@cli.command("validate-smtp-host", context_settings=CLICK_CONTEXT_SETTINGS)
@click.argument("host")
def cli_validate_smtp_host(host: str) -> None:
    """### cli_validate_smtp_host(host: str) -> None {#cli-validate-smtp-host}

    **Purpose:** Validate that *host* is a syntactically correct SMTP host
    string, including IPv6 bracketed addresses. Exits successfully when valid;
    raises when invalid.

    **Parameters:**
    - `host: str` — SMTP host string to validate.

    **Returns:** `None`.

    **Side Effects:** Echoes a confirmation message on success.
    """

    validate_smtp_host(host)
    click.echo(f"Valid SMTP host: {host}")


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
    - `argv: Sequence[str] | None = None` — Optional argument vector. `None`
      lets Click consume `sys.argv`.
    - `restore_traceback: bool = True` — `True` restores the prior traceback
      configuration after execution; set to `False` to leave modifications in
      place.
    - `summary_limit: int = TRACEBACK_SUMMARY_LIMIT` — Character budget applied
      when tracebacks are summarised.
    - `verbose_limit: int = TRACEBACK_VERBOSE_LIMIT` — Character budget applied
      when verbose tracebacks are enabled.

    **Returns:** `int` — Exit code produced by the CLI.

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
