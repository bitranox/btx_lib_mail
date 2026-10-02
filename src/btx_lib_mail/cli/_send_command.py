"""The `send` subcommand: one `ConfMail` built from options > environment > env file > `conf`.

Private to btx_lib_mail.cli: import the public names from `btx_lib_mail.cli`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING

import rich_click as click
from pydantic import SecretStr

from ..lib_mail import ConfMail, conf, send
from ..typed_click import option

if TYPE_CHECKING:
    from collections.abc import Sequence
from ._commands import CLICK_CONTEXT_SETTINGS, cli
from ._output import cli_context, collect_skipped, emit
from ._settings_sources import (
    Sources,
    checked_hosts,
    env_file_to_read,
    or_default,
    read_env_file,
    refusals_as_value_error,
    resolve_bool,
    resolve_credentials,
    resolve_directories,
    resolve_extensions,
    resolve_float,
    resolve_int,
    resolve_list,
    resolve_optional_bool,
    resolve_password,
)

__all__ = ["cli_send_mail"]


@cli.command(
    "send",
    context_settings=CLICK_CONTEXT_SETTINGS,
    help="Send one message to each recipient. Unset settings come from BTX_MAIL_* environment variables, then from the --env-file.",
)
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
    help="Read unset BTX_MAIL_* settings from this KEY=value file instead of ./.env (also BTX_MAIL_ENV_FILE).",
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
    """Provide a convenient SMTP smoke test built from CLI options, the environment and an env file.

    Resolves CLI options, the environment and an optional `--env-file` into one validated
    `ConfMail` (a copy of the global `conf`, so settings without an option keep their value) and
    hands it to `btx_lib_mail.lib_mail.send` as `config=`. A value the model refuses is raised as
    `InvalidInputError` before any delivery. Calls `send()` and reports the result on standard
    output (a summary line, or the JSON envelope with the recipients, hosts and the attachments
    and recipients skipped in warn mode). Exceptions from `send()` propagate to the shared error
    handlers.

    Args:
        ctx: Click context carrying the output mode and the transport seam.
        hosts: One or more `host[:port]` entries; defaults to `BTX_MAIL_SMTP_HOSTS`
            when omitted.
        recipients: Recipient addresses; defaults to `BTX_MAIL_RECIPIENTS`.
        sender: Optional envelope sender. Falls back to `BTX_MAIL_SENDER` or the
            first recipient.
        subject: Required subject line.
        body: Required plain-text body.
        html_body: Optional HTML body.
        attachments: Zero or more filesystem paths to attach.
        env_file: `KEY=value` file read for settings neither an option nor the
            environment gave; also `BTX_MAIL_ENV_FILE`. When it is not given,
            `./.env` is read if it is a regular file.
        starttls: Override for STARTTLS preference. When `None`, falls back to the
            sources, then `conf`.
        starttls_verify: Override for STARTTLS certificate verification. When
            `None`, falls back to `BTX_MAIL_SMTP_STARTTLS_VERIFY` or
            `conf.smtp_starttls_verify`. `--no-starttls-verify` keeps encryption but
            skips certificate validation for internal self-signed relays.
        username: Optional SMTP username; both a username and a password are
            required to authenticate.
        password: Optional SMTP password; `--password` and `--password-file`
            exclude each other.
        password_file: Optional file handle to read the password from; excludes
            `password`.
        timeout: Optional socket timeout override in seconds.
        delivery_deadline: Optional bound in seconds for one SMTP session; also
            `BTX_MAIL_SMTP_DELIVERY_DEADLINE`.
        local_hostname: Name announced in EHLO. Falls back to
            `BTX_MAIL_SMTP_LOCAL_HOSTNAME`, then `conf.smtp_local_hostname`.
        attachment_allowed_ext: Comma-separated allowed extensions, enabling
            whitelist mode.
        attachment_blocked_ext: Comma-separated blocked extensions, overriding the
            default dangerous extensions.
        attachment_allowed_dirs: Allowed directories, enabling whitelist mode.
        attachment_blocked_dirs: Blocked directories, overriding the default
            sensitive directories.
        attachment_max_size: Max attachment size in bytes.
        attachment_allow_symlinks: Allow or reject symlinked attachments.
        attachment_raise_on_security: Raise on a security violation (strict) or log
            a warning and skip (warn).
    """
    sources = Sources(environ=os.environ, env_file=read_env_file(env_file_to_read(env_file)))
    requested_hosts = resolve_list(hosts, "BTX_MAIL_SMTP_HOSTS", label="SMTP host", sources=sources)
    resolved_recipients = resolve_list(recipients, "BTX_MAIL_RECIPIENTS", label="recipient", sources=sources)
    sender_value = sender or sources.value("BTX_MAIL_SENDER") or resolved_recipients[0]

    # One validated ConfMail is the boundary: every assignment below runs the
    # model's validators, and the copy keeps the global conf untouched while
    # carrying the settings this command has no option for.
    settings = conf.model_copy(deep=True)
    with refusals_as_value_error():
        settings.smtphosts = checked_hosts(requested_hosts)
        credentials = resolve_credentials(
            username or sources.value("BTX_MAIL_SMTP_USERNAME"),
            resolve_password(password=password, password_file=password_file, sources=sources),
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

    with collect_skipped() as collector:
        send(
            mail_from=sender_value,
            mail_recipients=resolved_recipients,
            mail_subject=subject,
            mail_body=body,
            mail_body_html=html_body or "",
            attachment_file_paths=list(attachments),
            config=settings,
            transport=cli_context(ctx).transport,
        )

    skipped_recipients = {item["value"] for item in collector.skipped if item["kind"] == "recipient"}
    delivered = [recipient for recipient in resolved_recipients if recipient.lower() not in skipped_recipients]
    data = {"sender": sender_value, "recipients": delivered, "hosts": list(settings.smtphosts)}
    emit(ctx, "send", data, f"Mail sent to {', '.join(delivered)} via {', '.join(settings.smtphosts)}", skipped=collector.skipped)


@dataclass(frozen=True)
class _ConnectionOptions:
    """The `send` options that shape the SMTP session."""

    starttls: bool | None
    starttls_verify: bool | None
    timeout: float | None
    delivery_deadline: float | None
    local_hostname: str | None


def _apply_connection_settings(settings: ConfMail, options: _ConnectionOptions, sources: Sources) -> None:
    settings.smtp_use_starttls = resolve_bool(
        cli_flag=options.starttls, env_key="BTX_MAIL_SMTP_USE_STARTTLS", default=settings.smtp_use_starttls, sources=sources
    )
    settings.smtp_starttls_verify = resolve_bool(
        cli_flag=options.starttls_verify, env_key="BTX_MAIL_SMTP_STARTTLS_VERIFY", default=settings.smtp_starttls_verify, sources=sources
    )
    settings.smtp_timeout = or_default(resolve_float(options.timeout, "BTX_MAIL_SMTP_TIMEOUT", sources=sources), settings.smtp_timeout)
    settings.smtp_delivery_deadline = or_default(
        resolve_float(options.delivery_deadline, "BTX_MAIL_SMTP_DELIVERY_DEADLINE", sources=sources), settings.smtp_delivery_deadline
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


def _apply_attachment_settings(settings: ConfMail, options: _AttachmentOptions, sources: Sources) -> None:
    settings.attachment_allowed_extensions = or_default(
        resolve_extensions(options.allowed_ext, "BTX_MAIL_ATTACHMENT_ALLOWED_EXT", sources=sources), settings.attachment_allowed_extensions
    )
    settings.attachment_blocked_extensions = or_default(
        resolve_extensions(options.blocked_ext, "BTX_MAIL_ATTACHMENT_BLOCKED_EXT", sources=sources), settings.attachment_blocked_extensions
    )
    settings.attachment_allowed_directories = or_default(
        resolve_directories(options.allowed_dirs, "BTX_MAIL_ATTACHMENT_ALLOWED_DIRS", sources=sources), settings.attachment_allowed_directories
    )
    settings.attachment_blocked_directories = or_default(
        resolve_directories(options.blocked_dirs, "BTX_MAIL_ATTACHMENT_BLOCKED_DIRS", sources=sources), settings.attachment_blocked_directories
    )
    settings.attachment_max_size_bytes = or_default(
        resolve_int(options.max_size, "BTX_MAIL_ATTACHMENT_MAX_SIZE", sources=sources), settings.attachment_max_size_bytes
    )
    settings.attachment_allow_symlinks = or_default(
        resolve_optional_bool(cli_flag=options.allow_symlinks, env_key="BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS", sources=sources),
        settings.attachment_allow_symlinks,
    )
    settings.attachment_raise_on_security_violation = or_default(
        resolve_optional_bool(cli_flag=options.raise_on_security, env_key="BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY", sources=sources),
        settings.attachment_raise_on_security_violation,
    )
