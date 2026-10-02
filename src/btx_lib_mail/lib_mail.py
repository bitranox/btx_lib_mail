"""Provide `send()`, the delivery entry point and public face of the library's mail machinery.

`send()` resolves its keywords against a `ConfMail`, checks and opens the
attachments, composes the message once, and hands one copy per recipient to
a `Transport`, failing over across hosts.

Contents:
    - `send` - public orchestration entry point.
    - Re-exported from the private modules it composes: `ConfMail` and `conf`
      (`_config`), `Transport`, `SmtplibTransport` and `DeliveryOptions`
      (`_transport`), the attachment security names (`_attachments`),
      `validate_email_address`, `validate_smtp_host` and `EMAIL_PATTERN`
      (`_validation`), and `logger` (`_common`).

Matches `docs/systemdesign/module_reference.md#core-components` by
translating intent gathered by the CLI into SMTP side effects while keeping
configuration flow and delivery flow separated.
"""

from __future__ import annotations

import smtplib
from dataclasses import dataclass, field
from typing import IO, TYPE_CHECKING, Final

from ._attachments import (
    DANGEROUS_DIRECTORIES_POSIX,
    DANGEROUS_DIRECTORIES_WINDOWS,
    DANGEROUS_EXTENSIONS_POSIX,
    DANGEROUS_EXTENSIONS_WINDOWS,
    SENSITIVE_PATH_PATTERNS,
    AttachmentPayload,
    AttachmentSecurityError,
    AttachmentSecurityOptions,
    AttachmentViolation,
    close_attachments,
    coerce_attachment_paths,
    normalise_extensions,
    prepare_attachments,
)
from ._common import logger, printable
from ._compose import MessageContent, check_body, check_subject, compose_body_once, envelope_header_lines, message_for
from ._config import ConfMail, conf
from ._transport import DEFAULT_TRANSPORT, DeliveryOptions, SmtplibTransport, Transport
from ._validation import (
    EMAIL_PATTERN,
    address_length_problem,
    check_credentials,
    check_local_hostname,
    check_seconds,
    check_timeout,
    host_entries,
    prepare_hosts,
    prepare_recipients,
    require_text,
    validate_email_address,
    validate_smtp_host,
)
from .errors import DeliveryError, InvalidInputError

if TYPE_CHECKING:
    import pathlib
    from collections.abc import Sequence


def send(  # noqa: PLR0913, PLR0917 - public API; the first 7 params are called positionally by existing consumers
    mail_from: str,
    mail_recipients: str | Sequence[str],
    mail_subject: str,
    mail_body: str = "",
    mail_body_html: str = "",
    smtphosts: Sequence[str] | None = None,
    attachment_file_paths: Sequence[pathlib.Path | str] | None = None,
    *,
    credentials: tuple[str, str] | None = None,
    use_starttls: bool | None = None,
    starttls_verify: bool | None = None,
    timeout: float | None = None,
    local_hostname: str | None = None,
    delivery_deadline: float | None = None,
    # Attachment security parameters
    attachment_allowed_extensions: frozenset[str] | None = None,
    attachment_blocked_extensions: frozenset[str] | None = None,
    attachment_allowed_directories: frozenset[pathlib.Path] | None = None,
    attachment_blocked_directories: frozenset[pathlib.Path] | None = None,
    attachment_max_size_bytes: int | None = None,
    attachment_allow_symlinks: bool | None = None,
    attachment_raise_on_security_violation: bool | None = None,
    # Error handling parameters
    raise_on_missing_attachments: bool | None = None,
    raise_on_invalid_recipient: bool | None = None,
    # Settings object used instead of the module-global conf (explicit keywords still win).
    config: ConfMail | None = None,
    # Delivery seam (advanced/testing): override the SMTP transport adapter.
    transport: Transport | None = None,
) -> bool:
    """Turn validated intent into SMTP delivery, honouring the policies in ConfMail.

    Provides the library/CLI facade that turns validated intent (sender,
    recipients, message bodies, attachments) into SMTP activity. Each
    attachment is checked, opened once, and encoded once; every recipient's
    message carries the bytes of that open file, and the files are closed
    before `send()` returns.

    Args:
        mail_from: Envelope sender address. Must be a syntactically valid email.
        mail_recipients: Single recipient or iterable of recipients. Values
            are trimmed, deduplicated, lower-cased, and validated.
        mail_subject: Subject line; UTF-8 is supported.
        mail_body: Optional plain-text body. Defaults to "".
        mail_body_html: Optional HTML body. Defaults to "".
        smtphosts: Override host list. When `None`, the helper falls back to
            the passed `config.smtphosts`, else the global `conf.smtphosts`.
        attachment_file_paths: Optional sequence of filesystem paths
            (``pathlib.Path`` or ``str``). Each
            existing, readable file becomes an attachment.
        credentials: Override credentials. When omitted,
            `resolved_credentials()` of the passed `config`, else of `conf`,
            is used.
        use_starttls: Override STARTTLS preference. When `None`, the helper
            uses `smtp_use_starttls` of the passed `config`, else `conf`.
        starttls_verify: Override STARTTLS certificate verification. When
            `None`, the helper uses `smtp_starttls_verify` of the passed
            `config`, else `conf`. `False` keeps the connection encrypted but
            skips certificate/hostname validation (for internal self-signed
            relays). Ignored unless STARTTLS runs.
        timeout: Override socket timeout in seconds. When `None`, the helper
            uses `smtp_timeout` of the passed `config`, else `conf`.
        local_hostname: Override the name announced in `EHLO`. When `None`,
            the helper uses `smtp_local_hostname` of the passed `config`,
            else `conf`; when that is unset too, the host's own name, looked
            up once per process.
        delivery_deadline: Override the upper bound in seconds for one SMTP
            session. When `None`, the helper uses `smtp_delivery_deadline` of
            the passed `config`, else `conf`.
        attachment_allowed_extensions: Override allowed extensions (whitelist
            mode). When `None`, uses the passed `config`'s default, else
            `conf`'s.
        attachment_blocked_extensions: Override blocked extensions. When
            `None`, uses the passed `config`'s default, else `conf`'s.
        attachment_allowed_directories: Override allowed directories. When
            `None`, uses the passed `config`'s default, else `conf`'s.
        attachment_blocked_directories: Override blocked directories. When
            `None`, uses the passed `config`'s default, else `conf`'s.
        attachment_max_size_bytes: Override max attachment size in bytes.
            When `None`, uses the passed `config`'s default, else `conf`'s.
        attachment_allow_symlinks: Override symlink policy. When `None`, uses
            the passed `config`'s default, else `conf`'s.
        attachment_raise_on_security_violation: Override security violation
            behaviour. When `None`, uses the passed `config`'s default, else
            `conf`'s.
        raise_on_missing_attachments: Override `raise_on_missing_attachments`
            of the passed `config`, else `conf`. When `None`, uses that
            default; `True` raises on missing, `False` logs a warning and
            skips.
        raise_on_invalid_recipient: Override `raise_on_invalid_recipient` of
            the passed `config`, else `conf`. When `None`, uses that default;
            `True` raises on invalid, `False` logs a warning and skips.
        config: Settings used in place of the module-global `conf` for every
            value not passed explicitly; when given, `conf` is not read.
            Lets an application hold its own `ConfMail` (or subclass) without
            mutating the global.
        transport: Delivery seam (advanced/testing): override the SMTP
            transport adapter. When `None`, the default stdlib-based
            transport is used.

    Returns:
        Always `True` when all deliveries succeed. A failure raises instead
        of returning `False`.

    Raises:
        InvalidInputError: If the sender, a recipient (in strict mode), a
            host, the subject (over 4096 characters, a line break, a control
            character other than TAB, or invalid Unicode), the body (invalid Unicode),
            `local_hostname`, `timeout` or `delivery_deadline` is refused, or
            no valid recipient remains. Raised before the first delivery.
            Also a `ValueError`.
        AttachmentNotFoundError: If required attachments are missing and
            `raise_on_missing_attachments` is `True` on the config in use
            (the passed `config`, else the global `conf`). Also a
            `FileNotFoundError`.
        AttachmentSecurityError: If an attachment violates security policies
            and `attachment_raise_on_security_violation` is `True`,
            including a file that changed or grew past the size limit after
            it was checked.
        DeliveryError: If every SMTP host fails for a recipient; the error
            lists the affected recipients and host set, and carries them as
            `failed_recipients` and `hosts`. Also a `RuntimeError`.

    Examples:
        >>> class _NullTransport:  # a stand-in transport that accepts every message
        ...     def deliver(self, **kwargs: object) -> None:
        ...         return None
        >>> send(
        ...     mail_from="sender@example.com",
        ...     mail_recipients="receiver@example.com",
        ...     mail_subject="Hello",
        ...     config=ConfMail(smtphosts=["smtp.example.com"]),
        ...     transport=_NullTransport(),
        ... )
        True
    """
    settings = config if config is not None else conf

    require_text(mail_from, field_name="mail_from")
    # An overlong sender is reported by its length; the generic message below quotes the value.
    sender_problem = address_length_problem(mail_from)
    if sender_problem is not None:
        raise InvalidInputError(f"invalid sender address: {sender_problem}")
    try:
        validate_email_address(mail_from)
    except ValueError:
        raise InvalidInputError(f"invalid sender address: {mail_from!r}") from None

    # Resolve error handling parameters
    resolved_raise_on_missing = raise_on_missing_attachments if raise_on_missing_attachments is not None else settings.raise_on_missing_attachments
    resolved_raise_on_invalid = raise_on_invalid_recipient if raise_on_invalid_recipient is not None else settings.raise_on_invalid_recipient

    recipients = prepare_recipients(mail_recipients, raise_on_invalid=resolved_raise_on_invalid, max_count=settings.recipient_max_count)

    # Resolve security options
    security = _resolve_attachment_security_options(
        settings=settings,
        explicit_allowed_extensions=attachment_allowed_extensions,
        explicit_blocked_extensions=attachment_blocked_extensions,
        explicit_allowed_directories=attachment_allowed_directories,
        explicit_blocked_directories=attachment_blocked_directories,
        explicit_max_size_bytes=attachment_max_size_bytes,
        explicit_allow_symlinks=attachment_allow_symlinks,
        explicit_raise_on_violation=attachment_raise_on_security_violation,
    )

    attachments = prepare_attachments(
        coerce_attachment_paths(attachment_file_paths or ()),
        security,
        raise_on_missing=resolved_raise_on_missing,
    )
    try:
        plan = _DeliveryPlan(
            hosts=prepare_hosts(host_entries(smtphosts or settings.smtphosts)),
            delivery=_resolve_delivery_options(
                settings=settings,
                overrides=_DeliveryOverrides(
                    credentials=credentials,
                    use_starttls=use_starttls,
                    starttls_verify=starttls_verify,
                    timeout=timeout,
                    local_hostname=local_hostname,
                    deadline=delivery_deadline,
                ),
            ),
            transport=transport if transport is not None else DEFAULT_TRANSPORT,
        )
        check_subject(mail_subject)
        check_body(plain_body=mail_body, html_body=mail_body_html)
        # Every header block is built before the first delivery, so a header the
        # email package refuses fails the call before any recipient was sent to.
        envelopes = list(zip(recipients, envelope_header_lines(sender=mail_from, subject=mail_subject, recipients=recipients), strict=True))
        body = compose_body_once(
            MessageContent(plain_body=mail_body, html_body=mail_body_html, attachments=attachments),
            raise_on_violation=security.raise_on_violation,
        )
        try:
            failed_recipients = [
                recipient
                for recipient, header_lines in envelopes
                if not _deliver_composed(sender=mail_from, recipient=recipient, header_lines=header_lines, body=body, plan=plan)
            ]
        finally:
            body.close()
    finally:
        close_attachments(attachments)

    if failed_recipients:
        raise DeliveryError(
            f'following recipients failed "{failed_recipients}" on all of following hosts : "{plan.hosts}"',
            failed_recipients=tuple(failed_recipients),
            hosts=plan.hosts,
        )

    return True


@dataclass(frozen=True)
class _DeliveryOverrides:
    """The delivery keywords `send` received; `None` means "take it from the settings"."""

    credentials: tuple[str, str] | None = field(repr=False)
    use_starttls: bool | None
    starttls_verify: bool | None
    timeout: float | None
    local_hostname: str | None
    deadline: float | None


@dataclass(frozen=True)
class _DeliveryPlan:
    """Where and how every recipient of one `send()` call is delivered."""

    hosts: tuple[str, ...]
    delivery: DeliveryOptions
    transport: Transport


def _resolve_delivery_options(*, settings: ConfMail, overrides: _DeliveryOverrides) -> DeliveryOptions:
    """Resolve per-call overrides against configuration defaults.

    Centralises option resolution so callers remain declarative, returning
    an immutable snapshot applied to each SMTP attempt. Pure function.

    Args:
        settings: The `ConfMail` whose values fill in anything not passed explicitly.
        overrides: The delivery keywords supplied by `send`.

    Returns:
        Frozen options object consumed by the delivery helpers.

    Raises:
        InvalidInputError: If the resolved credentials, timeout, local_hostname, or deadline is refused.
    """
    credentials = overrides.credentials or settings.resolved_credentials()
    check_credentials(credentials)
    use_starttls = bool(overrides.use_starttls if overrides.use_starttls is not None else settings.smtp_use_starttls)
    starttls_verify = bool(overrides.starttls_verify if overrides.starttls_verify is not None else settings.smtp_starttls_verify)
    timeout = float(overrides.timeout if overrides.timeout is not None else settings.smtp_timeout)
    check_timeout(timeout)
    if overrides.local_hostname is not None:
        check_local_hostname(overrides.local_hostname, label="local_hostname")
    local_hostname = overrides.local_hostname if overrides.local_hostname is not None else settings.smtp_local_hostname
    if overrides.deadline is not None:
        check_seconds(overrides.deadline, label="delivery_deadline")
    deadline = overrides.deadline if overrides.deadline is not None else settings.smtp_delivery_deadline
    return DeliveryOptions(
        credentials=credentials,
        use_starttls=use_starttls,
        starttls_verify=starttls_verify,
        timeout=timeout,
        local_hostname=local_hostname,
        deadline=deadline,
    )


def _resolve_attachment_security_options(  # noqa: PLR0913 - one keyword-only override per independent security policy
    *,
    settings: ConfMail,
    explicit_allowed_extensions: frozenset[str] | None,
    explicit_blocked_extensions: frozenset[str] | None,
    explicit_allowed_directories: frozenset[pathlib.Path] | None,
    explicit_blocked_directories: frozenset[pathlib.Path] | None,
    explicit_max_size_bytes: int | None,
    explicit_allow_symlinks: bool | None,
    explicit_raise_on_violation: bool | None,
) -> AttachmentSecurityOptions:
    """Resolve per-call security overrides against configuration defaults.

    Centralises security option resolution so callers remain declarative.
    Pure function.

    Note:
        For extension and directory sets, `None` means "use the default"
        while an empty frozenset means "no restrictions". To distinguish,
        pass an explicit empty frozenset to override the default.

    Args:
        settings: The `ConfMail` whose values fill in anything not passed explicitly.
        explicit_allowed_extensions: Optional override supplied by `send`.
            When `None`, the corresponding `conf` default is used.
        explicit_blocked_extensions: Optional override supplied by `send`.
            When `None`, the corresponding `conf` default is used.
        explicit_allowed_directories: Optional override supplied by `send`.
            When `None`, the corresponding `conf` default is used.
        explicit_blocked_directories: Optional override supplied by `send`.
            When `None`, the corresponding `conf` default is used.
        explicit_max_size_bytes: Optional override supplied by `send`. When
            `None`, the corresponding `conf` default is used.
        explicit_allow_symlinks: Optional override supplied by `send`. When
            `None`, the corresponding `conf` default is used.
        explicit_raise_on_violation: Optional override supplied by `send`.
            When `None`, the corresponding `conf` default is used.

    Returns:
        Frozen options object consumed by security validation.
    """
    # Use sentinel pattern: None means "use default", explicit value overrides
    # A keyword set is normalised like the ConfMail field, so {".EXE"} blocks x.exe here too.
    allowed_ext = normalise_extensions(explicit_allowed_extensions) if explicit_allowed_extensions is not None else settings.attachment_allowed_extensions
    blocked_ext = normalise_extensions(explicit_blocked_extensions) if explicit_blocked_extensions is not None else settings.attachment_blocked_extensions
    allowed_dirs = explicit_allowed_directories if explicit_allowed_directories is not None else settings.attachment_allowed_directories
    blocked_dirs = explicit_blocked_directories if explicit_blocked_directories is not None else settings.attachment_blocked_directories
    max_size = explicit_max_size_bytes if explicit_max_size_bytes is not None else settings.attachment_max_size_bytes
    allow_symlinks = explicit_allow_symlinks if explicit_allow_symlinks is not None else settings.attachment_allow_symlinks
    raise_on_violation = explicit_raise_on_violation if explicit_raise_on_violation is not None else settings.attachment_raise_on_security_violation

    return AttachmentSecurityOptions(
        allowed_extensions=allowed_ext,
        blocked_extensions=blocked_ext,
        allowed_directories=allowed_dirs,
        blocked_directories=blocked_dirs,
        max_size_bytes=max_size,
        allow_symlinks=allow_symlinks,
        raise_on_violation=raise_on_violation,
        max_count=settings.attachment_max_count,
    )


# Bounds one logged failure line so a hostile or chatty server reply cannot
# flood the log.
_FAILURE_TEXT_LIMIT: Final[int] = 200


def _describe_failure(error: BaseException) -> str:
    """Return a one-line, credential-free description of a delivery failure.

    The per-host failure log used to attach the whole exception. An
    exception raised while encoding SMTP AUTH quotes the AUTH string,
    password included, in its repr, and structured loggers serialise that
    repr. Only the text of an `OSError` is kept (every
    `smtplib.SMTPException` is one): for the stdlib transport it comes from
    the OS, the TLS layer or the server reply. A custom `Transport` can raise
    an `OSError` with any text, and that text is logged as given. Anything
    else is logged by type name only.

    Args:
        error: The exception raised while delivering to one host.

    Returns:
        A one-line, credential-free description, truncated to `_FAILURE_TEXT_LIMIT` characters.

    Examples:
        >>> _describe_failure(ValueError("anything"))
        'ValueError'
        >>> _describe_failure(smtplib.SMTPAuthenticationError(535, b"5.7.8 invalid"))
        'SMTPAuthenticationError 535 5.7.8 invalid'
    """
    name = type(error).__name__
    if isinstance(error, smtplib.SMTPResponseException):
        reply = error.smtp_error
        text = reply.decode("utf-8", "replace") if isinstance(reply, bytes) else str(reply)
        return printable(f"{name} {error.smtp_code} {text}")[:_FAILURE_TEXT_LIMIT]
    if isinstance(error, OSError):
        return printable(f"{name}: {error}")[:_FAILURE_TEXT_LIMIT]
    return name


def _deliver_to_any_host(*, sender: str, recipient: str, message: IO[bytes], plan: _DeliveryPlan) -> bool:
    """Attempt delivery of one composed message across hosts until one succeeds.

    Encapsulates failover logic to keep orchestration linear. The same
    message stream is rewound and reused for every host attempt. Performs
    network I/O, and logs one credential-free WARNING per failed host (no
    traceback attached).

    Args:
        sender: Envelope sender address.
        recipient: Envelope recipient address.
        message: The complete message for this recipient (headers and body).
        plan: Hosts to try in order, resolved delivery options, and the transport.

    Returns:
        `True` if any host accepts the message; `False` otherwise.
    """
    for host in plan.hosts:
        try:
            # A host that read part of the message and failed leaves the stream mid-way;
            # every attempt starts from the first byte, whatever the transport does.
            message.seek(0)
            plan.transport.deliver(
                host=host,
                sender=sender,
                recipient=recipient,
                message=message,
                delivery=plan.delivery,
            )
            # sender, recipient and host normally reach here already
            # validated (no control characters), but the log call cleans
            # them again as defense in depth: nothing upstream of this
            # call is trusted to be the last guard against a forged log
            # line, and `_deliver_to_any_host` is reachable directly
            # (tests do exactly that) without going through `send()`'s
            # own validation first.
            logger.debug(
                'mail sent to "%s" via host "%s"',
                printable(recipient),
                printable(host),
                extra={"sender": printable(sender), "recipient": printable(recipient), "host": printable(host)},
            )
            return True
        except Exception as error:
            clean_recipient = printable(recipient)
            clean_host = printable(host)
            warning_call = (
                'can not send mail to "%s" via host "%s": %s',
                (clean_recipient, clean_host, _describe_failure(error)),
                {
                    "sender": printable(sender),
                    "recipient": clean_recipient,
                    "host": clean_host,
                    "error_type": type(error).__name__,
                    "smtp_code": getattr(error, "smtp_code", None),
                },
            )
        # Logged OUTSIDE the except block: once that block exits, this
        # host's failure is no longer the active exception, so a handler
        # or formatter that itself raises (handleError, a broken sink)
        # cannot chain it in as __context__ and print it via "During
        # handling of the above exception ...". Reached only through the
        # except branch above (the try's success path returns already).
        message_text, args, extra = warning_call
        logger.warning(message_text, *args, extra=extra)
    return False


def _deliver_composed(*, sender: str, recipient: str, header_lines: bytes, body: IO[bytes], plan: _DeliveryPlan) -> bool:
    """Build recipient's message from its header block and the shared body, deliver it, and close it.

    Args:
        sender: Envelope sender address.
        recipient: Envelope recipient address.
        header_lines: This recipient's header block.
        body: The shared, already-composed message body.
        plan: Hosts to try in order, resolved delivery options, and the transport.

    Returns:
        `True` if any host accepts the message; `False` otherwise.
    """
    message = message_for(header_lines, body)
    try:
        return _deliver_to_any_host(sender=sender, recipient=recipient, message=message, plan=plan)
    finally:
        message.close()


__all__ = [
    "DANGEROUS_DIRECTORIES_POSIX",
    "DANGEROUS_DIRECTORIES_WINDOWS",
    "DANGEROUS_EXTENSIONS_POSIX",
    "DANGEROUS_EXTENSIONS_WINDOWS",
    "EMAIL_PATTERN",
    "SENSITIVE_PATH_PATTERNS",
    "AttachmentPayload",
    "AttachmentSecurityError",
    "AttachmentSecurityOptions",
    "AttachmentViolation",
    "ConfMail",
    "DeliveryOptions",
    "SmtplibTransport",
    "Transport",
    "conf",
    "logger",
    "send",
    "validate_email_address",
    "validate_smtp_host",
]
