"""## btx_lib_mail.lib_mail {#module-btx-lib-mail-lib-mail}

**Purpose:** Provide the SMTP delivery boundary for the library. The module
collects configuration, normalises user input, and renders multipart messages so
adapters such as the CLI can treat delivery as a single call.

**Contents:**
- `AttachmentPayload` — frozen attachment payload supplied to the MIME renderer.
- `ConfMail` — Pydantic configuration surface shared across transports.
- `DeliveryOptions` — resolved runtime options derived from configuration.
- `send` — public orchestration entry point.

**System Role:** Matches `docs/systemdesign/module_reference.md#feature-cli-components`
by translating intent gathered by the CLI into SMTP side effects while keeping
configuration flow and delivery flow separated.
"""

from __future__ import annotations

from dataclasses import dataclass
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
import logging
import pathlib
import re
import smtplib
import ssl
from collections.abc import Iterable, Sequence
from typing import Any, Final, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator


logger = logging.getLogger("btx_lib_mail")

EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
"""Compiled regex used by :func:`_is_valid_email_address`."""


@dataclass(frozen=True)
class AttachmentPayload:
    """### AttachmentPayload {#lib-mail-attachmentpayload}

    **Purpose:** Preserve the filename and bytes read from disk so MIME
    rendering remains declarative and reproducible.

    **Fields:**
    - `filename: str` — Basename surfaced in the `Content-Disposition` header.
    - `content: bytes` — UTF-8 agnostic payload already read from disk.

    Instances are immutable (`frozen=True`) so helpers can rely on their
    stability across retries.
    """

    filename: str
    content: bytes


class ConfMail(BaseModel):
    """### ConfMail {#lib-mail-confmail}

    **Purpose:** Serve as the authoritative SMTP configuration object, merging
    CLI options, environment variables, and defaults while enforcing type and
    range checks.

    **Fields:**
    - `smtphosts: list[str] = []` — Ordered hosts in `host[:port]` form. Empty
      by default so callers must supply at least one host.
    - `raise_on_missing_attachments: bool = True` — When `True`, missing files
      raise `FileNotFoundError`; otherwise the module logs a warning and
      continues.
    - `raise_on_invalid_recipient: bool = True` — When `True`, invalid addresses
      raise `ValueError`; otherwise a warning is logged and delivery skips the
      address.
    - `smtp_username: str | None = None` and `smtp_password: str | None = None`
      — Optional credentials; both must be populated to enable authentication.
    - `smtp_use_starttls: bool = True` — Enables `STARTTLS` negotiation before
      authentication when supported by the server.
    - `smtp_timeout: float = 30.0` — Socket timeout in seconds applied to SMTP
      connections.

    **Interactions:** The CLI resolves its defaults through this model, and
    `send` reads resolved values when per-call overrides are absent.
    """

    smtphosts: list[str] = Field(default_factory=list)
    raise_on_missing_attachments: bool = True
    raise_on_invalid_recipient: bool = True
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_starttls: bool = True
    smtp_timeout: float = 30.0

    model_config = ConfigDict(validate_assignment=True)

    @field_validator("smtphosts", mode="before")
    @classmethod
    def _coerce_smtphosts(cls, value: Any) -> list[str]:
        """Coerce user input into a validated host list before assignment.

        Why
            Ensures assignment is resilient to ``None``, strings, and iterables.

        Inputs
        ------
        value:
            Raw value provided to the model (``None`` | ``str`` | iterable).

        Outputs
        -------
        list[str]
            Normalised host collection.

        Side Effects
        ------------
        None.
        """

        return _collect_host_inputs(value)

    def resolved_credentials(self) -> tuple[str, str] | None:
        """### resolved_credentials() -> tuple[str, str] | None {#lib-mail-confmail-resolved-credentials}

        **Purpose:** Provide downstream helpers with a single optional tuple
        rather than juggling two separate optional strings.

        **Returns:** `(username, password)` when both `smtp_username` and
        `smtp_password` are populated; `None` otherwise.
        """

        if self.smtp_username and self.smtp_password:
            return self.smtp_username, self.smtp_password
        return None


conf: ConfMail = ConfMail()
"""Global SMTP configuration surface used when per-call overrides are absent."""


def send(
    mail_from: str,
    mail_recipients: str | Sequence[str],
    mail_subject: str,
    mail_body: str = "",
    mail_body_html: str = "",
    smtphosts: Sequence[str] | None = None,
    attachment_file_paths: Sequence[pathlib.Path] | None = None,
    *,
    credentials: tuple[str, str] | None = None,
    use_starttls: bool | None = None,
    timeout: float | None = None,
) -> bool:
    """### send(...) -> bool {#lib-mail-send}

    **Purpose:** Provide the library/CLI façade that turns validated intent
    (sender, recipients, message bodies, attachments) into SMTP activity while
    honouring delivery policies defined in `ConfMail`.

    **Parameters:**
    - `mail_from: str` — Envelope sender address. Must be a syntactically valid
      email.
    - `mail_recipients: str | Sequence[str]` — Single recipient or iterable of
      recipients. Values are trimmed, deduplicated, lower-cased, and validated.
    - `mail_subject: str` — Subject line; UTF-8 is supported.
    - `mail_body: str = ""` — Optional plain-text body.
    - `mail_body_html: str = ""` — Optional HTML body.
    - `smtphosts: Sequence[str] | None = None` — Override host list. When
      `None`, the helper falls back to `conf.smtphosts`.
    - `attachment_file_paths: Sequence[pathlib.Path] | None = None` — Optional
      iterable of filesystem paths. Each existing file becomes an attachment.
    - `credentials: tuple[str, str] | None = None` — Override credentials. When
      omitted, `conf.resolved_credentials()` is used.
    - `use_starttls: bool | None = None` — Override STARTTLS preference. When
      `None`, the helper uses `conf.smtp_use_starttls`.
    - `timeout: float | None = None` — Override socket timeout in seconds. When
      `None`, the helper uses `conf.smtp_timeout`.

    **Returns:** `bool` — Always `True` when all deliveries succeed. A failure
    raises instead of returning `False`.

    **Raises:**
    - `ValueError` — When no valid recipients remain after validation.
    - `FileNotFoundError` — When required attachments are missing and
      `conf.raise_on_missing_attachments` is `True`.
    - `RuntimeError` — When every SMTP host fails for a recipient; the error
      lists the affected recipients and host set.

    **Example:**
    >>> from unittest import mock
    >>> sentinel = mock.MagicMock()
    >>> _ = mock.patch("smtplib.SMTP", sentinel).start()
    >>> conf.smtphosts = ["smtp.example.com"]
    >>> send(
    ...     mail_from="sender@example.com",
    ...     mail_recipients="receiver@example.com",
    ...     mail_subject="Hello",
    ... )
    True
    >>> _ = mock.patch.stopall()
    """

    recipients = _prepare_recipients(mail_recipients)
    attachments = _prepare_attachments(tuple(attachment_file_paths or ()))
    hosts = _prepare_hosts(tuple(smtphosts or conf.smtphosts))

    delivery = _resolve_delivery_options(
        explicit_credentials=credentials,
        explicit_starttls=use_starttls,
        explicit_timeout=timeout,
    )

    failed_recipients: list[str] = []
    for recipient in recipients:
        if not _deliver_to_any_host(
            sender=mail_from,
            recipient=recipient,
            subject=mail_subject,
            plain_body=mail_body,
            html_body=mail_body_html,
            hosts=hosts,
            attachments=attachments,
            delivery=delivery,
        ):
            failed_recipients.append(recipient)

    if failed_recipients:
        raise RuntimeError(f'following recipients failed "{failed_recipients}" on all of following hosts : "{hosts}"')

    return True


@dataclass(frozen=True)
class DeliveryOptions:
    """### DeliveryOptions {#lib-mail-deliveryoptions}

    **Purpose:** Capture the resolved runtime knobs for a single delivery attempt
    so low-level helpers receive one immutable object.

    **Fields:**
    - `credentials: tuple[str, str] | None` — `(username, password)` pair or
      `None` when anonymous delivery is requested.
    - `use_starttls: bool` — `True` enables `STARTTLS` handshakes.
    - `timeout: float` — Socket timeout (seconds) applied to SMTP connections.
    """

    credentials: tuple[str, str] | None
    use_starttls: bool
    timeout: float


def _resolve_delivery_options(
    *,
    explicit_credentials: tuple[str, str] | None,
    explicit_starttls: bool | None,
    explicit_timeout: float | None,
) -> DeliveryOptions:
    """Resolve per-call overrides against configuration defaults.

    Why
        Centralises option resolution so callers remain declarative.

    Inputs
    ------
    explicit_credentials / explicit_starttls / explicit_timeout:
        Optional overrides supplied by :func:`send`.

    What
        Returns an immutable snapshot applied to each SMTP attempt.

    Outputs
    -------
    DeliveryOptions
        Frozen options object consumed by the delivery helpers.

    Side Effects
    ------------
    None; pure function.
    """

    credentials = explicit_credentials or conf.resolved_credentials()
    use_starttls = bool(explicit_starttls if explicit_starttls is not None else conf.smtp_use_starttls)
    timeout = float(explicit_timeout if explicit_timeout is not None else conf.smtp_timeout)
    return DeliveryOptions(credentials=credentials, use_starttls=use_starttls, timeout=timeout)


def _deliver_to_any_host(
    *,
    sender: str,
    recipient: str,
    subject: str,
    plain_body: str,
    html_body: str,
    hosts: tuple[str, ...],
    attachments: tuple[AttachmentPayload, ...],
    delivery: DeliveryOptions,
) -> bool:
    """Attempt delivery across hosts until one succeeds.

    Why
        Encapsulates failover logic to keep orchestration linear.

    Inputs
    ------
    sender, recipient, subject, plain_body, html_body:
        Message metadata and content to deliver.
    hosts:
        Ordered tuple of host strings to try in sequence.
    attachments:
        Attachment payloads prepared earlier.
    delivery:
        Resolved delivery options (credentials, STARTTLS, timeout).

    What
        Iterates hosts, invoking :func:`_deliver_via_host` until success.

    Outputs
    -------
    bool
        ``True`` if any host accepts the message; ``False`` otherwise.

    Side Effects
    ------------
    Logs warnings when hosts fail; delegates to :func:`_deliver_via_host`.
    """

    for host in hosts:
        try:
            _deliver_via_host(
                host=host,
                sender=sender,
                recipient=recipient,
                subject=subject,
                plain_body=plain_body,
                html_body=html_body,
                attachments=attachments,
                delivery=delivery,
            )
            logger.debug(f'mail sent to "{recipient}" via host "{host}"')
            return True
        except Exception:
            logger.warning(
                'can not send mail to "%s" via host "%s"',
                recipient,
                host,
                exc_info=True,
            )
    return False


def _deliver_via_host(
    *,
    host: str,
    sender: str,
    recipient: str,
    subject: str,
    plain_body: str,
    html_body: str,
    attachments: tuple[AttachmentPayload, ...],
    delivery: DeliveryOptions,
) -> None:
    """Deliver a message through a specific SMTP host.

    Why
        Encapsulates the SMTP session lifecycle (connect → starttls → login →
        send).

    Inputs
    ------
    host:
        Host string containing hostname and optional port.
    sender / recipient / subject / plain_body / html_body / attachments:
        Message attributes to deliver.
    delivery:
        Resolved options controlling STARTTLS, credentials, timeout.

    What
        Opens an SMTP session, applies STARTTLS/login as needed, and sends the message.

    Outputs
    -------
    None

    Side Effects
    ------------
    Network I/O, optional STARTTLS handshake, optional authentication.
    """

    hostname, port = _split_host_and_port(host)
    with smtplib.SMTP(hostname, port=port or 0, timeout=delivery.timeout) as smtp_connection:
        if delivery.use_starttls:
            smtp_connection.starttls(context=ssl.create_default_context())
        if delivery.credentials is not None:
            username, password = delivery.credentials
            smtp_connection.login(username, password)

        message = _compose_message(
            sender=sender,
            recipient=recipient,
            subject=subject,
            plain_body=plain_body,
            html_body=html_body,
            attachments=attachments,
        )
        smtp_connection.sendmail(sender, recipient, message)


def _compose_message(
    *,
    sender: str,
    recipient: str,
    subject: str,
    plain_body: str,
    html_body: str,
    attachments: tuple[AttachmentPayload, ...],
) -> str:
    """Construct the MIME message string for the SMTP session.

    Why
        Provides a single location for header and body assembly.

    Inputs
    ------
    sender / recipient / subject:
        Header values.
    plain_body / html_body:
        Optional body content.
    attachments:
        Prepared attachment payloads.

    What
        Builds a multipart message consistent with SMTP expectations.

    Outputs
    -------
    str
        UTF-8 encoded message returned via ``as_string()``.

    Side Effects
    ------------
    None.
    """

    message = MIMEMultipart()
    message["Subject"] = Header(subject, "utf-8").encode()
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)

    if plain_body:
        message.attach(MIMEText(plain_body, "plain", "utf-8"))
    if html_body:
        message.attach(MIMEText(html_body, "html", "utf-8"))
    for attachment in attachments:
        message.attach(_render_attachment(attachment))

    return message.as_string()


def _render_attachment(attachment: AttachmentPayload) -> MIMEBase:
    """Wrap an :class:`AttachmentPayload` as a MIME part.

    Why
        Keeps MIME encoding concerns isolated from core assembly.

    Inputs
    ------
    attachment:
        Frozen payload harvested from disk.

    What
        Encodes bytes and sets headers so the part can be attached.

    Outputs
    -------
    MIMEBase
        Base64-encoded part ready for ``message.attach``.

    Side Effects
    ------------
    None.
    """

    part = MIMEBase("application", "octet-stream")
    part.set_payload(attachment.content)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{attachment.filename}"')
    return part


def _prepare_attachments(paths: tuple[pathlib.Path, ...]) -> tuple[AttachmentPayload, ...]:
    """Normalise attachment paths into frozen payloads.

    Why
        Validates attachment existence before SMTP attempts begin.

    Inputs
    ------
    paths:
        Tuple of candidate filesystem paths (may be empty).

    What
        Resolves existing files and emits immutable payloads.

    Outputs
    -------
    tuple[AttachmentPayload, ...]
        Resolved payloads.

    Side Effects
    ------------
    Reads file bytes when paths exist; logs or raises when missing.
    """

    prepared: list[AttachmentPayload] = []
    for path in paths:
        absolute_path = path.resolve()
        if absolute_path.is_file():
            prepared.append(
                AttachmentPayload(
                    filename=absolute_path.name,
                    content=absolute_path.read_bytes(),
                )
            )
            continue
        if conf.raise_on_missing_attachments:
            raise FileNotFoundError(f'Attachment File "{absolute_path}" can not be found')
        logger.warning(f'Attachment File "{absolute_path}" can not be found')
    return tuple(prepared)


def _prepare_hosts(hosts: tuple[str, ...]) -> tuple[str, ...]:
    """Return a deduplicated tuple of normalised host strings.

    Why
        Ensures the host list is stable, stripped, and free of empties.

    Inputs
    ------
    hosts:
        Tuple of raw host strings collected from config and overrides.

    What
        Strips formatting, removes blanks, and deduplicates while preserving order.

    Outputs
    -------
    tuple[str, ...]
        Ordered, deduplicated host strings.

    Side Effects
    ------------
    None.
    """

    normalised = [_normalise_host(entry) for entry in hosts]
    filtered = [value for value in normalised if value]
    unique = tuple(dict.fromkeys(filtered))
    if not unique:
        raise ValueError("no valid smtphost passed")
    return unique


def _prepare_recipients(recipients: str | Sequence[str]) -> tuple[str, ...]:
    """Return a deduplicated tuple of valid, lower-cased recipient addresses.

    Why
        Consolidates parsing, trimming, deduplication, and validation.

    Inputs
    ------
    recipients:
        Single email or sequence of emails supplied by callers.

    What
        Produces a ready-to-send tuple after validation and deduplication.

    Outputs
    -------
    tuple[str, ...]
        Validated, deduplicated, lower-cased emails.

    Side Effects
    ------------
    Logs warnings when invalid recipients are tolerated.
    """

    if isinstance(recipients, str):
        raw_items: Iterable[str] = (recipients,)
    elif isinstance(recipients, Sequence):  # pyright: ignore[reportUnnecessaryIsInstance]
        raw_items = recipients
    else:  # pragma: no cover - defensive guard
        raise RuntimeError("invalid type of mail_addresses")

    cleaned = [_normalise_email_address(item) for item in raw_items]
    filtered = [value for value in cleaned if value]
    unique = tuple(dict.fromkeys(filtered))

    valid: list[str] = []
    for entry in unique:
        if _is_valid_email_address(entry):
            valid.append(entry)
            continue
        if conf.raise_on_invalid_recipient:
            raise ValueError(f"invalid recipient {entry}")
        logger.warning(f"invalid recipient {entry}")

    if not valid:
        raise ValueError("no valid recipients")
    return tuple(valid)


def _normalise_email_address(candidate: str) -> str:
    """Trim whitespace/quotes and lower-case the candidate email.

    Why
        Email addresses should compare case-insensitively in our context.

    Inputs
    ------
    candidate:
        Raw string supplied by the caller.

    What
        Returns a lower-case, trimmed representation that supports deduping.

    Outputs
    -------
    str
        Normalised email address (may be empty string).

    Side Effects
    ------------
    None.
    """

    return candidate.strip().strip('"').strip("'").lower()


def _normalise_host(candidate: str) -> str:
    """Trim whitespace/quotes from the candidate host entry.

    Why
        Host strings from .env files often contain whitespace; this removes it.

    Inputs
    ------
    candidate:
        Raw host string.

    What
        Removes surrounding quotes/whitespace without altering order.

    Outputs
    -------
    str
        Normalised host string.

    Side Effects
    ------------
    None.
    """

    return candidate.strip().strip('"').strip("'")


def _collect_host_inputs(value: Any) -> list[str]:
    """Coerce user input into a list of host strings.

    Why
        Supports ``None``, strings, and iterables while validating entries.

    Inputs
    ------
    value:
        Caller-supplied host configuration.

    What
        Converts supported forms into a list while validating element types.

    Outputs
    -------
    list[str]
        Normalised list of hosts (possibly empty).

    Side Effects
    ------------
    None.
    """

    if value is None:
        return []
    if isinstance(value, str):
        return [_normalise_host(value)]
    if isinstance(value, Iterable):  # type: ignore[reportUnnecessaryIsInstance]
        hosts: list[str] = []
        for item in cast(Iterable[Any], value):
            if not isinstance(item, str):
                raise ValueError("smtphosts entries must be strings")
            hosts.append(_normalise_host(item))
        return hosts
    raise ValueError("smtphosts must be a string, list of strings, or tuple of strings")


def _split_host_and_port(address: str) -> tuple[str, int | None]:
    """Separate host and port components when specified.

    Why
        Allows callers to accept ``host:port`` while passing integers to SMTP.

    Inputs
    ------
    address:
        Host string with optional ``:<port>`` suffix.

    What
        Parses the suffix when present and casts it to ``int``.

    Outputs
    -------
    tuple[str, int | None]
        Hostname and optional port number.

    Side Effects
    ------------
    None.
    """

    if ":" not in address:
        return address, None
    host, port_str = address.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError as exc:  # pragma: no cover - defensive guard
        raise ValueError(f'invalid smtp port in "{address}"') from exc
    return host, port


def _is_valid_email_address(value: str) -> bool:
    """Return ``True`` when the value matches a simple email pattern.

    Why
        Prevents avoidable SMTP failures by checking syntax early.

    What
        Applies a conservative regex that covers common email formats.

    Inputs
    ------
    value:
        Candidate email string.

    Outputs
    -------
    bool
        ``True`` when syntax matches; ``False`` otherwise.

    Side Effects
    ------------
    None.

    Examples
    --------
    >>> _is_valid_email_address("user@example.com")
    True
    >>> _is_valid_email_address("invalid@")
    False
    """

    return bool(EMAIL_PATTERN.fullmatch(value))
