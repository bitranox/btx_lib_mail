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

import base64
import io
import logging
import mimetypes
import pathlib
import re
import smtplib
import ssl
import sys
import tempfile
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from email import policy as email_policy
from email.generator import BytesGenerator
from email.message import EmailMessage
from email.utils import formatdate
from enum import Enum
from typing import IO, Any, Final, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

logger = logging.getLogger("btx_lib_mail")

EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


# ---------------------------------------------------------------------------
# Attachment Security: Public Constants
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS_POSIX: Final[frozenset[str]] = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".csh",
        ".py",
        ".pyw",
        ".pyc",
        ".pyo",
        ".pl",
        ".pm",
        ".rb",
        ".php",
        ".js",
        ".mjs",
        ".cjs",
        ".so",
        ".dylib",
        ".bin",
        ".run",
        ".appimage",
        ".elf",
        ".out",
        ".jar",
        ".war",
        ".ear",
        ".deb",
        ".rpm",
        ".apk",
    }
)
"""Dangerous file extensions for POSIX systems (Linux/macOS)."""

DANGEROUS_EXTENSIONS_WINDOWS: Final[frozenset[str]] = frozenset(
    {
        ".exe",
        ".com",
        ".bat",
        ".cmd",
        ".msi",
        ".msp",
        ".msc",
        ".ps1",
        ".ps2",
        ".psc1",
        ".psc2",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".ws",
        ".wsf",
        ".wsc",
        ".wsh",
        ".scr",
        ".pif",
        ".hta",
        ".cpl",
        ".inf",
        ".reg",
        ".dll",
        ".ocx",
        ".sys",
        ".drv",
        ".lnk",
        ".scf",
        ".url",
        ".gadget",
        ".application",
        ".jar",
        ".war",
        ".ear",
    }
)
"""Dangerous file extensions for Windows systems."""

DANGEROUS_DIRECTORIES_POSIX: Final[frozenset[pathlib.Path]] = frozenset(
    {
        pathlib.Path("/etc"),
        pathlib.Path("/var"),
        pathlib.Path("/root"),
        pathlib.Path("/boot"),
        pathlib.Path("/sys"),
        pathlib.Path("/proc"),
        pathlib.Path("/dev"),
        pathlib.Path("/usr/bin"),
        pathlib.Path("/usr/sbin"),
        pathlib.Path("/bin"),
        pathlib.Path("/sbin"),
    }
)
"""Sensitive directories blocked by default on POSIX systems."""

DANGEROUS_DIRECTORIES_WINDOWS: Final[frozenset[pathlib.Path]] = frozenset(
    {
        pathlib.Path("C:/Windows"),
        pathlib.Path("C:/Windows/System32"),
        pathlib.Path("C:/Program Files"),
        pathlib.Path("C:/Program Files (x86)"),
        pathlib.Path("C:/ProgramData"),
    }
)
"""Sensitive directories blocked by default on Windows systems."""

SENSITIVE_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "/.ssh/",
    "/id_rsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/authorized_keys",
    "/known_hosts",
    "/.gnupg/",
    "/private.key",
    "/secret",
    "/.env",
    "/credentials",
    "/password",
    "/token",
    "/.aws/credentials",
    "/.kube/config",
)
"""Path patterns that indicate sensitive files (always blocked)."""


def _default_blocked_extensions() -> frozenset[str]:
    """Return the OS-appropriate set of dangerous file extensions.

    Why
        Provides sensible defaults without requiring manual configuration.

    Outputs
    -------
    frozenset[str]
        Dangerous extensions for the current operating system.
    """
    if sys.platform == "win32":
        return DANGEROUS_EXTENSIONS_WINDOWS
    return DANGEROUS_EXTENSIONS_POSIX


def _default_blocked_directories() -> frozenset[pathlib.Path]:
    """Return the OS-appropriate set of dangerous directories.

    Why
        Provides sensible defaults without requiring manual configuration.

    Outputs
    -------
    frozenset[pathlib.Path]
        Dangerous directories for the current operating system.
    """
    if sys.platform == "win32":
        return DANGEROUS_DIRECTORIES_WINDOWS
    return DANGEROUS_DIRECTORIES_POSIX


# ---------------------------------------------------------------------------
# Attachment Security: Violation category
# ---------------------------------------------------------------------------


class AttachmentViolation(str, Enum):
    """### AttachmentViolation {#lib-mail-attachmentviolation}

    **Purpose:** Enumerate the closed set of attachment security violation
    categories so callers match on a typed member instead of a bare string.

    Members subclass ``str`` (``str, Enum`` rather than 3.11+ ``StrEnum`` to keep
    the 3.10 baseline), so ``violation is AttachmentViolation.SYMLINK``,
    ``violation == "symlink"``, and JSON serialisation all behave as expected and
    the wire value is unchanged.
    """

    PATH_TRAVERSAL = "path_traversal"
    SYMLINK = "symlink"
    SENSITIVE_PATTERN = "sensitive_pattern"
    DIRECTORY = "directory"
    EXTENSION = "extension"
    SIZE = "size"


# ---------------------------------------------------------------------------
# Attachment Security: Exception
# ---------------------------------------------------------------------------


class AttachmentSecurityError(Exception):
    """Raised when an attachment violates security policies.

    **Purpose:** Provide a structured exception for attachment security
    violations so callers can handle or report them appropriately.

    **Fields:**
    - `path: pathlib.Path` — The offending attachment path.
    - `reason: str` — Human-readable description of the violation.
    - `violation_type: AttachmentViolation` — Category of the violation
      (`AttachmentViolation.SYMLINK`, `.EXTENSION`, `.SIZE`, etc.). Members
      subclass `str`, so `== "symlink"` comparisons keep working.
    """

    def __init__(self, path: pathlib.Path, reason: str, violation_type: AttachmentViolation) -> None:
        super().__init__(reason)
        self.path = path
        self.reason = reason
        self.violation_type = violation_type

    def __str__(self) -> str:
        # .value keeps the message text stable across Python versions, where
        # f-string formatting of a `str, Enum` member is inconsistent.
        return f"Attachment security violation ({self.violation_type.value}): {self.reason} [path={self.path}]"


"""Compiled regex used by :func:`validate_email_address`."""


@dataclass(frozen=True)
class AttachmentPayload:
    """### AttachmentPayload {#lib-mail-attachmentpayload}

    **Purpose:** Name a validated attachment and point at its source file so the
    bytes are read only while the message is streamed to the transport, not held
    in memory from preparation onward.

    **Fields:**
    - `filename: str` - Basename surfaced in the `Content-Disposition` header.
    - `source: pathlib.Path` - Validated path whose bytes are read at send time.

    Instances are immutable (`frozen=True`) so helpers can rely on their
    stability across retries.
    """

    filename: str
    source: pathlib.Path


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
    - `smtp_username: str | None = None` and `smtp_password: SecretStr | None = None`
      — Optional credentials; both must be populated to enable authentication.
      `smtp_password` is a `SecretStr`, so it is masked in `repr()` and
      `model_dump()`; call `.get_secret_value()` (or `resolved_credentials()`) to
      read the plaintext. A plain string assigned to it is coerced to `SecretStr`.
    - `smtp_use_starttls: bool = True` — Enables `STARTTLS` negotiation before
      authentication when supported by the server.
    - `smtp_starttls_verify: bool = True` — When `True`, the `STARTTLS` handshake
      verifies the server certificate and hostname (the secure default). Set to
      `False` for an internal relay whose certificate is self-signed or has a
      hostname mismatch: the traffic stays encrypted but the certificate is not
      validated. Has no effect when `smtp_use_starttls` is `False`.
    - `smtp_timeout: float = 30.0` — Socket timeout in seconds applied to SMTP
      connections.
    - `attachment_allowed_extensions: frozenset[str] | None = None` — When set,
      only these extensions are allowed (whitelist mode). When `None`, the
      blocked extensions list applies instead.
    - `attachment_blocked_extensions: frozenset[str]` — Extensions to reject.
      Ignored when `attachment_allowed_extensions` is set. Defaults to
      OS-specific dangerous extensions.
    - `attachment_allowed_directories: frozenset[pathlib.Path] | None = None` —
      When set, attachments must reside under one of these directories.
    - `attachment_blocked_directories: frozenset[pathlib.Path]` — Directories
      from which attachments cannot be read. Defaults to OS-specific sensitive
      directories.
    - `attachment_max_size_bytes: int | None = 26_214_400` — Maximum attachment
      size in bytes (default 25 MiB). `None` disables size checking.
    - `attachment_allow_symlinks: bool = False` — When `False`, symlinks are
      rejected; when `True`, symlinks are resolved and validated.
    - `attachment_raise_on_security_violation: bool = True` — When `True`,
      security violations raise `AttachmentSecurityError`; when `False`, they
      log a warning and skip the attachment.

    **Interactions:** The CLI resolves its defaults through this model, and
    `send` reads resolved values when per-call overrides are absent.
    """

    smtphosts: list[str] = Field(default_factory=list)
    raise_on_missing_attachments: bool = True
    raise_on_invalid_recipient: bool = True
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_use_starttls: bool = True
    smtp_starttls_verify: bool = True
    smtp_timeout: float = 30.0

    # Attachment security settings
    attachment_allowed_extensions: frozenset[str] | None = None
    attachment_blocked_extensions: frozenset[str] = Field(default_factory=_default_blocked_extensions)
    attachment_allowed_directories: frozenset[pathlib.Path] | None = None
    attachment_blocked_directories: frozenset[pathlib.Path] = Field(default_factory=_default_blocked_directories)
    attachment_max_size_bytes: int | None = 26_214_400  # 25 MiB
    attachment_allow_symlinks: bool = False
    attachment_raise_on_security_violation: bool = True

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

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

    @field_validator("smtp_timeout", mode="after")
    @classmethod
    def _validate_smtp_timeout(cls, value: float) -> float:
        """Reject non-positive timeout values at configuration time.

        Why
            A zero or negative socket timeout is never valid for SMTP connections.

        Inputs
        ------
        value:
            Timeout in seconds after Pydantic type coercion.

        Outputs
        -------
        float
            The validated positive timeout.

        Side Effects
        ------------
        None.
        """

        if value <= 0:
            raise ValueError(f"smtp_timeout must be positive, got {value}")
        return value

    @field_validator("attachment_allowed_extensions", "attachment_blocked_extensions", mode="before")
    @classmethod
    def _normalise_extensions(cls, value: Any) -> frozenset[str] | None:
        """Normalise extension sets to lowercase with leading dots.

        Why
            Extensions should compare case-insensitively and consistently.

        Inputs
        ------
        value:
            Raw extension set (None, set, frozenset, or iterable of strings).

        Outputs
        -------
        frozenset[str] | None
            Normalised extension set with lowercase, dot-prefixed extensions.
        """
        if value is None:
            return None
        if callable(value):
            # Handle default_factory case
            value = value()
        if not isinstance(value, (frozenset, set, list, tuple)):
            raise ValueError("extensions must be a set, frozenset, list, or tuple of strings")
        raw_list: list[object] = list(value)  # pyright: ignore[reportUnknownArgumentType]

        normalised: set[str] = set()
        for ext in raw_list:
            if not isinstance(ext, str):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise ValueError(f"extension must be a string, got {type(ext).__name__}")
            ext_lower = ext.lower().strip()
            if not ext_lower:
                continue
            if not ext_lower.startswith("."):
                ext_lower = "." + ext_lower
            normalised.add(ext_lower)
        return frozenset(normalised)

    @field_validator("attachment_allowed_directories", "attachment_blocked_directories", mode="before")
    @classmethod
    def _normalise_directories(cls, value: Any) -> frozenset[pathlib.Path] | None:
        """Normalise directory sets to resolved Path objects.

        Why
            Directories should be resolved for consistent comparison.

        Inputs
        ------
        value:
            Raw directory set (None, set, frozenset, or iterable of paths/strings).

        Outputs
        -------
        frozenset[pathlib.Path] | None
            Normalised directory set.
        """
        if value is None:
            return None
        if callable(value):
            # Handle default_factory case
            value = value()
        if not isinstance(value, (frozenset, set, list, tuple)):
            raise ValueError("directories must be a set, frozenset, list, or tuple")
        raw_list: list[object] = list(value)  # pyright: ignore[reportUnknownArgumentType]

        normalised: set[pathlib.Path] = set()
        for directory in raw_list:
            if isinstance(directory, str):
                normalised.add(pathlib.Path(directory))
            elif isinstance(directory, pathlib.Path):  # pyright: ignore[reportUnnecessaryIsInstance]
                normalised.add(directory)
            else:
                raise ValueError(f"directory must be a string or Path, got {type(directory).__name__}")
        return frozenset(normalised)

    @field_validator("attachment_max_size_bytes", mode="after")
    @classmethod
    def _validate_max_size(cls, value: int | None) -> int | None:
        """Validate that max size is positive when set.

        Why
            A zero or negative size limit would reject all attachments.

        Inputs
        ------
        value:
            Max size in bytes (None to disable checking).

        Outputs
        -------
        int | None
            The validated size limit.
        """
        if value is not None and value <= 0:
            raise ValueError(f"attachment_max_size_bytes must be positive, got {value}")
        return value

    def resolved_credentials(self) -> tuple[str, str] | None:
        """### resolved_credentials() -> tuple[str, str] | None {#lib-mail-confmail-resolved-credentials}

        **Purpose:** Provide downstream helpers with a single optional tuple
        rather than juggling two separate optional strings.

        **Returns:** `(username, password)` with the plaintext password when both
        `smtp_username` and `smtp_password` are populated; `None` otherwise.
        """

        password = self.smtp_password.get_secret_value() if self.smtp_password is not None else None
        if self.smtp_username and password:
            return self.smtp_username, password
        return None


conf: ConfMail = ConfMail()
"""Global SMTP configuration surface used when per-call overrides are absent."""


def send(  # noqa: PLR0913, PLR0917 - public API; the first 7 params are called positionally by existing consumers
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
    starttls_verify: bool | None = None,
    timeout: float | None = None,
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
    # Delivery seam (advanced/testing): override the SMTP transport adapter.
    transport: Transport | None = None,
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
    - `starttls_verify: bool | None = None` — Override STARTTLS certificate
      verification. When `None`, the helper uses `conf.smtp_starttls_verify`.
      `False` keeps the connection encrypted but skips certificate/hostname
      validation (for internal self-signed relays). Ignored unless STARTTLS runs.
    - `timeout: float | None = None` — Override socket timeout in seconds. When
      `None`, the helper uses `conf.smtp_timeout`.
    - `attachment_allowed_extensions: frozenset[str] | None = None` — Override
      allowed extensions (whitelist mode). When `None`, uses `conf` default.
    - `attachment_blocked_extensions: frozenset[str] | None = None` — Override
      blocked extensions. When `None`, uses `conf` default.
    - `attachment_allowed_directories: frozenset[pathlib.Path] | None = None` —
      Override allowed directories. When `None`, uses `conf` default.
    - `attachment_blocked_directories: frozenset[pathlib.Path] | None = None` —
      Override blocked directories. When `None`, uses `conf` default.
    - `attachment_max_size_bytes: int | None = None` — Override max attachment
      size in bytes. When `None`, uses `conf` default.
    - `attachment_allow_symlinks: bool | None = None` — Override symlink policy.
      When `None`, uses `conf` default.
    - `attachment_raise_on_security_violation: bool | None = None` — Override
      security violation behaviour. When `None`, uses `conf` default.
    - `raise_on_missing_attachments: bool | None = None` — Override
      `conf.raise_on_missing_attachments`. When `None`, uses `conf` default;
      `True` raises on missing, `False` logs warning and skips.
    - `raise_on_invalid_recipient: bool | None = None` — Override
      `conf.raise_on_invalid_recipient`. When `None`, uses `conf` default;
      `True` raises on invalid, `False` logs warning and skips.

    **Returns:** `bool` — Always `True` when all deliveries succeed. A failure
    raises instead of returning `False`.

    **Raises:**
    - `ValueError` — When no valid recipients remain after validation.
    - `FileNotFoundError` — When required attachments are missing and
      `conf.raise_on_missing_attachments` is `True`.
    - `AttachmentSecurityError` — When an attachment violates security policies
      and `attachment_raise_on_security_violation` is `True`.
    - `RuntimeError` — When every SMTP host fails for a recipient; the error
      lists the affected recipients and host set.

    **Example:**
    >>> class _NullTransport:  # a stand-in transport that accepts every message
    ...     def deliver(self, **kwargs: object) -> None:
    ...         return None
    >>> conf.smtphosts = ["smtp.example.com"]
    >>> send(
    ...     mail_from="sender@example.com",
    ...     mail_recipients="receiver@example.com",
    ...     mail_subject="Hello",
    ...     transport=_NullTransport(),
    ... )
    True
    """

    try:
        validate_email_address(mail_from)
    except ValueError:
        raise ValueError(f"invalid sender address: {mail_from!r}") from None

    # Resolve error handling parameters
    resolved_raise_on_missing = raise_on_missing_attachments if raise_on_missing_attachments is not None else conf.raise_on_missing_attachments
    resolved_raise_on_invalid = raise_on_invalid_recipient if raise_on_invalid_recipient is not None else conf.raise_on_invalid_recipient

    recipients = _prepare_recipients(mail_recipients, raise_on_invalid=resolved_raise_on_invalid)

    # Resolve security options
    security = _resolve_attachment_security_options(
        explicit_allowed_extensions=attachment_allowed_extensions,
        explicit_blocked_extensions=attachment_blocked_extensions,
        explicit_allowed_directories=attachment_allowed_directories,
        explicit_blocked_directories=attachment_blocked_directories,
        explicit_max_size_bytes=attachment_max_size_bytes,
        explicit_allow_symlinks=attachment_allow_symlinks,
        explicit_raise_on_violation=attachment_raise_on_security_violation,
    )

    attachments = _prepare_attachments(
        tuple(attachment_file_paths or ()),
        security,
        raise_on_missing=resolved_raise_on_missing,
    )
    hosts = _prepare_hosts(tuple(smtphosts or conf.smtphosts))

    delivery = _resolve_delivery_options(
        explicit_credentials=credentials,
        explicit_starttls=use_starttls,
        explicit_starttls_verify=starttls_verify,
        explicit_timeout=timeout,
    )

    active_transport = transport if transport is not None else _DEFAULT_TRANSPORT

    failed_recipients: list[str] = [
        recipient
        for recipient in recipients
        if not _deliver_to_any_host(
            sender=mail_from,
            recipient=recipient,
            subject=mail_subject,
            plain_body=mail_body,
            html_body=mail_body_html,
            hosts=hosts,
            attachments=attachments,
            delivery=delivery,
            transport=active_transport,
        )
    ]

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
    - `starttls_verify: bool` — `True` verifies the server certificate and
      hostname during `STARTTLS`; `False` keeps the traffic encrypted but skips
      verification (for internal self-signed relays).
    - `timeout: float` — Socket timeout (seconds) applied to SMTP connections.
    """

    credentials: tuple[str, str] | None
    use_starttls: bool
    starttls_verify: bool
    timeout: float


def _resolve_delivery_options(
    *,
    explicit_credentials: tuple[str, str] | None,
    explicit_starttls: bool | None,
    explicit_starttls_verify: bool | None,
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
    starttls_verify = bool(explicit_starttls_verify if explicit_starttls_verify is not None else conf.smtp_starttls_verify)
    timeout = float(explicit_timeout if explicit_timeout is not None else conf.smtp_timeout)
    if timeout <= 0:
        raise ValueError(f"smtp_timeout must be positive, got {timeout}")
    return DeliveryOptions(credentials=credentials, use_starttls=use_starttls, starttls_verify=starttls_verify, timeout=timeout)


@dataclass(frozen=True)
class AttachmentSecurityOptions:
    """### AttachmentSecurityOptions {#lib-mail-attachmentsecurityoptions}

    **Purpose:** Capture the resolved attachment security options for a single
    send operation so validation helpers receive one immutable object.

    **Fields:**
    - `allowed_extensions: frozenset[str] | None` — When set, only these
      extensions are allowed (whitelist mode).
    - `blocked_extensions: frozenset[str]` — Extensions to reject (ignored
      when whitelist is active).
    - `allowed_directories: frozenset[pathlib.Path] | None` — When set,
      attachments must reside under one of these directories.
    - `blocked_directories: frozenset[pathlib.Path]` — Directories from which
      attachments cannot be read.
    - `max_size_bytes: int | None` — Maximum attachment size in bytes.
    - `allow_symlinks: bool` — Whether symlinks are permitted.
    - `raise_on_violation: bool` — Whether violations raise or just warn.
    """

    allowed_extensions: frozenset[str] | None
    blocked_extensions: frozenset[str]
    allowed_directories: frozenset[pathlib.Path] | None
    blocked_directories: frozenset[pathlib.Path]
    max_size_bytes: int | None
    allow_symlinks: bool
    raise_on_violation: bool


def _resolve_attachment_security_options(  # noqa: PLR0913 - one keyword-only override per independent security policy
    *,
    explicit_allowed_extensions: frozenset[str] | None,
    explicit_blocked_extensions: frozenset[str] | None,
    explicit_allowed_directories: frozenset[pathlib.Path] | None,
    explicit_blocked_directories: frozenset[pathlib.Path] | None,
    explicit_max_size_bytes: int | None,
    explicit_allow_symlinks: bool | None,
    explicit_raise_on_violation: bool | None,
) -> AttachmentSecurityOptions:
    """Resolve per-call security overrides against configuration defaults.

    Why
        Centralises security option resolution so callers remain declarative.

    Inputs
    ------
    explicit_allowed_extensions / explicit_blocked_extensions / ... :
        Optional overrides supplied by :func:`send`. When `None`, the
        corresponding `conf` default is used.

    Note
    ----
    For extension and directory sets, `None` means "use the default" while an
    empty frozenset means "no restrictions". To distinguish, pass an explicit
    empty frozenset to override the default.

    Outputs
    -------
    AttachmentSecurityOptions
        Frozen options object consumed by security validation.

    Side Effects
    ------------
    None; pure function.
    """
    # Use sentinel pattern: None means "use default", explicit value overrides
    allowed_ext = explicit_allowed_extensions if explicit_allowed_extensions is not None else conf.attachment_allowed_extensions
    blocked_ext = explicit_blocked_extensions if explicit_blocked_extensions is not None else conf.attachment_blocked_extensions
    allowed_dirs = explicit_allowed_directories if explicit_allowed_directories is not None else conf.attachment_allowed_directories
    blocked_dirs = explicit_blocked_directories if explicit_blocked_directories is not None else conf.attachment_blocked_directories
    max_size = explicit_max_size_bytes if explicit_max_size_bytes is not None else conf.attachment_max_size_bytes
    allow_symlinks = explicit_allow_symlinks if explicit_allow_symlinks is not None else conf.attachment_allow_symlinks
    raise_on_violation = explicit_raise_on_violation if explicit_raise_on_violation is not None else conf.attachment_raise_on_security_violation

    return AttachmentSecurityOptions(
        allowed_extensions=allowed_ext,
        blocked_extensions=blocked_ext,
        allowed_directories=allowed_dirs,
        blocked_directories=blocked_dirs,
        max_size_bytes=max_size,
        allow_symlinks=allow_symlinks,
        raise_on_violation=raise_on_violation,
    )


def _deliver_to_any_host(  # noqa: PLR0913 - one keyword-only param per piece of message/delivery state, all required
    *,
    sender: str,
    recipient: str,
    subject: str,
    plain_body: str,
    html_body: str,
    hosts: tuple[str, ...],
    attachments: tuple[AttachmentPayload, ...],
    delivery: DeliveryOptions,
    transport: Transport,
) -> bool:
    """Attempt delivery across hosts until one succeeds.

    Why
        Encapsulates failover logic to keep orchestration linear. The message is
        composed once into a spooled temp file and reused across host attempts,
        so a large payload is neither re-rendered per host nor held on the heap.

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
    transport:
        Delivery adapter that streams the message to a host.

    What
        Iterates hosts, invoking ``transport.deliver`` until one accepts.

    Outputs
    -------
    bool
        ``True`` if any host accepts the message; ``False`` otherwise.

    Side Effects
    ------------
    Composes a spooled message, performs network I/O, logs warnings on failure.
    """

    spool = _compose_to_spool(
        sender=sender,
        recipient=recipient,
        subject=subject,
        plain_body=plain_body,
        html_body=html_body,
        attachments=attachments,
    )
    try:
        for host in hosts:
            try:
                transport.deliver(
                    host=host,
                    sender=sender,
                    recipient=recipient,
                    message=spool,
                    delivery=delivery,
                )
                logger.debug(
                    'mail sent to "%s" via host "%s"',
                    recipient,
                    host,
                    extra={"sender": sender, "recipient": recipient, "host": host},
                )
                return True
            except Exception:  # noqa: PERF203 - failover needs the try inside the loop to keep trying remaining hosts
                logger.warning(
                    'can not send mail to "%s" via host "%s"',
                    recipient,
                    host,
                    exc_info=True,
                    extra={"sender": sender, "recipient": recipient, "host": host},
                )
        return False
    finally:
        spool.close()


def _build_starttls_context(*, verify: bool) -> ssl.SSLContext:
    """Return the SSL context used for the STARTTLS handshake.

    Why
        Internal relays often present a self-signed certificate or one whose
        hostname does not match. Verifying such a certificate makes ``starttls``
        fail even though the channel would still be encrypted. ``verify=False``
        lets an operator keep encryption while opting out of validation, which
        is strictly better than falling back to plaintext.

    Inputs
    ------
    verify:
        ``True`` returns the standard verifying context (certificate chain and
        hostname checked). ``False`` disables both checks.

    Outputs
    -------
    ssl.SSLContext
        A verifying context by default, or a non-verifying one when
        ``verify`` is ``False``.

    Side Effects
    ------------
    None.
    """

    context = ssl.create_default_context()
    if not verify:
        # Opt-in for internal self-signed relays: the channel stays encrypted,
        # only certificate and hostname validation are dropped. check_hostname
        # must be cleared before verify_mode, or assigning CERT_NONE raises
        # ValueError while hostname checking is still on.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


# ---------------------------------------------------------------------------
# Transport port and streamed SMTP adapter
# ---------------------------------------------------------------------------


# Bytes read from the spooled message per socket write. Bounds peak delivery
# memory to roughly one chunk rather than the whole payload.
_STREAM_CHUNK_SIZE: Final[int] = 64 * 1024

# RFC 5321 SMTP reply codes used to gate the streamed DATA/BDAT protocol steps.
_SMTP_OK: Final[int] = 250
_SMTP_WILL_FORWARD: Final[int] = 251
_SMTP_START_MAIL_INPUT: Final[int] = 354

# Length of a CRLF line terminator; used to detect whether the DATA phase
# already ended on a line boundary before appending the terminal "." line.
_CRLF_LEN: Final[int] = 2


class Transport(Protocol):
    """### Transport {#lib-mail-transport}

    **Purpose:** Delivery seam that decouples failover orchestration from the
    concrete SMTP wire protocol, so an alternative transport (or a test double)
    is injected rather than monkeypatched over :mod:`smtplib`.

    An implementation delivers one already-composed message to one recipient via
    one host and raises on any failure so the caller can fall over to the next
    host.
    """

    def deliver(
        self,
        *,
        host: str,
        sender: str,
        recipient: str,
        message: IO[bytes],
        delivery: DeliveryOptions,
    ) -> None:
        """Deliver ``message`` (a rewindable byte stream) to ``recipient`` via ``host``."""
        ...


class SmtplibTransport:
    """### SmtplibTransport {#lib-mail-smtplibtransport}

    **Purpose:** Production :class:`Transport` that streams the message to the
    server over :mod:`smtplib` chunk by chunk instead of buffering the whole
    payload. When the server advertises ``CHUNKING`` (RFC 3030) it frames the
    body with ``BDAT``; otherwise it drives the classic ``DATA`` phase with
    incremental dot-stuffing. Either way peak transfer memory is ~one chunk.
    """

    def deliver(
        self,
        *,
        host: str,
        sender: str,
        recipient: str,
        message: IO[bytes],
        delivery: DeliveryOptions,
    ) -> None:
        hostname, port = _parse_smtp_host(host)
        with smtplib.SMTP(hostname, port=port or 0, timeout=delivery.timeout) as smtp_connection:
            smtp_connection.ehlo_or_helo_if_needed()
            if delivery.use_starttls:
                smtp_connection.starttls(context=_build_starttls_context(verify=delivery.starttls_verify))
                # RFC 3207: server capabilities must be re-fetched after TLS.
                smtp_connection.ehlo()
            if delivery.credentials is not None:
                username, password = delivery.credentials
                smtp_connection.login(username, password)
            smtp_connection.ehlo_or_helo_if_needed()

            message.seek(0)
            if smtp_connection.has_extn("chunking"):
                _send_via_bdat(smtp_connection, sender, recipient, message)
            else:
                _send_via_data(smtp_connection, sender, recipient, message)


def _require_socket(smtp_connection: smtplib.SMTP) -> Any:
    """Return the live socket, or raise if the connection was never established."""
    sock = smtp_connection.sock
    if sock is None:  # pragma: no cover - smtplib sets sock once connected
        raise smtplib.SMTPServerDisconnected("connection unexpectedly closed")
    return sock


def _open_envelope(smtp_connection: smtplib.SMTP, sender: str, recipient: str) -> None:
    """Issue MAIL FROM / RCPT TO, raising on rejection (shared by DATA and BDAT)."""
    code, resp = smtp_connection.mail(sender)
    if code != _SMTP_OK:
        raise smtplib.SMTPSenderRefused(code, resp, sender)
    code, resp = smtp_connection.rcpt(recipient)
    if code not in (_SMTP_OK, _SMTP_WILL_FORWARD):
        raise smtplib.SMTPRecipientsRefused({recipient: (code, resp)})


def _send_via_data(smtp_connection: smtplib.SMTP, sender: str, recipient: str, message: IO[bytes]) -> None:
    """Stream the message through the classic DATA phase with incremental dot-stuffing."""
    _open_envelope(smtp_connection, sender, recipient)
    code, resp = smtp_connection.docmd("DATA")
    if code != _SMTP_START_MAIL_INPUT:
        raise smtplib.SMTPDataError(code, resp)

    sock = _require_socket(smtp_connection)
    stuffer = _DotStuffer()
    tail = b""
    while True:
        chunk = message.read(_STREAM_CHUNK_SIZE)
        if not chunk:
            break
        sock.sendall(stuffer.feed(chunk))
        tail = chunk[-_CRLF_LEN:] if len(chunk) >= _CRLF_LEN else (tail + chunk)[-_CRLF_LEN:]
    # End the DATA phase with a lone "." line, guaranteeing exactly one CRLF
    # before it so we neither merge into the final body line nor add a blank one.
    if tail[-_CRLF_LEN:] != b"\r\n":
        sock.sendall(b"\r\n")
    sock.sendall(b".\r\n")
    code, resp = smtp_connection.getreply()
    if code != _SMTP_OK:
        raise smtplib.SMTPDataError(code, resp)


def _send_via_bdat(smtp_connection: smtplib.SMTP, sender: str, recipient: str, message: IO[bytes]) -> None:
    """Stream the message as RFC 3030 BDAT chunks (length-prefixed, no dot-stuffing)."""
    _open_envelope(smtp_connection, sender, recipient)
    sock = _require_socket(smtp_connection)
    while True:
        chunk = message.read(_STREAM_CHUNK_SIZE)
        if not chunk:
            break
        sock.sendall(b"BDAT " + str(len(chunk)).encode("ascii") + b"\r\n" + chunk)
        code, resp = smtp_connection.getreply()
        if code != _SMTP_OK:
            raise smtplib.SMTPDataError(code, resp)
    sock.sendall(b"BDAT 0 LAST\r\n")
    code, resp = smtp_connection.getreply()
    if code != _SMTP_OK:
        raise smtplib.SMTPDataError(code, resp)


# Default production transport; `send` uses it unless a transport is injected.
_DEFAULT_TRANSPORT: Final[Transport] = SmtplibTransport()


# Message assembly spills to disk above this threshold so a large message never
# has to fit in memory as one contiguous string.
_SPOOL_MAX_SIZE: Final[int] = 1024 * 1024  # 1 MiB


def _guess_attachment_mimetype(filename: str) -> tuple[str, str]:
    """Return the ``(maintype, subtype)`` Content-Type for an attachment name.

    Why
        A specific Content-Type helps the receiving client render the
        attachment; an unrecognised extension falls back to the generic binary
        type so delivery never fails on an unknown name.
    """
    guessed, _encoding = mimetypes.guess_type(filename)
    if guessed is None:
        return "application", "octet-stream"
    maintype, _slash, subtype = guessed.partition("/")
    return maintype, subtype or "octet-stream"


def _compose_to_spool(  # noqa: PLR0913 - one keyword-only param per message part; mirrors _deliver_to_any_host
    *,
    sender: str,
    recipient: str,
    subject: str,
    plain_body: str,
    html_body: str,
    attachments: tuple[AttachmentPayload, ...],
) -> IO[bytes]:
    """Assemble the message into a rewound, CRLF-encoded spooled temp file.

    Why
        Serialising into a ``SpooledTemporaryFile`` (in memory below
        ``_SPOOL_MAX_SIZE``, on disk above it) keeps the fully rendered message
        off the heap so delivery can stream it to the socket in bounded chunks
        instead of buffering the whole payload. ``email.policy.SMTP`` yields RFC
        5321 CRLF line endings on the wire, so the DATA and BDAT senders only add
        transfer framing and never re-encode the body.

    Outputs
    -------
    IO[bytes]
        Spooled file positioned at offset 0, holding the complete message.

    Side Effects
    ------------
    Reads each attachment's bytes from disk in chunks; may create a temp file.
    """

    # Returned open and closed later by the caller (_deliver_to_any_host's `finally`)
    # once streaming delivery finishes, so it cannot be opened as a `with` block here.
    spool = cast("IO[bytes]", tempfile.SpooledTemporaryFile(max_size=_SPOOL_MAX_SIZE))  # noqa: SIM115
    body_message = _build_body_message(plain_body, html_body)

    if not attachments:
        # No attachments: the body message itself is the whole message, so give
        # it the envelope headers and flatten it directly (it is small).
        body_message["Subject"] = subject
        body_message["From"] = sender
        body_message["To"] = recipient
        body_message["Date"] = formatdate(localtime=True)
        BytesGenerator(spool, policy=email_policy.SMTP).flatten(body_message)
        spool.seek(0)
        return spool

    # With attachments: hand-write a multipart/mixed so each attachment's base64
    # is streamed from disk instead of held in an in-memory message part.
    boundary = f"==============={uuid.uuid4().hex}=="
    outer = EmailMessage()
    outer["Subject"] = subject
    outer["From"] = sender
    outer["To"] = recipient
    outer["Date"] = formatdate(localtime=True)
    outer["MIME-Version"] = "1.0"
    outer["Content-Type"] = f'multipart/mixed; boundary="{boundary}"'

    delimiter = b"--" + boundary.encode("ascii") + b"\r\n"
    spool.write(_header_block(outer))
    # First body part: the (small) text/alternative message, headers and all.
    spool.write(delimiter)
    spool.write(_flatten_message(body_message))
    spool.write(b"\r\n")
    for attachment in attachments:
        spool.write(delimiter)
        _write_attachment_part(spool, attachment)
    spool.write(b"--" + boundary.encode("ascii") + b"--\r\n")
    spool.seek(0)
    return spool


def _build_body_message(plain_body: str, html_body: str) -> EmailMessage:
    """Build the text/alternative body part (no envelope headers, no attachments)."""
    message = EmailMessage()
    if plain_body and html_body:
        message.set_content(plain_body)
        message.add_alternative(html_body, subtype="html")
    elif html_body:
        message.set_content(html_body, subtype="html")
    else:
        message.set_content(plain_body)
    return message


def _header_block(message: EmailMessage) -> bytes:
    """Serialise a message's headers to CRLF bytes, terminated by a blank line."""
    out = bytearray()
    for name, value in message.items():
        out += email_policy.SMTP.fold_binary(name, value)
    out += b"\r\n"
    return bytes(out)


def _flatten_message(message: EmailMessage) -> bytes:
    """Serialise a whole (small) message to CRLF bytes via the SMTP policy."""
    buffer = io.BytesIO()
    BytesGenerator(buffer, policy=email_policy.SMTP).flatten(message)
    return buffer.getvalue()


def _write_attachment_part(spool: IO[bytes], attachment: AttachmentPayload) -> None:
    """Write one base64 attachment part, streaming its bytes from disk in chunks.

    Why
        Encoding the file incrementally (57 raw bytes per 76-char base64 line,
        read in a large multiple so whole lines are emitted per chunk) keeps peak
        memory at roughly one chunk instead of the full attachment plus its
        base64 expansion.
    """
    maintype, subtype = _guess_attachment_mimetype(attachment.filename)
    part_headers = EmailMessage()
    part_headers["Content-Type"] = f"{maintype}/{subtype}"
    part_headers["Content-Transfer-Encoding"] = "base64"
    part_headers.add_header("Content-Disposition", "attachment", filename=attachment.filename)
    spool.write(_header_block(part_headers))

    # 57 decoded bytes -> one 76-char base64 line; a large multiple keeps each
    # read aligned to whole lines so chunk encodings concatenate cleanly.
    raw_chunk = 57 * 1024
    with attachment.source.open("rb") as handle:
        while True:
            chunk = handle.read(raw_chunk)
            if not chunk:
                break
            spool.write(base64.encodebytes(chunk).replace(b"\n", b"\r\n"))
    spool.write(b"\r\n")


# ---------------------------------------------------------------------------
# Streamed delivery: DATA-phase dot-stuffing
# ---------------------------------------------------------------------------


class _DotStuffer:
    """Incrementally SMTP-dot-stuff a CRLF byte stream for the DATA phase.

    Why
        RFC 5321 section 4.5.2 requires that a line beginning with ``.`` be
        transmitted as ``..`` so the single-dot line stays reserved as the
        end-of-data marker. When the message is streamed in fixed-size chunks a
        line boundary (and therefore the leading dot to protect) can fall on any
        chunk edge, so the transform must remember whether the next byte starts
        a fresh line across ``feed`` calls rather than re-scanning whole lines.

    What
        Assumes the input already uses CRLF line endings (the caller serialises
        with :class:`email.policy.SMTP`); only period doubling is applied here.
    """

    def __init__(self) -> None:
        # The DATA payload begins at the start of a line, so the first byte is a
        # candidate for doubling.
        self._at_line_start = True

    def feed(self, chunk: bytes) -> bytes:
        """Return ``chunk`` with any line-leading ``.`` doubled."""
        dot = ord(".")
        line_feed = ord("\n")
        out = bytearray()
        at_line_start = self._at_line_start
        for byte in chunk:
            if at_line_start and byte == dot:
                out.append(dot)
            out.append(byte)
            at_line_start = byte == line_feed  # the byte after LF starts a line
        self._at_line_start = at_line_start
        return bytes(out)


# ---------------------------------------------------------------------------
# Attachment Security: Validation Functions
# ---------------------------------------------------------------------------


def _check_path_traversal(path: pathlib.Path, original_str: str) -> None:
    """Detect path traversal attempts in the original path string.

    Why
        Path traversal sequences like `../` can escape intended directories.

    Inputs
    ------
    path:
        The path object (for error reporting).
    original_str:
        The original string representation of the path.

    Side Effects
    ------------
    Raises AttachmentSecurityError if traversal is detected.
    """
    # Check the original string for traversal patterns before resolution
    if ".." in original_str:
        raise AttachmentSecurityError(
            path=path,
            reason=f'path contains traversal sequence: "{original_str}"',
            violation_type=AttachmentViolation.PATH_TRAVERSAL,
        )


def _check_symlink(*, path: pathlib.Path, allow_symlinks: bool) -> pathlib.Path:
    """Check symlink status and return the resolved path.

    Why
        Symlinks can point to sensitive files outside intended directories.

    Inputs
    ------
    path:
        The path to check.
    allow_symlinks:
        Whether symlinks are permitted.

    Outputs
    -------
    pathlib.Path
        The resolved path (follows symlinks if allowed).

    Side Effects
    ------------
    Raises AttachmentSecurityError if symlink is rejected.
    """
    if path.is_symlink():
        if not allow_symlinks:
            raise AttachmentSecurityError(
                path=path,
                reason=f'symlink detected and not allowed: "{path}"',
                violation_type=AttachmentViolation.SYMLINK,
            )
        # Follow the symlink and return the resolved target
        return path.resolve()
    return path.resolve()


def _check_sensitive_patterns(path: pathlib.Path) -> None:
    """Check if the path matches any sensitive patterns.

    Why
        Some paths (SSH keys, credentials) should never be attached.

    Inputs
    ------
    path:
        The resolved path to check.

    Side Effects
    ------------
    Raises AttachmentSecurityError if sensitive pattern is matched.
    """
    path_str = str(path)
    # Normalise to forward slashes for consistent matching
    path_str_normalised = path_str.replace("\\", "/")

    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern in path_str_normalised:
            raise AttachmentSecurityError(
                path=path,
                reason=f'path matches sensitive pattern "{pattern}": "{path}"',
                violation_type=AttachmentViolation.SENSITIVE_PATTERN,
            )


def _check_directory_restrictions(
    path: pathlib.Path,
    allowed: frozenset[pathlib.Path] | None,
    blocked: frozenset[pathlib.Path],
) -> None:
    """Check directory whitelist/blacklist restrictions.

    Why
        Restrict which directories attachments can be read from.

    Inputs
    ------
    path:
        The resolved path to check.
    allowed:
        When set, path must be under one of these directories.
    blocked:
        Path must not be under any of these directories.

    Side Effects
    ------------
    Raises AttachmentSecurityError if directory restriction is violated.
    """
    resolved_path = path.resolve()

    if allowed is not None:
        # Whitelist mode: path must be under an allowed directory. is_relative_to()
        # (3.9+) reports membership without raising, so no try/except is needed per
        # candidate directory.
        is_allowed = any(resolved_path.is_relative_to(allowed_dir.resolve()) for allowed_dir in allowed)
        if not is_allowed:
            raise AttachmentSecurityError(
                path=path,
                reason=f'path not under any allowed directory: "{path}"',
                violation_type=AttachmentViolation.DIRECTORY,
            )
    else:
        # Blacklist mode: path must not be under a blocked directory
        for blocked_dir in blocked:
            if resolved_path.is_relative_to(blocked_dir.resolve()):
                raise AttachmentSecurityError(
                    path=path,
                    reason=f'path under blocked directory "{blocked_dir}": "{path}"',
                    violation_type=AttachmentViolation.DIRECTORY,
                )


def _check_extension(
    path: pathlib.Path,
    allowed: frozenset[str] | None,
    blocked: frozenset[str],
) -> None:
    """Check extension whitelist/blacklist restrictions.

    Why
        Prevent attachment of dangerous executable file types.

    Inputs
    ------
    path:
        The path to check.
    allowed:
        When set, only these extensions are permitted (whitelist mode).
    blocked:
        Extensions to reject (ignored when whitelist is active).

    Side Effects
    ------------
    Raises AttachmentSecurityError if extension is not allowed.
    """
    ext = path.suffix.lower()

    if allowed is not None:
        # Whitelist mode: only allowed extensions pass
        if ext not in allowed:
            raise AttachmentSecurityError(
                path=path,
                reason=f'extension "{ext}" not in allowed list: "{path}"',
                violation_type=AttachmentViolation.EXTENSION,
            )
    # Blacklist mode: block only blacklisted extensions
    elif ext in blocked:
        raise AttachmentSecurityError(
            path=path,
            reason=f'extension "{ext}" is blocked: "{path}"',
            violation_type=AttachmentViolation.EXTENSION,
        )


def _check_file_size(path: pathlib.Path, max_size: int | None) -> None:
    """Check that the file size does not exceed the limit.

    Why
        Prevent memory exhaustion from excessively large attachments.

    Inputs
    ------
    path:
        The resolved path to check.
    max_size:
        Maximum allowed size in bytes (None to skip check).

    Side Effects
    ------------
    Raises AttachmentSecurityError if file exceeds size limit.
    """
    if max_size is None:
        return

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AttachmentSecurityError(
            path=path,
            reason=f'cannot stat file: "{path}" ({exc})',
            violation_type=AttachmentViolation.SIZE,
        ) from exc

    if size > max_size:
        raise AttachmentSecurityError(
            path=path,
            reason=f'file size {size} bytes exceeds limit {max_size} bytes: "{path}"',
            violation_type=AttachmentViolation.SIZE,
        )


def _validate_attachment_security(
    path: pathlib.Path,
    original_path_str: str,
    security: AttachmentSecurityOptions,
) -> pathlib.Path:
    """Orchestrate all security checks for a single attachment.

    Why
        Provides a single entry point for attachment security validation.

    Inputs
    ------
    path:
        The path object to validate.
    original_path_str:
        The original string representation (for traversal detection).
    security:
        Resolved security options.

    Outputs
    -------
    pathlib.Path
        The resolved path (after symlink resolution if applicable).

    Side Effects
    ------------
    Raises AttachmentSecurityError if any check fails. Note that file
    existence is NOT checked here - that's handled by _prepare_attachments
    after security validation completes.
    """
    # 1. Check path traversal (before any I/O)
    _check_path_traversal(path, original_path_str)

    # 2. Check symlink handling
    resolved_path = _check_symlink(path=path, allow_symlinks=security.allow_symlinks)

    # 3. Check sensitive patterns
    _check_sensitive_patterns(resolved_path)

    # 4. Check directory restrictions
    _check_directory_restrictions(
        resolved_path,
        security.allowed_directories,
        security.blocked_directories,
    )

    # 5. Check extension
    _check_extension(
        resolved_path,
        security.allowed_extensions,
        security.blocked_extensions,
    )

    # 6. Check file size (only if file exists)
    # Note: File existence check comes later in _prepare_attachments
    if resolved_path.exists():
        _check_file_size(resolved_path, security.max_size_bytes)

    return resolved_path


def _prepare_attachments(
    paths: tuple[pathlib.Path, ...],
    security: AttachmentSecurityOptions,
    *,
    raise_on_missing: bool,
) -> tuple[AttachmentPayload, ...]:
    """Normalise attachment paths into frozen payloads with security validation.

    Why
        Validates attachment existence and security before SMTP attempts begin.

    Inputs
    ------
    paths:
        Tuple of candidate filesystem paths (may be empty).
    security:
        Resolved security options for validation.
    raise_on_missing:
        When ``True``, missing files raise ``FileNotFoundError``; when ``False``,
        a warning is logged and the attachment is skipped.

    What
        Resolves existing files, validates security, and emits immutable payloads.

    Outputs
    -------
    tuple[AttachmentPayload, ...]
        Resolved payloads that passed security validation.

    Side Effects
    ------------
    Reads file bytes when paths exist and pass security checks; logs or raises
    when missing or security violations occur.
    """
    prepared: list[AttachmentPayload] = []
    for path in paths:
        original_path_str = str(path)

        # Security validation (before reading file contents)
        try:
            validated_path = _validate_attachment_security(path, original_path_str, security)
        except AttachmentSecurityError as exc:
            if security.raise_on_violation:
                raise
            logger.warning(
                "Attachment security violation: %s",
                exc.reason,
                extra={
                    "attachment_path": original_path_str,
                    "violation_type": exc.violation_type.value,
                },
            )
            continue

        # Check file existence
        if not validated_path.is_file():
            if raise_on_missing:
                raise FileNotFoundError(f'Attachment File "{validated_path}" can not be found')
            logger.warning(
                'Attachment File "%s" can not be found',
                validated_path,
                extra={"attachment_path": str(validated_path)},
            )
            continue

        # Record the validated path; bytes are read later while streaming so a
        # large attachment never sits fully in memory from here to delivery.
        prepared.append(
            AttachmentPayload(
                filename=validated_path.name,
                source=validated_path,
            )
        )

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
    for host in unique:
        validate_smtp_host(host)
    return unique


def _prepare_recipients(
    recipients: str | Sequence[str],
    *,
    raise_on_invalid: bool,
) -> tuple[str, ...]:
    """Return a deduplicated tuple of valid, lower-cased recipient addresses.

    Why
        Consolidates parsing, trimming, deduplication, and validation.

    Inputs
    ------
    recipients:
        Single email or sequence of emails supplied by callers.
    raise_on_invalid:
        When ``True``, invalid recipients raise ``ValueError``; when ``False``,
        a warning is logged and the address is skipped.

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
        try:
            validate_email_address(entry)
        except ValueError:
            if raise_on_invalid:
                raise ValueError(f"invalid recipient {entry}") from None
            logger.warning("invalid recipient %s", entry, extra={"recipient": entry})
            continue
        valid.append(entry)

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
        for item in cast("Iterable[Any]", value):
            if not isinstance(item, str):
                raise ValueError("smtphosts entries must be strings")
            hosts.append(_normalise_host(item))
        return hosts
    raise ValueError("smtphosts must be a string, list of strings, or tuple of strings")


def validate_email_address(address: str) -> None:
    """Raise ``ValueError`` when *address* does not match the email pattern.

    Why
        Prevents avoidable SMTP failures by checking syntax early.

    What
        Applies :data:`EMAIL_PATTERN` and raises on mismatch.

    Inputs
    ------
    address:
        Candidate email string.

    Outputs
    -------
    None

    Side Effects
    ------------
    None.

    Examples
    --------
    >>> validate_email_address("user@example.com")
    >>> validate_email_address("invalid@")
    Traceback (most recent call last):
        ...
    ValueError: invalid email address: 'invalid@'
    """

    if not EMAIL_PATTERN.fullmatch(address):
        raise ValueError(f"invalid email address: {address!r}")


def validate_smtp_host(host: str) -> None:
    """Raise ``ValueError`` when *host* is not a valid SMTP host string.

    Accepts the following forms:

    - ``hostname``
    - ``hostname:port``
    - ``[IPv6]:port``  (e.g. ``[::1]:25``)
    - ``[IPv6]``       (e.g. ``[::1]``)

    Why
        Validates SMTP host syntax early so errors surface before delivery.

    Inputs
    ------
    host:
        Host string with optional port and/or IPv6 bracket notation.

    Outputs
    -------
    None

    Side Effects
    ------------
    None.

    Examples
    --------
    >>> validate_smtp_host("smtp.example.com:587")
    >>> validate_smtp_host("[::1]:25")
    >>> validate_smtp_host("bad:host:format")
    Traceback (most recent call last):
        ...
    ValueError: invalid smtp port in "bad:host:format"
    """

    if not host:
        raise ValueError("empty SMTP host")

    if host.startswith("["):
        # IPv6 bracketed address: [addr] or [addr]:port
        bracket_end = host.find("]")
        if bracket_end == -1:
            raise ValueError(f'missing closing bracket in "{host}"')
        remainder = host[bracket_end + 1 :]
        if remainder == "":
            # bare [IPv6] — valid, no port
            return
        if not remainder.startswith(":"):
            raise ValueError(f'unexpected characters after bracket in "{host}"')
        port_str = remainder[1:]
        _validate_port(port_str, host)
        return

    if ":" not in host:
        return
    _, port_str = host.rsplit(":", 1)
    _validate_port(port_str, host)


def _validate_port(port_str: str, original: str) -> None:
    """Validate that *port_str* is a numeric port in the 1-65535 range.

    Inputs
    ------
    port_str:
        Raw port substring extracted from the host string.
    original:
        The full host string used in error messages.

    Outputs
    -------
    None

    Side Effects
    ------------
    None.
    """

    min_port = 1
    max_port = 65535  # highest valid TCP port
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ValueError(f'invalid smtp port in "{original}"') from exc
    if not (min_port <= port <= max_port):
        raise ValueError(f'port must be {min_port}-{max_port} in "{original}", got {port}')


def _parse_smtp_host(address: str) -> tuple[str, int | None]:
    """Validate and split an SMTP host string into hostname and port.

    Calls :func:`validate_smtp_host` first, then extracts the components.
    IPv6 brackets are stripped so ``smtplib.SMTP`` receives a bare address.

    Why
        Delivery helpers need separate hostname and port values.

    Inputs
    ------
    address:
        Host string validated by :func:`validate_smtp_host`.

    Outputs
    -------
    tuple[str, int | None]
        Hostname (bare for IPv6) and optional port number.

    Side Effects
    ------------
    None.
    """

    validate_smtp_host(address)

    if address.startswith("["):
        bracket_end = address.find("]")
        ipv6_addr = address[1:bracket_end]
        remainder = address[bracket_end + 1 :]
        if remainder.startswith(":"):
            return ipv6_addr, int(remainder[1:])
        return ipv6_addr, None

    if ":" not in address:
        return address, None
    host, port_str = address.rsplit(":", 1)
    return host, int(port_str)
