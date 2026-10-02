"""## btx_lib_mail.lib_mail {#module-btx-lib-mail-lib-mail}

**Purpose:** Provide the SMTP delivery boundary for the library. The module
collects configuration, normalises user input, and renders multipart messages so
adapters such as the CLI can treat delivery as a single call.

**Contents:**
- `AttachmentPayload` - frozen attachment payload supplied to the MIME renderer.
- `ConfMail` - Pydantic configuration surface shared across transports.
- `DeliveryOptions` - resolved runtime options derived from configuration.
- `send` - public orchestration entry point.

**System Role:** Matches `docs/systemdesign/module_reference.md#feature-cli-components`
by translating intent gathered by the CLI into SMTP side effects while keeping
configuration flow and delivery flow separated.
"""

from __future__ import annotations

import base64
import errno
import functools
import io
import logging
import math
import mimetypes
import os
import pathlib
import re
import shutil
import smtplib
import socket
import ssl
import stat
import sys
import tempfile
import threading
import unicodedata
import uuid
from collections.abc import Generator, Iterable, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from email import policy as email_policy
from email.generator import BytesGenerator
from email.message import EmailMessage
from email.utils import formatdate
from enum import Enum
from typing import IO, Any, Final, Protocol, cast

from pydantic import ConfigDict, Field, SecretStr, field_validator, model_validator

from .errors import AttachmentNotFoundError, BtxMailError, ConfigurationError, DeliveryError, InvalidInputError
from .secret_safety import SecretSafeModel

logger = logging.getLogger("btx_lib_mail")

EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
"""Compiled regex used by :func:`validate_email_address`."""


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
    "/.netrc",
    "/.pgpass",
    "/.git-credentials",
    "/.docker/config.json",
    "/.pypirc",
    "/.npmrc",
    "/gh/hosts.yml",
)
"""Path patterns that indicate sensitive files (always blocked).

Matched as substrings of the resolved path with forward slashes, ignoring case.
"""


def _default_blocked_extensions() -> frozenset[str]:
    """Return the dangerous extensions of every platform.

    Why
        What runs an attachment is the RECIPIENT's machine, not the sender's, so a
        Linux sender must refuse ``.exe`` as firmly as a Windows sender refuses
        ``.sh``. Unlike the blocked directories, which describe the sender's own
        disk, this set does not depend on where the library runs.

    Outputs
    -------
    frozenset[str]
        The union of :data:`DANGEROUS_EXTENSIONS_POSIX` and
        :data:`DANGEROUS_EXTENSIONS_WINDOWS`.
    """
    return DANGEROUS_EXTENSIONS_POSIX | DANGEROUS_EXTENSIONS_WINDOWS


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
    CHANGED = "changed"


# ---------------------------------------------------------------------------
# Attachment Security: Exception
# ---------------------------------------------------------------------------


class AttachmentSecurityError(BtxMailError):
    """Raised when an attachment violates security policies.

    **Purpose:** Provide a structured exception for attachment security
    violations so callers can handle or report them appropriately.

    **Fields:**
    - `path: pathlib.Path` - The offending attachment path.
    - `reason: str` - Human-readable description of the violation, with every
      control character (CR, LF, ESC, NUL, ...) already replaced by a space, since
      the path embedded in it is filesystem-supplied and could otherwise forge a
      line in whatever renders `str(exc)`, `repr(exc)`, or a log line built from
      this field.
    - `violation_type: AttachmentViolation` - Category of the violation
      (`AttachmentViolation.SYMLINK`, `.EXTENSION`, `.SIZE`, etc.). Members
      subclass `str`, so `== "symlink"` comparisons keep working.
    """

    def __init__(self, path: pathlib.Path, reason: str, violation_type: AttachmentViolation) -> None:
        # `reason` is built with an f-string at every call site and usually
        # embeds `path` (filesystem-supplied), so it is cleaned once here:
        # this also cleans `self.args` (via `super().__init__`), so neither
        # `str(exc)` nor the default `repr(exc)` (which renders `self.args`
        # unclean-through-`__str__`) can carry a forged line, whether this
        # exception is logged or propagated to the caller in strict mode.
        clean_reason = _printable(reason)
        super().__init__(clean_reason)
        self.path = path
        self.reason = clean_reason
        self.violation_type = violation_type

    def __str__(self) -> str:
        # .value keeps the message text stable across Python versions, where
        # f-string formatting of a `str, Enum` member is inconsistent.
        return f"Attachment security violation ({self.violation_type.value}): {self.reason} [path={_printable(str(self.path))}]"


@dataclass(frozen=True)
class AttachmentPayload:
    """### AttachmentPayload {#lib-mail-attachmentpayload}

    **Purpose:** Name a validated attachment and hold the file it was checked
    as, open, so the bytes encoded into the message are those of the checked
    file even if the path is swapped afterwards.

    **Fields:**
    - `filename: str` - Basename surfaced in the `Content-Disposition` header.
    - `source: pathlib.Path` - The resolved path that was checked (for messages).
    - `handle: IO[bytes]` - The checked file, opened once; read while the
      message body is encoded and closed when `send()` returns.
    - `size_limit: int | None` - The size limit in force; a file that grows
      past it while it is read is refused.

    Instances are immutable (`frozen=True`); the handle itself is rewound before
    each read.
    """

    filename: str
    source: pathlib.Path
    handle: IO[bytes] = field(repr=False, compare=False)
    size_limit: int | None = None


class ConfMail(SecretSafeModel):
    """### ConfMail {#lib-mail-confmail}

    **Purpose:** Serve as the authoritative SMTP configuration object, merging
    CLI options, environment variables, and defaults while enforcing type and
    range checks.

    **Fields:**
    - `smtphosts: list[str] = []` - Ordered hosts in `host[:port]` form. Empty
      by default so callers must supply at least one host.
    - `raise_on_missing_attachments: bool = True` - When `True`, missing files
      raise `AttachmentNotFoundError` (a `FileNotFoundError`); otherwise the
      module logs a warning and continues.
    - `raise_on_invalid_recipient: bool = True` - When `True`, invalid addresses
      raise `InvalidInputError` (a `ValueError`); otherwise a warning is logged
      and delivery skips the address.
    - `smtp_username: str | None = None` and `smtp_password: SecretStr | None = None`
      - Optional credentials; both must be populated to enable authentication.
      `smtp_password` is a `SecretStr`, so it is masked in `repr()` and
      `model_dump()`; call `.get_secret_value()` (or `resolved_credentials()`) to
      read the plaintext. A plain string assigned to it is coerced to `SecretStr`.
      An int is accepted as its decimal text (config loaders parse digit strings
      as numbers); any other non-text value is refused, and validation errors of
      this model never carry the password (see `SecretSafeModel`).
    - `smtp_use_starttls: bool = True` - Enables `STARTTLS` negotiation before
      authentication when supported by the server.
    - `smtp_starttls_verify: bool = True` - When `True`, the `STARTTLS` handshake
      verifies the server certificate and hostname (the secure default). Set to
      `False` for an internal relay whose certificate is self-signed or has a
      hostname mismatch: the traffic stays encrypted but the certificate is not
      validated. Has no effect when `smtp_use_starttls` is `False`.
    - `smtp_timeout: float = 30.0` - Socket timeout in seconds applied to SMTP
      connections. Must be positive and finite.
    - `smtp_local_hostname: str | None = None` - The name announced in
      `EHLO`/`HELO`. When `None`, the host's fully qualified name is looked up
      once per process and reused (a domain literal such as `[192.0.2.7]` when
      it has no dot). Set it where reverse DNS is slow, since that lookup
      otherwise delays the first connection. Must be non-empty printable ASCII
      without spaces.
    - `smtp_delivery_deadline: float | None = None` - Upper bound in seconds for
      one SMTP session (one recipient via one host), from the open connection to
      the server's final reply. `smtp_timeout` bounds each socket operation, so
      a server answering one byte at a time never trips it; this bounds the
      whole session, after which the host counts as failed and the next one is
      tried. `None` sets no bound. Must be positive and finite when set.
    - `attachment_allowed_extensions: frozenset[str] | None = None` - When set,
      only these extensions are allowed (whitelist mode). When `None`, the
      blocked extensions list applies instead.
    - `attachment_blocked_extensions: frozenset[str]` - Extensions to reject.
      Ignored when `attachment_allowed_extensions` is set. Defaults to the
      dangerous extensions of BOTH platform families
      (`DANGEROUS_EXTENSIONS_POSIX | DANGEROUS_EXTENSIONS_WINDOWS`), since the
      recipient's system decides what an attachment runs as. An empty set with
      no allowlist is refused unless `attachment_allow_empty_blocklists` is
      `True`.
    - `attachment_allowed_directories: frozenset[pathlib.Path] | None = None` -
      When set, attachments must reside under one of these directories.
    - `attachment_blocked_directories: frozenset[pathlib.Path]` - Directories
      from which attachments cannot be read. Ignored when
      `attachment_allowed_directories` is set. Defaults to OS-specific
      sensitive directories. An empty set with no allowlist is refused unless
      `attachment_allow_empty_blocklists` is `True`.
    - `attachment_max_size_bytes: int | None = 26_214_400` - Maximum attachment
      size in bytes (default 25 MiB). `None` disables size checking.
    - `attachment_allow_symlinks: bool = False` - When `False`, a path whose
      last component is a symlink is rejected; when `True`, it is resolved and
      validated. A symlinked directory along the path is followed either way;
      every rule runs on the resolved target.
    - `attachment_raise_on_security_violation: bool = True` - When `True`,
      security violations raise `AttachmentSecurityError`; when `False`, they
      log a warning and skip the attachment.
    - `attachment_allow_empty_blocklists: bool = False` - When `False`, an empty
      `attachment_blocked_extensions` or `attachment_blocked_directories` whose
      allowlist is not set is refused at validation (construction and
      assignment), because it blocks nothing: a configuration loader that turns
      an empty list meaning "defaults" into an empty set would otherwise switch
      the protection off silently. Set `True` to block nothing on purpose. An
      explicit `send(attachment_blocked_*=frozenset())` keyword is never checked.

    **Refusals:** A refused setting raises `ConfigurationError`, a pydantic
    `ValidationError` that is also a `BtxMailError`.

    **Unknown names:** A name that is not one of the fields above is refused
    with a `ConfigurationError` (`extra_forbidden`, naming the key, never its
    value), at construction and in `model_validate`. The `send()` keyword
    names are not field names: `ConfMail(use_starttls=False)` is refused, the
    field is `smtp_use_starttls`.

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
    smtp_local_hostname: str | None = None
    smtp_delivery_deadline: float | None = None

    # Attachment security settings
    attachment_allowed_extensions: frozenset[str] | None = None
    attachment_blocked_extensions: frozenset[str] = Field(default_factory=_default_blocked_extensions)
    attachment_allowed_directories: frozenset[pathlib.Path] | None = None
    attachment_blocked_directories: frozenset[pathlib.Path] = Field(default_factory=_default_blocked_directories)
    attachment_max_size_bytes: int | None = 26_214_400  # 25 MiB
    attachment_allow_symlinks: bool = False
    attachment_raise_on_security_violation: bool = True
    attachment_allow_empty_blocklists: bool = False

    # extra="forbid": a name ConfMail does not have is refused rather than
    # dropped, so send()'s use_starttls/timeout passed here cannot silently
    # leave STARTTLS on and the default timeout in force.
    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True, extra="forbid")

    # smtphosts is listed because a host that carries user:password@ is refused
    # there, and that refusal must not echo the value.
    credential_fields = frozenset({"smtp_password", "smtphosts"})
    validation_error_class = ConfigurationError

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

    @field_validator("smtp_password", mode="before")
    @classmethod
    def _coerce_password(cls, value: Any) -> Any:
        """Accept text and whole numbers; refuse anything else without echoing it.

        Why
            Layered config loaders turn an all-digit environment value into an
            ``int`` before it reaches this model, and quoting it does not help
            (the quotes are kept as characters). A float, a bool or a container
            is never a password a loader produced faithfully, so it is refused
            with only its type named.

        Note
            A loader that parsed ``0123`` as the number 123 has already lost the
            leading zero; this model cannot restore it.
        """
        if value is None or isinstance(value, (str, bytes, SecretStr)):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        raise InvalidInputError(f"smtp_password must be text, got {type(value).__name__}; quote it in the configuration source")

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

        _check_timeout(value)
        return value

    @field_validator("smtp_delivery_deadline", mode="after")
    @classmethod
    def _validate_delivery_deadline(cls, value: float | None) -> float | None:
        """Refuse a deadline that is not a positive, finite number of seconds."""
        if value is not None:
            _check_seconds(value, label="smtp_delivery_deadline")
        return value

    @field_validator("smtp_local_hostname", mode="after")
    @classmethod
    def _validate_local_hostname(cls, value: str | None) -> str | None:
        """Refuse an EHLO name that cannot be sent as one SMTP command argument."""
        if value is not None:
            _check_local_hostname(value, label="smtp_local_hostname")
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
            raise InvalidInputError("extensions must be a set, frozenset, list, or tuple of strings")
        raw_list: list[object] = list(cast("Iterable[object]", value))

        normalised: set[str] = set()
        for ext in raw_list:
            if not isinstance(ext, str):
                raise InvalidInputError(f"extension must be a string, got {type(ext).__name__}")
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
            raise InvalidInputError("directories must be a set, frozenset, list, or tuple")
        raw_list: list[object] = list(cast("Iterable[object]", value))

        normalised: set[pathlib.Path] = set()
        for directory in raw_list:
            if isinstance(directory, str):
                normalised.add(pathlib.Path(directory))
            elif isinstance(directory, pathlib.Path):
                normalised.add(directory)
            else:
                raise InvalidInputError(f"directory must be a string or Path, got {type(directory).__name__}")
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
            raise InvalidInputError(f"attachment_max_size_bytes must be positive, got {value}")
        return value

    @model_validator(mode="after")
    def _refuse_an_empty_blocklist(self) -> ConfMail:
        """Refuse a blocked set that blocks nothing unless that is opted into.

        Why
            ``[]`` from a config file often means "use the defaults" to the
            loader that wrote it, while here it means "block nothing"; a silent
            switch-off of executable and system-directory blocking is the
            failure this prevents.
        """
        if self.attachment_allow_empty_blocklists:
            return self
        axes = (
            ("attachment_blocked_extensions", self.attachment_blocked_extensions, "attachment_allowed_extensions", self.attachment_allowed_extensions),
            ("attachment_blocked_directories", self.attachment_blocked_directories, "attachment_allowed_directories", self.attachment_allowed_directories),
        )
        for blocked_name, blocked, allowed_name, allowed in axes:
            if not blocked and allowed is None:
                raise InvalidInputError(
                    f"{blocked_name} is empty and {allowed_name} is not set, so nothing would be blocked; "
                    f"omit {blocked_name} for the OS defaults, or set attachment_allow_empty_blocklists=True to block nothing on purpose"
                )
        return self

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
    """### send(...) -> bool {#lib-mail-send}

    **Purpose:** Provide the library/CLI façade that turns validated intent
    (sender, recipients, message bodies, attachments) into SMTP activity while
    honouring delivery policies defined in `ConfMail`.

    **Parameters:**
    - `mail_from: str` - Envelope sender address. Must be a syntactically valid
      email.
    - `mail_recipients: str | Sequence[str]` - Single recipient or iterable of
      recipients. Values are trimmed, deduplicated, lower-cased, and validated.
    - `mail_subject: str` - Subject line; UTF-8 is supported.
    - `mail_body: str = ""` - Optional plain-text body.
    - `mail_body_html: str = ""` - Optional HTML body.
    - `smtphosts: Sequence[str] | None = None` - Override host list. When
      `None`, the helper falls back to the passed `config.smtphosts`, else the
      global `conf.smtphosts`.
    - `attachment_file_paths: Sequence[pathlib.Path] | None = None` - Optional
      iterable of filesystem paths. Each existing file becomes an attachment.
    - `credentials: tuple[str, str] | None = None` - Override credentials. When
      omitted, `resolved_credentials()` of the passed `config`, else of `conf`,
      is used.
    - `use_starttls: bool | None = None` - Override STARTTLS preference. When
      `None`, the helper uses `smtp_use_starttls` of the passed `config`, else
      `conf`.
    - `starttls_verify: bool | None = None` - Override STARTTLS certificate
      verification. When `None`, the helper uses `smtp_starttls_verify` of the
      passed `config`, else `conf`. `False` keeps the connection encrypted but
      skips certificate/hostname validation (for internal self-signed relays).
      Ignored unless STARTTLS runs.
    - `timeout: float | None = None` - Override socket timeout in seconds. When
      `None`, the helper uses `smtp_timeout` of the passed `config`, else `conf`.
    - `local_hostname: str | None = None` - Override the name announced in
      `EHLO`. When `None`, the helper uses `smtp_local_hostname` of the passed
      `config`, else `conf`; when that is unset too, the host's own name,
      looked up once per process.
    - `delivery_deadline: float | None = None` - Override the upper bound in
      seconds for one SMTP session. When `None`, the helper uses
      `smtp_delivery_deadline` of the passed `config`, else `conf`.
    - `attachment_allowed_extensions: frozenset[str] | None = None` - Override
      allowed extensions (whitelist mode). When `None`, uses the passed
      `config`'s default, else `conf`'s.
    - `attachment_blocked_extensions: frozenset[str] | None = None` - Override
      blocked extensions. When `None`, uses the passed `config`'s default, else
      `conf`'s.
    - `attachment_allowed_directories: frozenset[pathlib.Path] | None = None` -
      Override allowed directories. When `None`, uses the passed `config`'s
      default, else `conf`'s.
    - `attachment_blocked_directories: frozenset[pathlib.Path] | None = None` -
      Override blocked directories. When `None`, uses the passed `config`'s
      default, else `conf`'s.
    - `attachment_max_size_bytes: int | None = None` - Override max attachment
      size in bytes. When `None`, uses the passed `config`'s default, else
      `conf`'s.
    - `attachment_allow_symlinks: bool | None = None` - Override symlink policy.
      When `None`, uses the passed `config`'s default, else `conf`'s.
    - `attachment_raise_on_security_violation: bool | None = None` - Override
      security violation behaviour. When `None`, uses the passed `config`'s
      default, else `conf`'s.
    - `raise_on_missing_attachments: bool | None = None` - Override
      `raise_on_missing_attachments` of the passed `config`, else `conf`. When
      `None`, uses that default; `True` raises on missing, `False` logs warning
      and skips.
    - `raise_on_invalid_recipient: bool | None = None` - Override
      `raise_on_invalid_recipient` of the passed `config`, else `conf`. When
      `None`, uses that default; `True` raises on invalid, `False` logs warning
      and skips.
    - `config: ConfMail | None = None` - Settings used in place of the
      module-global `conf` for every value not passed explicitly; when given,
      `conf` is not read. Lets an application hold its own `ConfMail` (or
      subclass) without mutating the global.

    **Returns:** `bool` - Always `True` when all deliveries succeed. A failure
    raises instead of returning `False`.

    **Raises:** (every one a `BtxMailError`)
    - `InvalidInputError` (a `ValueError`) - When the sender, a recipient (in
      strict mode), a host, the subject (a control character other than TAB),
      `local_hostname`, `timeout` or `delivery_deadline` is refused, or no
      valid recipient remains.
      Raised before the first delivery.
    - `AttachmentNotFoundError` (a `FileNotFoundError`) - When required
      attachments are missing and `raise_on_missing_attachments` is `True` on
      the config in use (the passed `config`, else the global `conf`).
    - `AttachmentSecurityError` - When an attachment violates security policies
      and `attachment_raise_on_security_violation` is `True`, including a file
      that changed or grew past the size limit after it was checked.
    - `DeliveryError` (a `RuntimeError`) - When every SMTP host fails for a
      recipient; the error lists the affected recipients and host set, and
      carries them as `failed_recipients` and `hosts`.

    **Attachments:** each file is checked, opened once, and encoded once; every
    recipient's message carries the bytes of that open file, and the files are
    closed before `send()` returns.

    **Example:**
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

    try:
        validate_email_address(mail_from)
    except ValueError:
        raise InvalidInputError(f"invalid sender address: {mail_from!r}") from None

    # Resolve error handling parameters
    resolved_raise_on_missing = raise_on_missing_attachments if raise_on_missing_attachments is not None else settings.raise_on_missing_attachments
    resolved_raise_on_invalid = raise_on_invalid_recipient if raise_on_invalid_recipient is not None else settings.raise_on_invalid_recipient

    recipients = _prepare_recipients(mail_recipients, raise_on_invalid=resolved_raise_on_invalid)

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

    attachments = _prepare_attachments(
        tuple(attachment_file_paths or ()),
        security,
        raise_on_missing=resolved_raise_on_missing,
    )
    try:
        plan = _DeliveryPlan(
            hosts=_prepare_hosts(tuple(smtphosts or settings.smtphosts)),
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
            transport=transport if transport is not None else _DEFAULT_TRANSPORT,
        )
        _check_subject(mail_subject)
        # Every header block is built before the first delivery, so a header the
        # email package refuses fails the call before any recipient was sent to.
        envelopes = [(recipient, _envelope_header_lines(sender=mail_from, recipient=recipient, subject=mail_subject)) for recipient in recipients]
        body = _compose_body_once(
            _MessageContent(plain_body=mail_body, html_body=mail_body_html, attachments=attachments),
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
        _close_attachments(attachments)

    if failed_recipients:
        raise DeliveryError(
            f'following recipients failed "{failed_recipients}" on all of following hosts : "{plan.hosts}"',
            failed_recipients=tuple(failed_recipients),
            hosts=plan.hosts,
        )

    return True


@dataclass(frozen=True)
class DeliveryOptions:
    """### DeliveryOptions {#lib-mail-deliveryoptions}

    **Purpose:** Capture the resolved runtime knobs for a single delivery attempt
    so low-level helpers receive one immutable object.

    **Fields:**
    - `credentials: tuple[str, str] | None` - `(username, password)` pair or
      `None` when anonymous delivery is requested.
    - `use_starttls: bool` - `True` enables `STARTTLS` handshakes.
    - `starttls_verify: bool` - `True` verifies the server certificate and
      hostname during `STARTTLS`; `False` keeps the traffic encrypted but skips
      verification (for internal self-signed relays).
    - `timeout: float` - Socket timeout (seconds) applied to SMTP connections.
    - `local_hostname: str | None` - Name announced in `EHLO`; `None` lets the
      transport use the host's own name, looked up once per process.
    - `deadline: float | None` - Upper bound in seconds for the whole SMTP
      session once connected; `None` sets none.
    """

    # repr=False: a transport or a debugger printing the options must not print the password.
    credentials: tuple[str, str] | None = field(repr=False)
    use_starttls: bool
    starttls_verify: bool
    timeout: float
    # Defaulted so a DeliveryOptions built without them keeps the behaviour of having none.
    local_hostname: str | None = None
    deadline: float | None = None


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

    Why
        Centralises option resolution so callers remain declarative.

    Inputs
    ------
    settings:
        The `ConfMail` whose values fill in anything not passed explicitly.
    overrides:
        The delivery keywords supplied by :func:`send`.

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

    credentials = overrides.credentials or settings.resolved_credentials()
    use_starttls = bool(overrides.use_starttls if overrides.use_starttls is not None else settings.smtp_use_starttls)
    starttls_verify = bool(overrides.starttls_verify if overrides.starttls_verify is not None else settings.smtp_starttls_verify)
    timeout = float(overrides.timeout if overrides.timeout is not None else settings.smtp_timeout)
    _check_timeout(timeout)
    if overrides.local_hostname is not None:
        _check_local_hostname(overrides.local_hostname, label="local_hostname")
    local_hostname = overrides.local_hostname if overrides.local_hostname is not None else settings.smtp_local_hostname
    if overrides.deadline is not None:
        _check_seconds(overrides.deadline, label="delivery_deadline")
    deadline = overrides.deadline if overrides.deadline is not None else settings.smtp_delivery_deadline
    return DeliveryOptions(
        credentials=credentials,
        use_starttls=use_starttls,
        starttls_verify=starttls_verify,
        timeout=timeout,
        local_hostname=local_hostname,
        deadline=deadline,
    )


# EHLO takes one argument: printable ASCII, no space (RFC 5321 section 4.1.1.1).
_EHLO_NAME_FIRST_CHAR: Final[int] = 0x21
_EHLO_NAME_LAST_CHAR: Final[int] = 0x7E


def _check_local_hostname(value: str, *, label: str) -> None:
    """Raise ``ValueError`` unless *value* can be sent as the EHLO argument.

    The value is not echoed: a refused name may carry control characters.
    """
    if not value or not all(_EHLO_NAME_FIRST_CHAR <= ord(char) <= _EHLO_NAME_LAST_CHAR for char in value):
        raise InvalidInputError(f"{label} must be non-empty printable ASCII without spaces")


def _check_timeout(value: float) -> None:
    """Raise unless *value* is a usable socket timeout: positive and finite."""
    _check_seconds(value, label="smtp_timeout")


def _check_seconds(value: float, *, label: str) -> None:
    """Raise unless *value* is a positive, finite number of seconds.

    The non-positive check runs first, so a timeout refused before keeps its
    message; NaN and infinity, which ``value <= 0`` let through to fail later as
    an unrelated delivery error, get their own.
    """
    if value <= 0:
        raise InvalidInputError(f"{label} must be positive, got {value}")
    if not math.isfinite(value):
        raise InvalidInputError(f"{label} must be a finite number of seconds, got {value}")


@functools.cache
def _default_local_hostname() -> str:
    """Return the EHLO name smtplib would compute, looked up once per process.

    Why
        smtplib calls ``socket.getfqdn()`` (a reverse DNS lookup) for every
        connection it opens without ``local_hostname``, and delivery opens one
        connection per recipient; on a host with slow reverse DNS each one
        waits for it. The rule is smtplib's own: the FQDN when it has a dot,
        else an address literal (RFC 5321 section 4.1.3).
    """
    fqdn = socket.getfqdn()
    if "." in fqdn:
        return fqdn
    try:
        return f"[{socket.gethostbyname(socket.gethostname())}]"
    except socket.gaierror:
        return "[127.0.0.1]"


@dataclass(frozen=True)
class AttachmentSecurityOptions:
    """### AttachmentSecurityOptions {#lib-mail-attachmentsecurityoptions}

    **Purpose:** Capture the resolved attachment security options for a single
    send operation so validation helpers receive one immutable object.

    **Fields:**
    - `allowed_extensions: frozenset[str] | None` - When set, only these
      extensions are allowed (whitelist mode).
    - `blocked_extensions: frozenset[str]` - Extensions to reject (ignored
      when whitelist is active).
    - `allowed_directories: frozenset[pathlib.Path] | None` - When set,
      attachments must reside under one of these directories.
    - `blocked_directories: frozenset[pathlib.Path]` - Directories from which
      attachments cannot be read.
    - `max_size_bytes: int | None` - Maximum attachment size in bytes.
    - `allow_symlinks: bool` - Whether symlinks are permitted.
    - `raise_on_violation: bool` - Whether violations raise or just warn.
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

    Why
        Centralises security option resolution so callers remain declarative.

    Inputs
    ------
    settings:
        The `ConfMail` whose values fill in anything not passed explicitly.
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
    allowed_ext = explicit_allowed_extensions if explicit_allowed_extensions is not None else settings.attachment_allowed_extensions
    blocked_ext = explicit_blocked_extensions if explicit_blocked_extensions is not None else settings.attachment_blocked_extensions
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
    )


# Bounds one logged failure line so a hostile or chatty server reply cannot
# flood the log.
_FAILURE_TEXT_LIMIT: Final[int] = 200


def _printable(text: str) -> str:
    """Return *text* with every control character (CR, LF, ESC, NUL, ...) replaced by a space.

    Why
        A multi-line or escape-laden server reply must not forge extra log
        lines or terminal sequences in whatever renders the record.

    Examples
    --------
    >>> _printable("535 denied" + chr(10) + "forged")
    '535 denied forged'
    """
    return "".join(character if character.isprintable() else " " for character in text)


def _describe_failure(error: BaseException) -> str:
    """Return a one-line, credential-free description of a delivery failure.

    Why
        The per-host failure log used to attach the whole exception. An
        exception raised while encoding SMTP AUTH quotes the AUTH string,
        password included, in its repr, and structured loggers serialise that
        repr. Only the text of an ``OSError`` is kept (every
        ``smtplib.SMTPException`` is one): for the stdlib transport it comes
        from the OS, the TLS layer or the server reply. A custom ``Transport``
        can raise an ``OSError`` with any text, and that text is logged as
        given. Anything else is logged by type name only.

    Examples
    --------
    >>> _describe_failure(ValueError("anything"))
    'ValueError'
    >>> _describe_failure(smtplib.SMTPAuthenticationError(535, b"5.7.8 invalid"))
    'SMTPAuthenticationError 535 5.7.8 invalid'
    """
    name = type(error).__name__
    if isinstance(error, smtplib.SMTPResponseException):
        reply = error.smtp_error
        text = reply.decode("utf-8", "replace") if isinstance(reply, bytes) else str(reply)
        return _printable(f"{name} {error.smtp_code} {text}")[:_FAILURE_TEXT_LIMIT]
    if isinstance(error, OSError):
        return _printable(f"{name}: {error}")[:_FAILURE_TEXT_LIMIT]
    return name


def _deliver_to_any_host(*, sender: str, recipient: str, message: IO[bytes], plan: _DeliveryPlan) -> bool:
    """Attempt delivery of one composed message across hosts until one succeeds.

    Why
        Encapsulates failover logic to keep orchestration linear. The same
        message stream is rewound and reused for every host attempt.

    Inputs
    ------
    sender, recipient:
        Envelope addresses.
    message:
        The complete message for this recipient (headers and body).
    plan:
        Hosts to try in order, resolved delivery options, and the transport.

    Outputs
    -------
    bool
        ``True`` if any host accepts the message; ``False`` otherwise.

    Side Effects
    ------------
    Performs network I/O, logs one credential-free WARNING per failed host (no
    traceback attached).
    """

    for host in plan.hosts:
        try:
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
                _printable(recipient),
                _printable(host),
                extra={"sender": _printable(sender), "recipient": _printable(recipient), "host": _printable(host)},
            )
            return True
        except Exception as error:
            clean_recipient = _printable(recipient)
            clean_host = _printable(host)
            warning_call = (
                'can not send mail to "%s" via host "%s": %s',
                (clean_recipient, clean_host, _describe_failure(error)),
                {
                    "sender": _printable(sender),
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
    """Build *recipient*'s message from its header block and the shared body, deliver it, and close it."""
    message = _message_for(header_lines, body)
    try:
        return _deliver_to_any_host(sender=sender, recipient=recipient, message=message, plan=plan)
    finally:
        message.close()


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

_SMTP_AUTH_OK: Final[int] = 235
_SMTP_AUTH_CONTINUE: Final[int] = 334
# smtplib.SMTP.login treats 503 ("already authenticated") as success; mirrored here.
_SMTP_ALREADY_AUTHENTICATED: Final[int] = 503

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
    host. An OSError (including any smtplib.SMTPException) raised by deliver()
    is logged with its text, stripped of control characters; any other
    exception is logged by type name only. Do not put a credential into the
    text of an OSError.
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
        local_hostname = delivery.local_hostname or _default_local_hostname()
        with (
            smtplib.SMTP(hostname, port=port or 0, local_hostname=local_hostname, timeout=delivery.timeout) as smtp_connection,
            _session_deadline(smtp_connection, delivery.deadline),
        ):
            smtp_connection.ehlo_or_helo_if_needed()
            if delivery.use_starttls:
                smtp_connection.starttls(context=_build_starttls_context(verify=delivery.starttls_verify))
                # RFC 3207: server capabilities must be re-fetched after TLS.
                smtp_connection.ehlo()
            if delivery.credentials is not None:
                if not delivery.use_starttls:
                    # Allowed (an internal relay may offer no TLS), but never silently.
                    logger.warning(
                        'sending SMTP credentials to host "%s" without TLS (STARTTLS is off)',
                        _printable(host),
                        extra={"host": _printable(host)},
                    )
                username, password = delivery.credentials
                _authenticate(smtp_connection, username, password)
            smtp_connection.ehlo_or_helo_if_needed()

            message.seek(0)
            if smtp_connection.has_extn("chunking"):
                _send_via_bdat(smtp_connection, sender, recipient, message)
            else:
                _send_via_data(smtp_connection, sender, recipient, message)


@contextmanager
def _session_deadline(smtp_connection: smtplib.SMTP, seconds: float | None) -> Generator[None, None, None]:
    """Bound the whole SMTP session to *seconds*, raising ``TimeoutError`` past it.

    Why
        The socket timeout bounds ONE read or write, so a server that answers a
        byte at a time keeps a session alive indefinitely. When the deadline
        passes, a watchdog thread shuts the socket down, which ends whatever
        read or write is blocked; the resulting failure is reported as a
        ``TimeoutError`` naming the deadline, so the host counts as failed and
        the next one is tried.
    """
    if seconds is None:
        yield
        return
    expired = threading.Event()

    def cut() -> None:
        expired.set()
        connection_socket = smtp_connection.sock
        if connection_socket is not None:
            with suppress(OSError):
                connection_socket.shutdown(socket.SHUT_RDWR)

    watchdog = threading.Timer(seconds, cut)
    watchdog.daemon = True
    watchdog.start()
    try:
        yield
    except OSError as error:
        if expired.is_set():
            raise TimeoutError(f"SMTP session did not finish within the delivery deadline of {seconds} seconds") from error
        raise
    finally:
        watchdog.cancel()


def _authenticate(smtp_connection: smtplib.SMTP, username: str, password: str) -> None:
    """Log in, using UTF-8 AUTH PLAIN only when the credentials are not ASCII.

    Why
        stdlib ``smtplib`` encodes every AUTH exchange as ASCII, so a non-ASCII
        password raises ``UnicodeEncodeError`` whose repr quotes the whole AUTH
        string. ASCII credentials keep the stdlib path unchanged.
    """
    if username.isascii() and password.isascii():
        smtp_connection.login(username, password)
        return
    _login_plain_utf8(smtp_connection, username, password)


def _login_plain_utf8(smtp_connection: smtplib.SMTP, username: str, password: str) -> None:
    """Authenticate with RFC 4616 AUTH PLAIN, credentials encoded as UTF-8.

    Raises
    ------
    smtplib.SMTPNotSupportedError
        The server offers no AUTH, or no PLAIN mechanism.
    smtplib.SMTPAuthenticationError
        The server rejected the credentials, or answered a second 334;
        carries only the server reply.
    """
    if not smtp_connection.has_extn("auth"):
        raise smtplib.SMTPNotSupportedError("SMTP AUTH extension not supported by server.")
    mechanisms = smtp_connection.esmtp_features["auth"].upper().split()
    if "PLAIN" not in mechanisms:
        raise smtplib.SMTPNotSupportedError("non-ASCII SMTP credentials need a server that offers AUTH PLAIN (RFC 4616)")
    token = base64.b64encode(b"\0" + username.encode("utf-8") + b"\0" + password.encode("utf-8")).decode("ascii")
    code, reply = smtp_connection.docmd("AUTH", "PLAIN " + token)
    if code == _SMTP_AUTH_CONTINUE:
        # A server that ignores the initial response asks for it with an empty
        # 334 challenge (RFC 4954); smtplib.SMTP.auth answers the same way, once.
        code, reply = smtp_connection.docmd(token)
    if code not in (_SMTP_AUTH_OK, _SMTP_ALREADY_AUTHENTICATED):
        raise smtplib.SMTPAuthenticationError(code, reply)


def _require_socket(smtp_connection: smtplib.SMTP) -> socket.socket:
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


@dataclass(frozen=True)
class _MessageContent:
    """The recipient-independent content of one `send()` call."""

    plain_body: str
    html_body: str
    attachments: tuple[AttachmentPayload, ...]


def _new_spool() -> IO[bytes]:
    """Return an empty spooled temp file: in memory below ``_SPOOL_MAX_SIZE``, on disk above it."""
    # Returned open and closed by the caller once the bytes are delivered, so
    # it cannot be opened as a `with` block here.
    return cast("IO[bytes]", tempfile.SpooledTemporaryFile(max_size=_SPOOL_MAX_SIZE))


def _compose_body(content: _MessageContent) -> IO[bytes]:
    """Encode everything below the per-recipient headers into a rewound spool, once.

    Why
        The body and every attachment are the same for each recipient, so they
        are base64-encoded once per ``send()`` and each recipient's message is
        its own header block plus a copy of this spool. Serialising into a
        ``SpooledTemporaryFile`` keeps a large message off the heap, and
        ``email.policy.SMTP`` yields RFC 5321 CRLF line endings, so the DATA and
        BDAT senders only add transfer framing.

    Outputs
    -------
    IO[bytes]
        Spool positioned at offset 0: the MIME headers of the message body
        (``MIME-Version``, ``Content-Type``, ...), a blank line, and the body.
        Closed on any failure.
    """
    spool = _new_spool()
    try:
        _write_body(spool, content)
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


def _write_body(spool: IO[bytes], content: _MessageContent) -> None:
    body_message = _build_body_message(content.plain_body, content.html_body)
    if not content.attachments:
        # No attachments: the body message is the whole message body (it is small).
        spool.write(_flatten_message(body_message))
        return

    # With attachments: hand-write a multipart/mixed so each attachment's base64
    # is streamed from its file instead of held in an in-memory message part.
    boundary = f"==============={uuid.uuid4().hex}=="
    outer = EmailMessage()
    outer["MIME-Version"] = "1.0"
    outer["Content-Type"] = f'multipart/mixed; boundary="{boundary}"'
    delimiter = b"--" + boundary.encode("ascii") + b"\r\n"
    spool.write(_header_block(outer))
    # First body part: the (small) text/alternative message, headers and all.
    spool.write(delimiter)
    spool.write(_flatten_message(body_message))
    spool.write(b"\r\n")
    for attachment in content.attachments:
        spool.write(delimiter)
        _write_attachment_part(spool, attachment)
    spool.write(b"--" + boundary.encode("ascii") + b"--\r\n")


def _compose_body_once(content: _MessageContent, *, raise_on_violation: bool) -> IO[bytes]:
    """Compose the shared body; in warn mode drop an attachment that grew past its limit and retry.

    A file that grows past the size limit while it is read is refused like an
    oversized file: raised in strict mode, logged and left out in warn mode.
    """
    while True:
        try:
            return _compose_body(content)
        except AttachmentSecurityError as exc:
            if raise_on_violation:
                raise
            violation = exc
        _log_violation(violation, str(violation.path))
        content = _MessageContent(
            plain_body=content.plain_body,
            html_body=content.html_body,
            attachments=tuple(attachment for attachment in content.attachments if attachment.source != violation.path),
        )


def _envelope_header_lines(*, sender: str, recipient: str, subject: str) -> bytes:
    """Return the per-recipient header lines (Subject, From, To, Date), CRLF-terminated, no blank line."""
    envelope = EmailMessage()
    envelope["Subject"] = subject
    envelope["From"] = sender
    envelope["To"] = recipient
    envelope["Date"] = formatdate(localtime=True)
    return _header_lines(envelope)


def _message_for(header_lines: bytes, body: IO[bytes]) -> IO[bytes]:
    """Return one recipient's complete message: its header lines, then a copy of the shared body.

    The copy streams in ``_STREAM_CHUNK_SIZE`` pieces, so memory stays at one
    chunk; the attachments are not read or encoded again.
    """
    spool = _new_spool()
    try:
        spool.write(header_lines)
        body.seek(0)
        shutil.copyfileobj(body, spool, _STREAM_CHUNK_SIZE)
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


# Control characters a subject may not carry: CR and LF would end the header (the
# email package refuses those itself), the rest reach the recipient raw. TAB is
# legal folding whitespace in an unstructured header.
_SUBJECT_ALLOWED_CONTROLS: Final[frozenset[str]] = frozenset({"\t"})


def _check_subject(subject: str) -> None:
    """Refuse a subject carrying a control character, without echoing it.

    CR and LF keep the email package's own message, which ``send()`` raised for
    them before.
    """
    if "\r" in subject or "\n" in subject:
        raise InvalidInputError("Header values may not contain linefeed or carriage return characters")
    if any(unicodedata.category(character) == "Cc" and character not in _SUBJECT_ALLOWED_CONTROLS for character in subject):
        raise InvalidInputError("mail_subject must not contain control characters (only TAB is allowed)")


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


def _header_lines(message: EmailMessage) -> bytes:
    """Serialise a message's headers to CRLF bytes, without the terminating blank line."""
    out = bytearray()
    for name, value in message.items():
        out += email_policy.SMTP.fold_binary(name, value)
    return bytes(out)


def _header_block(message: EmailMessage) -> bytes:
    """Serialise a message's headers to CRLF bytes, terminated by a blank line."""
    return _header_lines(message) + b"\r\n"


def _flatten_message(message: EmailMessage) -> bytes:
    """Serialise a whole (small) message to CRLF bytes via the SMTP policy."""
    buffer = io.BytesIO()
    BytesGenerator(buffer, policy=email_policy.SMTP).flatten(message)
    return buffer.getvalue()


def _write_attachment_part(spool: IO[bytes], attachment: AttachmentPayload) -> None:
    """Write one base64 attachment part, streaming the checked file's bytes in chunks.

    Why
        Encoding the file incrementally (57 raw bytes per 76-char base64 line,
        read in a large multiple so whole lines are emitted per chunk) keeps peak
        memory at roughly one chunk instead of the full attachment plus its
        base64 expansion. The bytes are counted as they are read, so a file that
        grows past the size limit after it was checked is refused, having been
        read at most one chunk past the limit.
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
    handle = attachment.handle
    handle.seek(0)
    total = 0
    while True:
        chunk = handle.read(raw_chunk)
        if not chunk:
            break
        total += len(chunk)
        if attachment.size_limit is not None and total > attachment.size_limit:
            raise AttachmentSecurityError(
                path=attachment.source,
                reason=f'file grew past the limit of {attachment.size_limit} bytes while it was read: "{attachment.source}"',
                violation_type=AttachmentViolation.SIZE,
            )
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
    # A ".." COMPONENT climbs out of a directory; "report..final.txt" is just a name.
    if ".." in pathlib.Path(original_str).parts:
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
    # Forward slashes so one pattern serves Windows too; casefolded because macOS and
    # Windows file systems are case-insensitive, where .SSH/config IS ~/.ssh/config.
    path_str_normalised = str(path).replace("\\", "/").casefold()

    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.casefold() in path_str_normalised:
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
    ext = _effective_suffix(path.name)

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


def _effective_suffix(name: str) -> str:
    """Return the lower-cased extension a recipient's system sees for *name*.

    Why
        Windows drops trailing dots and spaces from a file name, so ``x.exe.``
        and ``x.exe `` are saved as ``x.exe``; :attr:`pathlib.PurePath.suffix`
        reports ``.`` and ``.exe `` for them, which no blocklist entry matches.

    Examples
    --------
    >>> _effective_suffix("x.sh. . ")
    '.sh'
    >>> _effective_suffix("REPORT.PDF")
    '.pdf'
    """
    return pathlib.PurePath(name.rstrip(". ") or name).suffix.lower()


def _check_size(path: pathlib.Path, size: int, max_size: int | None) -> None:
    """Raise when *size* (of the opened file at *path*) exceeds *max_size*."""
    if max_size is not None and size > max_size:
        raise AttachmentSecurityError(
            path=path,
            reason=f'file size {size} bytes exceeds limit {max_size} bytes: "{path}"',
            violation_type=AttachmentViolation.SIZE,
        )


# How an attachment is opened. O_NOFOLLOW refuses a symlink as the last
# component: the path opened is already resolved, so a symlink there was swapped
# in after the checks. O_NONBLOCK keeps a FIFO swapped in from blocking the open.
# O_BINARY matters on Windows only. Each is 0 where the OS lacks it.
_ATTACHMENT_OPEN_FLAGS: Final[int] = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)

# errno of open(O_NOFOLLOW) on a symlink: ELOOP on Linux and macOS, EMLINK on FreeBSD.
_NOFOLLOW_ERRNOS: Final[frozenset[int]] = frozenset({errno.ELOOP, errno.EMLINK})


def _changed_after_check(path: pathlib.Path) -> AttachmentSecurityError:
    return AttachmentSecurityError(
        path=path,
        reason=f'file changed after it was checked: "{path}"',
        violation_type=AttachmentViolation.CHANGED,
    )


def _open_attachment(path: pathlib.Path, max_size: int | None) -> IO[bytes] | None:
    """Open the checked, resolved *path* once and prove it is the file that was checked.

    Why
        Reading the file again later by name (once per recipient, as before)
        lets a path swapped after the checks - a symlink to ``/etc/passwd``, a
        file grown past the limit - reach the message. The file is opened here
        once, compared with what was checked (same device and inode, still a
        regular file, size within the limit), and that open file is what the
        message body is encoded from.

    Outputs
    -------
    IO[bytes] | None
        The opened file, or ``None`` when *path* does not exist or is not a
        regular file (the caller reports it as missing).

    Raises
    ------
    AttachmentSecurityError
        ``CHANGED`` when the path became a symlink or another file after the
        checks; ``SIZE`` when the file exceeds *max_size*.
    """
    try:
        checked = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(checked.st_mode):
        raise _changed_after_check(path)
    if not stat.S_ISREG(checked.st_mode):
        return None
    try:
        descriptor = os.open(path, _ATTACHMENT_OPEN_FLAGS)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in _NOFOLLOW_ERRNOS:
            raise _changed_after_check(path) from None
        raise
    handle = os.fdopen(descriptor, "rb")
    try:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
            raise _changed_after_check(path)
        _check_size(path, opened.st_size, max_size)
    except BaseException:
        handle.close()
        raise
    return handle


def _validate_attachment_security(
    path: pathlib.Path,
    original_path_str: str,
    security: AttachmentSecurityOptions,
) -> pathlib.Path:
    """Run the path-based security checks for a single attachment.

    Why
        Provides a single entry point for attachment path validation. The size
        is checked on the opened file (:func:`_open_attachment`), not here.

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
    Raises AttachmentSecurityError if any check fails. File existence is not
    checked here.
    """
    _check_path_traversal(path, original_path_str)
    resolved_path = _check_symlink(path=path, allow_symlinks=security.allow_symlinks)
    _check_sensitive_patterns(resolved_path)
    _check_directory_restrictions(
        resolved_path,
        security.allowed_directories,
        security.blocked_directories,
    )
    _check_extension(
        resolved_path,
        security.allowed_extensions,
        security.blocked_extensions,
    )
    return resolved_path


def _prepare_attachments(
    paths: tuple[pathlib.Path, ...],
    security: AttachmentSecurityOptions,
    *,
    raise_on_missing: bool,
) -> tuple[AttachmentPayload, ...]:
    """Check each attachment path, open the checked file once, and return the payloads.

    Why
        Validates attachment existence and security before SMTP attempts begin,
        and ties what is sent to the file that was checked.

    Inputs
    ------
    paths:
        Tuple of candidate filesystem paths (may be empty).
    security:
        Resolved security options for validation.
    raise_on_missing:
        When ``True``, missing files raise ``AttachmentNotFoundError``; when
        ``False``, a warning is logged and the attachment is skipped.

    Outputs
    -------
    tuple[AttachmentPayload, ...]
        Payloads holding open files; the caller closes them
        (:func:`_close_attachments`). On any failure, those already opened are
        closed before the error propagates.

    Side Effects
    ------------
    Opens files; logs or raises when missing or security violations occur.
    """
    prepared: list[AttachmentPayload] = []
    try:
        for path in paths:
            payload = _prepare_attachment(path, security, raise_on_missing=raise_on_missing)
            if payload is not None:
                prepared.append(payload)
    except BaseException:
        _close_attachments(tuple(prepared))
        raise
    return tuple(prepared)


def _prepare_attachment(path: pathlib.Path, security: AttachmentSecurityOptions, *, raise_on_missing: bool) -> AttachmentPayload | None:
    """Check and open one attachment; ``None`` when it is skipped (warn mode, or missing and tolerated)."""
    original_path_str = str(path)
    try:
        validated_path = _validate_attachment_security(path, original_path_str, security)
        handle = _open_attachment(validated_path, security.max_size_bytes)
    except AttachmentSecurityError as exc:
        if security.raise_on_violation:
            raise
        _log_violation(exc, original_path_str)
        return None

    if handle is None:
        clean_path = _printable(str(validated_path))
        if raise_on_missing:
            raise AttachmentNotFoundError(f'Attachment File "{clean_path}" can not be found')
        logger.warning(
            'Attachment File "%s" can not be found',
            clean_path,
            extra={"attachment_path": clean_path, "skipped": "attachment"},
        )
        return None

    return AttachmentPayload(
        filename=validated_path.name,
        source=validated_path,
        handle=handle,
        size_limit=security.max_size_bytes,
    )


def _log_violation(exc: AttachmentSecurityError, original_path_str: str) -> None:
    """Log a skipped attachment's violation (warn mode)."""
    # `exc.reason` and `original_path_str` are both built from the
    # caller-supplied path; `AttachmentSecurityError.__init__` already
    # cleans `.reason`, but the path is cleaned again here too, as
    # defense in depth and for consistency with every other log call.
    logger.warning(
        "Attachment security violation: %s",
        _printable(exc.reason),
        extra={
            "attachment_path": _printable(original_path_str),
            "violation_type": exc.violation_type.value,
            "skipped": "attachment",
        },
    )


def _close_attachments(attachments: tuple[AttachmentPayload, ...]) -> None:
    for attachment in attachments:
        attachment.handle.close()


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
        raise InvalidInputError("no valid smtphost passed")
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
    elif isinstance(recipients, Sequence):  # pyright: ignore[reportUnnecessaryIsInstance] - a caller ignoring the annotation can pass anything
        raw_items = recipients
    else:  # pragma: no cover - defensive guard
        raise InvalidInputError("invalid type of mail_addresses")

    cleaned = [_normalise_email_address(item) for item in raw_items]
    filtered = [value for value in cleaned if value]
    unique = tuple(dict.fromkeys(filtered))

    valid: list[str] = []
    for entry in unique:
        try:
            validate_email_address(entry)
        except ValueError:
            # `entry` is exactly the value that FAILED validation, so unlike
            # `recipients`/`failed_recipients` elsewhere in this module it is
            # not provably free of control characters; clean it before it
            # reaches a log line or an exception message a caller may log.
            clean_entry = _printable(entry)
            if raise_on_invalid:
                raise InvalidInputError(f"invalid recipient {clean_entry}") from None
            logger.warning("invalid recipient %s", clean_entry, extra={"recipient": clean_entry, "skipped": "recipient"})
            continue
        valid.append(entry)

    if not valid:
        raise InvalidInputError("no valid recipients")
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
        Refuses a host carrying userinfo or a path, without quoting it.

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
        return _checked_hosts([value])
    if isinstance(value, Iterable):
        items = list(cast("Iterable[Any]", value))
        if not all(isinstance(item, str) for item in items):
            raise InvalidInputError("smtphosts entries must be strings")
        return _checked_hosts(cast("list[str]", items))
    raise InvalidInputError("smtphosts must be a string, list of strings, or tuple of strings")


def _checked_hosts(raw_hosts: list[str]) -> list[str]:
    """Normalise each host, drop the blank ones, and validate the rest.

    Why
        A blank entry is what an empty environment value or a trailing comma
        in a list produces; :func:`send` already skips it, so the model reads
        it as absent rather than as a malformed host. Every other entry is
        checked with :func:`validate_smtp_host`, so a typo in a port or an
        IPv6 bracket is refused when the configuration is built instead of at
        the first delivery.
    """
    hosts = [_normalise_host(raw) for raw in raw_hosts]
    present = [host for host in hosts if host]
    for host in present:
        validate_smtp_host(host)
    return present


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
    btx_lib_mail.errors.InvalidInputError: invalid email address: 'invalid@'
    """

    if not EMAIL_PATTERN.fullmatch(address):
        raise InvalidInputError(f"invalid email address: {address!r}")


def _refuse_credentials_in_host(host: str) -> str:
    """Return *host* unchanged, or raise when it carries userinfo, a path, or an interior control character.

    Why
        ``smtp://user:<password>@relay`` in a host list puts the password into
        every log line and error text that names the host. The error never
        quotes the value.

        A host carrying a newline or an escape sequence can forge an extra log
        line or a terminal control sequence wherever the host is later logged.
        Callers run this after :func:`_normalise_host`, which trims OUTER
        whitespace, so only an INTERIOR whitespace or control character is
        refused here; an ordinary ``" smtp.example.com "`` from an env file
        still validates.
    """
    if "@" in host or "/" in host:
        # Never quote the value: a userinfo part here is a password in the wrong field.
        raise InvalidInputError("SMTP host must be host[:port]; it must not contain '@' or '/' (pass credentials as smtp_username and smtp_password)")
    if any(not character.isprintable() or character.isspace() for character in host):
        # Never quote the value: it may itself be the forged content.
        raise InvalidInputError("SMTP host must not contain whitespace or control characters")
    return host


def validate_smtp_host(host: str) -> None:
    """Raise ``ValueError`` when *host* is not a valid SMTP host string.

    Accepts the following forms:

    - ``hostname``
    - ``hostname:port``
    - ``[IPv6]:port``  (e.g. ``[::1]:25``)
    - ``[IPv6]``       (e.g. ``[::1]``)

    Never accepted: userinfo (user:password@host) or a URL (smtp://...), for
    which the error does not echo the value; several hosts in one string
    (``a.example.com,b.example.com``); a port with no host name (``:25``);
    an IPv6 address without brackets (``fe80::1``), whose last group
    would otherwise be read as the port; and a port that is not plain ASCII
    digits in 1-65535 (``+25``, ``2_5``, non-ASCII digits).

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
    >>> validate_smtp_host("smtp.example.com:abc")
    Traceback (most recent call last):
        ...
    btx_lib_mail.errors.InvalidInputError: invalid smtp port in "smtp.example.com:abc"
    >>> validate_smtp_host("a.example.com,b.example.com")
    Traceback (most recent call last):
        ...
    btx_lib_mail.errors.InvalidInputError: SMTP host must be one host per entry; pass several hosts as a list, got "a.example.com,b.example.com"
    """

    if not host:
        raise InvalidInputError("empty SMTP host")

    _refuse_credentials_in_host(host)

    # The port and bracket checks run first and the shape checks only on what they let
    # through, so a host the 2.x checks refused keeps its 2.x message and a caller (or a
    # consumer's test) matching that message is unaffected.
    _validate_port_and_brackets(host)
    _validate_host_shape(host)


def _validate_port_and_brackets(host: str) -> None:
    """Validate the bracket syntax and the port, splitting a port off at the last colon."""
    if not host.startswith("["):
        if ":" in host:
            _validate_port(host.rsplit(":", 1)[1], host)
        return
    bracket_end = host.find("]")
    if bracket_end == -1:
        raise InvalidInputError(f'missing closing bracket in "{host}"')
    remainder = host[bracket_end + 1 :]
    if remainder == "":
        return
    if not remainder.startswith(":"):
        raise InvalidInputError(f'unexpected characters after bracket in "{host}"')
    _validate_port(remainder[1:], host)


def _validate_host_shape(host: str) -> None:
    """Refuse a host whose port is valid but whose shape is not one host name.

    Runs after :func:`_validate_port_and_brackets`, so every input reaching it has a
    well-formed port; what is left is two hosts in one string, a host name containing a
    colon (an IPv6 address without brackets, whose last group would read as the port),
    and an empty host name.
    """
    if "," in host:
        raise InvalidInputError(f'SMTP host must be one host per entry; pass several hosts as a list, got "{host}"')
    if host.startswith("["):
        name = host[1 : host.find("]")]
    else:
        name = host.rsplit(":", 1)[0] if ":" in host else host
        if ":" in name:
            raise InvalidInputError(f'more than one ":" in "{host}"; an IPv6 address must be in brackets, as [addr] or [addr]:port')
    if not name:
        raise InvalidInputError(f'missing host name in "{host}"')


def _validate_port(port_str: str, original: str) -> None:
    """Validate that *port_str* is plain ASCII digits naming a port in the 1-65535 range.

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
        raise InvalidInputError(f'invalid smtp port in "{original}"') from exc
    if not (min_port <= port <= max_port):
        # The message names the host and nothing derived from it: a model that scrubs
        # the host as a credential can only remove the whole string, not a re-quoted port.
        raise InvalidInputError(f'port must be {min_port}-{max_port} in "{original}"')
    # int() also takes a sign, "_" separators and any Unicode digits; checked after the
    # range so a port the range check already refused keeps that message.
    if not (port_str.isascii() and port_str.isdigit()):
        raise InvalidInputError(f'invalid smtp port in "{original}"')


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
