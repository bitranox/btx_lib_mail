"""`ConfMail`, the validated settings model, and `conf`, the module-global instance `send()` reads.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING, Any, cast

from pydantic import ConfigDict, Field, SecretStr, ValidationInfo, field_validator, model_validator

from ._attachments import (
    default_blocked_directories,
    default_blocked_extensions,
    normalise_extensions,
)
from ._validation import check_local_hostname, check_seconds, check_timeout, collect_host_inputs
from .errors import ConfigurationError, InvalidInputError
from .secret_safety import SecretSafeModel

if TYPE_CHECKING:
    from collections.abc import Iterable


class ConfMail(SecretSafeModel):
    """Hold the validated SMTP configuration, merging CLI options, environment variables, and defaults.

    A refused setting raises `ConfigurationError`, a pydantic `ValidationError`
    that is also a `BtxMailError`. A name that is not one of the fields below
    is refused with a `ConfigurationError` (`extra_forbidden`, naming the key,
    never its value), at construction and in `model_validate`. The `send()`
    keyword names are not field names: `ConfMail(use_starttls=False)` is
    refused, the field is `smtp_use_starttls`.

    The CLI resolves its defaults through this model, and `send` reads
    resolved values when per-call overrides are absent.

    Attributes:
        smtphosts: Ordered hosts in `host[:port]` form. Empty by default so
            callers must supply at least one host.
        raise_on_missing_attachments: When `True`, missing files raise
            `AttachmentNotFoundError` (a `FileNotFoundError`); otherwise the
            module logs a warning and continues.
        raise_on_invalid_recipient: When `True`, invalid addresses raise
            `InvalidInputError` (a `ValueError`); otherwise a warning is
            logged and delivery skips the address.
        recipient_max_count: Most recipients one `send()` call accepts,
            counted after duplicates are dropped and before any is validated;
            more is refused with `InvalidInputError` before any delivery
            (default 1000). `None` sets no limit. Must be positive when set.
        smtp_username: Optional username; must be populated together with
            `smtp_password` to enable authentication.
        smtp_password: Optional password as a `SecretStr`, masked in `repr()`
            and `model_dump()`; call `.get_secret_value()` (or
            `resolved_credentials()`) to read the plaintext. A plain string
            assigned to it is coerced to `SecretStr`. An int is accepted as
            its decimal text (config loaders parse digit strings as numbers);
            any other non-text value is refused, and validation errors of
            this model never carry the password (see `SecretSafeModel`).
        smtp_use_starttls: Enables `STARTTLS` negotiation before
            authentication when supported by the server.
        smtp_starttls_verify: When `True`, the `STARTTLS` handshake verifies
            the server certificate and hostname (the secure default). Set to
            `False` for an internal relay whose certificate is self-signed or
            has a hostname mismatch: the traffic stays encrypted but the
            certificate is not validated. Has no effect when
            `smtp_use_starttls` is `False`.
        smtp_timeout: Socket timeout in seconds applied to SMTP connections.
            Must be positive and finite.
        smtp_local_hostname: The name announced in `EHLO`/`HELO`. When
            `None`, the host's fully qualified name is looked up once per
            process and reused (a domain literal such as `[192.0.2.7]` when
            it has no dot). Set it where reverse DNS is slow, since that
            lookup otherwise delays the first connection. Must be non-empty
            printable ASCII without spaces.
        smtp_delivery_deadline: Upper bound in seconds for one SMTP session
            (one recipient via one host), from the open connection to the
            server's final reply. `smtp_timeout` bounds each socket
            operation, so a server answering one byte at a time never trips
            it; this bounds the whole session, after which the host counts
            as failed and the next one is tried. `None` sets no bound. Must
            be positive and finite when set.
        attachment_allowed_extensions: When set, only these extensions are
            allowed (whitelist mode). When `None`, the blocked extensions
            list applies instead.
        attachment_blocked_extensions: Extensions to reject. Ignored when
            `attachment_allowed_extensions` is set. Defaults to the
            dangerous extensions of BOTH platform families
            (`DANGEROUS_EXTENSIONS_POSIX | DANGEROUS_EXTENSIONS_WINDOWS`),
            since the recipient's system decides what an attachment runs as.
            An empty set with no allowlist is refused unless
            `attachment_allow_empty_blocklists` is `True`.
        attachment_allowed_directories: When set, attachments must reside
            under one of these directories.
        attachment_blocked_directories: Directories from which attachments
            cannot be read. Ignored when `attachment_allowed_directories` is
            set. Defaults to OS-specific sensitive directories. An empty set
            with no allowlist is refused unless
            `attachment_allow_empty_blocklists` is `True`.
        attachment_max_size_bytes: Maximum attachment size in bytes (default
            25 MiB). `None` disables size checking.
        attachment_max_count: Most attachments one `send()` call accepts;
            more is refused with `InvalidInputError` before any file is
            checked or opened (default 100). `None` sets no limit. Must be
            positive when set.
        attachment_allow_symlinks: When `False`, a path whose last component
            is a symlink is rejected; when `True`, it is resolved and
            validated. A symlinked directory along the path is followed
            either way; every rule runs on the resolved target.
        attachment_raise_on_security_violation: When `True`, security
            violations raise `AttachmentSecurityError`; when `False`, they
            log a warning and skip the attachment.
        attachment_allow_empty_blocklists: When `False`, an empty
            `attachment_blocked_extensions` or `attachment_blocked_directories`
            whose allowlist is not set is refused at validation (construction
            and assignment), because it blocks nothing: a configuration
            loader that turns an empty list meaning "defaults" into an empty
            set would otherwise switch the protection off silently. Set
            `True` to block nothing on purpose. An explicit
            `send(attachment_blocked_*=frozenset())` keyword is never
            checked.
    """

    smtphosts: list[str] = Field(default_factory=list)
    raise_on_missing_attachments: bool = True
    raise_on_invalid_recipient: bool = True
    recipient_max_count: int | None = 1000
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_use_starttls: bool = True
    smtp_starttls_verify: bool = True
    smtp_timeout: float = 30.0
    smtp_local_hostname: str | None = None
    smtp_delivery_deadline: float | None = None

    # Attachment security settings
    attachment_allowed_extensions: frozenset[str] | None = None
    attachment_blocked_extensions: frozenset[str] = Field(default_factory=default_blocked_extensions)
    attachment_allowed_directories: frozenset[pathlib.Path] | None = None
    attachment_blocked_directories: frozenset[pathlib.Path] = Field(default_factory=default_blocked_directories)
    attachment_max_size_bytes: int | None = 26_214_400  # 25 MiB
    attachment_max_count: int | None = 100
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

        Ensures assignment is resilient to `None`, strings, and iterables.

        Args:
            value: Raw value provided to the model (`None` | `str` | iterable).

        Returns:
            Normalised host collection.
        """
        return collect_host_inputs(value)

    @field_validator("smtp_password", mode="before")
    @classmethod
    def _coerce_password(cls, value: Any) -> Any:
        """Accept text and whole numbers; refuse anything else without echoing it.

        Layered config loaders turn an all-digit environment value into an
        `int` before it reaches this model, and quoting it does not help (the
        quotes are kept as characters). A float, a bool or a container is
        never a password a loader produced faithfully, so it is refused with
        only its type named.

        Note:
            A loader that parsed `0123` as the number 123 has already lost
            the leading zero; this model cannot restore it.

        Args:
            value: Raw value provided to the model.

        Returns:
            The value, unchanged or coerced to text.

        Raises:
            InvalidInputError: If value is not text, a whole number, or None.
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

        A zero or negative socket timeout is never valid for SMTP connections.

        Args:
            value: Timeout in seconds after Pydantic type coercion.

        Returns:
            The validated positive timeout.

        Raises:
            InvalidInputError: If value is not positive and finite.
        """
        check_timeout(value)
        return value

    @field_validator("smtp_delivery_deadline", mode="after")
    @classmethod
    def _validate_delivery_deadline(cls, value: float | None) -> float | None:
        """Refuse a deadline that is not a positive, finite number of seconds.

        Args:
            value: Deadline in seconds after Pydantic type coercion, or None.

        Returns:
            The validated deadline, unchanged.

        Raises:
            InvalidInputError: If value is set but not positive and finite.
        """
        if value is not None:
            check_seconds(value, label="smtp_delivery_deadline")
        return value

    @field_validator("smtp_local_hostname", mode="after")
    @classmethod
    def _validate_local_hostname(cls, value: str | None) -> str | None:
        """Refuse an EHLO name that cannot be sent as one SMTP command argument.

        Args:
            value: EHLO name after Pydantic type coercion, or None.

        Returns:
            The validated EHLO name, unchanged.

        Raises:
            InvalidInputError: If value is set but not non-empty printable ASCII without spaces.
        """
        if value is not None:
            check_local_hostname(value, label="smtp_local_hostname")
        return value

    @field_validator("attachment_allowed_extensions", "attachment_blocked_extensions", mode="before")
    @classmethod
    def _normalise_extensions(cls, value: Any) -> frozenset[str] | None:
        """Normalise extension sets to lowercase with leading dots.

        Extensions should compare case-insensitively and consistently.

        Args:
            value: Raw extension set (None, set, frozenset, or iterable of strings).

        Returns:
            Normalised extension set with lowercase, dot-prefixed extensions.

        Raises:
            InvalidInputError: If value is not a set, frozenset, list, or tuple.
        """
        if value is None:
            return None
        if callable(value):
            # Handle default_factory case
            value = value()
        if not isinstance(value, (frozenset, set, list, tuple)):
            raise InvalidInputError("extensions must be a set, frozenset, list, or tuple of strings")
        return normalise_extensions(cast("Iterable[object]", value))

    @field_validator("attachment_allowed_directories", "attachment_blocked_directories", mode="before")
    @classmethod
    def _normalise_directories(cls, value: Any) -> frozenset[pathlib.Path] | None:
        """Normalise directory sets to resolved Path objects.

        Directories should be resolved for consistent comparison.

        Args:
            value: Raw directory set (None, set, frozenset, or iterable of paths/strings).

        Returns:
            Normalised directory set.

        Raises:
            InvalidInputError: If value is not a set, frozenset, list, or tuple, or an entry is not a string or Path.
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

    @field_validator("attachment_max_size_bytes", "attachment_max_count", "recipient_max_count", mode="after")
    @classmethod
    def _validate_ceiling(cls, value: int | None, info: ValidationInfo) -> int | None:
        """Validate that a size or count ceiling is positive when set.

        A zero or negative ceiling would refuse every message.

        Args:
            value: The ceiling (None to disable it).
            info: Names the field, for the message.

        Returns:
            The validated ceiling.

        Raises:
            InvalidInputError: If value is set but not positive.
        """
        if value is not None and value <= 0:
            raise InvalidInputError(f"{info.field_name} must be positive, got {value}")
        return value

    @model_validator(mode="after")
    def _refuse_an_empty_blocklist(self) -> ConfMail:
        """Refuse a blocked set that blocks nothing unless that is opted into.

        `[]` from a config file often means "use the defaults" to the loader
        that wrote it, while here it means "block nothing"; a silent
        switch-off of executable and system-directory blocking is the
        failure this prevents.

        Returns:
            This instance, unchanged.

        Raises:
            InvalidInputError: If a blocked set is empty and its matching allowlist is unset.
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
        """Provide downstream helpers with a single optional tuple rather than two separate optional strings.

        Returns:
            `(username, password)` with the plaintext password when both
            `smtp_username` and `smtp_password` are populated; `None`
            otherwise.
        """
        password = self.smtp_password.get_secret_value() if self.smtp_password is not None else None
        if self.smtp_username and password:
            return self.smtp_username, password
        return None


conf: ConfMail = ConfMail()
"""Global SMTP configuration surface used when per-call overrides are absent."""
