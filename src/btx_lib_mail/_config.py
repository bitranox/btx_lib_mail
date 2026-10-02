"""`ConfMail`, the validated settings model, and `conf`, the module-global instance `send()` reads.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING, Any, cast

from pydantic import ConfigDict, Field, SecretStr, field_validator, model_validator

from ._attachments import (
    default_blocked_directories,
    default_blocked_extensions,
)
from ._validation import check_local_hostname, check_seconds, check_timeout, collect_host_inputs
from .errors import ConfigurationError, InvalidInputError
from .secret_safety import SecretSafeModel

if TYPE_CHECKING:
    from collections.abc import Iterable


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
    attachment_blocked_extensions: frozenset[str] = Field(default_factory=default_blocked_extensions)
    attachment_allowed_directories: frozenset[pathlib.Path] | None = None
    attachment_blocked_directories: frozenset[pathlib.Path] = Field(default_factory=default_blocked_directories)
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

        return collect_host_inputs(value)

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

        check_timeout(value)
        return value

    @field_validator("smtp_delivery_deadline", mode="after")
    @classmethod
    def _validate_delivery_deadline(cls, value: float | None) -> float | None:
        """Refuse a deadline that is not a positive, finite number of seconds."""
        if value is not None:
            check_seconds(value, label="smtp_delivery_deadline")
        return value

    @field_validator("smtp_local_hostname", mode="after")
    @classmethod
    def _validate_local_hostname(cls, value: str | None) -> str | None:
        """Refuse an EHLO name that cannot be sent as one SMTP command argument."""
        if value is not None:
            check_local_hostname(value, label="smtp_local_hostname")
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
