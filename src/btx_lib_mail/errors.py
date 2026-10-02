"""## btx_lib_mail.errors {#module-btx-lib-mail-errors}

**Purpose:** Give every failure the library raises one common base,
`BtxMailError`, so a caller can catch "anything btx_lib_mail refused" in one
clause.

Each concrete class also keeps the builtin a caller caught before as a second
base (`InvalidInputError` is a `ValueError`, `DeliveryError` a `RuntimeError`,
and so on), so an existing `except ValueError:` keeps working, and so does a
CLI exit code derived from the builtin type.

**Contents:**
- `BtxMailError` - the common base.
- `InvalidInputError` - a refused argument value (also a `ValueError`).
- `ConfigurationError` - a refused `ConfMail` setting (also a pydantic
  `ValidationError`, so also a `ValueError`).
- `AttachmentNotFoundError` - a required attachment is missing (also a
  `FileNotFoundError`).
- `DeliveryError` - every host failed for at least one recipient (also a
  `RuntimeError`).

`AttachmentSecurityError` is a `BtxMailError` too; it lives with the
attachment checks in `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

from pydantic import ValidationError


class BtxMailError(Exception):
    """### BtxMailError {#errors-btxmailerror}

    **Purpose:** Common base of every exception btx_lib_mail raises on purpose.
    Catch it to handle any refusal or delivery failure of the library.

    **Example:**
    >>> from btx_lib_mail import validate_email_address
    >>> try:
    ...     validate_email_address("not-an-address")
    ... except BtxMailError as error:
    ...     print(type(error).__name__)
    InvalidInputError
    """


class InvalidInputError(BtxMailError, ValueError):
    """### InvalidInputError {#errors-invalidinputerror}

    **Purpose:** An argument value was refused: a sender, recipient, host,
    subject, EHLO name or timeout that cannot be used. Also a `ValueError`.
    """


class ConfigurationError(BtxMailError, ValidationError):
    """### ConfigurationError {#errors-configurationerror}

    **Purpose:** A `ConfMail` setting was refused, at construction, in
    `model_validate`/`model_validate_json`, or on assignment. It is a pydantic
    `ValidationError` (so also a `ValueError`) with the same `errors()`, title
    and redaction as before; the type adds only the common base.
    """


class AttachmentNotFoundError(BtxMailError, FileNotFoundError):
    """### AttachmentNotFoundError {#errors-attachmentnotfounderror}

    **Purpose:** A required attachment does not exist or is not a regular
    file. Also a `FileNotFoundError`.
    """


class DeliveryError(BtxMailError, RuntimeError):
    """### DeliveryError {#errors-deliveryerror}

    **Purpose:** Every SMTP host failed for at least one recipient. Also a
    `RuntimeError`.

    **Fields:**
    - `failed_recipients: tuple[str, ...]` - Recipients no host accepted.
    - `hosts: tuple[str, ...]` - The hosts that were tried, in order.

    Recipients not listed were delivered. The per-host reasons were logged as
    WARNING records while delivery ran.
    """

    # Defaulted so pickle, which rebuilds an exception from its args alone, can recreate it.
    def __init__(self, message: str, *, failed_recipients: tuple[str, ...] = (), hosts: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.failed_recipients = failed_recipients
        self.hosts = hosts


__all__ = [
    "AttachmentNotFoundError",
    "BtxMailError",
    "ConfigurationError",
    "DeliveryError",
    "InvalidInputError",
]
