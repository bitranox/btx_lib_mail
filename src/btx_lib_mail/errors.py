"""Give every failure the library raises one common base, `BtxMailError`.

A caller can catch "anything btx_lib_mail refused" in one clause.

Each concrete class also keeps the builtin a caller caught before as a second
base (`InvalidInputError` is a `ValueError`, `DeliveryError` a `RuntimeError`,
and so on), so an existing `except ValueError:` keeps working, and so does a
CLI exit code derived from the builtin type.

Contents:
    - `BtxMailError` - the common base.
    - `InvalidInputError` - a refused argument value (also a `ValueError`).
    - `ConfigurationError` - a refused `ConfMail` setting (also a pydantic
      `ValidationError`, so also a `ValueError`).
    - `AttachmentNotFoundError` - a required attachment is missing (also a
      `FileNotFoundError`).
    - `DeliveryError` - every host failed for at least one recipient (also a
      `RuntimeError`).

`AttachmentSecurityError` is a `BtxMailError` too; it is defined with the
attachment checks and importable from `btx_lib_mail`.
"""

from __future__ import annotations

from pydantic import ValidationError


class BtxMailError(Exception):
    """Serve as the common base of every exception btx_lib_mail raises on purpose.

    Catch it to handle any refusal or delivery failure of the library.

    Examples:
        >>> from btx_lib_mail import validate_email_address
        >>> try:
        ...     validate_email_address("not-an-address")
        ... except BtxMailError as error:
        ...     print(type(error).__name__)
        InvalidInputError
    """


class InvalidInputError(BtxMailError, ValueError):
    """Signal that an argument value was refused.

    Raised for a sender, recipient, host, subject, EHLO name or timeout that
    cannot be used. Also a `ValueError`.
    """


class ConfigurationError(BtxMailError, ValidationError):
    """Signal that a `ConfMail` setting was refused.

    Raised at construction, in `model_validate`/`model_validate_json`, or on
    assignment. It is a pydantic `ValidationError` (so also a `ValueError`):
    `errors()`, title and redaction are pydantic's, and the class adds the
    common base.
    """


class AttachmentNotFoundError(BtxMailError, FileNotFoundError):
    """Signal that a required attachment does not exist or is not a regular file.

    Also a `FileNotFoundError`.
    """


class DeliveryError(BtxMailError, RuntimeError):
    """Signal that every SMTP host failed for at least one recipient.

    Also a `RuntimeError`. Recipients not listed in `failed_recipients` were
    delivered. The per-host reasons were logged as WARNING records while
    delivery ran.

    Attributes:
        failed_recipients: Recipients no host accepted.
        hosts: The hosts that were tried, in order.
    """

    # Defaulted so pickle, which rebuilds an exception from its args alone, can recreate it.
    def __init__(self, message: str, *, failed_recipients: tuple[str, ...] = (), hosts: tuple[str, ...] = ()) -> None:
        """Build the error with the message plus the recipients and hosts it concerns.

        Args:
            message: Human-readable description of the failure.
            failed_recipients: Recipients no host accepted. Defaults to an empty tuple.
            hosts: The hosts that were tried, in order. Defaults to an empty tuple.
        """
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
