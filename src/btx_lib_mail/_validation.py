"""Address, host and value checks: email and SMTP host syntax, EHLO name, durations, host and recipient lists.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from typing import Any, Final, cast

from ._common import logger, printable
from .errors import InvalidInputError

EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
"""Compiled regex used by :func:`validate_email_address`."""


# EHLO takes one argument: printable ASCII, no space (RFC 5321 section 4.1.1.1).
_EHLO_NAME_FIRST_CHAR: Final[int] = 0x21


_EHLO_NAME_LAST_CHAR: Final[int] = 0x7E


def check_local_hostname(value: str, *, label: str) -> None:
    """Raise ``ValueError`` unless *value* can be sent as the EHLO argument.

    The value is not echoed: a refused name may carry control characters.
    """
    if not value or not all(_EHLO_NAME_FIRST_CHAR <= ord(char) <= _EHLO_NAME_LAST_CHAR for char in value):
        raise InvalidInputError(f"{label} must be non-empty printable ASCII without spaces")


def check_timeout(value: float) -> None:
    """Raise unless *value* is a usable socket timeout: positive and finite."""
    check_seconds(value, label="smtp_timeout")


def check_seconds(value: float, *, label: str) -> None:
    """Raise unless *value* is a positive, finite number of seconds.

    The non-positive check runs first, so a timeout refused before keeps its
    message; NaN and infinity, which ``value <= 0`` let through to fail later as
    an unrelated delivery error, get their own.
    """
    if value <= 0:
        raise InvalidInputError(f"{label} must be positive, got {value}")
    if not math.isfinite(value):
        raise InvalidInputError(f"{label} must be a finite number of seconds, got {value}")


def prepare_hosts(hosts: tuple[str, ...]) -> tuple[str, ...]:
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


def prepare_recipients(
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
            clean_entry = printable(entry)
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


def collect_host_inputs(value: Any) -> list[str]:
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


def parse_smtp_host(address: str) -> tuple[str, int | None]:
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
