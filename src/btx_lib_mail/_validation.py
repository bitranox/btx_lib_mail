"""Address, host and value checks: email and SMTP host syntax, EHLO name, durations, host and recipient lists.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Iterable, Sequence
from typing import Any, Final, cast

from ._common import is_valid_unicode, logger, printable
from .errors import InvalidInputError

EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
"""Compiled regex used by :func:`validate_email_address`."""

# RFC 5321 section 4.5.3.1: 64 octets before the @, and 254 for the whole address.
_MAX_LOCAL_PART: Final[int] = 64
_MAX_ADDRESS: Final[int] = 254
# RFC 1035 section 2.3.4: 63 octets per label and 253 for a name written without its root dot.
_MAX_HOST_LABEL: Final[int] = 63
_MAX_HOST_NAME: Final[int] = 253
# RFC 5321 section 4.5.3.1.2: a domain, as the EHLO argument is, holds at most 255 octets.
_MAX_EHLO_NAME: Final[int] = 255
# How much of an overlong address a skipped-recipient log line shows.
_SHOWN_PREFIX: Final[int] = 40


# EHLO takes one argument: printable ASCII, no space (RFC 5321 section 4.1.1.1).
_EHLO_NAME_FIRST_CHAR: Final[int] = 0x21


_EHLO_NAME_LAST_CHAR: Final[int] = 0x7E


def require_text(value: object, *, field_name: str) -> None:
    """Refuse a value that is not a ``str``, before a string method raises a bare error on it.

    The annotations on ``send()`` and the validators are not enforced at run
    time; ``None`` or bytes would otherwise surface as ``AttributeError`` or
    ``TypeError`` from deep inside a check.

    Args:
        value: The caller's value.
        field_name: The name the message reports.

    Raises:
        InvalidInputError: If value is not a ``str``.

    Examples:
        >>> require_text(None, field_name="mail_subject")
        Traceback (most recent call last):
            ...
        btx_lib_mail.errors.InvalidInputError: mail_subject must be str, got NoneType
    """
    if not isinstance(value, str):
        raise InvalidInputError(f"{field_name} must be str, got {type(value).__name__}")


def check_local_hostname(value: str, *, label: str) -> None:
    """Raise unless value can be sent as the EHLO argument.

    The value is not echoed: a refused name may carry control characters.

    Args:
        value: Candidate EHLO/HELO name.
        label: Name of the setting or argument to use in the error message.

    Raises:
        InvalidInputError: If value is empty, not printable ASCII without
            spaces, or longer than 255 characters.
    """
    if not value or not all(_EHLO_NAME_FIRST_CHAR <= ord(char) <= _EHLO_NAME_LAST_CHAR for char in value):
        raise InvalidInputError(f"{label} must be non-empty printable ASCII without spaces")
    if len(value) > _MAX_EHLO_NAME:
        raise InvalidInputError(f"{label} has {len(value)} characters, more than the {_MAX_EHLO_NAME} allowed")


def check_credentials(credentials: tuple[str, str] | None) -> None:
    """Refuse a user name or password that cannot be written as UTF-8, without echoing it.

    A lone surrogate (an invalid UTF-8 byte in argv or an env file) would make
    AUTH fail only after each host's connection was made.

    Args:
        credentials: ``(user name, password)``, or ``None`` for no AUTH.

    Raises:
        InvalidInputError: If either cannot be encoded as UTF-8.
    """
    if credentials is None:
        return
    user, password = credentials
    if not is_valid_unicode(user):
        raise InvalidInputError("the SMTP user name must be valid Unicode text")
    if not is_valid_unicode(password):
        raise InvalidInputError("the SMTP password must be valid Unicode text")


def check_timeout(value: float) -> None:
    """Raise unless value is a usable socket timeout: positive and finite.

    Args:
        value: Candidate timeout in seconds.

    Raises:
        InvalidInputError: If value is not positive and finite.
    """
    check_seconds(value, label="smtp_timeout")


def check_seconds(value: float, *, label: str) -> None:
    """Raise unless value is a positive, finite number of seconds.

    The non-positive check runs first, so a timeout refused before keeps its
    message; NaN and infinity, which `value <= 0` let through to fail later
    as an unrelated delivery error, get their own.

    Args:
        value: Candidate number of seconds.
        label: Name of the setting or argument to use in the error message.

    Raises:
        InvalidInputError: If value is not positive and finite.
    """
    if value <= 0:
        raise InvalidInputError(f"{label} must be positive, got {value}")
    if not math.isfinite(value):
        raise InvalidInputError(f"{label} must be a finite number of seconds, got {value}")


def prepare_hosts(hosts: tuple[str, ...]) -> tuple[str, ...]:
    """Return a deduplicated tuple of normalised host strings.

    Ensures the host list is stable, stripped, and free of empties. Strips
    formatting, removes blanks, and deduplicates while preserving order.

    Args:
        hosts: Tuple of raw host strings collected from config and overrides.

    Returns:
        Ordered, deduplicated host strings.

    Raises:
        InvalidInputError: If no valid host remains, or a host fails `validate_smtp_host`.
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
    max_count: int | None,
) -> tuple[str, ...]:
    """Return a deduplicated tuple of valid, lower-cased recipient addresses.

    Consolidates parsing, trimming, deduplication, and validation into a
    ready-to-send tuple. Logs a warning for each invalid recipient tolerated.

    Args:
        recipients: Single email or sequence of emails supplied by callers.
        raise_on_invalid: When `True`, invalid recipients raise `ValueError`;
            when `False`, a warning is logged and the address is skipped.
        max_count: Most distinct recipients accepted, counted before any is
            validated; `None` sets no limit.

    Returns:
        Validated, deduplicated, lower-cased emails.

    Raises:
        InvalidInputError: If recipients is not a string or sequence, there
            are more distinct recipients than max_count, an entry fails
            validation and raise_on_invalid is True, or no valid recipient
            remains.
    """
    if isinstance(recipients, str):
        raw_items: Iterable[str] = (recipients,)
    elif isinstance(recipients, Sequence):  # pyright: ignore[reportUnnecessaryIsInstance] - a caller ignoring the annotation can pass anything
        raw_items = recipients
    else:
        raise InvalidInputError("invalid type of mail_addresses")

    for item in raw_items:
        require_text(item, field_name="mail_recipients entries")
    cleaned = [_normalise_email_address(item) for item in raw_items]
    filtered = [value for value in cleaned if value]
    unique = tuple(dict.fromkeys(filtered))
    # Counted before validation, so an oversized list costs no regex run per entry.
    if max_count is not None and len(unique) > max_count:
        raise InvalidInputError(f"{len(unique)} recipients, more than recipient_max_count ({max_count})")

    valid = [entry for entry in unique if _accept_recipient(entry, raise_on_invalid=raise_on_invalid)]

    if not valid:
        raise InvalidInputError("no valid recipients")
    return tuple(valid)


def _accept_recipient(entry: str, *, raise_on_invalid: bool) -> bool:
    """Return whether entry is a valid address; refuse or skip it otherwise.

    An overlong entry is reported by its length, never by its text: a
    megabyte address would otherwise land whole in the exception and the log.

    Args:
        entry: One normalised recipient address.
        raise_on_invalid: Raise for an invalid entry instead of logging and skipping it.

    Returns:
        True when entry is valid, False when it was logged and skipped.

    Raises:
        InvalidInputError: If entry is invalid and raise_on_invalid is True.
    """
    problem = address_length_problem(entry)
    if problem is None and EMAIL_PATTERN.fullmatch(entry):
        return True
    # `entry` is exactly the value that FAILED validation, so unlike
    # `recipients`/`failed_recipients` elsewhere in this module it is not
    # provably free of control characters; clean it before it reaches a log
    # line or an exception message a caller may log.
    if problem is not None:
        template, detail = "invalid recipient: %s", problem
        shown = f"{printable(entry[:_SHOWN_PREFIX])}... ({len(entry)} characters)"
    else:
        template, detail = "invalid recipient %s", printable(entry)
        shown = detail
    if raise_on_invalid:
        raise InvalidInputError(template % detail)
    logger.warning(template, detail, extra={"recipient": shown, "skipped": "recipient"})
    return False


def address_length_problem(address: str) -> str | None:
    """Describe how address exceeds the RFC 5321 lengths, or return None.

    RFC 5321 section 4.5.3.1 allows 64 octets before the `@` and a 256-octet
    path, which leaves 254 for the address between the angle brackets. The
    description names the length, so a caller can report it without quoting
    the address.

    Args:
        address: Candidate email string.

    Returns:
        The problem as a sentence fragment, or None when both lengths fit.

    Examples:
        >>> address_length_problem("user@example.com") is None
        True
        >>> address_length_problem("a" * 65 + "@example.com")
        'the local part has 65 characters, more than the 64 RFC 5321 allows'
    """
    local_part, at_sign, _domain = address.rpartition("@")
    if at_sign and len(local_part) > _MAX_LOCAL_PART:
        return f"the local part has {len(local_part)} characters, more than the {_MAX_LOCAL_PART} RFC 5321 allows"
    if len(address) > _MAX_ADDRESS:
        return f"{len(address)} characters, more than the {_MAX_ADDRESS} RFC 5321 allows"
    return None


def _normalise_email_address(candidate: str) -> str:
    """Trim whitespace/quotes and lower-case the candidate email if it is ASCII.

    Email addresses should compare case-insensitively in our context, so this
    returns a lower-case, trimmed representation that supports deduping. A
    non-ASCII entry is left as it is: the address pattern is ASCII-only, and
    lower-casing first would turn KELVIN SIGN into an ASCII "k", so a refused
    address would become a different, valid one.

    Args:
        candidate: Raw string supplied by the caller.

    Returns:
        Normalised email address (may be empty string).
    """
    trimmed = candidate.strip().strip('"').strip("'")
    return trimmed.lower() if trimmed.isascii() else trimmed


def _normalise_host(candidate: str) -> str:
    """Trim whitespace/quotes from the candidate host entry.

    Host strings from .env files often contain whitespace; this removes
    surrounding quotes and whitespace without altering order.

    Args:
        candidate: Raw host string.

    Returns:
        Normalised host string.
    """
    return candidate.strip().strip('"').strip("'")


def collect_host_inputs(value: Any) -> list[str]:
    """Coerce user input into a list of host strings.

    Supports `None`, strings, and iterables while validating entries, and
    converts supported forms into a list while validating element types.
    Refuses a host carrying userinfo or a path, without quoting it.

    Args:
        value: Caller-supplied host configuration.

    Returns:
        Normalised list of hosts (possibly empty).

    Raises:
        InvalidInputError: If value is not a string or iterable of strings,
            or a host fails `validate_smtp_host`.
    """
    return _checked_hosts(list(host_entries(value)))


def host_entries(value: object) -> tuple[str, ...]:
    """Return the host entries a caller passed: one string is one host, never one per character.

    Args:
        value: ``None``, one host string, or an iterable of host strings.

    Returns:
        The entries as given, not yet normalised or validated.

    Raises:
        InvalidInputError: If value is not a string or iterable of strings.

    Examples:
        >>> host_entries("smtp.example.com")
        ('smtp.example.com',)
        >>> host_entries(None)
        ()
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        items = tuple(cast("Iterable[object]", value))
        if not all(isinstance(item, str) for item in items):
            raise InvalidInputError("smtphosts entries must be strings")
        return cast("tuple[str, ...]", items)
    raise InvalidInputError("smtphosts must be a string, list of strings, or tuple of strings")


def _checked_hosts(raw_hosts: list[str]) -> list[str]:
    """Normalise each host, drop the blank ones, and validate the rest.

    A blank entry is what an empty environment value or a trailing comma in a
    list produces; `send` already skips it, so the model reads it as absent
    rather than as a malformed host. Every other entry is checked with
    `validate_smtp_host`, so a typo in a port or an IPv6 bracket is refused
    when the configuration is built instead of at the first delivery.

    Args:
        raw_hosts: Raw host strings to normalise and validate.

    Returns:
        Normalised, non-blank host strings.

    Raises:
        InvalidInputError: If a non-blank host fails `validate_smtp_host`.
    """
    hosts = [_normalise_host(raw) for raw in raw_hosts]
    present = [host for host in hosts if host]
    for host in present:
        validate_smtp_host(host)
    return present


def validate_email_address(address: str) -> None:
    """Raise when address does not match the email pattern.

    Prevents avoidable SMTP failures by checking syntax early, applying
    `EMAIL_PATTERN` and raising on mismatch.

    Args:
        address: Candidate email string.

    Raises:
        InvalidInputError: If address is longer than RFC 5321 allows (the
            message names the length, not the address) or does not match
            `EMAIL_PATTERN`.

    Examples:
        >>> validate_email_address("user@example.com")
        >>> validate_email_address("invalid@")
        Traceback (most recent call last):
            ...
        btx_lib_mail.errors.InvalidInputError: invalid email address: 'invalid@'
    """
    require_text(address, field_name="email address")
    problem = address_length_problem(address)
    if problem is not None:
        raise InvalidInputError(f"invalid email address: {problem}")
    if not EMAIL_PATTERN.fullmatch(address):
        raise InvalidInputError(f"invalid email address: {address!r}")


def _refuse_credentials_in_host(host: str) -> str:
    """Return host unchanged, or raise when it carries userinfo, a path, or an interior control character.

    `smtp://user:<password>@relay` in a host list puts the password into
    every log line and error text that names the host. The error never
    quotes the value.

    A host carrying a newline or an escape sequence can forge an extra log
    line or a terminal control sequence wherever the host is later logged.
    Callers run this after `_normalise_host`, which trims OUTER whitespace,
    so only an INTERIOR whitespace or control character is refused here; an
    ordinary `" smtp.example.com "` from an env file still validates.

    Args:
        host: Host string already stripped of outer whitespace.

    Returns:
        The host, unchanged.

    Raises:
        InvalidInputError: If host carries userinfo, a path, or an interior
            whitespace or control character.
    """
    if "@" in host or "/" in host:
        # Never quote the value: a userinfo part here is a password in the wrong field.
        raise InvalidInputError("SMTP host must be host[:port]; it must not contain '@' or '/' (pass credentials as smtp_username and smtp_password)")
    if any(not character.isprintable() or character.isspace() for character in host):
        # Never quote the value: it may itself be the forged content.
        raise InvalidInputError("SMTP host must not contain whitespace or control characters")
    return host


def validate_smtp_host(host: str) -> None:
    """Raise when host is not a valid SMTP host string.

    Accepts the following forms:

    - `hostname`
    - `hostname:port`
    - `[IPv6]:port`  (e.g. `[::1]:25`)
    - `[IPv6]`       (e.g. `[::1]`)

    Never accepted: userinfo (user:password@host) or a URL (smtp://...), for
    which the error does not echo the value; several hosts in one string
    (`a.example.com,b.example.com`); a port with no host name (`:25`); an
    IPv6 address without brackets (`fe80::1`), whose last group would
    otherwise be read as the port; a port that is not plain ASCII digits
    in 1-65535 (`+25`, `2_5`, non-ASCII digits); bracket content that is not
    an IP address (`[zz]`); and a name DNS can never resolve (`a..b`,
    `-bad-.example.com`, a label over 63 or a name over 253 characters).

    Validates SMTP host syntax early so errors surface before delivery.

    Args:
        host: Host string with optional port and/or IPv6 bracket notation.

    Raises:
        InvalidInputError: If host is empty or does not match one of the
            accepted forms.

    Examples:
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
    require_text(host, field_name="SMTP host")

    _refuse_credentials_in_host(host)

    # The port and bracket checks run first and the shape checks only on what they let
    # through, so a host the 2.x checks refused keeps its 2.x message and a caller (or a
    # consumer's test) matching that message is unaffected.
    _validate_port_and_brackets(host)
    _validate_host_shape(host)


def _validate_port_and_brackets(host: str) -> None:
    """Validate the bracket syntax and the port, splitting a port off at the last colon.

    Args:
        host: Host string with optional port and/or IPv6 bracket notation.

    Raises:
        InvalidInputError: If the bracket is unclosed, trailing characters
            follow it, or the port is invalid.
    """
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

    Runs after `_validate_port_and_brackets`, so every input reaching it has
    a well-formed port; what is left is two hosts in one string, a host name
    containing a colon (an IPv6 address without brackets, whose last group
    would read as the port), and an empty host name.

    Args:
        host: Host string already validated for port and bracket syntax.

    Raises:
        InvalidInputError: If host names more than one host, an unbracketed
            IPv6 address, or no host name at all; or, checked last, bracket
            content that is not an IP address or a name DNS can never resolve.
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
    if host.startswith("["):
        _check_address_literal(name, host)
    else:
        _check_host_name(name, host)


def _check_address_literal(address: str, host: str) -> None:
    """Refuse bracket content that is not an IP address (IPv6, zone id included, or IPv4).

    Args:
        address: The text between the brackets.
        host: The full host string, for the message.

    Raises:
        InvalidInputError: If address does not parse as an IP address.
    """
    try:
        ipaddress.ip_address(address)
    except ValueError:
        raise InvalidInputError(f'not an IP address in brackets in "{host}"') from None


def _check_host_name(name: str, host: str) -> None:
    """Refuse a host name DNS can never resolve: too long, an empty label, or a label's hyphen.

    The character set is not restricted (internal names use ``_``, IDN names
    are Unicode), and one trailing dot (a fully qualified name) is allowed.
    Run after every older check, so a host those refused keeps its message;
    the length refusal does not echo the name, which may be megabytes long.

    Args:
        name: The host name without its port.
        host: The full host string, for the message.

    Raises:
        InvalidInputError: If name is longer than 253 characters, holds an
            empty label or one longer than 63 characters, or a label starts
            or ends with ``-``.
    """
    if len(name) > _MAX_HOST_NAME:
        raise InvalidInputError(f"SMTP host name has {len(name)} characters, more than the {_MAX_HOST_NAME} allowed")
    for label in name.removesuffix(".").split("."):
        if not label:
            raise InvalidInputError(f'empty host name label in "{host}"')
        if len(label) > _MAX_HOST_LABEL:
            raise InvalidInputError(f"a host name label has {len(label)} characters, more than the {_MAX_HOST_LABEL} allowed")
        if label.startswith("-") or label.endswith("-"):
            raise InvalidInputError(f'a host name label must not start or end with "-" in "{host}"')


def _validate_port(port_str: str, original: str) -> None:
    """Validate that port_str is plain ASCII digits naming a port in the 1-65535 range.

    Args:
        port_str: Raw port substring extracted from the host string.
        original: The full host string used in error messages.

    Raises:
        InvalidInputError: If port_str is not a plain ASCII decimal integer in 1-65535.
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

    Calls `validate_smtp_host` first, then extracts the components. IPv6
    brackets are stripped so `smtplib.SMTP` receives a bare address, since
    delivery helpers need separate hostname and port values.

    Args:
        address: Host string to validate and split.

    Returns:
        Hostname (bare for IPv6) and optional port number.

    Raises:
        InvalidInputError: If address fails `validate_smtp_host`.
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
