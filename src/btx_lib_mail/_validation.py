"""Address, host and value checks: email and SMTP host syntax, EHLO name, durations, host and recipient lists.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import ipaddress
import math
import re
import string
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Any, Final, cast

from ._common import SkipKind, is_valid_unicode, logger, printable
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
# The characters EMAIL_PATTERN allows in an ASCII local part. An internationalised local part
# (RFC 6531 section 3.3) allows these plus printable non-ASCII characters.
_ASCII_LOCAL_PART_CHARACTERS: Final[frozenset[str]] = frozenset(string.ascii_letters + string.digits + "._%+-")
# A top-level domain label holds at least two letters (EMAIL_PATTERN's [A-Za-z]{2,}).
_MIN_TOP_LEVEL_LABEL: Final[int] = 2
# A domain is at least a name and a top-level label.
_MIN_DOMAIN_LABELS: Final[int] = 2
# An ASCII-compatible encoding of an internationalised label (RFC 5890), which may end in digits.
_ACE_PREFIX: Final[str] = "xn--"


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


def require_flag(value: object, *, field_name: str) -> bool:
    """Return value when it is ``True`` or ``False``; refuse anything else.

    A string such as ``"false"`` is truthy, so reading it as a flag would turn
    the setting it names on.

    Args:
        value: The caller's value.
        field_name: The name the message reports.

    Returns:
        The value, a ``bool``.

    Raises:
        InvalidInputError: If value is not a ``bool``.

    Examples:
        >>> require_flag("false", field_name="attachment_allow_symlinks")
        Traceback (most recent call last):
            ...
        btx_lib_mail.errors.InvalidInputError: attachment_allow_symlinks must be True or False, got str
    """
    if not isinstance(value, bool):
        raise InvalidInputError(f"{field_name} must be True or False, got {type(value).__name__}")
    return value


def require_number(value: object, *, field_name: str) -> float:
    """Return value unchanged when it is an ``int`` or ``float`` (not a ``bool``).

    Args:
        value: The caller's value, a number of seconds.
        field_name: The name the message reports.

    Returns:
        The value; its range is checked by :func:`check_seconds`.

    Raises:
        InvalidInputError: If value is not a number, or is a ``bool``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidInputError(f"{field_name} must be a number of seconds, got {type(value).__name__}")
    return value


def require_ceiling(value: object, *, field_name: str) -> int:
    """Return value when it is a positive ``int`` (not a ``bool``), with the message ConfMail gives.

    Args:
        value: The caller's size or count limit.
        field_name: The name the message reports.

    Returns:
        The value.

    Raises:
        InvalidInputError: If value is not an ``int``, or not positive.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidInputError(f"{field_name} must be int, got {type(value).__name__}")
    if value <= 0:
        raise InvalidInputError(f"{field_name} must be positive, got {value}")
    return value


def require_collection(value: object, *, field_name: str, of_what: str = "") -> Iterable[object]:
    """Return value when it is a set, frozenset, list or tuple; a bare string is refused.

    A string is iterable too and would be read one character at a time: a
    blocklist of ``".exe"`` became ``{".", ".e", ".x"}`` and blocked nothing.

    Args:
        value: The caller's collection.
        field_name: The name the message reports.
        of_what: What the entries are, appended to the message (``" of strings"``).

    Returns:
        The value.

    Raises:
        InvalidInputError: If value is not a set, frozenset, list or tuple.
    """
    if not isinstance(value, (frozenset, set, list, tuple)):
        raise InvalidInputError(f"{field_name} must be a set, frozenset, list, or tuple{of_what}, got {type(value).__name__}")
    return cast("Iterable[object]", value)


def require_credentials(value: object) -> tuple[str, str]:
    """Return value when it is a ``(user, password)`` pair of ``str``.

    The message does not echo the value, which holds a password.

    Args:
        value: The caller's credentials.

    Returns:
        The pair as a tuple.

    Raises:
        InvalidInputError: If value is not a tuple or list of two ``str``.
    """
    if isinstance(value, (tuple, list)):
        pair = cast("tuple[object, ...] | list[object]", value)
        if len(pair) == 2 and isinstance(pair[0], str) and isinstance(pair[1], str):  # noqa: PLR2004 - a user and a password
            return (pair[0], pair[1])
    raise InvalidInputError("credentials must be a (user, password) pair of str")


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
    """Refuse a user name or password AUTH cannot carry, without echoing it.

    A lone surrogate (an invalid UTF-8 byte in argv or an env file) would make
    AUTH fail only after each host's connection was made. AUTH PLAIN separates
    its fields with NUL (RFC 4616), so a NUL inside one splits it into another
    identity on a lenient server.

    Args:
        credentials: ``(user name, password)``, or ``None`` for no AUTH.

    Raises:
        InvalidInputError: If either cannot be encoded as UTF-8 or contains NUL.
    """
    if credentials is None:
        return
    for value, label in zip(credentials, ("the SMTP user name", "the SMTP password"), strict=True):
        if not is_valid_unicode(value):
            raise InvalidInputError(f"{label} must be valid Unicode text")
        if "\x00" in value:
            raise InvalidInputError(f"{label} must not contain NUL")


def check_timeout(value: float) -> None:
    """Raise unless value is a usable socket timeout: positive, finite, at most ``_MAX_SECONDS``.

    Args:
        value: Candidate timeout in seconds.

    Raises:
        InvalidInputError: If value is not positive and finite, or too long.
    """
    check_seconds(value, label="smtp_timeout")


def as_timeout(value: float) -> float:
    """Return value as a float socket timeout, checked by :func:`check_timeout`.

    An int too large for a float is refused before the conversion, which would
    raise a bare ``OverflowError``; any other value is converted first, so a
    refused ``0`` still reads ``got 0.0``.

    Args:
        value: Candidate timeout in seconds, an ``int`` or ``float``.

    Returns:
        The timeout as a float.

    Raises:
        InvalidInputError: If value is not a usable socket timeout.
    """
    if isinstance(value, int) and value > _MAX_SECONDS:
        check_seconds(value, label="smtp_timeout")
    timeout = float(value)
    check_timeout(timeout)
    return timeout


# The longest timeout or deadline: 2**31 - 1 milliseconds, the most a Windows
# socket timeout holds (threading.TIMEOUT_MAX is larger on every platform).
_MAX_SECONDS: Final = 2_147_483


def check_seconds(value: float, *, label: str) -> None:
    """Raise unless value is a positive, finite number of seconds every platform can wait.

    The non-positive check runs first, so a timeout refused before keeps its
    message; NaN and infinity, which `value <= 0` let through to fail later
    as an unrelated delivery error, get their own. Past ``_MAX_SECONDS`` a
    socket or a timer refuses the value only when it is used; an int too large
    for a float is refused here without converting it.

    Args:
        value: Candidate number of seconds.
        label: Name of the setting or argument to use in the error message.

    Raises:
        InvalidInputError: If value is not positive and finite, or longer than
            ``_MAX_SECONDS``.
    """
    if value <= 0:
        raise InvalidInputError(f"{label} must be positive, got {value}")
    if isinstance(value, float) and not math.isfinite(value):
        raise InvalidInputError(f"{label} must be a finite number of seconds, got {value}")
    if value > _MAX_SECONDS:
        # The value is not echoed: an int this large can have more digits than str() will write.
        raise InvalidInputError(f"{label} must be at most {_MAX_SECONDS} seconds")


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
    unique = distinct_recipients(recipients)
    # Counted before validation, so an oversized list costs no regex run per entry.
    if max_count is not None and len(unique) > max_count:
        raise InvalidInputError(f"{len(unique)} recipients, more than recipient_max_count ({max_count})")

    valid = [entry for entry in unique if _accept_recipient(entry, raise_on_invalid=raise_on_invalid)]

    if not valid:
        raise InvalidInputError("no valid recipients")
    return tuple(valid)


def distinct_recipients(recipients: str | Sequence[str]) -> tuple[str, ...]:
    """Return the recipients as `send()` considers them: normalised, de-duplicated, in order.

    Each entry is trimmed of whitespace and quotes and lower-cased when ASCII; blank
    entries are dropped and a repeat is kept once. Invalid addresses are still
    present; `is_valid_recipient` tells them apart. Nothing is logged.

    Args:
        recipients: Single email or sequence of emails supplied by callers.

    Returns:
        The distinct normalised entries, first occurrence first.

    Raises:
        InvalidInputError: If recipients is not a string or sequence, or an entry is not text.

    Examples:
        >>> distinct_recipients([" B@Example.com", '"b@example.com"', "", "c@example.com"])
        ('b@example.com', 'c@example.com')
    """
    if isinstance(recipients, str):
        raw_items: Iterable[str] = (recipients,)
    elif isinstance(recipients, Sequence):  # pyright: ignore[reportUnnecessaryIsInstance] - a caller ignoring the annotation can pass anything
        raw_items = recipients
    else:
        raise InvalidInputError("invalid type of mail_addresses")

    for item in raw_items:
        require_text(item, field_name="mail_recipients entries")
    cleaned = (_normalise_email_address(item) for item in raw_items)
    return tuple(dict.fromkeys(value for value in cleaned if value))


def is_valid_recipient(entry: str) -> bool:
    """Return whether one normalised entry is an address `send()` delivers to.

    Args:
        entry: One entry from `distinct_recipients`.

    Returns:
        True when it is within the RFC 5321 lengths and has the address syntax
        (`matches_address_syntax`).

    Examples:
        >>> is_valid_recipient("b@example.com"), is_valid_recipient("nope")
        (True, False)
    """
    return address_length_problem(entry) is None and matches_address_syntax(entry)


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
    if is_valid_recipient(entry):
        return True
    problem = address_length_problem(entry)
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
    logger.warning(template, detail, extra={"recipient": shown, "skipped": SkipKind.RECIPIENT.value})
    return False


def address_length_problem(address: str) -> str | None:
    """Describe how address exceeds the RFC 5321 lengths, or return None.

    RFC 5321 section 4.5.3.1 allows 64 octets before the `@` and a 256-octet
    path, which leaves 254 for the address between the angle brackets. The
    lengths are UTF-8 octets, so a non-ASCII character counts as the two to
    four it takes on the wire; the description says "characters" for an ASCII
    address (where the two are the same) and "UTF-8 octets" otherwise. It names
    the length, so a caller can report it without quoting the address.

    Args:
        address: Candidate email string.

    Returns:
        The problem as a sentence fragment, or None when both lengths fit.

    Examples:
        >>> address_length_problem("user@example.com") is None
        True
        >>> address_length_problem("a" * 65 + "@example.com")
        'the local part has 65 characters, more than the 64 RFC 5321 allows'
        >>> address_length_problem(chr(0xE4) * 33 + "@example.com")
        'the local part has 66 UTF-8 octets, more than the 64 RFC 5321 allows'
    """
    unit = "characters" if address.isascii() else "UTF-8 octets"
    local_part, at_sign, _domain = address.rpartition("@")
    local_size = _utf8_octets(local_part)
    if at_sign and local_size > _MAX_LOCAL_PART:
        return f"the local part has {local_size} {unit}, more than the {_MAX_LOCAL_PART} RFC 5321 allows"
    size = _utf8_octets(address)
    if size > _MAX_ADDRESS:
        return f"{size} {unit}, more than the {_MAX_ADDRESS} RFC 5321 allows"
    return None


def _utf8_octets(text: str) -> int:
    """Return how many octets text takes as UTF-8.

    A lone surrogate counts as the three octets it would take; the syntax check
    refuses it afterwards, and the length check must not raise on it first.

    Args:
        text: The text to measure.

    Returns:
        The UTF-8 length in octets.

    Examples:
        >>> _utf8_octets("abc"), _utf8_octets(chr(0xE4)), _utf8_octets(chr(0xDCFF))
        (3, 2, 3)
    """
    return len(text.encode("utf-8", "surrogatepass"))


def _normalise_email_address(candidate: str) -> str:
    """Trim whitespace/quotes, normalise to NFC, and lower-case the result if it is ASCII.

    Email addresses compare case-insensitively in our context, so an ASCII
    address is lower-cased for de-duplication. NFC runs first (RFC 6532 asks
    for it), so a decomposed `a` plus combining diaeresis becomes the `ä` a
    caller typed elsewhere, and a character that is canonically an ASCII letter
    (KELVIN SIGN is `K`) is then lower-cased like one. A non-ASCII address
    keeps its case: Unicode lower-casing can change the length and leave
    non-NFC text, and RFC 5321 treats the local part as case-sensitive.

    Args:
        candidate: Raw string supplied by the caller.

    Returns:
        Normalised email address (may be empty string).

    Examples:
        >>> _normalise_email_address(' "B@Example.com" ')
        'b@example.com'
        >>> _normalise_email_address("a" + chr(0x308) + "@Example.com") == chr(0xE4) + "@Example.com"
        True
    """
    trimmed = to_nfc(candidate.strip().strip('"').strip("'"))
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

    Only a collection is read: a lazy iterable (a generator, a ``range``) would
    be read whole before any entry is checked, and an endless one never ends.

    Args:
        value: ``None``, one host string, or a list, tuple, set or frozenset of host strings.

    Returns:
        The entries as given, not yet normalised or validated.

    Raises:
        InvalidInputError: If value is not a string or a collection of strings.

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
    if isinstance(value, (list, tuple, set, frozenset)):
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
    """Raise when address is not a syntactically valid email address.

    Prevents avoidable SMTP failures by checking syntax early. An ASCII address
    must match `EMAIL_PATTERN`; an address holding non-ASCII characters is an
    internationalised one (RFC 6531), checked by `matches_address_syntax`. The
    lengths are UTF-8 octets (`address_length_problem`). The NFC form of the
    address is checked, the form `send()` delivers to, so the two agree; the
    caller's string is not changed and nothing is returned.

    Args:
        address: Candidate email string.

    Raises:
        InvalidInputError: If address is longer than RFC 5321 allows (the
            message names the length, not the address) or does not have the
            address syntax.

    Examples:
        >>> validate_email_address("user@example.com")
        >>> validate_email_address("empf" + chr(0xE4) + "nger@m" + chr(0xFC) + "ller.de")
        >>> validate_email_address("invalid@")
        Traceback (most recent call last):
            ...
        btx_lib_mail.errors.InvalidInputError: invalid email address: 'invalid@'
    """
    require_text(address, field_name="email address")
    normalised = to_nfc(address)
    problem = address_length_problem(normalised)
    if problem is not None:
        raise InvalidInputError(f"invalid email address: {problem}")
    if not matches_address_syntax(normalised):
        raise InvalidInputError(f"invalid email address: {normalised!r}")


def to_nfc(address: str) -> str:
    """Return address in Unicode Normalization Form C, the form RFC 6532 asks for.

    The same visible character can be one code point or a base letter plus a
    combining mark; a relay comparing bytes treats the two as different
    mailboxes. NFC picks the composed form. An ASCII address is returned as it is.

    Args:
        address: The address as the caller gave it.

    Returns:
        The NFC form of address.

    Examples:
        >>> to_nfc("a" + chr(0x308) + "@example.com") == chr(0xE4) + "@example.com"
        True
        >>> to_nfc("User@Example.com")
        'User@Example.com'
    """
    return unicodedata.normalize("NFC", address)


def matches_address_syntax(address: str) -> bool:
    """Return whether address has the syntax of a deliverable email address.

    An ASCII address must match `EMAIL_PATTERN`, exactly as before. An address
    holding non-ASCII characters is internationalised (RFC 6531): its local part
    allows the ASCII characters `EMAIL_PATTERN` allows plus any printable
    non-ASCII character, and its domain is dot-separated labels of
    letters, combining marks (part of words in Indic and Thai scripts) and
    digits of any script plus hyphens. A label starts with a letter or digit
    and does not end with a hyphen; the last label is at least two letters or
    marks (no digit, no hyphen) or an `xn--` label. Lengths are not checked here (`address_length_problem`).

    Args:
        address: Candidate email string.

    Returns:
        True when address has the syntax, False otherwise.

    Examples:
        >>> matches_address_syntax("user@example.com")
        True
        >>> matches_address_syntax("empf" + chr(0xE4) + "nger@example.com")
        True
        >>> matches_address_syntax("user@m" + chr(0xFC) + "ller")
        False
    """
    if address.isascii():
        return EMAIL_PATTERN.fullmatch(address) is not None
    local_part, at_sign, domain = address.rpartition("@")
    return bool(at_sign) and _is_international_local_part(local_part) and _is_international_domain(domain)


def needs_smtputf8(sender: str, recipient: str) -> bool:
    """Return whether the message from sender to recipient must travel as SMTPUTF8 (RFC 6531).

    It must when either address holds a non-ASCII character. Composition folds
    such an address as raw UTF-8 and the transport announces SMTPUTF8 for it;
    both ask this one function, so they cannot disagree.

    Args:
        sender: The envelope sender, as `send()` normalised it.
        recipient: The envelope recipient, as `send()` normalised it.

    Returns:
        True when either address holds non-ASCII, False when both are ASCII.

    Examples:
        >>> needs_smtputf8("a@example.com", "b@example.com")
        False
        >>> needs_smtputf8("a@example.com", "b@m" + chr(0xFC) + "ller.de")
        True
    """
    return not (sender.isascii() and recipient.isascii())


def _is_international_local_part(local_part: str) -> bool:
    """Return whether local_part is a non-empty internationalised local part.

    Args:
        local_part: The text before the last `@`.

    Returns:
        True when it is non-empty and every character is allowed there.

    Examples:
        >>> _is_international_local_part("empf" + chr(0xE4) + "nger"), _is_international_local_part("")
        (True, False)
    """
    return bool(local_part) and all(_is_local_part_character(character) for character in local_part)


def _is_local_part_character(character: str) -> bool:
    """Return whether character may stand in an internationalised local part.

    An ASCII character must be one `EMAIL_PATTERN` allows. A non-ASCII one must
    be printable: `str.isprintable()` is False for controls (Cc), format
    characters (Cf, which holds every bidirectional mark, override and isolate,
    and the zero-width joiner), separators (Z*, the no-break space among them),
    surrogates (Cs) and unassigned code points (Cn).

    Args:
        character: One character.

    Returns:
        True when it is allowed.

    Examples:
        >>> _is_local_part_character(chr(0xE4)), _is_local_part_character(chr(0x200E)), _is_local_part_character(" ")
        (True, False, False)
    """
    if character.isascii():
        return character in _ASCII_LOCAL_PART_CHARACTERS
    return character.isprintable()


def _is_international_domain(domain: str) -> bool:
    """Return whether domain is a dotted name of valid labels with a valid top-level label.

    Args:
        domain: The text after the last `@`.

    Returns:
        True when there are two or more labels, each valid, and the last is at
        least two characters of letters and combining marks (no digit, no
        hyphen) or an `xn--` label.

    Examples:
        >>> _is_international_domain("m" + chr(0xFC) + "ller.de"), _is_international_domain("m" + chr(0xFC) + "ller")
        (True, False)
        >>> _is_international_domain("example." + chr(0x92D) + chr(0x93E) + chr(0x930) + chr(0x924))
        True
    """
    labels = domain.split(".")
    if len(labels) < _MIN_DOMAIN_LABELS or not all(_is_domain_label(label) for label in labels):
        return False
    top = labels[-1]
    return (len(top) >= _MIN_TOP_LEVEL_LABEL and all(_is_letter_or_mark(character) for character in top)) or top.lower().startswith(_ACE_PREFIX)


def _is_domain_label(label: str) -> bool:
    """Return whether label is letters, marks, digits and inner hyphens.

    Args:
        label: One dot-separated part of a domain.

    Returns:
        True when it is non-empty, starts with a letter or digit (never a mark
        or a hyphen), does not end with a hyphen, and holds nothing but
        letters, combining marks, digits and hyphens.

    Examples:
        >>> _is_domain_label("m" + chr(0xFC) + "ller"), _is_domain_label("-x"), _is_domain_label("")
        (True, False, False)
        >>> _is_domain_label(chr(0xE2A) + chr(0xE27) + chr(0xE31)), _is_domain_label(chr(0x93E) + "x")
        (True, False)
    """
    return (
        bool(label)
        and _is_letter_or_digit(label[0])
        and not label.endswith("-")
        and all(character == "-" or _is_letter_mark_or_digit(character) for character in label)
    )


def _is_letter_or_mark(character: str) -> bool:
    """Return whether character is an ASCII letter, or a non-ASCII letter or combining mark.

    Marks (Unicode Mn, Mc) are part of words in Indic and Thai scripts, so a
    top-level label written in them must pass, which `str.isalpha()` refuses.

    Args:
        character: One character.

    Returns:
        True for a letter or a mark.

    Examples:
        >>> _is_letter_or_mark("a"), _is_letter_or_mark(chr(0x93E)), _is_letter_or_mark("3"), _is_letter_or_mark("-")
        (True, True, False, False)
    """
    if character.isascii():
        return character.isalpha()
    return unicodedata.category(character)[0] in "LM"


def _is_letter_or_digit(character: str) -> bool:
    """Return whether character is an ASCII letter or digit, or a non-ASCII letter or digit.

    Args:
        character: One character.

    Returns:
        True for a letter or a digit; False for a mark and a hyphen.

    Examples:
        >>> _is_letter_or_digit("a"), _is_letter_or_digit("7"), _is_letter_or_digit(chr(0x93E)), _is_letter_or_digit("-")
        (True, True, False, False)
    """
    if character.isascii():
        return character.isalnum()
    return unicodedata.category(character)[0] in "LN"


def _is_letter_mark_or_digit(character: str) -> bool:
    """Return whether character may stand inside a domain label (hyphen aside).

    Args:
        character: One character.

    Returns:
        True for an ASCII letter or digit, or a non-ASCII letter, mark or digit.

    Examples:
        >>> _is_letter_mark_or_digit("a"), _is_letter_mark_or_digit(chr(0x93E)), _is_letter_mark_or_digit("_")
        (True, True, False)
    """
    if character.isascii():
        return character.isalnum()
    return unicodedata.category(character)[0] in "LMN"


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


# Longest host a refusal quotes whole: past any name DNS allows (253) plus a port and
# brackets. A longer one is quoted in part, so a refused megabyte is not copied into the
# error and the log.
_HOST_QUOTE_LIMIT: Final[int] = 300


def _shown(host: str) -> str:
    """Return host for a refusal message: whole up to ``_HOST_QUOTE_LIMIT`` characters, else its start and length.

    Examples:
        >>> _shown("smtp.example.com:x")
        'smtp.example.com:x'
        >>> _shown("h" * 1000).endswith("h... (1000 characters)")
        True
    """
    if len(host) <= _HOST_QUOTE_LIMIT:
        return host
    return f"{host[:_HOST_QUOTE_LIMIT]}... ({len(host)} characters)"


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
        raise InvalidInputError(f'missing closing bracket in "{_shown(host)}"')
    remainder = host[bracket_end + 1 :]
    if remainder == "":
        return
    if not remainder.startswith(":"):
        raise InvalidInputError(f'unexpected characters after bracket in "{_shown(host)}"')
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
        raise InvalidInputError(f'SMTP host must be one host per entry; pass several hosts as a list, got "{_shown(host)}"')
    if host.startswith("["):
        name = host[1 : host.find("]")]
    else:
        name = host.rsplit(":", 1)[0] if ":" in host else host
        if ":" in name:
            raise InvalidInputError(f'more than one ":" in "{_shown(host)}"; an IPv6 address must be in brackets, as [addr] or [addr]:port')
    if not name:
        raise InvalidInputError(f'missing host name in "{_shown(host)}"')
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
        raise InvalidInputError(f'not an IP address in brackets in "{_shown(host)}"') from None


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
            raise InvalidInputError(f'empty host name label in "{_shown(host)}"')
        if len(label) > _MAX_HOST_LABEL:
            raise InvalidInputError(f"a host name label has {len(label)} characters, more than the {_MAX_HOST_LABEL} allowed")
        if label.startswith("-") or label.endswith("-"):
            raise InvalidInputError(f'a host name label must not start or end with "-" in "{_shown(host)}"')


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
        raise InvalidInputError(f'invalid smtp port in "{_shown(original)}"') from exc
    if not (min_port <= port <= max_port):
        # The message names the host and nothing derived from it: a model that scrubs
        # the host as a credential can only remove the whole string, not a re-quoted port.
        raise InvalidInputError(f'port must be {min_port}-{max_port} in "{_shown(original)}"')
    # int() also takes a sign, "_" separators and any Unicode digits; checked after the
    # range so a port the range check already refused keeps that message.
    if not (port_str.isascii() and port_str.isdigit()):
        raise InvalidInputError(f'invalid smtp port in "{_shown(original)}"')


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
