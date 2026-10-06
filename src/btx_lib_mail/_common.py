"""The library logger, the skip kinds its warn-mode warnings carry, the control-character cleaning every log line and message uses, and the UTF-8 test.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import logging
from enum import Enum

logger = logging.getLogger("btx_lib_mail")


class SkipKind(str, Enum):
    """What a warn-mode warning says was left out of the send.

    The warning carries it as the plain string ``.value`` in its ``skipped`` log
    record attribute, so a log formatter shows the same word on every Python
    version; the CLI parses it back into a member when it collects the skips.

    Examples:
        >>> SkipKind("recipient") is SkipKind.RECIPIENT
        True
        >>> SkipKind.ATTACHMENT.value
        'attachment'
    """

    RECIPIENT = "recipient"
    ATTACHMENT = "attachment"


def printable(text: str) -> str:
    """Return text with every control character (CR, LF, ESC, NUL, ...) replaced by a space.

    A multi-line or escape-laden server reply must not forge extra log lines or
    terminal sequences in whatever renders the record.

    Args:
        text: The raw text to clean.

    Returns:
        A copy of text with every non-printable character replaced by a space.

    Examples:
        >>> printable("535 denied" + chr(10) + "forged")
        '535 denied forged'
    """
    return "".join(character if character.isprintable() else " " for character in text)


def is_valid_unicode(text: str) -> bool:
    """Return whether text can be written as UTF-8.

    A lone surrogate is what an invalid UTF-8 byte in argv or a POSIX file name
    decodes to; the email package raises ``UnicodeEncodeError`` for it, and that
    exception's message quotes the raw byte.

    Args:
        text: The text to check.

    Returns:
        ``False`` when text holds a lone surrogate, else ``True``.

    Examples:
        >>> is_valid_unicode("Bericht M\u00e4rz")
        True
        >>> is_valid_unicode("a" + chr(0xDCFF))
        False
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True
