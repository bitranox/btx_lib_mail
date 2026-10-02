"""The library logger and the control-character cleaning every log line and message uses.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("btx_lib_mail")


def printable(text: str) -> str:
    """Return *text* with every control character (CR, LF, ESC, NUL, ...) replaced by a space.

    Why
        A multi-line or escape-laden server reply must not forge extra log
        lines or terminal sequences in whatever renders the record.

    Examples
    --------
    >>> printable("535 denied" + chr(10) + "forged")
    '535 denied forged'
    """
    return "".join(character if character.isprintable() else " " for character in text)
