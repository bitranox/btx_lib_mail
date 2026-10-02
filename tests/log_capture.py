"""Read back everything a log record carries, not only its rendered message.

``caplog.text`` holds the formatted message alone. A structured log adapter (lib_log_rich, a
JSON handler) also serialises the ``extra={...}`` fields, so a value kept out of the message but
put into ``extra`` still reaches the log. A "never logged" assertion has to read both.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def everything_logged(caplog: pytest.LogCaptureFixture) -> str:
    """Return each captured record's message and every attribute, ``extra`` fields included.

    Args:
        caplog: The pytest log capture fixture.

    Returns:
        One line per record: its rendered message, then ``repr`` of all its attributes.
    """
    return "\n".join(f"{record.getMessage()} {vars(record)!r}" for record in caplog.records)
