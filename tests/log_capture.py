"""Read back everything a log record carries, not only its rendered message.

``caplog.text`` holds the formatted message alone. A structured log adapter (lib_log_rich, a
JSON handler) also serialises the ``extra={...}`` fields, so a value kept out of the message but
put into ``extra`` still reaches the log. A "never logged" assertion has to read both, and has to
look for the secret in every form a record can carry it (see ``assert_never_logged``).
"""

from __future__ import annotations

import base64
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


def secret_forms(secret: str, *, user: str | None = None) -> dict[str, str]:
    """Return each form a secret takes in a rendered log record, keyed by a name for the form.

    ``repr`` of the UTF-8 bytes escapes every non-ASCII byte (``\\xc3\\xa4``), so the text is
    not a substring of it; an SMTP AUTH PLAIN token is base64 of ``NUL user NUL secret``.

    Args:
        secret: The secret to look for.
        user: The user name the secret authenticates, when the AUTH PLAIN token can appear.

    Returns:
        The form's name mapped to the text to search for.
    """
    forms = {"text": secret, "escaped text": repr(secret)[1:-1], "escaped bytes": repr(secret.encode("utf-8"))[2:-1]}
    if user is not None:
        token = b"\0" + user.encode("utf-8") + b"\0" + secret.encode("utf-8")
        forms["AUTH PLAIN token"] = base64.b64encode(token).decode("ascii")
    return forms


def assert_never_logged(caplog: pytest.LogCaptureFixture, secret: str, *, user: str | None = None) -> None:
    """Fail when any captured record carries the secret in any of its forms.

    Args:
        caplog: The pytest log capture fixture.
        secret: The secret that must not appear.
        user: The user name, so the AUTH PLAIN token is searched for too.

    Raises:
        AssertionError: Naming each form found, never the secret itself.
    """
    logged = everything_logged(caplog)
    found = [name for name, form in secret_forms(secret, user=user).items() if form in logged]
    assert not found, f"the secret was logged as: {', '.join(found)}"
