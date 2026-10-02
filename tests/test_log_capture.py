"""The "never logged" check finds a secret in every form a log record can carry it.

A password reaches a record as text, as bytes (whose ``repr`` escapes every non-ASCII byte, so
the text form is no longer a substring), or inside the base64 AUTH PLAIN token. Each form is
planted here and must be found; an unrelated record must not trip it.
"""

from __future__ import annotations

import base64
import logging

import pytest
from log_capture import assert_never_logged

_SECRET = f"DUMMY-p{chr(0xE4)}ssw{chr(0xF6)}rd-PLANTED-3b8d"  # non-ASCII, so repr() of its bytes escapes them
_USER = "user"
_logger = logging.getLogger("btx_lib_mail.test_log_capture")


def _auth_plain(user: str, secret: str) -> str:
    return base64.b64encode(b"\0" + user.encode() + b"\0" + secret.encode()).decode("ascii")


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("message", "extra"),
    [
        (f"login with {_SECRET}", {}),
        ("login failed", {"password": _SECRET}),
        ("login failed", {"password": _SECRET.encode()}),
        (f"sent AUTH PLAIN {_auth_plain(_USER, _SECRET)}", {}),
    ],
    ids=["text-in-message", "text-in-extra", "bytes-in-extra", "auth-plain-token"],
)
def test_a_planted_secret_is_found_in_every_form(caplog: pytest.LogCaptureFixture, message: str, extra: dict[str, object]) -> None:
    caplog.set_level(logging.DEBUG, logger=_logger.name)
    _logger.warning(message, extra=extra)

    with pytest.raises(AssertionError) as caught:
        assert_never_logged(caplog, _SECRET, user=_USER)

    assert _SECRET not in str(caught.value), "the failure names the form, never the secret"


@pytest.mark.os_agnostic
def test_records_without_the_secret_pass(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=_logger.name)
    _logger.warning("login failed", extra={"password": "something-else", "token": _auth_plain(_USER, "other")})
    assert caplog.records, "positive control: a record was captured"

    assert_never_logged(caplog, _SECRET, user=_USER)
