"""Guards that keep SMTP credentials out of logs, exception texts and validation errors.

Every secret here is a planted dummy. Every absence assertion is preceded by a
positive control proving the thing searched was actually produced.
"""

from __future__ import annotations

# Tests reach module internals (the failure describer, the transport seam) on purpose.
# pyright: reportPrivateUsage=false
import ast
import logging
import smtplib
from pathlib import Path
from typing import IO, TYPE_CHECKING

import pytest

import btx_lib_mail
from btx_lib_mail import lib_mail

if TYPE_CHECKING:
    from btx_lib_mail.lib_mail import DeliveryOptions

_DUMMY = "DUMMY-pässwörd-PLANTED-7f3a"
_AUTH_STRING = "\x00user\x00" + _DUMMY


class _RaisingTransport:
    """Transport double that fails every delivery with a preset exception."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        raise self.error


def _send_through(transport: lib_mail.Transport) -> None:
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="s",
        mail_body="b",
        smtphosts=["smtp.example.com"],
        transport=transport,
    )


def _failure_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "btx_lib_mail" and r.levelno == logging.WARNING and "can not send mail" in r.msg]


@pytest.mark.os_agnostic
def test_a_failed_host_logs_no_traceback_and_no_auth_string(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="btx_lib_mail")
    error = UnicodeEncodeError("ascii", _AUTH_STRING, 6, 7, "ordinal not in range(128)")

    with pytest.raises(RuntimeError):
        _send_through(_RaisingTransport(error))

    records = _failure_records(caplog)
    assert len(records) == 1, "positive control: the per-host failure must reach the capture"
    record = records[0]
    assert "UnicodeEncodeError" in record.getMessage(), "positive control: the failure is still described"
    assert record.exc_info is None
    assert record.stack_info is None
    assert _DUMMY not in repr(vars(record))
    assert _DUMMY not in caplog.text


@pytest.mark.os_agnostic
def test_a_failed_host_logs_the_smtp_code_and_server_text(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="btx_lib_mail")
    error = smtplib.SMTPAuthenticationError(535, b"5.7.8 Authentication credentials invalid")

    with pytest.raises(RuntimeError):
        _send_through(_RaisingTransport(error))

    record = _failure_records(caplog)[0]
    assert "SMTPAuthenticationError 535 5.7.8 Authentication credentials invalid" in record.getMessage()
    assert record.__dict__["error_type"] == "SMTPAuthenticationError"
    assert record.__dict__["smtp_code"] == 535


@pytest.mark.os_agnostic
def test_a_network_error_keeps_its_text() -> None:
    assert lib_mail._describe_failure(ConnectionRefusedError(111, "Connection refused")) == "ConnectionRefusedError: [Errno 111] Connection refused"


@pytest.mark.os_agnostic
def test_an_unknown_error_is_named_but_not_quoted() -> None:
    assert lib_mail._describe_failure(ValueError(_DUMMY)) == "ValueError"


@pytest.mark.os_agnostic
def test_a_long_server_reply_is_bounded() -> None:
    described = lib_mail._describe_failure(smtplib.SMTPDataError(554, b"x" * 5000))
    assert described.startswith("SMTPDataError 554 x")
    assert len(described) == lib_mail._FAILURE_TEXT_LIMIT


@pytest.mark.os_agnostic
def test_a_server_reply_cannot_forge_log_lines() -> None:
    reply = b"5.7.8 denied\r\nWARNING forged line\x1b[31m\x00"
    described = lib_mail._describe_failure(smtplib.SMTPAuthenticationError(535, reply))
    assert described.startswith("SMTPAuthenticationError 535 5.7.8 denied"), "positive control: the reply text is kept"
    assert "forged line" in described, "positive control: text after the line break is kept, on the same line"
    assert all(character.isprintable() for character in described)


@pytest.mark.os_agnostic
def test_a_custom_transport_os_error_is_kept_on_one_line() -> None:
    described = lib_mail._describe_failure(ConnectionError("refused\nsecond line"))
    assert described == "ConnectionError: refused second line"


_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "critical", "exception", "log"})


def _refers_to(node: ast.expr, names: set[str]) -> bool:
    """Return True when *node* is one of *names*, or an f-string interpolating one."""
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) and _refers_to(part.value, names) for part in node.values)
    return False


def _hands_over_the_exception(call: ast.Call, names: set[str]) -> bool:
    """Return True when a logging call passes a caught exception as an argument or an `extra` value."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr in _LOG_METHODS):
        return False
    extra_values = [value for keyword in call.keywords if keyword.arg == "extra" and isinstance(keyword.value, ast.Dict) for value in keyword.value.values]
    return any(_refers_to(value, names) for value in [*call.args, *extra_values])


def _attaches_a_traceback(call: ast.Call) -> bool:
    if any(keyword.arg in {"exc_info", "stack_info"} for keyword in call.keywords):
        return True
    return isinstance(call.func, ast.Attribute) and call.func.attr == "exception"


def _exception_leaking_log_calls(source: str, filename: str) -> list[str]:
    """Return `file:line` for every log call that hands an exception object to the log record."""
    tree = ast.parse(source)
    lines = {node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call) and _attaches_a_traceback(node)}
    for handler in ast.walk(tree):
        if not (isinstance(handler, ast.ExceptHandler) and handler.name):
            continue
        calls = (node for statement in handler.body for node in ast.walk(statement) if isinstance(node, ast.Call))
        lines |= {call.lineno for call in calls if _hands_over_the_exception(call, {handler.name})}
    return [f"{filename}:{line}" for line in sorted(lines)]


# Lines 3, 4, 8, 9 and 10 hand the exception (or its traceback) to the record;
# lines 11 and 12 only pass values derived from it and must NOT be flagged.
_PLANTED = """\
import logging
log = logging.getLogger("x")
log.warning("m", exc_info=True)
log.exception("m")
try:
    pass
except Exception as error:
    log.warning("m %r", error)
    log.warning("m", extra={"error": error})
    log.warning(f"m {error!r}")
    log.warning("m %s", describe(error))
    log.warning("m %s", type(error).__name__, extra={"code": getattr(error, "code", None)})
"""


@pytest.mark.os_agnostic
def test_the_log_call_detector_flags_every_planted_shape_and_nothing_else() -> None:
    assert _exception_leaking_log_calls(_PLANTED, "planted.py") == ["planted.py:3", "planted.py:4", "planted.py:8", "planted.py:9", "planted.py:10"]


@pytest.mark.os_agnostic
def test_no_log_call_in_the_package_hands_over_an_exception() -> None:
    package_dir = Path(btx_lib_mail.__file__).parent
    sources = sorted(package_dir.rglob("*.py"))
    assert any(path.name == "lib_mail.py" for path in sources), "positive control: the scan reaches lib_mail.py"
    offenders = [hit for path in sources for hit in _exception_leaking_log_calls(path.read_text(encoding="utf-8"), path.name)]
    assert offenders == []


_HOST_DUMMY = "DUMMY-PLANTED-5e8b"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "host",
    [f"user:{_HOST_DUMMY}@smtp.example.com", f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587", "smtp.example.com/relay"],
)
def test_a_host_with_userinfo_or_a_path_is_refused_without_quoting_it(host: str) -> None:
    with pytest.raises(ValueError, match="must not contain") as caught:
        lib_mail.validate_smtp_host(host)
    assert _HOST_DUMMY not in str(caught.value)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("host", ["smtp.example.com", "smtp.example.com:587", "[::1]:25", "[::1]"])
def test_plain_hosts_still_validate(host: str) -> None:
    lib_mail.validate_smtp_host(host)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "hosts",
    [[f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587"], [f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587", "good.example.com"]],
    ids=["alone", "before a good host"],
)
def test_send_refuses_a_userinfo_host_before_any_delivery(hosts: list[str], caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="btx_lib_mail")
    transport = _RaisingTransport(AssertionError("transport must not be reached"))
    with pytest.raises(ValueError, match="must not contain") as caught:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="rcpt@example.com",
            mail_subject="s",
            smtphosts=hosts,
            transport=transport,
        )
    assert _HOST_DUMMY not in str(caught.value)
    assert _HOST_DUMMY not in caplog.text


@pytest.mark.os_agnostic
def test_delivery_options_repr_hides_the_credentials() -> None:
    options = lib_mail.DeliveryOptions(credentials=("user", _HOST_DUMMY), use_starttls=True, starttls_verify=True, timeout=5.0)
    assert "use_starttls=True" in repr(options), "positive control: the repr is still produced"
    assert _HOST_DUMMY not in repr(options)
    assert options.credentials == ("user", _HOST_DUMMY)
