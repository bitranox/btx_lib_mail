"""What is sent is the file that was checked: opened once, encoded once, closed afterwards."""

from __future__ import annotations

# The growth, symlink-swap and spool-leak cases need the open and compose steps on their own,
# since send() leaves no window between them for a test to act in.
# pyright: reportPrivateUsage=false
import contextlib
import gc
import math
import os
import sys
import warnings
from email import message_from_bytes
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

import pytest

from btx_lib_mail import AttachmentSecurityError, AttachmentViolation, ConfigurationError, ConfMail, InvalidInputError, _attachments, _compose, lib_mail, send

if TYPE_CHECKING:
    from collections.abc import Callable


class _RecordingTransport:
    """Records each delivered message; runs *on_first_delivery* once, after recipient 1 is sent."""

    def __init__(self, on_first_delivery: Callable[[], None] | None = None) -> None:
        self.messages: dict[str, bytes] = {}
        self._on_first_delivery = on_first_delivery

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: Any) -> None:
        message.seek(0)
        self.messages[recipient] = message.read()
        if self._on_first_delivery is not None:
            hook, self._on_first_delivery = self._on_first_delivery, None
            hook()


def _attempt(change: Callable[[], None]) -> bool:
    """Run *change* to the attachment's path; return whether the OS allowed it.

    Windows refuses to delete or replace a file another handle has open, and ``send`` holds
    each attachment open from its check until it returns, so there the change is refused with
    ``PermissionError``. POSIX allows it. Every recipient must get the checked bytes either way.
    """
    try:
        change()
    except PermissionError:
        if sys.platform != "win32":
            raise
        return False
    return True


def _attachment_bytes(raw: bytes) -> bytes:
    parts = [part for part in message_from_bytes(raw).walk() if part.get_filename()]
    assert len(parts) == 1, "positive control: the message carries exactly one attachment"
    payload = parts[0].get_payload(decode=True)
    assert isinstance(payload, bytes)
    return payload


def _send(transport: Any, attachment: Path, **overrides: Any) -> bool:
    arguments: dict[str, Any] = {
        "mail_from": "sender@example.com",
        "mail_recipients": ["one@example.com", "two@example.com", "three@example.com"],
        "mail_subject": "Report",
        "smtphosts": ["smtp.example.com"],
        "attachment_file_paths": [attachment],
        "attachment_blocked_directories": frozenset(),
        "transport": transport,
    }
    arguments.update(overrides)
    return send(**arguments)


@pytest.mark.os_agnostic
def test_a_path_swapped_for_a_symlink_after_the_check_does_not_reach_later_recipients(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    secret = tmp_path / "vault" / "notes.txt"
    secret.parent.mkdir()
    secret.write_bytes(b"NOT FOR MAIL")

    def swap() -> None:
        report.unlink()
        report.symlink_to(secret)

    applied: list[bool] = []
    transport = _RecordingTransport(on_first_delivery=lambda: applied.append(_attempt(swap)))
    assert _send(transport, report) is True

    assert applied == [sys.platform != "win32"]
    assert set(transport.messages) == {"one@example.com", "two@example.com", "three@example.com"}
    for raw in transport.messages.values():
        assert _attachment_bytes(raw) == b"quarterly numbers"


@pytest.mark.os_agnostic
def test_an_attachment_deleted_during_delivery_does_not_abandon_later_recipients(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")

    applied: list[bool] = []
    transport = _RecordingTransport(on_first_delivery=lambda: applied.append(_attempt(report.unlink)))
    assert _send(transport, report) is True

    assert applied == [sys.platform != "win32"]
    assert len(transport.messages) == 3
    assert all(_attachment_bytes(raw) == b"quarterly numbers" for raw in transport.messages.values())


def _prepare(path: Path, *, max_size: int | None) -> tuple[lib_mail.AttachmentPayload, ...]:
    security = lib_mail.AttachmentSecurityOptions(
        allowed_extensions=None,
        blocked_extensions=frozenset(),
        allowed_directories=None,
        blocked_directories=frozenset(),
        max_size_bytes=max_size,
        allow_symlinks=False,
        raise_on_violation=True,
        max_count=None,
    )
    return _attachments.prepare_attachments((path,), security, raise_on_missing=True)


@pytest.mark.os_agnostic
def test_a_file_grown_past_the_limit_after_the_check_is_refused_while_it_is_read(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"x" * 10)
    attachments = _prepare(report, max_size=10)
    try:
        with report.open("ab") as grow:
            grow.write(b"y" * 200_000)

        with pytest.raises(AttachmentSecurityError) as caught:
            _compose._compose_body(_compose.MessageContent(plain_body="b", html_body="", attachments=attachments))
    finally:
        _attachments.close_attachments(attachments)

    assert caught.value.violation_type is AttachmentViolation.SIZE
    assert "grew past the limit of 10 bytes" in str(caught.value)


@pytest.mark.os_agnostic
def test_in_warn_mode_a_grown_file_is_left_out_and_the_rest_is_sent(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    grown = tmp_path / "grown.txt"
    grown.write_bytes(b"x" * 10)
    steady = tmp_path / "steady.txt"
    steady.write_bytes(b"ok")
    security = lib_mail.AttachmentSecurityOptions(
        allowed_extensions=None,
        blocked_extensions=frozenset(),
        allowed_directories=None,
        blocked_directories=frozenset(),
        max_size_bytes=10,
        allow_symlinks=False,
        raise_on_violation=False,
        max_count=None,
    )
    attachments = _attachments.prepare_attachments((grown, steady), security, raise_on_missing=True)
    try:
        with grown.open("ab") as grow:
            grow.write(b"y" * 200_000)
        body = _compose.compose_body_once(_compose.MessageContent(plain_body="b", html_body="", attachments=attachments), raise_on_violation=False)
        raw = body.read()
        body.close()
    finally:
        _attachments.close_attachments(attachments)

    assert b"steady.txt" in raw
    assert b"grown.txt" not in raw
    assert "grew past the limit" in caplog.text


@pytest.mark.os_agnostic
def test_a_symlink_at_the_checked_path_is_refused_as_changed(tmp_path: Path) -> None:
    # The opened path is already resolved, so a symlink there was swapped in after the checks.
    target = tmp_path / "target.txt"
    target.write_bytes(b"data")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(AttachmentSecurityError) as caught:
        _attachments._open_attachment(link, None)

    assert caught.value.violation_type is AttachmentViolation.CHANGED


@pytest.mark.os_agnostic
def test_a_directory_at_the_checked_path_is_reported_as_missing(tmp_path: Path) -> None:
    assert _attachments._open_attachment(tmp_path, None) is None


def _unclosed_file_warnings(action: Callable[[], object]) -> list[str]:
    # Collect first, so a file an EARLIER test left unclosed is not blamed on this action.
    gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        # The action may fail on purpose; only the warnings it leaves matter.
        with contextlib.suppress(Exception):
            action()
        gc.collect()
    return [str(warning.message) for warning in caught if issubclass(warning.category, ResourceWarning)]


@pytest.mark.os_agnostic
def test_every_attachment_handle_and_spool_is_closed_after_a_successful_send(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"data")

    assert _unclosed_file_warnings(lambda: _send(_RecordingTransport(), report)) == []


@pytest.mark.os_agnostic
def test_opened_attachments_are_closed_when_a_later_check_refuses_the_call(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"data")

    # The attachment is opened before the hosts are checked; the bad host must not leak it.
    assert _unclosed_file_warnings(lambda: _send(_RecordingTransport(), report, smtphosts=["bad host"])) == []


@pytest.mark.os_agnostic
def test_an_attachment_opened_before_a_later_one_is_refused_is_closed(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"data")

    def refused_second() -> object:
        return send(
            "sender@example.com",
            "one@example.com",
            "s",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[report, tmp_path / "missing.txt"],
            attachment_blocked_directories=frozenset(),
            transport=_RecordingTransport(),
        )

    assert _unclosed_file_warnings(refused_second) == []


@pytest.mark.os_agnostic
def test_the_body_spool_is_closed_when_composition_fails(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"x" * 10)
    attachments = _prepare(report, max_size=10)
    with report.open("ab") as grow:
        grow.write(b"y" * 200_000)

    def compose() -> object:
        return _compose._compose_body(_compose.MessageContent(plain_body="b", html_body="", attachments=attachments))

    leaked = _unclosed_file_warnings(compose)
    _attachments.close_attachments(attachments)
    assert leaked == []


# ---------------------------------------------------------------------------
# Subject: refused before the first delivery
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("subject", ["a\r\nBcc: x@example.com", "a\nb", "a\rb"])
def test_a_subject_with_a_line_break_is_refused_with_the_email_package_message(subject: str) -> None:
    transport = _RecordingTransport()

    with pytest.raises(InvalidInputError, match=r"^Header values may not contain linefeed or carriage return characters$"):
        send("sender@example.com", ["one@example.com", "two@example.com"], subject, smtphosts=["smtp.example.com"], transport=transport)

    assert transport.messages == {}, "no recipient was sent to"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("subject", ["a\x00b", "a\x1b[31mb", "a\x7fb"])
def test_a_subject_with_another_control_character_is_refused_without_echoing_it(subject: str) -> None:
    transport = _RecordingTransport()

    with pytest.raises(InvalidInputError) as caught:
        send("sender@example.com", "one@example.com", subject, smtphosts=["smtp.example.com"], transport=transport)

    assert str(caught.value) == "mail_subject must not contain control characters (only TAB is allowed)"
    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize("separator", [chr(0x2028), chr(0x2029)], ids=["line-separator", "paragraph-separator"])
def test_a_subject_with_a_unicode_line_separator_is_refused_with_the_email_package_message(separator: str) -> None:
    transport = _RecordingTransport()

    with pytest.raises(InvalidInputError, match=r"^Header values may not contain linefeed or carriage return characters$"):
        send("sender@example.com", "one@example.com", f"a{separator}b", smtphosts=["smtp.example.com"], transport=transport)

    assert transport.messages == {}


_LONE_SURROGATE = chr(0xDCFF)  # what an invalid UTF-8 byte in argv decodes to on POSIX


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("mail_subject", "mail_subject must be valid Unicode text"),
        ("mail_body", "mail_body must be valid Unicode text"),
        ("mail_body_html", "mail_body_html must be valid Unicode text"),
    ],
)
def test_text_holding_a_lone_surrogate_is_refused_without_echoing_it(field: str, message: str) -> None:
    transport = _RecordingTransport()
    text: dict[str, Any] = {"mail_subject": "Report", field: f"a{_LONE_SURROGATE}b"}

    with pytest.raises(InvalidInputError) as caught:
        send("sender@example.com", "one@example.com", smtphosts=["smtp.example.com"], transport=transport, **text)

    assert str(caught.value) == message
    assert transport.messages == {}


@pytest.mark.os_agnostic
def test_a_subject_with_a_tab_is_sent() -> None:
    transport = _RecordingTransport()

    assert send("sender@example.com", "one@example.com", "a\tb", smtphosts=["smtp.example.com"], transport=transport) is True
    assert message_from_bytes(transport.messages["one@example.com"])["Subject"] == "a\tb"


# ---------------------------------------------------------------------------
# Timeout: finite only
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_conf_mail_refuses_a_timeout_that_is_not_finite(value: float) -> None:
    with pytest.raises(ConfigurationError, match="smtp_timeout must be a finite number of seconds"):
        ConfMail(smtp_timeout=value)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_send_refuses_a_timeout_that_is_not_finite(value: float) -> None:
    with pytest.raises(InvalidInputError, match="smtp_timeout must be a finite number of seconds"):
        send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], timeout=value, transport=_RecordingTransport())


@pytest.mark.os_agnostic
def test_a_negative_infinite_timeout_keeps_the_positive_message() -> None:
    with pytest.raises(InvalidInputError, match="smtp_timeout must be positive, got -inf"):
        send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], timeout=-math.inf, transport=_RecordingTransport())


# ---------------------------------------------------------------------------
# send() keyword extension sets, failover rewind, the per-recipient stream
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_blocked_extension_given_to_send_matches_any_case(tmp_path: Path) -> None:
    tool = tmp_path / "x.EXE"
    tool.write_bytes(b"MZ")

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(_RecordingTransport(), tool, attachment_blocked_extensions=frozenset({".EXE"}))

    assert caught.value.violation_type is AttachmentViolation.EXTENSION


@pytest.mark.os_agnostic
@pytest.mark.parametrize("spelling", ["PDF", ".PDF", " pdf "])
def test_an_allowed_extension_given_to_send_is_normalised_like_the_config(tmp_path: Path, spelling: str) -> None:
    report = tmp_path / "r.pdf"
    report.write_bytes(b"%PDF")

    assert _send(_RecordingTransport(), report, attachment_allowed_extensions=frozenset({spelling})) is True


class _ReadThenFailOnFirstHost:
    """Reads the whole message on the first host, then fails, so failover must rewind it."""

    def __init__(self) -> None:
        self.read_sizes: dict[str, int] = {}

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: Any) -> None:
        self.read_sizes[host] = len(message.read())
        if host == "first.example.com":
            raise ConnectionResetError("dropped")


@pytest.mark.os_agnostic
def test_the_next_host_receives_the_whole_message_after_a_host_read_and_failed() -> None:
    transport = _ReadThenFailOnFirstHost()

    send("sender@example.com", "one@example.com", "s", "body", smtphosts=["first.example.com", "second.example.com"], transport=transport)

    assert transport.read_sizes["first.example.com"] > 0
    assert transport.read_sizes["second.example.com"] == transport.read_sizes["first.example.com"]


@pytest.mark.os_agnostic
def test_a_recipient_message_reads_the_shared_body_in_place() -> None:
    shared = _compose._new_spool()
    shared.write(b"MIME-Version: 1.0\r\n\r\nbody\r\n")
    message = _compose.message_for(b"Subject: s\r\n", shared)
    try:
        assert message.read() == b"Subject: s\r\nMIME-Version: 1.0\r\n\r\nbody\r\n"
        message.seek(0)
        assert message.read(5) == b"Subje"
        # No copy: the recipient's stream reads the shared spool itself, so scratch
        # disk is the body once, not once more per recipient.
        shared.seek(0, 2)
        shared.write(b"tail\r\n")
        message.seek(0)
        assert message.read().endswith(b"tail\r\n")
    finally:
        message.close()
    assert not shared.closed, "closing one recipient's message must not close the shared body"
    shared.close()


# Control characters a POSIX file name can hold. CR, LF, VT and FF made the header serialiser
# raise a bare ValueError mid-compose; NUL, ESC and DEL went into the header raw.
_CONTROL_CHARACTERS = ["\n", "\r", "\x0b", "\x0c", "\x00", "\x1b", "\x7f", "\x85"]
_CONTROL_CHARACTERS_ON_DISK = [character for character in _CONTROL_CHARACTERS if character != "\x00"]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("character", _CONTROL_CHARACTERS, ids=repr)
def test_the_filename_check_refuses_a_control_character(character: str) -> None:
    with pytest.raises(AttachmentSecurityError) as caught:
        _attachments._check_filename(Path(f"/data/report{character}final.txt"))

    assert caught.value.violation_type is AttachmentViolation.FILENAME
    assert character not in caught.value.reason


@pytest.mark.os_agnostic
def test_the_filename_check_accepts_printable_unicode() -> None:
    _attachments._check_filename(Path("/data/Bericht für März - 日本.txt"))


@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold control characters")
@pytest.mark.parametrize("character", _CONTROL_CHARACTERS_ON_DISK, ids=repr)
def test_a_control_character_in_an_attachment_name_is_a_security_refusal_through_send(tmp_path: Path, character: str) -> None:
    report = tmp_path / f"report{character}final.txt"
    report.write_bytes(b"quarterly numbers")
    transport = _RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, report)

    assert caught.value.violation_type is AttachmentViolation.FILENAME
    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize("strict", [True, False], ids=["strict", "warn"])
def test_a_nul_in_an_attachment_path_is_a_filename_refusal_before_any_file_system_call(tmp_path: Path, strict: bool) -> None:
    transport = _RecordingTransport()
    report = tmp_path / "report\x00final.txt"

    if strict:
        with pytest.raises(AttachmentSecurityError) as caught:
            _send(transport, report)
        assert caught.value.violation_type is AttachmentViolation.FILENAME
        assert "\x00" not in caught.value.reason
        assert transport.messages == {}
    else:
        assert _send(transport, report, attachment_raise_on_security_violation=False) is True
        assert len(transport.messages) == 3, "warn mode skips the attachment and still sends"


@pytest.mark.os_linux
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="macOS and Windows file systems refuse a name that is not valid UTF-8")
@pytest.mark.parametrize("strict", [True, False], ids=["strict", "warn"])
def test_an_attachment_name_that_is_not_valid_unicode_is_a_filename_refusal(tmp_path: Path, strict: bool) -> None:
    # An invalid UTF-8 byte in a POSIX file name decodes to a lone surrogate, which the
    # Content-Disposition header cannot encode.
    report = tmp_path / f"report{chr(0xDCFF)}final.txt"
    report.write_bytes(b"quarterly numbers")
    transport = _RecordingTransport()

    if strict:
        with pytest.raises(AttachmentSecurityError) as caught:
            _send(transport, report)
        assert caught.value.violation_type is AttachmentViolation.FILENAME
        assert transport.messages == {}
    else:
        assert _send(transport, report, attachment_raise_on_security_violation=False) is True
        assert len(transport.messages) == 3
        for raw in transport.messages.values():
            assert not [part for part in message_from_bytes(raw).walk() if part.get_filename()]


@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold control characters")
def test_warn_mode_skips_an_attachment_whose_name_holds_a_line_break(tmp_path: Path) -> None:
    report = tmp_path / "report\r\nBcc: victim@example.com.txt"
    report.write_bytes(b"quarterly numbers")
    transport = _RecordingTransport()

    assert _send(transport, report, attachment_raise_on_security_violation=False) is True

    assert len(transport.messages) == 3
    for raw in transport.messages.values():
        assert not [part for part in message_from_bytes(raw).walk() if part.get_filename()]
        assert b"victim@example.com" not in raw


@pytest.mark.os_agnostic
def test_a_path_swapped_for_another_regular_file_after_the_check_is_refused_as_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The (device, inode) comparison is the only thing that catches a same-kind swap.

    The swap must land between the lstat that records the checked file and the open that
    reads it, a window inside one function; os.open is wrapped (the stdlib edge) so the
    replacement happens at exactly that moment.
    """
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    impostor = tmp_path / "impostor.txt"
    impostor.write_bytes(b"NOT FOR MAIL")
    real_open = os.open
    swapped: list[bool] = []

    def open_after_swap(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if not swapped and os.fspath(path) == os.fspath(report.resolve()):
            impostor.replace(report)
            swapped.append(True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_after_swap)
    transport = _RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, report)

    assert swapped, "positive control: the swap ran inside the open"
    assert caught.value.violation_type is AttachmentViolation.CHANGED
    assert transport.messages == {}
