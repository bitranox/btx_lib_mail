"""What is sent is the file that was checked: opened once, encoded once, closed afterwards."""

from __future__ import annotations

# The growth, symlink-swap and spool-leak cases need the open and compose steps on their own,
# since send() leaves no window between them for a test to act in.
# pyright: reportPrivateUsage=false
import contextlib
import errno
import gc
import logging
import math
import os
import sys
import threading
import warnings
from email import message_from_bytes
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

import pytest
from transport_doubles import RecordingTransport

from btx_lib_mail import (
    AttachmentNotFoundError,
    AttachmentSecurityError,
    AttachmentViolation,
    ConfigurationError,
    ConfMail,
    InvalidInputError,
    _attachments,
    _compose,
    _descriptor_path,
    lib_mail,
    send,
)

if TYPE_CHECKING:
    from collections.abc import Callable


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


def _send(transport: Any, attachment: Path | str, **overrides: Any) -> bool:
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
    transport = RecordingTransport(on_first_delivery=lambda: applied.append(_attempt(swap)))
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
    transport = RecordingTransport(on_first_delivery=lambda: applied.append(_attempt(report.unlink)))
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
        _attachments._open_attachment(link, _security())

    assert caught.value.violation_type is AttachmentViolation.CHANGED


@pytest.mark.os_agnostic
def test_a_directory_at_the_checked_path_is_reported_as_missing(tmp_path: Path) -> None:
    assert _attachments._open_attachment(tmp_path, _security()) is None


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

    assert _unclosed_file_warnings(lambda: _send(RecordingTransport(), report)) == []


@pytest.mark.os_agnostic
def test_opened_attachments_are_closed_when_a_later_check_refuses_the_call(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"data")

    # The attachment is opened before the hosts are checked; the bad host must not leak it.
    assert _unclosed_file_warnings(lambda: _send(RecordingTransport(), report, smtphosts=["bad host"])) == []


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
            transport=RecordingTransport(),
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
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match=r"^Header values may not contain linefeed or carriage return characters$"):
        send("sender@example.com", ["one@example.com", "two@example.com"], subject, smtphosts=["smtp.example.com"], transport=transport)

    assert transport.messages == {}, "no recipient was sent to"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("subject", ["a\x00b", "a\x1b[31mb", "a\x7fb"])
def test_a_subject_with_another_control_character_is_refused_without_echoing_it(subject: str) -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError) as caught:
        send("sender@example.com", "one@example.com", subject, smtphosts=["smtp.example.com"], transport=transport)

    assert str(caught.value) == "mail_subject must not contain control characters (only TAB is allowed)"
    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize("separator", [chr(0x2028), chr(0x2029)], ids=["line-separator", "paragraph-separator"])
def test_a_subject_with_a_unicode_line_separator_is_refused_with_the_email_package_message(separator: str) -> None:
    transport = RecordingTransport()

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
    transport = RecordingTransport()
    text: dict[str, Any] = {"mail_subject": "Report", field: f"a{_LONE_SURROGATE}b"}

    with pytest.raises(InvalidInputError) as caught:
        send("sender@example.com", "one@example.com", smtphosts=["smtp.example.com"], transport=transport, **text)

    assert str(caught.value) == message
    assert transport.messages == {}


@pytest.mark.os_agnostic
def test_a_subject_at_the_length_limit_is_sent_and_one_past_it_is_refused() -> None:
    limit = _compose.SUBJECT_MAX_CHARACTERS
    transport = RecordingTransport()

    assert send("sender@example.com", "one@example.com", "s" * limit, smtphosts=["smtp.example.com"], transport=transport) is True
    with pytest.raises(InvalidInputError) as caught:
        send("sender@example.com", "two@example.com", "s" * (limit + 1), smtphosts=["smtp.example.com"], transport=transport)

    assert str(caught.value) == f"mail_subject has {limit + 1} characters, more than the {limit} allowed"
    assert list(transport.messages) == ["one@example.com"]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("subject", "message"),
    [
        ("x" * 5000 + "\r", "Header values may not contain linefeed or carriage return characters"),
        ("x" * 5000 + "\x00", "mail_subject must not contain control characters (only TAB is allowed)"),
        ("a\x00b" + chr(0x2028) + "c", "mail_subject must not contain control characters (only TAB is allowed)"),
    ],
    ids=["line-break-before-length", "control-before-length", "control-before-separator"],
)
def test_a_subject_with_two_faults_is_refused_with_the_message_it_always_had(subject: str, message: str) -> None:
    # The length cap is checked last and a control character before the Unicode separators, so a
    # subject refused before either check existed keeps the message callers already match on.
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError) as caught:
        send("sender@example.com", "one@example.com", subject, smtphosts=["smtp.example.com"], transport=transport)

    assert str(caught.value) == message
    assert transport.messages == {}


@pytest.mark.os_agnostic
def test_a_subject_with_a_tab_is_sent() -> None:
    transport = RecordingTransport()

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
        send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], timeout=value, transport=RecordingTransport())


@pytest.mark.os_agnostic
def test_a_negative_infinite_timeout_keeps_the_positive_message() -> None:
    with pytest.raises(InvalidInputError, match="smtp_timeout must be positive, got -inf"):
        send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], timeout=-math.inf, transport=RecordingTransport())


# ---------------------------------------------------------------------------
# send() keyword extension sets, failover rewind, the per-recipient stream
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_blocked_extension_given_to_send_matches_any_case(tmp_path: Path) -> None:
    tool = tmp_path / "x.EXE"
    tool.write_bytes(b"MZ")

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(RecordingTransport(), tool, attachment_blocked_extensions=frozenset({".EXE"}))

    assert caught.value.violation_type is AttachmentViolation.EXTENSION


@pytest.mark.os_agnostic
@pytest.mark.parametrize("spelling", ["PDF", ".PDF", " pdf "])
def test_an_allowed_extension_given_to_send_is_normalised_like_the_config(tmp_path: Path, spelling: str) -> None:
    report = tmp_path / "r.pdf"
    report.write_bytes(b"%PDF")

    assert _send(RecordingTransport(), report, attachment_allowed_extensions=frozenset({spelling})) is True


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
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, report)

    assert caught.value.violation_type is AttachmentViolation.FILENAME
    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize("strict", [True, False], ids=["strict", "warn"])
def test_a_nul_in_an_attachment_path_is_a_filename_refusal_before_any_file_system_call(tmp_path: Path, strict: bool) -> None:
    transport = RecordingTransport()
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
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the component walk and /proc/self/fd are Linux-only")
def test_sending_an_attachment_from_a_deep_directory_leaks_no_descriptor(tmp_path: Path) -> None:
    """The walk opens one descriptor per directory; each must be closed, or a long-running sender reaches EMFILE."""
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    report = deep / "report.txt"
    report.write_text("hello")
    assert _send(RecordingTransport(), report)  # warm-up: imports, logger handlers
    before = len(list(Path("/proc/self/fd").iterdir()))

    for _ in range(5):
        assert _send(RecordingTransport(), report)

    assert len(list(Path("/proc/self/fd").iterdir())) == before


@pytest.mark.os_linux
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="macOS and Windows file systems refuse a name that is not valid UTF-8")
@pytest.mark.parametrize("strict", [True, False], ids=["strict", "warn"])
def test_an_attachment_name_that_is_not_valid_unicode_is_a_filename_refusal(tmp_path: Path, strict: bool) -> None:
    # An invalid UTF-8 byte in a POSIX file name decodes to a lone surrogate, which the
    # Content-Disposition header cannot encode.
    report = tmp_path / f"report{chr(0xDCFF)}final.txt"
    report.write_bytes(b"quarterly numbers")
    transport = RecordingTransport()

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
def test_an_allowed_symlink_is_judged_by_the_name_of_its_target(tmp_path: Path) -> None:
    # The message carries the resolved file's name, so that is the name the check must read:
    # a clean link name in front of a target whose name breaks the header is still refused.
    target = tmp_path / "report\nBcc: victim@example.com.txt"
    target.write_bytes(b"quarterly numbers")
    link = tmp_path / "report.txt"
    link.symlink_to(target)
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, link, attachment_allow_symlinks=True)

    assert caught.value.violation_type is AttachmentViolation.FILENAME
    assert transport.messages == {}


@pytest.mark.os_agnostic
def test_a_file_of_exactly_the_size_limit_is_sent_and_one_byte_more_is_refused(tmp_path: Path) -> None:
    at_limit = tmp_path / "at-limit.txt"
    at_limit.write_bytes(b"x" * 100)
    over_limit = tmp_path / "over-limit.txt"
    over_limit.write_bytes(b"x" * 101)
    transport = RecordingTransport()

    assert _send(transport, at_limit, attachment_max_size_bytes=100) is True
    assert _attachment_bytes(transport.messages["one@example.com"]) == b"x" * 100

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(RecordingTransport(), over_limit, attachment_max_size_bytes=100)
    assert caught.value.violation_type is AttachmentViolation.SIZE


# root reads a mode-000 file anyway; the condition reads geteuid only where it exists.
_UNREADABLE_FILE_SKIP = sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0)


@pytest.mark.os_posix
@pytest.mark.skipif(_UNREADABLE_FILE_SKIP, reason="needs POSIX permissions and a non-root user")
@pytest.mark.parametrize("tolerate", [False, True], ids=["raise", "tolerate"])
def test_an_attachment_that_cannot_be_read_is_reported_like_a_missing_one(tmp_path: Path, tolerate: bool) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    report.chmod(0)
    transport = RecordingTransport()

    try:
        if tolerate:
            assert _send(transport, report, raise_on_missing_attachments=False) is True
            assert len(transport.messages) == 3, "tolerate mode skips the attachment and still sends"
        else:
            with pytest.raises(AttachmentNotFoundError, match=r'^Attachment File ".*report\.txt" can not be read \(EACCES\)$'):
                _send(transport, report)
            assert transport.messages == {}
    finally:
        report.chmod(0o600)


@pytest.mark.os_posix
@pytest.mark.skipif(_UNREADABLE_FILE_SKIP, reason="needs POSIX permissions and a non-root user")
@pytest.mark.parametrize("tolerate", [False, True], ids=["raise", "tolerate"])
def test_an_attachment_in_a_directory_that_cannot_be_searched_is_reported_as_unreadable(tmp_path: Path, tolerate: bool) -> None:
    # Python 3.10-3.13 re-raise EACCES from Path.is_symlink(), so the symlink check itself must not leak it.
    locked = tmp_path / "locked"
    locked.mkdir()
    report = locked / "report.txt"
    report.write_bytes(b"quarterly numbers")
    locked.chmod(0)
    transport = RecordingTransport()

    try:
        if tolerate:
            assert _send(transport, report, raise_on_missing_attachments=False) is True
            assert len(transport.messages) == 3, "tolerate mode skips the attachment and still sends"
        else:
            with pytest.raises(AttachmentNotFoundError, match=r'^Attachment File ".*report\.txt" can not be read \(EACCES\)$'):
                _send(transport, report)
            assert transport.messages == {}
    finally:
        locked.chmod(0o700)


@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform == "win32", reason="Windows reports an overlong name differently")
@pytest.mark.parametrize("tolerate", [False, True], ids=["raise", "tolerate"])
def test_an_attachment_name_longer_than_the_filesystem_allows_is_reported_as_unreadable(tmp_path: Path, tolerate: bool) -> None:
    report = tmp_path / ("x" * 300 + ".txt")
    transport = RecordingTransport()

    if tolerate:
        assert _send(transport, report, raise_on_missing_attachments=False) is True
        assert len(transport.messages) == 3
    else:
        with pytest.raises(AttachmentNotFoundError, match=r'^Attachment File ".*x\.txt" can not be read \(ENAMETOOLONG\)$'):
            _send(transport, report)
        assert transport.messages == {}


@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform == "win32", reason="creating symlinks needs a privilege on Windows")
@pytest.mark.parametrize("tolerate", [False, True], ids=["raise", "tolerate"])
def test_an_allowed_symlink_loop_is_reported_as_unreadable(tmp_path: Path, tolerate: bool) -> None:
    # Python 3.10-3.12 raise RuntimeError from Path.resolve() on a loop; 3.13+ return the loop unresolved.
    first, second = tmp_path / "first.txt", tmp_path / "second.txt"
    first.symlink_to(second)
    second.symlink_to(first)
    transport = RecordingTransport()

    if tolerate:
        assert _send(transport, first, attachment_allow_symlinks=True, raise_on_missing_attachments=False) is True
        assert len(transport.messages) == 3
    else:
        with pytest.raises(AttachmentNotFoundError, match=r'^Attachment File ".*first\.txt" can not be read \(ELOOP\)$'):
            _send(transport, first, attachment_allow_symlinks=True)
        assert transport.messages == {}


@pytest.mark.os_agnostic
def test_an_attachment_path_given_as_a_string_is_sent(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    transport = RecordingTransport()

    assert _send(transport, str(report)) is True

    assert _attachment_bytes(transport.messages["one@example.com"]) == b"quarterly numbers"


@pytest.mark.os_agnostic
def test_an_attachment_entry_that_is_not_a_path_is_refused() -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match=r"^attachment_file_paths entries must be paths, got int$"):
        _send(transport, 5)  # pyright: ignore[reportArgumentType]  # the wrong type is the point

    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize("tolerate", [False, True], ids=["raise", "tolerate"])
@pytest.mark.parametrize(
    ("whole", "type_name"),
    [("/data/report.pdf", "str"), (b"/data/report.pdf", "bytes"), (Path("/data/report.pdf"), Path("x").__class__.__name__), (5, "int")],
    ids=["str", "bytes", "path", "int"],
)
def test_attachment_paths_given_as_one_value_instead_of_a_sequence_are_refused(whole: object, type_name: str, tolerate: bool) -> None:
    # A bare string iterates per character: each letter was checked as a path of its own.
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match=rf"^attachment_file_paths must be a sequence of paths, got {type_name}$"):
        _send(transport, "unused", attachment_file_paths=whole, raise_on_missing_attachments=not tolerate)

    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize("control", [0x202E, 0x202A, 0x2066, 0x2069, 0x200F, 0x061C], ids=["RLO", "LRE", "LRI", "PDI", "RLM", "ALM"])
def test_an_attachment_name_holding_a_bidi_control_is_refused(tmp_path: Path, control: int) -> None:
    # U+202E turns "report<RLO>fdp.xlsm" into "reportmslx.pdf" on screen: a macro file posing as a PDF.
    report = tmp_path / f"report{chr(control)}fdp.xlsm"
    report.write_bytes(b"quarterly numbers")
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, report)

    assert caught.value.violation_type is AttachmentViolation.FILENAME
    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "name",
    ["=?utf-8?b?aW52b2ljZS5leGU=?=", "report =?utf-8?q?x.exe?= ", "=?iso-8859-1?q?Bericht=2Epdf?= =?utf-8?b?LmV4ZQ==?="],
    ids=["whole-name", "inside-the-name", "two-words"],
)
def test_a_file_name_the_message_would_carry_differently_is_refused(name: str) -> None:
    """The header decodes an RFC 2047 encoded word, so the name the checks saw is not the one sent.

    ``=?utf-8?b?aW52b2ljZS5leGU=?=`` has no suffix to block, and the recipient gets ``invoice.exe``.
    """
    with pytest.raises(AttachmentSecurityError) as caught:
        _attachments._check_filename(Path("/data") / name)

    assert caught.value.violation_type is AttachmentViolation.FILENAME


@pytest.mark.os_agnostic
@pytest.mark.parametrize("name", ["a=?utf-8?q?x?=.pdf", "=?bad.pdf", 'say "hi"; again.pdf', "Bericht März.pdf"])
def test_a_file_name_the_message_carries_unchanged_passes(name: str) -> None:
    _attachments._check_filename(Path("/data") / name)


@pytest.mark.os_agnostic
def test_an_encoded_word_file_name_is_not_sent(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("Windows does not allow '?' in a file name")
    disguised = tmp_path / "=?utf-8?b?aW52b2ljZS5leGU=?="
    disguised.write_bytes(b"MZ")
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, disguised)

    assert caught.value.violation_type is AttachmentViolation.FILENAME
    assert transport.messages == {}


@pytest.mark.os_agnostic
def test_an_attachment_name_holding_a_zero_width_joiner_is_sent(tmp_path: Path) -> None:
    # A format character that only joins glyphs (emoji sequences) cannot reorder the name.
    report = tmp_path / f"family-{chr(0x1F468)}{chr(0x200D)}{chr(0x1F469)}.txt"
    report.write_bytes(b"quarterly numbers")
    transport = RecordingTransport()

    assert _send(transport, report) is True


@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold control characters")
def test_warn_mode_skips_an_attachment_whose_name_holds_a_line_break(tmp_path: Path) -> None:
    report = tmp_path / "report\r\nBcc: victim@example.com.txt"
    report.write_bytes(b"quarterly numbers")
    transport = RecordingTransport()

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
        if not swapped and _opens(path, report):
            impostor.replace(report)
            swapped.append(True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_after_swap)
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, report)

    assert swapped, "positive control: the swap ran inside the open"
    assert caught.value.violation_type is AttachmentViolation.CHANGED
    assert transport.messages == {}


@pytest.mark.os_agnostic
def test_a_path_swapped_for_a_directory_inside_the_open_is_refused_and_leaks_no_descriptor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """POSIX opens a directory for reading; os.fdopen then raised a bare IsADirectoryError and the descriptor leaked.

    Windows refuses to open a directory as a file, so there it is unreadable (EACCES).
    """
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    real_open = os.open
    swapped: list[bool] = []
    # The descriptors opened on the swapped path. Checked one by one: a lowest-free-number
    # comparison misses the leak, because the POSIX open walks the parent directory first and
    # closes it, so the leaked descriptor sits above a free one.
    opened: list[int] = []

    def open_after_swap(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if not swapped and _opens(path, report):
            report.unlink()
            report.mkdir()
            swapped.append(True)
        descriptor = real_open(path, flags, *args, **kwargs)
        if _opens(path, report):
            opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", open_after_swap)
    transport = RecordingTransport()

    with pytest.raises((AttachmentSecurityError, AttachmentNotFoundError)) as caught:
        _send(transport, report)

    assert swapped, "positive control: the swap ran inside the open"
    for descriptor in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF, f"descriptor {descriptor} was left open"
    if sys.platform == "win32":
        assert str(caught.value).endswith("can not be read (EACCES)")
    else:
        assert opened, "positive control: the directory was opened"
        assert isinstance(caught.value, AttachmentSecurityError)
        assert caught.value.violation_type is AttachmentViolation.CHANGED
    assert transport.messages == {}


@pytest.mark.os_agnostic
def test_a_file_deleted_inside_the_open_is_reported_as_not_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Deleted between the check and the open, the file is missing, not unreadable (ENOENT)."""
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    real_open = os.open
    deleted: list[bool] = []

    def open_after_delete(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if not deleted and _opens(path, report):
            report.unlink()
            deleted.append(True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_after_delete)

    with pytest.raises(AttachmentNotFoundError) as raised:
        _send(RecordingTransport(), report)

    assert deleted, "positive control: the file was deleted inside the open"
    assert str(raised.value).endswith("can not be found")


def _opens(path: Any, target: Path) -> bool:
    """Whether an os.open call is the attachment's own open: by full path, or by name below a directory (Linux)."""
    return os.fspath(path) in {os.fspath(target.resolve()), target.name}


def _security(**overrides: Any) -> _attachments.AttachmentSecurityOptions:
    values: dict[str, Any] = {
        "allowed_extensions": None,
        "blocked_extensions": frozenset(),
        "allowed_directories": None,
        "blocked_directories": frozenset(),
        "max_size_bytes": None,
        "allow_symlinks": False,
        "raise_on_violation": True,
        "max_count": None,
    }
    values.update(overrides)
    return _attachments.AttachmentSecurityOptions(**values)


def _swap_for_link(directory: Path, target: Path) -> None:
    """Replace *directory* by a symlink to *target*; skip where the OS refuses to create one."""
    directory.rename(directory.with_name(directory.name + "-old"))
    try:
        directory.symlink_to(target, target_is_directory=True)
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a directory symlink here: {exc}")


@pytest.mark.os_agnostic
def test_a_parent_directory_swapped_after_the_checks_is_refused_as_changed(tmp_path: Path) -> None:
    """O_NOFOLLOW guards only the last component; a parent swapped for a link must not lead the open elsewhere.

    ``shared/notes.txt`` passes the checks; then ``shared`` becomes a link to the blocked
    ``vault``, so opening the checked path by name would read ``vault/notes.txt``.
    """
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "notes.txt").write_bytes(b"TOPSECRET")
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "notes.txt").write_bytes(b"benign")
    security = _security(blocked_directories=frozenset({vault}))
    checked = _attachments._validate_attachment_security(shared / "notes.txt", str(shared / "notes.txt"), security)
    _swap_for_link(shared, vault)

    with pytest.raises(AttachmentSecurityError) as caught:
        _attachments._open_attachment(checked, security)

    assert caught.value.violation_type is AttachmentViolation.CHANGED


@pytest.mark.os_agnostic
def test_a_parent_directory_swapped_for_an_equally_permitted_one_is_refused_on_linux_and_judged_elsewhere(tmp_path: Path) -> None:
    """Linux opens the checked path one component at a time and follows no link, /proc or not.

    Elsewhere the open follows the link and the path the system reports for the open file is
    judged by the same checks, so a file the policy permits is still sent there.
    """
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_bytes(b"also fine")
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "notes.txt").write_bytes(b"benign")
    security = _security()
    checked = _attachments._validate_attachment_security(shared / "notes.txt", str(shared / "notes.txt"), security)
    _swap_for_link(shared, other)

    if sys.platform.startswith("linux"):
        with pytest.raises(AttachmentSecurityError) as caught:
            _attachments._open_attachment(checked, security)
        assert caught.value.violation_type is AttachmentViolation.CHANGED
        return
    handle = _attachments._open_attachment(checked, security)
    assert handle is not None
    with handle:
        assert handle.read() == b"also fine"


@pytest.mark.os_agnostic
def test_an_attachment_path_below_a_regular_file_is_not_found(tmp_path: Path) -> None:
    """ENOTDIR: a component is a file, so the path can never exist; that is missing, not unreadable."""
    report = tmp_path / "file.txt"
    report.write_text("x")
    transport = RecordingTransport()

    with pytest.raises(AttachmentNotFoundError, match=r"can not be found$"):
        _send(transport, report / "report.txt")

    assert transport.messages == {}


@pytest.mark.os_agnostic
@pytest.mark.parametrize("tolerate", [False, True], ids=["raise", "tolerate"])
def test_a_relative_attachment_path_whose_working_directory_is_gone_is_reported_as_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tolerate: bool
) -> None:
    """Resolving a relative path asks for the working directory; a deleted one raised a bare FileNotFoundError."""
    if sys.platform == "win32":
        pytest.skip("Windows refuses to delete the working directory of a running process")
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    transport = RecordingTransport()

    if tolerate:
        assert _send(transport, "report.txt", raise_on_missing_attachments=False) is True
        assert "can not be read (ENOENT)" in caplog.text
    else:
        with pytest.raises(AttachmentNotFoundError, match=r"can not be read \(ENOENT\)$"):
            _send(transport, "report.txt")


@pytest.mark.os_agnostic
def test_the_directory_rules_are_resolved_once_per_call_not_once_per_attachment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """100 attachments against 5000 blocked directories took 7.7 s, every directory resolved for every file."""
    attachments: list[Path] = []
    for index in range(20):
        attachment = tmp_path / f"report-{index}.txt"
        attachment.write_text("x")
        attachments.append(attachment)
    blocked = frozenset(tmp_path / "blocked" / str(index) for index in range(200))
    real_resolve = Path.resolve
    calls: list[int] = []

    def counting_resolve(self: Path, *, strict: bool = False) -> Path:
        calls.append(1)
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", counting_resolve)

    _send(RecordingTransport(), attachments[0], attachment_file_paths=attachments, attachment_blocked_directories=blocked)

    assert len(calls) < len(blocked) + 10 * len(attachments)


@pytest.mark.os_agnostic
def test_a_relative_directory_rule_whose_working_directory_is_gone_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        pytest.skip("Windows refuses to delete the working directory of a running process")
    report = tmp_path / "report.txt"
    report.write_text("x")
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()

    with pytest.raises(InvalidInputError, match=r"^an attachment directory can not be resolved \(ENOENT\)$"):
        _send(RecordingTransport(), report, attachment_blocked_directories=frozenset({Path("private")}))


@pytest.mark.os_agnostic
def test_a_directory_rule_that_cannot_be_resolved_does_not_stop_a_send_without_attachments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The rules were resolved for every send(), so a mail with no attachment failed over a rule it never used."""
    if sys.platform == "win32":
        pytest.skip("Windows refuses to delete the working directory of a running process")
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    transport = RecordingTransport()

    _send(transport, "unused", attachment_file_paths=[], attachment_blocked_directories=frozenset({Path("private")}))

    assert len(transport.recipients) == 3


@pytest.mark.os_agnostic
@pytest.mark.parametrize("company", ["alone", "beside-an-ordinary-rule"])
def test_a_directory_rule_that_is_a_symlink_loop_is_refused_as_unresolvable(tmp_path: Path, company: str) -> None:
    """Python before 3.13 raises a bare RuntimeError resolving a loop; 3.13 and later returned it unresolved, an inert rule.

    Beside an ordinary rule too: a check that refuses only when every rule is a loop passes the rule alone.
    """
    loop = tmp_path / "loop"
    try:
        loop.symlink_to(loop)
    except OSError:
        pytest.skip("this platform or account cannot create a symlink")
    rules = {loop}
    if company == "beside-an-ordinary-rule":
        ordinary = tmp_path / "ordinary"
        ordinary.mkdir()
        rules.add(ordinary)
    report = tmp_path / "report.txt"
    report.write_text("x")
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match=r"^an attachment directory can not be resolved \(ELOOP\)$"):
        _send(transport, report, attachment_blocked_directories=frozenset(rules))
    assert transport.recipients == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize("kind", ["blocked", "allowed"])
def test_a_directory_rule_under_a_symlink_loop_is_refused_as_unresolvable(tmp_path: Path, kind: str) -> None:
    """A loop in a PARENT of the rule made lstat raise ELOOP, which the loop check read as "not a loop" on 3.13+."""
    loop = tmp_path / "self"
    try:
        loop.symlink_to(loop)
    except OSError:
        pytest.skip("this platform or account cannot create a symlink")
    report = tmp_path / "report.txt"
    report.write_text("x")
    transport = RecordingTransport()
    rule = {f"attachment_{kind}_directories": frozenset({loop / "sub"})}

    with pytest.raises(InvalidInputError, match=r"^an attachment directory can not be resolved \(ELOOP\)$"):
        _send(transport, report, **rule)
    assert transport.recipients == []


@pytest.mark.os_posix
@pytest.mark.skipif(_UNREADABLE_FILE_SKIP, reason="needs POSIX permissions and a non-root user")
def test_a_directory_rule_the_process_cannot_examine_is_compared_as_written(tmp_path: Path) -> None:
    """The symlink-loop check raised the private unreadable-path error for a rule under a directory it cannot search."""
    locked = tmp_path / "locked"
    locked.mkdir()
    rule = locked / "rule"
    report = tmp_path / "report.txt"
    report.write_text("x")
    transport = RecordingTransport()
    locked.chmod(0)
    try:
        assert _send(transport, report, attachment_blocked_directories=frozenset({rule}))
    finally:
        locked.chmod(0o700)

    assert len(transport.recipients) == 3


@pytest.mark.os_agnostic
def test_a_directory_rule_holding_nul_is_refused_by_conf_mail() -> None:
    """NUL was accepted into the setting and broke every later send() with a bare ValueError."""
    with pytest.raises(ConfigurationError, match="directory must not contain NUL"):
        ConfMail.model_validate({"attachment_blocked_directories": ["/srv/a\x00b"]})


@pytest.mark.os_agnostic
def test_a_directory_rule_holding_nul_is_refused_by_send() -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match=r"^directory must not contain NUL$"):
        _send(transport, "unused", attachment_file_paths=[], attachment_allowed_directories=frozenset({"/srv/a\x00b"}))

    assert transport.recipients == []


# Longer than any operating system can name; resolving it on Windows raised a bare ValueError ("path too long for Windows").
_TOO_LONG_DIRECTORY = "/srv/" + "d" * 40_000

# 17000 characters, below the limit as Python counts, but 34000 UTF-16 code units, which is how Windows counts.
_TOO_LONG_IN_UTF16 = "/srv/" + chr(0x1F4C4) * 17_000


@pytest.mark.os_agnostic
@pytest.mark.parametrize("rule", [_TOO_LONG_DIRECTORY, _TOO_LONG_IN_UTF16], ids=["characters", "utf16-units"])
def test_a_directory_rule_too_long_to_name_is_refused_by_conf_mail(rule: str) -> None:
    with pytest.raises(ConfigurationError, match="directory must not be longer than 32767 UTF-16 code units"):
        ConfMail.model_validate({"attachment_blocked_directories": [rule]})


@pytest.mark.os_agnostic
@pytest.mark.parametrize("rule", [_TOO_LONG_DIRECTORY, _TOO_LONG_IN_UTF16], ids=["characters", "utf16-units"])
def test_a_directory_rule_too_long_to_name_is_refused_by_send(rule: str) -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match=r"^directory must not be longer than 32767 UTF-16 code units$"):
        _send(transport, "unused", attachment_file_paths=[], attachment_allowed_directories=frozenset({rule}))

    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_a_directory_rule_of_exactly_the_longest_path_is_kept() -> None:
    """Only a rule longer than Windows can name is refused; an emoji counts two UTF-16 code units, as there."""
    by_characters = "/" + "a" * (_attachments._LONGEST_PATH - 1)
    by_units = "/" + chr(0x1F4C4) * ((_attachments._LONGEST_PATH - 1) // 2)
    assert _attachments._utf16_length(by_units) == _attachments._LONGEST_PATH

    assert _attachments.normalise_directories([by_characters, by_units]) == frozenset({Path(by_characters), Path(by_units)})
    with pytest.raises(InvalidInputError):
        _attachments.normalise_directories([by_units + "a"])


@pytest.mark.os_agnostic
def test_a_path_of_exactly_the_quote_limit_is_quoted_whole() -> None:
    path = "/" + "a" * (_attachments._QUOTE_LIMIT - 1)
    assert _attachments._quoted(path) == path


@pytest.mark.os_agnostic
@pytest.mark.parametrize("tolerate", [False, True], ids=["raise", "tolerate"])
def test_an_attachment_path_too_long_in_utf16_units_is_reported_as_unreadable(tmp_path: Path, tolerate: bool, caplog: pytest.LogCaptureFixture) -> None:
    """Linux refuses the name as ENAMETOOLONG; Python on Windows raised a bare ValueError for it, now reported the same."""
    long_path = tmp_path / (chr(0x1F4C4) * 17_000 + ".txt")
    transport = RecordingTransport()
    if not tolerate:
        with pytest.raises(AttachmentNotFoundError, match=r"can not be read \(ENAMETOOLONG\)$"):
            _send(transport, long_path)
        return
    _send(transport, long_path, raise_on_missing_attachments=False)
    assert "can not be read (ENAMETOOLONG)" in caplog.text
    assert len(transport.recipients) == 3


# What Python on Windows raises, instead of an OSError, for a path past 32767 UTF-16 code units;
# a path can grow past it while it is resolved (C:\PROGRA~2 expanded), after every earlier check.
_WINDOWS_TOO_LONG = "path too long for Windows"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("call", ["lstat", "open"])
def test_a_path_windows_refuses_as_too_long_is_unreadable_at_each_file_system_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call: str) -> None:
    """Each call site reports the ValueError as Linux reports the length: unreadable (ENAMETOOLONG), not a foreign error."""
    report = tmp_path / "report.txt"
    report.write_bytes(b"numbers")
    names = {os.fspath(report), os.fspath(report.resolve()), report.name}  # resolved now: resolving calls lstat
    real_call = getattr(os, call)

    def too_long(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) in names:
            raise ValueError(_WINDOWS_TOO_LONG)
        return real_call(path, *args, **kwargs)

    monkeypatch.setattr(os, call, too_long)

    with pytest.raises(AttachmentNotFoundError, match=r"can not be read \(ENAMETOOLONG\)$"):
        _send(RecordingTransport(), report)


@pytest.mark.os_agnostic
def test_an_attachment_path_that_resolves_too_long_for_windows_is_unreadable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"numbers")
    real_resolve = Path.resolve

    def too_long(self: Path, *, strict: bool = False) -> Path:
        if self.name == report.name:
            raise ValueError(_WINDOWS_TOO_LONG)
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", too_long)

    with pytest.raises(AttachmentNotFoundError, match=r"can not be read \(ENAMETOOLONG\)$"):
        _send(RecordingTransport(), report)


@pytest.mark.os_agnostic
def test_a_directory_rule_that_resolves_too_long_for_windows_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = tmp_path / "report.txt"
    report.write_bytes(b"numbers")
    rule = tmp_path / "PROGRA~2"
    real_resolve = Path.resolve

    def too_long(self: Path, *, strict: bool = False) -> Path:
        if self == rule:
            raise ValueError(_WINDOWS_TOO_LONG)
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", too_long)

    with pytest.raises(InvalidInputError, match=r"^an attachment directory can not be resolved \(ENAMETOOLONG\)$"):
        _send(RecordingTransport(), report, attachment_blocked_directories=frozenset({rule}))


# A high surrogate is outside the surrogateescape range: POSIX has no bytes for it (Windows names it).
_UNENCODABLE = chr(0xD800)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("strict", [True, False], ids=["strict", "warn"])
def test_an_attachment_name_holding_a_lone_surrogate_is_a_filename_refusal(tmp_path: Path, strict: bool, caplog: pytest.LogCaptureFixture) -> None:
    """os.lstat raised a bare UnicodeEncodeError for it on POSIX; on every platform it is now refused as FILENAME."""
    odd = tmp_path / f"report{_UNENCODABLE}.pdf"
    transport = RecordingTransport()
    if strict:
        with pytest.raises(AttachmentSecurityError) as caught:
            _send(transport, odd)
        assert caught.value.violation_type is AttachmentViolation.FILENAME
        return
    _send(transport, odd, attachment_raise_on_security_violation=False)
    assert "Attachment security violation" in caplog.text
    assert len(transport.recipients) == 3


@pytest.mark.os_posix
def test_a_directory_holding_a_lone_surrogate_in_an_attachment_path_is_a_filename_refusal(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("Windows can name a lone surrogate")
    with pytest.raises(AttachmentSecurityError, match="can not be encoded for the operating system") as caught:
        _send(RecordingTransport(), tmp_path / _UNENCODABLE / "report.pdf")
    assert caught.value.violation_type is AttachmentViolation.FILENAME


@pytest.mark.os_posix
@pytest.mark.parametrize("field", ["attachment_blocked_directories", "attachment_allowed_directories"])
def test_a_directory_rule_holding_a_lone_surrogate_is_refused_where_it_is_given(tmp_path: Path, field: str) -> None:
    """Resolving it raised a bare UnicodeEncodeError at send time on POSIX."""
    if sys.platform == "win32":
        pytest.skip("Windows can name a lone surrogate")
    rule = f"/srv/{_UNENCODABLE}"
    with pytest.raises(ConfigurationError, match="directory can not be encoded for the operating system"):
        ConfMail.model_validate({field: [rule]})
    report = tmp_path / "report.txt"
    report.write_bytes(b"numbers")
    with pytest.raises(InvalidInputError, match=r"^directory can not be encoded for the operating system$"):
        _send(RecordingTransport(), report, **{field: frozenset({rule})})


@pytest.mark.os_agnostic
def test_a_live_file_whose_name_ends_in_deleted_is_judged_by_its_own_name(tmp_path: Path) -> None:
    """Linux marks an unlinked file "<path> (deleted)"; the marker was cut from a live file that is really named so."""
    build = tmp_path / "build.sh (deleted)"
    build.write_text("echo hi")
    transport = RecordingTransport()

    _send(transport, build)

    assert len(transport.recipients) == 3


@pytest.mark.os_agnostic
def test_a_file_unlinked_right_after_its_open_is_still_judged_by_its_own_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        pytest.skip("Windows refuses to delete a file that is open")
    report = tmp_path / "report.txt"
    report.write_bytes(b"numbers")
    real_open = os.open
    unlinked: list[bool] = []

    def open_then_unlink(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = real_open(path, flags, *args, **kwargs)
        if not unlinked and _opens(path, report):
            report.unlink()
            unlinked.append(True)
        return descriptor

    monkeypatch.setattr(os, "open", open_then_unlink)  # the unlink must land between the open and the check
    transport = RecordingTransport()

    _send(transport, report, attachment_allowed_extensions={".txt"})

    assert unlinked, "positive control: the file was unlinked while open"
    assert len(transport.recipients) == 3


@pytest.mark.os_agnostic
def test_a_pipe_names_no_path() -> None:
    read_end, write_end = os.pipe()
    try:
        assert _descriptor_path.descriptor_path(read_end) is None
    finally:
        os.close(read_end)
        os.close(write_end)


@pytest.mark.os_agnostic
def test_a_closed_descriptor_names_no_path() -> None:
    read_end, write_end = os.pipe()
    os.close(read_end)
    os.close(write_end)

    assert _descriptor_path.descriptor_path(read_end) is None


@pytest.mark.os_agnostic
def test_an_allowed_directory_given_through_a_link_admits_what_lies_in_its_target(tmp_path: Path) -> None:
    """The allowlist is resolved like the attachment, so a link and its target name the same place."""
    real = tmp_path / "real"
    real.mkdir()
    report = real / "report.txt"
    report.write_text("x")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"cannot create a directory symlink here: {exc}")
    transport = RecordingTransport()

    _send(transport, report, attachment_allowed_directories=frozenset({link}))

    assert len(transport.recipients) == 3


@pytest.mark.os_agnostic
def test_a_blocked_entry_naming_the_file_itself_blocks_it(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_text("x")

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(RecordingTransport(), report, attachment_blocked_directories=frozenset({report}))

    assert caught.value.violation_type is AttachmentViolation.DIRECTORY


@pytest.mark.os_agnostic
def test_a_refusal_names_the_nearest_blocked_directory(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    report = vault / "report.txt"
    report.write_text("x")

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(RecordingTransport(), report, attachment_blocked_directories=frozenset({tmp_path, vault}))

    assert f'under blocked directory "{vault.resolve()}"' in caught.value.reason


# Sweep 9 reviewer B: each test below fails on the mutant it was written against.


@pytest.mark.os_agnostic
def test_every_recipient_gets_the_attachment_bytes_encoded_once_for_the_call(tmp_path: Path) -> None:
    """The body is encoded once per call: a file appended to after the first delivery does not change the second."""
    report = tmp_path / "report.txt"
    report.write_text("first version\n")

    def append() -> None:
        with report.open("a") as handle:
            handle.write("appended after the first delivery\n")

    transport = RecordingTransport(on_first_delivery=append)
    lib_mail.send(
        "sender@example.com",
        ["one@example.com", "two@example.com"],
        "s",
        "b",
        smtphosts=["smtp.example.com"],
        attachment_file_paths=[report],
        attachment_blocked_directories=frozenset(),
        transport=transport,
    )

    bodies = [raw.split(b"\r\n\r\n", 1)[1] for raw in transport.messages.values()]
    assert len(bodies) == 2
    assert bodies[0] == bodies[1]


def _warn_security(max_size: int | None) -> _attachments.AttachmentSecurityOptions:
    return _attachments.AttachmentSecurityOptions(
        allowed_extensions=None,
        blocked_extensions=frozenset(),
        allowed_directories=None,
        blocked_directories=frozenset(),
        max_size_bytes=max_size,
        allow_symlinks=False,
        raise_on_violation=False,
        max_count=None,
    )


@pytest.mark.os_agnostic
def test_in_warn_mode_an_attachment_read_before_the_grown_one_keeps_its_bytes(tmp_path: Path) -> None:
    """The retry re-encodes the attachments already read; each must be read from its start again."""
    steady = tmp_path / "steady.txt"
    steady.write_bytes(b"steady bytes")
    grown = tmp_path / "grown.txt"
    grown.write_bytes(b"x" * 10)
    attachments = _attachments.prepare_attachments((steady, grown), _warn_security(12), raise_on_missing=True)
    try:
        with grown.open("ab") as grow:
            grow.write(b"y" * 200_000)
        body = _compose.compose_body_once(_compose.MessageContent(plain_body="b", html_body="", attachments=attachments), raise_on_violation=False)
        raw = b"Subject: s\r\n" + body.read()
        body.close()
    finally:
        _attachments.close_attachments(attachments)

    parts = {part.get_filename(): part.get_payload(decode=True) for part in message_from_bytes(raw).walk() if part.get_filename()}
    assert parts == {"steady.txt": b"steady bytes"}


@pytest.mark.os_agnostic
def test_in_warn_mode_an_oversized_attachment_is_skipped_and_the_mail_is_sent(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The size is checked when the file is opened; warn mode must skip it there too, not raise."""
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * 100)
    small = tmp_path / "small.txt"
    small.write_bytes(b"ok")
    transport = RecordingTransport()

    with caplog.at_level(logging.WARNING, logger="btx_lib_mail"):
        assert lib_mail.send(
            "sender@example.com",
            "one@example.com",
            "s",
            "b",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[big, small],
            attachment_blocked_directories=frozenset(),
            attachment_max_size_bytes=10,
            attachment_raise_on_security_violation=False,
            transport=transport,
        )

    names = [part.get_filename() for part in message_from_bytes(transport.only.raw).walk() if part.get_filename()]
    assert names == ["small.txt"]
    assert "exceeds limit 10 bytes" in caplog.text


@pytest.mark.os_agnostic
def test_a_path_swapped_for_a_symlink_inside_the_open_is_refused_as_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """O_NOFOLLOW makes that open fail with ELOOP; it is a swap, not an unreadable file."""
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"NOT FOR MAIL")
    real_open = os.open
    swapped: list[bool] = []

    def open_after_swap(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if not swapped and os.fspath(path) in {os.fspath(report.resolve()), report.name}:
            report.unlink()
            report.symlink_to(secret)
            swapped.append(True)
        return real_open(path, flags, *args, **kwargs)

    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("this platform has no O_NOFOLLOW")
    monkeypatch.setattr(os, "open", open_after_swap)
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        lib_mail.send(
            "sender@example.com",
            "one@example.com",
            "s",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[report],
            attachment_blocked_directories=frozenset(),
            transport=transport,
        )

    assert swapped, "positive control: the swap ran inside the open"
    assert caught.value.violation_type is AttachmentViolation.CHANGED
    assert transport.deliveries == []


@pytest.mark.os_posix
def test_a_path_swapped_for_a_fifo_inside_the_open_is_refused_without_blocking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """O_NONBLOCK keeps the open of a FIFO nobody writes to from waiting for a writer forever."""
    # A guard in the body, not a skipif, so the type checker sees os.mkfifo and os.O_NONBLOCK only where they exist.
    if sys.platform == "win32":
        pytest.skip("needs mkfifo")
    make_fifo = os.mkfifo  # bound here, where the guard above narrows the platform; the nested function is checked on its own
    report = tmp_path / "report.txt"
    report.write_bytes(b"quarterly numbers")
    real_open = os.open
    swapped: list[bool] = []

    def open_after_swap(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if not swapped and os.fspath(path) in {os.fspath(report.resolve()), report.name}:
            report.unlink()
            make_fifo(report)
            swapped.append(True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_after_swap)
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            lib_mail.send(
                "sender@example.com",
                "one@example.com",
                "s",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[report],
                attachment_blocked_directories=frozenset(),
                transport=RecordingTransport(),
            )
        except BaseException as error:
            outcome.append(error)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():
        # Release the blocked open so the thread does not outlive the test.
        os.close(real_open(report, os.O_WRONLY | os.O_NONBLOCK))
        worker.join(timeout=5)
        pytest.fail("the open of a swapped-in FIFO blocked")
    assert swapped, "positive control: the swap ran inside the open"
    assert len(outcome) == 1
    assert isinstance(outcome[0], AttachmentSecurityError)
    assert outcome[0].violation_type is AttachmentViolation.CHANGED
