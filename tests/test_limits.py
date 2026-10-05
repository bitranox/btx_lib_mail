"""Upper bounds on one send() call: address length, recipient count and attachment count.

Every refusal happens before the first delivery and names the limit, never the oversized value.
"""

from __future__ import annotations

import pickle
import time
from typing import TYPE_CHECKING, Any

import pytest
from log_capture import everything_logged
from transport_doubles import RecordingTransport

from btx_lib_mail import (
    AttachmentNotFoundError,
    AttachmentSecurityError,
    AttachmentViolation,
    ConfigurationError,
    ConfMail,
    InvalidInputError,
    send,
    validate_email_address,
)
from btx_lib_mail.cli import CliContext, cli

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from click.testing import CliRunner

# RFC 5321 section 4.5.3.1: a local part holds at most 64 octets and a path at most 256,
# which leaves 254 for the address between the angle brackets.
_DOMAIN_189 = ".".join(["b" * 61] * 3) + ".com"
_ADDRESS_254 = "a" * 64 + "@" + _DOMAIN_189


def _send(transport: RecordingTransport, **overrides: Any) -> bool:
    arguments: dict[str, Any] = {
        "mail_from": "sender@example.com",
        "mail_recipients": ["one@example.com"],
        "mail_subject": "Report",
        "smtphosts": ["smtp.example.com"],
        "transport": transport,
    }
    arguments.update(overrides)
    return send(**arguments)


# ---------------------------------------------------------------------------
# Address length (a protocol limit, not a setting)
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_an_address_at_both_rfc_5321_limits_is_accepted() -> None:
    assert len(_ADDRESS_254) == 254

    validate_email_address(_ADDRESS_254)


@pytest.mark.os_agnostic
def test_a_local_part_longer_than_64_characters_is_refused_without_echoing_it() -> None:
    address = "a" * 65 + "@example.com"

    with pytest.raises(InvalidInputError) as caught:
        validate_email_address(address)

    assert str(caught.value) == "invalid email address: the local part has 65 characters, more than the 64 RFC 5321 allows"


@pytest.mark.os_agnostic
def test_an_address_longer_than_254_characters_is_refused_without_echoing_it() -> None:
    address = _ADDRESS_254 + "m"

    with pytest.raises(InvalidInputError) as caught:
        validate_email_address(address)

    assert str(caught.value) == "invalid email address: 255 characters, more than the 254 RFC 5321 allows"


@pytest.mark.os_agnostic
def test_an_overlong_sender_is_refused_before_any_delivery() -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError) as caught:
        _send(transport, mail_from="a" * 1_000_000 + "@example.com")

    assert str(caught.value) == "invalid sender address: the local part has 1000000 characters, more than the 64 RFC 5321 allows"
    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_an_overlong_recipient_is_refused_without_echoing_it() -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError) as caught:
        _send(transport, mail_recipients=["ok@example.com", "a" * 70 + "@example.com"])

    assert str(caught.value) == "invalid recipient: the local part has 70 characters, more than the 64 RFC 5321 allows"
    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_an_overlong_recipient_in_warn_mode_is_skipped_and_logged_without_its_text(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING", logger="btx_lib_mail")
    transport = RecordingTransport()
    overlong = "z" * 70 + "@example.com"

    assert _send(transport, mail_recipients=["ok@example.com", overlong], raise_on_invalid_recipient=False) is True

    assert transport.recipients == ["ok@example.com"]
    logged = everything_logged(caplog)
    assert "the local part has 70 characters" in logged, "positive control: the skip was logged"
    assert overlong not in logged, "neither the message nor an extra field carries the whole address"


# ---------------------------------------------------------------------------
# Recipient count
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_more_recipients_than_the_ceiling_are_refused_before_any_delivery() -> None:
    transport = RecordingTransport()
    recipients = ["one@example.com", "two@example.com", "three@example.com"]

    with pytest.raises(InvalidInputError) as caught:
        _send(transport, mail_recipients=recipients, config=ConfMail(recipient_max_count=2))

    assert str(caught.value) == "3 recipients, more than recipient_max_count (2)"
    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_the_recipient_ceiling_counts_each_address_once() -> None:
    transport = RecordingTransport()
    recipients = ["one@example.com", "ONE@example.com", "two@example.com"]

    assert _send(transport, mail_recipients=recipients, config=ConfMail(recipient_max_count=2)) is True

    assert transport.recipients == ["one@example.com", "two@example.com"]


@pytest.mark.os_agnostic
def test_the_recipient_ceiling_counts_entries_before_any_is_validated() -> None:
    # Invalid entries count too, so an oversized list is refused without a regex run per entry,
    # even in warn mode, where the invalid ones would otherwise be skipped.
    transport = RecordingTransport()
    recipients = ["ok@example.com", "bad@", "worse@"]

    with pytest.raises(InvalidInputError, match=r"^3 recipients, more than recipient_max_count \(2\)$"):
        _send(transport, mail_recipients=recipients, raise_on_invalid_recipient=False, config=ConfMail(recipient_max_count=2))

    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_no_recipient_ceiling_delivers_every_recipient() -> None:
    transport = RecordingTransport()
    recipients = [f"r{index}@example.com" for index in range(1_001)]

    assert _send(transport, mail_recipients=recipients, config=ConfMail(recipient_max_count=None)) is True

    assert len(transport.recipients) == 1_001


@pytest.mark.os_agnostic
def test_the_default_recipient_ceiling_is_one_thousand() -> None:
    transport = RecordingTransport()
    recipients = [f"r{index}@example.com" for index in range(1_001)]

    assert ConfMail().recipient_max_count == 1_000
    with pytest.raises(InvalidInputError, match=r"^1001 recipients, more than recipient_max_count \(1000\)$"):
        _send(transport, mail_recipients=recipients, config=ConfMail())
    assert transport.recipients == []


# ---------------------------------------------------------------------------
# Attachment count
# ---------------------------------------------------------------------------


def _attachments(directory: Path, count: int) -> list[Path]:
    paths = [directory / f"part{index}.txt" for index in range(count)]
    for path in paths:
        path.write_bytes(b"x")
    return paths


@pytest.mark.os_agnostic
def test_more_attachments_than_the_ceiling_are_refused_before_any_is_opened(tmp_path: Path) -> None:
    transport = RecordingTransport()
    present = _attachments(tmp_path, 2)
    # A third path that does not exist: a refusal by count must come before any file check.
    paths = [*present, tmp_path / "missing.txt"]

    with pytest.raises(InvalidInputError) as caught:
        _send(transport, attachment_file_paths=paths, attachment_blocked_directories=frozenset(), config=ConfMail(attachment_max_count=2))

    assert str(caught.value) == "3 attachments, more than attachment_max_count (2)"
    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_attachments_up_to_the_ceiling_are_sent(tmp_path: Path) -> None:
    transport = RecordingTransport()

    config = ConfMail(attachment_max_count=2)
    assert _send(transport, attachment_file_paths=_attachments(tmp_path, 2), attachment_blocked_directories=frozenset(), config=config) is True

    assert transport.recipients == ["one@example.com"]


class _ReadTooFarError(Exception):
    """Raised by a generator read past the point the code under test should have stopped."""


def _endless(item: object, *, stop_after: int) -> Iterator[object]:
    """Yield item for ever, as far as the caller is concerned; past stop_after reads, fail the test.

    A regression reads the whole iterable, and an endless one would exhaust memory before the
    test could fail; this one fails fast instead, naming why.
    """
    for _ in range(stop_after):
        yield item
    raise _ReadTooFarError(f"read more than {stop_after} entries of an endless iterable")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("lazy", ["range", "generator"])
def test_a_lazy_host_iterable_is_refused_before_it_is_read(lazy: str) -> None:
    """A lazy iterable was read whole before any check, so an endless one ran out of memory."""
    hosts = range(3) if lazy == "range" else _endless("smtp.example.com", stop_after=50)
    with pytest.raises(InvalidInputError, match=r"^smtphosts must be a string, list of strings, or tuple of strings$"):
        _send(RecordingTransport(), smtphosts=hosts)


@pytest.mark.os_agnostic
def test_an_endless_attachment_generator_is_refused_at_the_ceiling(tmp_path: Path) -> None:
    """Read only one past attachment_max_count, so an endless generator is refused rather than exhausting memory."""
    report = tmp_path / "report.txt"
    report.write_text("hello")

    with pytest.raises(InvalidInputError, match=r"^attachment_file_paths yields more than attachment_max_count \(3\) paths$"):
        _send(
            RecordingTransport(),
            # Exactly one past the ceiling may be read; a second read past it fails the test by name.
            attachment_file_paths=_endless(report, stop_after=4),
            attachment_blocked_directories=frozenset(),
            config=ConfMail(attachment_max_count=3),
        )


@pytest.mark.os_agnostic
def test_an_attachment_generator_within_the_ceiling_is_sent(tmp_path: Path) -> None:
    """A generator such as Path.glob() stays accepted, and send()'s annotation admits it: no list() needed under pyright strict."""
    for name in ("a.txt", "b.txt"):
        (tmp_path / name).write_text(name)
    transport = RecordingTransport()

    assert send(
        "sender@example.com",
        ["one@example.com"],
        "Report",
        smtphosts=["smtp.example.com"],
        attachment_file_paths=tmp_path.glob("*.txt"),
        attachment_blocked_directories=frozenset(),
        config=ConfMail(attachment_max_count=2),
        transport=transport,
    )
    assert len(transport.recipients) == 1


@pytest.mark.os_agnostic
def test_the_default_attachment_ceiling_refuses_the_hundred_and_first(tmp_path: Path) -> None:
    transport = RecordingTransport()
    # The count is checked before any path, so the files need not exist.
    paths = [tmp_path / f"part{index}.txt" for index in range(101)]

    with pytest.raises(InvalidInputError, match=r"^101 attachments, more than attachment_max_count \(100\)$"):
        _send(transport, attachment_file_paths=paths, config=ConfMail())
    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_no_attachment_ceiling_sends_every_attachment(tmp_path: Path) -> None:
    transport = RecordingTransport()
    config = ConfMail(attachment_max_count=None)

    assert _send(transport, attachment_file_paths=_attachments(tmp_path, 101), attachment_blocked_directories=frozenset(), config=config) is True

    assert transport.recipients == ["one@example.com"]


# ---------------------------------------------------------------------------
# Cost per recipient
# ---------------------------------------------------------------------------


def _fastest_send_seconds(recipient_count: int, subject: str) -> float:
    recipients = [f"r{index}@example.com" for index in range(recipient_count)]
    timings: list[float] = []
    for _ in range(3):
        started = time.perf_counter()
        _send(RecordingTransport(), mail_recipients=recipients, mail_subject=subject)
        timings.append(time.perf_counter() - started)
    return min(timings)


@pytest.mark.os_agnostic
def test_a_long_subject_is_folded_once_per_call_not_once_per_recipient() -> None:
    # Folding a 4096-character non-ASCII subject costs tens of milliseconds; done per
    # recipient, a thousand recipients spent over a minute before the first delivery.
    subject = "\U0001f600 " * 2048
    _fastest_send_seconds(1, subject)  # warm the email package's caches

    one = _fastest_send_seconds(1, subject)
    many = _fastest_send_seconds(41, subject)

    assert many < one * 8, f"41 recipients took {many:.3f}s against {one:.3f}s for one: the subject is folded per recipient"


# ---------------------------------------------------------------------------
# Configuration and the CLI
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("field", ["recipient_max_count", "attachment_max_count"])
@pytest.mark.parametrize("value", [0, -1])
def test_a_non_positive_ceiling_is_refused(field: str, value: int) -> None:
    with pytest.raises(ConfigurationError, match=f"{field} must be positive, got {value}"):
        ConfMail.model_validate({field: value})


_CLI_ROUTE = ["send", "--host", "smtp.example.com", "--sender", "sender@example.com", "--subject", "S", "--body", "B"]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("source", ["option", "environment"])
def test_the_cli_reads_the_recipient_ceiling(cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch, source: str) -> None:
    args = [*_CLI_ROUTE, "--recipient", "one@example.com", "--recipient", "two@example.com"]
    if source == "option":
        args += ["--recipient-max-count", "1"]
    else:
        monkeypatch.setenv("BTX_MAIL_RECIPIENT_MAX_COUNT", "1")
    transport = RecordingTransport()

    result = cli_runner.invoke(cli, args, obj=CliContext(transport=transport))

    assert type(result.exception) is InvalidInputError
    assert str(result.exception) == "2 recipients, more than recipient_max_count (1)"
    assert transport.recipients == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize("source", ["option", "environment"])
def test_the_cli_reads_the_attachment_ceiling(cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, source: str) -> None:
    first, second = _attachments(tmp_path, 2)
    # The POSIX default blocks /var, which holds the temp dir on macOS.
    args = [*_CLI_ROUTE, "--recipient", "one@example.com", "--attachment", str(first), "--attachment", str(second)]
    args += ["--attachment-blocked-dir", str(tmp_path / "nothing-blocked-here")]
    if source == "option":
        args += ["--attachment-max-count", "1"]
    else:
        monkeypatch.setenv("BTX_MAIL_ATTACHMENT_MAX_COUNT", "1")
    transport = RecordingTransport()

    result = cli_runner.invoke(cli, args, obj=CliContext(transport=transport))

    assert type(result.exception) is InvalidInputError
    assert str(result.exception) == "2 attachments, more than attachment_max_count (1)"
    assert transport.recipients == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("option", "value"), [("--recipient-max-count", "0"), ("--attachment-max-count", "-1")])
def test_the_cli_refuses_a_non_positive_ceiling(cli_runner: CliRunner, option: str, value: str) -> None:
    transport = RecordingTransport()
    field = option.removeprefix("--").replace("-", "_")

    result = cli_runner.invoke(cli, [*_CLI_ROUTE, "--recipient", "one@example.com", option, value], obj=CliContext(transport=transport))

    assert type(result.exception) is InvalidInputError
    assert f"{field} must be positive, got {value}" in str(result.exception)
    assert transport.recipients == []


@pytest.mark.os_agnostic
def test_the_cli_sends_within_both_ceilings(cli_runner: CliRunner, tmp_path: Path) -> None:
    (only,) = _attachments(tmp_path, 1)
    args = [*_CLI_ROUTE, "--recipient", "one@example.com", "--attachment", str(only)]
    args += ["--attachment-blocked-dir", str(tmp_path / "nothing-blocked-here"), "--recipient-max-count", "1", "--attachment-max-count", "1"]
    transport = RecordingTransport()

    result = cli_runner.invoke(cli, args, obj=CliContext(transport=transport))

    assert result.exit_code == 0, result.output
    assert transport.recipients == ["one@example.com"]


# A path no file can have (Linux's PATH_MAX is 4096) was quoted whole: a megabyte of path made a megabyte of message.
_OVERLONG_NAME = "a" * 1_000_000


@pytest.mark.os_agnostic
def test_an_overlong_attachment_path_is_quoted_by_its_start_and_length(tmp_path: Path) -> None:
    long_path = tmp_path / f"{_OVERLONG_NAME}.txt"

    with pytest.raises(AttachmentNotFoundError) as raised:
        _send(RecordingTransport(), attachment_file_paths=[long_path], attachment_blocked_directories=frozenset())

    message = str(raised.value)
    assert len(message) < 4096
    assert f"... ({len(str(long_path))} characters)" in message
    assert message.endswith("can not be read (ENAMETOOLONG)")  # the same on Windows, whose lstat raised a bare ValueError


@pytest.mark.os_agnostic
def test_an_overlong_attachment_path_is_logged_by_its_start_and_length(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    long_path = tmp_path / f"{_OVERLONG_NAME}.txt"

    _send(
        RecordingTransport(),
        attachment_file_paths=[long_path],
        attachment_blocked_directories=frozenset(),
        config=ConfMail(raise_on_missing_attachments=False),
    )

    logged = everything_logged(caplog)
    assert f"... ({len(str(long_path))} characters)" in logged
    assert len(logged) < 16384


@pytest.mark.os_agnostic
def test_a_security_refusal_quotes_an_overlong_path_by_its_start_and_length_and_pickles_unchanged(tmp_path: Path) -> None:
    long_path = tmp_path / f"{_OVERLONG_NAME}.exe"
    error = AttachmentSecurityError(long_path, f'extension ".exe" is blocked: "{long_path}"', AttachmentViolation.EXTENSION)

    assert len(str(error)) < 2 * 4096
    assert str(error).count(f"... ({len(str(long_path))} characters)") == 1  # [path=...]; the reason is cut by its own length
    assert str(pickle.loads(pickle.dumps(error))) == str(error)  # noqa: S301 - round-trips an object this test just built


@pytest.mark.os_agnostic
def test_a_warn_mode_violation_logs_an_overlong_path_by_its_start_and_length(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The violation log's attachment_path field is bounded like the message; a traversal is refused before any file system call."""
    long_path = f"{tmp_path}/../{'a' * 30_000}.txt"  # over the quote limit, so the path is cut, and refused as a traversal

    _send(
        RecordingTransport(),
        attachment_file_paths=[long_path],
        attachment_blocked_directories=frozenset(),
        config=ConfMail(attachment_raise_on_security_violation=False),
    )

    logged = everything_logged(caplog)
    assert "traversal" in logged, "positive control: the violation was logged"
    assert len(logged) < 16384


@pytest.mark.os_agnostic
def test_an_overlong_path_has_its_start_cleaned_of_control_characters(tmp_path: Path) -> None:
    """A long path is quoted by its first characters; those are cleaned like a short path, so no line can be forged."""
    long_path = tmp_path / f"report\nWARNING forged{_OVERLONG_NAME}.txt"

    with pytest.raises(AttachmentNotFoundError) as raised:
        _send(RecordingTransport(), attachment_file_paths=[long_path], attachment_blocked_directories=frozenset())

    assert "... (" in str(raised.value), "positive control: the path was quoted by its start"
    assert "\n" not in str(raised.value)
