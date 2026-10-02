"""Upper bounds on one send() call: address length, recipient count and attachment count.

Every refusal happens before the first delivery and names the limit, never the oversized value.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from log_capture import everything_logged
from transport_doubles import RecordingTransport

from btx_lib_mail import ConfigurationError, ConfMail, InvalidInputError, send, validate_email_address
from btx_lib_mail.cli import CliContext, cli

if TYPE_CHECKING:
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
