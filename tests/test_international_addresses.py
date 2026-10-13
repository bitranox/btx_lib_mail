"""Internationalised addresses (RFC 6531 SMTPUTF8): validation, composition, delivery, CLI.

Validation and composition are driven through the package's own functions; delivery through
`send()` with a `RecordingTransport` or a real in-process aiosmtpd server. Nothing in the package
is patched.
"""

from __future__ import annotations

import contextlib
import smtplib
from typing import IO, TYPE_CHECKING

import pytest
from aiosmtpd.controller import Controller
from smtp_test_server import BdatController, ChunkingHandler, CollectingHandler, run_server
from transport_doubles import RecordingTransport

from btx_lib_mail import DeliveryError, InvalidInputError, _compose, lib_mail, validate_email_address
from btx_lib_mail._transport import SMTPUTF8NotSupportedError
from btx_lib_mail._validation import address_length_problem, distinct_recipients, needs_smtputf8, to_nfc

if TYPE_CHECKING:
    from collections.abc import Generator

    from btx_lib_mail import DeliveryOptions

UMLAUT_LOCAL = "empfänger@example.com"
UMLAUT_DOMAIN = "user@müller.de"
DECOMPOSED_LOCAL = "empfa" + chr(0x308) + "nger@example.com"
# Indic and Thai words hold combining marks (Mc, Mn) that str.isalnum() rejects.
DEVANAGARI_BHARAT = chr(0x92D) + chr(0x93E) + chr(0x930) + chr(0x924)
THAI_SAWASDEE = chr(0xE2A) + chr(0xE27) + chr(0xE31) + chr(0xE2A) + chr(0xE14) + chr(0xE35)
BENGALI_BHARAT = chr(0x9AD) + chr(0x9BE) + chr(0x9B0) + chr(0x9A4)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "address",
    [
        UMLAUT_LOCAL,
        UMLAUT_DOMAIN,
        "ñandú@españa.es",
        "用户@例子.中国",
        "user@xn--mller-kva.de",
        "user@" + DEVANAGARI_BHARAT + ".in",
        "user@example." + DEVANAGARI_BHARAT,
        "user@" + THAI_SAWASDEE + ".th",
        "user@example." + BENGALI_BHARAT,
    ],
    ids=["umlaut-local", "umlaut-domain", "spanish", "chinese", "ace-label", "devanagari-label", "devanagari-tld", "thai-label-ending-in-mark", "bengali-tld"],
)
def test_an_internationalised_address_is_valid(address: str) -> None:
    validate_email_address(address)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "address",
    [
        "empf" + chr(0x7) + "nger@müller.de",
        "empf" + chr(0x200E) + "änger@example.com",
        "empf" + chr(0x202E) + "änger@example.com",
        "empf" + chr(0x200D) + "änger@example.com",
        "empf" + chr(0xA0) + "änger@example.com",
        "empf" + chr(0xDCFF) + "änger@example.com",
        "emp fänger@example.com",
        "@müller.de",
        "user@-müller.de",
        "user@müller-.de",
        "user@müller..de",
        "user@müller",
        "user@müller.d",
        "user@müller.d3",
        "a@b@müller.de",
        "user@" + chr(0x93E) + "abc.de",
        "user@example." + chr(0x93E) + "bc",
        "user@example." + DEVANAGARI_BHARAT + "3",
    ],
    ids=[
        "bell",
        "lrm",
        "rlo",
        "zwj",
        "nbsp",
        "surrogate",
        "space",
        "empty-local",
        "lead-hyphen",
        "trail-hyphen",
        "empty-label",
        "no-dot",
        "short-tld",
        "digit-tld",
        "two-at",
        "label-starting-with-mark",
        "tld-starting-with-mark",
        "tld-with-digit-after-mark",
    ],
)
def test_a_malformed_internationalised_address_is_refused(address: str) -> None:
    with pytest.raises(InvalidInputError, match="invalid email address"):
        validate_email_address(address)


@pytest.mark.os_agnostic
def test_a_local_part_is_measured_in_utf8_octets() -> None:
    assert address_length_problem("a" * 33 + "@example.com") is None
    assert address_length_problem("ä" * 33 + "@example.com") == "the local part has 66 UTF-8 octets, more than the 64 RFC 5321 allows"


@pytest.mark.os_agnostic
def test_an_ascii_length_message_is_unchanged() -> None:
    assert address_length_problem("a" * 65 + "@example.com") == "the local part has 65 characters, more than the 64 RFC 5321 allows"


@pytest.mark.os_agnostic
def test_a_whole_address_is_measured_in_utf8_octets() -> None:
    domain = ".".join(["ü" * 31] * 4) + ".de"  # four 62-octet labels, 3 dots, ".de": 254 octets
    address = "u@" + domain  # 2 + 254 = 256 octets

    assert address_length_problem(address) == "256 UTF-8 octets, more than the 254 RFC 5321 allows"


@pytest.mark.os_agnostic
def test_a_decomposed_recipient_is_normalised_to_nfc() -> None:
    assert distinct_recipients([DECOMPOSED_LOCAL]) == (UMLAUT_LOCAL,)


@pytest.mark.os_agnostic
def test_a_non_ascii_recipient_keeps_its_case_and_an_ascii_one_is_lower_cased() -> None:
    assert distinct_recipients(["Empfänger@Example.com", "B@Example.com"]) == ("Empfänger@Example.com", "b@example.com")


@pytest.mark.os_agnostic
def test_a_character_canonically_equal_to_an_ascii_letter_is_lower_cased_like_one() -> None:
    assert distinct_recipients([chr(0x212A) + "elvin@example.com"]) == ("kelvin@example.com",)


@pytest.mark.os_agnostic
def test_to_nfc_leaves_an_ascii_address_alone() -> None:
    assert to_nfc("User@Example.com") == "User@Example.com"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("sender", "recipient", "expected"),
    [
        ("a@example.com", "b@example.com", False),
        ("a@example.com", UMLAUT_LOCAL, True),
        (UMLAUT_DOMAIN, "b@example.com", True),
        (UMLAUT_DOMAIN, UMLAUT_LOCAL, True),
    ],
)
def test_smtputf8_is_needed_exactly_when_an_address_holds_non_ascii(sender: str, recipient: str, expected: bool) -> None:
    assert needs_smtputf8(sender, recipient) is expected


@pytest.mark.os_agnostic
def test_an_ascii_envelope_folds_exactly_as_before() -> None:
    [block] = _compose.envelope_header_lines(sender="absender@example.com", subject="Hallo", recipients=["empfaenger@example.com"])

    assert block.startswith(b"Subject: Hallo\r\nFrom: absender@example.com\r\nTo: empfaenger@example.com\r\nDate: ")
    assert block.isascii()


@pytest.mark.os_agnostic
def test_a_non_ascii_recipient_gets_a_raw_utf8_to_header() -> None:
    [block] = _compose.envelope_header_lines(sender="absender@example.com", subject="Hallo", recipients=[UMLAUT_LOCAL])

    assert b"\r\nTo: " + UMLAUT_LOCAL.encode() + b"\r\n" in block
    assert b"\r\nFrom: absender@example.com\r\n" in block


@pytest.mark.os_agnostic
def test_a_non_ascii_sender_gets_a_raw_utf8_from_header_in_every_block() -> None:
    blocks = _compose.envelope_header_lines(sender=UMLAUT_DOMAIN, subject="Hallo", recipients=["a@example.com", "b@example.com"])

    assert all(b"\r\nFrom: " + UMLAUT_DOMAIN.encode() + b"\r\n" in block for block in blocks)


@pytest.mark.os_agnostic
def test_the_subject_and_from_lines_are_the_same_for_ascii_and_utf8_recipients() -> None:
    subject = "Quartalsbericht für Müller & Söhne " * 6
    ascii_block, utf8_block = _compose.envelope_header_lines(sender="absender@example.com", subject=subject, recipients=["a@example.com", UMLAUT_LOCAL])

    assert ascii_block.split(b"To: ")[0] == utf8_block.split(b"To: ")[0]


@contextlib.contextmanager
def _relay(*, smtputf8: bool, chunking: bool = False) -> Generator[tuple[str, CollectingHandler]]:
    """Run an in-process relay that does or does not offer SMTPUTF8; yield its host and handler."""
    handler: CollectingHandler = ChunkingHandler() if chunking else CollectingHandler()
    controller = run_server(handler, controller_cls=BdatController if chunking else Controller, enable_SMTPUTF8=smtputf8)
    try:
        yield f"127.0.0.1:{controller.port}", handler
    finally:
        controller.stop()


def _send_via(hosts: list[str], *, sender: str = "absender@example.com", recipients: str | list[str] = UMLAUT_LOCAL) -> bool:
    return lib_mail.send(
        mail_from=sender,
        mail_recipients=recipients,
        mail_subject="Grüße",
        mail_body="Hallo",
        smtphosts=hosts,
        use_starttls=False,
        local_hostname="client.example.com",
    )


@pytest.mark.os_agnostic
@pytest.mark.parametrize("chunking", [False, True], ids=["DATA", "BDAT"])
def test_a_non_ascii_recipient_travels_as_smtputf8(chunking: bool) -> None:
    with _relay(smtputf8=True, chunking=chunking) as (host, handler):
        assert _send_via([host]) is True

    assert handler.rcpts == [UMLAUT_LOCAL]
    assert [option.upper() for option in handler.mail_options[0]] == ["SMTPUTF8", "BODY=8BITMIME"]
    assert b"\r\nTo: " + UMLAUT_LOCAL.encode() + b"\r\n" in handler.messages[0]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("chunking", [False, True], ids=["DATA", "BDAT"])
def test_a_non_ascii_sender_travels_as_smtputf8(chunking: bool) -> None:
    with _relay(smtputf8=True, chunking=chunking) as (host, handler):
        assert _send_via([host], sender=UMLAUT_DOMAIN, recipients="b@example.com") is True

    assert handler.senders == [UMLAUT_DOMAIN]
    assert b"\r\nFrom: " + UMLAUT_DOMAIN.encode() + b"\r\n" in handler.messages[0]


@pytest.mark.os_agnostic
def test_ascii_mail_sends_no_mail_parameter_even_where_smtputf8_is_offered() -> None:
    with _relay(smtputf8=True) as (host, handler):
        assert _send_via([host], recipients="b@example.com") is True

    assert handler.mail_options == [[]]


@pytest.mark.os_agnostic
def test_a_relay_without_smtputf8_fails_over_to_one_with_it() -> None:
    with _relay(smtputf8=False) as (old_host, old_handler), _relay(smtputf8=True) as (new_host, new_handler):
        assert _send_via([old_host, new_host]) is True

    assert old_handler.rcpts == []
    assert new_handler.rcpts == [UMLAUT_LOCAL]


@pytest.mark.os_agnostic
def test_with_no_relay_offering_smtputf8_the_umlaut_recipient_fails_and_an_ascii_one_is_delivered() -> None:
    with _relay(smtputf8=False) as (host, handler), pytest.raises(DeliveryError) as raised:
        _send_via([host], recipients=[UMLAUT_LOCAL, "b@example.com"])

    assert raised.value.failed_recipients == (UMLAUT_LOCAL,)
    assert handler.rcpts == ["b@example.com"]


@pytest.mark.os_agnostic
def test_a_relay_without_smtputf8_stays_first_for_the_ascii_recipients_after_it() -> None:
    transport_hosts: list[str] = []

    class _OldFirstRelay(RecordingTransport):
        def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
            transport_hosts.append(host)
            if host == "old.example.com" and not recipient.isascii():
                raise SMTPUTF8NotSupportedError("the relay does not offer SMTPUTF8, which a non-ASCII address needs")
            super().deliver(host=host, sender=sender, recipient=recipient, message=message, delivery=delivery)

    lib_mail.send(
        "absender@example.com",
        [UMLAUT_LOCAL, "b@example.com"],
        "s",
        smtphosts=["old.example.com", "new.example.com"],
        transport=_OldFirstRelay(),
    )

    assert transport_hosts == ["old.example.com", "new.example.com", "old.example.com"]


@pytest.mark.os_agnostic
def test_the_smtputf8_refusal_is_still_an_smtp_not_supported_error() -> None:
    assert issubclass(SMTPUTF8NotSupportedError, smtplib.SMTPNotSupportedError)
