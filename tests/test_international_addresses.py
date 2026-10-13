"""Internationalised addresses (RFC 6531 SMTPUTF8): validation, composition, delivery, CLI.

Validation and composition are driven through the package's own functions; delivery through
`send()` with a `RecordingTransport` or a real in-process aiosmtpd server. Nothing in the package
is patched.
"""

from __future__ import annotations

import pytest

from btx_lib_mail import InvalidInputError, validate_email_address
from btx_lib_mail._validation import address_length_problem, distinct_recipients, needs_smtputf8, to_nfc

UMLAUT_LOCAL = "empfänger@example.com"
UMLAUT_DOMAIN = "user@müller.de"
DECOMPOSED_LOCAL = "empfa" + chr(0x308) + "nger@example.com"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("address", [UMLAUT_LOCAL, UMLAUT_DOMAIN, "ñandú@españa.es", "用户@例子.中国", "user@xn--mller-kva.de"])
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
