"""Every failure btx_lib_mail raises shares BtxMailError and keeps its builtin base."""

from __future__ import annotations

import pickle
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError
from transport_doubles import RecordingTransport, RefusingTransport

import btx_lib_mail
from btx_lib_mail import (
    AttachmentNotFoundError,
    AttachmentSecurityError,
    BtxMailError,
    ConfigurationError,
    ConfMail,
    DeliveryError,
    InvalidInputError,
    send,
    validate_email_address,
    validate_smtp_host,
)

if TYPE_CHECKING:
    from pathlib import Path


def _send(**overrides: Any) -> bool:
    arguments: dict[str, Any] = {
        "mail_from": "sender@example.com",
        "mail_recipients": "recipient@example.com",
        "mail_subject": "Subject",
        "smtphosts": ["smtp.example.com"],
        "transport": RecordingTransport(),
    }
    arguments.update(overrides)
    return send(**arguments)


@pytest.mark.os_agnostic
def test_the_error_types_are_exported_from_the_package() -> None:
    for name in ("BtxMailError", "InvalidInputError", "ConfigurationError", "AttachmentNotFoundError", "DeliveryError"):
        assert name in btx_lib_mail.__all__


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "overrides",
    [
        {"mail_from": "not-an-address"},
        {"mail_recipients": "not-an-address"},
        {"smtphosts": [" "]},
        {"local_hostname": "bad name"},
        {"timeout": -1.0},
    ],
    ids=["sender", "recipient", "no-host", "ehlo-name", "timeout"],
)
def test_a_refused_send_argument_is_an_invalid_input_error_and_a_value_error(overrides: dict[str, Any]) -> None:
    with pytest.raises(InvalidInputError) as caught:
        _send(**overrides)

    assert isinstance(caught.value, BtxMailError)
    assert isinstance(caught.value, ValueError)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("validator", "value"),
    [(validate_email_address, "invalid@"), (validate_smtp_host, "smtp.example.com:abc")],
    ids=["email", "host"],
)
def test_the_public_validators_raise_invalid_input_error(validator: Any, value: str) -> None:
    with pytest.raises(InvalidInputError):
        validator(value)


@pytest.mark.os_agnostic
def test_a_missing_attachment_is_an_attachment_not_found_error_and_a_file_not_found_error(tmp_path: Path) -> None:
    with pytest.raises(AttachmentNotFoundError) as caught:
        # The temporary directory is under /private/var on macOS, a blocked directory by default.
        _send(attachment_file_paths=[tmp_path / "missing.txt"], attachment_blocked_directories=frozenset())

    assert isinstance(caught.value, BtxMailError)
    assert isinstance(caught.value, FileNotFoundError)
    assert "can not be found" in str(caught.value)


@pytest.mark.os_agnostic
def test_an_attachment_security_error_is_a_btx_mail_error(tmp_path: Path) -> None:
    script = tmp_path / "run.sh"
    script.write_text("echo hi")

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(attachment_file_paths=[script], attachment_blocked_directories=frozenset())

    assert isinstance(caught.value, BtxMailError)


@pytest.mark.os_agnostic
def test_a_failed_delivery_is_a_delivery_error_naming_recipients_and_hosts() -> None:
    with pytest.raises(DeliveryError) as caught:
        _send(mail_recipients=["a@example.com", "b@example.com"], smtphosts=["one.example.com", "two.example.com"], transport=RefusingTransport())

    error = caught.value
    assert isinstance(error, BtxMailError)
    assert isinstance(error, RuntimeError)
    assert error.failed_recipients == ("a@example.com", "b@example.com")
    assert error.hosts == ("one.example.com", "two.example.com")
    assert (
        str(error)
        == "following recipients failed \"['a@example.com', 'b@example.com']\" on all of following hosts : \"('one.example.com', 'two.example.com')\""
    )


@pytest.mark.os_agnostic
def test_a_delivery_error_survives_pickling() -> None:
    error = DeliveryError("text", failed_recipients=("a@example.com",), hosts=("h",))

    restored = pickle.loads(pickle.dumps(error))  # noqa: S301 - round-trips an object this test just built

    assert str(restored) == "text"
    assert restored.failed_recipients == ("a@example.com",)
    assert restored.hosts == ("h",)


def _construct() -> None:
    ConfMail(smtp_timeout=-1)


def _validate() -> None:
    ConfMail.model_validate({"smtp_timeout": -1})


def _validate_json() -> None:
    ConfMail.model_validate_json('{"smtp_timeout": -1}')


def _validate_strings() -> None:
    ConfMail.model_validate_strings({"smtp_timeout": "-1"})


def _assign() -> None:
    ConfMail().smtp_timeout = -1


def _unknown_key() -> None:
    ConfMail.model_validate({"use_starttls": False})


@pytest.mark.os_agnostic
@pytest.mark.parametrize("entry", [_construct, _validate, _validate_json, _validate_strings, _assign, _unknown_key])
def test_a_refused_conf_mail_setting_is_a_configuration_error_and_a_validation_error(entry: Any) -> None:
    with pytest.raises(ConfigurationError) as caught:
        entry()

    assert isinstance(caught.value, ValidationError)
    assert isinstance(caught.value, BtxMailError)
    assert caught.value.title == "ConfMail"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("entry", [_construct, _validate, _validate_json, _validate_strings, _assign, _unknown_key])
def test_a_configuration_error_names_the_setting_but_not_the_pydantic_version(entry: Any) -> None:
    with pytest.raises(ConfigurationError) as caught:
        entry()

    for rendered in (str(caught.value), repr(caught.value)):
        assert "validation error for ConfMail" in rendered, "positive control: pydantic's report is kept"
        assert "errors.pydantic.dev" not in rendered
        assert "For further information" not in rendered


@pytest.mark.os_agnostic
def test_a_configuration_error_keeps_the_password_hidden() -> None:
    with pytest.raises(ConfigurationError) as caught:
        ConfMail(smtp_password=1.5, smtp_timeout=-1)  # pyright: ignore[reportArgumentType]

    assert "1.5" not in str(caught.value)
    assert caught.value.__context__ is None
