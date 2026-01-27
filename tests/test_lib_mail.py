from __future__ import annotations

import os
from pathlib import Path
from email import message_from_string
from email.message import EmailMessage
from email.policy import default as default_policy
from typing import Any, Generator, cast

import pytest
from pydantic import ValidationError

from btx_lib_mail import ConfMail
from btx_lib_mail import lib_mail


_DOTENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def _dotenv_value(key: str) -> str | None:
    if not _DOTENV_PATH.is_file():
        return None
    for line in _DOTENV_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        candidate_key, candidate_value = stripped.split("=", 1)
        if candidate_key.strip() != key:
            continue
        value = candidate_value.strip().strip('"').strip("'")
        return value
    return None


def _configured_value(key: str) -> str | None:
    return os.getenv(key) or _dotenv_value(key)


@pytest.fixture(autouse=True)
def _reset_conf_mail() -> Generator[None, None, None]:  # pyright: ignore[reportUnusedFunction]
    snapshot = lib_mail.conf.model_copy(deep=True)
    try:
        yield
    finally:
        for key, value in snapshot.model_dump().items():
            setattr(lib_mail.conf, key, value)


def test_conf_mail_accepts_single_host() -> None:
    config = ConfMail.model_validate({"smtphosts": "smtp.example.com"})
    assert config.smtphosts == ["smtp.example.com"]


def test_conf_mail_accepts_iterable_hosts() -> None:
    hosts = ("smtp1.example.com", "smtp2.example.com")
    config = ConfMail.model_validate({"smtphosts": hosts})
    assert config.smtphosts == list(hosts)


def test_conf_mail_assignment_validates() -> None:
    config = ConfMail()
    cast(Any, config).smtphosts = "smtp.example.com"
    assert config.smtphosts == ["smtp.example.com"]


def test_conf_mail_rejects_non_string_entries() -> None:
    with pytest.raises(ValidationError):
        ConfMail.model_validate({"smtphosts": [1]})  # type: ignore[list-item]

    config = ConfMail()
    with pytest.raises(ValidationError):
        cast(Any, config).smtphosts = [1]  # type: ignore[list-item]


def test_conf_mail_resolves_credentials() -> None:
    config = ConfMail(smtp_username="user", smtp_password="pass")
    assert config.resolved_credentials() == ("user", "pass")

    config = ConfMail()
    assert config.resolved_credentials() is None


@pytest.mark.os_agnostic
def test_when_conf_receives_none_for_hosts_it_sets_an_empty_list() -> None:
    config = ConfMail.model_validate({"smtphosts": None})

    assert config.smtphosts == []


@pytest.mark.os_agnostic
def test_when_conf_receives_an_illegal_host_type_it_objects() -> None:
    with pytest.raises(ValidationError, match="smtphosts must be a string"):
        ConfMail.model_validate({"smtphosts": 123})


class RecordingSMTP:
    created: list["RecordingSMTP"] = []
    init_calls: list[tuple[str, int | None, float | None]] = []
    fail_on_send: set[str] = set()
    fail_on_init: set[str] = set()
    send_attempts: list[str] = []

    def __init__(self, host: str, *, port: int | None = None, timeout: float | None = None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.logged_in: tuple[str, str] | None = None
        self.sent_messages: list[tuple[str, str, str]] = []
        self.closed = False
        RecordingSMTP.init_calls.append((host, port, timeout))
        if host in RecordingSMTP.fail_on_init:
            raise ConnectionError("initialisation failed")

    def __enter__(self) -> "RecordingSMTP":
        RecordingSMTP.created.append(self)
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.closed = True

    def starttls(self, *, context: Any) -> None:  # noqa: ANN401 - test helper
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        self.logged_in = (username, password)

    def sendmail(self, from_addr: str, to_addr: str, message: str) -> None:
        RecordingSMTP.send_attempts.append(self.host)
        if self.host in RecordingSMTP.fail_on_send:
            raise RuntimeError("boom")
        self.sent_messages.append((from_addr, to_addr, message))

    @classmethod
    def reset(cls) -> None:
        cls.created = []
        cls.init_calls = []
        cls.fail_on_send = set()
        cls.fail_on_init = set()
        cls.send_attempts = []


def _install_recording_smtp(monkeypatch: pytest.MonkeyPatch) -> type[RecordingSMTP]:
    RecordingSMTP.reset()
    monkeypatch.setattr(lib_mail.smtplib, "SMTP", RecordingSMTP)
    return RecordingSMTP


@pytest.mark.os_agnostic
def test_when_an_attachment_is_missing_strict_mode_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError, match="Attachment File"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[missing],
        )


@pytest.mark.os_agnostic
def test_when_missing_attachments_are_allowed_a_warning_is_logged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    recorder = _install_recording_smtp(monkeypatch)
    caplog.set_level("WARNING")
    ghost = tmp_path / "ghost.txt"

    lib_mail.conf.raise_on_missing_attachments = False

    result = lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["smtp.example.com"],
        attachment_file_paths=[ghost],
    )

    assert result is True
    assert "Attachment File" in caplog.text
    assert recorder.created[0].sent_messages[0][2]


@pytest.mark.os_agnostic
def test_when_all_hosts_are_blank_the_send_call_refuses() -> None:
    with pytest.raises(ValueError, match="no valid smtphost passed"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["   "],
        )


@pytest.mark.os_agnostic
def test_when_an_invalid_recipient_is_spotted_strict_mode_raises() -> None:
    with pytest.raises(ValueError, match="invalid recipient"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="invalid@",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
        )


@pytest.mark.os_agnostic
def test_when_invalid_recipients_are_tolerated_a_warning_is_emitted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    recorder = _install_recording_smtp(monkeypatch)
    caplog.set_level("WARNING")
    lib_mail.conf.raise_on_invalid_recipient = False

    result = lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients=["invalid@", "valid@example.com"],
        mail_subject="Subject",
        smtphosts=["smtp.example.com"],
    )

    assert result is True
    assert "invalid recipient invalid@" in caplog.text
    assert recorder.created[0].sent_messages[0][1] == "valid@example.com"


@pytest.mark.os_agnostic
def test_when_every_recipient_is_invalid_the_call_still_fails() -> None:
    lib_mail.conf.raise_on_invalid_recipient = False

    with pytest.raises(ValueError, match="no valid recipients"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients=["invalid@"],
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
        )


def test_send_handles_utf8_and_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    _install_recording_smtp(monkeypatch)
    attachment = tmp_path / "document.txt"
    attachment.write_text("payload", encoding="utf-8")

    result = lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Überraschung",
        mail_body="Grüße 😊",
        mail_body_html="<p>Grüße 😊</p>",
        smtphosts=["smtp.example.com:2525"],
        attachment_file_paths=[attachment],
        credentials=("user", "pass"),
        use_starttls=True,
        timeout=12.5,
    )

    assert result is True
    instance = RecordingSMTP.created[0]
    assert instance.started_tls is True
    assert instance.logged_in == ("user", "pass")
    assert instance.closed is True
    sent = instance.sent_messages[0]
    parsed_message = message_from_string(sent[2], policy=default_policy)
    assert isinstance(parsed_message, EmailMessage)
    parts = list(parsed_message.iter_parts())
    plain_part = parts[0]
    html_part = parts[1]
    plain_payload = plain_part.get_payload(decode=True)
    html_payload = html_part.get_payload(decode=True)
    assert isinstance(plain_payload, (bytes, bytearray))
    assert isinstance(html_payload, (bytes, bytearray))
    assert "Grüße 😊" in plain_payload.decode("utf-8")
    assert "Grüße 😊" in html_payload.decode("utf-8")
    assert RecordingSMTP.init_calls[0] == ("smtp.example.com", 2525, 12.5)


def test_send_attempts_next_host_on_failure(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    recorder = _install_recording_smtp(monkeypatch)
    recorder.fail_on_init = {"primary.example.com"}

    lib_mail.conf.smtp_use_starttls = False

    result = lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients=["recipient@example.com"],
        mail_subject="Subject",
        smtphosts=["primary.example.com", "backup.example.com"],
        mail_body="Text",
    )

    assert result is True
    assert recorder.created[-1].sent_messages[0][1] == "recipient@example.com"
    assert recorder.send_attempts == ["backup.example.com"]


def test_send_raises_when_all_hosts_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_recording_smtp(monkeypatch)
    recorder.fail_on_send = {"fail.example.com"}

    with pytest.raises(RuntimeError):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients=["recipient@example.com"],
            mail_subject="Subject",
            smtphosts=["fail.example.com"],
            mail_body="Body",
        )
    assert recorder.send_attempts == ["fail.example.com"]


@pytest.mark.integration
@pytest.mark.os_agnostic
def test_send_real_mail_when_env_configured(tmp_path: Path) -> None:
    hosts_env = _configured_value("TEST_SMTP_HOSTS")
    recipients_env = _configured_value("TEST_RECIPIENTS")
    if not hosts_env or not recipients_env:
        pytest.skip("TEST_SMTP_HOSTS/TEST_RECIPIENTS not configured")

    smtphosts = [item.strip() for item in hosts_env.split(",") if item.strip()]
    recipients = [item.strip() for item in recipients_env.split(",") if item.strip()]
    if not smtphosts or not recipients:
        pytest.skip("SMTP integration env vars are empty")

    sender = _configured_value("TEST_SENDER") or recipients[0]

    conf_snapshot = lib_mail.conf.model_copy(deep=True)
    try:
        lib_mail.conf.smtphosts = smtphosts
        use_starttls_env = _configured_value("TEST_SMTP_USE_STARTTLS")
        if use_starttls_env is not None:
            normalized = use_starttls_env.strip().lower()
            lib_mail.conf.smtp_use_starttls = normalized in {"1", "true", "yes", "on"}
        username = _configured_value("TEST_SMTP_USERNAME")
        password = _configured_value("TEST_SMTP_PASSWORD")
        if username and password:
            lib_mail.conf.smtp_username = username
            lib_mail.conf.smtp_password = password

        attachment_path = tmp_path / "integration-attachment.txt"
        attachment_path.write_text("integration payload 😊", encoding="utf-8")

        assert lib_mail.send(
            mail_from=sender,
            mail_recipients=recipients,
            mail_subject="btx_lib_mail integration test 🚀",
            mail_body="This is an automated integration test from btx_lib_mail. 🚀",
            mail_body_html="<p><strong>Integration</strong> test 🚀 with <em>UTF-8</em> emoji.</p>",
            attachment_file_paths=[attachment_path],
        )
    finally:
        for key, value in conf_snapshot.model_dump().items():
            setattr(lib_mail.conf, key, value)


# ---------------------------------------------------------------------------
# smtp_timeout validation
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_when_conf_receives_negative_timeout_it_rejects() -> None:
    with pytest.raises(ValidationError, match="smtp_timeout must be positive"):
        ConfMail(smtp_timeout=-5.0)


@pytest.mark.os_agnostic
def test_when_conf_receives_zero_timeout_it_rejects() -> None:
    with pytest.raises(ValidationError, match="smtp_timeout must be positive"):
        ConfMail(smtp_timeout=0.0)


@pytest.mark.os_agnostic
def test_when_conf_receives_positive_timeout_it_accepts() -> None:
    config = ConfMail(smtp_timeout=0.5)
    assert config.smtp_timeout == 0.5


@pytest.mark.os_agnostic
def test_when_conf_timeout_assigned_negative_it_rejects() -> None:
    config = ConfMail()
    with pytest.raises(ValidationError, match="smtp_timeout must be positive"):
        cast(Any, config).smtp_timeout = -1.0


@pytest.mark.os_agnostic
def test_when_explicit_timeout_is_negative_the_send_call_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_recording_smtp(monkeypatch)
    with pytest.raises(ValueError, match="smtp_timeout must be positive"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            timeout=-1.0,
        )


# ---------------------------------------------------------------------------
# Port range validation
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_when_port_is_zero_the_send_call_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_recording_smtp(monkeypatch)
    with pytest.raises(ValueError, match="port must be 1-65535"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["host:0"],
        )


@pytest.mark.os_agnostic
def test_when_port_exceeds_65535_the_send_call_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_recording_smtp(monkeypatch)
    with pytest.raises(ValueError, match="port must be 1-65535"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["host:99999"],
        )


@pytest.mark.os_agnostic
def test_when_port_is_valid_it_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_recording_smtp(monkeypatch)
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["host:587"],
    )
    assert recorder.init_calls[0] == ("host", 587, 30.0)


# ---------------------------------------------------------------------------
# mail_from validation
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_when_mail_from_is_invalid_the_send_call_rejects() -> None:
    with pytest.raises(ValueError, match="invalid sender address"):
        lib_mail.send(
            mail_from="not-an-email",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
        )


@pytest.mark.os_agnostic
def test_when_mail_from_lacks_domain_the_send_call_rejects() -> None:
    with pytest.raises(ValueError, match="invalid sender address"):
        lib_mail.send(
            mail_from="user@",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
        )


# ---------------------------------------------------------------------------
# validate_email_address
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_validate_email_address_accepts_valid() -> None:
    lib_mail.validate_email_address("user@example.com")


@pytest.mark.os_agnostic
def test_validate_email_address_rejects_missing_domain() -> None:
    with pytest.raises(ValueError, match="invalid email address"):
        lib_mail.validate_email_address("user@")


@pytest.mark.os_agnostic
def test_validate_email_address_rejects_missing_local_part() -> None:
    with pytest.raises(ValueError, match="invalid email address"):
        lib_mail.validate_email_address("@example.com")


@pytest.mark.os_agnostic
def test_validate_email_address_rejects_bare_word() -> None:
    with pytest.raises(ValueError, match="invalid email address"):
        lib_mail.validate_email_address("bareword")


@pytest.mark.os_agnostic
def test_validate_email_address_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="invalid email address"):
        lib_mail.validate_email_address("")


# ---------------------------------------------------------------------------
# validate_smtp_host
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_validate_smtp_host_accepts_bare_hostname() -> None:
    lib_mail.validate_smtp_host("smtp.example.com")


@pytest.mark.os_agnostic
def test_validate_smtp_host_accepts_hostname_port() -> None:
    lib_mail.validate_smtp_host("smtp.example.com:587")


@pytest.mark.os_agnostic
def test_validate_smtp_host_accepts_ipv6_bare() -> None:
    lib_mail.validate_smtp_host("[::1]")


@pytest.mark.os_agnostic
def test_validate_smtp_host_accepts_ipv6_with_port() -> None:
    lib_mail.validate_smtp_host("[::1]:25")


@pytest.mark.os_agnostic
def test_validate_smtp_host_accepts_ipv6_full_with_port() -> None:
    lib_mail.validate_smtp_host("[2001:db8::1]:587")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_missing_bracket() -> None:
    with pytest.raises(ValueError, match="missing closing bracket"):
        lib_mail.validate_smtp_host("[::1")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_garbage_after_bracket() -> None:
    with pytest.raises(ValueError, match="unexpected characters after bracket"):
        lib_mail.validate_smtp_host("[::1]garbage")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_non_numeric_port() -> None:
    with pytest.raises(ValueError, match="invalid smtp port"):
        lib_mail.validate_smtp_host("host:abc")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_port_zero() -> None:
    with pytest.raises(ValueError, match="port must be 1-65535"):
        lib_mail.validate_smtp_host("host:0")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_port_over_65535() -> None:
    with pytest.raises(ValueError, match="port must be 1-65535"):
        lib_mail.validate_smtp_host("host:99999")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_empty_host() -> None:
    with pytest.raises(ValueError, match="empty SMTP host"):
        lib_mail.validate_smtp_host("")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_ipv6_non_numeric_port() -> None:
    with pytest.raises(ValueError, match="invalid smtp port"):
        lib_mail.validate_smtp_host("[::1]:abc")


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_ipv6_port_out_of_range() -> None:
    with pytest.raises(ValueError, match="port must be 1-65535"):
        lib_mail.validate_smtp_host("[::1]:0")


# ---------------------------------------------------------------------------
# IPv6 delivery integration (via _parse_smtp_host -> RecordingSMTP)
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_ipv6_host_with_port_parses_for_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_recording_smtp(monkeypatch)
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["[::1]:2525"],
    )
    assert recorder.init_calls[0] == ("::1", 2525, 30.0)


@pytest.mark.os_agnostic
def test_ipv6_host_without_port_parses_for_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_recording_smtp(monkeypatch)
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["[::1]"],
    )
    assert recorder.init_calls[0] == ("::1", 0, 30.0)
