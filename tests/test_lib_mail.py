from __future__ import annotations

# Tests deliberately reach into module internals (the injected transport seam,
# host parser, context builder), which is the tests' job, not an API leak.
# pyright: reportPrivateUsage=false
import os
import socket
import ssl
import sys
from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default as default_policy
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, ClassVar, cast

import pytest
from pydantic import SecretStr, ValidationError

from btx_lib_mail import ConfMail, _transport, _validation, lib_mail

if TYPE_CHECKING:
    from collections.abc import Generator

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
    # cast(Any, …) is required here because this test intentionally assigns
    # a plain str to a list[str] field to exercise the field_validator
    # coercion that runs at runtime via validate_assignment=True.  Pyright
    # correctly rejects ``config.smtphosts = "…"`` (str is not list[str]);
    # the cast silences the diagnostic for this deliberate type mismatch.
    config = ConfMail()
    cast("Any", config).smtphosts = "smtp.example.com"
    assert config.smtphosts == ["smtp.example.com"]


def test_conf_mail_rejects_non_string_entries() -> None:
    with pytest.raises(ValidationError):
        ConfMail.model_validate({"smtphosts": [1]})  # type: ignore[list-item]

    config = ConfMail()
    with pytest.raises(ValidationError):
        cast("Any", config).smtphosts = [1]  # type: ignore[list-item]


def test_conf_mail_resolves_credentials() -> None:
    config = ConfMail(smtp_username="user", smtp_password=SecretStr("pass"))
    assert config.resolved_credentials() == ("user", "pass")

    config = ConfMail()
    assert config.resolved_credentials() is None


@pytest.mark.os_agnostic
def test_smtp_password_accepts_a_plain_string_and_coerces_it() -> None:
    # A plain string assigned to the SecretStr field is coerced, so existing
    # callers that pass a literal keep working at runtime.
    config = ConfMail.model_validate({"smtp_username": "user", "smtp_password": "pass"})
    assert config.resolved_credentials() == ("user", "pass")


@pytest.mark.os_agnostic
def test_smtp_password_is_masked_in_repr_and_dump() -> None:
    config = ConfMail(smtp_username="user", smtp_password=SecretStr("s3cr3t-pw"))
    assert "s3cr3t-pw" not in repr(config)
    assert config.model_dump()["smtp_password"] != "s3cr3t-pw"
    # the real value is still available for the SMTP login
    assert config.resolved_credentials() == ("user", "s3cr3t-pw")


@pytest.mark.os_agnostic
def test_when_conf_receives_none_for_hosts_it_sets_an_empty_list() -> None:
    config = ConfMail.model_validate({"smtphosts": None})

    assert config.smtphosts == []


@pytest.mark.os_agnostic
def test_when_conf_receives_an_illegal_host_type_it_objects() -> None:
    with pytest.raises(ValidationError, match="smtphosts must be a string"):
        ConfMail.model_validate({"smtphosts": 123})


@pytest.mark.os_agnostic
def test_when_conf_receives_send_style_names_it_refuses_them() -> None:
    # send() calls these use_starttls/timeout; on ConfMail they are
    # smtp_use_starttls/smtp_timeout. Ignoring them would leave STARTTLS on.
    with pytest.raises(ValidationError) as caught:
        ConfMail(**cast("dict[str, Any]", {"use_starttls": False, "timeout": 5}))

    refused = {(error["loc"], error["type"]) for error in caught.value.errors()}
    assert refused == {(("use_starttls",), "extra_forbidden"), (("timeout",), "extra_forbidden")}


@pytest.mark.os_agnostic
def test_when_a_misspelled_password_name_is_refused_the_value_stays_hidden() -> None:
    with pytest.raises(ValidationError) as caught:
        ConfMail.model_validate({"smtp_pasword": "s3cr3t-pw"})

    assert "smtp_pasword" in str(caught.value)
    assert "s3cr3t-pw" not in str(caught.value)


class _RecordedDelivery:
    """One captured ``Transport.deliver`` call, exposing the resolved delivery
    options the orchestration layer forwarded (STARTTLS/credentials) and the raw
    message bytes streamed to the host."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        timeout: float | None,
        started_tls: bool,
        starttls_verify: bool,
        logged_in: tuple[str, str] | None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = started_tls
        self.starttls_verify = starttls_verify
        self.logged_in = logged_in
        self.closed = True
        self.sent_messages: list[tuple[str, str, bytes]] = []


class FakeTransport:
    """Real in-memory :class:`~btx_lib_mail.lib_mail.Transport` double.

    Injected via the ``transport`` seam instead of monkeypatching ``smtplib``,
    so orchestration tests (failover order, resolved STARTTLS/credentials, which
    host each recipient reached) assert against captured data. Actual socket,
    TLS, and BDAT/DATA wire behaviour is covered separately by the real-server
    e2e tests in ``test_streaming.py``.
    """

    # Shared across all FakeTransport instances by design: tests record via the
    # class itself (FakeTransport.init_calls.append(...)) to inspect delivery
    # history after `send()` returns.
    created: ClassVar[list[_RecordedDelivery]] = []
    init_calls: ClassVar[list[tuple[str, int, float | None]]] = []
    fail_on_send: ClassVar[set[str]] = set()
    fail_on_init: ClassVar[set[str]] = set()
    send_attempts: ClassVar[list[str]] = []

    def deliver(
        self,
        *,
        host: str,
        sender: str,
        recipient: str,
        message: IO[bytes],
        delivery: Any,
    ) -> None:
        hostname, port = _validation.parse_smtp_host(host)
        FakeTransport.init_calls.append((hostname, port or 0, delivery.timeout))
        # A host in fail_on_init never establishes a connection, so it records no
        # send attempt (matches a real connect failure feeding host failover).
        if hostname in FakeTransport.fail_on_init or host in FakeTransport.fail_on_init:
            raise ConnectionError("initialisation failed")
        FakeTransport.send_attempts.append(host)
        record = _RecordedDelivery(
            host=hostname,
            port=port or 0,
            timeout=delivery.timeout,
            started_tls=delivery.use_starttls,
            starttls_verify=delivery.starttls_verify,
            logged_in=delivery.credentials,
        )
        FakeTransport.created.append(record)
        if hostname in FakeTransport.fail_on_send or host in FakeTransport.fail_on_send:
            raise RuntimeError("boom")
        message.seek(0)
        record.sent_messages.append((sender, recipient, message.read()))

    @classmethod
    def reset(cls) -> None:
        cls.created = []
        cls.init_calls = []
        cls.fail_on_send = set()
        cls.fail_on_init = set()
        cls.send_attempts = []


def _install_fake_transport(monkeypatch: pytest.MonkeyPatch) -> type[FakeTransport]:
    FakeTransport.reset()
    monkeypatch.setattr(lib_mail, "DEFAULT_TRANSPORT", FakeTransport())
    return FakeTransport


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
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
        )


@pytest.mark.os_agnostic
def test_when_missing_attachments_are_allowed_a_warning_is_logged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    recorder = _install_fake_transport(monkeypatch)
    caplog.set_level("WARNING")
    ghost = tmp_path / "ghost.txt"

    lib_mail.conf.raise_on_missing_attachments = False

    result = lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["smtp.example.com"],
        attachment_file_paths=[ghost],
        attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
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
    recorder = _install_fake_transport(monkeypatch)
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
    _install_fake_transport(monkeypatch)
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
        attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
    )

    assert result is True
    instance = FakeTransport.created[0]
    assert instance.started_tls is True
    assert instance.logged_in == ("user", "pass")
    assert instance.closed is True
    sent = instance.sent_messages[0]
    # The wire message is now raw bytes streamed from the spool, not a str.
    parsed_message = message_from_bytes(sent[2], policy=default_policy)
    assert isinstance(parsed_message, EmailMessage)
    plain_payload: bytes | None = None
    html_payload: bytes | None = None
    attachment_names: list[str] = []
    for part in parsed_message.walk():
        filename = part.get_filename()
        if filename:
            attachment_names.append(filename)
        elif part.get_content_type() == "text/plain":
            plain_payload = cast("bytes | None", part.get_payload(decode=True))
        elif part.get_content_type() == "text/html":
            html_payload = cast("bytes | None", part.get_payload(decode=True))
    assert plain_payload is not None and "Grüße 😊" in plain_payload.decode("utf-8")
    assert html_payload is not None and "Grüße 😊" in html_payload.decode("utf-8")
    assert "document.txt" in attachment_names
    assert FakeTransport.init_calls[0] == ("smtp.example.com", 2525, 12.5)


@pytest.mark.os_agnostic
def test_conf_starttls_verify_defaults_to_true() -> None:
    assert ConfMail().smtp_starttls_verify is True


@pytest.mark.os_agnostic
def test_starttls_uses_a_verifying_context_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_fake_transport(monkeypatch)

    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        mail_body="Body",
        smtphosts=["smtp.example.com"],
        use_starttls=True,
    )

    delivered = recorder.created[0]
    assert delivered.started_tls is True
    assert delivered.starttls_verify is True


@pytest.mark.os_agnostic
def test_starttls_can_skip_certificate_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_fake_transport(monkeypatch)

    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        mail_body="Body",
        smtphosts=["smtp.example.com"],
        use_starttls=True,
        starttls_verify=False,
    )

    instance = recorder.created[0]
    assert instance.started_tls is True
    assert instance.starttls_verify is False


@pytest.mark.os_agnostic
def test_starttls_verify_falls_back_to_conf(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_fake_transport(monkeypatch)
    lib_mail.conf.smtp_starttls_verify = False

    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        mail_body="Body",
        smtphosts=["smtp.example.com"],
        use_starttls=True,
    )

    assert recorder.created[0].starttls_verify is False


@pytest.mark.os_agnostic
def test_build_starttls_context_verifies_by_default() -> None:
    context = _transport._build_starttls_context(verify=True)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.os_agnostic
def test_build_starttls_context_can_disable_verification() -> None:
    context = _transport._build_starttls_context(verify=False)
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_send_attempts_next_host_on_failure(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    recorder = _install_fake_transport(monkeypatch)
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
    recorder = _install_fake_transport(monkeypatch)
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


@pytest.mark.local_only
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
            lib_mail.conf.smtp_password = SecretStr(password)

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
        config.smtp_timeout = -1.0


@pytest.mark.os_agnostic
def test_when_explicit_timeout_is_negative_the_send_call_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_transport(monkeypatch)
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
    _install_fake_transport(monkeypatch)
    with pytest.raises(ValueError, match="port must be 1-65535"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["host:0"],
        )


@pytest.mark.os_agnostic
def test_when_port_exceeds_65535_the_send_call_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_transport(monkeypatch)
    with pytest.raises(ValueError, match="port must be 1-65535"):
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["host:99999"],
        )


@pytest.mark.os_agnostic
def test_when_port_is_valid_it_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_fake_transport(monkeypatch)
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

    # Accepted means usable: recipient preparation keeps it as given.
    assert _validation.prepare_recipients("user@example.com", raise_on_invalid=True, max_count=None) == ("user@example.com",)


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


@pytest.mark.os_agnostic
def test_validate_email_address_rejects_pipe_in_tld() -> None:
    # The TLD must be letters only; a '|' must not sneak through.
    with pytest.raises(ValueError, match="invalid email address"):
        lib_mail.validate_email_address("user@example.c|m")


# ---------------------------------------------------------------------------
# validate_smtp_host
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("host", "parsed"),
    [
        ("smtp.example.com", ("smtp.example.com", None)),
        ("smtp.example.com:587", ("smtp.example.com", 587)),
        ("[::1]", ("::1", None)),
        ("[::1]:25", ("::1", 25)),
        ("[2001:db8::1]:587", ("2001:db8::1", 587)),
        ("host:0025", ("host", 25)),
    ],
)
def test_validate_smtp_host_accepts_a_usable_host(host: str, parsed: tuple[str, int | None]) -> None:
    lib_mail.validate_smtp_host(host)

    # Accepted means usable: it splits into what the transport connects to, and the model keeps it.
    assert _validation.parse_smtp_host(host) == parsed
    assert ConfMail(smtphosts=[host]).smtphosts == [host]


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


# int() accepts these and they land in range, but no SMTP configuration means a port written
# with a sign, a digit separator or non-ASCII digits.
@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "host",
    [
        "host:+25",
        "host:2_5",
        "host:" + chr(0x0662) + chr(0x0665),  # Arabic-Indic 25
        "host:" + chr(0xFF12) + chr(0xFF15),  # fullwidth 25
        "[::1]:+25",
    ],
)
def test_validate_smtp_host_refuses_a_port_that_is_not_ascii_digits(host: str) -> None:
    with pytest.raises(ValueError) as caught:
        lib_mail.validate_smtp_host(host)
    assert str(caught.value) == f'invalid smtp port in "{host}"'


# Odd ports the range check already refused: the ASCII-digit check must not take them over.
@pytest.mark.os_agnostic
@pytest.mark.parametrize("host", ["host:-25", "host:+0", "host:" + chr(0x0660)])  # chr(0x0660): Arabic-Indic 0
def test_validate_smtp_host_keeps_the_range_message_for_an_odd_port_out_of_range(host: str) -> None:
    with pytest.raises(ValueError) as caught:
        lib_mail.validate_smtp_host(host)
    assert str(caught.value) == f'port must be 1-65535 in "{host}"'


# Every host 2.x refused, with the exact message 2.0.0 gave (recorded from the published 2.0.0).
# The 3.x checks may only refuse hosts 2.x ACCEPTED; a host 2.x refused keeps its message, so a
# consumer test written against 2.x stays green. The one deliberate difference: the range message
# lost its ", got <port>" suffix, which leaked digits past ConfMail's scrub.
_REFUSED_BY_2X = [
    ("smtp.test.com:587:extra", 'invalid smtp port in "smtp.test.com:587:extra"'),
    ("bad:host:format", 'invalid smtp port in "bad:host:format"'),
    ("host:abc", 'invalid smtp port in "host:abc"'),
    ("host:0", 'port must be 1-65535 in "host:0"'),
    ("host:99999", 'port must be 1-65535 in "host:99999"'),
    ("host:", 'invalid smtp port in "host:"'),
    ("[::1", 'missing closing bracket in "[::1"'),
    ("[::1]garbage", 'unexpected characters after bracket in "[::1]garbage"'),
    ("[::1]:abc", 'invalid smtp port in "[::1]:abc"'),
    ("[::1]:0", 'port must be 1-65535 in "[::1]:0"'),
    ("[::1]:", 'invalid smtp port in "[::1]:"'),
    ("", "empty SMTP host"),
    (":abc", 'invalid smtp port in ":abc"'),
    (":", 'invalid smtp port in ":"'),
    ("a.example.com:abc,b", 'invalid smtp port in "a.example.com:abc,b"'),
    ("a,b:abc", 'invalid smtp port in "a,b:abc"'),
    ("[::1]:25,x", 'invalid smtp port in "[::1]:25,x"'),
    ("[::1],[::2]", 'unexpected characters after bracket in "[::1],[::2]"'),
    ("a:25,", 'invalid smtp port in "a:25,"'),
]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("host", "message_2x"), _REFUSED_BY_2X)
def test_validate_smtp_host_keeps_the_2x_message_for_a_host_2x_refused(host: str, message_2x: str) -> None:
    with pytest.raises(ValueError) as caught:
        lib_mail.validate_smtp_host(host)
    assert str(caught.value) == message_2x


@pytest.mark.os_agnostic
def test_validate_smtp_host_names_the_extra_colon_for_a_host_name() -> None:
    # Not an IPv6 address at all, so the message must not read as if it were one.
    with pytest.raises(ValueError, match='more than one ":"'):
        lib_mail.validate_smtp_host("smtp.example.com:587:25")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("host", ["a.example.com:25,b.example.com:25", "a.example.com,b.example.com"])
def test_validate_smtp_host_rejects_several_hosts_in_one_string(host: str) -> None:
    with pytest.raises(ValueError, match="one host per entry"):
        lib_mail.validate_smtp_host(host)


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_a_port_without_a_host_name() -> None:
    with pytest.raises(ValueError, match="missing host name"):
        lib_mail.validate_smtp_host(":25")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("host", ["fe80::1", "2001:db8::1:587"])
def test_validate_smtp_host_rejects_an_unbracketed_ipv6_address(host: str) -> None:
    with pytest.raises(ValueError, match=r"IPv6 address must be in brackets"):
        lib_mail.validate_smtp_host(host)


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_empty_brackets() -> None:
    with pytest.raises(ValueError, match="missing host name"):
        lib_mail.validate_smtp_host("[]:25")


# ---------------------------------------------------------------------------
# ConfMail.smtphosts runs validate_smtp_host
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("smtp.example.com:99999", "port must be 1-65535"),
        ("smtp.example.com:abc", "invalid smtp port"),
        ("[::1", "missing closing bracket"),
        ("a.example.com:25,b.example.com:25", "one host per entry"),
    ],
)
def test_conf_mail_refuses_a_malformed_host_at_construction(host: str, reason: str) -> None:
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtphosts=[host])
    (error,) = caught.value.errors()
    assert error["loc"] == ("smtphosts",)
    assert reason in error["msg"]


@pytest.mark.os_agnostic
def test_conf_mail_refuses_a_malformed_host_on_assignment() -> None:
    config = ConfMail()
    with pytest.raises(ValidationError, match="port must be 1-65535"):
        config.smtphosts = ["smtp.example.com:0"]
    assert config.smtphosts == []


@pytest.mark.os_agnostic
def test_conf_mail_refusal_of_a_malformed_host_does_not_echo_it() -> None:
    # Without an '@', "user:<secret>" passes the userinfo check and is refused by
    # the port parser, whose message quotes the host; ConfMail must not repeat it.
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtphosts=["user:pw-not-a-port-7731"])
    assert "invalid smtp port" in str(caught.value), "positive control: refused by the port check"
    assert "pw-not-a-port-7731" not in str(caught.value)
    assert "pw-not-a-port-7731" not in caught.value.json()


@pytest.mark.os_agnostic
def test_conf_mail_refusal_of_an_out_of_range_port_does_not_echo_the_digits() -> None:
    # The scrub hides the host as a whole; a message that re-quotes a PART of it
    # (the parsed port) would still carry an all-digit secret written after a colon.
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtphosts=["mailer:98765432"])
    assert "port must be 1-65535" in str(caught.value), "positive control: refused by the range check"
    assert "98765432" not in str(caught.value)
    assert "98765432" not in caught.value.json()


@pytest.mark.os_agnostic
def test_conf_mail_reads_a_blank_host_string_as_no_hosts() -> None:
    assert ConfMail.model_validate({"smtphosts": "  "}).smtphosts == []


@pytest.mark.os_agnostic
def test_conf_mail_drops_a_blank_entry_from_a_host_list() -> None:
    assert ConfMail(smtphosts=["smtp.example.com", " "]).smtphosts == ["smtp.example.com"]


# ---------------------------------------------------------------------------
# IPv6 delivery integration (via _parse_smtp_host -> FakeTransport)
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_ipv6_host_with_port_parses_for_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_fake_transport(monkeypatch)
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["[::1]:2525"],
    )
    assert recorder.init_calls[0] == ("::1", 2525, 30.0)


@pytest.mark.os_agnostic
def test_ipv6_host_without_port_parses_for_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _install_fake_transport(monkeypatch)
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["[::1]"],
    )
    assert recorder.init_calls[0] == ("::1", 0, 30.0)


# ---------------------------------------------------------------------------
# Attachment Security: Configuration Field Tests
# ---------------------------------------------------------------------------


class TestExtensionNormalisation:
    """Tests for extension field validation and normalisation."""

    @pytest.mark.os_agnostic
    def test_extensions_are_lowercased(self) -> None:
        config = ConfMail(attachment_blocked_extensions=frozenset({".EXE", ".BAT"}))
        assert ".exe" in config.attachment_blocked_extensions
        assert ".bat" in config.attachment_blocked_extensions

    @pytest.mark.os_agnostic
    def test_extensions_get_leading_dot(self) -> None:
        config = ConfMail(attachment_blocked_extensions=frozenset({"exe", "bat"}))
        assert ".exe" in config.attachment_blocked_extensions
        assert ".bat" in config.attachment_blocked_extensions

    @pytest.mark.os_agnostic
    def test_empty_extensions_are_filtered(self) -> None:
        config = ConfMail(attachment_blocked_extensions=frozenset({".exe", "", "  "}))
        assert config.attachment_blocked_extensions == frozenset({".exe"})

    @pytest.mark.os_agnostic
    def test_none_allowed_extensions_means_blacklist_mode(self) -> None:
        config = ConfMail(attachment_allowed_extensions=None)
        assert config.attachment_allowed_extensions is None


class TestDirectoryNormalisation:
    """Tests for directory field validation and normalisation."""

    @pytest.mark.os_agnostic
    def test_string_directories_are_converted_to_paths(self) -> None:
        # Use list to test conversion from strings
        config = ConfMail(attachment_blocked_directories=["/etc", "/var"])  # type: ignore[arg-type]
        assert Path("/etc") in config.attachment_blocked_directories
        assert Path("/var") in config.attachment_blocked_directories

    @pytest.mark.os_agnostic
    def test_path_directories_remain_paths(self) -> None:
        config = ConfMail(attachment_blocked_directories=frozenset({Path("/etc")}))
        assert Path("/etc") in config.attachment_blocked_directories


_EMPTY_BLOCKED_CASES = [
    pytest.param("attachment_blocked_extensions", [".exe"], id="extensions"),
    pytest.param("attachment_blocked_directories", ["/etc"], id="directories"),
]


class TestEmptyBlockedSetIsRefused:
    """An empty blocked set with no allowlist blocks nothing, so ConfMail refuses it unless opted out."""

    @pytest.mark.os_agnostic
    @pytest.mark.parametrize(("field", "non_empty"), _EMPTY_BLOCKED_CASES)
    def test_an_empty_list_from_a_config_source_is_refused(self, field: str, non_empty: list[str]) -> None:
        assert getattr(ConfMail.model_validate({field: non_empty}), field), "positive control: a non-empty list validates"

        with pytest.raises(ValidationError) as caught:
            ConfMail.model_validate({field: []})

        message = str(caught.value)
        assert field in message
        assert "attachment_allow_empty_blocklists" in message

    @pytest.mark.os_agnostic
    @pytest.mark.parametrize(
        ("blocked", "allowed", "allowed_value"),
        [
            pytest.param("attachment_blocked_extensions", "attachment_allowed_extensions", [".pdf"], id="extensions"),
            pytest.param("attachment_blocked_directories", "attachment_allowed_directories", ["/srv/mail"], id="directories"),
        ],
    )
    def test_an_empty_blocked_set_is_accepted_when_its_own_allowlist_is_set(self, blocked: str, allowed: str, allowed_value: list[str]) -> None:
        config = ConfMail.model_validate({blocked: [], allowed: allowed_value})

        assert getattr(config, blocked) == frozenset()

    @pytest.mark.os_agnostic
    def test_the_allowlist_of_the_other_axis_does_not_excuse_an_empty_blocked_set(self) -> None:
        with pytest.raises(ValidationError, match="attachment_blocked_extensions"):
            ConfMail.model_validate({"attachment_blocked_extensions": [], "attachment_allowed_directories": ["/srv/mail"]})

    @pytest.mark.os_agnostic
    @pytest.mark.parametrize(("field", "non_empty"), _EMPTY_BLOCKED_CASES)
    def test_the_opt_out_accepts_an_empty_blocked_set(self, field: str, non_empty: list[str]) -> None:
        config = ConfMail.model_validate({field: [], "attachment_allow_empty_blocklists": True})

        assert getattr(config, field) == frozenset()

    @pytest.mark.os_agnostic
    @pytest.mark.parametrize(("field", "non_empty"), _EMPTY_BLOCKED_CASES)
    def test_assigning_an_empty_blocked_set_is_refused_and_changes_nothing(self, field: str, non_empty: list[str]) -> None:
        config = ConfMail()
        before = getattr(config, field)
        assert before, "positive control: the OS default is not empty"

        with pytest.raises(ValidationError):
            setattr(config, field, frozenset())

        assert getattr(config, field) == before
        assert field not in config.model_fields_set

    @pytest.mark.os_agnostic
    def test_clearing_the_allowlist_under_an_empty_blocked_set_is_refused_and_changes_nothing(self) -> None:
        config = ConfMail(attachment_allowed_extensions=frozenset({".pdf"}), attachment_blocked_extensions=frozenset())

        with pytest.raises(ValidationError, match="attachment_blocked_extensions"):
            config.attachment_allowed_extensions = None

        assert config.attachment_allowed_extensions == frozenset({".pdf"})

    @pytest.mark.os_agnostic
    def test_withdrawing_the_opt_out_under_an_empty_blocked_set_is_refused_and_changes_nothing(self) -> None:
        config = ConfMail(attachment_blocked_directories=frozenset(), attachment_allow_empty_blocklists=True)

        with pytest.raises(ValidationError, match="attachment_blocked_directories"):
            config.attachment_allow_empty_blocklists = False

        assert config.attachment_allow_empty_blocklists is True

    @pytest.mark.os_agnostic
    def test_an_opted_out_config_lets_send_attach_a_default_blocked_extension(self, tmp_path: Path) -> None:
        extension = sorted(ConfMail().attachment_blocked_extensions)[0]
        attachment = tmp_path / f"payload{extension}"
        attachment.write_bytes(b"payload")
        # The directory allowlist keeps the platform's blocked directories (macOS
        # /var/folders holds tmp_path) out of this test's way.
        directories = frozenset({tmp_path})
        guarded = ConfMail(smtphosts=["cfg.example.com"], attachment_allowed_directories=directories)
        with pytest.raises(lib_mail.AttachmentSecurityError) as refused:
            lib_mail.send("sender@example.com", "rcpt@example.com", "s", attachment_file_paths=[attachment], config=guarded, transport=_RecordingTransport())
        assert refused.value.violation_type is lib_mail.AttachmentViolation.EXTENSION, "positive control: the default config blocks this extension"
        opted_out = ConfMail(
            smtphosts=["cfg.example.com"],
            attachment_allowed_directories=directories,
            attachment_blocked_extensions=frozenset(),
            attachment_allow_empty_blocklists=True,
        )
        transport = _RecordingTransport()

        lib_mail.send("sender@example.com", "rcpt@example.com", "s", attachment_file_paths=[attachment], config=opted_out, transport=transport)

        assert len(transport.calls) == 1

    @pytest.mark.os_agnostic
    def test_an_explicit_empty_keyword_to_send_stays_allowed_under_the_default_config(self, tmp_path: Path) -> None:
        extension = sorted(ConfMail().attachment_blocked_extensions)[0]
        attachment = tmp_path / f"payload{extension}"
        attachment.write_bytes(b"payload")
        config = ConfMail(smtphosts=["cfg.example.com"], attachment_allowed_directories=frozenset({tmp_path}))
        transport = _RecordingTransport()

        lib_mail.send(
            "sender@example.com",
            "rcpt@example.com",
            "s",
            attachment_file_paths=[attachment],
            attachment_blocked_extensions=frozenset(),
            config=config,
            transport=transport,
        )

        assert len(transport.calls) == 1


class TestSizeLimitValidation:
    """Tests for attachment size limit validation."""

    @pytest.mark.os_agnostic
    def test_positive_size_limit_is_accepted(self) -> None:
        config = ConfMail(attachment_max_size_bytes=1024)
        assert config.attachment_max_size_bytes == 1024

    @pytest.mark.os_agnostic
    def test_none_size_limit_disables_check(self) -> None:
        config = ConfMail(attachment_max_size_bytes=None)
        assert config.attachment_max_size_bytes is None

    @pytest.mark.os_agnostic
    def test_zero_size_limit_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="attachment_max_size_bytes must be positive"):
            ConfMail(attachment_max_size_bytes=0)

    @pytest.mark.os_agnostic
    def test_negative_size_limit_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="attachment_max_size_bytes must be positive"):
            ConfMail(attachment_max_size_bytes=-1)


# ---------------------------------------------------------------------------
# Attachment Security: Validation Function Tests
# ---------------------------------------------------------------------------


class TestPathTraversalPrevention:
    """Tests for path traversal attack prevention."""

    @pytest.mark.os_agnostic
    def test_path_with_dotdot_is_rejected(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        # Create a file to attach
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("content")

        with pytest.raises(lib_mail.AttachmentSecurityError, match="path contains traversal sequence"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[Path("../../../etc/passwd")],
            )

    @pytest.mark.os_agnostic
    def test_path_without_traversal_is_allowed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("content")

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[safe_file],
            attachment_blocked_extensions=frozenset(),  # Allow .txt
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
        )
        assert result is True

    @pytest.mark.os_agnostic
    @pytest.mark.parametrize("name", ["report..final.txt", "...txt"])
    def test_a_double_dot_inside_a_file_name_is_not_traversal(self, tmp_path: Path, name: str) -> None:
        attachment = tmp_path / name
        attachment.write_text("content")

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[attachment],
            attachment_blocked_directories=frozenset(),
            transport=FakeTransport(),
        )
        assert result is True

    @pytest.mark.os_agnostic
    def test_a_double_dot_component_mid_path_is_still_traversal(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b.txt").write_text("content")

        with pytest.raises(lib_mail.AttachmentSecurityError, match="path contains traversal sequence"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[tmp_path / "a" / ".." / "b.txt"],
                attachment_blocked_directories=frozenset(),
                transport=FakeTransport(),
            )


class TestSymlinkHandling:
    """Tests for symlink security handling."""

    @pytest.mark.os_agnostic
    def test_a_symlinked_parent_into_a_blocked_directory_is_refused(self, tmp_path: Path) -> None:
        # Only a symlink as the FINAL component is refused as SYMLINK; a symlinked
        # directory along the way is followed, and every rule runs on the resolved
        # target, so it cannot carry a file out of a blocked directory.
        vault = tmp_path / "vault"
        vault.mkdir()
        (vault / "report.txt").write_text("content")
        (tmp_path / "docs").symlink_to(vault, target_is_directory=True)

        with pytest.raises(lib_mail.AttachmentSecurityError) as excinfo:
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[tmp_path / "docs" / "report.txt"],
                attachment_blocked_directories=frozenset({vault}),
                transport=FakeTransport(),
            )
        assert excinfo.value.violation_type is lib_mail.AttachmentViolation.DIRECTORY

    @pytest.mark.os_agnostic
    def test_a_symlinked_parent_out_of_an_allowed_directory_is_refused(self, tmp_path: Path) -> None:
        public = tmp_path / "public"
        public.mkdir()
        private = tmp_path / "private"
        private.mkdir()
        (private / "report.txt").write_text("content")
        (public / "shared").symlink_to(private, target_is_directory=True)

        with pytest.raises(lib_mail.AttachmentSecurityError) as excinfo:
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[public / "shared" / "report.txt"],
                attachment_allowed_directories=frozenset({public}),
                transport=FakeTransport(),
            )
        assert excinfo.value.violation_type is lib_mail.AttachmentViolation.DIRECTORY

    @pytest.mark.os_agnostic
    def test_symlink_is_rejected_by_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        symlink_file = tmp_path / "link.txt"
        symlink_file.symlink_to(real_file)

        with pytest.raises(lib_mail.AttachmentSecurityError, match="symlink detected"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[symlink_file],
                attachment_blocked_extensions=frozenset(),
            )

    @pytest.mark.os_agnostic
    def test_symlink_is_allowed_when_enabled(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        symlink_file = tmp_path / "link.txt"
        symlink_file.symlink_to(real_file)

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[symlink_file],
            attachment_blocked_extensions=frozenset(),
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
            attachment_allow_symlinks=True,
        )
        assert result is True


class TestExtensionBlocking:
    """Tests for extension-based filtering."""

    @pytest.mark.os_agnostic
    def test_blocked_extension_raises_by_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        # Use .js which is blocked on both POSIX and Windows
        script_file = tmp_path / "malicious.js"
        script_file.write_text("console.log('pwned')")

        with pytest.raises(lib_mail.AttachmentSecurityError, match=r"extension.*is blocked"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[script_file],
                attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
            )

    @pytest.mark.os_agnostic
    def test_allowed_extension_passes_whitelist_mode(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        pdf_file = tmp_path / "document.pdf"
        pdf_file.write_bytes(b"%PDF-1.4 fake pdf content")

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[pdf_file],
            attachment_allowed_extensions=frozenset({".pdf", ".txt"}),
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
        )
        assert result is True

    @pytest.mark.os_agnostic
    def test_non_allowed_extension_fails_whitelist_mode(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        doc_file = tmp_path / "document.docx"
        doc_file.write_bytes(b"fake docx content")

        with pytest.raises(lib_mail.AttachmentSecurityError, match=r"extension.*not in allowed list"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[doc_file],
                attachment_allowed_extensions=frozenset({".pdf", ".txt"}),
                attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
            )


class TestDirectoryBlocking:
    """Tests for directory-based filtering."""

    @pytest.mark.os_agnostic
    def test_blocked_directory_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        blocked_dir = tmp_path / "blocked"
        blocked_dir.mkdir()
        blocked_file = blocked_dir / "document.txt"
        blocked_file.write_text("content in blocked dir")

        with pytest.raises(lib_mail.AttachmentSecurityError, match="path under blocked directory"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[blocked_file],
                attachment_blocked_directories=frozenset({blocked_dir}),
                attachment_blocked_extensions=frozenset(),
            )

    @pytest.mark.os_agnostic
    def test_allowed_directory_whitelist_mode(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        allowed_file = allowed_dir / "document.txt"
        allowed_file.write_text("safe content")

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[allowed_file],
            attachment_allowed_directories=frozenset({allowed_dir}),
            attachment_blocked_extensions=frozenset(),
        )
        assert result is True

    @pytest.mark.os_agnostic
    def test_non_allowed_directory_fails_whitelist_mode(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        other_file = other_dir / "document.txt"
        other_file.write_text("content")

        with pytest.raises(lib_mail.AttachmentSecurityError, match="not under any allowed directory"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[other_file],
                attachment_allowed_directories=frozenset({allowed_dir}),
                attachment_blocked_extensions=frozenset(),
            )


class TestSizeLimit:
    """Tests for attachment size limit enforcement."""

    @pytest.mark.os_agnostic
    def test_oversized_attachment_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        large_file = tmp_path / "large.txt"
        large_file.write_bytes(b"x" * 1000)  # 1000 bytes

        with pytest.raises(lib_mail.AttachmentSecurityError, match=r"file size.*exceeds limit"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[large_file],
                attachment_max_size_bytes=500,
                attachment_blocked_extensions=frozenset(),
                attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
            )

    @pytest.mark.os_agnostic
    def test_small_attachment_passes(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        small_file = tmp_path / "small.txt"
        small_file.write_bytes(b"x" * 100)

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[small_file],
            attachment_max_size_bytes=500,
            attachment_blocked_extensions=frozenset(),
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
        )
        assert result is True


# Case variants of names the SSH, AWS and GnuPG clients and dotenv loaders read.
_CASE_VARIANTS_OF_CREDENTIAL_FILES: tuple[str, ...] = (".SSH/config", ".AWS/CREDENTIALS", ".GNUPG/pubring.kbx", ".Env")


def _written(target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("secret material")
    return target


def _send_one_attachment(attachment: Path) -> bool:
    return lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="recipient@example.com",
        mail_subject="Subject",
        smtphosts=["smtp.example.com"],
        attachment_file_paths=[attachment],
        attachment_blocked_directories=frozenset(),
        transport=FakeTransport(),
    )


class TestSensitivePatterns:
    """Tests for sensitive path pattern detection."""

    @pytest.mark.os_agnostic
    def test_ssh_key_path_is_blocked(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key_file = ssh_dir / "id_rsa"
        key_file.write_text("fake private key")

        with pytest.raises(lib_mail.AttachmentSecurityError, match="sensitive pattern"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[key_file],
                attachment_blocked_extensions=frozenset(),
            )

    @pytest.mark.os_agnostic
    def test_env_file_is_blocked(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_KEY=supersecret")

        with pytest.raises(lib_mail.AttachmentSecurityError, match="sensitive pattern"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[env_file],
                attachment_blocked_extensions=frozenset(),
            )

    @pytest.mark.os_agnostic
    @pytest.mark.parametrize(
        "relative",
        [
            ".ssh/config",
            ".aws/credentials",
            ".gnupg/pubring.kbx",
            ".env",
            ".netrc",
            ".pgpass",
            ".git-credentials",
            ".docker/config.json",
            ".pypirc",
            ".npmrc",
            ".config/gh/hosts.yml",
        ],
    )
    def test_a_credential_file_is_blocked(self, tmp_path: Path, relative: str) -> None:
        with pytest.raises(lib_mail.AttachmentSecurityError) as excinfo:
            _send_one_attachment(_written(tmp_path / relative))
        assert excinfo.value.violation_type is lib_mail.AttachmentViolation.SENSITIVE_PATTERN

    @pytest.mark.os_macos
    @pytest.mark.os_windows
    @pytest.mark.skipif(sys.platform not in ("darwin", "win32"), reason="macOS and Windows file systems ignore case; Linux file systems do not")
    @pytest.mark.parametrize("relative", _CASE_VARIANTS_OF_CREDENTIAL_FILES)
    def test_a_case_variant_of_a_credential_file_is_blocked_where_paths_ignore_case(self, tmp_path: Path, relative: str) -> None:
        # .SSH/config IS ~/.ssh/config on a case-insensitive file system.
        with pytest.raises(lib_mail.AttachmentSecurityError) as excinfo:
            _send_one_attachment(_written(tmp_path / relative))
        assert excinfo.value.violation_type is lib_mail.AttachmentViolation.SENSITIVE_PATTERN

    @pytest.mark.os_linux
    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux file systems tell names apart by case")
    @pytest.mark.parametrize("relative", _CASE_VARIANTS_OF_CREDENTIAL_FILES)
    def test_a_case_variant_of_a_credential_file_is_an_ordinary_file_on_linux(self, tmp_path: Path, relative: str) -> None:
        # On Linux .SSH/config is a different file from .ssh/config, not the SSH client's.
        FakeTransport.reset()
        assert _send_one_attachment(_written(tmp_path / relative)) is True
        (delivery,) = FakeTransport.created
        assert b"c2VjcmV0IG1hdGVyaWFs" in delivery.sent_messages[0][2]  # base64 of the file's content

    @pytest.mark.os_agnostic
    def test_an_ordinary_document_passes_the_sensitive_pattern_check(self, tmp_path: Path) -> None:
        target = tmp_path / "Quarterly Report.pdf"
        target.write_bytes(b"%PDF-1.4")

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[target],
            attachment_blocked_directories=frozenset(),
            transport=FakeTransport(),
        )
        assert result is True


class TestSecurityViolationWarningMode:
    """Tests for warn-only mode (raise_on_security_violation=False)."""

    @pytest.mark.os_agnostic
    def test_violation_logs_warning_and_continues(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        _install_fake_transport(monkeypatch)
        caplog.set_level("WARNING")

        script_file = tmp_path / "script.sh"
        script_file.write_text("#!/bin/bash")
        safe_file = tmp_path / "document.pdf"
        safe_file.write_bytes(b"%PDF-1.4 content")

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[script_file, safe_file],
            attachment_raise_on_security_violation=False,
            attachment_allowed_extensions=frozenset({".pdf"}),
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
        )

        assert result is True
        assert "Attachment security violation" in caplog.text
        assert "extension" in caplog.text


class TestAttachmentSecurityErrorAttributes:
    """Tests for AttachmentSecurityError exception attributes."""

    @pytest.mark.os_agnostic
    def test_exception_has_path_and_reason(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        # Use .js which is blocked on both POSIX and Windows
        script_file = tmp_path / "script.js"
        script_file.write_text("console.log('test')")

        try:
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[script_file],
                attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
            )
            pytest.fail("Expected AttachmentSecurityError")
        except lib_mail.AttachmentSecurityError as exc:
            assert exc.path == script_file.resolve()
            assert exc.violation_type == "extension"
            assert ".js" in exc.reason

    @pytest.mark.os_agnostic
    def test_exception_str_contains_all_info(self) -> None:
        test_path = Path("/test/file.exe")
        exc = lib_mail.AttachmentSecurityError(
            path=test_path,
            reason="extension blocked",
            violation_type=lib_mail.AttachmentViolation.EXTENSION,
        )
        exc_str = str(exc)
        assert "extension" in exc_str
        assert "file.exe" in exc_str  # Check filename, not full path (OS-agnostic)
        assert "blocked" in exc_str


@pytest.mark.os_agnostic
def test_attachment_violation_type_is_an_enum_member() -> None:
    from btx_lib_mail import AttachmentViolation

    with pytest.raises(lib_mail.AttachmentSecurityError) as excinfo:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[Path("../secret.txt")],
        )
    exc = excinfo.value
    assert exc.violation_type is AttachmentViolation.PATH_TRAVERSAL
    assert exc.violation_type == "path_traversal"  # str-enum keeps the wire value
    assert isinstance(exc.violation_type, str)


class TestDefaultSecuritySettings:
    """Tests for default security settings."""

    @pytest.mark.os_agnostic
    def test_default_blocked_extensions_include_common_dangers(self) -> None:
        config = ConfMail()
        # Check some common dangerous extensions
        assert ".sh" in config.attachment_blocked_extensions or ".exe" in config.attachment_blocked_extensions

    @pytest.mark.os_agnostic
    def test_default_blocked_extensions_cover_both_families_on_every_platform(self) -> None:
        # The recipient's OS decides what runs, not the sender's: a Linux sender must
        # still refuse .exe/.bat, and a Windows sender .sh.
        blocked = ConfMail().attachment_blocked_extensions
        assert blocked >= lib_mail.DANGEROUS_EXTENSIONS_POSIX
        assert blocked >= lib_mail.DANGEROUS_EXTENSIONS_WINDOWS

    @pytest.mark.os_agnostic
    @pytest.mark.parametrize("name", ["tool.exe", "run.bat", "x.sh.", "x.exe ", "x.sh. . ", "X.EXE"])
    def test_default_blocklist_refuses_an_executable_name(self, tmp_path: Path, name: str) -> None:
        if sys.platform == "win32" and name != name.rstrip(". "):
            pytest.skip("Windows cannot create a file whose name ends in a dot or space")
        attachment = tmp_path / name
        attachment.write_bytes(b"payload")

        with pytest.raises(lib_mail.AttachmentSecurityError) as excinfo:
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[attachment],
                attachment_blocked_directories=frozenset(),
                transport=FakeTransport(),
            )
        assert excinfo.value.violation_type is lib_mail.AttachmentViolation.EXTENSION

    @pytest.mark.os_agnostic
    def test_default_symlinks_disabled(self) -> None:
        config = ConfMail()
        assert config.attachment_allow_symlinks is False

    @pytest.mark.os_agnostic
    def test_default_raise_on_violation_enabled(self) -> None:
        config = ConfMail()
        assert config.attachment_raise_on_security_violation is True

    @pytest.mark.os_agnostic
    def test_default_max_size_is_25mib(self) -> None:
        config = ConfMail()
        assert config.attachment_max_size_bytes == 26_214_400


class TestPerCallSecurityOverrides:
    """Tests for per-call security parameter overrides."""

    @pytest.mark.os_agnostic
    def test_can_override_blocked_extensions_per_call(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        script_file = tmp_path / "script.sh"
        script_file.write_text("#!/bin/bash")

        # Override to allow .sh for this call
        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[script_file],
            attachment_blocked_extensions=frozenset(),  # No blocked extensions
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
        )
        assert result is True

    @pytest.mark.os_agnostic
    def test_can_override_size_limit_per_call(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _install_fake_transport(monkeypatch)
        large_file = tmp_path / "large.txt"
        large_file.write_bytes(b"x" * 1000)

        # Default would fail (assuming default < 1000), but override allows it
        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[large_file],
            attachment_max_size_bytes=10_000,  # Override to 10KB
            attachment_blocked_extensions=frozenset(),
            attachment_blocked_directories=frozenset(),  # Disable for macOS /var/folders
        )
        assert result is True


# ---------------------------------------------------------------------------
# Per-call Error Handling Parameter Overrides
# ---------------------------------------------------------------------------


class TestRaiseOnMissingAttachmentsParameter:
    """Tests for raise_on_missing_attachments per-call override."""

    @pytest.mark.os_agnostic
    def test_parameter_true_raises_when_conf_false(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Override to raise even when conf says don't."""
        _install_fake_transport(monkeypatch)
        lib_mail.conf.raise_on_missing_attachments = False
        missing_file = tmp_path / "missing.txt"

        with pytest.raises(FileNotFoundError, match="Attachment File"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[missing_file],
                attachment_blocked_directories=frozenset(),
                raise_on_missing_attachments=True,  # Override
            )

    @pytest.mark.os_agnostic
    def test_parameter_false_warns_when_conf_true(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Override to warn even when conf says raise."""
        recorder = _install_fake_transport(monkeypatch)
        caplog.set_level("WARNING")
        lib_mail.conf.raise_on_missing_attachments = True
        missing_file = tmp_path / "missing.txt"

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[missing_file],
            attachment_blocked_directories=frozenset(),
            raise_on_missing_attachments=False,  # Override
        )

        assert result is True
        assert "Attachment File" in caplog.text
        assert recorder.created[0].sent_messages[0][2]

    @pytest.mark.os_agnostic
    def test_parameter_none_uses_conf_default_true(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """When None, fall back to conf which is True."""
        _install_fake_transport(monkeypatch)
        lib_mail.conf.raise_on_missing_attachments = True
        missing_file = tmp_path / "missing.txt"

        with pytest.raises(FileNotFoundError, match="Attachment File"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="recipient@example.com",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                attachment_file_paths=[missing_file],
                attachment_blocked_directories=frozenset(),
                raise_on_missing_attachments=None,  # Use default
            )

    @pytest.mark.os_agnostic
    def test_parameter_none_uses_conf_default_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """When None, fall back to conf which is False."""
        recorder = _install_fake_transport(monkeypatch)
        caplog.set_level("WARNING")
        lib_mail.conf.raise_on_missing_attachments = False
        missing_file = tmp_path / "missing.txt"

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[missing_file],
            attachment_blocked_directories=frozenset(),
            raise_on_missing_attachments=None,  # Use default
        )

        assert result is True
        assert "Attachment File" in caplog.text
        assert recorder.created[0].sent_messages[0][2]

    @pytest.mark.os_agnostic
    def test_config_param_supplies_the_default_not_the_global_conf(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """With no per-call override, a passed config's own setting governs, not the global conf's opposite one."""
        recorder = _install_fake_transport(monkeypatch)
        lib_mail.conf.raise_on_missing_attachments = True  # global: strict
        settings = ConfMail(smtphosts=["smtp.example.com"], raise_on_missing_attachments=False)  # config: tolerant
        missing_file = tmp_path / "missing.txt"

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="recipient@example.com",
            mail_subject="Subject",
            attachment_file_paths=[missing_file],
            attachment_blocked_directories=frozenset(),
            config=settings,
        )

        assert result is True, "the passed config's tolerant setting must win over the global conf's strict one"
        assert recorder.created[0].sent_messages[0][2]


class TestRaiseOnInvalidRecipientParameter:
    """Tests for raise_on_invalid_recipient per-call override."""

    @pytest.mark.os_agnostic
    def test_parameter_true_raises_when_conf_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Override to raise even when conf says don't."""
        _install_fake_transport(monkeypatch)
        lib_mail.conf.raise_on_invalid_recipient = False

        with pytest.raises(ValueError, match="invalid recipient"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="invalid@",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                raise_on_invalid_recipient=True,  # Override
            )

    @pytest.mark.os_agnostic
    def test_parameter_false_warns_when_conf_true(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Override to warn even when conf says raise."""
        recorder = _install_fake_transport(monkeypatch)
        caplog.set_level("WARNING")
        lib_mail.conf.raise_on_invalid_recipient = True

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients=["invalid@", "valid@example.com"],
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            raise_on_invalid_recipient=False,  # Override
        )

        assert result is True
        assert "invalid recipient invalid@" in caplog.text
        assert recorder.created[0].sent_messages[0][1] == "valid@example.com"

    @pytest.mark.os_agnostic
    def test_parameter_none_uses_conf_default_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When None, fall back to conf which is True."""
        _install_fake_transport(monkeypatch)
        lib_mail.conf.raise_on_invalid_recipient = True

        with pytest.raises(ValueError, match="invalid recipient"):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="invalid@",
                mail_subject="Subject",
                smtphosts=["smtp.example.com"],
                raise_on_invalid_recipient=None,  # Use default
            )

    @pytest.mark.os_agnostic
    def test_parameter_none_uses_conf_default_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """When None, fall back to conf which is False."""
        recorder = _install_fake_transport(monkeypatch)
        caplog.set_level("WARNING")
        lib_mail.conf.raise_on_invalid_recipient = False

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients=["invalid@", "valid@example.com"],
            mail_subject="Subject",
            smtphosts=["smtp.example.com"],
            raise_on_invalid_recipient=None,  # Use default
        )

        assert result is True
        assert "invalid recipient invalid@" in caplog.text
        assert recorder.created[0].sent_messages[0][1] == "valid@example.com"

    @pytest.mark.os_agnostic
    def test_config_param_supplies_the_default_not_the_global_conf(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With no per-call override, a passed config's own setting governs, not the global conf's opposite one."""
        recorder = _install_fake_transport(monkeypatch)
        lib_mail.conf.raise_on_invalid_recipient = True  # global: strict
        settings = ConfMail(smtphosts=["smtp.example.com"], raise_on_invalid_recipient=False)  # config: tolerant

        result = lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients=["invalid@", "valid@example.com"],
            mail_subject="Subject",
            config=settings,
        )

        assert result is True, "the passed config's tolerant setting must win over the global conf's strict one"
        assert recorder.created[0].sent_messages[0][1] == "valid@example.com"


class _RecordingTransport:
    """Transport double that records the options each delivery received."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, lib_mail.DeliveryOptions]] = []

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: lib_mail.DeliveryOptions) -> None:
        self.calls.append((host, delivery))


@pytest.mark.os_agnostic
def test_send_uses_a_passed_config_and_leaves_the_global_conf_alone() -> None:
    lib_mail.conf.smtphosts = ["global.example.com"]
    config = ConfMail(
        smtphosts=["cfg.example.com:2525"],
        smtp_username="user",
        smtp_password=SecretStr("DUMMY-PLANTED-cfg"),
        smtp_timeout=7.0,
        smtp_use_starttls=False,
    )
    transport = _RecordingTransport()

    lib_mail.send("sender@example.com", "rcpt@example.com", "s", config=config, transport=transport)

    host, delivery = transport.calls[0]
    assert host == "cfg.example.com:2525"
    assert delivery.credentials == ("user", "DUMMY-PLANTED-cfg")
    assert delivery.timeout == 7.0
    assert delivery.use_starttls is False
    assert lib_mail.conf.smtphosts == ["global.example.com"]


@pytest.mark.os_agnostic
def test_an_explicit_keyword_beats_the_passed_config() -> None:
    config = ConfMail(smtphosts=["cfg.example.com"], smtp_timeout=7.0)
    transport = _RecordingTransport()

    lib_mail.send("sender@example.com", "rcpt@example.com", "s", smtphosts=["kw.example.com"], timeout=3.0, config=config, transport=transport)

    host, delivery = transport.calls[0]
    assert (host, delivery.timeout) == ("kw.example.com", 3.0)


@pytest.mark.os_agnostic
def test_a_passed_config_supplies_the_attachment_policy(tmp_path: Path) -> None:
    attachment = tmp_path / "report.pdf"
    attachment.write_bytes(b"%PDF-1.4")
    config = ConfMail(smtphosts=["cfg.example.com"], attachment_allowed_extensions=frozenset({".txt"}))

    with pytest.raises(lib_mail.AttachmentSecurityError):
        lib_mail.send("sender@example.com", "rcpt@example.com", "s", attachment_file_paths=[attachment], config=config, transport=_RecordingTransport())


# ---------------------------------------------------------------------------
# The EHLO name: smtp_local_hostname / send(local_hostname=)
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_the_ehlo_name_is_unset_by_default() -> None:
    assert ConfMail().smtp_local_hostname is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize("name", ["relay.example.test", "[192.0.2.7]", "[IPv6:2001:db8::1]", "host-1"])
def test_a_plausible_ehlo_name_is_accepted(name: str) -> None:
    assert ConfMail(smtp_local_hostname=name).smtp_local_hostname == name


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "name",
    ["", "   ", "two words", "evil\r\nRCPT TO:<x@example.com>", "tab\there", "bell\x07", "bücher.example"],
    ids=["empty", "blank", "space", "crlf", "tab", "control", "non-ascii"],
)
def test_an_ehlo_name_that_cannot_go_on_the_wire_is_refused(name: str) -> None:
    with pytest.raises(ValidationError, match="smtp_local_hostname"):
        ConfMail(smtp_local_hostname=name)


@pytest.mark.os_agnostic
def test_the_config_supplies_the_ehlo_name_and_a_keyword_beats_it() -> None:
    config = ConfMail(smtphosts=["cfg.example.com"], smtp_local_hostname="cfg.example.test")
    transport = _RecordingTransport()

    lib_mail.send("sender@example.com", "rcpt@example.com", "s", config=config, transport=transport)
    lib_mail.send("sender@example.com", "rcpt@example.com", "s", local_hostname="kw.example.test", config=config, transport=transport)

    assert [delivery.local_hostname for _host, delivery in transport.calls] == ["cfg.example.test", "kw.example.test"]


@pytest.mark.os_agnostic
def test_an_unusable_ehlo_keyword_is_refused_before_delivery() -> None:
    transport = _RecordingTransport()

    with pytest.raises(ValueError, match="local_hostname"):
        lib_mail.send("sender@example.com", "rcpt@example.com", "s", smtphosts=["h.example.com"], local_hostname="a b", transport=transport)

    assert transport.calls == []


def _bare_host_fqdn(name: str = "") -> str:
    """A getfqdn() stand-in for a host whose name has no domain part."""
    return "bare-host"


def _documentation_address(name: str) -> str:
    """A gethostbyname() stand-in answering with an RFC 5737 documentation address."""
    return "192.0.2.9"


@pytest.mark.os_agnostic
def test_without_a_dotted_fqdn_the_default_is_the_host_address_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mirrors smtplib: RFC 5321 wants a domain in EHLO, else an address literal."""
    monkeypatch.setattr(socket, "getfqdn", _bare_host_fqdn)
    monkeypatch.setattr(socket, "gethostbyname", _documentation_address)
    _transport._default_local_hostname.cache_clear()
    try:
        assert _transport._default_local_hostname() == "[192.0.2.9]"
    finally:
        _transport._default_local_hostname.cache_clear()


@pytest.mark.os_agnostic
def test_an_unresolvable_host_name_falls_back_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    def unresolvable(name: str) -> str:
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getfqdn", _bare_host_fqdn)
    monkeypatch.setattr(socket, "gethostbyname", unresolvable)
    _transport._default_local_hostname.cache_clear()
    try:
        assert _transport._default_local_hostname() == "[127.0.0.1]"
    finally:
        _transport._default_local_hostname.cache_clear()
