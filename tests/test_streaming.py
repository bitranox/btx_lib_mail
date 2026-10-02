"""Tests for streamed SMTP delivery: dot-stuffing, spool assembly, transport, e2e."""

from __future__ import annotations

# Tests reach into module internals (dot-stuffer, spool composer) by design, and
# aiosmtpd ships no type stubs, so its server/handler objects are untyped here.
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
import smtplib
import socket
from email import message_from_bytes
from typing import IO, TYPE_CHECKING, Any, cast

import pytest
from click.testing import CliRunner

from btx_lib_mail import cli as cli_mod
from btx_lib_mail import lib_mail

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

from aiosmtpd.controller import Controller
from smtp_test_server import BdatController as _BdatController
from smtp_test_server import ChunkingHandler as _ChunkingHandler
from smtp_test_server import CollectingHandler as _CollectingHandler
from smtp_test_server import run_server as _run_server


def _compose(
    *,
    sender: str,
    recipient: str,
    subject: str,
    plain_body: str,
    html_body: str,
    attachments: tuple[lib_mail.AttachmentPayload, ...],
) -> IO[bytes]:
    """Compose one recipient's whole message the way send() does: shared body plus its header lines."""
    body = lib_mail._compose_body(lib_mail._MessageContent(plain_body=plain_body, html_body=html_body, attachments=attachments))
    try:
        return lib_mail._message_for(lib_mail._envelope_header_lines(sender=sender, recipient=recipient, subject=subject), body)
    finally:
        body.close()


def _read_spool(spool: object) -> bytes:
    """Rewind a returned message spool and read all of its bytes."""
    spool.seek(0)  # type: ignore[attr-defined]
    return spool.read()  # type: ignore[attr-defined]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("controller_cls", [Controller, _BdatController], ids=["data", "bdat"])
def test_the_test_server_never_resolves_the_host_name(monkeypatch: pytest.MonkeyPatch, controller_cls: type[Controller]) -> None:
    """A test server that falls back to socket.getfqdn() stalls on slow reverse DNS (macOS runners)."""

    def refuse(name: str = "") -> str:
        raise AssertionError(f"the test SMTP server called socket.getfqdn({name!r})")

    monkeypatch.setattr(socket, "getfqdn", refuse)

    controller = _run_server(_CollectingHandler(), controller_cls=controller_cls)
    try:
        with socket.create_connection(("127.0.0.1", controller.port), timeout=5) as probe:
            banner = probe.recv(1024)
    finally:
        controller.stop()

    assert banner.startswith(b"220 localhost "), banner


@pytest.fixture
def bdat_server() -> Iterator[tuple[Controller, _ChunkingHandler]]:
    """A real aiosmtpd server advertising CHUNKING that forces the BDAT path."""
    handler = _ChunkingHandler()
    controller = _run_server(handler, controller_cls=_BdatController)
    try:
        yield controller, handler
    finally:
        controller.stop()


# ---------------------------------------------------------------------------
# Incremental dot-stuffing (DATA phase, RFC 5321 section 4.5.2)
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_dot_stuffer_doubles_a_leading_dot_on_a_line() -> None:
    stuffer = lib_mail._DotStuffer()

    result = stuffer.feed(b"hello\r\n.world\r\n")

    assert result == b"hello\r\n..world\r\n"


@pytest.mark.os_agnostic
def test_dot_stuffer_doubles_a_leading_dot_at_the_very_start() -> None:
    stuffer = lib_mail._DotStuffer()

    result = stuffer.feed(b".start\r\n")

    assert result == b"..start\r\n"


@pytest.mark.os_agnostic
def test_dot_stuffer_leaves_a_mid_line_dot_untouched() -> None:
    stuffer = lib_mail._DotStuffer()

    result = stuffer.feed(b"a.b\r\n")

    assert result == b"a.b\r\n"


@pytest.mark.os_agnostic
def test_dot_stuffer_tracks_line_start_across_chunk_boundaries() -> None:
    stuffer = lib_mail._DotStuffer()

    first = stuffer.feed(b"a\r\n")
    # The dot that opens the next line arrives as the first byte of a new chunk.
    second = stuffer.feed(b".x\r\n")

    assert first == b"a\r\n"
    assert second == b"..x\r\n"


# ---------------------------------------------------------------------------
# Message assembly into a spooled temp file
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_compose_round_trips_headers_body_and_attachment(tmp_path: Path) -> None:
    attachment = tmp_path / "report.pdf"
    payload = b"%PDF-1.4\nbinary\x00\xff bytes\n"
    attachment.write_bytes(payload)

    with attachment.open("rb") as handle:
        spool = _compose(
            sender="sender@example.com",
            recipient="recipient@example.com",
            subject="Grüße",
            plain_body="hello body",
            html_body="",
            attachments=(lib_mail.AttachmentPayload(filename="report.pdf", source=attachment, handle=handle),),
        )
    raw = _read_spool(spool)
    message = message_from_bytes(raw)

    assert message["From"] == "sender@example.com"
    assert message["To"] == "recipient@example.com"
    # Non-ASCII subject is RFC 2047 encoded but decodes back.
    from email.header import decode_header, make_header

    assert str(make_header(decode_header(message["Subject"]))) == "Grüße"

    parts = {part.get_filename(): part for part in message.walk() if part.get_filename()}
    assert "report.pdf" in parts
    assert parts["report.pdf"].get_payload(decode=True) == payload

    bodies = [cast("bytes | None", p.get_payload(decode=True)) for p in message.walk() if p.get_content_type() == "text/plain"]
    assert b"hello body" in b"".join(b for b in bodies if b)


@pytest.mark.os_agnostic
def test_compose_streams_attachment_without_loading_it(tmp_path: Path) -> None:
    import tracemalloc

    big = tmp_path / "big.bin"
    size = 16 * 1024 * 1024
    big.write_bytes(b"\xab" * size)

    with big.open("rb") as handle:
        content = lib_mail._MessageContent(
            plain_body="body",
            html_body="",
            attachments=(lib_mail.AttachmentPayload(filename="big.bin", source=big, handle=handle),),
        )
        tracemalloc.start()
        try:
            spool = lib_mail._compose_body(content)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    spool.close()

    # The attachment is streamed and base64-encoded in small chunks, never read
    # or encoded whole, so peak heap stays close to the spool's own 1 MiB buffer
    # and far below the 16 MiB payload (which, buffered whole, peaked ~90+ MiB).
    assert peak < 3 * 1024 * 1024, f"peak {peak} bytes suggests the attachment was buffered whole"


@pytest.mark.os_agnostic
def test_compose_uses_crlf_line_endings(tmp_path: Path) -> None:
    spool = _compose(
        sender="s@example.com",
        recipient="r@example.com",
        subject="Subject",
        plain_body="line one\nline two",
        html_body="",
        attachments=(),
    )
    raw = _read_spool(spool)

    # RFC 5321 wire format: every line ends CRLF, and no bare LF slips through.
    assert b"\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


# ---------------------------------------------------------------------------
# End-to-end delivery against a real in-process SMTP server
# ---------------------------------------------------------------------------


def _plain_text(message: Any) -> str:
    for part in message.walk():
        if part.get_content_type() == "text/plain" and not part.get_filename():
            payload = part.get_payload(decode=True)
            return payload.decode("utf-8") if payload else ""
    return ""


def _attachment_bytes(message: Any, filename: str) -> bytes | None:
    for part in message.walk():
        if part.get_filename() == filename:
            return part.get_payload(decode=True)
    return None


@pytest.mark.os_agnostic
def test_data_path_delivers_and_round_trips(data_server: tuple[Any, _CollectingHandler], tmp_path: Path) -> None:
    controller, handler = data_server
    attachment = tmp_path / "data.bin"
    attachment.write_bytes(b"\x00\x01\x02payload\xff")
    # A body whose lines start with dots exercises the DATA-phase dot-stuffing:
    # a broken stuffer would let ".\r\n" end the message early and truncate it.
    body = "first line\n.dot-led line\n..two dots\nlast line"

    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="DATA path",
        mail_body=body,
        smtphosts=[f"127.0.0.1:{controller.port}"],
        use_starttls=False,
        attachment_file_paths=[attachment],
        attachment_blocked_directories=frozenset(),
        attachment_blocked_extensions=frozenset(),
    )

    assert len(handler.messages) == 1
    received = message_from_bytes(handler.messages[0])
    plain = _plain_text(received)
    assert ".dot-led line" in plain
    assert "..two dots" in plain
    assert "last line" in plain
    assert _attachment_bytes(received, "data.bin") == b"\x00\x01\x02payload\xff"
    assert handler.rcpts == ["rcpt@example.com"]


@pytest.mark.os_agnostic
def test_bdat_path_delivers_and_round_trips(bdat_server: tuple[Any, _ChunkingHandler], tmp_path: Path) -> None:
    controller, handler = bdat_server
    attachment = tmp_path / "report.bin"
    attachment.write_bytes(b"binary\x00\xff\xfe attachment payload")
    body = "chunked delivery\n.leading dot stays intact\nend"

    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="BDAT path",
        mail_body=body,
        smtphosts=[f"127.0.0.1:{controller.port}"],
        use_starttls=False,
        attachment_file_paths=[attachment],
        attachment_blocked_directories=frozenset(),
        attachment_blocked_extensions=frozenset(),
    )

    # The client must have chosen BDAT (server advertised CHUNKING).
    assert handler.bdat_command_count >= 1
    assert len(handler.messages) == 1
    received = message_from_bytes(handler.messages[0])
    assert ".leading dot stays intact" in _plain_text(received)
    assert _attachment_bytes(received, "report.bin") == b"binary\x00\xff\xfe attachment payload"
    assert handler.rcpts == ["rcpt@example.com"]


@pytest.mark.os_agnostic
def test_data_path_handles_a_body_that_is_only_a_dot(data_server: tuple[Any, _CollectingHandler]) -> None:
    controller, handler = data_server

    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="Lone dot",
        mail_body=".",
        smtphosts=[f"127.0.0.1:{controller.port}"],
        use_starttls=False,
    )

    assert len(handler.messages) == 1
    received = message_from_bytes(handler.messages[0])
    assert _plain_text(received).strip() == "."


class _RejectRcptHandler(_CollectingHandler):
    """Server that refuses every recipient, to exercise the RCPT failure path."""

    async def handle_RCPT(self, server: Any, session: Any, envelope: Any, address: str, rcpt_options: list[str]) -> str:
        return "550 no such recipient"


class _RejectDataHandler(_CollectingHandler):
    """Server that accepts the envelope but rejects the message body."""

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        return "550 message rejected"


@pytest.mark.os_agnostic
def test_recipient_rejection_fails_the_send() -> None:
    handler = _RejectRcptHandler()
    controller = _run_server(handler)
    try:
        with pytest.raises(RuntimeError):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="rcpt@example.com",
                mail_subject="Subject",
                mail_body="body",
                smtphosts=[f"127.0.0.1:{controller.port}"],
                use_starttls=False,
            )
    finally:
        controller.stop()
    assert handler.messages == []


@pytest.mark.os_agnostic
def test_data_rejection_fails_the_send() -> None:
    handler = _RejectDataHandler()
    controller = _run_server(handler)
    try:
        with pytest.raises(RuntimeError):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="rcpt@example.com",
                mail_subject="Subject",
                mail_body="body",
                smtphosts=[f"127.0.0.1:{controller.port}"],
                use_starttls=False,
            )
    finally:
        controller.stop()


@pytest.mark.os_agnostic
def test_bdat_rejection_fails_the_send() -> None:
    class _RejectBdatHandler(_ChunkingHandler):
        async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
            return "550 chunk rejected"

    handler = _RejectBdatHandler()
    controller = _run_server(handler, controller_cls=_BdatController)
    try:
        with pytest.raises(RuntimeError):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="rcpt@example.com",
                mail_subject="Subject",
                mail_body="body",
                smtphosts=[f"127.0.0.1:{controller.port}"],
                use_starttls=False,
            )
    finally:
        controller.stop()
    assert handler.bdat_command_count >= 1


# ---------------------------------------------------------------------------
# STARTTLS + AUTH end-to-end (streamed DATA over a TLS-upgraded, authenticated
# session), using a throwaway self-signed cert.
# ---------------------------------------------------------------------------


def _self_signed_cert(tmp_path: Path) -> tuple[str, str]:
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)


@pytest.mark.os_agnostic
def test_starttls_and_auth_path_delivers(tmp_path: Path) -> None:
    import ssl

    from aiosmtpd.smtp import AuthResult, LoginPassword

    cert_file, key_file = _self_signed_cert(tmp_path)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    def authenticator(server: Any, session: Any, envelope: Any, mechanism: str, auth_data: Any) -> Any:
        ok = isinstance(auth_data, LoginPassword) and auth_data.login == b"user" and auth_data.password == b"pass"
        return AuthResult(success=True) if ok else AuthResult(success=False, handled=False)

    handler = _CollectingHandler()
    controller = _run_server(
        handler,
        tls_context=tls_context,
        authenticator=authenticator,
        auth_required=True,
    )
    try:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="rcpt@example.com",
            mail_subject="Secure",
            mail_body="over TLS",
            smtphosts=[f"127.0.0.1:{controller.port}"],
            use_starttls=True,
            starttls_verify=False,  # self-signed throwaway cert
            credentials=("user", "pass"),
        )
    finally:
        controller.stop()

    assert len(handler.messages) == 1
    received = message_from_bytes(handler.messages[0])
    assert "over TLS" in _plain_text(received)


# ---------------------------------------------------------------------------
# Non-ASCII credentials: stdlib smtplib encodes AUTH as ASCII only, so the
# library sends RFC 4616 AUTH PLAIN with UTF-8 itself. Planted dummy only.
# ---------------------------------------------------------------------------

_UTF8_DUMMY = "DUMMY-p\u00e4ssw\u00f6rd-PLANTED-7f3a"


def _utf8_authenticator(seen: list[bool]) -> Any:
    from aiosmtpd.smtp import AuthResult, LoginPassword

    def authenticator(server: Any, session: Any, envelope: Any, mechanism: str, auth_data: Any) -> Any:
        ok = isinstance(auth_data, LoginPassword) and auth_data.login == b"user" and auth_data.password == _UTF8_DUMMY.encode("utf-8")
        seen.append(ok)
        # An explicit 535 message: a bare AuthResult(success=False) left aiosmtpd silent.
        return AuthResult(success=ok, handled=False, message=None if ok else "535 5.7.8 Authentication credentials invalid")

    return authenticator


@pytest.mark.os_agnostic
def test_a_non_ascii_password_authenticates_with_utf8_plain() -> None:
    seen: list[bool] = []
    handler = _CollectingHandler()
    controller = _run_server(handler, authenticator=_utf8_authenticator(seen), auth_require_tls=False, auth_required=True)
    try:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="rcpt@example.com",
            mail_subject="utf8 auth",
            mail_body="body",
            smtphosts=[f"127.0.0.1:{controller.port}"],
            use_starttls=False,
            credentials=("user", _UTF8_DUMMY),
        )
    finally:
        controller.stop()

    assert seen == [True]
    assert len(handler.messages) == 1


@pytest.mark.os_agnostic
def test_credentials_sent_without_tls_are_reported_as_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING", logger="btx_lib_mail")
    seen: list[bool] = []
    controller = _run_server(_CollectingHandler(), authenticator=_utf8_authenticator(seen), auth_require_tls=False, auth_required=True)
    try:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="rcpt@example.com",
            mail_subject="plain auth",
            smtphosts=[f"127.0.0.1:{controller.port}"],
            use_starttls=False,
            credentials=("user", _UTF8_DUMMY),
        )
    finally:
        controller.stop()

    warnings = [record for record in caplog.records if "without TLS" in record.getMessage()]
    assert len(warnings) == 1
    assert f"127.0.0.1:{controller.port}" in warnings[0].getMessage()
    assert _UTF8_DUMMY not in caplog.text


@pytest.mark.os_agnostic
def test_an_anonymous_session_without_tls_logs_no_credential_warning(
    data_server: tuple[Controller, _CollectingHandler], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("WARNING", logger="btx_lib_mail")
    controller, _handler = data_server

    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="anonymous",
        smtphosts=[f"127.0.0.1:{controller.port}"],
        use_starttls=False,
    )

    assert "without TLS" not in caplog.text


@pytest.mark.os_agnostic
def test_a_wrong_non_ascii_password_is_refused_without_quoting_it(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING", logger="btx_lib_mail")
    seen: list[bool] = []
    wrong = "DUMMY-w\u00f6ng-PLANTED-11aa"
    handler = _CollectingHandler()
    controller = _run_server(handler, authenticator=_utf8_authenticator(seen), auth_require_tls=False, auth_required=True)
    try:
        with pytest.raises(RuntimeError):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="rcpt@example.com",
                mail_subject="s",
                smtphosts=[f"127.0.0.1:{controller.port}"],
                use_starttls=False,
                credentials=("user", wrong),
            )
    finally:
        controller.stop()

    assert seen == [False], "positive control: the server received and judged the attempt"
    assert "SMTPAuthenticationError 535" in caplog.text
    assert wrong not in caplog.text
    assert handler.messages == []


@pytest.mark.os_agnostic
def test_a_non_ascii_password_without_plain_fails_clearly(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING", logger="btx_lib_mail")
    seen: list[bool] = []
    # The stock Controller forwards extra keywords to the SMTP instance; this one
    # advertises AUTH LOGIN only (measured: EHLO shows " LOGIN").
    controller = _run_server(
        _CollectingHandler(),
        authenticator=_utf8_authenticator(seen),
        auth_require_tls=False,
        auth_exclude_mechanism=["PLAIN"],
    )
    try:
        with pytest.raises(RuntimeError):
            lib_mail.send(
                mail_from="sender@example.com",
                mail_recipients="rcpt@example.com",
                mail_subject="s",
                smtphosts=[f"127.0.0.1:{controller.port}"],
                use_starttls=False,
                credentials=("user", _UTF8_DUMMY),
            )
    finally:
        controller.stop()

    assert "SMTPNotSupportedError" in caplog.text, "positive control: the refusal was logged"
    assert "AUTH PLAIN" in caplog.text
    assert seen == []
    assert _UTF8_DUMMY not in caplog.text


class _ScriptedSMTP:
    """Stands in for smtplib.SMTP at the AUTH exchange: fixed EHLO features, scripted replies.

    aiosmtpd cannot be made to answer an AUTH PLAIN initial response with 334,
    so the continuation path is driven through this double at the connection
    seam that _login_plain_utf8 takes as its parameter.
    """

    def __init__(self, replies: list[tuple[int, bytes]]) -> None:
        self.esmtp_features = {"auth": "PLAIN LOGIN"}
        self.replies = replies
        self.sent: list[tuple[str, str]] = []

    def has_extn(self, name: str) -> bool:
        return name.lower() in self.esmtp_features

    def docmd(self, cmd: str, args: str = "") -> tuple[int, bytes]:
        self.sent.append((cmd, args))
        return self.replies.pop(0)


@pytest.mark.os_agnostic
def test_a_334_continuation_gets_the_utf8_token_once() -> None:
    server = _ScriptedSMTP([(334, b""), (235, b"2.7.0 Authentication successful")])
    lib_mail._login_plain_utf8(cast("smtplib.SMTP", server), "user", _UTF8_DUMMY)
    assert len(server.sent) == 2
    assert server.sent[0][0] == "AUTH"
    assert server.sent[1][0] == server.sent[0][1].removeprefix("PLAIN ")


@pytest.mark.os_agnostic
def test_a_503_already_authenticated_reply_is_treated_as_success() -> None:
    """smtplib.SMTP.login treats 503 the same as 235; _login_plain_utf8 mirrors that."""
    server = _ScriptedSMTP([(503, b"5.5.1 already authenticated")])
    lib_mail._login_plain_utf8(cast("smtplib.SMTP", server), "user", _UTF8_DUMMY)
    assert len(server.sent) == 1, "one AUTH command, no continuation, no raise"


@pytest.mark.os_agnostic
def test_a_second_334_is_refused_not_looped() -> None:
    server = _ScriptedSMTP([(334, b""), (334, b"")])
    with pytest.raises(smtplib.SMTPAuthenticationError) as caught:
        lib_mail._login_plain_utf8(cast("smtplib.SMTP", server), "user", _UTF8_DUMMY)
    assert caught.value.smtp_code == 334
    assert len(server.sent) == 2


# ---------------------------------------------------------------------------
# The EHLO name the client announces (smtplib's local_hostname)
# ---------------------------------------------------------------------------


class _EhloRecordingHandler(_CollectingHandler):
    """Collecting handler that also records the name each client announced in EHLO."""

    def __init__(self) -> None:
        super().__init__()
        self.ehlo_names: list[str] = []

    async def handle_EHLO(self, server: Any, session: Any, envelope: Any, hostname: str, responses: list[str]) -> list[str]:
        session.host_name = hostname
        self.ehlo_names.append(hostname)
        return responses


@pytest.fixture
def ehlo_server() -> Iterator[tuple[Controller, _EhloRecordingHandler]]:
    handler = _EhloRecordingHandler()
    controller = _run_server(handler)
    try:
        yield controller, handler
    finally:
        controller.stop()


@pytest.fixture
def fresh_local_name_cache() -> Iterator[None]:
    """Start and end with no cached default EHLO name, so a planted one never leaks."""
    lib_mail._default_local_hostname.cache_clear()
    yield
    lib_mail._default_local_hostname.cache_clear()


def _send_two(controller: Controller, **kwargs: Any) -> None:
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients=["one@example.com", "two@example.com"],
        mail_subject="EHLO",
        mail_body="body",
        smtphosts=[f"127.0.0.1:{controller.port}"],
        use_starttls=False,
        **kwargs,
    )


@pytest.mark.os_agnostic
def test_a_configured_ehlo_name_is_announced_without_a_lookup(
    ehlo_server: tuple[Controller, _EhloRecordingHandler], monkeypatch: pytest.MonkeyPatch, fresh_local_name_cache: None
) -> None:
    controller, handler = ehlo_server

    def refuse(name: str = "") -> str:
        raise AssertionError(f"the client called socket.getfqdn({name!r}) although a name was configured")

    monkeypatch.setattr(socket, "getfqdn", refuse)

    _send_two(controller, config=lib_mail.ConfMail(smtp_local_hostname="relay.example.test"))

    assert handler.ehlo_names == ["relay.example.test", "relay.example.test"]


@pytest.mark.os_agnostic
def test_the_default_ehlo_name_is_resolved_once_per_process(
    ehlo_server: tuple[Controller, _EhloRecordingHandler], monkeypatch: pytest.MonkeyPatch, fresh_local_name_cache: None
) -> None:
    controller, handler = ehlo_server
    lookups: list[str] = []

    def counting_getfqdn(name: str = "") -> str:
        lookups.append(name)
        return "client.example.test"

    monkeypatch.setattr(socket, "getfqdn", counting_getfqdn)

    _send_two(controller)
    _send_two(controller)

    assert handler.ehlo_names == ["client.example.test"] * 4
    assert len(lookups) == 1, f"one lookup per process, got {len(lookups)} for four connections"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("from_env", [False, True], ids=["option", "env"])
def test_the_cli_announces_the_local_hostname(
    ehlo_server: tuple[Controller, _EhloRecordingHandler],
    fresh_local_name_cache: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    from_env: bool,
) -> None:
    # The CLI also reads BTX_MAIL_* from the environment (and a named env file); a
    # developer's credentials there would make it log in to this AUTH-less server.
    for key in ("BTX_MAIL_ENV_FILE", "BTX_MAIL_SMTP_USERNAME", "BTX_MAIL_SMTP_PASSWORD", "BTX_MAIL_SMTP_LOCAL_HOSTNAME", "BTX_MAIL_SENDER"):
        monkeypatch.delenv(key, raising=False)
    name_args = ["--local-hostname", "cli.example.test"]
    if from_env:
        monkeypatch.setenv("BTX_MAIL_SMTP_LOCAL_HOSTNAME", "cli.example.test")
        name_args = []
    controller, handler = ehlo_server
    result = CliRunner().invoke(
        cli_mod.cli,
        [
            "send",
            "--host",
            f"127.0.0.1:{controller.port}",
            "--recipient",
            "rcpt@example.com",
            "--subject",
            "s",
            "--body",
            "b",
            "--no-starttls",
            *name_args,
        ],
    )

    assert result.exit_code == 0, result.output
    assert handler.ehlo_names == ["cli.example.test"]
