"""Tests for streamed SMTP delivery: dot-stuffing, spool assembly, transport, e2e."""

from __future__ import annotations

# Tests reach into module internals (dot-stuffer, spool composer) by design, and
# aiosmtpd ships no type stubs, so its server/handler objects are untyped here.
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false

import socket
from email import message_from_bytes
from pathlib import Path
from typing import Any, Iterator, cast

import pytest

from btx_lib_mail import lib_mail

aiosmtpd_controller = pytest.importorskip("aiosmtpd.controller")
aiosmtpd_smtp = pytest.importorskip("aiosmtpd.smtp")
Controller = aiosmtpd_controller.Controller
AioSMTP = aiosmtpd_smtp.SMTP
_AIO_MISSING = aiosmtpd_smtp.MISSING


def _read_spool(spool: object) -> bytes:
    """Rewind a returned message spool and read all of its bytes."""
    spool.seek(0)  # type: ignore[attr-defined]
    return spool.read()  # type: ignore[attr-defined]


def _free_port() -> int:
    """Pick a currently-free localhost TCP port for a throwaway server."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _CollectingHandler:
    """aiosmtpd handler that captures each delivered message (DATA path)."""

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.rcpts: list[str] = []

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        self.messages.append(bytes(envelope.content))
        self.rcpts.extend(envelope.rcpt_tos)
        return "250 Message accepted"


class _ChunkingHandler(_CollectingHandler):
    """Collecting handler that also advertises CHUNKING so the client uses BDAT."""

    def __init__(self) -> None:
        super().__init__()
        # Incremented by the BDAT command handler; proves the client took the
        # BDAT branch rather than falling back to DATA.
        self.bdat_command_count = 0

    async def handle_EHLO(self, server: Any, session: Any, envelope: Any, hostname: str, responses: list[str]) -> list[str]:
        session.host_name = hostname
        # Insert CHUNKING before the terminal '250 HELP' line so the multiline
        # EHLO reply stays well-formed.
        return [*responses[:-1], "250-CHUNKING", responses[-1]]


class _BdatSMTP(AioSMTP):
    """aiosmtpd SMTP subclass adding an RFC 3030 BDAT command handler.

    Stock aiosmtpd speaks only DATA, so this minimal receiver reads each
    length-prefixed BDAT chunk straight off the wire and, on the LAST chunk,
    hands the assembled message to the normal DATA hook.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._bdat_data = bytearray()

    async def smtp_BDAT(self, arg: str) -> None:
        parts = (arg or "").split()
        if not parts or not parts[0].isdigit():
            await self.push("501 Syntax: BDAT <size> [LAST]")
            return
        size = int(parts[0])
        last = any(token.upper() == "LAST" for token in parts[1:])
        counter = getattr(self.event_handler, "bdat_command_count", None)
        if counter is not None:
            self.event_handler.bdat_command_count += 1
        if size:
            self._bdat_data += await self._reader.readexactly(size)
        if self.envelope is None:  # pragma: no cover - defensive
            await self.push("503 Error: need MAIL command")
            return
        if last:
            self.envelope.content = bytes(self._bdat_data)
            self._bdat_data = bytearray()
            status = await self._call_handler_hook("DATA")
            await self.push("250 Message accepted" if status is _AIO_MISSING else status)
        else:
            await self.push(f"250 {size} octets received")


class _BdatController(Controller):
    """Controller that serves the BDAT-capable SMTP subclass."""

    def factory(self) -> Any:
        return _BdatSMTP(self.handler)


def _run_server(handler: Any, *, controller_cls: type[Controller] = Controller) -> Controller:
    controller = controller_cls(handler, hostname="127.0.0.1", port=_free_port())
    controller.start()
    return controller


@pytest.fixture
def data_server() -> Iterator[tuple[Controller, _CollectingHandler]]:
    """A real stock aiosmtpd server (no CHUNKING) that forces the DATA path."""
    handler = _CollectingHandler()
    controller = _run_server(handler)
    try:
        yield controller, handler
    finally:
        controller.stop()


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
def test_compose_to_spool_round_trips_headers_body_and_attachment(tmp_path: Path) -> None:
    attachment = tmp_path / "report.pdf"
    payload = b"%PDF-1.4\nbinary\x00\xff bytes\n"
    attachment.write_bytes(payload)

    spool = lib_mail._compose_to_spool(
        sender="sender@example.com",
        recipient="recipient@example.com",
        subject="Grüße",
        plain_body="hello body",
        html_body="",
        attachments=(lib_mail.AttachmentPayload(filename="report.pdf", source=attachment),),
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
def test_compose_to_spool_streams_attachment_without_loading_it(tmp_path: Path) -> None:
    import tracemalloc

    big = tmp_path / "big.bin"
    size = 16 * 1024 * 1024
    big.write_bytes(b"\xab" * size)

    tracemalloc.start()
    try:
        spool = lib_mail._compose_to_spool(
            sender="s@example.com",
            recipient="r@example.com",
            subject="Big",
            plain_body="body",
            html_body="",
            attachments=(lib_mail.AttachmentPayload(filename="big.bin", source=big),),
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    spool.close()

    # The attachment is streamed and base64-encoded in small chunks, never read
    # or encoded whole, so peak heap stays close to the spool's own 1 MiB buffer
    # and far below the 16 MiB payload (which, buffered whole, peaked ~90+ MiB).
    assert peak < 3 * 1024 * 1024, f"peak {peak} bytes suggests the attachment was buffered whole"


@pytest.mark.os_agnostic
def test_compose_to_spool_uses_crlf_line_endings(tmp_path: Path) -> None:
    spool = lib_mail._compose_to_spool(
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
    controller = Controller(
        handler,
        hostname="127.0.0.1",
        port=_free_port(),
        tls_context=tls_context,
        authenticator=authenticator,
        auth_required=True,
    )
    controller.start()
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
