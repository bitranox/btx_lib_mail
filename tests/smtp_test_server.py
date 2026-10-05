"""A real in-process aiosmtpd server for tests that need one (DATA and BDAT)."""

from __future__ import annotations

# aiosmtpd ships no type stubs, so its server/handler objects are untyped here.
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
import contextlib
import datetime
import ipaddress
import socket
from typing import TYPE_CHECKING, Any

from aiosmtpd import smtp as aiosmtpd_smtp
from aiosmtpd.controller import Controller
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from pathlib import Path


def free_port() -> int:
    """Pick a currently-free localhost TCP port for a throwaway server."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class CollectingHandler:
    """aiosmtpd handler that captures each delivered message (DATA path)."""

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.rcpts: list[str] = []

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        self.messages.append(bytes(envelope.content))
        self.rcpts.extend(envelope.rcpt_tos)
        return "250 Message accepted"


class ChunkingHandler(CollectingHandler):
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


class BdatSMTP(aiosmtpd_smtp.SMTP):
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
            await self.push("250 Message accepted" if status is aiosmtpd_smtp.MISSING else status)
        else:
            await self.push(f"250 {size} octets received")


class BdatController(Controller):
    """Controller that serves the BDAT-capable SMTP subclass."""

    def factory(self) -> Any:
        return BdatSMTP(self.handler, **self.SMTP_kwargs)


# A working server reports ready in well under a second.
SERVER_READY_TIMEOUT = 8.0
SERVER_BIND_ATTEMPTS = 3
# The name the test server announces. Without one, aiosmtpd's SMTP falls back to
# socket.getfqdn(), a reverse DNS lookup run inside the server thread on the first
# connection; on macOS CI runners it takes about 30 s, so every start timed out.
SERVER_NAME = "localhost"


def run_server(handler: Any, *, controller_cls: type[Controller] = Controller, **controller_kwargs: Any) -> Controller:
    # free_port() releases the port before the server binds it, so another process
    # can take it in between: only that bind failure is retried, on a fresh port.
    # Any other start failure is a real defect and fails the test.
    for attempt in range(1, SERVER_BIND_ATTEMPTS + 1):
        controller = controller_cls(
            handler,
            hostname="127.0.0.1",
            port=free_port(),
            ready_timeout=SERVER_READY_TIMEOUT,
            server_hostname=SERVER_NAME,
            **controller_kwargs,
        )
        try:
            controller.start()
        except TimeoutError:
            # A subclass of OSError, but a server that bound and then did not
            # answer is not the bind race, so it is never retried.
            raise
        except OSError:
            with contextlib.suppress(Exception):
                controller.stop()
            if attempt == SERVER_BIND_ATTEMPTS:
                raise
            continue
        return controller
    raise AssertionError("unreachable: the last bind attempt either returns or raises")


def self_signed_cert(directory: Path) -> tuple[str, str]:
    """Write a throwaway self-signed certificate for 127.0.0.1 and its key; return both paths."""
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
    cert_file = directory / "cert.pem"
    key_file = directory / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)
