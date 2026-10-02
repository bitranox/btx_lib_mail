"""Streaming a message to the server holds about one chunk in memory, not the message.

aiosmtpd keeps the whole received message in memory inside this process, which
would swamp a ``tracemalloc`` reading, so the server here is a minimal sink that
answers the SMTP dialogue and discards the payload into one preallocated buffer.
"""

from __future__ import annotations

import socket
import tempfile
import threading
import tracemalloc
from typing import TYPE_CHECKING

import pytest

from btx_lib_mail import DeliveryOptions
from btx_lib_mail.lib_mail import SmtplibTransport

if TYPE_CHECKING:
    import io
    from collections.abc import Iterator

_MESSAGE_SIZE = 8 * 1024 * 1024
_RECEIVE_BUFFER = 64 * 1024
# A fixed bound, deliberately NOT derived from the library's chunk size: a test whose
# limit grows with the constant it guards passes however large that constant becomes.
# One 64 KiB chunk plus its dot-stuffed copy fits with plenty of room; the 8 MiB
# message read at once does not.
_PEAK_LIMIT = 2 * 1024 * 1024


class _SinkServer:
    """Speaks just enough SMTP for one delivery and throws the payload away."""

    def __init__(self, *, chunking: bool) -> None:
        self._chunking = chunking
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self.received = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        connection, _address = self._listener.accept()
        with connection:
            reader = connection.makefile("rb")
            buffer = bytearray(_RECEIVE_BUFFER)
            connection.sendall(b"220 sink.example.com ESMTP\r\n")
            while line := reader.readline():
                if not self._answer(connection, reader, line, buffer):
                    return

    def _answer(self, connection: socket.socket, reader: io.BufferedReader, line: bytes, buffer: bytearray) -> bool:
        verb = line[:4].upper()
        if verb == b"EHLO":
            extensions = b"250-sink.example.com\r\n250-CHUNKING\r\n250 8BITMIME\r\n" if self._chunking else b"250 sink.example.com\r\n"
            connection.sendall(extensions)
        elif verb == b"DATA":
            connection.sendall(b"354 go ahead\r\n")
            self._discard_until_dot(reader)
            connection.sendall(b"250 ok\r\n")
        elif verb == b"BDAT":
            parts = line.split()
            self._discard_exactly(reader, int(parts[1]), buffer)
            connection.sendall(b"250 ok\r\n")
        elif verb == b"QUIT":
            connection.sendall(b"221 bye\r\n")
            return False
        else:
            connection.sendall(b"250 ok\r\n")
        return True

    def _discard_until_dot(self, reader: io.BufferedReader) -> None:
        while True:
            line = reader.readline()
            if line in (b".\r\n", b""):
                return
            self.received += len(line)

    def _discard_exactly(self, reader: io.BufferedReader, size: int, buffer: bytearray) -> None:
        view = memoryview(buffer)
        while size:
            got = reader.readinto(view[: min(size, len(buffer))])
            if not got:
                return
            size -= got
            self.received += got

    def close(self) -> None:
        self._listener.close()
        self._thread.join(timeout=5)


@pytest.fixture(params=[False, True], ids=["data", "bdat"])
def sink(request: pytest.FixtureRequest) -> Iterator[_SinkServer]:
    server = _SinkServer(chunking=bool(request.param))
    try:
        yield server
    finally:
        server.close()


@pytest.mark.os_agnostic
def test_streaming_a_large_message_holds_about_one_chunk(sink: _SinkServer) -> None:
    with tempfile.TemporaryFile() as message:
        line = b"x" * 998 + b"\r\n"
        while message.tell() < _MESSAGE_SIZE:
            message.write(line)
        message.seek(0)
        delivery = DeliveryOptions(credentials=None, use_starttls=False, starttls_verify=True, timeout=30.0, local_hostname="client.example.com")

        tracemalloc.start()
        try:
            SmtplibTransport().deliver(host=f"127.0.0.1:{sink.port}", sender="s@example.com", recipient="r@example.com", message=message, delivery=delivery)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

    assert sink.received >= _MESSAGE_SIZE, "positive control: the whole message reached the server"
    assert peak < _PEAK_LIMIT, f"peak {peak} bytes while streaming {_MESSAGE_SIZE} bytes: the message was not streamed in chunks"
