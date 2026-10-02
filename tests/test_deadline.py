"""The delivery deadline bounds a whole SMTP session that the per-operation timeout cannot."""

from __future__ import annotations

import io
import math
import socket
import threading
import time
from typing import IO, TYPE_CHECKING, Any

import pytest

from btx_lib_mail import ConfigurationError, ConfMail, DeliveryOptions, InvalidInputError, send
from btx_lib_mail.lib_mail import SmtplibTransport

if TYPE_CHECKING:
    from collections.abc import Iterator

# One byte every this many seconds: each read finishes well inside the socket timeout,
# so only a bound on the whole session can end it.
_DRIP_INTERVAL = 0.05
_SOCKET_TIMEOUT = 5.0
_DEADLINE = 0.5


class _DripServer:
    """Greets, then answers EHLO one byte at a time and never ends the reply line."""

    def __init__(self) -> None:
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._listener.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, _address = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return  # close() shut the listener
            threading.Thread(target=self._drip, args=(connection,), daemon=True).start()

    def _drip(self, connection: socket.socket) -> None:
        with connection:
            try:
                connection.sendall(b"220 drip.example.com ESMTP\r\n")
                connection.recv(1024)
                connection.sendall(b"250-")
                while not self._stop.is_set():
                    connection.sendall(b"x")
                    time.sleep(_DRIP_INTERVAL)
            except OSError:
                return

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)


@pytest.fixture
def drip_server() -> Iterator[_DripServer]:
    server = _DripServer()
    try:
        yield server
    finally:
        server.close()


def _deliver(port: int, *, deadline: float | None) -> None:
    SmtplibTransport().deliver(
        host=f"127.0.0.1:{port}",
        sender="sender@example.com",
        recipient="recipient@example.com",
        message=io.BytesIO(b"Subject: s\r\n\r\nbody\r\n"),
        delivery=DeliveryOptions(
            credentials=None, use_starttls=False, starttls_verify=True, timeout=_SOCKET_TIMEOUT, local_hostname="client.example.com", deadline=deadline
        ),
    )


@pytest.mark.os_agnostic
def test_without_a_deadline_a_dripping_server_keeps_the_session_open(drip_server: _DripServer) -> None:
    # Positive control: the socket timeout alone does not end this session.
    worker = threading.Thread(target=lambda: _attempt(drip_server.port, deadline=None), daemon=True)
    worker.start()
    worker.join(timeout=4 * _DEADLINE)

    assert worker.is_alive(), "the session should still be blocked on the dripping reply"


def _attempt(port: int, *, deadline: float | None) -> None:
    try:
        _deliver(port, deadline=deadline)
    except OSError:
        return


@pytest.mark.os_agnostic
def test_a_deadline_ends_a_session_the_socket_timeout_cannot(drip_server: _DripServer) -> None:
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            _deliver(drip_server.port, deadline=_DEADLINE)
        except BaseException as error:
            outcome.append(error)

    started = time.monotonic()
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    # Bounded by the test, not by the mechanism under test: without the deadline the
    # session never ends, and the fixture's server shutdown releases the thread.
    worker.join(timeout=_SOCKET_TIMEOUT)
    elapsed = time.monotonic() - started

    assert not worker.is_alive(), "the deadline did not end the session"
    assert len(outcome) == 1
    assert isinstance(outcome[0], TimeoutError)
    assert "delivery deadline of 0.5 seconds" in str(outcome[0])
    assert elapsed < _SOCKET_TIMEOUT


@pytest.mark.os_agnostic
@pytest.mark.parametrize("value", [0.0, -1.0, math.nan, math.inf])
def test_conf_mail_refuses_a_deadline_that_is_not_a_positive_finite_number(value: float) -> None:
    with pytest.raises(ConfigurationError, match="smtp_delivery_deadline must be"):
        ConfMail(smtp_delivery_deadline=value)


@pytest.mark.os_agnostic
def test_send_refuses_a_deadline_that_is_not_positive() -> None:
    with pytest.raises(InvalidInputError, match="delivery_deadline must be positive, got 0"):
        send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], delivery_deadline=0, transport=_Recorder())


class _Recorder:
    def __init__(self) -> None:
        self.deadlines: list[float | None] = []

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: Any) -> None:
        self.deadlines.append(delivery.deadline)


@pytest.mark.os_agnostic
def test_the_deadline_reaches_the_transport_from_the_config_or_the_keyword() -> None:
    recorder = _Recorder()

    send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], config=ConfMail(smtp_delivery_deadline=30), transport=recorder)
    send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], delivery_deadline=5, transport=recorder)
    send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], config=ConfMail(), transport=recorder)

    assert recorder.deadlines == [30.0, 5, None]
