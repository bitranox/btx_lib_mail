"""The delivery deadline bounds a whole SMTP session that the per-operation timeout cannot."""

# The watchdog is driven on its own where a connect is too fast to leave it a window.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import contextlib
import io
import math
import smtplib
import socket
import threading
import time
from typing import TYPE_CHECKING

import pytest
from transport_doubles import RecordingTransport

from btx_lib_mail import ConfigurationError, ConfMail, DeliveryOptions, InvalidInputError, _transport, send
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
        self._drips: list[threading.Thread] = []
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
            drip = threading.Thread(target=self._drip, args=(connection,), daemon=True)
            self._drips.append(drip)
            drip.start()

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
        # The drip threads are joined too, so none outlives its test into the next one.
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)
        for drip in self._drips:
            drip.join(timeout=2)


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
        send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], delivery_deadline=0, transport=RecordingTransport())


@pytest.mark.os_agnostic
def test_the_deadline_reaches_the_transport_from_the_config_or_the_keyword() -> None:
    recorder = RecordingTransport()

    send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], config=ConfMail(smtp_delivery_deadline=30), transport=recorder)
    send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], delivery_deadline=5, transport=recorder)
    send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], config=ConfMail(), transport=recorder)

    assert [delivery.options.deadline for delivery in recorder.deliveries] == [30.0, 5, None]


class _SessionServer:
    """A plain SMTP session whose greeting or QUIT reply can drip, or whose QUIT reply can be refused.

    Counts the messages it accepted, so a test can tell "delivered, then QUIT failed" from
    "not delivered".
    """

    def __init__(self, *, drip_greeting: bool = False, drip_quit: bool = False, quit_reply: bytes = b"221 bye\r\n") -> None:
        self.drip_greeting = drip_greeting
        self.drip_quit = drip_quit
        self.quit_reply = quit_reply
        self.stored = 0
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._sessions: list[threading.Thread] = []
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
            session = threading.Thread(target=self._session, args=(connection,), daemon=True)
            self._sessions.append(session)
            session.start()

    def _send(self, connection: socket.socket, data: bytes, *, drip: bool) -> None:
        if not drip:
            connection.sendall(data)
            return
        while not self._stop.is_set():  # never finishes the line
            connection.sendall(data[:1])
            time.sleep(_DRIP_INTERVAL)

    def _session(self, connection: socket.socket) -> None:
        with connection, connection.makefile("rb") as lines:
            try:
                self._send(connection, b"220 session.example.com ESMTP\r\n", drip=self.drip_greeting)
                in_data = False
                for line in lines:
                    if in_data:
                        if line == b".\r\n":
                            in_data = False
                            self.stored += 1
                            connection.sendall(b"250 queued\r\n")
                        continue
                    verb = line[:4].upper()
                    if verb == b"QUIT":
                        self._send(connection, self.quit_reply, drip=self.drip_quit)
                        return
                    if verb == b"DATA":
                        in_data = True
                        connection.sendall(b"354 go ahead\r\n")
                    elif verb == b"EHLO":
                        connection.sendall(b"250-session.example.com\r\n250 8BITMIME\r\n")
                    else:
                        connection.sendall(b"250 ok\r\n")
            except OSError:
                return

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)
        for session in self._sessions:
            session.join(timeout=2)


def _deliver_bounded(port: int) -> tuple[list[BaseException], float]:
    """Deliver once with the short deadline, bounded by the test; return what was raised and how long it took."""
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            _deliver(port, deadline=_DEADLINE)
        except BaseException as error:
            outcome.append(error)

    started = time.monotonic()
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=_SOCKET_TIMEOUT)
    assert not worker.is_alive(), "the deadline did not end the session"
    return outcome, time.monotonic() - started


@pytest.mark.os_agnostic
def test_a_deadline_bounds_a_greeting_that_drips() -> None:
    """The greeting is read while connecting; that read is inside the deadline too."""
    server = _SessionServer(drip_greeting=True)
    try:
        outcome, elapsed = _deliver_bounded(server.port)
    finally:
        server.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], TimeoutError)
    assert elapsed < _SOCKET_TIMEOUT


@pytest.mark.os_agnostic
def test_a_deadline_bounds_a_quit_reply_that_drips_and_the_message_still_counts_as_sent() -> None:
    server = _SessionServer(drip_quit=True)
    try:
        outcome, elapsed = _deliver_bounded(server.port)
    finally:
        server.close()

    assert outcome == []
    assert server.stored == 1
    assert elapsed < 4 * _DEADLINE


@pytest.mark.os_agnostic
@pytest.mark.parametrize("quit_reply", [b"500 no\r\n", b"421 closing\r\n"], ids=["500", "421"])
def test_a_refused_quit_after_the_message_was_accepted_is_a_delivery_not_a_host_failure(quit_reply: bytes) -> None:
    """The server stored the message; trying the next host would deliver it twice."""
    first = _SessionServer(quit_reply=quit_reply)
    second = _SessionServer()
    try:
        assert send(
            "sender@example.com",
            "one@example.com",
            "s",
            smtphosts=[f"127.0.0.1:{first.port}", f"127.0.0.1:{second.port}"],
            config=ConfMail(smtp_use_starttls=False, smtp_local_hostname="client.example.com", smtp_timeout=_SOCKET_TIMEOUT),
        )
    finally:
        first.close()
        second.close()

    assert (first.stored, second.stored) == (1, 0)


@pytest.mark.os_agnostic
def test_a_deadline_that_passes_before_the_socket_exists_still_ends_the_read_after_it() -> None:
    """A slow TCP connect can outlast the deadline; the greeting read that follows must still be cut."""
    connection = smtplib.SMTP(local_hostname="client.example.com")  # not connected: no socket yet
    near, far = socket.socketpair()
    finished_reading = threading.Event()
    try:
        with _transport._session_deadline(connection, 0.1):
            time.sleep(0.3)  # the connect, still running when the deadline passes
            connection.sock = near
            near.settimeout(_SOCKET_TIMEOUT)
            started = time.monotonic()
            with contextlib.suppress(OSError):
                near.recv(1)  # far never writes: only the watchdog can end this read
            finished_reading.set()
            elapsed = time.monotonic() - started
    finally:
        near.close()
        far.close()

    assert finished_reading.is_set()
    assert elapsed < _SOCKET_TIMEOUT / 2
