"""The delivery deadline bounds a whole SMTP session that the per-operation timeout cannot."""

# The watchdog is driven on its own where a connect is too fast to leave it a window.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import contextlib
import errno
import gc
import io
import math
import smtplib
import socket
import ssl
import sys
import threading
import time
import warnings
from typing import TYPE_CHECKING, Any

import pytest
from smtp_test_server import self_signed_cert
from transport_doubles import RecordingTransport

from btx_lib_mail import ConfigurationError, ConfMail, DeliveryOptions, InvalidInputError, _transport, _validation, send
from btx_lib_mail.lib_mail import SmtplibTransport

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator
    from pathlib import Path

    from smtp_test_server import CollectingHandler

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


def _deliver(port: int, *, deadline: float | None, use_starttls: bool = False) -> None:
    SmtplibTransport().deliver(
        host=f"127.0.0.1:{port}",
        sender="sender@example.com",
        recipient="recipient@example.com",
        message=io.BytesIO(b"Subject: s\r\n\r\nbody\r\n"),
        delivery=DeliveryOptions(
            credentials=None,
            use_starttls=use_starttls,
            starttls_verify=False,
            timeout=_SOCKET_TIMEOUT,
            local_hostname="client.example.com",
            deadline=deadline,
        ),
    )


def _run_bounded(call: Callable[[], object], *, what: str = "the call") -> tuple[BaseException | None, float]:
    """Run call on a worker bounded by the test, not by the mechanism under test; return what it raised and how long it took.

    A connect left without a timeout waits out the kernel's SYN retries, minutes on Linux;
    on the test's own thread that stalls the suite instead of failing the test by name.
    """
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            call()
        except BaseException as error:
            outcome.append(error)

    started = time.monotonic()
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=_SOCKET_TIMEOUT)
    elapsed = time.monotonic() - started
    if worker.is_alive():
        pytest.fail(f"{what} was still running after {_SOCKET_TIMEOUT} seconds")
    return (outcome[0] if outcome else None), elapsed


@pytest.mark.os_agnostic
def test_without_a_deadline_a_dripping_server_keeps_the_session_open(drip_server: _DripServer) -> None:
    # Positive control: the socket timeout alone does not end this session.
    worker = threading.Thread(target=lambda: _attempt(drip_server.port, deadline=None), daemon=True)
    worker.start()
    worker.join(timeout=4 * _DEADLINE)
    still_open = worker.is_alive()
    drip_server.close()  # ends the drip, so the session ends and the worker with it
    worker.join(timeout=_SOCKET_TIMEOUT)

    assert still_open, "the session should still be blocked on the dripping reply"
    assert not worker.is_alive()


def _attempt(port: int, *, deadline: float | None) -> None:
    try:
        _deliver(port, deadline=deadline)
    except OSError:
        return


@pytest.mark.os_agnostic
def test_a_deadline_ends_a_session_the_socket_timeout_cannot(drip_server: _DripServer) -> None:
    # Without the deadline the session never ends; the fixture's server shutdown releases the worker.
    outcome, elapsed = _deliver_bounded(drip_server.port)

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

    With silent_at, the server stops answering for good: before the greeting ("greeting") or
    once it has read the named command ("EHLO", "RCPT").

    Counts the messages it accepted, so a test can tell "delivered, then QUIT failed" from
    "not delivered".
    """

    def __init__(
        self,
        *,
        drip_greeting: bool = False,
        drip_quit: bool = False,
        quit_reply: bytes = b"221 bye\r\n",
        silent_at: str | None = None,
    ) -> None:
        self.drip_greeting = drip_greeting
        self.silent_at = silent_at
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
                if self.silent_at == "greeting":
                    self._stop.wait()
                    return
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
                    if self.silent_at is not None and verb == self.silent_at.encode():
                        self._stop.wait()
                        return
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
    raised, elapsed = _run_bounded(lambda: _deliver(port, deadline=_DEADLINE), what="the session the deadline should have ended")
    return ([] if raised is None else [raised]), elapsed


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
    assert elapsed < 4 * _DEADLINE


@pytest.mark.os_agnostic
@pytest.mark.parametrize("silent_at", ["greeting", "EHLO", "RCPT"])
def test_a_deadline_ends_a_session_whose_server_falls_silent(silent_at: str) -> None:
    """A peer that sends nothing at all is cut at the deadline, not at the socket timeout."""
    server = _SessionServer(silent_at=silent_at)
    try:
        outcome, elapsed = _deliver_bounded(server.port)
    finally:
        server.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], TimeoutError)
    assert elapsed < 4 * _DEADLINE


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
@pytest.mark.parametrize("quit_reply", [b"500 no\r\n", b"421 closing\r\n", b""], ids=["500", "421", "hang-up"])
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
    connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=_SOCKET_TIMEOUT)  # not connected: no socket yet
    near, far = socket.socketpair()
    finished_reading = threading.Event()
    try:
        with _transport._session_deadline(connection, 0.1):
            time.sleep(0.3)  # the connect, still running when the deadline passes
            connection.sock = near  # what the connect makes once it returns
            connection.cut_handle = near.dup()
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


class _SlowHandshakeServer:
    """Offers STARTTLS, holds the TLS handshake past the deadline, then drips the EHLO reply after it."""

    def __init__(self, directory: Path, *, handshake_delay: float) -> None:
        cert_file, key_file = self_signed_cert(directory)
        self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls.load_cert_chain(certfile=cert_file, keyfile=key_file)
        self._handshake_delay = handshake_delay
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            connection, _address = self._listener.accept()
        except OSError:
            return  # close() shut the listener
        with connection, connection.makefile("rb") as lines:
            try:
                connection.sendall(b"220 tls.example.com ESMTP\r\n")
                for line in lines:
                    if line[:4].upper() == b"EHLO":
                        connection.sendall(b"250-tls.example.com\r\n250 STARTTLS\r\n")
                    elif line[:8].upper() == b"STARTTLS":
                        connection.sendall(b"220 go ahead\r\n")
                        break
                self._stop.wait(self._handshake_delay)
                with self._tls.wrap_socket(connection, server_side=True) as secured:
                    secured.recv(1024)  # EHLO
                    secured.sendall(b"250-")
                    while not self._stop.is_set():
                        secured.sendall(b"x")
                        time.sleep(_DRIP_INTERVAL)
            except OSError:
                return

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)


@pytest.mark.os_agnostic
def test_a_deadline_that_passes_during_the_starttls_handshake_still_ends_the_session(tmp_path: Path) -> None:
    """STARTTLS detached the socket the watchdog held, so its shutdown failed and the deadline was lost for good."""
    server = _SlowHandshakeServer(tmp_path, handshake_delay=2 * _DEADLINE)
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            _deliver(server.port, deadline=_DEADLINE, use_starttls=True)
        except BaseException as error:
            outcome.append(error)

    started = time.monotonic()
    worker = threading.Thread(target=run, daemon=True)
    try:
        worker.start()
        worker.join(timeout=_SOCKET_TIMEOUT)
        elapsed = time.monotonic() - started
        assert not worker.is_alive(), "the deadline did not end the session"
    finally:
        server.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], TimeoutError)
    assert "delivery deadline of 0.5 seconds" in str(outcome[0])
    assert elapsed < 4 * _DEADLINE


@contextlib.contextmanager
def _unanswered_port() -> Generator[int, None, None]:
    """Yield a port whose connects hang: a listener whose backlog is already full."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(0)
    port = listener.getsockname()[1]
    queued: list[socket.socket] = []
    try:
        for _ in range(4):
            client = socket.socket()
            client.setblocking(False)
            with contextlib.suppress(BlockingIOError):
                client.connect(("127.0.0.1", port))
            queued.append(client)
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        except TimeoutError:
            yield port
        except OSError:
            pytest.skip("this platform refuses a connect past a full backlog instead of leaving it waiting")
        else:
            pytest.skip("this platform accepts a connect past a full backlog")
    finally:
        for client in queued:
            client.close()
        listener.close()


@pytest.mark.os_agnostic
def test_a_deadline_bounds_a_tcp_connect_that_hangs() -> None:
    """The connect ran under the socket timeout alone; a listener whose backlog is full never answers it."""
    with _unanswered_port() as port:
        raised, elapsed = _run_bounded(lambda: _deliver(port, deadline=_DEADLINE), what="the connect")

    assert isinstance(raised, TimeoutError), repr(raised)
    assert "delivery deadline of 0.5 seconds" in str(raised)
    assert elapsed < _SOCKET_TIMEOUT / 2


@pytest.mark.os_agnostic
def test_the_deadline_bounds_every_address_a_host_name_resolves_to(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each address got the whole time left, so three that never answer ran the deadline three times over."""
    with _unanswered_port() as port:
        resolved = socket.getaddrinfo("127.0.0.1", port, 0, socket.SOCK_STREAM)

        # The name service is the external edge: a host name with three addresses, none answering.
        def three_addresses(*_args: Any, **_kwargs: Any) -> list[Any]:
            return resolved * 3

        monkeypatch.setattr(socket, "getaddrinfo", three_addresses)
        raised, elapsed = _run_bounded(lambda: _deliver(port, deadline=_DEADLINE), what="every connect")

    assert isinstance(raised, TimeoutError), repr(raised)
    assert "delivery deadline of 0.5 seconds" in str(raised)
    assert elapsed < 2 * _DEADLINE


def _closed_port() -> int:
    """A loopback port nothing listens on, so a connect to it is refused at once."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.os_agnostic
def test_a_host_name_whose_first_address_refuses_is_delivered_through_the_next(
    data_server: tuple[Any, CollectingHandler], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dual-stack name whose first address (often ::1) refuses must still reach the second."""
    controller, handler = data_server
    port = int(controller.port)
    resolved = socket.getaddrinfo("127.0.0.1", _closed_port(), 0, socket.SOCK_STREAM) + socket.getaddrinfo("127.0.0.1", port, 0, socket.SOCK_STREAM)

    # The name service is the external edge: one refusing address, then the server.
    def two_addresses(*_args: Any, **_kwargs: Any) -> list[Any]:
        return resolved

    monkeypatch.setattr(socket, "getaddrinfo", two_addresses)
    _deliver(port, deadline=_SOCKET_TIMEOUT)

    assert len(handler.messages) == 1


@pytest.mark.os_agnostic
def test_a_connected_socket_is_closed_when_its_duplicate_cannot_be_made(monkeypatch: pytest.MonkeyPatch) -> None:
    """smtplib had not stored the socket yet, so a failed dup() left it open until garbage collection."""

    # The descriptor table is the external edge: full, as at the process's open-file limit.
    def no_descriptor_left(_self: socket.socket) -> socket.socket:
        raise OSError(errno.EMFILE, "Too many open files")

    with socket.create_server(("127.0.0.1", 0)) as listener:
        monkeypatch.setattr(socket.socket, "dup", no_descriptor_left)
        # Held until the end: the traceback keeps the failed frame alive, so only an explicit close ends the connection.
        with pytest.raises(OSError, match="Too many open files") as raised:
            _deliver(listener.getsockname()[1], deadline=_SOCKET_TIMEOUT)
        monkeypatch.undo()
        peer, _address = listener.accept()
        with peer:
            peer.settimeout(2)
            assert peer.recv(1) == b"", "the client's socket is still open"

    assert raised.value.errno == errno.EMFILE


@pytest.mark.os_agnostic
def test_a_refused_connect_under_a_deadline_reports_the_refusal() -> None:
    """The last address's own error is raised, not a placeholder saying there was no address."""
    with pytest.raises(ConnectionRefusedError):
        _deliver(_closed_port(), deadline=_SOCKET_TIMEOUT)


_REAL_CONNECT = socket.socket.connect


def _refuse_with_os_timeout(monkeypatch: pytest.MonkeyPatch, port: int) -> None:
    """Make a connect to port fail at once with TimeoutError, as the OS's own SYN-retry limit does."""

    def connect(self: socket.socket, address: Any) -> None:
        if address[1] == port:
            raise TimeoutError(110, "Connection timed out")
        _REAL_CONNECT(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)


@pytest.mark.os_agnostic
def test_an_os_connect_timeout_before_a_working_address_is_not_called_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """The first address timing out left the flag set, so the second's own failure read as the deadline."""
    with socket.create_server(("127.0.0.1", 0)) as hangs_up, socket.create_server(("127.0.0.1", 0)) as unused:
        hangup_port, timed_out_port = hangs_up.getsockname()[1], unused.getsockname()[1]
        first = socket.getaddrinfo("127.0.0.1", timed_out_port, 0, socket.SOCK_STREAM)
        second = socket.getaddrinfo("127.0.0.1", hangup_port, 0, socket.SOCK_STREAM)

        def two_addresses(*_args: Any, **_kwargs: Any) -> list[Any]:
            return first + second

        monkeypatch.setattr(socket, "getaddrinfo", two_addresses)
        _refuse_with_os_timeout(monkeypatch, timed_out_port)

        def hang_up() -> None:
            connection, _address = hangs_up.accept()
            connection.close()

        closer = threading.Thread(target=hang_up, daemon=True)
        closer.start()
        with pytest.raises(smtplib.SMTPServerDisconnected):
            _deliver(hangup_port, deadline=3.0)
        closer.join(timeout=2)


@pytest.mark.os_agnostic
def test_an_os_connect_timeout_well_inside_the_deadline_is_not_called_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """A timeout the OS raised long before the time left ran out is the connect's own failure."""
    with socket.create_server(("127.0.0.1", 0)) as unused:
        port = unused.getsockname()[1]
        _refuse_with_os_timeout(monkeypatch, port)
        with pytest.raises(TimeoutError) as raised:
            _deliver(port, deadline=3.0)

    assert "delivery deadline" not in str(raised.value)


@pytest.mark.os_agnostic
def test_a_name_lookup_that_outlasts_the_deadline_starts_no_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lookup cannot be interrupted, but no connect is attempted once it has used up the deadline."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        resolved = socket.getaddrinfo("127.0.0.1", listener.getsockname()[1], 0, socket.SOCK_STREAM)

        def slow_lookup(*_args: Any, **_kwargs: Any) -> list[Any]:
            time.sleep(2 * _DEADLINE)
            return resolved

        monkeypatch.setattr(socket, "getaddrinfo", slow_lookup)
        with pytest.raises(TimeoutError, match=r"delivery deadline of 0\.5 seconds"):
            _deliver(listener.getsockname()[1], deadline=_DEADLINE)
        listener.settimeout(0.2)
        with pytest.raises(TimeoutError):
            listener.accept()  # nothing connected


@pytest.mark.os_agnostic
def test_a_connect_that_runs_out_of_the_deadline_is_reported_as_the_deadline_before_the_watchdog_fires() -> None:
    """On Windows the bounded connect timed out a clock tick before the watchdog ran and read as a plain timeout."""
    with _unanswered_port() as port:

        def connect() -> None:
            connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=_SOCKET_TIMEOUT)
            with _transport._session_deadline(connection, 30):
                connection.ends_at = time.monotonic() + 0.2  # the watchdog's timer is still 30 seconds away
                connection.connect("127.0.0.1", port)

        raised, _elapsed = _run_bounded(connect, what="the connect")

    assert isinstance(raised, TimeoutError), repr(raised)
    assert "delivery deadline of 30 seconds" in str(raised)


@pytest.mark.os_agnostic
def test_the_watchdog_stops_when_a_session_that_never_connected_ends() -> None:
    """The watchdog waits for a socket after the deadline; a session that ends without one must release it."""
    before = set(threading.enumerate())
    watchdogs: list[threading.Thread] = []

    def session() -> None:
        connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=_SOCKET_TIMEOUT)  # never connected
        with _transport._session_deadline(connection, 0.05):
            time.sleep(0.2)  # the deadline passes while there is no socket
            watchdogs.extend(thread for thread in threading.enumerate() if thread not in before and thread is not threading.current_thread())

    # Bounded by the test: a watchdog that never stops would hold the session open.
    worker = threading.Thread(target=session, daemon=True)
    worker.start()
    worker.join(timeout=2)
    for watchdog in watchdogs:
        watchdog.join(timeout=1)

    assert watchdogs, "positive control: the session started a watchdog"
    assert not worker.is_alive()
    assert not any(watchdog.is_alive() for watchdog in watchdogs)


_TOO_LONG = [10**400, 1e300, _validation._MAX_SECONDS + 0.001]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("keyword", ["timeout", "delivery_deadline"])
@pytest.mark.parametrize("value", _TOO_LONG, ids=["10**400", "1e300", "just-over"])
def test_send_refuses_a_number_of_seconds_no_timer_can_wait(keyword: str, value: float) -> None:
    """10**400 raised a bare OverflowError; 1e300 was accepted, then failed every delivery or killed the watchdog."""
    overrides: dict[str, Any] = {keyword: value}
    label = {"timeout": "smtp_timeout", "delivery_deadline": "delivery_deadline"}[keyword]  # as for every other refused timeout
    with pytest.raises(InvalidInputError, match=rf"^{label} must be at most "):
        send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], transport=RecordingTransport(), **overrides)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("field", ["smtp_timeout", "smtp_delivery_deadline"])
@pytest.mark.parametrize("value", [1e300, _validation._MAX_SECONDS + 0.001], ids=["1e300", "just-over"])
def test_conf_mail_refuses_a_number_of_seconds_no_timer_can_wait(field: str, value: float) -> None:
    with pytest.raises(ConfigurationError, match=f"{field} must be at most "):
        ConfMail.model_validate({field: value})


def _send_with(**overrides: Any) -> RecordingTransport:
    transport = RecordingTransport()
    send("sender@example.com", "one@example.com", "s", smtphosts=["smtp.example.com"], transport=transport, **overrides)
    return transport


@pytest.mark.os_agnostic
def test_the_longest_timeout_is_two_to_the_31_milliseconds() -> None:
    """The ceiling is the Windows socket limit the docs name, not whatever the constant says."""
    assert _send_with(timeout=2_147_483).deliveries
    with pytest.raises(InvalidInputError, match="must be at most 2147483 seconds"):
        _send_with(timeout=2_147_484)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("keyword", ["timeout", "delivery_deadline"])
def test_an_int_too_long_to_print_is_refused_as_invalid_input(keyword: str) -> None:
    """str() refuses an int of more than 4300 digits, so echoing it raised a bare ValueError."""
    with pytest.raises(InvalidInputError, match=r"must be at most 2147483 seconds$"):
        _send_with(**{keyword: 10**5000})


@pytest.mark.os_agnostic
def test_an_int_timeout_reaches_the_transport_as_a_float() -> None:
    timeout = _send_with(timeout=7).deliveries[0].options.timeout

    assert type(timeout) is float
    assert timeout == 7.0


@pytest.mark.os_agnostic
def test_a_refused_zero_timeout_reads_as_a_float() -> None:
    with pytest.raises(InvalidInputError, match=r"smtp_timeout must be positive, got 0\.0$"):
        _send_with(timeout=0)


@pytest.mark.os_agnostic
def test_a_connect_timing_out_on_the_socket_timeout_is_not_called_the_deadline() -> None:
    with _unanswered_port() as port:

        def connect() -> None:
            connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=0.2)
            with _transport._session_deadline(connection, 30):
                connection.connect("127.0.0.1", port)

        raised, _elapsed = _run_bounded(connect, what="the connect")

    assert isinstance(raised, TimeoutError), repr(raised)
    assert "delivery deadline" not in str(raised)


@pytest.mark.os_agnostic
def test_a_connect_started_with_no_time_left_fails_as_the_deadline() -> None:
    connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=_SOCKET_TIMEOUT)
    with _unanswered_port() as port, pytest.raises(TimeoutError, match="delivery deadline of 30 seconds"), _transport._session_deadline(connection, 30):
        connection.ends_at = time.monotonic() - 1  # the watchdog's timer is still 30 seconds away
        connection.connect("127.0.0.1", port)


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="only Windows closes the live socket to wake a silent read")
def test_the_handle_number_a_cut_frees_is_kept_from_other_sockets_until_the_session_closes() -> None:
    """OpenSSL keeps the closed handle number, and Windows gave it to the next new socket, whose bytes a waking read then took."""
    connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=_SOCKET_TIMEOUT)
    connection.ends_at = time.monotonic() + 30  # a session with a deadline keeps a duplicate to cut
    with socket.create_server(("127.0.0.1", 0)) as listener:
        connection.sock = connection._get_socket("127.0.0.1", listener.getsockname()[1], _SOCKET_TIMEOUT)
        live_handle = connection.sock.fileno()

        assert _transport._cut_session(connection)
        guard = connection.handle_guard
        assert guard is not None, "positive control: the cut took a placeholder"
        with socket.socket() as newcomer:
            assert guard.fileno() == live_handle
            assert newcomer.fileno() != live_handle

        connection.close()

    assert connection.handle_guard is None
    assert guard.fileno() == -1


@pytest.mark.os_agnostic
def test_a_session_with_a_deadline_closes_its_duplicate_descriptor() -> None:
    connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=_SOCKET_TIMEOUT)
    with socket.create_server(("127.0.0.1", 0)) as listener:
        try:
            with _transport._session_deadline(connection, 30):
                connection.sock = connection._get_socket("127.0.0.1", listener.getsockname()[1], _SOCKET_TIMEOUT)
                duplicate = connection.cut_handle
                assert duplicate is not None, "positive control: the connect made a duplicate"
        finally:
            if connection.sock is not None:
                connection.sock.close()

    assert duplicate.fileno() == -1
    assert connection.cut_handle is None


@pytest.mark.os_agnostic
def test_no_watchdog_is_still_running_when_a_session_ends() -> None:
    """The watchdog is joined before the duplicate closes, so it never shuts down a reused descriptor."""
    before = set(threading.enumerate())
    connection = _transport._SessionSMTP(local_hostname="client.example.com", timeout=_SOCKET_TIMEOUT)
    with _transport._session_deadline(connection, 30):
        started = [thread for thread in threading.enumerate() if thread not in before]
    alive = [thread for thread in started if thread.is_alive()]

    assert started, "positive control: the session started a watchdog"
    assert alive == []


@pytest.mark.os_agnostic
def test_the_longest_accepted_timeout_and_deadline_still_deliver() -> None:
    server = _SessionServer()
    try:
        assert send(
            "sender@example.com",
            "one@example.com",
            "s",
            smtphosts=[f"127.0.0.1:{server.port}"],
            config=ConfMail(smtp_use_starttls=False, smtp_local_hostname="client.example.com"),
            timeout=_validation._MAX_SECONDS,
            delivery_deadline=_validation._MAX_SECONDS,
        )
    finally:
        server.close()

    assert server.stored == 1


@pytest.mark.os_agnostic
def test_a_failed_session_closes_its_socket() -> None:
    """A session that fails after connecting (here STARTTLS is not offered) must not leave its socket to the collector."""
    server = _SessionServer()
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with pytest.raises(smtplib.SMTPNotSupportedError):
                SmtplibTransport().deliver(
                    host=f"127.0.0.1:{server.port}",
                    sender="sender@example.com",
                    recipient="recipient@example.com",
                    message=io.BytesIO(b"Subject: s\r\n\r\nbody\r\n"),
                    delivery=DeliveryOptions(
                        credentials=None, use_starttls=True, starttls_verify=True, timeout=_SOCKET_TIMEOUT, local_hostname="client.example.com"
                    ),
                )
            gc.collect()
    finally:
        server.close()

    assert [warning for warning in caught if issubclass(warning.category, ResourceWarning)] == []


# Sweep 9 reviewer B: each test below fails on the mutant it was written against.


class _Clock:
    """A monotonic clock the test moves; the clock is the external edge the deadline reads."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.os_agnostic
def test_a_later_address_that_connects_clears_the_ran_out_mark(monkeypatch: pytest.MonkeyPatch) -> None:
    """The first address ran out of its time (inside the clock slack), the second connected: nothing ran out."""
    clock = _Clock()
    with socket.create_server(("127.0.0.1", 0)) as listening, socket.create_server(("127.0.0.1", 0)) as silent:
        good_port, slow_port = listening.getsockname()[1], silent.getsockname()[1]
        addresses = socket.getaddrinfo("127.0.0.1", slow_port, 0, socket.SOCK_STREAM) + socket.getaddrinfo("127.0.0.1", good_port, 0, socket.SOCK_STREAM)

        def connect(self: socket.socket, address: Any) -> None:
            if address[1] == slow_port:
                given = self.gettimeout()
                assert given is not None
                clock.now += given - 0.02  # used its time, within the slack, with time left for the next address
                raise TimeoutError("timed out")
            _REAL_CONNECT(self, address)

        def resolve(*_args: Any, **_kwargs: Any) -> list[Any]:
            return addresses

        monkeypatch.setattr(socket, "getaddrinfo", resolve)
        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(time, "monotonic", clock)
        session = _transport._SessionSMTP(local_hostname="client.example.com", timeout=5.0)
        connected = session._connect_in_time_left("127.0.0.1", good_port, timeout=5.0, ends_at=clock.now + 0.5)
        connected.close()

    assert session.connect_ran_out is False


@pytest.mark.os_agnostic
def test_an_os_timeout_on_a_later_address_counts_only_its_own_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slow refusal on the first address must not make the second's instant OS timeout read as the deadline."""
    clock = _Clock()
    with socket.create_server(("127.0.0.1", 0)) as first, socket.create_server(("127.0.0.1", 0)) as second:
        refusing_port, timing_out_port = first.getsockname()[1], second.getsockname()[1]
        addresses = socket.getaddrinfo("127.0.0.1", refusing_port, 0, socket.SOCK_STREAM) + socket.getaddrinfo(
            "127.0.0.1", timing_out_port, 0, socket.SOCK_STREAM
        )

        def connect(self: socket.socket, address: Any) -> None:
            if address[1] == refusing_port:
                clock.now += 0.3  # refused, slowly
                raise ConnectionRefusedError(111, "Connection refused")
            raise TimeoutError(110, "Connection timed out")  # the OS gave up at once

        def resolve(*_args: Any, **_kwargs: Any) -> list[Any]:
            return addresses

        monkeypatch.setattr(socket, "getaddrinfo", resolve)
        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(time, "monotonic", clock)
        session = _transport._SessionSMTP(local_hostname="client.example.com", timeout=5.0)
        with pytest.raises(TimeoutError):
            session._connect_in_time_left("127.0.0.1", refusing_port, timeout=5.0, ends_at=clock.now + 0.6)

    assert session.connect_ran_out is False
