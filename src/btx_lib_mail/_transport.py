"""The delivery seam (Transport, DeliveryOptions) and the stdlib SMTP transport.

The transport streams a message to the server as RFC 3030 BDAT chunks or
through the DATA phase with dot-stuffing.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import _socket
import base64
import functools
import smtplib
import socket
import ssl
import sys
import threading
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import IO, TYPE_CHECKING, Final, Protocol

from ._common import logger, printable
from ._validation import parse_smtp_host

if TYPE_CHECKING:
    from collections.abc import Generator


@dataclass(frozen=True)
class DeliveryOptions:
    """Capture the resolved runtime knobs for a single delivery attempt.

    Bundles them into one immutable object so low-level helpers receive a
    single argument instead of a long parameter list.

    Attributes:
        credentials: (username, password) pair, or None when anonymous
            delivery is requested.
        use_starttls: True enables STARTTLS handshakes.
        starttls_verify: True verifies the server certificate and hostname
            during STARTTLS; False keeps the traffic encrypted but skips
            verification (for internal self-signed relays).
        timeout: Socket timeout (seconds) applied to SMTP connections.
        local_hostname: Name announced in EHLO; None lets the transport use
            the host's own name, looked up once per process.
        deadline: Upper bound in seconds for the whole SMTP session once
            connected; None sets none.
    """

    # repr=False: a transport or a debugger printing the options must not print the password.
    credentials: tuple[str, str] | None = field(repr=False)
    use_starttls: bool
    starttls_verify: bool
    timeout: float
    # Defaulted so a DeliveryOptions built without them keeps the behaviour of having none.
    local_hostname: str | None = None
    deadline: float | None = None


@functools.cache
def _default_local_hostname() -> str:
    """Return the EHLO name smtplib would compute, looked up once per process.

    smtplib calls socket.getfqdn() (a reverse DNS lookup) for every
    connection it opens without local_hostname, and delivery opens one
    connection per recipient; on a host with slow reverse DNS each one waits
    for it. The rule is smtplib's own: the FQDN when it has a dot, else an
    address literal (RFC 5321 section 4.1.3).

    Returns:
        The FQDN when it contains a dot, otherwise a bracketed IP address
        literal.
    """
    fqdn = socket.getfqdn()
    if "." in fqdn:
        return fqdn
    try:
        return f"[{socket.gethostbyname(socket.gethostname())}]"
    except socket.gaierror:
        return "[127.0.0.1]"


def _build_starttls_context(*, verify: bool) -> ssl.SSLContext:
    """Return the SSL context used for the STARTTLS handshake.

    Internal relays often present a self-signed certificate or one whose
    hostname does not match. Verifying such a certificate makes starttls fail
    even though the channel would still be encrypted. verify=False lets an
    operator keep encryption while opting out of validation, which is
    strictly better than falling back to plaintext.

    Args:
        verify: True returns the standard verifying context (certificate
            chain and hostname checked). False disables both checks.

    Returns:
        A verifying context by default, or a non-verifying one when verify
        is False.
    """
    context = ssl.create_default_context()
    if not verify:
        # Opt-in for internal self-signed relays: the channel stays encrypted,
        # only certificate and hostname validation are dropped. check_hostname
        # must be cleared before verify_mode, or assigning CERT_NONE raises
        # ValueError while hostname checking is still on.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


# Bytes read from the spooled message per socket write. Bounds peak delivery
# memory to roughly one chunk rather than the whole payload.
STREAM_CHUNK_SIZE: Final[int] = 64 * 1024


# RFC 5321 SMTP reply codes used to gate the streamed DATA/BDAT protocol steps.
_SMTP_OK: Final[int] = 250


_SMTP_WILL_FORWARD: Final[int] = 251


_SMTP_START_MAIL_INPUT: Final[int] = 354


_SMTP_AUTH_OK: Final[int] = 235


_SMTP_AUTH_CONTINUE: Final[int] = 334


# smtplib.SMTP.login treats 503 ("already authenticated") as success; mirrored here.
_SMTP_ALREADY_AUTHENTICATED: Final[int] = 503


# Length of a CRLF line terminator; used to detect whether the DATA phase
# already ended on a line boundary before appending the terminal "." line.
_CRLF_LEN: Final[int] = 2


class Transport(Protocol):
    """Delivery seam that decouples failover orchestration from the SMTP wire protocol.

    An alternative transport (or a test double) is injected through this seam
    rather than monkeypatched over smtplib. An implementation delivers one
    already-composed message to one recipient via one host and raises on any
    failure so the caller can fall over to the next host. An OSError
    (including any smtplib.SMTPException) raised by deliver() is logged with
    its text, stripped of control characters; any other exception is logged
    by type name only. Do not put a credential into the text of an OSError.
    """

    def deliver(
        self,
        *,
        host: str,
        sender: str,
        recipient: str,
        message: IO[bytes],
        delivery: DeliveryOptions,
    ) -> None:
        """Deliver a message to one recipient via one host.

        Args:
            host: SMTP host spec consumed by parse_smtp_host (host[:port]).
            sender: Envelope sender address.
            recipient: Envelope recipient address.
            message: Rewindable byte stream holding the already-composed
                message.
            delivery: Resolved delivery options (STARTTLS, credentials,
                timeouts, deadline).
        """
        ...


class SmtplibTransport:
    """Production Transport that streams the message instead of buffering it whole.

    It streams to the server over smtplib chunk by chunk. When the server
    advertises CHUNKING (RFC 3030) it frames the body with BDAT; otherwise it
    drives the classic DATA phase with incremental dot-stuffing. Either way
    peak transfer memory is about one chunk.
    """

    def deliver(
        self,
        *,
        host: str,
        sender: str,
        recipient: str,
        message: IO[bytes],
        delivery: DeliveryOptions,
    ) -> None:
        """Deliver a message to one recipient via one host over smtplib.

        Args:
            host: SMTP host spec consumed by parse_smtp_host (host[:port]).
            sender: Envelope sender address.
            recipient: Envelope recipient address.
            message: Rewindable byte stream holding the already-composed
                message.
            delivery: Resolved delivery options (STARTTLS, credentials,
                timeouts, deadline).
        """
        hostname, port = parse_smtp_host(host)
        local_hostname = delivery.local_hostname or _default_local_hostname()
        # Not connected yet: the greeting is read while connecting, and that read
        # belongs inside the deadline. No `with`: its exit turns a QUIT reply other
        # than 221 into a failure, after the server has already taken the message.
        smtp_connection = _SessionSMTP(local_hostname=local_hostname, timeout=delivery.timeout)
        try:
            with _session_deadline(smtp_connection, delivery.deadline):
                smtp_connection.connect(hostname, port or 0)
                _prepare_session(smtp_connection, host=host, delivery=delivery)
                _send_message(smtp_connection, sender=sender, recipient=recipient, message=message)
                _quit_quietly(smtp_connection)
        finally:
            smtp_connection.close()


def _prepare_session(smtp_connection: smtplib.SMTP, *, host: str, delivery: DeliveryOptions) -> None:
    """Greet, secure and authenticate a connected session."""
    smtp_connection.ehlo_or_helo_if_needed()
    if delivery.use_starttls:
        smtp_connection.starttls(context=_build_starttls_context(verify=delivery.starttls_verify))
        # RFC 3207: server capabilities must be re-fetched after TLS.
        smtp_connection.ehlo()
    if delivery.credentials is not None:
        if not delivery.use_starttls:
            # Allowed (an internal relay may offer no TLS), but never silently.
            logger.warning(
                'sending SMTP credentials to host "%s" without TLS (STARTTLS is off)',
                printable(host),
                extra={"host": printable(host)},
            )
        username, password = delivery.credentials
        _authenticate(smtp_connection, username, password)
    smtp_connection.ehlo_or_helo_if_needed()


def _send_message(smtp_connection: smtplib.SMTP, *, sender: str, recipient: str, message: IO[bytes]) -> None:
    """Send one message over a prepared session, with BDAT where the server offers CHUNKING."""
    message.seek(0)
    if smtp_connection.has_extn("chunking"):
        _send_via_bdat(smtp_connection, sender, recipient, message)
    else:
        _send_via_data(smtp_connection, sender, recipient, message)


def _quit_quietly(smtp_connection: smtplib.SMTP) -> None:
    """Say QUIT after the server accepted the message; how it answers changes nothing.

    The message is delivered once the final reply to DATA or BDAT LAST is 250.
    Counting a refused or lost QUIT as a failed host would send the message
    again through the next host, or report as failed a message the server kept.
    """
    with suppress(smtplib.SMTPException, OSError):
        smtp_connection.quit()


# How often the deadline watchdog looks for a socket that a running connect has not made yet.
_SOCKET_POLL_SECONDS: Final[float] = 0.05

# A connect started with a sliver of time left still gets this long, so it fails as a
# timeout rather than as a non-blocking connect.
_MIN_CONNECT_SECONDS: Final[float] = 0.001

# One entry of socket.getaddrinfo(): family, socket kind, protocol, canonical name, address.
_AddressInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, "tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]"]


class _SessionSMTP(smtplib.SMTP):
    """smtplib.SMTP whose session the delivery deadline can cut, through STARTTLS too.

    STARTTLS detaches the plain socket and hands its descriptor to an SSL
    socket, so the socket object the session started with can no longer be
    shut down. A duplicate descriptor names the same connection whatever wraps
    it: shutting it down ends a read blocked in the TLS handshake as well as
    any read after it.

    Attributes:
        ends_at: The ``time.monotonic()`` value at which the deadline passes,
            or None when the session has no deadline.
        cut_handle: Duplicate of the TCP socket for the deadline watchdog,
            made when a session with a deadline connects.
        connect_ran_out: True when the TCP connect timed out on the time
            left before the deadline rather than on the socket timeout.
    """

    def __init__(self, *, local_hostname: str, timeout: float) -> None:
        """Create an unconnected session.

        Args:
            local_hostname: Name announced in EHLO.
            timeout: Socket timeout in seconds for each read or write.
        """
        super().__init__(local_hostname=local_hostname, timeout=timeout)
        self.ends_at: float | None = None
        self.cut_handle: socket.socket | None = None
        self.connect_ran_out = False

    # smtplib's own hook for the TCP connect (SMTP_SSL and LMTP override it too).
    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        # starttls() names the server for TLS by self._host, which connect() sets
        # only from Python 3.14 on; a session created without a host would
        # otherwise wrap with an empty server_hostname and refuse.
        self._host = host
        if self.ends_at is None:
            return socket.create_connection((host, port), timeout, self.source_address)
        connection_socket = self._connect_in_time_left(host, port, timeout=timeout, ends_at=self.ends_at)
        # The reads and writes after the connect keep the socket timeout.
        connection_socket.settimeout(timeout)
        self.cut_handle = connection_socket.dup()
        return connection_socket

    def _connect_in_time_left(self, host: str, port: int, *, timeout: float, ends_at: float) -> socket.socket:
        """Try each address host resolves to, each attempt bounded by what is left of the deadline.

        socket.create_connection() gives every address the same timeout, so a host
        name with several addresses that never answer ran the deadline several
        times over. The name lookup itself cannot be interrupted; once it has used
        up the deadline, no connect is started.

        Args:
            host: Host name or address to connect to.
            port: TCP port.
            timeout: Socket timeout in seconds; an attempt never gets longer.
            ends_at: The ``time.monotonic()`` value at which the deadline passes.

        Returns:
            The connected socket.

        Raises:
            OSError: The error of the last address tried (TimeoutError when it
                ran out of time), or a TimeoutError when no time was left to try.
        """
        last_error: OSError = OSError(f"no address to connect to for {host!r}")
        for address_info in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            time_left = ends_at - time.monotonic()
            if time_left <= 0:
                self.connect_ran_out = True
                raise TimeoutError("no time left before the delivery deadline to connect") from None
            connect_timeout = max(min(timeout, time_left), _MIN_CONNECT_SECONDS)
            try:
                return self._open_connection(address_info, timeout=connect_timeout)
            except TimeoutError as error:
                # Decided here, not by the clock afterwards: the watchdog can still be
                # a clock tick away (Windows), and then nothing else says why it ended.
                self.connect_ran_out = connect_timeout < timeout
                last_error = error
            except OSError as error:
                self.connect_ran_out = False
                last_error = error
        raise last_error

    def _open_connection(self, address_info: _AddressInfo, *, timeout: float) -> socket.socket:
        """Connect to one resolved address, closing the socket if the connect fails.

        Args:
            address_info: One entry of ``socket.getaddrinfo()``.
            timeout: Seconds the connect may take.

        Returns:
            The connected socket.
        """
        family, kind, protocol, _name, address = address_info
        connection_socket = socket.socket(family, kind, protocol)
        try:
            connection_socket.settimeout(timeout)
            if self.source_address:
                connection_socket.bind(self.source_address)
            connection_socket.connect(address)
        except BaseException:
            connection_socket.close()
            raise
        return connection_socket


@contextmanager
def _session_deadline(smtp_connection: _SessionSMTP, seconds: float | None) -> Generator[None, None, None]:
    """Bound the whole SMTP session to seconds, raising TimeoutError past it.

    The socket timeout bounds one read or write, so a server that answers a
    byte at a time keeps a session alive indefinitely. When the deadline
    passes, a watchdog thread shuts the connection down, which ends whatever
    read or write is blocked; the resulting failure is reported as a
    TimeoutError naming the deadline, so the host counts as failed and the
    next one is tried. Each attempt of the TCP connect is bounded by the time
    left before the deadline.

    Args:
        smtp_connection: The SMTP connection to bound.
        seconds: Deadline in seconds for the whole session, or None to apply
            no bound.

    Yields:
        None, for the duration of the bounded session.

    Raises:
        TimeoutError: The deadline passed while a read or write was blocked.
    """
    if seconds is None:
        yield
        return
    smtp_connection.ends_at = time.monotonic() + seconds
    expired = threading.Event()
    finished = threading.Event()

    def cut() -> None:
        expired.set()
        # The deadline can pass while the TCP connect is still running, before the
        # socket exists, or in the TLS handshake on Windows; wait for it, or the
        # read after it is unbounded.
        while not finished.is_set():
            if _cut_session(smtp_connection):
                return
            finished.wait(_SOCKET_POLL_SECONDS)

    watchdog = threading.Timer(seconds, cut)
    watchdog.daemon = True
    watchdog.start()
    try:
        yield
    except OSError as error:
        if expired.is_set() or smtp_connection.connect_ran_out:
            raise TimeoutError(f"SMTP session did not finish within the delivery deadline of {seconds} seconds") from error
        raise
    finally:
        finished.set()
        watchdog.cancel()
        # Joined before the duplicate is closed, so the watchdog never shuts down
        # a descriptor number the system has handed out again.
        watchdog.join()
        if smtp_connection.cut_handle is not None:
            smtp_connection.cut_handle.close()
            smtp_connection.cut_handle = None


def _cut_session(smtp_connection: _SessionSMTP) -> bool:
    """Shut the session's connection down; False while there is nothing to cut yet."""
    handle = smtp_connection.cut_handle
    if handle is None:
        return False  # the TCP connect is still running
    with suppress(OSError):
        handle.shutdown(socket.SHUT_RDWR)
    if sys.platform != "win32":
        # POSIX may reuse a closed descriptor under the reading thread, so
        # shutdown alone does it there.
        return True
    # Windows wakes a blocked recv on close, not on shutdown, when the peer
    # sends nothing at all, and only once no handle to the connection is left
    # open: the duplicate and the session's own socket are both closed, the
    # latter once STARTTLS has installed it.
    live_socket = smtp_connection.sock
    if live_socket is None or live_socket.fileno() == -1:
        return False
    with suppress(OSError):
        handle.close()
    # socket.close() leaves the handle open while smtplib's makefile() reader
    # holds a reference to it, which is exactly while a read is blocked; the
    # C-level close releases it regardless.
    with suppress(OSError):
        _socket.socket.close(live_socket)
    return True


def _authenticate(smtp_connection: smtplib.SMTP, username: str, password: str) -> None:
    """Log in, using UTF-8 AUTH PLAIN only when the credentials are not ASCII.

    stdlib smtplib encodes every AUTH exchange as ASCII, so a non-ASCII
    password raises UnicodeEncodeError whose repr quotes the whole AUTH
    string. ASCII credentials keep the stdlib path unchanged.

    Args:
        smtp_connection: The SMTP connection to authenticate on.
        username: SMTP account name.
        password: SMTP account password.
    """
    if username.isascii() and password.isascii():
        smtp_connection.login(username, password)
        return
    _login_plain_utf8(smtp_connection, username, password)


def _login_plain_utf8(smtp_connection: smtplib.SMTP, username: str, password: str) -> None:
    """Authenticate with RFC 4616 AUTH PLAIN, credentials encoded as UTF-8.

    Args:
        smtp_connection: The SMTP connection to authenticate on.
        username: SMTP account name.
        password: SMTP account password.

    Raises:
        smtplib.SMTPNotSupportedError: The server offers no AUTH, or no
            PLAIN mechanism.
        smtplib.SMTPAuthenticationError: The server rejected the
            credentials, or answered a second 334; carries only the server
            reply.
    """
    if not smtp_connection.has_extn("auth"):
        raise smtplib.SMTPNotSupportedError("SMTP AUTH extension not supported by server.")
    mechanisms = smtp_connection.esmtp_features["auth"].upper().split()
    if "PLAIN" not in mechanisms:
        raise smtplib.SMTPNotSupportedError("non-ASCII SMTP credentials need a server that offers AUTH PLAIN (RFC 4616)")
    token = base64.b64encode(b"\0" + username.encode("utf-8") + b"\0" + password.encode("utf-8")).decode("ascii")
    code, reply = smtp_connection.docmd("AUTH", "PLAIN " + token)
    if code == _SMTP_AUTH_CONTINUE:
        # A server that ignores the initial response asks for it with an empty
        # 334 challenge (RFC 4954); smtplib.SMTP.auth answers the same way, once.
        code, reply = smtp_connection.docmd(token)
    if code not in (_SMTP_AUTH_OK, _SMTP_ALREADY_AUTHENTICATED):
        raise smtplib.SMTPAuthenticationError(code, reply)


def _require_socket(smtp_connection: smtplib.SMTP) -> socket.socket:
    """Return the live socket, or raise if the connection was never established.

    Args:
        smtp_connection: The SMTP connection to read the socket from.

    Returns:
        The connection's live socket.

    Raises:
        smtplib.SMTPServerDisconnected: The connection has no socket yet.
    """
    sock = smtp_connection.sock
    if sock is None:  # pragma: no cover - smtplib sets sock once connected
        raise smtplib.SMTPServerDisconnected("connection unexpectedly closed")
    return sock


def _open_envelope(smtp_connection: smtplib.SMTP, sender: str, recipient: str) -> None:
    """Issue MAIL FROM / RCPT TO, raising on rejection (shared by DATA and BDAT).

    Args:
        smtp_connection: The SMTP connection to issue the commands on.
        sender: Envelope sender address.
        recipient: Envelope recipient address.

    Raises:
        smtplib.SMTPSenderRefused: The server rejected MAIL FROM.
        smtplib.SMTPRecipientsRefused: The server rejected RCPT TO.
    """
    code, resp = smtp_connection.mail(sender)
    if code != _SMTP_OK:
        raise smtplib.SMTPSenderRefused(code, resp, sender)
    code, resp = smtp_connection.rcpt(recipient)
    if code not in (_SMTP_OK, _SMTP_WILL_FORWARD):
        raise smtplib.SMTPRecipientsRefused({recipient: (code, resp)})


def _send_via_data(smtp_connection: smtplib.SMTP, sender: str, recipient: str, message: IO[bytes]) -> None:
    """Stream the message through the classic DATA phase with incremental dot-stuffing.

    Args:
        smtp_connection: The SMTP connection to stream on.
        sender: Envelope sender address.
        recipient: Envelope recipient address.
        message: Rewindable byte stream holding the already-composed message.

    Raises:
        smtplib.SMTPDataError: The server rejected DATA or the final
            transcript.
    """
    _open_envelope(smtp_connection, sender, recipient)
    code, resp = smtp_connection.docmd("DATA")
    if code != _SMTP_START_MAIL_INPUT:
        raise smtplib.SMTPDataError(code, resp)

    sock = _require_socket(smtp_connection)
    stuffer = _DotStuffer()
    tail = b""
    while True:
        chunk = message.read(STREAM_CHUNK_SIZE)
        if not chunk:
            break
        sock.sendall(stuffer.feed(chunk))
        tail = chunk[-_CRLF_LEN:] if len(chunk) >= _CRLF_LEN else (tail + chunk)[-_CRLF_LEN:]
    # End the DATA phase with a lone "." line, guaranteeing exactly one CRLF
    # before it so we neither merge into the final body line nor add a blank one.
    if tail[-_CRLF_LEN:] != b"\r\n":
        sock.sendall(b"\r\n")
    sock.sendall(b".\r\n")
    code, resp = smtp_connection.getreply()
    if code != _SMTP_OK:
        raise smtplib.SMTPDataError(code, resp)


def _send_via_bdat(smtp_connection: smtplib.SMTP, sender: str, recipient: str, message: IO[bytes]) -> None:
    """Stream the message as RFC 3030 BDAT chunks (length-prefixed, no dot-stuffing).

    Args:
        smtp_connection: The SMTP connection to stream on.
        sender: Envelope sender address.
        recipient: Envelope recipient address.
        message: Rewindable byte stream holding the already-composed message.

    Raises:
        smtplib.SMTPDataError: The server rejected a BDAT chunk.
    """
    _open_envelope(smtp_connection, sender, recipient)
    sock = _require_socket(smtp_connection)
    while True:
        chunk = message.read(STREAM_CHUNK_SIZE)
        if not chunk:
            break
        sock.sendall(b"BDAT " + str(len(chunk)).encode("ascii") + b"\r\n" + chunk)
        code, resp = smtp_connection.getreply()
        if code != _SMTP_OK:
            raise smtplib.SMTPDataError(code, resp)
    sock.sendall(b"BDAT 0 LAST\r\n")
    code, resp = smtp_connection.getreply()
    if code != _SMTP_OK:
        raise smtplib.SMTPDataError(code, resp)


# Default production transport; `send` uses it unless a transport is injected.
DEFAULT_TRANSPORT: Final[Transport] = SmtplibTransport()


class _DotStuffer:
    """Incrementally SMTP-dot-stuff a CRLF byte stream for the DATA phase.

    RFC 5321 section 4.5.2 requires that a line beginning with "." be
    transmitted as ".." so the single-dot line stays reserved as the
    end-of-data marker. When the message is streamed in fixed-size chunks a
    line boundary (and therefore the leading dot to protect) can fall on any
    chunk edge, so the transform must remember whether the next byte starts a
    fresh line across feed calls rather than re-scanning whole lines.

    Assumes the input already uses CRLF line endings (the caller serialises
    with email.policy.SMTP); only period doubling is applied here.
    """

    def __init__(self) -> None:
        """Start the stuffer so the first byte fed is treated as a line start."""
        # The DATA payload begins at the start of a line, so the first byte is a
        # candidate for doubling.
        self._at_line_start = True

    def feed(self, chunk: bytes) -> bytes:
        """Return chunk with any line-leading "." doubled.

        Args:
            chunk: The next slice of the CRLF byte stream to dot-stuff.

        Returns:
            chunk with each line-leading "." doubled, carrying the
            line-start state across calls.
        """
        if not chunk:
            return chunk
        # bytes.replace runs in C; a per-byte Python loop held a 25 MiB attachment
        # to about 27 MB/s, once per recipient and host attempt.
        stuffed = chunk.replace(b"\n.", b"\n..")
        if self._at_line_start and stuffed.startswith(b"."):
            stuffed = b"." + stuffed
        self._at_line_start = chunk.endswith(b"\n")  # the byte after LF starts a line
        return stuffed
