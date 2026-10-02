"""Message assembly: the recipient-independent body encoded once into a spool, each recipient's header lines, and the copy that joins them.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import base64
import io
import mimetypes
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass
from email import policy as email_policy
from email.generator import BytesGenerator
from email.message import EmailMessage
from email.utils import formatdate
from typing import IO, TYPE_CHECKING, Final, cast

from ._attachments import AttachmentPayload, AttachmentSecurityError, AttachmentViolation, log_violation
from ._transport import STREAM_CHUNK_SIZE
from .errors import InvalidInputError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from _typeshed import WriteableBuffer

# Message assembly spills to disk above this threshold so a large message never
# has to fit in memory as one contiguous string.
_SPOOL_MAX_SIZE: Final[int] = 1024 * 1024  # 1 MiB


def _guess_attachment_mimetype(filename: str) -> tuple[str, str]:
    """Return the ``(maintype, subtype)`` Content-Type for an attachment name.

    A specific Content-Type helps the receiving client render the attachment;
    an unrecognised extension falls back to the generic binary type so
    delivery never fails on an unknown name.

    Args:
        filename: The attachment's file name.

    Returns:
        The guessed ``(maintype, subtype)`` pair.
    """
    guessed, _encoding = mimetypes.guess_type(filename)
    if guessed is None:
        return "application", "octet-stream"
    maintype, _slash, subtype = guessed.partition("/")
    return maintype, subtype or "octet-stream"


@dataclass(frozen=True)
class MessageContent:
    """The recipient-independent content of one `send()` call."""

    plain_body: str
    html_body: str
    attachments: tuple[AttachmentPayload, ...]


def _new_spool() -> IO[bytes]:
    """Return an empty spooled temp file: in memory below ``_SPOOL_MAX_SIZE``, on disk above it."""
    # Returned open and closed by the caller once the bytes are delivered, so
    # it cannot be opened as a `with` block here.
    return cast("IO[bytes]", tempfile.SpooledTemporaryFile(max_size=_SPOOL_MAX_SIZE))


def _compose_body(content: MessageContent) -> IO[bytes]:
    """Encode everything below the per-recipient headers into a rewound spool, once.

    The body and every attachment are the same for each recipient, so they are
    base64-encoded once per ``send()`` and each recipient's message is its own
    header block plus a copy of this spool. Serialising into a
    ``SpooledTemporaryFile`` keeps a large message off the heap, and
    ``email.policy.SMTP`` yields RFC 5321 CRLF line endings, so the DATA and
    BDAT senders only add transfer framing.

    Args:
        content: The recipient-independent body and attachments to encode.

    Returns:
        Spool positioned at offset 0: the MIME headers of the message body
        (``MIME-Version``, ``Content-Type``, ...), a blank line, and the body.
        Closed on any failure.
    """
    spool = _new_spool()
    try:
        _write_body(spool, content)
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


def _write_body(spool: IO[bytes], content: MessageContent) -> None:
    body_message = _build_body_message(content.plain_body, content.html_body)
    if not content.attachments:
        # No attachments: the body message is the whole message body (it is small).
        spool.write(_flatten_message(body_message))
        return

    # With attachments: hand-write a multipart/mixed so each attachment's base64
    # is streamed from its file instead of held in an in-memory message part.
    boundary = f"==============={uuid.uuid4().hex}=="
    outer = EmailMessage()
    outer["MIME-Version"] = "1.0"
    outer["Content-Type"] = f'multipart/mixed; boundary="{boundary}"'
    delimiter = b"--" + boundary.encode("ascii") + b"\r\n"
    spool.write(_header_block(outer))
    # First body part: the (small) text/alternative message, headers and all.
    spool.write(delimiter)
    spool.write(_flatten_message(body_message))
    spool.write(b"\r\n")
    for attachment in content.attachments:
        spool.write(delimiter)
        _write_attachment_part(spool, attachment)
    spool.write(b"--" + boundary.encode("ascii") + b"--\r\n")


def compose_body_once(content: MessageContent, *, raise_on_violation: bool) -> IO[bytes]:
    """Compose the shared body; in warn mode drop an attachment that grew past its limit and retry.

    A file that grows past the size limit while it is read is refused like an
    oversized file: raised in strict mode, logged and left out in warn mode.

    Args:
        content: The recipient-independent body and attachments to encode.
        raise_on_violation: Raise on a security violation instead of dropping
            the offending attachment and retrying.

    Returns:
        Spool positioned at offset 0, as returned by :func:`_compose_body`.
    """
    while True:
        try:
            return _compose_body(content)
        except AttachmentSecurityError as exc:
            if raise_on_violation:
                raise
            violation = exc
        log_violation(violation, str(violation.path))
        content = MessageContent(
            plain_body=content.plain_body,
            html_body=content.html_body,
            attachments=tuple(attachment for attachment in content.attachments if attachment.source != violation.path),
        )


def envelope_header_lines(*, sender: str, subject: str, recipients: Sequence[str]) -> tuple[bytes, ...]:
    """Return each recipient's header lines (Subject, From, To, Date), CRLF-terminated, no blank line.

    Subject and From are the same for every recipient and folded once: folding
    a long non-ASCII subject costs tens of milliseconds, which per recipient
    added up to over a minute for a thousand. Each header folds on its own, so
    joining the shared lines to a recipient's own gives the same bytes as
    folding all four together.

    Args:
        sender: The From address.
        subject: The message subject.
        recipients: The To addresses, one header block each.

    Returns:
        One block of CRLF-terminated header lines per recipient, in order,
        with no trailing blank line.
    """
    shared = EmailMessage()
    shared["Subject"] = subject
    shared["From"] = sender
    shared_lines = _header_lines(shared)
    date = formatdate(localtime=True)
    return tuple(shared_lines + _recipient_header_lines(recipient, date) for recipient in recipients)


def _recipient_header_lines(recipient: str, date: str) -> bytes:
    """Return one recipient's own header lines (To, Date)."""
    envelope = EmailMessage()
    envelope["To"] = recipient
    envelope["Date"] = date
    return _header_lines(envelope)


def message_for(header_lines: bytes, body: IO[bytes]) -> IO[bytes]:
    """Return one recipient's complete message: its header lines, then the shared body.

    The body is read in place, never copied, so the scratch disk a large
    attachment needs is its encoded size once however many recipients there
    are. The stream is read-only and seekable; closing it leaves the shared body
    open for the next recipient.

    Args:
        header_lines: The recipient's own header lines.
        body: The shared, already-composed body spool.

    Returns:
        A read-only, seekable stream of the header lines followed by the body.
    """
    return io.BufferedReader(_JoinedMessage(header_lines, body), buffer_size=STREAM_CHUNK_SIZE)


class _JoinedMessage(io.RawIOBase):
    """A read-only, seekable view of ``header_lines`` followed by ``body``."""

    def __init__(self, header_lines: bytes, body: IO[bytes]) -> None:
        super().__init__()
        self._header = header_lines
        self._body = body
        self._size = len(header_lines) + body.seek(0, io.SEEK_END)
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._position, io.SEEK_END: self._size}[whence]
        self._position = max(0, base + offset)
        return self._position

    def readinto(self, buffer: WriteableBuffer, /) -> int:
        view = memoryview(buffer).cast("B")
        header_left = len(self._header) - self._position
        if header_left > 0:
            count = min(header_left, len(view))
            view[:count] = self._header[self._position : self._position + count]
        else:
            # Seek on every read: the body is shared, and another reader may have moved it.
            self._body.seek(self._position - len(self._header))
            chunk = self._body.read(len(view))
            count = len(chunk)
            view[:count] = chunk
        self._position += count
        return count


# Control characters a subject may not carry: CR and LF would end the header (the
# email package refuses those itself), the rest reach the recipient raw. TAB is
# legal folding whitespace in an unstructured header.
_SUBJECT_ALLOWED_CONTROLS: Final[frozenset[str]] = frozenset({"\t"})


_LINE_BREAK_MESSAGE: Final[str] = "Header values may not contain linefeed or carriage return characters"

# Folding a subject costs more than linear time in its length, so an unbounded subject is CPU
# and memory a caller can burn before the first delivery. No mail
# client shows more than a line or two of it.
SUBJECT_MAX_CHARACTERS: Final[int] = 4096


def _check_unicode_text(text: str, *, field_name: str) -> None:
    """Refuse text that cannot be written as UTF-8, without echoing it.

    A lone surrogate is what an invalid UTF-8 byte in argv or a file name decodes
    to on POSIX; the email package would raise UnicodeEncodeError for it.

    Args:
        text: The text to check.
        field_name: The parameter name the message reports.

    Raises:
        InvalidInputError: If text holds a lone surrogate.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidInputError(f"{field_name} must be valid Unicode text") from None


def check_subject(subject: str) -> None:
    """Refuse a subject the email package would refuse or the recipient would see raw.

    A line break keeps the email package's own message, which ``send()`` raised
    for it before; that covers CR and LF and the Unicode separators U+2028 and
    U+2029, which the email package also treats as line breaks. A control
    character is checked before the separators, so its message stays the one it
    always had.

    Args:
        subject: The message subject to check.

    Raises:
        InvalidInputError: If subject is longer than SUBJECT_MAX_CHARACTERS, or
            contains a line break, a control character other than TAB, or a lone
            surrogate.
    """
    if "\r" in subject or "\n" in subject:
        raise InvalidInputError(_LINE_BREAK_MESSAGE)
    if any(unicodedata.category(character) == "Cc" and character not in _SUBJECT_ALLOWED_CONTROLS for character in subject):
        raise InvalidInputError("mail_subject must not contain control characters (only TAB is allowed)")
    if len(subject.splitlines()) > 1:
        raise InvalidInputError(_LINE_BREAK_MESSAGE)
    _check_unicode_text(subject, field_name="mail_subject")
    # Checked last, so a subject an earlier check refuses keeps the message it always had.
    if len(subject) > SUBJECT_MAX_CHARACTERS:
        raise InvalidInputError(f"mail_subject has {len(subject)} characters, more than the {SUBJECT_MAX_CHARACTERS} allowed")


def check_body(*, plain_body: str, html_body: str) -> None:
    """Refuse a body that cannot be written as UTF-8, without echoing it.

    Args:
        plain_body: The plain-text body.
        html_body: The HTML body.

    Raises:
        InvalidInputError: If either body holds a lone surrogate.
    """
    _check_unicode_text(plain_body, field_name="mail_body")
    _check_unicode_text(html_body, field_name="mail_body_html")


def _build_body_message(plain_body: str, html_body: str) -> EmailMessage:
    """Build the text/alternative body part (no envelope headers, no attachments).

    Args:
        plain_body: The plain-text body.
        html_body: The HTML body.

    Returns:
        The assembled text/alternative (or single-part) message.
    """
    message = EmailMessage()
    if plain_body and html_body:
        message.set_content(plain_body)
        message.add_alternative(html_body, subtype="html")
    elif html_body:
        message.set_content(html_body, subtype="html")
    else:
        message.set_content(plain_body)
    return message


def _header_lines(message: EmailMessage) -> bytes:
    """Serialise a message's headers to CRLF bytes, without the terminating blank line.

    Args:
        message: The message whose headers are serialised.

    Returns:
        The CRLF-terminated header lines, with no trailing blank line.
    """
    out = bytearray()
    for name, value in message.items():
        out += email_policy.SMTP.fold_binary(name, value)
    return bytes(out)


def _header_block(message: EmailMessage) -> bytes:
    """Serialise a message's headers to CRLF bytes, terminated by a blank line.

    Args:
        message: The message whose headers are serialised.

    Returns:
        The CRLF-terminated header lines, followed by a blank line.
    """
    return _header_lines(message) + b"\r\n"


def _flatten_message(message: EmailMessage) -> bytes:
    """Serialise a whole (small) message to CRLF bytes via the SMTP policy.

    Args:
        message: The message to serialise.

    Returns:
        The CRLF-encoded message bytes.
    """
    buffer = io.BytesIO()
    BytesGenerator(buffer, policy=email_policy.SMTP).flatten(message)
    return buffer.getvalue()


def _write_attachment_part(spool: IO[bytes], attachment: AttachmentPayload) -> None:
    """Write one base64 attachment part, streaming the checked file's bytes in chunks.

    Encoding the file incrementally (57 raw bytes per 76-char base64 line, read
    in a large multiple so whole lines are emitted per chunk) keeps peak memory
    at roughly one chunk instead of the full attachment plus its base64
    expansion. The bytes are counted as they are read, so a file that grows
    past the size limit after it was checked is refused, having been read at
    most one chunk past the limit.

    Args:
        spool: The spool to append the attachment part to.
        attachment: The checked attachment to stream from.

    Raises:
        AttachmentSecurityError: If the file grows past its size limit while
            it is being read.
    """
    maintype, subtype = _guess_attachment_mimetype(attachment.filename)
    part_headers = EmailMessage()
    part_headers["Content-Type"] = f"{maintype}/{subtype}"
    part_headers["Content-Transfer-Encoding"] = "base64"
    part_headers.add_header("Content-Disposition", "attachment", filename=attachment.filename)
    spool.write(_header_block(part_headers))

    # 57 decoded bytes -> one 76-char base64 line; a large multiple keeps each
    # read aligned to whole lines so chunk encodings concatenate cleanly.
    raw_chunk = 57 * 1024
    handle = attachment.handle
    handle.seek(0)
    total = 0
    while True:
        chunk = handle.read(raw_chunk)
        if not chunk:
            break
        total += len(chunk)
        if attachment.size_limit is not None and total > attachment.size_limit:
            raise AttachmentSecurityError(
                path=attachment.source,
                reason=f'file grew past the limit of {attachment.size_limit} bytes while it was read: "{attachment.source}"',
                violation_type=AttachmentViolation.SIZE,
            )
        spool.write(base64.encodebytes(chunk).replace(b"\n", b"\r\n"))
    spool.write(b"\r\n")
