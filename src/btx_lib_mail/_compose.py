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
from dataclasses import dataclass, replace
from email import policy as email_policy
from email.generator import BytesGenerator
from email.message import EmailMessage
from email.utils import formatdate
from functools import partial
from typing import IO, TYPE_CHECKING, Final, cast

from ._attachments import AttachmentPayload, AttachmentSecurityError, AttachmentViolation, log_violation
from ._common import is_valid_unicode
from ._transport import STREAM_CHUNK_SIZE
from ._validation import require_text
from .errors import InvalidInputError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from _typeshed import WriteableBuffer

    from ._inline_images import InlineImagePayload

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
    """The recipient-independent content of one `send()` call.

    Attributes:
        plain_body: The plain-text body, or "".
        html_body: The HTML body, or ""; required when there are inline images.
        attachments: The checked, open attachments.
        inline_images: The checked, open images the HTML shows in place.
    """

    plain_body: str
    html_body: str
    attachments: tuple[AttachmentPayload, ...]
    inline_images: tuple[InlineImagePayload, ...] = ()


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
    """Write the whole body: the text entity, wrapped in multipart/mixed when there are attachments.

    Each multipart is hand-written (:func:`_write_multipart`), so every
    attachment's and every inline image's base64 is streamed from its file
    instead of held in an in-memory message part.

    Args:
        spool: Where the bytes are written.
        content: The recipient-independent body, attachments and inline images.
    """
    if not content.attachments:
        _write_text_entity(spool, content, top_level=True)
        return
    parts: list[Callable[[IO[bytes]], None]] = [partial(_write_text_entity, content=content, top_level=False)]
    parts.extend(partial(_write_attachment_part, attachment=attachment) for attachment in content.attachments)
    _write_multipart(spool, "multipart/mixed", parts, top_level=True)


def _write_text_entity(spool: IO[bytes], content: MessageContent, *, top_level: bool) -> None:
    """Write the text entity: the bodies, and the inline images the HTML shows.

    Without inline images it is the single-part or multipart/alternative message
    the email package builds, as it always was. With them, the HTML and the
    images form a multipart/related (RFC 2387), which replaces the HTML part of
    the multipart/alternative when there is a plain body too.

    Args:
        spool: Where the bytes are written.
        content: The recipient-independent content.
        top_level: Whether this entity is the whole body, and so carries ``MIME-Version``.
    """
    if not content.inline_images:
        # The text and HTML bodies arrive as str and are encoded in memory; only the
        # attachments and images, which arrive as files, are streamed.
        _flatten_into(spool, _build_body_message(content.plain_body, content.html_body))
        return
    related = partial(_write_related, html_body=content.html_body, images=content.inline_images)
    if not content.plain_body:
        related(spool, top_level=top_level)
        return
    plain = partial(_flatten_into, message=_text_part(content.plain_body, subtype="plain"))
    _write_multipart(spool, "multipart/alternative", [plain, partial(related, top_level=False)], top_level=top_level)


def _write_related(spool: IO[bytes], *, html_body: str, images: tuple[InlineImagePayload, ...], top_level: bool) -> None:
    """Write a multipart/related holding the HTML part first, then each inline image.

    Args:
        spool: Where the bytes are written.
        html_body: The HTML body, which references each image as ``cid:<Content-ID>``.
        images: The inline images, in the caller's order.
        top_level: Whether this entity is the whole body.
    """
    parts: list[Callable[[IO[bytes]], None]] = [partial(_flatten_into, message=_text_part(html_body, subtype="html"))]
    parts.extend(partial(_write_inline_image_part, image=image) for image in images)
    # RFC 2387: "type" names the root part's type, so a reader knows to show the HTML.
    _write_multipart(spool, 'multipart/related; type="text/html"', parts, top_level=top_level)


def _text_part(text: str, *, subtype: str) -> EmailMessage:
    """Return a text part without ``MIME-Version``, for use inside a hand-written multipart.

    Examples:
        >>> part = _text_part("<p>Hi</p>", subtype="html")
        >>> (part.get_content_type(), "MIME-Version" in part)
        ('text/html', False)
    """
    part = EmailMessage()
    part.set_content(text, subtype=subtype)
    # set_content adds MIME-Version; a part inside a multipart needs none.
    del part["MIME-Version"]
    return part


def _write_multipart(spool: IO[bytes], content_type: str, parts: Sequence[Callable[[IO[bytes]], None]], *, top_level: bool) -> None:
    """Write a multipart entity: its header block, then each part between boundary delimiters.

    Each part writer writes the part's own header block and content; the CRLF
    that ends each part (and begins the next delimiter) is written here.

    Args:
        spool: Where the bytes are written.
        content_type: The multipart type with any parameters but the boundary,
            which is added here.
        parts: One writer per body part, in order.
        top_level: Whether this entity is the whole body, and so carries ``MIME-Version``.
    """
    boundary = f"==============={uuid.uuid4().hex}=="
    headers = EmailMessage()
    if top_level:
        headers["MIME-Version"] = "1.0"
    headers["Content-Type"] = f'{content_type}; boundary="{boundary}"'
    delimiter = b"--" + boundary.encode("ascii") + b"\r\n"
    spool.write(_header_block(headers))
    for write_part in parts:
        spool.write(delimiter)
        write_part(spool)
        spool.write(b"\r\n")
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

    Raises:
        AttachmentSecurityError: In strict mode; in warn mode too when the
            violation names no attachment left to drop, since composing again
            would meet it again and never end, or names an inline image.
    """
    while True:
        try:
            return _compose_body(content)
        except AttachmentSecurityError as exc:
            # An inline image is never left out: the HTML references it.
            if raise_on_violation or any(image.attachment.source == exc.path for image in content.inline_images):
                raise
            violation = exc
        remaining = tuple(attachment for attachment in content.attachments if attachment.source != violation.path)
        if len(remaining) == len(content.attachments):
            raise violation
        log_violation(violation, str(violation.path))
        content = replace(content, attachments=remaining)


def envelope_header_lines(*, sender: str, subject: str, recipients: Sequence[str]) -> tuple[bytes, ...]:
    """Return each recipient's header lines (Subject, From, To, Date), CRLF-terminated, no blank line.

    Subject and From are the same for every recipient and folded once: folding
    a long non-ASCII subject costs tens of milliseconds, which per recipient
    added up to over a minute for a thousand. Each header folds on its own, so
    joining the shared lines to a recipient's own gives the same bytes as
    folding all four together.

    A From or To header whose address holds non-ASCII is folded with
    `email.policy.SMTPUTF8`, which writes the address as raw UTF-8 (RFC 6532);
    that message travels as SMTPUTF8 (`needs_smtputf8`). Every other header is
    folded with `email.policy.SMTP`, so a message whose addresses are ASCII is
    unchanged byte for byte. The subject keeps its RFC 2047 encoded-words, which
    are valid in both kinds of message.

    Args:
        sender: The From address.
        subject: The message subject.
        recipients: The To addresses, one header block each.

    Returns:
        One block of CRLF-terminated header lines per recipient, in order,
        with no trailing blank line.

    Examples:
        >>> [block] = envelope_header_lines(sender="a@example.com", subject="Hi", recipients=["b@m" + chr(0xFC) + "ller.de"])
        >>> b"To: b@m" + chr(0xFC).encode() + b"ller.de" in block
        True
    """
    shared_lines = _header_lines(_single_header("Subject", subject)) + _address_header_lines("From", sender)
    date = formatdate(localtime=True)
    return tuple(shared_lines + _recipient_header_lines(recipient, date) for recipient in recipients)


def _recipient_header_lines(recipient: str, date: str) -> bytes:
    r"""Return one recipient's own header lines (To, Date).

    Args:
        recipient: The To address.
        date: The Date header value shared by the whole call.

    Returns:
        The CRLF-terminated To and Date lines.

    Examples:
        >>> _recipient_header_lines("b@example.com", "Tue, 13 Oct 2026 10:00:00 +0200")
        b'To: b@example.com\r\nDate: Tue, 13 Oct 2026 10:00:00 +0200\r\n'
    """
    return _address_header_lines("To", recipient) + _header_lines(_single_header("Date", date))


def _address_header_lines(name: str, address: str) -> bytes:
    r"""Return one address header, folded as raw UTF-8 when the address holds non-ASCII.

    Args:
        name: The header name (`From` or `To`).
        address: The bare address.

    Returns:
        The CRLF-terminated header line(s).

    Examples:
        >>> _address_header_lines("To", "b@example.com")
        b'To: b@example.com\r\n'
        >>> _address_header_lines("To", "b@m" + chr(0xFC) + "ller.de") == ("To: b@m" + chr(0xFC) + "ller.de\r\n").encode()
        True
    """
    return _header_lines(_single_header(name, address), utf8=not address.isascii())


def _single_header(name: str, value: str) -> EmailMessage:
    """Return a message holding one header, so it can be folded on its own.

    Args:
        name: The header name.
        value: The header value.

    Returns:
        A headers-only `EmailMessage`.

    Examples:
        >>> _single_header("Subject", "Hi")["Subject"]
        'Hi'
    """
    message = EmailMessage()
    message[name] = value
    return message


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
    if not is_valid_unicode(text):
        raise InvalidInputError(f"{field_name} must be valid Unicode text")


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
    require_text(subject, field_name="mail_subject")
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
    require_text(plain_body, field_name="mail_body")
    require_text(html_body, field_name="mail_body_html")
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


def _header_lines(message: EmailMessage, *, utf8: bool = False) -> bytes:
    r"""Serialise a message's headers to CRLF bytes, without the terminating blank line.

    Args:
        message: The message whose headers are serialised.
        utf8: Fold with `email.policy.SMTPUTF8` (raw UTF-8, RFC 6532) instead
            of `email.policy.SMTP` (RFC 2047 encoded-words).

    Returns:
        The CRLF-terminated header lines, with no trailing blank line.

    Examples:
        >>> _header_lines(_single_header("To", "b@example.com"))
        b'To: b@example.com\r\n'
    """
    policy = email_policy.SMTPUTF8 if utf8 else email_policy.SMTP
    out = bytearray()
    for name, value in message.items():
        out += policy.fold_binary(name, value)
    return bytes(out)


def _header_block(message: EmailMessage) -> bytes:
    """Serialise a message's headers to CRLF bytes, terminated by a blank line.

    Args:
        message: The message whose headers are serialised.

    Returns:
        The CRLF-terminated header lines, followed by a blank line.
    """
    return _header_lines(message) + b"\r\n"


def _flatten_into(spool: IO[bytes], message: EmailMessage) -> None:
    """Serialise a whole message to CRLF bytes via the SMTP policy, straight into spool.

    Args:
        spool: Where the bytes are written.
        message: The message to serialise.
    """
    BytesGenerator(spool, policy=email_policy.SMTP).flatten(message)


def _write_attachment_part(spool: IO[bytes], attachment: AttachmentPayload) -> None:
    """Write one base64 attachment part, streaming the checked file's bytes in chunks.

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
    _stream_base64(spool, attachment)


def _write_inline_image_part(spool: IO[bytes], image: InlineImagePayload) -> None:
    """Write one base64 inline image part, streaming the checked file's bytes in chunks.

    The Content-ID line is written raw: the email package encodes an over-long
    unstructured header as RFC 2047 encoded-words, which no client would match
    against ``cid:`` in the HTML. The Content-ID is printable ASCII without
    spaces (:func:`~btx_lib_mail._inline_images.check_content_id`), so the raw
    line is valid as it is. The file name is encoded as an attachment's is
    (RFC 2231 for non-ASCII).

    Args:
        spool: The spool to append the image part to.
        image: The checked inline image to stream from.

    Raises:
        AttachmentSecurityError: If the file grows past its size limit while
            it is being read.
    """
    type_headers = EmailMessage()
    type_headers["Content-Type"] = image.content_type
    type_headers["Content-Transfer-Encoding"] = "base64"
    disposition = EmailMessage()
    disposition.add_header("Content-Disposition", "inline", filename=image.attachment.filename)
    spool.write(_header_lines(type_headers) + _content_id_line(image.content_id) + _header_lines(disposition) + b"\r\n")
    _stream_base64(spool, image.attachment)


def _content_id_line(content_id: str) -> bytes:
    r"""Return the raw, CRLF-terminated ``Content-ID`` header line for a checked Content-ID.

    Examples:
        >>> _content_id_line("logo@example.com")
        b'Content-ID: <logo@example.com>\r\n'
    """
    return b"Content-ID: <" + content_id.encode("ascii") + b">\r\n"


def _stream_base64(spool: IO[bytes], attachment: AttachmentPayload) -> None:
    """Append the checked file's bytes as base64 lines, reading it in chunks.

    Encoding the file incrementally (57 raw bytes per 76-char base64 line, read
    in a large multiple so whole lines are emitted per chunk) keeps peak memory
    at roughly one chunk instead of the full file plus its base64 expansion.
    The bytes are counted as they are read, so a file that grows past the size
    limit after it was checked is refused, having been read at most one chunk
    past the limit.

    Args:
        spool: The spool to append the base64 lines to.
        attachment: The checked file to stream from.

    Raises:
        AttachmentSecurityError: If the file grows past its size limit while
            it is being read.
    """
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
