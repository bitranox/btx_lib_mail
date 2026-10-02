"""Message assembly: the recipient-independent body encoded once into a spool, each recipient's
header lines, and the copy that joins them.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import base64
import io
import mimetypes
import shutil
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass
from email import policy as email_policy
from email.generator import BytesGenerator
from email.message import EmailMessage
from email.utils import formatdate
from typing import IO, Final, cast

from ._attachments import AttachmentPayload, AttachmentSecurityError, AttachmentViolation, log_violation
from ._transport import STREAM_CHUNK_SIZE
from .errors import InvalidInputError

# Message assembly spills to disk above this threshold so a large message never
# has to fit in memory as one contiguous string.
_SPOOL_MAX_SIZE: Final[int] = 1024 * 1024  # 1 MiB


def _guess_attachment_mimetype(filename: str) -> tuple[str, str]:
    """Return the ``(maintype, subtype)`` Content-Type for an attachment name.

    Why
        A specific Content-Type helps the receiving client render the
        attachment; an unrecognised extension falls back to the generic binary
        type so delivery never fails on an unknown name.
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

    Why
        The body and every attachment are the same for each recipient, so they
        are base64-encoded once per ``send()`` and each recipient's message is
        its own header block plus a copy of this spool. Serialising into a
        ``SpooledTemporaryFile`` keeps a large message off the heap, and
        ``email.policy.SMTP`` yields RFC 5321 CRLF line endings, so the DATA and
        BDAT senders only add transfer framing.

    Outputs
    -------
    IO[bytes]
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


def envelope_header_lines(*, sender: str, recipient: str, subject: str) -> bytes:
    """Return the per-recipient header lines (Subject, From, To, Date), CRLF-terminated, no blank line."""
    envelope = EmailMessage()
    envelope["Subject"] = subject
    envelope["From"] = sender
    envelope["To"] = recipient
    envelope["Date"] = formatdate(localtime=True)
    return _header_lines(envelope)


def message_for(header_lines: bytes, body: IO[bytes]) -> IO[bytes]:
    """Return one recipient's complete message: its header lines, then a copy of the shared body.

    The copy streams in ``STREAM_CHUNK_SIZE`` pieces, so memory stays at one
    chunk; the attachments are not read or encoded again.
    """
    spool = _new_spool()
    try:
        spool.write(header_lines)
        body.seek(0)
        shutil.copyfileobj(body, spool, STREAM_CHUNK_SIZE)
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


# Control characters a subject may not carry: CR and LF would end the header (the
# email package refuses those itself), the rest reach the recipient raw. TAB is
# legal folding whitespace in an unstructured header.
_SUBJECT_ALLOWED_CONTROLS: Final[frozenset[str]] = frozenset({"\t"})


def check_subject(subject: str) -> None:
    """Refuse a subject carrying a control character, without echoing it.

    CR and LF keep the email package's own message, which ``send()`` raised for
    them before.
    """
    if "\r" in subject or "\n" in subject:
        raise InvalidInputError("Header values may not contain linefeed or carriage return characters")
    if any(unicodedata.category(character) == "Cc" and character not in _SUBJECT_ALLOWED_CONTROLS for character in subject):
        raise InvalidInputError("mail_subject must not contain control characters (only TAB is allowed)")


def _build_body_message(plain_body: str, html_body: str) -> EmailMessage:
    """Build the text/alternative body part (no envelope headers, no attachments)."""
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
    """Serialise a message's headers to CRLF bytes, without the terminating blank line."""
    out = bytearray()
    for name, value in message.items():
        out += email_policy.SMTP.fold_binary(name, value)
    return bytes(out)


def _header_block(message: EmailMessage) -> bytes:
    """Serialise a message's headers to CRLF bytes, terminated by a blank line."""
    return _header_lines(message) + b"\r\n"


def _flatten_message(message: EmailMessage) -> bytes:
    """Serialise a whole (small) message to CRLF bytes via the SMTP policy."""
    buffer = io.BytesIO()
    BytesGenerator(buffer, policy=email_policy.SMTP).flatten(message)
    return buffer.getvalue()


def _write_attachment_part(spool: IO[bytes], attachment: AttachmentPayload) -> None:
    """Write one base64 attachment part, streaming the checked file's bytes in chunks.

    Why
        Encoding the file incrementally (57 raw bytes per 76-char base64 line,
        read in a large multiple so whole lines are emitted per chunk) keeps peak
        memory at roughly one chunk instead of the full attachment plus its
        base64 expansion. The bytes are counted as they are read, so a file that
        grows past the size limit after it was checked is refused, having been
        read at most one chunk past the limit.
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
