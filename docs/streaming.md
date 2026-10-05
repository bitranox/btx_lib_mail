# Streaming and BDAT

`btx_lib_mail` never buffers an attachment whole. Attachments are streamed from their
files during message assembly, and the finished message is streamed during delivery, so
peak memory stays roughly constant regardless of attachment size. The text and HTML bodies
arrive as `str` and are encoded in memory by the standard library's `email` package (a peak
of about six times a plain body's UTF-8 size, ten times with an HTML alternative of the same
size); put a large payload in an attachment, not the body. No third-party dependency is
involved; it is built on the standard library.

## Why

A conventional `smtplib` send reads each attachment fully, base64-encodes it into a MIME
object, serialises the whole message to one string, and hands that string to `sendmail`,
which buffers it again. Peak memory is a multiple of the payload. A large attachment then
either exhausts RAM or forces an arbitrary size cap.

## How assembly works

The library writes everything below the per-recipient headers into one
`tempfile.SpooledTemporaryFile` (in memory below 1 MiB, on disk above it) using
`email.message.EmailMessage` and `email.policy.SMTP`, so the serialized bytes already use
RFC 5321 CRLF line endings. This happens once per `send()` call (again only in warn mode,
when an attachment that grew past the size limit is left out): the body and the attachments
are the same for every recipient. Each recipient's message is then its own header lines
(`Subject`, `From`, `To`, `Date`) followed by that spool, read in place rather than copied,
so the attachments are read and encoded once however many recipients there are.

Each attachment is read in chunks from the file opened when it was checked and base64-encoded incrementally (57 decoded
bytes per 76-character line, read in a large multiple so whole lines are emitted per
chunk). The attachment is never held whole and its base64 expansion is never materialised
as one object. For a message with attachments the top-level `multipart/mixed` envelope is
written by hand so the attachment payloads can be streamed into it.

## How delivery works

Delivery streams the message to the socket in 64 KiB chunks. The
transport picks the wire format per host, from the server's EHLO response:

- **BDAT (RFC 3030 CHUNKING).** When the server advertises `CHUNKING`, the message is sent
  as a series of length-prefixed `BDAT <n>` chunks, ending with `BDAT 0 LAST`. No
  dot-stuffing is needed because chunk boundaries are explicit.
- **DATA (fallback).** Otherwise the classic `DATA` phase is used, with incremental
  dot-stuffing (a line beginning with `.` is sent as `..`, tracked across chunk
  boundaries) and a terminating `.` line.

STARTTLS and authentication happen before either path: the transport re-runs EHLO after
the TLS upgrade so the `CHUNKING` decision reflects the encrypted session.

## Memory and disk

Peak heap memory is about one read chunk plus the spool's 1 MiB in-memory buffer while
composing, and about one 64 KiB chunk while streaming, independent of attachment size. The
test suite pins both: a 16 MiB attachment composes under 3 MiB of peak heap, and an 8 MiB
message streams through DATA and through BDAT under 2 MiB. Nothing in either path grows
with the attachment, so a larger file uses the same peak.

Attachments are capped at 25 MiB by default (`attachment_max_size_bytes`, or
`--attachment-max-size` on the CLI); raise the cap to send anything larger.

The trade is disk, not memory: a message larger than 1 MiB spills to a temporary file, so a
very large attachment needs temporary disk space of its encoded size, about 1.37x the file
(base64 in 76-character lines with CRLF), once per `send()` however many recipients there
are. If you are memory-constrained this is exactly the trade you want; if you are also
disk-constrained, size your attachments accordingly.

## Failover

Each recipient's message is built once from the shared body and reused across every host
in `smtphosts`: it is rewound to its first byte before every host attempt. A failed host is
logged and the next is tried without re-rendering the message.

Each recipient gets its own SMTP connection, so any fixed per-connection cost is paid once
per recipient. The client's `EHLO` name is one such cost when it is not configured: it is
then this host's fully qualified name, found by reverse DNS. The library looks it up once
per process and reuses it; set `smtp_local_hostname` (or `send(local_hostname=...)`,
`--local-hostname`, `BTX_MAIL_SMTP_LOCAL_HOSTNAME`) to skip the lookup entirely or to
announce a name the relay accepts.

## Custom transports

Delivery goes through a `Transport` protocol. `send()` uses `SmtplibTransport` by default,
but accepts a `transport=` override:

```python
from typing import IO

from btx_lib_mail import DeliveryOptions, Transport, send  # Transport: the protocol below


class MyTransport:
    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        # `message` is a read-only, seekable binary stream at its first byte; send()
        # rewinds it before every host attempt.
        ...


send(..., transport=MyTransport())
```

`delivery` is the resolved `DeliveryOptions` (`credentials`, `use_starttls`,
`starttls_verify`, `timeout`, `local_hostname`, `deadline`). A transport raises on any
failure so `send()` can try the next host, and returns once the server has accepted the
message (the default transport ignores how the server answers `QUIT`, since raising then
would make `send()` deliver the message again); an `OSError` it raises is logged with its text,
anything else by type name only, so never put a credential into an `OSError`'s text.

The CLI takes a transport the same way, through its typed context object, which lets an
application embed the `send` command, or a test drive it, without SMTP:

```python
from click.testing import CliRunner
from btx_lib_mail.cli import CliContext, cli

CliRunner().invoke(
    cli, ["send", "--host", "relay.example.com", "--recipient", "b@example.com", "--subject", "s", "--body", "b"], obj=CliContext(transport=MyTransport())
)
```

This is the seam the test suite uses: orchestration tests inject an in-memory transport,
while wire behaviour is verified end to end against a real in-process SMTP server
(`tests/test_streaming.py`, `tests/test_transfer_memory.py`, `tests/test_deadline.py`),
covering DATA, BDAT, dot-stuffing edge cases, STARTTLS with authentication, `tracemalloc`
memory bounds for composing and for streaming, and the delivery deadline.
