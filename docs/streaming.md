# Streaming and BDAT

`btx_lib_mail` never buffers a whole message in memory. Both message assembly and
delivery are streamed, so peak memory stays roughly constant regardless of attachment
size. No third-party dependency is involved; it is built on the standard library.

## Why

A conventional `smtplib` send reads each attachment fully, base64-encodes it into a MIME
object, serialises the whole message to one string, and hands that string to `sendmail`,
which buffers it again. Peak memory is a multiple of the payload. A large attachment then
either exhausts RAM or forces an arbitrary size cap.

## How assembly works

`_compose_body` writes everything below the per-recipient headers into a
`tempfile.SpooledTemporaryFile` (in memory below `_SPOOL_MAX_SIZE`, on disk above it) using
`email.message.EmailMessage` and `email.policy.SMTP`, so the serialized bytes already use
RFC 5321 CRLF line endings. It runs once per `send()` call: the body and the attachments are
the same for every recipient. Each recipient's message is then its own header lines
(`Subject`, `From`, `To`, `Date`) followed by a copy of that spool, streamed in
`_STREAM_CHUNK_SIZE` pieces, so the attachments are read and encoded once however many
recipients there are.

Each attachment is read in chunks from the file opened when it was checked and base64-encoded incrementally (57 decoded
bytes per 76-character line, read in a large multiple so whole lines are emitted per
chunk). The attachment is never held whole and its base64 expansion is never materialised
as one object. For a message with attachments the top-level `multipart/mixed` envelope is
written by hand so the attachment payloads can be streamed into it.

## How delivery works

Delivery streams the spooled message to the socket in `_STREAM_CHUNK_SIZE` chunks. The
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

Peak heap memory during a send is approximately one chunk plus the spool's in-memory
buffer (`_SPOOL_MAX_SIZE`, 1 MiB by default), independent of attachment size. A 16 MiB
attachment composes at under 3 MiB of peak heap; a 100 GB attachment composes at the same
peak.

The trade is disk, not memory: a message larger than `_SPOOL_MAX_SIZE` spills to a
temporary file, so a very large attachment needs temporary disk space of roughly its
base64-expanded size (about 1.33x). If you are memory-constrained this is exactly the
trade you want; if you are also disk-constrained, size your attachments accordingly.

## Failover

Each recipient's message is built once from the shared body and reused across every host
in `smtphosts`. A failed host is logged and the next is tried without re-rendering the
message.

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
from btx_lib_mail import send
from btx_lib_mail.lib_mail import Transport  # protocol for a custom adapter


class MyTransport:
    def deliver(self, *, host, sender, recipient, message, delivery):
        # `message` is a rewindable binary stream (the composed spool)
        ...


send(..., transport=MyTransport())
```

`delivery` is the resolved `DeliveryOptions` (`credentials`, `use_starttls`,
`starttls_verify`, `timeout`, `local_hostname`, `deadline`). A transport raises on any
failure so `send()` can try the next host; an `OSError` it raises is logged with its text,
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
(`tests/test_streaming.py`), covering DATA, BDAT, dot-stuffing edge cases, STARTTLS with
authentication, and a `tracemalloc` memory bound.
