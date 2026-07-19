# AI transparency

The author and owner of this project is the human, [@bitranox](https://github.com/bitranox).
Every design and engineering decision is theirs, and they answer for everything published
here. An AI assistant (Claude, run through the Claude Code CLI) was used as a tool along the
way, mostly for the typing and the legwork under that direction. This page says where, plainly,
so you can weigh the work on its merits. The reasoning behind working this way is in
[ai-stance.md](ai-stance.md).

## The human's work

The shape of this software is the human's, start to finish. They set the problem, made every
call, and own the result.

- The problem is theirs: scripts and small services kept hand-rolling `smtplib`, so the goal was
  one small, reusable library with a CLI that sends multipart UTF-8 mail with attachments over
  one audited path, instead of copying the same boilerplate around.
- Streaming was the human's call. When the question of large attachments came up, they chose to
  stream rather than buffer: the message is assembled into a disk-backed spool and sent to the
  server a chunk at a time, so peak memory stays flat regardless of attachment size. They also
  chose to speak RFC 3030 BDAT when the server advertises CHUNKING and fall back to a dot-stuffed
  DATA phase otherwise. The AI reported that no library does this and it must be built on the
  standard library; the human decided it was worth building and to advertise it.
- Every design and architecture decision was the human's: a typed Pydantic configuration surface
  (`ConfMail`) with a global instance and per-call overrides; multi-host failover that tries each
  configured server in order; the layered split kept honest by `import-linter`, where the CLI
  adapter depends on the behaviour helpers only; and representing the attachment violation
  category as a typed enum rather than a bare string. Where there were options, the human picked.
- The security posture was the human's call: attachments are validated before any bytes are read,
  and rejected for path traversal, symlinks, sensitive path patterns (`/.ssh/`, `/id_rsa`,
  `/.env`, credentials and the like), system directories, dangerous extensions, and oversize
  payloads -- with both blacklist and whitelist modes and a strict-or-warn switch. STARTTLS is on
  by default and, by default, verifies the server certificate.
- The one deliberate loosening was the human's call too: a certificate-verification opt-out
  (`starttls_verify=False` / `--no-starttls-verify`) for an internal relay whose certificate is
  self-signed or hostname-mismatched. It keeps the channel encrypted but skips validation, and it
  ships off by default. The AI flagged the tradeoff; the human decided to expose it as an explicit
  opt-in.
- The human reviewed and corrected the work at each step; what ships is what they signed off on.
- Every commit went out under the human's name and authority, with no AI co-author line. The
  human is responsible for what is published.

## Where the AI was used

As a tool, under the human's direction, it did the mechanical parts: typing the modules, the
configuration model, the validators, the attachment-security checks, the delivery and failover
helpers, the streaming path (disk-backed spool assembly, chunked DATA with dot-stuffing, and the
RFC 3030 BDAT sender) behind an injectable transport seam, the rich-click CLI adapter, the
docstrings and these docs, and the tests to the human's design (including the real in-process SMTP
server the wire tests run against); laying out options at each fork for the human to choose from;
and running the gate and grinding it to green. None of the decisions, and none of the
accountability, were the AI's, the human directed and approved every action and owns the result.

## What's been checked, and what hasn't

The suite runs on every commit and in CI across Linux, macOS and Windows: `ruff` for lint and
format, `pyright` in strict mode, `bandit` for a security scan, and `pytest` with doctests and a
high coverage bar. `import-linter` enforces the layer contract (the CLI depends on the behaviour
helpers, not the reverse). Delivery is checked two ways. The orchestration (host failover,
STARTTLS and credentials resolved from config, recipient and host validation, message
composition, and every attachment-security rule) runs against an injected in-memory transport, so
no socket is opened. The wire behaviour itself (the streamed DATA phase with dot-stuffing, RFC
3030 BDAT chunking, STARTTLS with authentication, and a memory bound a large attachment cannot
breach) is proven end to end against a real in-process SMTP server, in the normal suite, on every
platform.

What CI does not do is send real mail to a real mailbox. The in-process server speaks the SMTP
protocol but is a local test double, not a relay that delivers anywhere. Delivery to an actual
inbox is exercised only through an opt-in integration path (the `TEST_SMTP_*` environment
variables and the `integration` test marker) against a server the operator supplies; with those
unset, the live send is skipped. So the last hop to your own relay is something you verify, not
something CI asserts for you.

## Checking it yourself

The library is small and reads top to bottom. `send` is the one public entry point; it validates
input, prepares recipients, attachments and hosts, resolves the delivery and security options
against `ConfMail`, composes the message once into a disk-backed spool, then tries each host until
one accepts it. The SMTP session is a thin use of stdlib `smtplib` and `email`: connect, optional
STARTTLS, optional login, then the spool is streamed to the server, as RFC 3030 BDAT when the
server offers CHUNKING, otherwise the DATA phase with dot-stuffing, so a large attachment is never
held in memory. The places worth reading closely are the attachment security path,
`_validate_attachment_security` and its checks; the streaming compose and transport
(`_compose_to_spool`, `SmtplibTransport`); and the STARTTLS context builder,
`_build_starttls_context`, which is the only spot that can disable certificate verification and
does so only when explicitly asked.

The tests need no mail server: run `make test`, or `pytest` directly. The public API is
re-exported from the package root, and [module_reference](docs/systemdesign/module_reference.md)
lists every module and component.

## What this isn't

It isn't affiliated with or endorsed by any mail provider, and it isn't a mail server -- it hands
your message to one you configure. It's a thin, typed wrapper over stdlib `smtplib`/`email` with a
security layer in front of attachments, not a full mail stack. And the certificate-verification
opt-out is exactly that: an opt-in that trades away protection against a man-in-the-middle for the
sake of an internal self-signed relay. If you reach for it, understand what you are turning off,
and prefer adding the relay's CA to your trust store where you can.

## License and attribution

The text and code here are under the MIT License (see [`LICENSE`](LICENSE)). Anthropic's terms put
ownership of model output with the user, so the human owns this and answers for it. Under the MIT
License, anyone who passes it on keeps the copyright notice and the permission notice with the
source.
