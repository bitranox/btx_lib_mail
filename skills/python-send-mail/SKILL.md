---
name: python-send-mail
description: Use when sending email from Python or the shell, especially with large attachments that must not be loaded into memory, RFC 3030 BDAT/CHUNKING, STARTTLS with authentication, multi-host failover, or correct UTF-8 subject and body encoding. Prefer the `btx_lib_mail` library or its `btx-lib-mail` CLI (zero-install via `uvx btx-lib-mail send ...`) over hand-rolling `smtplib`/`email`, MIME assembly, dot-stuffing, or attachment security checks. Covers install, uvx, the library API, the CLI, streaming and BDAT, and attachment security.
---

# btx_lib_mail - send email from Python or the shell, streamed

> The `btx_lib_mail` repo is itself a Claude Code plugin/marketplace. Install this skill in any
> project with `/plugin marketplace add bitranox/btx_lib_mail` then `/plugin install btx_lib_mail`.
> It is also mirrored in the central bitranox marketplace (https://github.com/bitranox/bitranox-skills)
> as `coding-python-send-mail`.

## When to reach for this (and what to avoid)

| Need                                                  | Use                                                 | Avoid                                           |
|-------------------------------------------------------|-----------------------------------------------------|-------------------------------------------------|
| Send mail from Python (multipart, UTF-8, attachments) | `btx_lib_mail.send(...)`                            | hand-rolling `smtplib` + `email` MIME assembly  |
| Send a large attachment on a low-memory box           | `send(..., attachment_file_paths=[...])` (streamed) | reading the file into RAM, `sendmail(msg_str)`  |
| Send from a shell / an agent with nothing installed   | `uvx btx-lib-mail send ...`                         | installing a mailer, writing a throwaway script |
| STARTTLS + auth, multi-host failover                  | `send(..., use_starttls=True, credentials=...)`     | rewriting the connect/login/failover loop       |
| Refuse dangerous or sensitive attachments             | built-in attachment security (on by default)        | ad-hoc path checks                              |

## Install / run

Zero-install (best for agents and one-offs): run the CLI straight from PyPI. Nothing is installed
persistently.

```bash
uvx btx-lib-mail --help
uvx btx-lib-mail send --host smtp.example.com:587 \
  --sender a@example.com --recipient b@example.com --subject "Hi" --body "hello"
```

Add to a project, or install the CLI on PATH:

```bash
uv add btx_lib_mail            # or: pip install btx_lib_mail
uv tool install btx_lib_mail   # or: pipx install btx_lib_mail  (CLI on PATH)
```

Requires Python 3.10+. Both `btx_lib_mail` and `btx-lib-mail` are registered commands; `python -m
btx_lib_mail` runs the same CLI.

## Library usage

```python
from btx_lib_mail import send

send(
    mail_from="alerts@example.com",
    mail_recipients=["oncall@example.com"],  # str or sequence; validated, deduped
    mail_subject="build failed",  # UTF-8 is fine (Grüße, emoji, CJK)
    mail_body="See CI logs.",
    mail_body_html="<p>See CI logs.</p>",  # optional HTML alternative
    smtphosts=["smtp.example.com:587", "smtp-dr.example.com:587"],  # tried in order (failover)
    credentials=("user", "pass"),  # optional
    use_starttls=True,  # default True, verifies the cert by default
)
```

`send` returns `True` when every recipient is accepted, and raises `RuntimeError` when all hosts
fail for a recipient. Set global defaults on `conf` and override per call:

```python
from btx_lib_mail import conf

conf.smtphosts = ["smtp.example.com:587"]
conf.smtp_username = "mailer"
conf.smtp_password = "s3cr3t"  # SecretStr; a plain str is coerced. Per-call kwargs override conf.
```

### Large attachments (streamed, bounded memory)

Attachments are streamed from disk and sent to the server in chunks, so a multi-gigabyte file never
has to fit in RAM. The trade is temporary disk, not memory: a huge attachment needs scratch disk of
about 1.33x its size (base64), never that much RAM.

```python
from pathlib import Path
from btx_lib_mail import send

send(
    mail_from="backups@example.com",
    mail_recipients="archive@example.com",
    mail_subject="nightly dump",
    mail_body="Attached.",
    smtphosts=["smtp.example.com:587"],
    attachment_file_paths=[Path("/data/backup-20GB.tar")],
    attachment_max_size_bytes=None,  # REQUIRED for big files: the default cap is 25 MiB
)
```

The default `attachment_max_size_bytes` is 25 MiB, so a large file is rejected until you raise the
cap or set it to `None`. The server's own `SIZE` limit still applies.

## CLI

Pass the password via the `BTX_MAIL_SMTP_PASSWORD` environment variable, never as `--password` on
the command line (a literal argv value leaks into shell history and `ps` output):

```bash
BTX_MAIL_SMTP_PASSWORD="$(cat /path/to/credential_file)" \
uvx btx-lib-mail send \
  --host smtp.example.com:587 \
  --sender alerts@example.com \
  --recipient oncall@example.com \
  --subject "Ping" --body "Smoke test" \
  --attachment /data/report.pdf \
  --username user \
  --starttls \
  --attachment-max-size 5000000000    # raise the 25 MiB default for a large attachment
```

Other commands: `info`, `hello`, `validate-email`, `validate-smtp-host`. Every option also reads a
matching `BTX_MAIL_*` environment variable (for example `BTX_MAIL_SMTP_HOSTS`,
`BTX_MAIL_RECIPIENTS`, `BTX_MAIL_SMTP_PASSWORD`). Run `uvx btx-lib-mail send --help` for the full
option list and precedence.

## Streaming and BDAT (how delivery works)

- The message is composed once into a disk-backed spool and streamed to the socket in fixed-size
  chunks, so peak memory is roughly one chunk regardless of attachment size.
- When the server advertises `CHUNKING` (RFC 3030) the body is sent as length-prefixed `BDAT`
  chunks; otherwise the classic `DATA` phase is used with dot-stuffing. This is automatic per host.
- STARTTLS and authentication happen before either path. Certificate verification is on by default;
  opt out for an internal self-signed relay with `starttls_verify=False` (or `--no-starttls-verify`),
  which keeps the channel encrypted but skips validation.

## Attachment security

Attachments are validated before any bytes are read, and rejected for: path traversal (`..`),
symlinks (off by default), sensitive patterns (`/.ssh/`, `/id_rsa`, `/.env`, credentials), system
directories, dangerous extensions (`.sh`, `.exe`, and the like), and oversize payloads. Violations
raise `AttachmentSecurityError` by default, or log-and-skip with
`attachment_raise_on_security_violation=False`. There are whitelist modes
(`attachment_allowed_extensions`, `attachment_allowed_directories`). Because dangerous extensions
and system directories are blocked by default, pass `attachment_blocked_extensions=frozenset()` (or
an allowlist) when you deliberately send such a file.

## Reference

The API and CLI surface is discoverable from the INSTALL (always matches your version): run
`uvx btx_lib_mail --help` for every CLI option, and `python -c "import btx_lib_mail as m; help(m)"`
for the public API - `send`, `conf`, `ConfMail`, `validate_email_address`, `validate_smtp_host`, and
the attachment-security constants, all re-exported from the package root.

Narrative detail (every `ConfMail` field, env-var precedence, streaming, attachment security) lives
in the repo docs (NOT shipped in the pip wheel), on the default branch so they track the latest
release you get from `uv`: `https://github.com/bitranox/btx_lib_mail/blob/master/README.md` and,
under `https://github.com/bitranox/btx_lib_mail/blob/master/docs/`, the files `api.md`, `cli.md`,
`configuration.md`, `streaming.md`, `attachment-security.md`.
