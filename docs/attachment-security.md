# Attachment security

Attachments are validated against multiple security checks before being
included in outgoing mail. This prevents accidental (or malicious) attachment
of sensitive files, dangerous executables, or oversized payloads.

### Security Checks

1. **Path Traversal Prevention**  -  A path with a `..` component (`../x`, `a/../b`)
   is rejected. A `..` inside a file name (`report..final.txt`) is not a component
   and passes.
2. **Symlink Handling**  -  A path whose last component is a symlink is rejected by
   default; enable via `attachment_allow_symlinks=True`. A symlinked DIRECTORY along
   the path is followed either way: every rule below runs on the resolved target, so a
   symlinked directory cannot carry a file out of a blocked directory or into an
   allowed one.
3. **Sensitive Pattern Detection**  -  Paths matching patterns like `/.ssh/`,
   `/id_rsa`, `/.env`, `/credentials`, `/.aws/credentials`, `/.netrc`,
   `/.git-credentials` are always blocked. On macOS and Windows the match ignores
   case, since their file systems do (`.SSH/config` is `~/.ssh/config` there); on
   Linux it is exact, where `.SSH/config` is a different file.
4. **Directory Restrictions**  -  By default, files from system directories
   (`/etc`, `/var`, `/root`, etc. on POSIX; `C:\Windows`, etc. on Windows) are
   blocked. Use `attachment_allowed_directories` for whitelist mode.
5. **Extension Filtering**  -  Dangerous extensions (`.sh`, `.exe`, `.bat`, `.py`,
   etc.) are blocked by default on every platform: the default is the union of the
   POSIX and Windows lists, because the RECIPIENT's system decides what an attachment
   runs as. The extension is read after trailing dots and spaces are dropped (Windows
   saves `x.exe.` as `x.exe`) and compared without case; an extension set given to `send()` or
   `ConfMail` is normalised the same way (`{"EXE"}` and `{".exe"}` are one set). Use
   `attachment_allowed_extensions` for whitelist mode or
   `attachment_blocked_extensions` to customize the blacklist.
   `ConfMail` refuses an empty blocked extension or directory set when its
   allowlist is not set, because it would block nothing; set
   `attachment_allow_empty_blocklists=True` to do that on purpose.
6. **Size Limit**  -  Files larger than 25 MiB (default) are rejected. Override
   via `attachment_max_size_bytes`. The bytes are also counted while the file is
   read, so a file that grows past the limit after the check is refused too.
   One call accepts at most 100 attachments (`attachment_max_count`; `None` lifts
   the limit); more is refused with `InvalidInputError` before any file is opened.
7. **One Open File**  -  After the checks, each attachment is opened once and
   compared with what was checked (same file, still a regular file); the message
   body is encoded once from that open file and every recipient receives those
   bytes. A path swapped after the checks for a symlink or another file is refused
   as `CHANGED`; swapped for a directory or a FIFO, it is reported like a missing
   file (`AttachmentNotFoundError`). Swapping or deleting the file while delivery
   runs changes nothing that is sent. The files are closed before `send()` returns.
8. **File Name**  -  A file name holding a control character (CR, LF, NUL, ESC, DEL
   or any other Unicode `Cc` character), or one that is not valid Unicode text (an
   invalid UTF-8 byte in a POSIX name), is refused as `FILENAME`: the name becomes
   the attachment's `Content-Disposition` header, and a POSIX file system allows
   all of them in a name. A path holding NUL anywhere is refused the same way,
   before any file system call.

A refusal raises `AttachmentSecurityError`, whose `violation_type` is an
`AttachmentViolation` member: `PATH_TRAVERSAL`, `SYMLINK`, `SENSITIVE_PATTERN`,
`DIRECTORY`, `EXTENSION`, `SIZE`, `CHANGED` or `FILENAME`. Branch on it, not on the message.

### Configuration Example

```python
from pathlib import Path

from btx_lib_mail import conf, send, DANGEROUS_EXTENSIONS_POSIX, DANGEROUS_EXTENSIONS_WINDOWS

conf.smtphosts = ["smtp.example.com:587"]

# Global configuration (applies to all send() calls)
conf.attachment_max_size_bytes = 50_000_000  # 50 MiB
conf.attachment_allow_symlinks = True
conf.attachment_blocked_extensions = DANGEROUS_EXTENSIONS_POSIX | DANGEROUS_EXTENSIONS_WINDOWS | {".custom"}

# Per-call override (whitelist mode)
send(
    mail_from="sender@example.com",
    mail_recipients="recipient@example.com",
    mail_subject="Report",
    mail_body="See attached.",
    attachment_file_paths=[Path("report.pdf")],
    attachment_allowed_extensions=frozenset({".pdf", ".txt", ".docx"}),
    attachment_max_size_bytes=100_000_000,  # 100 MiB for this call only
)
```

### Warn-Only Mode

By default, security violations raise `AttachmentSecurityError`. To log a
warning and skip the offending attachment instead:

```python
send(
    ...,
    attachment_raise_on_security_violation=False,
)
```

### Public Constants

The library exports its defaults so they can be extended or replaced. Both extension
sets are blocked on every platform; the directory set of the platform the library runs
on is the default:

```python
from btx_lib_mail import (
    DANGEROUS_EXTENSIONS_POSIX,  # frozenset: .sh, .py, .so, etc.
    DANGEROUS_EXTENSIONS_WINDOWS,  # frozenset: .exe, .bat, .ps1, etc.
    DANGEROUS_DIRECTORIES_POSIX,  # frozenset[Path]: /etc, /var, /root, etc.
    DANGEROUS_DIRECTORIES_WINDOWS,  # frozenset[Path]: C:\Windows, etc.
    SENSITIVE_PATH_PATTERNS,  # tuple[str]: /.ssh/, /id_rsa, /.env, /.netrc, etc.
)
```
