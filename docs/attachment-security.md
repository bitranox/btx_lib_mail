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
   blocked. Use `attachment_allowed_directories` for whitelist mode. A directory given
   as a string is stripped of surrounding whitespace (`"/srv/a, /srv/b".split(",")`
   blocks `/srv/b`, not a relative ` /srv/b`); a `pathlib` path is taken as given. A
   rule that no operating system call can be handed (holding NUL, longer than 32767
   UTF-16 code units, or with a lone surrogate POSIX cannot encode) is refused where it
   is given, with `InvalidInputError` (`ConfigurationError` from `ConfMail`).
   The rules and the attachment are compared as resolved paths: a symlink is followed,
   but another NAME for the same directory is not recognised. A Windows loopback share
   (`\\localhost\C$\Windows`, `\\?\UNC\localhost\C$\...`) or a Linux bind mount reaches
   a blocked directory under a name the blocklist does not hold. For a hard boundary,
   list what may be sent with `attachment_allowed_directories` rather than what may not.
5. **Extension Filtering**  -  Dangerous extensions (`.sh`, `.exe`, `.bat`, `.py`,
   etc.) are blocked by default on every platform: the default is the union of the
   POSIX and Windows lists, because the RECIPIENT's system decides what an attachment
   runs as. The extension is read from the name the message carries (the header drops
   surrounding whitespace, a trailing no-break space included) after trailing dots and
   spaces are dropped (Windows saves `x.exe.` as `x.exe`), and compared without case; an extension set given to `send()` or
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
   as `CHANGED`, and so is one whose parent directory was swapped for a link. On Linux
   the checked path is opened one component at a time and a link in any of them is
   refused, with or without `/proc`; on macOS and Windows the open follows the link and
   the path the operating system reports for the open file (`F_GETPATH`,
   `GetFinalPathNameByHandleW`; `/proc/self/fd` on Linux as well) is checked again, so
   only a link into a place the checks refuse is `CHANGED` there. Swapped for a directory
   or a FIFO before the open, it is reported like a missing file
   (`AttachmentNotFoundError`, "can not be found"); swapped while it is being opened, it is
   refused as `CHANGED` (on Windows a directory cannot be opened as a file, so there it
   "can not be read (EACCES)"). Swapping or deleting the file while delivery
   runs changes nothing that is sent. The files are closed before `send()` returns.
8. **File Name**  -  A file name holding a control character (CR, LF, NUL, ESC, DEL
   or any other Unicode `Cc` character), a bidirectional formatting character
   (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069, which can make
   `report<U+202E>fdp.xlsm` display as `reportmslx.pdf`), or one that is not valid
   Unicode text (an invalid UTF-8 byte in a POSIX name), or one the message would carry as
   another name (an RFC 2047 encoded word: `=?utf-8?b?aW52b2ljZS5leGU=?=` arrives as
   `invoice.exe`), is refused as `FILENAME`:
   the name becomes the attachment's `Content-Disposition` header, and a POSIX file
   system allows all of them in a name. A path holding NUL anywhere, or a lone surrogate
   POSIX has no bytes for (`"\ud800"`; Windows can name it), is refused the same way,
   before any file system call. A path longer than the operating system can name (on
   Windows 32767 UTF-16 code units, which a path can also reach while it is resolved) "can
   not be read (ENAMETOOLONG)" on every platform.

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

An attachment that grows past its size limit while the message is composed is left out and
the message composed again without it. One case raises even in warn mode: a violation found
while composing that names no attachment still in the message. Leaving nothing out would
change nothing, and composing again would meet the same violation, so it is raised instead
of retried.

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
