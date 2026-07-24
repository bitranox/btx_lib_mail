# Attachment security

Attachments are validated against multiple security checks before being
included in outgoing mail. This prevents accidental (or malicious) attachment
of sensitive files, dangerous executables, or oversized payloads.

### Security Checks

1. **Path Traversal Prevention**  -  Paths containing `..` sequences are rejected
   to prevent escaping the intended directory.
2. **Symlink Handling**  -  Symlinks are rejected by default to prevent following
   links to sensitive files. Enable via `attachment_allow_symlinks=True`.
3. **Sensitive Pattern Detection**  -  Paths matching patterns like `/.ssh/`,
   `/id_rsa`, `/.env`, `/credentials`, `/.aws/credentials` are always blocked.
4. **Directory Restrictions**  -  By default, files from system directories
   (`/etc`, `/var`, `/root`, etc. on POSIX; `C:\Windows`, etc. on Windows) are
   blocked. Use `attachment_allowed_directories` for whitelist mode.
5. **Extension Filtering**  -  Dangerous extensions (`.sh`, `.exe`, `.bat`, `.py`,
   etc.) are blocked by default. Use `attachment_allowed_extensions` for
   whitelist mode or `attachment_blocked_extensions` to customize the blacklist.
6. **Size Limit**  -  Files larger than 25 MiB (default) are rejected. Override
   via `attachment_max_size_bytes`.

### Configuration Example

```python
from btx_lib_mail import conf, send, DANGEROUS_EXTENSIONS_POSIX

# Global configuration (applies to all send() calls)
conf.attachment_max_size_bytes = 50_000_000  # 50 MiB
conf.attachment_allow_symlinks = True
conf.attachment_blocked_extensions = DANGEROUS_EXTENSIONS_POSIX | {".custom"}

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

The library exports OS-specific defaults that can be extended or replaced:

```python
from btx_lib_mail import (
    DANGEROUS_EXTENSIONS_POSIX,  # frozenset: .sh, .py, .so, etc.
    DANGEROUS_EXTENSIONS_WINDOWS,  # frozenset: .exe, .bat, .ps1, etc.
    DANGEROUS_DIRECTORIES_POSIX,  # frozenset[Path]: /etc, /var, /root, etc.
    DANGEROUS_DIRECTORIES_WINDOWS,  # frozenset[Path]: C:\Windows, etc.
    SENSITIVE_PATH_PATTERNS,  # tuple[str]: /.ssh/, /id_rsa, /.env, etc.
)
```
