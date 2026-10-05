"""Attachment security: the default blocklists, the path checks, and opening each checked file once so the bytes sent are those of the file that was checked.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import errno
import itertools
import os
import pathlib
import stat
import sys
import unicodedata
from collections.abc import Iterable, Sized
from dataclasses import dataclass, field, replace
from email.message import EmailMessage
from enum import Enum
from typing import IO, Final, cast

from ._common import is_valid_unicode, logger, printable
from ._descriptor_path import descriptor_path
from .errors import AttachmentNotFoundError, BtxMailError, InvalidInputError

DANGEROUS_EXTENSIONS_POSIX: Final[frozenset[str]] = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".csh",
        ".py",
        ".pyw",
        ".pyc",
        ".pyo",
        ".pl",
        ".pm",
        ".rb",
        ".php",
        ".js",
        ".mjs",
        ".cjs",
        ".so",
        ".dylib",
        ".bin",
        ".run",
        ".appimage",
        ".elf",
        ".out",
        ".jar",
        ".war",
        ".ear",
        ".deb",
        ".rpm",
        ".apk",
    }
)
"""Dangerous file extensions for POSIX systems (Linux/macOS)."""


DANGEROUS_EXTENSIONS_WINDOWS: Final[frozenset[str]] = frozenset(
    {
        ".exe",
        ".com",
        ".bat",
        ".cmd",
        ".msi",
        ".msp",
        ".msc",
        ".ps1",
        ".ps2",
        ".psc1",
        ".psc2",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".ws",
        ".wsf",
        ".wsc",
        ".wsh",
        ".scr",
        ".pif",
        ".hta",
        ".cpl",
        ".inf",
        ".reg",
        ".dll",
        ".ocx",
        ".sys",
        ".drv",
        ".lnk",
        ".scf",
        ".url",
        ".gadget",
        ".application",
        ".jar",
        ".war",
        ".ear",
    }
)
"""Dangerous file extensions for Windows systems."""


DANGEROUS_DIRECTORIES_POSIX: Final[frozenset[pathlib.Path]] = frozenset(
    {
        pathlib.Path("/etc"),
        pathlib.Path("/var"),
        pathlib.Path("/root"),
        pathlib.Path("/boot"),
        pathlib.Path("/sys"),
        pathlib.Path("/proc"),
        pathlib.Path("/dev"),
        pathlib.Path("/usr/bin"),
        pathlib.Path("/usr/sbin"),
        pathlib.Path("/bin"),
        pathlib.Path("/sbin"),
    }
)
"""Sensitive directories blocked by default on POSIX systems."""


DANGEROUS_DIRECTORIES_WINDOWS: Final[frozenset[pathlib.Path]] = frozenset(
    {
        pathlib.Path("C:/Windows"),
        pathlib.Path("C:/Windows/System32"),
        pathlib.Path("C:/Program Files"),
        pathlib.Path("C:/Program Files (x86)"),
        pathlib.Path("C:/ProgramData"),
    }
)
"""Sensitive directories blocked by default on Windows systems."""


SENSITIVE_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "/.ssh/",
    "/id_rsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/authorized_keys",
    "/known_hosts",
    "/.gnupg/",
    "/private.key",
    "/secret",
    "/.env",
    "/credentials",
    "/password",
    "/token",
    "/.aws/credentials",
    "/.kube/config",
    "/.netrc",
    "/.pgpass",
    "/.git-credentials",
    "/.docker/config.json",
    "/.pypirc",
    "/.npmrc",
    "/gh/hosts.yml",
)
"""Path patterns that indicate sensitive files (always blocked).

Matched as substrings of the resolved path with forward slashes; ignoring case on
macOS and Windows, exactly on other platforms.
"""

# macOS and Windows file systems ignore case by default, so .SSH/config IS ~/.ssh/config
# there; on Linux it is a different file that no SSH client reads.
_PATHS_IGNORE_CASE: Final[bool] = sys.platform in ("darwin", "win32")

# The longest path Windows can name, in UTF-16 code units; longer than any POSIX PATH_MAX.
# Past it, Python on Windows raises a bare ValueError from every file system call instead
# of an OSError.
_LONGEST_PATH: Final[int] = 32767

# A path is quoted whole in a message or log line up to this many characters (Linux's
# PATH_MAX); a longer one, which no file can have there, shows its start and length.
_QUOTE_LIMIT: Final[int] = 4096

# What is kept of a longer one. Cleaned, it stays well under _QUOTE_LIMIT, so quoting an
# already quoted text (a pickled AttachmentSecurityError rebuilt) leaves it unchanged.
_QUOTE_HEAD: Final[int] = 256


def _quoted(text: str) -> str:
    """Return text cleaned for a message or log line, whole up to ``_QUOTE_LIMIT`` characters, else its start and length.

    Examples:
        >>> _quoted("/srv/report.pdf")
        '/srv/report.pdf'
        >>> _quoted("/srv/" + "a" * 5000).endswith("a... (5005 characters)")
        True
    """
    if len(text) <= _QUOTE_LIMIT:
        return printable(text)
    return f"{printable(text[:_QUOTE_HEAD])}... ({len(text)} characters)"


def default_blocked_extensions() -> frozenset[str]:
    """Return the dangerous extensions of every platform.

    What runs an attachment is the RECIPIENT's machine, not the sender's, so a
    Linux sender must refuse ``.exe`` as firmly as a Windows sender refuses
    ``.sh``. Unlike the blocked directories, which describe the sender's own
    disk, this set does not depend on where the library runs.

    Returns:
        The union of :data:`DANGEROUS_EXTENSIONS_POSIX` and
        :data:`DANGEROUS_EXTENSIONS_WINDOWS`.
    """
    return DANGEROUS_EXTENSIONS_POSIX | DANGEROUS_EXTENSIONS_WINDOWS


def default_blocked_directories() -> frozenset[pathlib.Path]:
    """Return the OS-appropriate set of dangerous directories.

    Provides sensible defaults without requiring manual configuration.

    Returns:
        Dangerous directories for the current operating system.
    """
    if sys.platform == "win32":
        return DANGEROUS_DIRECTORIES_WINDOWS
    return DANGEROUS_DIRECTORIES_POSIX


def normalise_extensions(values: Iterable[object]) -> frozenset[str]:
    """Return values as lower-case, dot-prefixed extensions; blanks are dropped.

    Used for the `ConfMail` fields and for the `send()` keywords alike, so
    `{"PDF"}`, `{".pdf"}` and `{" .PDF "}` mean the same set wherever they are given.

    Args:
        values: Extension strings, with or without a leading dot, in any case.

    Returns:
        The normalised, lower-case, dot-prefixed extensions.

    Raises:
        InvalidInputError: If any value is not a string.

    Examples:
        >>> sorted(normalise_extensions(["PDF", ".Txt", " ", "exe"]))
        ['.exe', '.pdf', '.txt']
    """
    normalised: set[str] = set()
    for ext in values:
        if not isinstance(ext, str):
            raise InvalidInputError(f"extension must be a string, got {type(ext).__name__}")
        ext_lower = ext.lower().strip()
        if not ext_lower:
            continue
        normalised.add(ext_lower if ext_lower.startswith(".") else "." + ext_lower)
    return frozenset(normalised)


def normalise_directories(values: Iterable[object]) -> frozenset[pathlib.Path]:
    """Return values as a set of paths; each must be a ``str`` or a ``pathlib`` path; strings are stripped, blank ones dropped.

    Used for the `ConfMail` fields and for the `send()` keywords alike, so a list of
    strings means the same directories wherever it is given. A blank string is what
    splitting an empty setting yields (``"".split(",") == [""]``); kept, it would name
    the working directory, replacing the default blocked directories with it or
    allowing all of it. Surrounding whitespace is what splitting ``"/srv/a, /srv/b"``
    leaves; kept, ``" /srv/b"`` would be a relative rule under the working directory
    and block nothing. A ``pathlib`` path is taken as given, a leading space included.

    Args:
        values: Directory entries.

    Returns:
        The entries as ``pathlib.Path`` objects.

    Raises:
        InvalidInputError: If any value is neither a ``str`` nor a ``pathlib`` path,
            holds NUL, is longer than ``_LONGEST_PATH`` UTF-16 code units (no
            directory can be named so on Windows, which counts in those units), or
            cannot be encoded for the operating system (a lone surrogate on POSIX).

    Examples:
        >>> sorted(path.name for path in normalise_directories(["/srv/a", pathlib.Path("/srv/b")]))
        ['a', 'b']
        >>> normalise_directories(["", "  "])
        frozenset()
        >>> normalise_directories(["  /srv/a "]) == frozenset({pathlib.Path("/srv/a")})
        True
    """
    normalised: set[pathlib.Path] = set()
    for directory in values:
        if not isinstance(directory, (str, pathlib.PurePath)):
            raise InvalidInputError(f"directory must be a string or Path, got {type(directory).__name__}")
        text = directory.strip() if isinstance(directory, str) else str(directory)
        _check_directory_text(text)
        if text:
            normalised.add(pathlib.Path(text) if isinstance(directory, str) else pathlib.Path(directory))
    return frozenset(normalised)


def _check_directory_text(text: str) -> None:
    """Refuse a directory rule no operating system call can be handed, the same way on every platform.

    Raises:
        InvalidInputError: If text holds NUL, is too long to name, or cannot be
            encoded for the operating system.
    """
    if "\x00" in text:
        raise InvalidInputError("directory must not contain NUL")
    if _utf16_length(text) > _LONGEST_PATH:
        raise InvalidInputError(f"directory must not be longer than {_LONGEST_PATH} UTF-16 code units")
    try:
        # What every file system call does to the path first; on POSIX a lone surrogate
        # outside the surrogateescape range has no bytes, and the call raises.
        os.fsencode(text)
    except UnicodeEncodeError:
        raise InvalidInputError("directory can not be encoded for the operating system") from None


def _utf16_length(text: str) -> int:
    """Return how long text is as Windows measures a path: in UTF-16 code units, so an emoji counts two.

    Examples:
        >>> _utf16_length("a" + chr(0x1F4C4))
        3
    """
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


class AttachmentViolation(str, Enum):
    """Enumerate the closed set of attachment security violation categories.

    Callers match on a typed member instead of a bare string. Members
    subclass ``str`` (``str, Enum`` rather than 3.11+ ``StrEnum`` to keep the
    3.10 baseline), so ``violation is AttachmentViolation.SYMLINK``,
    ``violation == "symlink"``, and JSON serialisation all behave as expected
    and the wire value is unchanged.
    """

    PATH_TRAVERSAL = "path_traversal"
    SYMLINK = "symlink"
    SENSITIVE_PATTERN = "sensitive_pattern"
    DIRECTORY = "directory"
    EXTENSION = "extension"
    SIZE = "size"
    CHANGED = "changed"
    FILENAME = "filename"


class AttachmentSecurityError(BtxMailError):
    """Raised when an attachment violates security policies.

    Provides a structured exception for attachment security violations so
    callers can handle or report them appropriately.

    Attributes:
        path: The offending attachment path.
        reason: Human-readable description of the violation, with every
            control character (CR, LF, ESC, NUL, ...) already replaced by a
            space, since the path embedded in it is filesystem-supplied and
            could otherwise forge a line in whatever renders `str(exc)`,
            `repr(exc)`, or a log line built from this field.
        violation_type: Category of the violation
            (`AttachmentViolation.SYMLINK`, `.EXTENSION`, `.SIZE`, etc.).
            Members subclass `str`, so `== "symlink"` comparisons keep
            working.
    """

    def __init__(self, path: pathlib.Path, reason: str, violation_type: AttachmentViolation) -> None:
        """Build the error, cleaning *reason* of forgeable control characters.

        Args:
            path: The offending attachment path.
            reason: Human-readable description of the violation; may embed
                a filesystem-supplied path.
            violation_type: Category of the violation.
        """
        # `reason` is built with an f-string at every call site and usually
        # embeds `path` (filesystem-supplied), so it is cleaned (and bounded) once here:
        # this also cleans `self.args` (via `super().__init__`), so neither
        # `str(exc)` nor the default `repr(exc)` (which renders `self.args`
        # unclean-through-`__str__`) can carry a forged line, whether this
        # exception is logged or propagated to the caller in strict mode.
        clean_reason = _quoted(reason)
        super().__init__(clean_reason)
        self.path = path
        self.reason = clean_reason
        self.violation_type = violation_type

    def __reduce__(self) -> tuple[type[AttachmentSecurityError], tuple[pathlib.Path, str, AttachmentViolation]]:
        """Rebuild from the three constructor arguments; pickle and deepcopy would pass only the message."""
        return (type(self), (self.path, self.reason, self.violation_type))

    def __str__(self) -> str:
        """Return the forgery-safe one-line rendering used by logs and tracebacks.

        Returns:
            The violation type, cleaned reason, and cleaned path in one line.
        """
        # .value keeps the message text stable across Python versions, where
        # f-string formatting of a `str, Enum` member is inconsistent.
        return f"Attachment security violation ({self.violation_type.value}): {self.reason} [path={_quoted(str(self.path))}]"


@dataclass(frozen=True)
class AttachmentPayload:
    """Name a validated attachment and hold the file it was checked as, open.

    The bytes encoded into the message are those of the checked file even if
    the path is swapped afterwards. Instances are immutable (`frozen=True`);
    the handle itself is rewound before each read.

    Attributes:
        filename: Basename surfaced in the `Content-Disposition` header.
        source: The resolved path that was checked (for messages).
        handle: The checked file, opened once; read while the message body is
            encoded and closed when `send()` returns.
        size_limit: The size limit in force; a file that grows past it while
            it is read is refused.
    """

    filename: str
    source: pathlib.Path
    handle: IO[bytes] = field(repr=False, compare=False)
    size_limit: int | None = None


@dataclass(frozen=True)
class AttachmentSecurityOptions:
    """Capture the attachment security options for a single send operation.

    Validation helpers receive one immutable object. The directory sets are
    resolved by :func:`prepare_attachments`, and only when there is an
    attachment to check, so a rule that cannot be resolved never fails a
    message without attachments.

    Attributes:
        allowed_extensions: When set, only these extensions are allowed
            (whitelist mode).
        blocked_extensions: Extensions to reject (ignored when whitelist is
            active).
        allowed_directories: When set, attachments must reside under one of
            these directories.
        blocked_directories: Directories from which attachments cannot be
            read.
        max_size_bytes: Maximum attachment size in bytes.
        allow_symlinks: Whether symlinks are permitted.
        raise_on_violation: Whether violations raise or just warn.
        max_count: Most attachments one call accepts; None sets no limit.
    """

    allowed_extensions: frozenset[str] | None
    blocked_extensions: frozenset[str]
    allowed_directories: frozenset[pathlib.Path] | None
    blocked_directories: frozenset[pathlib.Path]
    max_size_bytes: int | None
    allow_symlinks: bool
    raise_on_violation: bool
    max_count: int | None


def _with_resolved_directories(security: AttachmentSecurityOptions) -> AttachmentSecurityOptions:
    """Return security with its directory sets resolved once; every attachment is compared with these.

    Raises:
        InvalidInputError: If a directory cannot be resolved (a relative one whose
            working directory is gone, or a symlink loop).
    """
    allowed = security.allowed_directories
    return replace(
        security,
        allowed_directories=None if allowed is None else _resolved_directories(allowed),
        blocked_directories=_resolved_directories(security.blocked_directories),
    )


def _resolved_directories(directories: frozenset[pathlib.Path]) -> frozenset[pathlib.Path]:
    try:
        resolved = frozenset(directory.resolve() for directory in directories)
    except OSError as exc:
        code = _errno_name(exc.errno)
    except ValueError:  # a rule Windows can name only until it is resolved (a short name expanded)
        code = _too_long_to_name().code
    except RuntimeError:  # a symlink loop, before Python 3.13
        code = "ELOOP"
    else:
        # Python 3.13+ returns a loop unresolved, still a symlink: refused the
        # same way, rather than kept as a rule no file can ever match.
        if not any(_resolves_to_a_link(directory) for directory in resolved):
            return resolved
        code = "ELOOP"
    raise InvalidInputError(f"an attachment directory can not be resolved ({code})")


def _resolves_to_a_link(directory: pathlib.Path) -> bool:
    """Whether a resolved rule, or a directory above it, is still a symlink: where Python 3.13+ stops at a loop.

    Resolving follows every link it can, so a link left anywhere on the resolved
    path is one it could not follow. The rule itself is not enough to look at: a
    loop in a parent makes examining the rule fail with ``ELOOP`` on Linux but
    ``ENOENT`` on Windows, and only the parent shows the loop on both. A path the
    process may not examine for another reason (``EACCES`` on a parent) is
    compared as written, as it was before this check: no attachment the process
    can read lies under it.
    """
    return any(_is_a_link_or_in_a_loop(path) for path in (directory, *directory.parents))


def _is_a_link_or_in_a_loop(path: pathlib.Path) -> bool:
    try:
        return _is_symlink(path)
    except _UnreadableAttachmentError as exc:
        return exc.code == "ELOOP"


def _errno_name(error_number: int | None) -> str:
    return errno.errorcode.get(error_number, "OSError") if error_number is not None else "OSError"


def _too_long_to_name() -> _UnreadableAttachmentError:
    """Report a path Python on Windows refused to hand to the operating system as unreadable (``ENAMETOOLONG``).

    Past ``_LONGEST_PATH`` UTF-16 code units a file system call raises a bare
    ``ValueError`` ("path too long for Windows") where Linux raises ``OSError``
    (``ENAMETOOLONG``); a path can also grow past it while it is resolved (a short
    name such as ``PROGRA~2`` expanded). Every call site maps that ``ValueError``
    here, so the outcome is the one Linux reports. The other ``ValueError`` causes
    never get that far: an attachment path holding NUL or a lone surrogate is
    refused before any call (:func:`_check_nameable`), a directory rule where it
    is given (:func:`normalise_directories`).

    Returns:
        The error to raise.
    """
    return _UnreadableAttachmentError(errno.ENAMETOOLONG)


def _resolve(path: pathlib.Path) -> pathlib.Path:
    """``path.resolve()``, reporting a failure (a deleted working directory) as unreadable.

    Raises:
        _UnreadableAttachmentError: When the operating system cannot resolve path,
            or the path cannot be handed to it (:func:`_too_long_to_name`).
    """
    try:
        return path.resolve()
    except OSError as exc:
        raise _UnreadableAttachmentError(exc.errno) from None
    except ValueError:
        raise _too_long_to_name() from None


def _check_path_traversal(path: pathlib.Path, original_str: str) -> None:
    """Detect path traversal attempts in the original path string.

    Path traversal sequences like `../` can escape intended directories.

    Args:
        path: The path object (for error reporting).
        original_str: The original string representation of the path.

    Raises:
        AttachmentSecurityError: If traversal is detected.
    """
    # A ".." COMPONENT climbs out of a directory; "report..final.txt" is just a name.
    if ".." in pathlib.Path(original_str).parts:
        raise AttachmentSecurityError(
            path=path,
            reason=f'path contains traversal sequence: "{original_str}"',
            violation_type=AttachmentViolation.PATH_TRAVERSAL,
        )


def _check_symlink(*, path: pathlib.Path, allow_symlinks: bool) -> pathlib.Path:
    """Check symlink status and return the resolved path.

    Symlinks can point to sensitive files outside intended directories.

    Args:
        path: The path to check.
        allow_symlinks: Whether symlinks are permitted.

    Returns:
        The resolved path (follows symlinks if allowed).

    Raises:
        AttachmentSecurityError: If the path is a symlink and symlinks are
            not allowed.
        _UnreadableAttachmentError: When the path cannot be examined
            (``EACCES``, ``ENAMETOOLONG``) or is a symlink loop (``ELOOP``).
    """
    if not _is_symlink(path):
        return _resolve(path)
    if not allow_symlinks:
        raise AttachmentSecurityError(
            path=path,
            reason=f'symlink detected and not allowed: "{path}"',
            violation_type=AttachmentViolation.SYMLINK,
        )
    try:
        resolved = _resolve(path)
    except RuntimeError:  # Python < 3.13 reports a symlink loop this way
        raise _UnreadableAttachmentError(errno.ELOOP) from None
    # Python 3.13+ returns a loop unresolved, still a symlink.
    if _is_symlink(resolved):
        raise _UnreadableAttachmentError(errno.ELOOP)
    return resolved


def _is_symlink(path: pathlib.Path) -> bool:
    """Whether path itself is a symlink; a path that does not exist is not one.

    ``Path.is_symlink()`` re-raises ``EACCES`` and ``ENAMETOOLONG`` on Python
    3.10-3.13 but swallows them on 3.14, so the outcome is decided here, the
    same on every version.

    Raises:
        _UnreadableAttachmentError: When the operating system refuses to
            examine the path for any reason other than its absence.
    """
    status = _lstat_or_none(path)
    return status is not None and stat.S_ISLNK(status.st_mode)


def _lstat_or_none(path: pathlib.Path) -> os.stat_result | None:
    """``os.lstat(path)``, or ``None`` when path does not exist.

    Raises:
        _UnreadableAttachmentError: When the operating system refuses to
            examine the path for any reason other than its absence, or the
            path cannot be handed to it (:func:`_too_long_to_name`).
    """
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise _UnreadableAttachmentError(exc.errno) from None
    except ValueError:
        raise _too_long_to_name() from None


# Unicode bidirectional formatting characters: they reorder how a name is displayed, so
# "report<U+202E>fdp.xlsm" reads as "reportmslx.pdf" ("Trojan Source", CVE-2021-42574).
_BIDI_CONTROLS: Final[frozenset[str]] = frozenset(chr(code) for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)))


def _check_filename(path: pathlib.Path) -> None:
    r"""Refuse a file name holding a control character (Unicode category ``Cc``).

    The name becomes the ``filename`` parameter of the attachment's
    ``Content-Disposition`` header. CR, LF, VT and FF make the header
    serialiser raise a bare ``ValueError`` halfway through composing, and NUL,
    ESC and DEL would be written into the header raw. A POSIX file system
    allows all of them in a name.

    Args:
        path: The path whose name is checked.

    Raises:
        AttachmentSecurityError: If the file name contains a control
            character or a bidirectional formatting character (which can make
            ``.xlsm`` display as ``.pdf``), is not valid Unicode text, or
            would reach the recipient as another name (an RFC 2047 encoded
            word).

    Examples:
        >>> _check_filename(pathlib.Path("/data/Bericht März.pdf"))
        >>> _check_filename(pathlib.Path("a\nb"))  # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        btx_lib_mail._attachments.AttachmentSecurityError: ...contains a control character: "a b" [path=a b]
    """
    if any(unicodedata.category(character) == "Cc" for character in path.name):
        raise AttachmentSecurityError(
            path=path,
            reason=f'file name contains a control character: "{path}"',
            violation_type=AttachmentViolation.FILENAME,
        )
    if any(character in _BIDI_CONTROLS for character in path.name):
        raise AttachmentSecurityError(
            path=path,
            reason=f'file name contains a bidirectional control character: "{path}"',
            violation_type=AttachmentViolation.FILENAME,
        )
    if not is_valid_unicode(path.name):
        raise AttachmentSecurityError(
            path=path,
            reason=f'file name is not valid Unicode text: "{path}"',
            violation_type=AttachmentViolation.FILENAME,
        )
    # The header drops surrounding whitespace; the extension check judges that trimmed name.
    if _filename_as_sent(path.name) != path.name.strip():
        raise AttachmentSecurityError(
            path=path,
            reason=f'file name would reach the recipient as another name (an RFC 2047 encoded word): "{path}"',
            violation_type=AttachmentViolation.FILENAME,
        )


def _filename_as_sent(name: str) -> str | None:
    """Return the file name a recipient reads from the header ``_compose`` writes for name.

    The email package decodes an RFC 2047 encoded word in the ``filename``
    parameter, so ``=?utf-8?b?aW52b2ljZS5leGU=?=`` (no suffix to block) arrives
    as ``invoice.exe``. Every other file name check judges ``name``; only a
    name that arrives unchanged was the one they judged.

    Examples:
        >>> _filename_as_sent("=?utf-8?b?aW52b2ljZS5leGU=?=")
        'invoice.exe'
        >>> _filename_as_sent("Bericht März.pdf")
        'Bericht März.pdf'
    """
    header = EmailMessage()
    header.add_header("Content-Disposition", "attachment", filename=name)
    return header.get_filename()


def _check_nameable(path: pathlib.Path) -> None:
    """Refuse a path the operating system cannot be handed, before any file system call sees it.

    NUL ends a name for the operating system, and a lone surrogate outside the
    ``surrogateescape`` range has no bytes on POSIX (Windows names it); either way
    ``os.lstat`` would raise a bare ``ValueError`` before the file name check runs.

    Args:
        path: The path to check.

    Raises:
        AttachmentSecurityError: ``FILENAME`` if the path contains NUL or cannot be
            encoded for the operating system.
    """
    if "\x00" in str(path):
        raise AttachmentSecurityError(
            path=path,
            reason=f'file name contains a control character: "{path}"',
            violation_type=AttachmentViolation.FILENAME,
        )
    try:
        os.fsencode(path)
    except UnicodeEncodeError:
        raise AttachmentSecurityError(
            path=path,
            reason=f'path can not be encoded for the operating system: "{path}"',
            violation_type=AttachmentViolation.FILENAME,
        ) from None


def _case_as_the_file_system_does(text: str) -> str:
    return text.casefold() if _PATHS_IGNORE_CASE else text


def _check_sensitive_patterns(path: pathlib.Path) -> None:
    """Check if the path matches any sensitive patterns.

    Some paths (SSH keys, credentials) should never be attached.

    Args:
        path: The resolved path to check.

    Raises:
        AttachmentSecurityError: If a sensitive pattern is matched.
    """
    # Forward slashes so one pattern serves Windows too.
    path_str_normalised = _case_as_the_file_system_does(str(path).replace("\\", "/"))

    for pattern in SENSITIVE_PATH_PATTERNS:
        if _case_as_the_file_system_does(pattern) in path_str_normalised:
            raise AttachmentSecurityError(
                path=path,
                reason=f'path matches sensitive pattern "{pattern}": "{path}"',
                violation_type=AttachmentViolation.SENSITIVE_PATTERN,
            )


def _check_directory_restrictions(
    path: pathlib.Path,
    allowed: frozenset[pathlib.Path] | None,
    blocked: frozenset[pathlib.Path],
) -> None:
    """Check directory whitelist/blacklist restrictions.

    Restrict which directories attachments can be read from.

    Args:
        path: The resolved path to check.
        allowed: When set, path must be under one of these resolved directories.
        blocked: Path must not be under any of these resolved directories.

    Raises:
        AttachmentSecurityError: If a directory restriction is violated.
    """
    # A resolved path is under a directory exactly when that directory is the path or
    # one of its ancestors; a set intersection costs the path's depth, not the number
    # of rules (100 attachments against 5000 blocked directories took seconds).
    ancestors = {path, *path.parents}

    if allowed is not None:
        if allowed.isdisjoint(ancestors):
            raise AttachmentSecurityError(
                path=path,
                reason=f'path not under any allowed directory: "{path}"',
                violation_type=AttachmentViolation.DIRECTORY,
            )
    else:
        # The nearest blocked ancestor is named, the same one whatever the set's order.
        blocked_ancestors = blocked & ancestors
        if blocked_ancestors:
            blocked_dir = max(blocked_ancestors, key=lambda directory: len(directory.parts))
            raise AttachmentSecurityError(
                path=path,
                reason=f'path under blocked directory "{blocked_dir}": "{path}"',
                violation_type=AttachmentViolation.DIRECTORY,
            )


def _check_extension(
    path: pathlib.Path,
    allowed: frozenset[str] | None,
    blocked: frozenset[str],
) -> None:
    """Check extension whitelist/blacklist restrictions.

    Prevent attachment of dangerous executable file types.

    Args:
        path: The path to check.
        allowed: When set, only these extensions are permitted (whitelist
            mode).
        blocked: Extensions to reject (ignored when whitelist is active).

    Raises:
        AttachmentSecurityError: If the extension is not allowed.
    """
    # Judged on the name the recipient reads: the header drops a trailing no-break space.
    ext = _effective_suffix(_filename_as_sent(path.name) or path.name)

    if allowed is not None:
        # Whitelist mode: only allowed extensions pass
        if ext not in allowed:
            raise AttachmentSecurityError(
                path=path,
                reason=f'extension "{ext}" not in allowed list: "{path}"',
                violation_type=AttachmentViolation.EXTENSION,
            )
    # Blacklist mode: block only blacklisted extensions
    elif ext in blocked:
        raise AttachmentSecurityError(
            path=path,
            reason=f'extension "{ext}" is blocked: "{path}"',
            violation_type=AttachmentViolation.EXTENSION,
        )


def _effective_suffix(name: str) -> str:
    """Return the lower-cased extension a recipient's system sees for name.

    Windows drops trailing dots and spaces from a file name, so ``x.exe.`` and
    ``x.exe `` are saved as ``x.exe``; :attr:`pathlib.PurePath.suffix` reports
    ``.`` and ``.exe `` for them, which no blocklist entry matches.

    Args:
        name: The file name to derive the effective suffix from.

    Returns:
        The lower-cased extension, as the recipient's system would see it.

    Examples:
        >>> _effective_suffix("x.sh. . ")
        '.sh'
        >>> _effective_suffix("REPORT.PDF")
        '.pdf'
    """
    return pathlib.PurePath(name.rstrip(". ") or name).suffix.lower()


def _check_size(path: pathlib.Path, size: int, max_size: int | None) -> None:
    """Raise when size (of the opened file at path) exceeds max_size.

    Args:
        path: The attachment path, for the error message.
        size: The opened file's actual size, in bytes.
        max_size: The size limit in force, or None for no limit.

    Raises:
        AttachmentSecurityError: If size exceeds max_size.
    """
    if max_size is not None and size > max_size:
        raise AttachmentSecurityError(
            path=path,
            reason=f'file size {size} bytes exceeds limit {max_size} bytes: "{path}"',
            violation_type=AttachmentViolation.SIZE,
        )


# How an attachment is opened. O_NOFOLLOW refuses a symlink as the last
# component: the path opened is already resolved, so a symlink there was swapped
# in after the checks. O_NONBLOCK keeps a FIFO swapped in from blocking the open.
# O_BINARY matters on Windows only. Each is 0 where the OS lacks it.
_ATTACHMENT_OPEN_FLAGS: Final[int] = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


# errno of open(O_NOFOLLOW) on a symlink: ELOOP on Linux and macOS, EMLINK on FreeBSD.
_NOFOLLOW_ERRNOS: Final[frozenset[int]] = frozenset({errno.ELOOP, errno.EMLINK})


if sys.platform == "linux":
    # A directory on the walk below: O_PATH needs no read permission, O_NOFOLLOW with
    # O_DIRECTORY refuses a symlink (ENOTDIR).
    _WALK_FLAGS: Final[int] = os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC

    def _open_checked_path(path: pathlib.Path) -> int:
        """Open the checked path one component at a time, following no symlink anywhere.

        O_NOFOLLOW guards only the last component of a plain open; a parent swapped
        for a link after the checks would lead it elsewhere. The checked path is
        resolved, so a link in it now was put there since: refused as ``CHANGED``,
        whether or not /proc is there to report the path afterwards.
        """
        directory = os.open(path.anchor, _WALK_FLAGS)
        try:
            for name in path.parts[1:-1]:
                try:
                    child = os.open(name, _WALK_FLAGS, dir_fd=directory)
                except NotADirectoryError:
                    raise _changed_after_check(path) from None
                os.close(directory)
                directory = child
            return os.open(path.name, _ATTACHMENT_OPEN_FLAGS, dir_fd=directory)
        finally:
            os.close(directory)

else:

    def _open_checked_path(path: pathlib.Path) -> int:
        """Open the checked path; the path the system reports for it is judged afterwards."""
        return os.open(path, _ATTACHMENT_OPEN_FLAGS)


def _changed_after_check(path: pathlib.Path) -> AttachmentSecurityError:
    return AttachmentSecurityError(
        path=path,
        reason=f'file changed after it was checked: "{path}"',
        violation_type=AttachmentViolation.CHANGED,
    )


class _UnreadableAttachmentError(Exception):
    """The path exists, but examining or opening it failed (permission, name length, symlink loop, I/O).

    Internal: :func:`_prepare_attachment` reports it like a missing file, so
    ``raise_on_missing_attachments`` decides between raising and skipping.

    Attributes:
        code: The symbolic errno name (``EACCES``), or ``"OSError"`` when unknown.
    """

    def __init__(self, error_number: int | None) -> None:
        self.code = _errno_name(error_number)
        super().__init__(self.code)


def _open_attachment(path: pathlib.Path, security: AttachmentSecurityOptions) -> IO[bytes] | None:
    """Open the checked, resolved path once and prove it is the file that was checked.

    Reading the file again later by name (once per recipient, as before) lets
    a path swapped after the checks - a symlink to ``/etc/passwd``, a file
    grown past the limit - reach the message. The file is opened here once,
    compared with what was checked (same device and inode, still a regular
    file, size within the limit), and that open file is what the message body
    is encoded from. ``O_NOFOLLOW`` guards only the last component: on Linux
    the path is opened one component at a time and a link in any of them is
    refused (:func:`_open_checked_path`); everywhere the path the kernel holds
    for the open file is judged too (:func:`_check_descriptor_path`), so a
    parent directory swapped for a link cannot lead the open into a blocked
    directory.

    Args:
        path: The already-checked, resolved path to open.
        security: The security options the path was checked against.

    Returns:
        The opened file, or ``None`` when path does not exist or is not a
        regular file (the caller reports it as missing).

    Raises:
        AttachmentSecurityError: ``CHANGED`` when the path became a symlink or
            another file after the checks, or something other than a regular
            file (a directory, a FIFO) while it was opened; ``SIZE`` when the
            file exceeds max_size.
        _UnreadableAttachmentError: When the regular file exists but the
            operating system refuses to open it.
    """
    checked = _lstat_or_none(path)
    if checked is None:
        return None
    if stat.S_ISLNK(checked.st_mode):
        raise _changed_after_check(path)
    if not stat.S_ISREG(checked.st_mode):
        return None
    try:
        descriptor = _open_checked_path(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in _NOFOLLOW_ERRNOS:
            raise _changed_after_check(path) from None
        raise _UnreadableAttachmentError(exc.errno) from None
    except ValueError:
        raise _too_long_to_name() from None
    # Judged on the raw descriptor: os.fdopen raises a bare IsADirectoryError for a
    # directory swapped in during the open (POSIX opens one for reading), and the
    # descriptor it was handed would leak with it.
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
            raise _changed_after_check(path)
    except BaseException:
        os.close(descriptor)
        raise
    handle = os.fdopen(descriptor, "rb")
    try:
        _check_descriptor_path(handle.fileno(), path, security)
        _check_size(path, opened.st_size, security.max_size_bytes)
    except BaseException:
        handle.close()
        raise
    return handle


def _check_descriptor_path(descriptor: int, path: pathlib.Path, security: AttachmentSecurityOptions) -> None:
    """Refuse an open file whose own path would not pass the checks path passed.

    The kernel reports the path the descriptor actually names. Equal to the
    checked path is the common case; a different one (a parent swapped for a
    link, or another name of a hard-linked file) is judged by the same path
    checks, so a file the policy permits is still sent and one it refuses is
    not. Where the system cannot say (Linux without /proc), the open has already
    refused a link in any component; on another system without a lookup, a
    parent swapped for a link is not detected.

    Raises:
        AttachmentSecurityError: ``CHANGED`` when the opened file's path fails
            a check.
    """
    opened_path = descriptor_path(descriptor)
    if opened_path is None or _case_as_the_file_system_does(os.path.normcase(opened_path)) == _case_as_the_file_system_does(os.path.normcase(str(path))):
        return
    try:
        _check_resolved_path(pathlib.Path(opened_path), security)
    except AttachmentSecurityError:
        raise _changed_after_check(path) from None


def _check_resolved_path(resolved_path: pathlib.Path, security: AttachmentSecurityOptions) -> None:
    """Run the checks that judge a resolved path: its name, patterns, directory and extension."""
    # The resolved name is the one the message carries (see _prepare_attachment).
    _check_filename(resolved_path)
    _check_sensitive_patterns(resolved_path)
    _check_directory_restrictions(
        resolved_path,
        security.allowed_directories,
        security.blocked_directories,
    )
    _check_extension(
        resolved_path,
        security.allowed_extensions,
        security.blocked_extensions,
    )


def _validate_attachment_security(
    path: pathlib.Path,
    original_path_str: str,
    security: AttachmentSecurityOptions,
) -> pathlib.Path:
    """Run the path-based security checks for a single attachment.

    Provides a single entry point for attachment path validation. The size is
    checked on the opened file (:func:`_open_attachment`), not here.

    Args:
        path: The path object to validate.
        original_path_str: The original string representation (for traversal
            detection).
        security: Resolved security options.

    Returns:
        The resolved path (after symlink resolution if applicable).

    Raises:
        AttachmentSecurityError: If any check fails. File existence is not
            checked here.
        _UnreadableAttachmentError: When the path cannot be examined (also when
            it is longer than the operating system can name, or cannot be encoded
            for it), or is a symlink loop.
    """
    _check_nameable(path)
    _check_path_traversal(path, original_path_str)
    resolved_path = _check_symlink(path=path, allow_symlinks=security.allow_symlinks)
    _check_resolved_path(resolved_path, security)
    return resolved_path


def prepare_attachments(
    paths: tuple[pathlib.Path, ...],
    security: AttachmentSecurityOptions,
    *,
    raise_on_missing: bool,
) -> tuple[AttachmentPayload, ...]:
    """Check each attachment path, open the checked file once, and return the payloads.

    Validates attachment existence and security before SMTP attempts begin,
    and ties what is sent to the file that was checked. Opens files; logs or
    raises when missing or security violations occur.

    Args:
        paths: Tuple of candidate filesystem paths (may be empty).
        security: Resolved security options for validation.
        raise_on_missing: When ``True``, missing files raise
            ``AttachmentNotFoundError``; when ``False``, a warning is logged
            and the attachment is skipped.

    Returns:
        Payloads holding open files; the caller closes them
        (:func:`close_attachments`). On any failure, those already opened are
        closed before the error propagates.

    Raises:
        InvalidInputError: If there are more paths than `security.max_count`, or
            a directory rule cannot be resolved; no file is checked or opened then.
    """
    if security.max_count is not None and len(paths) > security.max_count:
        raise InvalidInputError(f"{len(paths)} attachments, more than attachment_max_count ({security.max_count})")
    if not paths:
        return ()
    security = _with_resolved_directories(security)
    prepared: list[AttachmentPayload] = []
    try:
        for path in paths:
            payload = _prepare_attachment(path, security, raise_on_missing=raise_on_missing)
            if payload is not None:
                prepared.append(payload)
    except BaseException:
        close_attachments(tuple(prepared))
        raise
    return tuple(prepared)


def _prepare_attachment(path: pathlib.Path, security: AttachmentSecurityOptions, *, raise_on_missing: bool) -> AttachmentPayload | None:
    """Check and open one attachment; ``None`` when it is skipped (warn mode, or missing and tolerated)."""
    original_path_str = str(path)
    try:
        validated_path = _validate_attachment_security(path, original_path_str, security)
    except AttachmentSecurityError as exc:
        if security.raise_on_violation:
            raise
        log_violation(exc, original_path_str)
        return None
    except _UnreadableAttachmentError as exc:
        return _unavailable(path, f"can not be read ({exc.code})", raise_on_missing=raise_on_missing)
    try:
        handle = _open_attachment(validated_path, security)
    except AttachmentSecurityError as exc:
        if security.raise_on_violation:
            raise
        log_violation(exc, original_path_str)
        return None
    except _UnreadableAttachmentError as exc:
        return _unavailable(validated_path, f"can not be read ({exc.code})", raise_on_missing=raise_on_missing)

    if handle is None:
        return _unavailable(validated_path, "can not be found", raise_on_missing=raise_on_missing)

    return AttachmentPayload(
        filename=validated_path.name,
        source=validated_path,
        handle=handle,
        size_limit=security.max_size_bytes,
    )


def _unavailable(path: pathlib.Path, problem: str, *, raise_on_missing: bool) -> None:
    """Raise or log an attachment that is missing or cannot be read.

    Args:
        path: The checked path.
        problem: What went wrong, completing ``Attachment File "<path>" ...``.
        raise_on_missing: Raise when ``True``; log a warning and skip otherwise.

    Raises:
        AttachmentNotFoundError: When raise_on_missing is ``True``.
    """
    clean_path = _quoted(str(path))
    if raise_on_missing:
        raise AttachmentNotFoundError(f'Attachment File "{clean_path}" {problem}')
    logger.warning(
        'Attachment File "%s" %s',
        clean_path,
        problem,
        extra={"attachment_path": clean_path, "skipped": "attachment"},
    )


def coerce_attachment_paths(entries: object, *, max_count: int | None = None) -> tuple[pathlib.Path, ...]:
    """Return each attachment entry as a path; a ``str`` or a ``pathlib`` path is accepted.

    A lazy iterable (a generator such as ``Path.glob()``) is read only one entry
    past max_count, so an endless one is refused instead of exhausting memory.

    Args:
        entries: The caller's attachment entries, typed loosely because the
            annotation on ``send()`` is not enforced at run time.
        max_count: Most attachments one call accepts; None sets no limit.

    Returns:
        The entries as ``pathlib.Path`` objects, in order.

    Raises:
        InvalidInputError: If entries is a single path (``str``, ``bytes``,
            ``pathlib`` path) or not iterable rather than a sequence of
            paths, an entry is neither a ``str`` nor a ``pathlib`` path, or a
            lazy iterable yields more than max_count entries.

    Examples:
        >>> [path.name for path in coerce_attachment_paths(["/data/a.pdf", pathlib.Path("/data/b.pdf")])]
        ['a.pdf', 'b.pdf']
    """
    # A bare string is iterable too, and would be checked one character at a time.
    if isinstance(entries, (str, bytes, pathlib.PurePath)) or not isinstance(entries, Iterable):
        raise InvalidInputError(f"attachment_file_paths must be a sequence of paths, got {type(entries).__name__}")
    iterable = cast("Iterable[object]", entries)
    # A collection is already in memory; only a lazy iterable is cut short.
    limit = None if isinstance(entries, Sized) else max_count
    if limit is not None:
        iterable = itertools.islice(iterable, limit + 1)
    paths: list[pathlib.Path] = []
    for entry in iterable:
        if not isinstance(entry, (str, pathlib.PurePath)):
            raise InvalidInputError(f"attachment_file_paths entries must be paths, got {type(entry).__name__}")
        paths.append(pathlib.Path(entry))
    if limit is not None and len(paths) > limit:
        raise InvalidInputError(f"attachment_file_paths yields more than attachment_max_count ({limit}) paths")
    return tuple(paths)


def log_violation(exc: AttachmentSecurityError, original_path_str: str) -> None:
    """Log a skipped attachment's violation (warn mode)."""
    # `exc.reason` and `original_path_str` are both built from the
    # caller-supplied path; `AttachmentSecurityError.__init__` already
    # cleans `.reason`, but the path is cleaned again here too, as
    # defense in depth and for consistency with every other log call.
    logger.warning(
        "Attachment security violation: %s",
        printable(exc.reason),
        extra={
            "attachment_path": _quoted(original_path_str),
            "violation_type": exc.violation_type.value,
            "skipped": "attachment",
        },
    )


def close_attachments(attachments: tuple[AttachmentPayload, ...]) -> None:
    for attachment in attachments:
        attachment.handle.close()
