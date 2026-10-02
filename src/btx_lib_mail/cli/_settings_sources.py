"""Where an unset `send` option comes from: the environment, then the env file, then `conf`.

Private to btx_lib_mail.cli: import the public names from `btx_lib_mail.cli`.
"""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, Final, TypeVar

import rich_click as click
from pydantic import ValidationError

from ..errors import InvalidInputError
from ..lib_mail import validate_smtp_host

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping, Sequence

__all__ = [
    "Sources",
    "checked_hosts",
    "env_file_to_read",
    "or_default",
    "read_env_file",
    "refusals_as_value_error",
    "resolve_bool",
    "resolve_credentials",
    "resolve_directories",
    "resolve_extensions",
    "resolve_float",
    "resolve_int",
    "resolve_list",
    "resolve_optional_bool",
    "resolve_password",
]


_TRUE_VALUES = {"1", "true", "yes", "on"}


_FALSE_VALUES = {"0", "false", "no", "off"}


_T = TypeVar("_T")


# Resolved against the working directory each time it is read, so it follows a chdir.
_DOTENV_PATH: Final[Path] = Path(".env")


# An env file is a handful of KEY=value lines; anything larger is not one, and is
# refused before it is read rather than parsed into memory.
_ENV_FILE_MAX_BYTES: Final[int] = 64 * 1024


# A password file holds one line; more than this is not a password file.
_PASSWORD_FILE_MAX_CHARS: Final[int] = 4096


# A quoted value has at least its two quote characters.
_QUOTED_MIN_LEN: Final[int] = 2


@dataclass(frozen=True)
class Sources:
    """The values a command may read for an option it was not given.

    The process environment wins over the env file; a key set to an empty
    string in either counts as unset. The env file is the one ``--env-file``
    names, otherwise ``.env`` in the working directory when it is a file.
    """

    environ: Mapping[str, str]
    env_file: Mapping[str, str] = field(default_factory=lambda: {})

    def value(self, key: str) -> str | None:
        env_value = self.environ.get(key)
        if env_value not in (None, ""):
            return env_value
        return self.env_file.get(key) or None


def env_file_to_read(named: Path | None) -> Path | None:
    """Return the file ``--env-file`` names, else ``./.env`` when it is a regular file.

    A named file replaces ``./.env`` entirely: keys it lacks do not fall through.
    """
    if named is not None:
        return named
    return _DOTENV_PATH if _DOTENV_PATH.is_file() else None


def _env_file_refusal(path: Path, problem: str) -> click.UsageError:
    """Name the file the way the user chose it: the ``--env-file`` value, or the implicit ``./.env``."""
    if path is _DOTENV_PATH:
        return click.UsageError(f"./.env in the working directory {problem}")
    return click.BadParameter(f"{path} {problem}", param_hint="--env-file")


def _read_bounded_text_file(path: Path) -> bytes:
    """Read a regular file of at most ``_ENV_FILE_MAX_BYTES`` bytes, refusing anything else.

    A device or FIFO reports size 0, so a size check before reading would let
    ``/dev/zero`` be read until memory runs out and a FIFO block for a writer.
    The file is opened without blocking, its type checked on the open handle,
    and at most one byte past the limit is read, so a file that grows after the
    check is refused too.

    Args:
        path: The env file.

    Returns:
        The file's bytes.

    Raises:
        click.UsageError: The file is not a regular file or is too large.
    """
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise _env_file_refusal(path, "is not a regular file")
        data = handle.read(_ENV_FILE_MAX_BYTES + 1)
        if len(data) > _ENV_FILE_MAX_BYTES:
            size = max(os.fstat(handle.fileno()).st_size, len(data))
            raise _env_file_refusal(path, f"is {size} bytes; an env file may be at most {_ENV_FILE_MAX_BYTES} bytes")
    return data


def read_env_file(path: Path | None) -> dict[str, str]:
    """Parse the env file once into ``KEY -> value`` (first occurrence wins).

    Lines are ``KEY=value``; blank lines, ``#`` comments and lines without ``=``
    are skipped; a value is stripped of whitespace and one layer of quotes.

    Args:
        path: Path to the env file, or ``None`` when none applies.

    Returns:
        Mapping of ``KEY`` to value for every parsed line.

    Raises:
        click.UsageError: The file is not a regular file, is larger than
            ``_ENV_FILE_MAX_BYTES``, or is not UTF-8.
    """
    if path is None:
        return {}
    try:
        text = _read_bounded_text_file(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _env_file_refusal(path, "is not UTF-8 text") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        values.setdefault(key.strip(), _unquoted(raw_value))
    return values


def _split_values(values: Sequence[str]) -> list[str]:
    flattened: list[str] = []
    for raw in values:
        for item in raw.split(","):
            candidate = item.strip()
            if candidate:
                flattened.append(candidate)
    return flattened


def resolve_list(cli_values: Sequence[str], env_key: str, *, label: str, sources: Sources) -> list[str]:
    values = _split_values(cli_values)
    if not values:
        env_raw = sources.value(env_key)
        if env_raw:
            values = _split_values([env_raw])
    if not values:
        raise click.UsageError(f"Provide at least one {label} via options or {env_key}.")
    return values


def _parse_bool(env_raw: str | None, env_key: str) -> bool | None:
    """Return the boolean *env_raw* spells, or ``None`` when it is unset or blank.

    A blank value is "not set": reading it as False would let a stray space switch
    STARTTLS or certificate checks off, while an unset variable keeps them on.
    """
    if env_raw is None or env_raw.strip() == "":
        return None
    lowered = env_raw.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise click.BadParameter(f"Unrecognised boolean value for {env_key}: {env_raw!r}")


def resolve_bool(*, cli_flag: bool | None, env_key: str, default: bool, sources: Sources) -> bool:
    if cli_flag is not None:
        return cli_flag
    return or_default(_parse_bool(sources.value(env_key), env_key), default)


def resolve_optional_bool(*, cli_flag: bool | None, env_key: str, sources: Sources) -> bool | None:
    """Return the bool value provided via CLI, the sources, or None for the config's own value."""
    if cli_flag is not None:
        return cli_flag
    return _parse_bool(sources.value(env_key), env_key)


def or_default(value: _T | None, default: _T) -> _T:
    """Return *value*, or *default* when it is ``None`` (a falsy ``0`` is kept, so the model can refuse it)."""
    return default if value is None else value


def _refusal_message(error: ValidationError) -> str:
    """Return the validators' own reasons, one line each.

    Every ``ConfMail`` validator names its field in its message, so the text is
    the one ``send()`` raised for the same value. pydantic's own report adds its
    error-type tags and a versioned URL, which describe the library rather than
    the operator's input; ``--traceback`` still shows it through the chain.
    """
    return "\n".join(detail["msg"].removeprefix("Value error, ") for detail in error.errors())


@contextmanager
def refusals_as_value_error() -> Generator[None, None, None]:
    """Raise a setting the model refuses as an ``InvalidInputError``, a ``ValueError`` (exit code 22)."""
    try:
        yield
    except ValidationError as exc:
        raise InvalidInputError(_refusal_message(exc)) from exc


def _unquoted(value: str) -> str:
    """Strip surrounding whitespace and ONE matching pair of quotes, as env-file values and hosts are read.

    Only a pair is removed, so a password that merely starts or ends with a quote
    character keeps it.

    Args:
        value: Raw value to strip.

    Returns:
        The stripped value.

    Examples:
        >>> _unquoted(' "s3cret" '), _unquoted('s3cret"'), _unquoted('""x""')
        ('s3cret', 's3cret"', '"x"')
    """
    stripped = value.strip()
    if len(stripped) >= _QUOTED_MIN_LEN and stripped[0] == stripped[-1] and stripped[0] in "\"'":
        return stripped[1:-1]
    return stripped


def checked_hosts(values: Sequence[str]) -> list[str]:
    """Return *values* unquoted, refusing a malformed one with ``validate_smtp_host``'s own message.

    ``ConfMail`` runs the same check, but its refusal hides the host (the field
    may carry a credential); checking first keeps the message quoting the host
    that the operator typed.
    """
    hosts = [_unquoted(value) for value in values]
    for host in hosts:
        if host:
            validate_smtp_host(host)
    return hosts


def resolve_credentials(user: str | None, password: str | None) -> tuple[str, str] | None:
    if user and password:
        return user, password
    return None


def _read_password_file(handle: IO[str] | None) -> str | None:
    """Return the first line of the ``--password-file`` (``-`` reads stdin), without its line break."""
    if handle is None:
        return None
    try:
        content = handle.read(_PASSWORD_FILE_MAX_CHARS + 1)
    except UnicodeDecodeError:
        # The decoder's message quotes the offending byte and its offset in the password.
        raise click.BadParameter("is not UTF-8 text", param_hint="--password-file") from None
    if len(content) > _PASSWORD_FILE_MAX_CHARS:
        raise click.BadParameter(f"a password file holds one line of at most {_PASSWORD_FILE_MAX_CHARS} characters", param_hint="--password-file")
    lines = content.splitlines()
    return lines[0] if lines else None


def resolve_password(*, password: str | None, password_file: IO[str] | None, sources: Sources) -> str | None:
    if password is not None and password_file is not None:
        raise click.UsageError(
            "--password and --password-file are mutually exclusive; prefer --password-file, which keeps the password out of the process list"
        )
    return password or _read_password_file(password_file) or sources.value("BTX_MAIL_SMTP_PASSWORD")


def resolve_float(cli_value: float | None, env_key: str, *, sources: Sources) -> float | None:
    """Return the float given on the CLI or in the sources, or ``None`` when neither set it.

    Args:
        cli_value: Value given on the CLI, or ``None``.
        env_key: Environment/env-file key to fall back to.
        sources: The environment and env-file values to read from.

    Returns:
        The resolved float, or ``None`` when neither source set it.

    Raises:
        click.BadParameter: The source value is not a number.
    """
    if cli_value is not None:
        return cli_value
    env_raw = sources.value(env_key)
    if env_raw is None or env_raw.strip() == "":
        return None
    try:
        return float(env_raw.strip())
    except ValueError as exc:
        raise click.BadParameter(f"Unrecognised float value for {env_key}: {env_raw!r}") from exc


def resolve_int(cli_value: int | None, env_key: str, *, sources: Sources) -> int | None:
    """Return the int given on the CLI or in the sources, or ``None`` when neither set it.

    Args:
        cli_value: Value given on the CLI, or ``None``.
        env_key: Environment/env-file key to fall back to.
        sources: The environment and env-file values to read from.

    Returns:
        The resolved int, or ``None`` when neither source set it.

    Raises:
        click.BadParameter: The source value is not an integer.
    """
    if cli_value is not None:
        return cli_value
    env_raw = sources.value(env_key)
    if env_raw is None or env_raw.strip() == "":
        return None
    try:
        return int(env_raw.strip())
    except ValueError as exc:
        raise click.BadParameter(f"Unrecognised int value for {env_key}: {env_raw!r}") from exc


def resolve_extensions(cli_value: str | None, env_key: str, *, sources: Sources) -> frozenset[str] | None:
    """Resolve a comma-separated extension list (lower-cased, dot-prefixed), or None for the config's own value."""
    raw = cli_value or sources.value(env_key)
    if raw is None or raw.strip() == "":
        return None

    extensions: set[str] = set()
    for raw_ext in raw.split(","):
        ext = raw_ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        extensions.add(ext)

    return frozenset(extensions) if extensions else None


def resolve_directories(cli_values: Sequence[str], env_key: str, *, sources: Sources) -> frozenset[Path] | None:
    """Resolve repeated or comma-separated directories, or None for the config's own value."""
    flattened = _split_values(cli_values)

    if not flattened:
        env_raw = sources.value(env_key)
        if env_raw:
            flattened = _split_values([env_raw])

    directories = {Path(raw_dir.strip()) for raw_dir in flattened if raw_dir.strip()}
    return frozenset(directories) if directories else None
