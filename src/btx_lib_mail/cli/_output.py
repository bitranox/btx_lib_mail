"""One place decides human text or JSON, for success and failure alike, and collects the skips of a run.

Private to btx_lib_mail.cli: import the public names from `btx_lib_mail.cli`.
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import rich_click as click
from pydantic import BaseModel, Field

from .._common import SkipKind
from ..errors import DeliveryError
from ..lib_mail import Transport
from ..lib_mail import logger as mail_logger
from ._payloads import CommandPayload

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

__all__ = [
    "FAILED_RUN_SKIPPED",
    "CliContext",
    "ErrorPayload",
    "FailureEnvelope",
    "SkippedItem",
    "SuccessEnvelope",
    "cli_context",
    "collect_skipped",
    "dumps_json",
    "emit",
    "error_payload",
]


class SkippedItem(BaseModel, frozen=True, extra="forbid"):
    """One recipient or attachment a warn-mode send left out.

    Attributes:
        kind: Whether a recipient or an attachment was left out.
        value: The recipient, or the attachment path, as the warning named it.
        reason: The warning's message.
    """

    kind: SkipKind
    value: str
    reason: str


def _absent(value: object) -> bool:
    return value is None


class ErrorPayload(BaseModel, frozen=True, extra="forbid"):
    """A failure as JSON reports it: `failed_recipients` and `hosts` appear for a `DeliveryError` only.

    Attributes:
        type: The exception's class name.
        message: The exception's message.
        failed_recipients: The recipients no host accepted; omitted unless delivery failed.
        hosts: The hosts that were tried; omitted unless delivery failed.
    """

    type: str
    message: str
    failed_recipients: tuple[str, ...] | None = Field(default=None, exclude_if=_absent)
    hosts: tuple[str, ...] | None = Field(default=None, exclude_if=_absent)


class SuccessEnvelope(BaseModel, frozen=True, extra="forbid"):
    """The `--json` report of a command that succeeded.

    Attributes:
        ok: Always ``True``.
        command: The subcommand name.
        data: The command's own payload.
        skipped: What a warn-mode send left out.
    """

    ok: Literal[True] = True
    command: str
    data: CommandPayload
    skipped: tuple[SkippedItem, ...] = ()


class FailureEnvelope(BaseModel, frozen=True, extra="forbid"):
    """The `--json` report of a command that failed.

    Attributes:
        ok: Always ``False``.
        command: The subcommand name, or ``None`` when the arguments name none.
        error: What failed.
        skipped: What a warn-mode send left out before it failed.
    """

    ok: Literal[False] = False
    command: str | None
    error: ErrorPayload
    skipped: tuple[SkippedItem, ...] = ()


# The skips of a send that then failed, for main()'s JSON failure report: the command's own
# frame is gone by the time the exception reaches the handler.
FAILED_RUN_SKIPPED: ContextVar[tuple[SkippedItem, ...]] = ContextVar("btx_mail_failed_run_skipped", default=())


@dataclass(frozen=True)
class CliContext:
    """The typed `ctx.obj` every command reads.

    Attributes:
        traceback: Verbose tracebacks were requested.
        json_output: Print the JSON envelope.
        json_bare: Print the JSON payload without the envelope.
        transport: Delivery adapter `send` hands to the library; `None` uses the SMTP
            transport. An application embedding the CLI, or a test, passes its own
            through `cli.main(obj=CliContext(transport=...))` or
            `CliRunner.invoke(cli, args, obj=...)`.
    """

    traceback: bool = False
    json_output: bool = False
    json_bare: bool = False
    transport: Transport | None = None

    @property
    def machine_readable(self) -> bool:
        return self.json_output or self.json_bare


def cli_context(ctx: click.Context) -> CliContext:
    """Return the typed context object, creating it when a command runs on its own."""
    if not isinstance(ctx.obj, CliContext):
        ctx.obj = CliContext()
    return ctx.obj


def dumps_json(model: BaseModel) -> str:
    r"""Serialise model as JSON that a UTF-8 stream can always write.

    Non-ASCII text stays readable, but a lone surrogate (what an invalid UTF-8
    byte in a path or argument decodes to) cannot be encoded; it is written as
    its ``\u`` escape, which is how JSON carries it.

    Args:
        model: The payload or envelope to report.

    Returns:
        The JSON text, keys in the model's field order.

    Examples:
        >>> dumps_json(ErrorPayload(type="X", message="a" + chr(0xDCFF)))
        '{"type": "X", "message": "a\\udcff"}'
    """
    return json.dumps(model.model_dump(mode="json"), ensure_ascii=False).encode("utf-8", "backslashreplace").decode("utf-8")


def emit(ctx: click.Context, command: str, data: CommandPayload, human: str, *, skipped: Sequence[SkippedItem] = ()) -> None:
    """Print one command's result in the output mode the group was given.

    Args:
        ctx: Click context carrying the output mode.
        command: The subcommand name, for the envelope.
        data: The command's payload.
        human: The line printed without `--json` / `--json-bare`.
        skipped: What a warn-mode send left out.
    """
    state = cli_context(ctx)
    if state.json_bare:
        click.echo(dumps_json(data))
    elif state.json_output:
        click.echo(dumps_json(SuccessEnvelope(command=command, data=data, skipped=tuple(skipped))))
    else:
        click.echo(human)


def error_payload(exc: BaseException) -> ErrorPayload:
    """Describe exc for the JSON failure report.

    Args:
        exc: The exception the command raised.

    Returns:
        Its payload; the recipient and host lists only for a `DeliveryError`.

    Examples:
        >>> error_payload(ValueError("nope")).model_dump(mode="json")
        {'type': 'ValueError', 'message': 'nope'}
    """
    if isinstance(exc, DeliveryError):
        return ErrorPayload(type=type(exc).__name__, message=str(exc), failed_recipients=tuple(exc.failed_recipients), hosts=tuple(exc.hosts))
    return ErrorPayload(type=type(exc).__name__, message=str(exc))


class _SkipCollector(logging.Filter):
    """Collect the library's "skipped" warnings while passing every record on unchanged.

    A filter on the library logger, not a handler: adding a handler would stop the
    warnings reaching stderr through logging's last-resort handler.
    """

    def __init__(self) -> None:
        super().__init__()
        self.skipped: list[SkippedItem] = []

    def filter(self, record: logging.LogRecord) -> bool:
        # The log record is where the library's words reach the CLI: parse the plain
        # "skipped" string into its kind here, once; a record without one is not a skip.
        try:
            kind = SkipKind(record.__dict__.get("skipped"))
        except ValueError:
            return True
        value = record.__dict__.get("attachment_path") or record.__dict__.get("recipient") or ""
        self.skipped.append(SkippedItem(kind=kind, value=str(value), reason=record.getMessage()))
        return True


@contextmanager
def collect_skipped() -> Generator[_SkipCollector, None, None]:
    collector = _SkipCollector()
    mail_logger.addFilter(collector)
    FAILED_RUN_SKIPPED.set(())
    try:
        yield collector
    except BaseException:
        FAILED_RUN_SKIPPED.set(tuple(collector.skipped))
        raise
    finally:
        mail_logger.removeFilter(collector)
