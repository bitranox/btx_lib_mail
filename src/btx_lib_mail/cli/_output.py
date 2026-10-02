"""One place decides human text or JSON, for success and failure alike, and collects the skips of a run.

Private to btx_lib_mail.cli: import the public names from `btx_lib_mail.cli`.
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import rich_click as click

from ..errors import DeliveryError
from ..lib_mail import Transport
from ..lib_mail import logger as mail_logger

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping, Sequence

__all__ = ["FAILED_RUN_SKIPPED", "CliContext", "cli_context", "collect_skipped", "dumps_json", "emit", "error_payload"]


# The skips of a send that then failed, for main()'s JSON failure report: the command's own
# frame is gone by the time the exception reaches the handler.
FAILED_RUN_SKIPPED: ContextVar[tuple[dict[str, str], ...]] = ContextVar("btx_mail_failed_run_skipped", default=())


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


def dumps_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False)


def emit(ctx: click.Context, command: str, data: Mapping[str, Any], human: str, *, skipped: Sequence[Mapping[str, str]] = ()) -> None:
    """Print one command's result in the output mode the group was given."""
    state = cli_context(ctx)
    if state.json_bare:
        click.echo(dumps_json(dict(data)))
    elif state.json_output:
        click.echo(dumps_json({"ok": True, "command": command, "data": dict(data), "skipped": [dict(item) for item in skipped]}))
    else:
        click.echo(human)


def error_payload(exc: BaseException) -> dict[str, object]:
    payload: dict[str, object] = {"type": type(exc).__name__, "message": str(exc)}
    if isinstance(exc, DeliveryError):
        payload["failed_recipients"] = list(exc.failed_recipients)
        payload["hosts"] = list(exc.hosts)
    return payload


class _SkipCollector(logging.Filter):
    """Collect the library's "skipped" warnings while passing every record on unchanged.

    A filter on the library logger, not a handler: adding a handler would stop the
    warnings reaching stderr through logging's last-resort handler.
    """

    def __init__(self) -> None:
        super().__init__()
        self.skipped: list[dict[str, str]] = []

    def filter(self, record: logging.LogRecord) -> bool:
        kind = record.__dict__.get("skipped")
        if isinstance(kind, str):
            value = record.__dict__.get("attachment_path") or record.__dict__.get("recipient") or ""
            self.skipped.append({"kind": kind, "value": str(value), "reason": record.getMessage()})
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
