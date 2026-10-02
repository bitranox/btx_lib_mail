"""Module entry stories ensuring `python -m` mirrors the CLI."""

from __future__ import annotations

import importlib
import json
import runpy
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, TextIO

import lib_cli_exit_tools
import pytest

from btx_lib_mail import __init__conf__
from btx_lib_mail import cli as cli_mod

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(slots=True)
class PrintedTraceback:
    """Capture of a traceback rendering invoked by ``lib_cli_exit_tools``.

    Attributes
    ----------
    trace_back:
        ``True`` when verbose tracebacks were printed.
    length_limit:
        Character budget applied to the output.
    stream_present:
        ``True`` when a stream object was provided to the printer.
    """

    trace_back: bool
    length_limit: int
    stream_present: bool


def _record_print_message(target: list[PrintedTraceback]) -> Callable[..., None]:
    """Return an exception printer that records each invocation.

    Why
        Module-entry tests assert that ``lib_cli_exit_tools`` prints the correct
        style of traceback; capturing the parameters lets the test assert intent
        without examining stderr.

    Inputs
        target:
            Mutable list collecting :class:`PrintedTraceback` entries.

    Outputs
        Callable[..., None]:
            Replacement printer used during the test.
    """

    def _printer(
        *,
        trace_back: bool = False,
        length_limit: int = 500,
        stream: TextIO | None = None,
    ) -> None:
        target.append(
            PrintedTraceback(
                trace_back=trace_back,
                length_limit=length_limit,
                stream_present=stream is not None,
            )
        )

    return _printer


@pytest.mark.os_agnostic
def test_when_module_entry_returns_zero_the_story_matches_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger: dict[str, object] = {}

    monkeypatch.setattr(sys, "argv", ["btx_lib_mail"], raising=False)

    def fake_run_cli(
        command: object,
        argv: list[str] | None = None,
        *,
        prog_name: str | None = None,
        **_: object,
    ) -> int:
        ledger["command"] = command
        ledger["argv"] = argv
        ledger["prog_name"] = prog_name
        return 0

    monkeypatch.setattr(lib_cli_exit_tools, "run_cli", fake_run_cli)
    monkeypatch.setattr("lib_cli_exit_tools.application.runner.run_cli", fake_run_cli)

    with pytest.raises(SystemExit) as exc:
        runpy.run_module("btx_lib_mail.__main__", run_name="__main__")

    assert exc.value.code == 0
    assert ledger["command"] is cli_mod.cli
    assert ledger["prog_name"] == __init__conf__.shell_command


@pytest.mark.os_agnostic
def test_when_module_entry_raises_the_exit_helpers_format_the_song(monkeypatch: pytest.MonkeyPatch) -> None:
    printed: list[PrintedTraceback] = []
    codes: list[str] = []
    monkeypatch.setattr(sys, "argv", ["btx_lib_mail"], raising=False)
    monkeypatch.setattr(lib_cli_exit_tools.config, "traceback", False, raising=False)
    monkeypatch.setattr(lib_cli_exit_tools.config, "traceback_force_color", False, raising=False)

    def fake_code(exc: BaseException) -> int:
        codes.append(f"code:{exc}")
        return 88

    def exploding_run_cli(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("boom")

    printer = _record_print_message(printed)
    monkeypatch.setattr(lib_cli_exit_tools, "print_exception_message", printer)
    monkeypatch.setattr(lib_cli_exit_tools, "get_system_exit_code", fake_code)
    monkeypatch.setattr(lib_cli_exit_tools, "run_cli", exploding_run_cli)

    with pytest.raises(SystemExit) as exc:
        runpy.run_module("btx_lib_mail.__main__", run_name="__main__")

    assert exc.value.code == 88
    assert printed == [PrintedTraceback(trace_back=False, length_limit=500, stream_present=False)]
    assert codes == ["code:boom"]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("traceback", "expected_limit"), [(True, 22), (False, 11)], ids=["verbose", "summary"])
def test_an_exception_escaping_the_cli_runner_is_printed_with_the_budget_of_the_traceback_mode(
    monkeypatch: pytest.MonkeyPatch, isolated_traceback_config: None, traceback: bool, expected_limit: int
) -> None:
    # run_cli handles a command's own failure, so main()'s except branch needs one escaping it.
    printed: list[PrintedTraceback] = []

    def exploding_run_cli(*_args: object, **_kwargs: object) -> int:
        cli_mod.apply_traceback_preferences(traceback)  # what --traceback does once parsed
        raise RuntimeError("boom")

    monkeypatch.setattr(lib_cli_exit_tools, "print_exception_message", _record_print_message(printed))
    monkeypatch.setattr(lib_cli_exit_tools, "run_cli", exploding_run_cli)

    exit_code = cli_mod.main(["info"], summary_limit=11, verbose_limit=22)

    assert exit_code != 0
    assert printed == [PrintedTraceback(trace_back=traceback, length_limit=expected_limit, stream_present=False)]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("argv", [["send", "--host", "smtp.example.com"], ["no-such-command"], ["validate-email", "not-an-address"]])
def test_module_entry_exits_with_the_code_the_console_script_gives(monkeypatch: pytest.MonkeyPatch, isolated_traceback_config: None, argv: list[str]) -> None:
    script_code = cli_mod.main(argv)
    monkeypatch.setattr(sys, "argv", ["btx_lib_mail", *argv])

    with pytest.raises(SystemExit) as exc:
        runpy.run_module("btx_lib_mail.__main__", run_name="__main__")

    assert exc.value.code == script_code


@pytest.mark.os_agnostic
def test_module_entry_reports_a_json_failure_as_json(
    monkeypatch: pytest.MonkeyPatch, isolated_traceback_config: None, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["btx_lib_mail", "--json", "validate-email", "not-an-address"])

    with pytest.raises(SystemExit):
        runpy.run_module("btx_lib_mail.__main__", run_name="__main__")

    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False
    assert envelope["error"]["type"] == "InvalidInputError"


@pytest.mark.os_agnostic
def test_when_traceback_flag_is_used_via_module_entry_the_full_poem_is_printed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    strip_ansi: Callable[[str], str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["btx_lib_mail", "--traceback", "fail"])
    monkeypatch.setattr(lib_cli_exit_tools.config, "traceback", False, raising=False)
    monkeypatch.setattr(lib_cli_exit_tools.config, "traceback_force_color", False, raising=False)

    with pytest.raises(SystemExit) as exc:
        runpy.run_module("btx_lib_mail.__main__", run_name="__main__")

    plain_err = strip_ansi(capsys.readouterr().err)

    assert exc.value.code != 0
    assert "Traceback (most recent call last)" in plain_err
    assert "RuntimeError: I should fail" in plain_err
    assert "[TRUNCATED" not in plain_err
    assert lib_cli_exit_tools.config.traceback is False
    assert lib_cli_exit_tools.config.traceback_force_color is False


@pytest.mark.os_agnostic
def test_when_the_module_is_imported_it_runs_nothing() -> None:
    # Left imported, every later runpy of btx_lib_mail.__main__ warns that it is already loaded.
    previous = sys.modules.pop("btx_lib_mail.__main__", None)
    try:
        module = importlib.import_module("btx_lib_mail.__main__")

        assert module.cli is cli_mod
    finally:
        sys.modules.pop("btx_lib_mail.__main__", None)
        if previous is not None:
            sys.modules["btx_lib_mail.__main__"] = previous
