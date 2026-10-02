"""CLI stories: every invocation a single beat."""

from __future__ import annotations

# Tests reach the dispatch and traceback internals (and the seams main() calls through) on purpose.
# pyright: reportPrivateUsage=false
from typing import TYPE_CHECKING, Any

import lib_cli_exit_tools
import pytest

from btx_lib_mail import __init__conf__
from btx_lib_mail import cli as cli_mod
from btx_lib_mail.cli import _dispatch, _settings_sources

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner, Result


def _call_cli_private(name: str, *args: Any, **kwargs: Any) -> Any:
    """Call a private helper by name from the submodule that defines it."""
    owner = _settings_sources if hasattr(_settings_sources, name) else _dispatch
    helper = getattr(owner, name)
    return helper(*args, **kwargs)


@pytest.mark.os_agnostic
def test_when_split_values_meet_blanks_only_words_survive() -> None:
    result = _call_cli_private("_split_values", ["alpha, , beta", "  ", "gamma"])

    assert result == ["alpha", "beta", "gamma"]


@pytest.mark.os_agnostic
def test_when_the_traceback_mode_is_read_the_truth_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lib_cli_exit_tools.config, "traceback", True, raising=False)

    assert _call_cli_private("_current_traceback_mode") is True


@pytest.mark.os_agnostic
def test_when_tracebacks_are_enabled_the_verbose_limit_wins() -> None:
    assert _call_cli_private("_traceback_limit", tracebacks_enabled=True, summary_limit=10, verbose_limit=999) == 999


@pytest.mark.os_agnostic
def test_when_tracebacks_are_disabled_the_summary_limit_wins() -> None:
    assert _call_cli_private("_traceback_limit", tracebacks_enabled=False, summary_limit=10, verbose_limit=999) == 10


@pytest.mark.os_agnostic
def test_when_print_exception_runs_the_exit_tools_are_consulted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notes: dict[str, Any] = {}

    def remember_print(**kwargs: Any) -> None:
        notes["print"] = kwargs

    def remember_code(exc: BaseException) -> int:
        notes["exc"] = exc
        return 55

    monkeypatch.setattr(lib_cli_exit_tools, "print_exception_message", remember_print)
    monkeypatch.setattr(lib_cli_exit_tools, "get_system_exit_code", remember_code)

    result = _call_cli_private("_print_exception", ValueError("boom"), tracebacks_enabled=True, length_limit=123)

    assert result == 55
    assert notes["print"] == {"trace_back": True, "length_limit": 123}
    assert isinstance(notes["exc"], ValueError)


@pytest.mark.os_agnostic
def test_when_fail_runs_without_traceback_only_the_summary_is_printed(
    isolated_traceback_config: None,
    capsys: pytest.CaptureFixture[str],
    strip_ansi: Callable[[str], str],
) -> None:
    exit_code = cli_mod.main(["fail"])

    plain_err = strip_ansi(capsys.readouterr().err)

    assert exit_code == 1
    assert "RuntimeError: I should fail" in plain_err
    assert "Traceback (most recent call last)" not in plain_err


@pytest.mark.os_agnostic
def test_when_we_snapshot_traceback_the_initial_state_is_quiet(isolated_traceback_config: None) -> None:
    assert cli_mod.snapshot_traceback_state() == (False, False)


@pytest.mark.os_agnostic
def test_when_we_enable_traceback_the_config_sings_true(isolated_traceback_config: None) -> None:
    cli_mod.apply_traceback_preferences(True)

    assert lib_cli_exit_tools.config.traceback is True
    assert lib_cli_exit_tools.config.traceback_force_color is True


@pytest.mark.os_agnostic
def test_when_we_restore_traceback_the_config_whispers_false(isolated_traceback_config: None) -> None:
    previous = cli_mod.snapshot_traceback_state()
    cli_mod.apply_traceback_preferences(True)

    cli_mod.restore_traceback_state(previous)

    assert lib_cli_exit_tools.config.traceback is False
    assert lib_cli_exit_tools.config.traceback_force_color is False


@pytest.mark.os_agnostic
def test_when_info_runs_with_traceback_the_metadata_prints_and_the_choice_is_restored(
    isolated_traceback_config: None,
    preserve_traceback_state: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli_mod.main(["--traceback", "info"])

    assert exit_code == 0
    assert __init__conf__.name in capsys.readouterr().out
    assert lib_cli_exit_tools.config.traceback is False
    assert lib_cli_exit_tools.config.traceback_force_color is False


@pytest.mark.os_agnostic
def test_when_cli_runs_without_arguments_help_is_printed(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(cli_mod.cli, [])

    assert result.exit_code == 0
    assert "Usage:" in result.output


@pytest.mark.os_agnostic
def test_when_main_receives_no_arguments_help_is_printed(
    isolated_traceback_config: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli_mod.main([])

    assert exit_code == 0
    assert "Usage:" in capsys.readouterr().out


@pytest.mark.os_agnostic
def test_when_traceback_is_requested_without_command_the_placeholder_runs_instead_of_help(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(cli_mod.cli, ["--traceback"])

    assert result.exit_code == 0
    assert "Usage:" not in result.output


@pytest.mark.os_agnostic
def test_when_traceback_flag_is_passed_the_full_story_is_printed(
    isolated_traceback_config: None,
    capsys: pytest.CaptureFixture[str],
    strip_ansi: Callable[[str], str],
) -> None:
    exit_code = cli_mod.main(["--traceback", "fail"])

    plain_err = strip_ansi(capsys.readouterr().err)

    assert exit_code != 0
    assert "Traceback (most recent call last)" in plain_err
    assert "RuntimeError: I should fail" in plain_err
    assert "[TRUNCATED" not in plain_err
    assert lib_cli_exit_tools.config.traceback is False
    assert lib_cli_exit_tools.config.traceback_force_color is False


@pytest.mark.os_agnostic
def test_when_hello_is_invoked_the_cli_smiles(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["hello"])

    assert result.exit_code == 0
    assert result.output == "Hello World\n"


@pytest.mark.os_agnostic
def test_when_fail_is_invoked_the_cli_raises(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["fail"])

    assert result.exit_code != 0
    assert isinstance(result.exception, RuntimeError)


@pytest.mark.os_agnostic
def test_when_info_is_invoked_the_metadata_is_displayed(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["info"])

    assert result.exit_code == 0
    assert f"Info for {__init__conf__.name}:" in result.output
    assert __init__conf__.version in result.output


@pytest.mark.os_agnostic
def test_when_an_unknown_command_is_used_a_helpful_error_appears(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["does-not-exist"])

    assert result.exit_code != 0
    assert "No such command" in result.output


# ---------------------------------------------------------------------------
# validate-email CLI command
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_validate_email_accepts_valid_address(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["validate-email", "user@example.com"])

    assert result.exit_code == 0
    assert "Valid email address" in result.output


@pytest.mark.os_agnostic
def test_validate_email_rejects_invalid_address(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["validate-email", "invalid@"])

    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# validate-smtp-host CLI command
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_validate_smtp_host_accepts_valid_host_port(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["validate-smtp-host", "smtp.example.com:587"])

    assert result.exit_code == 0
    assert "Valid SMTP host" in result.output


@pytest.mark.os_agnostic
def test_validate_smtp_host_accepts_ipv6(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["validate-smtp-host", "[::1]:25"])

    assert result.exit_code == 0
    assert "Valid SMTP host" in result.output


@pytest.mark.os_agnostic
def test_validate_smtp_host_rejects_invalid(cli_runner: CliRunner) -> None:
    result: Result = cli_runner.invoke(cli_mod.cli, ["validate-smtp-host", "[::1"])

    assert result.exit_code != 0


@pytest.mark.os_agnostic
def test_when_restore_is_disabled_the_traceback_choice_remains(
    isolated_traceback_config: None,
    preserve_traceback_state: None,
) -> None:
    cli_mod.apply_traceback_preferences(False)

    cli_mod.main(["--traceback", "hello"], restore_traceback=False)

    assert lib_cli_exit_tools.config.traceback is True
    assert lib_cli_exit_tools.config.traceback_force_color is True
