"""CLI stories: every invocation a single beat."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import click
from click.testing import CliRunner, Result

import lib_cli_exit_tools

from btx_lib_mail import cli as cli_mod
from btx_lib_mail import __init__conf__


def _call_cli_private(name: str, *args: Any, **kwargs: Any) -> Any:
    helper = getattr(cli_mod, name)
    return helper(*args, **kwargs)


@dataclass(slots=True)
class CapturedRun:
    """Record of a single ``lib_cli_exit_tools.run_cli`` invocation.

    Attributes
    ----------
    command:
        Command object passed to ``run_cli``.
    argv:
        Argument vector forwarded to the command, when any.
    prog_name:
        Program name announced in the help output.
    signal_specs:
        Signal handlers registered by the runner.
    install_signals:
        ``True`` when the runner installed default signal handlers.
    """

    command: Any
    argv: Sequence[str] | None
    prog_name: str | None
    signal_specs: Any
    install_signals: bool


def _capture_run_cli(target: list[CapturedRun]) -> Callable[..., int]:
    """Return a stub that records ``lib_cli_exit_tools.run_cli`` invocations.

    Why
        Tests assert that the CLI delegates to ``lib_cli_exit_tools`` with the
        expected arguments; recording each call keeps those assertions readable.

    Inputs
        target:
            Mutable list that will collect :class:`CapturedRun` entries.

    Outputs
        Callable[..., int]:
            Replacement for ``lib_cli_exit_tools.run_cli``.
    """

    def _run(
        command: Any,
        argv: Sequence[str] | None = None,
        *,
        prog_name: str | None = None,
        signal_specs: Any = None,
        install_signals: bool = True,
    ) -> int:
        target.append(
            CapturedRun(
                command=command,
                argv=argv,
                prog_name=prog_name,
                signal_specs=signal_specs,
                install_signals=install_signals,
            )
        )
        return 42

    return _run


@pytest.mark.os_agnostic
def test_when_the_dotenv_is_missing_the_lookup_has_no_answer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ghost_dotenv = tmp_path / "ghost.env"
    monkeypatch.setattr(cli_mod, "_DOTENV_PATH", ghost_dotenv)

    answer = _call_cli_private("_dotenv_value", "BTX_MAIL_GHOST")

    assert answer is None


@pytest.mark.os_agnostic
def test_when_the_dotenv_meets_malformed_lines_it_moves_on(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text("# comment\nMALFORMED\nOTHER=value\n  \n", encoding="utf-8")
    monkeypatch.setattr(cli_mod, "_DOTENV_PATH", dotenv_path)

    answer = _call_cli_private("_dotenv_value", "BTX_MAIL_MISSING")

    assert answer is None


@pytest.mark.os_agnostic
def test_when_split_values_meet_blanks_only_words_survive() -> None:
    result = _call_cli_private("_split_values", ["alpha, , beta", "  ", "gamma"])

    assert result == ["alpha", "beta", "gamma"]


@pytest.mark.os_agnostic
def test_when_no_host_input_is_given_the_cli_requests_help(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("BTX_MAIL_SMTP_HOSTS", raising=False)
    monkeypatch.setattr(cli_mod, "_DOTENV_PATH", tmp_path / "void.env")

    with pytest.raises(click.UsageError, match="Provide at least one SMTP host"):
        _call_cli_private("_resolve_list", (), "BTX_MAIL_SMTP_HOSTS", label="SMTP host")


@pytest.mark.os_agnostic
def test_when_boolean_env_is_absent_the_default_choice_wins(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("BTX_MAIL_SMTP_USE_STARTTLS", raising=False)
    monkeypatch.setattr(cli_mod, "_DOTENV_PATH", tmp_path / "void.env")

    assert _call_cli_private("_resolve_bool", None, "BTX_MAIL_SMTP_USE_STARTTLS", default=True) is True


@pytest.mark.os_agnostic
def test_when_boolean_env_says_yes_the_flag_follows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_USE_STARTTLS", "YES")

    assert _call_cli_private("_resolve_bool", None, "BTX_MAIL_SMTP_USE_STARTTLS", default=False) is True


@pytest.mark.os_agnostic
def test_when_boolean_env_is_nonsense_a_bad_parameter_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_USE_STARTTLS", "maybe")

    with pytest.raises(click.BadParameter, match="Unrecognised boolean value"):
        _call_cli_private("_resolve_bool", None, "BTX_MAIL_SMTP_USE_STARTTLS", default=False)


@pytest.mark.os_agnostic
def test_when_float_env_is_absent_the_default_fills_in(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("BTX_MAIL_SMTP_TIMEOUT", raising=False)
    monkeypatch.setattr(cli_mod, "_DOTENV_PATH", tmp_path / "void.env")

    assert _call_cli_private("_resolve_float", None, "BTX_MAIL_SMTP_TIMEOUT", default=7.0) == 7.0


@pytest.mark.os_agnostic
def test_when_float_env_is_gibberish_a_bad_parameter_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_TIMEOUT", "not-a-float")

    with pytest.raises(click.BadParameter, match="Unrecognised float value"):
        _call_cli_private("_resolve_float", None, "BTX_MAIL_SMTP_TIMEOUT", default=3.0)


@pytest.mark.os_agnostic
def test_when_the_traceback_mode_is_read_the_truth_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lib_cli_exit_tools.config, "traceback", True, raising=False)

    assert _call_cli_private("_current_traceback_mode") is True


@pytest.mark.os_agnostic
def test_when_tracebacks_are_enabled_the_verbose_limit_wins() -> None:
    assert _call_cli_private("_traceback_limit", True, summary_limit=10, verbose_limit=999) == 999


@pytest.mark.os_agnostic
def test_when_tracebacks_are_disabled_the_summary_limit_wins() -> None:
    assert _call_cli_private("_traceback_limit", False, summary_limit=10, verbose_limit=999) == 10


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
def test_when_cli_invocation_explodes_the_exception_story_is_told(
    monkeypatch: pytest.MonkeyPatch,
    isolated_traceback_config: None,
) -> None:
    monkeypatch.setattr(lib_cli_exit_tools.config, "traceback", True, raising=False)
    captured: dict[str, Any] = {}

    def explode(_argv: Sequence[str] | None) -> int:
        raise RuntimeError("boom")

    def record_print(
        exc: BaseException,
        *,
        tracebacks_enabled: bool,
        length_limit: int,
    ) -> int:
        captured["exc"] = exc
        captured["tracebacks_enabled"] = tracebacks_enabled
        captured["length_limit"] = length_limit
        return 99

    monkeypatch.setattr(cli_mod, "_invoke_cli", explode)
    monkeypatch.setattr(cli_mod, "_print_exception", record_print)

    result = _call_cli_private(
        "_run_cli_via_exit_tools",
        None,
        summary_limit=50,
        verbose_limit=500,
    )

    assert result == 99
    assert isinstance(captured["exc"], RuntimeError)
    assert captured["tracebacks_enabled"] is True
    assert captured["length_limit"] == 500


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
def test_when_info_runs_with_traceback_the_choice_is_shared(
    monkeypatch: pytest.MonkeyPatch,
    isolated_traceback_config: None,
    preserve_traceback_state: None,
) -> None:
    notes: list[tuple[bool, bool]] = []

    def record() -> None:
        notes.append(
            (
                lib_cli_exit_tools.config.traceback,
                lib_cli_exit_tools.config.traceback_force_color,
            )
        )

    monkeypatch.setattr(cli_mod.__init__conf__, "print_info", record)

    exit_code = cli_mod.main(["--traceback", "info"])

    assert exit_code == 0
    assert notes == [(True, True)]
    assert lib_cli_exit_tools.config.traceback is False
    assert lib_cli_exit_tools.config.traceback_force_color is False


@pytest.mark.os_agnostic
def test_when_main_is_called_it_delegates_to_run_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger: list[CapturedRun] = []
    monkeypatch.setattr(lib_cli_exit_tools, "run_cli", _capture_run_cli(ledger))

    result = cli_mod.main(["info"])

    assert result == 42
    assert ledger == [
        CapturedRun(
            command=cli_mod.cli,
            argv=["info"],
            prog_name=__init__conf__.shell_command,
            signal_specs=None,
            install_signals=True,
        )
    ]


@pytest.mark.os_agnostic
def test_when_cli_runs_without_arguments_help_is_printed(
    monkeypatch: pytest.MonkeyPatch,
    cli_runner: CliRunner,
) -> None:
    calls: list[str] = []

    def remember() -> None:
        calls.append("called")

    monkeypatch.setattr(cli_mod, "noop_main", remember)

    result = cli_runner.invoke(cli_mod.cli, [])

    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert calls == []


@pytest.mark.os_agnostic
def test_when_main_receives_no_arguments_cli_main_is_exercised(
    monkeypatch: pytest.MonkeyPatch,
    cli_runner: CliRunner,
    isolated_traceback_config: None,
) -> None:
    calls: list[str] = []
    outputs: list[str] = []

    def remember() -> None:
        calls.append("called")

    monkeypatch.setattr(cli_mod, "noop_main", remember)

    def fake_run_cli(
        command: Any,
        argv: Sequence[str] | None = None,
        *,
        prog_name: str | None = None,
        signal_specs: Any = None,
        install_signals: bool = True,
    ) -> int:
        args = [] if argv is None else list(argv)
        result: Result = cli_runner.invoke(command, args)
        if result.exception is not None:
            raise result.exception
        outputs.append(result.output)
        return result.exit_code

    monkeypatch.setattr(lib_cli_exit_tools, "run_cli", fake_run_cli)

    exit_code = cli_mod.main([])

    assert exit_code == 0
    assert calls == []
    assert outputs and "Usage:" in outputs[0]


@pytest.mark.os_agnostic
def test_when_traceback_is_requested_without_command_the_domain_runs(
    monkeypatch: pytest.MonkeyPatch,
    cli_runner: CliRunner,
) -> None:
    calls: list[str] = []

    def remember() -> None:
        calls.append("called")

    monkeypatch.setattr(cli_mod, "noop_main", remember)

    result = cli_runner.invoke(cli_mod.cli, ["--traceback"])

    assert result.exit_code == 0
    assert calls == ["called"]
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
def test_send_mail_command_uses_env_defaults(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_HOSTS", "smtp.example.com:2525")
    monkeypatch.setenv("BTX_MAIL_RECIPIENTS", "first@example.com,second@example.com")
    monkeypatch.setenv("BTX_MAIL_SMTP_USE_STARTTLS", "false")
    monkeypatch.setenv("BTX_MAIL_SMTP_TIMEOUT", "12.5")

    calls: dict[str, Any] = {}

    def fake_send(**kwargs: Any) -> bool:
        calls.update(kwargs)
        return True

    monkeypatch.setattr(cli_mod, "send", fake_send)

    result = cli_runner.invoke(
        cli_mod.cli,
        [
            "send",
            "--subject",
            "Env Subject",
            "--body",
            "Env Body",
        ],
    )

    assert result.exit_code == 0
    assert calls["mail_from"] == "first@example.com"
    assert calls["mail_recipients"] == ["first@example.com", "second@example.com"]
    assert calls["smtphosts"] == ["smtp.example.com:2525"]
    assert calls["mail_body_html"] == ""
    assert calls["credentials"] is None
    assert calls["use_starttls"] is False
    assert calls["timeout"] == 12.5


@pytest.mark.os_agnostic
def test_send_mail_command_honours_cli_overrides(
    monkeypatch: pytest.MonkeyPatch,
    cli_runner: CliRunner,
    tmp_path: Path,
) -> None:
    attachment = tmp_path / "note.txt"
    attachment.write_text("payload", encoding="utf-8")

    calls: dict[str, Any] = {}

    def fake_send(**kwargs: Any) -> bool:
        calls.update(kwargs)
        return True

    monkeypatch.setattr(cli_mod, "send", fake_send)

    result = cli_runner.invoke(
        cli_mod.cli,
        [
            "send",
            "--host",
            "cli.smtp.example:587",
            "--recipient",
            "cli@example.com",
            "--sender",
            "sender@example.com",
            "--subject",
            "CLI Subject",
            "--body",
            "CLI Body",
            "--html-body",
            "<p>CLI</p>",
            "--attachment",
            str(attachment),
            "--starttls",
            "--username",
            "user",
            "--password",
            "pass",
            "--timeout",
            "42",
        ],
    )

    assert result.exit_code == 0
    assert calls["mail_from"] == "sender@example.com"
    assert calls["mail_recipients"] == ["cli@example.com"]
    assert calls["smtphosts"] == ["cli.smtp.example:587"]
    assert calls["mail_body_html"] == "<p>CLI</p>"
    assert calls["attachment_file_paths"] == [attachment]
    assert calls["credentials"] == ("user", "pass")
    assert calls["use_starttls"] is True
    assert calls["timeout"] == 42.0


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


# ---------------------------------------------------------------------------
# CLI Attachment Security Options
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_send_command_passes_security_options_via_cli(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    attachment = tmp_path / "document.pdf"
    attachment.write_bytes(b"%PDF-1.4 content")

    calls: dict[str, Any] = {}

    def fake_send(**kwargs: Any) -> bool:
        calls.update(kwargs)
        return True

    monkeypatch.setattr(cli_mod, "send", fake_send)

    result = cli_runner.invoke(
        cli_mod.cli,
        [
            "send",
            "--host",
            "smtp.example.com",
            "--recipient",
            "test@example.com",
            "--subject",
            "Test",
            "--body",
            "Test body",
            "--attachment",
            str(attachment),
            "--attachment-allowed-ext",
            ".pdf,.txt",
            "--attachment-max-size",
            "50000000",
            "--attachment-allow-symlinks",
            "--attachment-warn",
        ],
    )

    assert result.exit_code == 0
    assert calls["attachment_allowed_extensions"] == frozenset({".pdf", ".txt"})
    assert calls["attachment_max_size_bytes"] == 50_000_000
    assert calls["attachment_allow_symlinks"] is True
    assert calls["attachment_raise_on_security_violation"] is False


@pytest.mark.os_agnostic
def test_send_command_passes_security_options_via_env(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_HOSTS", "smtp.example.com")
    monkeypatch.setenv("BTX_MAIL_RECIPIENTS", "test@example.com")
    monkeypatch.setenv("BTX_MAIL_ATTACHMENT_ALLOWED_EXT", ".docx,.xlsx")
    monkeypatch.setenv("BTX_MAIL_ATTACHMENT_MAX_SIZE", "10000000")
    monkeypatch.setenv("BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS", "true")

    calls: dict[str, Any] = {}

    def fake_send(**kwargs: Any) -> bool:
        calls.update(kwargs)
        return True

    monkeypatch.setattr(cli_mod, "send", fake_send)

    result = cli_runner.invoke(
        cli_mod.cli,
        [
            "send",
            "--subject",
            "Test",
            "--body",
            "Test body",
        ],
    )

    assert result.exit_code == 0
    assert calls["attachment_allowed_extensions"] == frozenset({".docx", ".xlsx"})
    assert calls["attachment_max_size_bytes"] == 10_000_000
    assert calls["attachment_allow_symlinks"] is True


@pytest.mark.os_agnostic
def test_resolve_extensions_normalises_input() -> None:
    """Test that extension resolution normalises to lowercase with dots."""
    result = _call_cli_private("_resolve_extensions", "PDF,TXT,.docx", "NONEXISTENT_ENV")
    assert result == frozenset({".pdf", ".txt", ".docx"})


@pytest.mark.os_agnostic
def test_resolve_extensions_returns_none_when_empty() -> None:
    """Test that empty extension input returns None."""
    result = _call_cli_private("_resolve_extensions", None, "NONEXISTENT_ENV")
    assert result is None


@pytest.mark.os_agnostic
def test_resolve_directories_handles_multiple_values() -> None:
    """Test that directory resolution handles multiple values."""
    result = _call_cli_private("_resolve_directories", ["/tmp", "/var"], "NONEXISTENT_ENV")
    assert result == frozenset({Path("/tmp"), Path("/var")})


@pytest.mark.os_agnostic
def test_resolve_optional_bool_parses_true_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that optional bool correctly parses true values."""
    monkeypatch.setenv("TEST_BOOL", "yes")
    result = _call_cli_private("_resolve_optional_bool", None, "TEST_BOOL")
    assert result is True


@pytest.mark.os_agnostic
def test_resolve_optional_bool_returns_none_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that optional bool returns None when env var is empty."""
    result = _call_cli_private("_resolve_optional_bool", None, "NONEXISTENT_ENV")
    assert result is None


@pytest.mark.os_agnostic
def test_resolve_int_parses_env_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that int resolution parses environment values."""
    monkeypatch.setenv("TEST_INT", "12345")
    result = _call_cli_private("_resolve_int", None, "TEST_INT")
    assert result == 12345


@pytest.mark.os_agnostic
def test_resolve_int_returns_none_when_empty() -> None:
    """Test that int resolution returns None when not set."""
    result = _call_cli_private("_resolve_int", None, "NONEXISTENT_ENV")
    assert result is None


@pytest.mark.os_agnostic
def test_resolve_int_raises_on_invalid_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that int resolution raises on invalid values."""
    monkeypatch.setenv("TEST_INT", "not_a_number")
    with pytest.raises(click.BadParameter, match="Unrecognised int value"):
        _call_cli_private("_resolve_int", None, "TEST_INT")
