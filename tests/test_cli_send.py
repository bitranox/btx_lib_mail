"""The ``send`` command: where its settings come from, what it delivers, and how it reports.

Tests drive the real ``send()``: through the transport seam the CLI context carries
(``CliRunner.invoke(..., obj=CliContext(transport=...))``), or against a real
in-process SMTP server. Nothing inside the package is patched.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from email import message_from_bytes
from typing import IO, TYPE_CHECKING, Any

import click
import lib_cli_exit_tools
import pytest

from btx_lib_mail import cli as cli_mod
from btx_lib_mail.cli import CliContext
from btx_lib_mail.errors import InvalidInputError

if TYPE_CHECKING:
    from pathlib import Path

    from click.testing import CliRunner, Result
    from smtp_test_server import CollectingHandler

# pyright: reportPrivateUsage=false


@dataclass(frozen=True)
class _Delivery:
    host: str
    sender: str
    recipient: str
    raw: bytes
    options: Any


class _RecordingTransport:
    """Accepts every message and records what the CLI made the library deliver."""

    def __init__(self) -> None:
        self.deliveries: list[_Delivery] = []

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: Any) -> None:
        message.seek(0)
        self.deliveries.append(_Delivery(host=host, sender=sender, recipient=recipient, raw=message.read(), options=delivery))

    @property
    def only(self) -> _Delivery:
        assert len(self.deliveries) == 1, f"expected one delivery, got {len(self.deliveries)}"
        return self.deliveries[0]


@pytest.fixture(autouse=True)
def _no_ambient_mail_settings(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    """A developer's own BTX_MAIL_* settings must not reach these tests."""
    for key in list(os.environ):
        if key.startswith("BTX_MAIL_"):
            monkeypatch.delenv(key)


_MESSAGE = ["--subject", "S", "--body", "B"]
_ROUTE = ["--host", "smtp.example.com", "--recipient", "one@example.com"]


def _invoke(cli_runner: CliRunner, args: list[str], *, input_text: str | None = None) -> tuple[Result, _RecordingTransport]:
    transport = _RecordingTransport()
    result = cli_runner.invoke(cli_mod.cli, args, obj=CliContext(transport=transport), input=input_text)
    return result, transport


def _attachment_names(raw: bytes) -> list[str]:
    return [name for part in message_from_bytes(raw).walk() if (name := part.get_filename())]


def _no_blocked_dirs(tmp_path: Path) -> list[str]:
    # The POSIX default blocks /var, which holds the temp dir on macOS.
    return ["--attachment-blocked-dir", str(tmp_path / "nothing-blocked-here")]


# ---------------------------------------------------------------------------
# Options and the environment
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_settings_come_from_the_environment_when_no_option_is_given(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_HOSTS", "smtp.example.com:2525")
    monkeypatch.setenv("BTX_MAIL_RECIPIENTS", "first@example.com,second@example.com")
    monkeypatch.setenv("BTX_MAIL_SMTP_USE_STARTTLS", "false")
    monkeypatch.setenv("BTX_MAIL_SMTP_TIMEOUT", "12.5")

    result, transport = _invoke(cli_runner, ["send", *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert [(d.host, d.sender, d.recipient) for d in transport.deliveries] == [
        ("smtp.example.com:2525", "first@example.com", "first@example.com"),
        ("smtp.example.com:2525", "first@example.com", "second@example.com"),
    ]
    options = transport.deliveries[0].options
    assert options.use_starttls is False
    assert options.timeout == 12.5
    assert options.credentials is None


@pytest.mark.os_agnostic
def test_options_override_the_environment(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_HOSTS", "env.example.com")
    monkeypatch.setenv("BTX_MAIL_SMTP_TIMEOUT", "5")
    attachment = tmp_path / "note.txt"
    attachment.write_text("payload", encoding="utf-8")

    args = [
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
        "--delivery-deadline",
        "90",
        *_no_blocked_dirs(tmp_path),
    ]
    result, transport = _invoke(cli_runner, args)

    assert result.exit_code == 0, result.output
    delivery = transport.only
    assert (delivery.host, delivery.sender, delivery.recipient) == ("cli.smtp.example:587", "sender@example.com", "cli@example.com")
    assert delivery.options.credentials == ("user", "pass")
    assert delivery.options.use_starttls is True
    assert delivery.options.starttls_verify is True
    assert delivery.options.timeout == 42.0
    assert delivery.options.deadline == 90.0
    message = message_from_bytes(delivery.raw)
    assert message["Subject"] == "CLI Subject"
    assert {part.get_content_type() for part in message.walk()} >= {"text/plain", "text/html"}
    assert _attachment_names(delivery.raw) == ["note.txt"]


@pytest.mark.os_agnostic
def test_certificate_verification_can_be_switched_off(cli_runner: CliRunner) -> None:
    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, "--no-starttls-verify"])

    assert result.exit_code == 0, result.output
    assert transport.only.options.starttls_verify is False


@pytest.mark.os_agnostic
@pytest.mark.parametrize("env_key", ["BTX_MAIL_SMTP_USE_STARTTLS", "BTX_MAIL_SMTP_STARTTLS_VERIFY"])
def test_a_blank_environment_value_keeps_the_secure_default(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, env_key: str) -> None:
    monkeypatch.setenv(env_key, "   ")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.options.use_starttls is True
    assert transport.only.options.starttls_verify is True


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("env_key", "field"), [("BTX_MAIL_SMTP_USE_STARTTLS", "use_starttls"), ("BTX_MAIL_SMTP_STARTTLS_VERIFY", "starttls_verify")])
def test_an_explicit_false_environment_value_still_turns_the_setting_off(
    monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, env_key: str, field: str
) -> None:
    monkeypatch.setenv(env_key, "no")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert getattr(transport.only.options, field) is False


@pytest.mark.os_agnostic
def test_an_unparseable_boolean_is_a_bad_parameter(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_USE_STARTTLS", "maybe")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    assert result.exit_code == 2
    assert "Unrecognised boolean value for BTX_MAIL_SMTP_USE_STARTTLS" in result.output
    assert transport.deliveries == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("env_key", "kind"), [("BTX_MAIL_SMTP_TIMEOUT", "float"), ("BTX_MAIL_ATTACHMENT_MAX_SIZE", "int")])
def test_an_unparseable_number_is_a_bad_parameter(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, env_key: str, kind: str) -> None:
    monkeypatch.setenv(env_key, "not-a-number")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    assert result.exit_code == 2
    assert f"Unrecognised {kind} value for {env_key}" in result.output
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_without_a_host_the_command_asks_for_one(cli_runner: CliRunner) -> None:
    result, transport = _invoke(cli_runner, ["send", "--recipient", "one@example.com", *_MESSAGE])

    assert result.exit_code == 2
    assert "Provide at least one SMTP host" in result.output
    assert transport.deliveries == []


# ---------------------------------------------------------------------------
# The env file: ./.env by default, or the one named
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_dotenv_in_the_working_directory_supplies_unset_settings(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("BTX_MAIL_SMTP_HOSTS=relay.example.com\nBTX_MAIL_SMTP_USE_STARTTLS=false\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result, transport = _invoke(cli_runner, ["send", "--recipient", "one@example.com", *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.host == "relay.example.com"
    assert transport.only.options.use_starttls is False


@pytest.mark.os_agnostic
def test_a_named_env_file_replaces_the_dotenv_in_the_working_directory(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("BTX_MAIL_SMTP_HOSTS=dotenv.example.com\nBTX_MAIL_SENDER=dotenv@example.com\n", encoding="utf-8")
    named = tmp_path / "mail.env"
    named.write_text("BTX_MAIL_SMTP_HOSTS=named.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result, transport = _invoke(cli_runner, ["send", "--env-file", str(named), "--recipient", "one@example.com", *_MESSAGE])

    assert result.exit_code == 0, result.output
    # Only the named file is read: a key it lacks does not fall through to ./.env.
    assert (transport.only.host, transport.only.sender) == ("named.example.com", "one@example.com")


@pytest.mark.os_agnostic
def test_the_environment_wins_over_the_dotenv_in_the_working_directory(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("BTX_MAIL_SMTP_HOSTS=dotenv.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BTX_MAIL_SMTP_HOSTS", "env.example.com")

    result, transport = _invoke(cli_runner, ["send", "--recipient", "one@example.com", *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.host == "env.example.com"


@pytest.mark.os_agnostic
def test_a_dotenv_that_is_not_a_file_is_ignored(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    (tmp_path / ".env").mkdir()
    monkeypatch.chdir(tmp_path)

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.host == "smtp.example.com"


@pytest.mark.os_agnostic
def test_an_oversized_dotenv_in_the_working_directory_is_refused(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    (tmp_path / ".env").write_bytes(b"#" * (cli_mod._ENV_FILE_MAX_BYTES + 1))
    monkeypatch.chdir(tmp_path)

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    assert result.exit_code == 2
    # Rich wraps the message in a box; compare it as one line.
    flat = " ".join(result.output.replace("│", " ").split())
    assert f"./.env in the working directory is {cli_mod._ENV_FILE_MAX_BYTES + 1} bytes; an env file may be at most" in flat
    assert "--env-file" not in flat
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_a_named_env_file_supplies_unset_settings(cli_runner: CliRunner, tmp_path: Path) -> None:
    env_file = tmp_path / "mail.env"
    env_file.write_text(
        '# relay settings\nBTX_MAIL_SMTP_HOSTS="relay.example.com:2525"\nMALFORMED LINE\n\n'
        "BTX_MAIL_RECIPIENTS=one@example.com\nBTX_MAIL_SMTP_HOSTS=second.example.com\n",
        encoding="utf-8",
    )

    result, transport = _invoke(cli_runner, ["send", "--env-file", str(env_file), *_MESSAGE])

    assert result.exit_code == 0, result.output
    # Quotes stripped, malformed lines skipped, the first occurrence of a key wins.
    assert (transport.only.host, transport.only.recipient) == ("relay.example.com:2525", "one@example.com")


@pytest.mark.os_agnostic
def test_the_env_file_can_be_named_by_btx_mail_env_file(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    env_file = tmp_path / "mail.env"
    env_file.write_text("BTX_MAIL_SMTP_HOSTS=relay.example.com\nBTX_MAIL_RECIPIENTS=one@example.com\n", encoding="utf-8")
    monkeypatch.setenv("BTX_MAIL_ENV_FILE", str(env_file))

    result, transport = _invoke(cli_runner, ["send", *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.host == "relay.example.com"


@pytest.mark.os_agnostic
def test_the_environment_wins_over_the_env_file(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    env_file = tmp_path / "mail.env"
    env_file.write_text("BTX_MAIL_SMTP_HOSTS=file.example.com\nBTX_MAIL_RECIPIENTS=one@example.com\n", encoding="utf-8")
    monkeypatch.setenv("BTX_MAIL_SMTP_HOSTS", "env.example.com")

    result, transport = _invoke(cli_runner, ["send", "--env-file", str(env_file), *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.host == "env.example.com"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("env_key", ["BTX_MAIL_SMTP_USE_STARTTLS", "BTX_MAIL_SMTP_STARTTLS_VERIFY"])
def test_a_quoted_blank_env_file_value_keeps_the_secure_default(cli_runner: CliRunner, tmp_path: Path, env_key: str) -> None:
    env_file = tmp_path / "mail.env"
    env_file.write_text(f'{env_key}="  "\n', encoding="utf-8")

    result, transport = _invoke(cli_runner, ["send", "--env-file", str(env_file), *_ROUTE, *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.options.use_starttls is True
    assert transport.only.options.starttls_verify is True


@pytest.mark.os_agnostic
def test_an_oversized_env_file_is_refused_before_it_is_read(cli_runner: CliRunner, tmp_path: Path) -> None:
    env_file = tmp_path / "huge.env"
    env_file.write_bytes(b"#" * (cli_mod._ENV_FILE_MAX_BYTES + 1))

    result, transport = _invoke(cli_runner, ["send", "--env-file", str(env_file), *_ROUTE, *_MESSAGE])

    assert result.exit_code == 2
    assert "an env file may be at most" in result.output
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_an_env_file_that_is_not_utf8_is_refused(cli_runner: CliRunner, tmp_path: Path) -> None:
    env_file = tmp_path / "latin1.env"
    env_file.write_bytes("BTX_MAIL_SENDER=f\xfc@example.com\n".encode("latin-1"))

    result, transport = _invoke(cli_runner, ["send", "--env-file", str(env_file), *_ROUTE, *_MESSAGE])

    assert result.exit_code == 2
    assert "is not UTF-8 text" in result.output
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_a_missing_env_file_is_a_usage_error(cli_runner: CliRunner, tmp_path: Path) -> None:
    result, transport = _invoke(cli_runner, ["send", "--env-file", str(tmp_path / "absent.env"), *_ROUTE, *_MESSAGE])

    assert result.exit_code == 2
    assert transport.deliveries == []


# ---------------------------------------------------------------------------
# The password, kept out of the process list
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_the_password_can_come_from_a_file(cli_runner: CliRunner, tmp_path: Path) -> None:
    password_file = tmp_path / "password"
    password_file.write_text("s3cr3t pass\nignored second line\n", encoding="utf-8")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, "--username", "user", "--password-file", str(password_file)])

    assert result.exit_code == 0, result.output
    assert transport.only.options.credentials == ("user", "s3cr3t pass")


@pytest.mark.os_agnostic
def test_the_password_can_come_from_stdin(cli_runner: CliRunner) -> None:
    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, "--username", "user", "--password-file", "-"], input_text="from-stdin\n")

    assert result.exit_code == 0, result.output
    assert transport.only.options.credentials == ("user", "from-stdin")


@pytest.mark.os_agnostic
def test_password_and_password_file_exclude_each_other(cli_runner: CliRunner, tmp_path: Path) -> None:
    password_file = tmp_path / "password"
    password_file.write_text("x\n", encoding="utf-8")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, "--username", "u", "--password", "y", "--password-file", str(password_file)])

    assert result.exit_code == 2
    assert "mutually exclusive" in result.output
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_an_overlong_password_file_is_refused(cli_runner: CliRunner, tmp_path: Path) -> None:
    password_file = tmp_path / "password"
    password_file.write_text("x" * (cli_mod._PASSWORD_FILE_MAX_CHARS + 1), encoding="utf-8")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, "--username", "u", "--password-file", str(password_file)])

    assert result.exit_code == 2
    assert "a password file holds one line" in result.output
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_the_password_falls_back_to_the_environment(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    monkeypatch.setenv("BTX_MAIL_SMTP_USERNAME", "user")
    monkeypatch.setenv("BTX_MAIL_SMTP_PASSWORD", "from-env")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.options.credentials == ("user", "from-env")


# ---------------------------------------------------------------------------
# Refusals: before any delivery, with the message send() gives
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_non_positive_attachment_size_is_refused(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    monkeypatch.setenv("BTX_MAIL_ATTACHMENT_MAX_SIZE", "0")

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE])

    # An InvalidInputError is a ValueError, which lib_cli_exit_tools maps to exit code 22.
    assert type(result.exception) is InvalidInputError
    assert str(result.exception) == "attachment_max_size_bytes must be positive, got 0"
    assert transport.deliveries == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("option", "value", "reason"),
    [
        ("--timeout", "-1", "smtp_timeout must be positive, got -1.0"),
        ("--delivery-deadline", "0", "smtp_delivery_deadline must be positive, got 0.0"),
    ],
)
def test_a_non_positive_duration_is_refused(cli_runner: CliRunner, option: str, value: str, reason: str) -> None:
    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, option, value])

    assert type(result.exception) is InvalidInputError
    assert str(result.exception) == reason
    assert transport.deliveries == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("smtp.example.com:99999", 'port must be 1-65535 in "smtp.example.com:99999"'),
        (
            "user:s3cr3t-pw@smtp.example.com",
            "SMTP host must be host[:port]; it must not contain '@' or '/' (pass credentials as smtp_username and smtp_password)",
        ),
    ],
)
def test_a_malformed_host_is_refused_with_the_message_send_gives(cli_runner: CliRunner, host: str, reason: str) -> None:
    result, transport = _invoke(cli_runner, ["send", "--host", host, "--recipient", "one@example.com", *_MESSAGE])

    assert type(result.exception) is InvalidInputError
    assert str(result.exception) == reason
    assert "s3cr3t-pw" not in result.output
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_a_quoted_host_is_accepted(cli_runner: CliRunner) -> None:
    result, transport = _invoke(cli_runner, ["send", "--host", '"smtp.example.com:587"', "--recipient", "one@example.com", *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.host == "smtp.example.com:587"


@pytest.mark.os_agnostic
def test_the_global_conf_is_left_untouched(cli_runner: CliRunner) -> None:
    before = cli_mod.conf.model_dump()

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, "--timeout", "42", "--no-starttls"])

    assert result.exit_code == 0, result.output
    assert transport.only.options.timeout == 42.0
    assert cli_mod.conf.model_dump() == before


@pytest.mark.os_agnostic
def test_conf_settings_without_an_option_still_apply(monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path) -> None:
    monkeypatch.setattr(cli_mod.conf, "raise_on_missing_attachments", False)

    result, transport = _invoke(cli_runner, ["send", *_ROUTE, *_MESSAGE, "--attachment", str(tmp_path / "missing.txt"), *_no_blocked_dirs(tmp_path)])

    assert result.exit_code == 0, result.output
    assert _attachment_names(transport.only.raw) == []


# ---------------------------------------------------------------------------
# Attachment security options, against a real SMTP server
# ---------------------------------------------------------------------------


def _server_args(data_server: tuple[Any, CollectingHandler]) -> list[str]:
    controller, _handler = data_server
    return ["--host", f"127.0.0.1:{controller.port}", "--recipient", "rcpt@example.com", "--no-starttls", "--local-hostname", "client.example.com"]


@pytest.mark.os_agnostic
def test_an_allowlist_from_the_options_sends_only_matching_files(cli_runner: CliRunner, tmp_path: Path, data_server: tuple[Any, CollectingHandler]) -> None:
    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF-1.4 content")
    sheet = tmp_path / "sheet.xlsx"
    sheet.write_bytes(b"cells")

    args = ["send", *_server_args(data_server), *_MESSAGE, "--attachment", str(report), "--attachment", str(sheet)]
    args += ["--attachment-allowed-ext", ".pdf,.txt", "--attachment-warn", *_no_blocked_dirs(tmp_path)]
    result = cli_runner.invoke(cli_mod.cli, args)

    assert result.exit_code == 0, result.output
    _controller, handler = data_server
    assert len(handler.messages) == 1
    assert _attachment_names(handler.messages[0]) == ["report.pdf"]


@pytest.mark.os_agnostic
def test_an_allowlist_from_the_environment_refuses_other_files(
    monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner, tmp_path: Path, data_server: tuple[Any, CollectingHandler]
) -> None:
    monkeypatch.setenv("BTX_MAIL_ATTACHMENT_ALLOWED_EXT", ".docx,.xlsx")
    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF-1.4 content")

    result = cli_runner.invoke(cli_mod.cli, ["send", *_server_args(data_server), *_MESSAGE, "--attachment", str(report), *_no_blocked_dirs(tmp_path)])

    assert result.exit_code != 0
    assert "not in allowed list" in str(result.exception)
    _controller, handler = data_server
    assert handler.messages == []


@pytest.mark.os_agnostic
def test_a_size_limit_from_the_options_refuses_a_larger_file(cli_runner: CliRunner, tmp_path: Path, data_server: tuple[Any, CollectingHandler]) -> None:
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * 100)

    result = cli_runner.invoke(
        cli_mod.cli, ["send", *_server_args(data_server), *_MESSAGE, "--attachment", str(big), "--attachment-max-size", "10", *_no_blocked_dirs(tmp_path)]
    )

    assert "exceeds limit 10 bytes" in str(result.exception)
    _controller, handler = data_server
    assert handler.messages == []


@pytest.mark.os_agnostic
def test_symlinks_are_sent_only_when_the_option_allows_them(cli_runner: CliRunner, tmp_path: Path, data_server: tuple[Any, CollectingHandler]) -> None:
    real = tmp_path / "real.txt"
    real.write_bytes(b"content")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    base = ["send", *_server_args(data_server), *_MESSAGE, "--attachment", str(link), *_no_blocked_dirs(tmp_path)]

    refused = cli_runner.invoke(cli_mod.cli, base)
    allowed = cli_runner.invoke(cli_mod.cli, [*base, "--attachment-allow-symlinks"])

    assert "symlink detected" in str(refused.exception)
    assert allowed.exit_code == 0, allowed.output
    _controller, handler = data_server
    assert [_attachment_names(raw) for raw in handler.messages] == [["real.txt"]]


@pytest.mark.os_agnostic
def test_the_default_blocklist_refuses_an_executable_from_the_cli(cli_runner: CliRunner, tmp_path: Path, data_server: tuple[Any, CollectingHandler]) -> None:
    tool = tmp_path / "tool.exe"
    tool.write_bytes(b"MZ")

    result = cli_runner.invoke(cli_mod.cli, ["send", *_server_args(data_server), *_MESSAGE, "--attachment", str(tool), *_no_blocked_dirs(tmp_path)])

    assert 'extension ".exe" is blocked' in str(result.exception)
    _controller, handler = data_server
    assert handler.messages == []


# ---------------------------------------------------------------------------
# Machine-readable output
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_send_prints_a_json_envelope_naming_what_was_skipped(cli_runner: CliRunner, tmp_path: Path) -> None:
    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF")
    tool = tmp_path / "tool.exe"
    tool.write_bytes(b"MZ")
    args = ["--json", "send", "--host", "smtp.example.com", "--recipient", "one@example.com,not-an-address", *_MESSAGE]
    args += ["--attachment", str(report), "--attachment", str(tool), "--attachment-warn", *_no_blocked_dirs(tmp_path)]

    transport = _RecordingTransport()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cli_mod.conf, "raise_on_invalid_recipient", False)
        result = cli_runner.invoke(cli_mod.cli, args, obj=CliContext(transport=transport))

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.stdout)
    assert envelope["ok"] is True
    assert envelope["command"] == "send"
    assert envelope["data"] == {"sender": "one@example.com", "recipients": ["one@example.com"], "hosts": ["smtp.example.com"]}
    assert {(item["kind"], item["value"]) for item in envelope["skipped"]} == {("attachment", str(tool)), ("recipient", "not-an-address")}
    assert _attachment_names(transport.only.raw) == ["report.pdf"]


@pytest.mark.os_agnostic
def test_json_bare_prints_the_payload_alone(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(cli_mod.cli, ["--json-bare", "validate-email", "user@example.com"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"address": "user@example.com", "valid": True}


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("args", "data"),
    [
        (["hello"], {"greeting": "Hello World"}),
        (["validate-smtp-host", "[::1]:25"], {"host": "[::1]:25", "valid": True}),
    ],
)
def test_every_command_has_a_json_envelope(cli_runner: CliRunner, args: list[str], data: dict[str, Any]) -> None:
    result = cli_runner.invoke(cli_mod.cli, ["--json", *args])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"ok": True, "command": args[0], "data": data, "skipped": []}


@pytest.mark.os_agnostic
def test_info_has_a_json_envelope(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(cli_mod.cli, ["--json", "info"])

    envelope = json.loads(result.stdout)
    assert envelope["data"]["version"] == cli_mod.__init__conf__.version
    assert envelope["data"]["name"] == cli_mod.__init__conf__.name


@pytest.mark.os_agnostic
def test_json_and_json_bare_exclude_each_other(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(cli_mod.cli, ["--json", "--json-bare", "hello"])

    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def _main(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = cli_mod.main(argv)
    return code, capsys.readouterr().out


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("argv", "error_type"),
    [
        (["validate-email", "not-an-address"], "InvalidInputError"),
        (["fail"], "RuntimeError"),
        (["send", "--host", "smtp.example.com"], "MissingParameter"),
    ],
    ids=["refused-value", "runtime-error", "usage-error"],
)
def test_a_failure_is_a_json_error_with_the_exit_code_it_has_without_json(
    capsys: pytest.CaptureFixture[str], isolated_traceback_config: None, argv: list[str], error_type: str
) -> None:
    plain_code, _plain_out = _main(argv, capsys)
    json_code, json_out = _main(["--json", *argv], capsys)
    bare_code, bare_out = _main(["--json-bare", *argv], capsys)

    assert json_code == plain_code == bare_code != 0
    envelope = json.loads(json_out)
    assert envelope["ok"] is False
    assert envelope["command"] == argv[0]
    assert envelope["error"]["type"] == error_type
    assert json.loads(bare_out) == envelope["error"]


@pytest.mark.os_agnostic
def test_a_refused_value_keeps_its_documented_exit_code_in_json_mode(capsys: pytest.CaptureFixture[str], isolated_traceback_config: None) -> None:
    code, _out = _main(["--json", "validate-smtp-host", "[::1"], capsys)

    assert code == lib_cli_exit_tools.get_system_exit_code(ValueError())


@pytest.mark.os_agnostic
def test_a_json_send_against_a_real_server_reports_and_delivers(
    capsys: pytest.CaptureFixture[str], isolated_traceback_config: None, tmp_path: Path, data_server: tuple[Any, CollectingHandler]
) -> None:
    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF")

    code, out = _main(["--json", "send", *_server_args(data_server), *_MESSAGE, "--attachment", str(report), *_no_blocked_dirs(tmp_path)], capsys)

    assert code == 0
    envelope = json.loads(out)
    assert envelope["ok"] is True
    assert envelope["data"]["recipients"] == ["rcpt@example.com"]
    _controller, handler = data_server
    assert [_attachment_names(raw) for raw in handler.messages] == [["report.pdf"]]


@pytest.mark.os_agnostic
def test_the_typed_context_keeps_an_embedded_transport_through_the_group(cli_runner: CliRunner) -> None:
    transport = _RecordingTransport()

    result = cli_runner.invoke(cli_mod.cli, ["--traceback", "send", *_ROUTE, *_MESSAGE], obj=CliContext(transport=transport))

    assert result.exit_code == 0, result.output
    assert len(transport.deliveries) == 1


@pytest.mark.os_agnostic
def test_a_command_run_on_its_own_gets_a_default_context() -> None:
    @click.command()
    @click.pass_context
    def probe(ctx: click.Context) -> None:
        click.echo(repr(cli_mod._context(ctx)))

    from click.testing import CliRunner as Runner

    assert "CliContext(traceback=False" in Runner().invoke(probe, []).output


# ---------------------------------------------------------------------------
# JSON failures carry what the caller needs; JSON mode comes from the group options only
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_json_delivery_failure_names_the_failed_recipients_and_what_was_skipped(
    capsys: pytest.CaptureFixture[str], isolated_traceback_config: None, tmp_path: Path
) -> None:
    script = tmp_path / "run.sh"
    script.write_text("echo hi", encoding="utf-8")
    argv = ["--json", "send", "--host", "127.0.0.1:1", "--recipient", "one@example.com", *_MESSAGE, "--no-starttls", "--timeout", "2"]
    argv += ["--local-hostname", "client.example.com", "--attachment", str(script), "--attachment-warn", *_no_blocked_dirs(tmp_path)]

    code, out = _main(argv, capsys)

    envelope = json.loads(out)
    assert code != 0
    assert envelope["error"]["type"] == "DeliveryError"
    assert envelope["error"]["failed_recipients"] == ["one@example.com"]
    assert envelope["error"]["hosts"] == ["127.0.0.1:1"]
    assert [(item["kind"], item["value"]) for item in envelope["skipped"]] == [("attachment", str(script))]


@pytest.mark.os_agnostic
def test_an_option_value_spelled_like_the_json_flag_does_not_switch_json_on(capsys: pytest.CaptureFixture[str], isolated_traceback_config: None) -> None:
    code, out = _main(["validate-email", "--json"], capsys)

    assert code != 0
    assert not out.lstrip().startswith("{"), out


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("raw", "value"),
    [('"s3cret"', "s3cret"), ("'s3cret'", "s3cret"), ('s3cret"', 's3cret"'), ('""x""', '"x"'), ("\"abc'", "\"abc'"), ("  plain  ", "plain")],
)
def test_an_env_file_value_loses_one_matching_pair_of_quotes_only(cli_runner: CliRunner, tmp_path: Path, raw: str, value: str) -> None:
    env_file = tmp_path / "mail.env"
    env_file.write_text(f"BTX_MAIL_SMTP_USERNAME=user\nBTX_MAIL_SMTP_PASSWORD={raw}\n", encoding="utf-8")

    result, transport = _invoke(cli_runner, ["send", "--env-file", str(env_file), *_ROUTE, *_MESSAGE])

    assert result.exit_code == 0, result.output
    assert transport.only.options.credentials == ("user", value)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("command", ["send", "info", "hello", "validate-email", "validate-smtp-host", "fail"])
def test_command_help_is_plain_text_not_docstring_markup(cli_runner: CliRunner, command: str) -> None:
    result = cli_runner.invoke(cli_mod.cli, [command, "--help"])

    assert result.exit_code == 0
    assert "###" not in result.output
    assert "**Purpose:**" not in result.output
