from __future__ import annotations

from click.testing import CliRunner
from collections.abc import Mapping, Sequence
import sys
from dataclasses import dataclass
from types import ModuleType, SimpleNamespace
from typing import Callable, Protocol, TypedDict

import pytest
from pytest import MonkeyPatch

import scripts.build as build
import scripts.cli as cli
import scripts.dev as dev
import scripts.install as install
import scripts.run_cli as run_cli
import scripts.test as test_script
from scripts._utils import RunResult, ProjectMetadata
from scripts import _utils


RunCommand = Sequence[str] | str
ModuleLike = ModuleType | SimpleNamespace


class RecordedOptions(TypedDict):
    check: bool
    capture: bool
    cwd: str | None
    env: Mapping[str, str] | None
    dry_run: bool


@dataclass(slots=True)
class RecordedRun:
    """Single invocation captured from a scripts command execution.

    Attributes
    ----------
    command:
        Command list or shell string passed to the automation runner.
    options:
        Keyword arguments controlling execution (capture, cwd, etc.).
    """

    command: RunCommand
    options: RecordedOptions


class RunStub(Protocol):
    def __call__(
        self,
        cmd: RunCommand,
        *,
        check: bool = True,
        capture: bool = True,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        dry_run: bool = False,
    ) -> RunResult: ...


def _remember_runs(history: list[RecordedRun]) -> RunStub:
    """Return a runner stub that appends every invocation to ``history``.

    Why
        Tests need to inspect the commands executed by automation wrappers
        without launching real subprocesses.

    Inputs
        history:
            Mutable list collecting :class:`RecordedRun` entries.

    Outputs
        RunStub: Callable mimicking ``scripts._utils.run``.
    """

    def _run(
        cmd: RunCommand,
        *,
        check: bool = True,
        capture: bool = True,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        dry_run: bool = False,
    ) -> RunResult:
        history.append(
            RecordedRun(
                command=cmd,
                options={
                    "check": check,
                    "capture": capture,
                    "cwd": cwd,
                    "env": env,
                    "dry_run": dry_run,
                },
            )
        )
        return RunResult(0, "", "")

    return _run


def _commands_as_text(runs: list[RecordedRun]) -> list[str]:
    """Render every recorded command as a single string.

    Why
        Simplifies assertions that look for substrings inside the recorded
        commands.

    Inputs
        runs:
            Sequence of recorded invocations.

    Outputs
        list[str]:
            Normalised textual commands.
    """

    rendered: list[str] = []
    for run in runs:
        command = run.command
        if isinstance(command, str):
            rendered.append(command)
        else:
            rendered.append(" ".join(command))
    return rendered


def _first_command(runs: list[RecordedRun]) -> RunCommand:
    """Return the command associated with the first recorded run.

    Why
        Several tests only care about the inaugural command executed by the
        automation wrapper; this helper keeps that intent obvious.

    Inputs
        runs:
            Recorded run list populated by :func:`_remember_runs`.

    Outputs
        RunCommand: the first command issued.
    """

    return runs[0].command


def _capture_sync(record: list[ProjectMetadata]) -> Callable[[ProjectMetadata], None]:
    def _sync(project: ProjectMetadata) -> None:
        record.append(project)

    return _sync


@pytest.mark.os_agnostic
def test_get_project_metadata_fields():
    meta = _utils.get_project_metadata()
    assert meta.name == "btx_lib_mail"
    assert meta.slug == "btx-lib-mail"
    assert meta.import_package == "btx_lib_mail"
    assert meta.coverage_source == "src/btx_lib_mail"
    assert meta.github_tarball_url("1.2.3").endswith("/bitranox/btx_lib_mail/archive/refs/tags/v1.2.3.tar.gz")
    assert meta.version
    assert meta.summary
    assert meta.author_name
    assert meta.metadata_module.as_posix().endswith("src/btx_lib_mail/__init__conf__.py")


@pytest.mark.os_agnostic
def test_build_script_uses_metadata(monkeypatch: MonkeyPatch) -> None:
    recorded: list[RecordedRun] = []
    synced: list[ProjectMetadata] = []
    monkeypatch.setattr(build, "run", _remember_runs(recorded))
    monkeypatch.setattr(test_script, "sync_metadata_module", _capture_sync(synced))
    runner = CliRunner()
    result = runner.invoke(cli.main, ["build"])
    assert result.exit_code == 0
    commands = _commands_as_text(recorded)
    assert any("python -m build" in cmd for cmd in commands)


@pytest.mark.os_agnostic
def test_dev_script_installs_dev_extras(monkeypatch: MonkeyPatch) -> None:
    recorded: list[RecordedRun] = []
    synced: list[ProjectMetadata] = []
    monkeypatch.setattr(dev, "run", _remember_runs(recorded))
    monkeypatch.setattr(test_script, "sync_metadata_module", _capture_sync(synced))
    runner = CliRunner()
    result = runner.invoke(cli.main, ["dev"])
    assert result.exit_code == 0
    first_command = _first_command(recorded)
    assert isinstance(first_command, list)
    assert first_command == [sys.executable, "-m", "pip", "install", "-e", ".[dev]"]


@pytest.mark.os_agnostic
def test_install_script_installs_package(monkeypatch: MonkeyPatch) -> None:
    recorded: list[RecordedRun] = []
    synced: list[ProjectMetadata] = []
    monkeypatch.setattr(install, "run", _remember_runs(recorded))
    monkeypatch.setattr(test_script, "sync_metadata_module", _capture_sync(synced))
    runner = CliRunner()
    result = runner.invoke(cli.main, ["install"])
    assert result.exit_code == 0
    first_command = _first_command(recorded)
    assert isinstance(first_command, list)
    assert first_command == [sys.executable, "-m", "pip", "install", "-e", "."]


@pytest.mark.os_agnostic
def test_run_cli_imports_dynamic_package(monkeypatch: MonkeyPatch) -> None:
    seen: list[str] = []
    synced: list[ProjectMetadata] = []

    def _run_cli_main(_args: Sequence[str] | None = None) -> int:
        return 0

    def fake_import(name: str) -> ModuleLike:
        seen.append(name)
        if name.endswith(".__main__"):
            return SimpleNamespace()
        if name.endswith(".cli"):
            return SimpleNamespace(main=_run_cli_main)
        raise AssertionError(f"unexpected import {name}")

    monkeypatch.setattr(run_cli, "import_module", fake_import)
    monkeypatch.setattr(test_script, "sync_metadata_module", _capture_sync(synced))
    runner = CliRunner()
    result = runner.invoke(cli.main, ["run"])
    assert result.exit_code == 0
    package = run_cli.PROJECT.import_package
    assert f"{package}.cli" in seen
    if len(seen) == 2:
        assert seen == [f"{package}.__main__", f"{package}.cli"]


@pytest.mark.os_agnostic
def test_test_script_uses_pyproject_configuration(monkeypatch: MonkeyPatch) -> None:
    recorded: list[RecordedRun] = []

    def _noop() -> None:
        return None

    def _always_false(_name: str) -> bool:
        return False

    monkeypatch.setattr(test_script, "bootstrap_dev", _noop)
    synced: list[ProjectMetadata] = []
    monkeypatch.setattr(_utils, "cmd_exists", _always_false)
    monkeypatch.setattr(test_script, "run", _remember_runs(recorded))
    monkeypatch.setattr(test_script, "sync_metadata_module", _capture_sync(synced))
    runner = CliRunner()
    result = runner.invoke(cli.main, ["test"])
    assert result.exit_code == 0
    pytest_commands: list[list[str]] = []
    for run in recorded:
        command = run.command
        if isinstance(command, str):
            continue
        command_list = list(command)
        if command_list[:3] == ["python", "-m", "pytest"]:
            pytest_commands.append(command_list)
    assert pytest_commands, "pytest not invoked"
    assert any(f"--cov={test_script.COVERAGE_TARGET}" in " ".join(sequence) for sequence in pytest_commands)
    assert synced
