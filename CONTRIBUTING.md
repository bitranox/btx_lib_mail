# Contributing Guide

Thanks for helping improve **btx_lib_mail**. The sections below summarise the day-to-day workflow, highlight the repository automation, and list the checks that must pass before a change is merged.

## 1. Workflow Overview

1. Fork and branch - use short, imperative branch names (`feature/cli-extension`, `fix/codecov-token`).
2. Make focused commits - keep unrelated refactors out of the same change.
3. Run `make test` locally before pushing (see `DEVELOPMENT.md`).
4. Update documentation and changelog entries that are affected by the change.
5. Open a pull request referencing any relevant issues.

## 2. Commits & Pushes

- Commit messages should be imperative (`Add rich handler`, `Fix CLI exit codes`).
- `make test` runs the full lint/type/test pipeline but leaves the repository untouched;
  create commits yourself before pushing.
- `make push` (bmk) runs the test gate, commits, and pushes to the remote in one step;
  see `DEVELOPMENT.md` and `make help` for its exact behaviour.

## 3. Coding Standards

- Apply the repository's Clean Architecture / SOLID rules (see `AGENTS.md`).
- Prefer small, single-purpose modules and functions; avoid mixing orthogonal concerns.
- Free functions and modules use `snake_case`; classes are `PascalCase`.
- Keep runtime dependencies minimal. Use the standard library where practical.

## 4. Tests & Tooling

- `make test` runs ruff (lint + format check), pyright strict, bandit, `import-linter`,
  and pytest with coverage (gated at `fail_under = 85` in `pyproject.toml`).
- Tests follow a narrative style: prefer names like `test_when_<condition>_<outcome>()`,
  keep each case laser-focused, and mark OS constraints with the provided markers
  (`os_agnostic`, `os_windows`, `os_macos`, `os_posix`, `os_linux`, `local_only`).
- Whenever you add a CLI behaviour or change metadata fallbacks, update the relevant
  story in `tests/test_cli.py` or `tests/test_metadata.py` so the specification remains
  complete.
- A model holding a credential extends `SecretSafeModel` (see the "Secret safety"
  section of `docs/api.md`) rather than a plain `pydantic.BaseModel`, and lists its
  credential field names in `credential_fields`.

## 5. Documentation Checklist

Before opening a PR, confirm the following:

- [ ] `make test` passes locally.
- [ ] Relevant documentation (`README.md`, `DEVELOPMENT.md`, `docs/systemdesign/*`) is updated.
- [ ] No generated artefacts or virtual environments are committed.
- [ ] Version bumps, when required, touch **only** `pyproject.toml` and `CHANGELOG.md`
      (`make bump-patch`/`-minor`/`-major` does both).

## 6. Security & Configuration

- Never commit secrets. Tokens (Codecov, PyPI) belong in `.env` (ignored by git) or CI secrets.
- Do not write a caller- or filesystem-supplied value (a host, recipient, sender, or
  attachment path) into a log line or raised error text unclean; see `_printable` in
  `src/btx_lib_mail/lib_mail.py` and the "Per-host failure log" section of `docs/api.md`.
- Do not format a credential into a custom validator's error message; see "Never put a
  secret into a custom validator's error message" in `docs/configuration.md`.

Happy hacking!
