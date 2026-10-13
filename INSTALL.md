# Installation Guide

> The CLI stack uses `rich-click`, which bundles `rich` styling on top of click-style ergonomics.

This guide collects every supported method to install `btx_lib_mail`, including
isolated environments and system package managers. Pick the option that matches your workflow.

## 1. uv with a cooldown (recommended)

[uv](https://docs.astral.sh/uv/) is the recommended way to install `btx_lib_mail`, with a cooldown so
that a release younger than 7 days is never picked up. Why that matters is explained in
[Why we recommend uv: supply-chain protection](#why-we-recommend-uv-supply-chain-protection).

Install uv (if not already installed):

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Run the CLI without installing anything, or install it on your PATH. `--exclude-newer` goes before
the package:

```bash
uvx --exclude-newer "7 days" btx-lib-mail --help
uv tool install --exclude-newer "7 days" btx_lib_mail
```

`uv tool install` stores the cutoff in the tool's receipt, so `uv tool upgrade btx_lib_mail` keeps
the cooldown. For a project that depends on the library, put the cooldown in its `pyproject.toml`:

```toml
[tool.uv]
exclude-newer = "7 days"
```

then `uv add btx_lib_mail`.

## 2. Standard Virtual Environment (pip)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[dev]       # development install
# or for runtime only:
pip install .
```

## 3. Per-User Installation (No Virtualenv)

```bash
pip install --user .
```

> Note: This respects PEP 668. Avoid using it on system Python builds marked as
> "externally managed". Ensure `~/.local/bin` (POSIX) is on your PATH so the CLI is available.

## 4. pipx (Isolated CLI-Friendly Environment)

```bash
pipx install .
pipx upgrade btx_lib_mail
# From Git tag/commit:
pipx install "git+https://github.com/bitranox/btx_lib_mail"
```

## 5. uv (Fast Installer/Runner)

```bash
uv pip install -e .[dev]
uv tool install .
uvx btx_lib_mail --help
```

## 6. From Build Artifacts

```bash
python -m build
pip install dist/btx_lib_mail-*.whl
pip install dist/btx_lib_mail-*.tar.gz   # sdist
```

## 7. Poetry or PDM Managed Environments

```bash
# Poetry
poetry add btx_lib_mail     # as dependency
poetry install                          # for local dev

# PDM
pdm add btx_lib_mail
pdm install
```

## 8. Install Directly from Git

```bash
pip install "git+https://github.com/bitranox/btx_lib_mail#egg=btx_lib_mail"
```

## 9. System Package Managers (Optional Distribution Channels)

- Deb/RPM: Package with `fpm` for OS-native delivery

All methods register both the `btx_lib_mail` and
`btx-lib-mail` commands on your PATH.

## Why we recommend uv: supply-chain protection

This repository commits a `uv.lock`. It pins every package the project needs, transitive
dependencies included, to an exact version and to the hashes of that version's files. The
`exclude-newer` setting under `[tool.uv]` in `pyproject.toml` adds a cooldown: uv leaves any
release younger than that out of the lock. CI installs from the lock, so a hijacked release that
gets pulled again within the cooldown never reaches our builds, and a file whose hash does not
match is refused.

That protection stays in this repository. The installable package declares only lower bounds
(`>=`) for its dependencies, so a plain `pip install` takes the newest release of every transitive
dependency at the moment you run it. If one of them was hijacked an hour earlier, you get the
hijacked version. `pipx install` and `uv tool install` without options do the same.

To install the command line tool with a cooldown of your own (uv then skips any release younger
than 7 days, transitive ones included), or to run the exact tree our CI tests:

```bash
uv tool install --exclude-newer "7 days" btx_lib_mail
git clone https://github.com/bitranox/btx_lib_mail.git && cd btx_lib_mail && uv sync --locked && uv run btx_lib_mail --help
```

If you depend on btx_lib_mail in your own project, give that project the same cooldown (7 days here, as
an example) and commit the `uv.lock` that `uv add btx_lib_mail` writes:

```toml
[tool.uv]
exclude-newer = "7 days"
```

