# Installation Guide

> The CLI stack uses `rich-click`, which bundles `rich` styling on top of click-style ergonomics.

This guide collects every supported method to install `btx_lib_mail`, including
isolated environments and system package managers. Pick the option that matches your workflow.

## 1. Standard Virtual Environment (pip)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[dev]       # development install
# or for runtime only:
pip install .
```

## 2. Per-User Installation (No Virtualenv)

```bash
pip install --user .
```

> Note: This respects PEP 668. Avoid using it on system Python builds marked as
> "externally managed". Ensure `~/.local/bin` (POSIX) is on your PATH so the CLI is available.

## 3. pipx (Isolated CLI-Friendly Environment)

```bash
pipx install .
pipx upgrade btx_lib_mail
# From Git tag/commit:
pipx install "git+https://github.com/bitranox/btx_lib_mail"
```

## 4. uv (Fast Installer/Runner)

```bash
uv pip install -e .[dev]
uv tool install .
uvx btx_lib_mail --help
```

## 5. From Build Artifacts

```bash
python -m build
pip install dist/btx_lib_mail-*.whl
pip install dist/btx_lib_mail-*.tar.gz   # sdist
```

## 6. Poetry or PDM Managed Environments

```bash
# Poetry
poetry add btx_lib_mail     # as dependency
poetry install                          # for local dev

# PDM
pdm add btx_lib_mail
pdm install
```

## 7. Install Directly from Git

```bash
pip install "git+https://github.com/bitranox/btx_lib_mail#egg=btx_lib_mail"
```

## 8. System Package Managers (Optional Distribution Channels)

- Deb/RPM: Package with `fpm` for OS-native delivery

All methods register both the `btx_lib_mail` and
`btx-lib-mail` commands on your PATH.
