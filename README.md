# btx_lib_mail

<!-- Badges -->
[![CI](https://github.com/bitranox/btx_lib_mail/actions/workflows/ci.yml/badge.svg)](https://github.com/bitranox/btx_lib_mail/actions/workflows/ci.yml)
[![CodeQL](https://github.com/bitranox/btx_lib_mail/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/btx_lib_mail/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open in Codespaces](https://img.shields.io/badge/Codespaces-Open-blue?logo=github&logoColor=white&style=flat-square)](https://codespaces.new/bitranox/btx_lib_mail?quickstart=1)
[![PyPI](https://img.shields.io/pypi/v/btx_lib_mail.svg)](https://pypi.org/project/btx_lib_mail/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/btx_lib_mail.svg)](https://pypi.org/project/btx_lib_mail/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)
[![codecov](https://codecov.io/gh/bitranox/btx_lib_mail/graph/badge.svg?token=UFBaUDIgRk)](https://codecov.io/gh/bitranox/btx_lib_mail)
[![Maintainability](https://qlty.sh/badges/041ba2c1-37d6-40bb-85a0-ec5a8a0aca0c/maintainability.svg)](https://qlty.sh/gh/bitranox/projects/btx_lib_mail)
[![Known Vulnerabilities](https://snyk.io/test/github/bitranox/btx_lib_mail/badge.svg)](https://snyk.io/test/github/bitranox/btx_lib_mail)

Scaffold for Python Projects with registered commandline commands:
- CLI entry point styled with rich-click (rich output + click ergonomics)
- Exit-code and messaging helpers powered by lib_cli_exit_tools

## Install

```bash
pip install btx_lib_mail
```

For alternative install paths (pipx, uv, source builds, etc.), see
[INSTALL.md](INSTALL.md). All supported methods register both the
`btx_lib_mail` and `btx-lib-mail` commands on your PATH.

### Python 3.13+ Baseline

- The project now targets **Python 3.13 and newer only**. All compatibility
  shims for older interpreters and legacy tool outputs have been removed; the
  automation helpers now lean on modern conveniences such as `Path.unlink(missing_ok=True)`
  and standard-library `shutil.which()` lookups.
- Runtime dependencies stay on the current stable releases (`rich-click>=1.9.3`
  and `lib_cli_exit_tools>=2.0.0`), while the development extra trims unused
  packages (notably `pytest-asyncio`) and keeps pytest, ruff, pyright, bandit,
  build, twine, codecov-cli, pip-audit, textual, and import-linter pinned to
  their newest majors.
- CI workflows now exercise GitHub's rolling runner images (`ubuntu-latest`,
  `macos-latest`, `windows-latest`) and cover CPython 3.13 alongside the latest
  available 3.x release provided by Actions.


## Usage

The CLI leverages [rich-click](https://github.com/ewels/rich-click) so help output, validation errors, and prompts render with Rich styling while keeping the familiar click ergonomics.
The scaffold keeps a CLI entry point so you can validate packaging flows, but it
currently exposes a single informational command while logging features are
developed:

```bash
btx_lib_mail info
btx_lib_mail hello
btx_lib_mail fail
btx_lib_mail --traceback fail
btx-lib-mail info
python -m btx_lib_mail info
```

For library use you can import the documented helpers directly:

```python
import btx_lib_mail as btpc

btpc.emit_greeting()
try:
    btpc.raise_intentional_failure()
except RuntimeError as exc:
    print(f"caught expected failure: {exc}")

btpc.print_info()
```


## Further Documentation

- [Install Guide](INSTALL.md)
- [Development Handbook](DEVELOPMENT.md)
- [Contributor Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Module Reference](docs/systemdesign/module_reference.md)
- [License](LICENSE)
