# Installation

```bash
pip install btx_lib_mail
```

For alternative install paths (pipx, uv, source builds, etc.), see
[INSTALL.md](../INSTALL.md). All supported methods register both the
`btx_lib_mail` and `btx-lib-mail` commands on your PATH.

### Python 3.10+ Baseline

- The project targets **Python 3.10 and newer only**. Helpers freely rely on conveniences
  such as `Path.unlink(missing_ok=True)` and modern `contextlib` utilities.
- **Dependency audit (October 16, 2025):** runtime requirements continue to
  match the latest stable releases (`rich-click>=1.9.3`,
  `lib_cli_exit_tools>=2.1.0`, `pydantic>=2.12.2`). Development extras were
  reconfirmed via `python -m pip index versions ...`, with no upgrades required.
- GitHub Actions jobs keep using the rolling runners (`ubuntu-latest`,
  `macos-latest`, `windows-latest`) and now cache pip downloads via
  `actions/setup-python@v6` while pinning CodeQL to `v4.30.8`, preserving
  parity with the latest 2025 ruleset.
