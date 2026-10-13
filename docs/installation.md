# Installation

Install with uv and a cooldown, so a release younger than 7 days is never picked up
([why](../INSTALL.md#why-we-recommend-uv-supply-chain-protection)):

```bash
# install uv first, if you do not have it (macOS / Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

uv tool install --exclude-newer "7 days" btx_lib_mail
```

In a project, set `[tool.uv] exclude-newer = "7 days"` in its `pyproject.toml` and run
`uv add btx_lib_mail`. `pip install btx_lib_mail` works as well, without the cooldown.

For alternative install paths (pipx, source builds, etc.), see
[INSTALL.md](../INSTALL.md). All supported methods register both the
`btx_lib_mail` and `btx-lib-mail` commands on your PATH.

## Python 3.10+ Baseline

- The project targets **Python 3.10 and newer only** (it uses the parenthesised
  multi-item `with` statement and `X | Y` type unions, among other 3.10 features).
- Runtime dependency floors live in `pyproject.toml` (`[project].dependencies`); read
  them there rather than a number restated here, since a floor is bumped independently
  of this page.
- GitHub Actions jobs run on the rolling `ubuntu-latest`, `macos-latest` and
  `windows-latest` runners. The job matrix comes from `pyproject.toml`: the operating
  systems from `[tool.ci].os`, the Python versions from the `Programming Language ::
  Python :: X.Y` classifiers. The workflow files under `.github/workflows/` are
  distributed from the `default_cicd_public` template.
