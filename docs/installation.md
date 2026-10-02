# Installation

```bash
pip install btx_lib_mail
```

For alternative install paths (pipx, uv, source builds, etc.), see
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
