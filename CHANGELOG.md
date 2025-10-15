# Changelog

## [0.0.1] - 2025-10-15
### Added
- Static metadata portrait generated from ``pyproject.toml`` and exported via
  ``btx_lib_mail.__init__conf__``; automation keeps the constants in
  sync during tests and push workflows.
- Help-first CLI experience: invoking the command without subcommands now
  prints the rich-click help screen; ``--traceback`` without subcommands still
  executes the placeholder domain entry.
- `ProjectMetadata` now captures version, summary, author, and console-script
  name, providing richer diagnostics for automation scripts.

### Changed
- Refactored CLI helpers into prose-like functions with explicit docstrings for
  intent, inputs, outputs, and side effects.
- Overhauled module headers and system design docs to align with the clean
  narrative style; `docs/systemdesign/module_reference.md` reflects every helper.
- Scripts (`test`, `push`) synchronise metadata before running, ensuring the
  portrait stays current without runtime lookups.

### Fixed
- Eliminated runtime dependency on ``importlib.metadata`` by generating the
  metadata file ahead of time, removing a failure point in minimal installs.
- Hardened tests around CLI help output, metadata constants, and automation
  scripts to keep coverage exhaustive.
