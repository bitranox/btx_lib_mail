# Handover - btx_lib_mail, 2026-10-02 16:50 (review sweep 1 fixed, docs and skill corrected, NOT pushed)

Read `OPEN-WORK.md` first: ranks 21, 22, 20, 30 (USER) and 40, 50, 60 (FOUND) are open.

## In flight

All 20 sweep-1 findings of the code-quality review are fixed, plus seven code defects a
three-agent documentation audit found. Every doc page and the `python-send-mail` skill now
match the code. Nothing has been pushed: Linux is green locally (`make test`; 548 tests in the last run), but
macOS and Windows CI have not run on any of it. The only Windows check was a probe on the Windows test machine
showing that `os.lstat` and `os.fstat` agree on `(st_dev, st_ino)` on Python 3.10, 3.12 and 3.14.
The attachment open-once check relies on that.

## Committed, or not

- btx_lib_mail master: 11 commits after `136d752` (the handover commit is the last). All are
  LOCAL ONLY.
- `OPEN-WORK.md` and this file are committed with this handover. `EXECUTION-USER-REVIEW.md` and
  `.private/` are gitignored.
- bitranox-skills clone: the twin
  `plugins/bitranox/skills/coding-python-send-mail/SKILL.md` is rewritten on disk and uncommitted
  (OPEN-WORK rank 22). The btx_lib_mail repo-gate compares the twin on disk, so leave it in place.

## Decided, and why

- The version is NOT decided. Everything is under CHANGELOG `[Unreleased]`, and pyproject still says
  3.1.0. The CLI no longer reads `./.env` implicitly, which breaks callers, so the owner picks
  3.1.0 or 4.0.0 at release time (rank 30).
- The full autonomous decision list is in `EXECUTION-USER-REVIEW.md` under "review sweep 1" and
  "documentation audit follow-up". In short:
  - extension defaults are POSIX|Windows everywhere;
  - `.env` is read only via `--env-file`;
  - plaintext AUTH logs a warning and is not refused;
  - a symlinked parent directory is followed, and that is documented;
  - the delivery deadline is opt-in;
  - exceptions keep their builtin second base.

## Decided against, and why

- No wrapping of `PermissionError` on an unreadable attachment into a `BtxMailError`: the library
  does not refuse it on purpose. It is documented as passing through.
- The 8 sibling repos whose `python -m` bypasses `cli.main()` were not fixed here. Each needs its
  own gate and release (rank 50).

## Still open, untouched

- Rank 20 (template ConfMail rollout), rank 40 (stale bitranox-skills branches), rank 50 (sibling
  `__main__`), rank 60 (`{#id}` anchors in api/module_reference/configuration docs): see
  `OPEN-WORK.md`.

## Lessons for the next nap

- When a test's bound is computed from the constant a mutation changes, the mutation cannot fail
  it: derive the bound from a fixed number.
- When a pydantic model overrides `__init__`, pydantic routes validation through it and silently
  drops `strict=`: wrap construction in a metaclass `__call__` instead.
- When a pydantic error is raised inside a schema wrap validator, pydantic rebuilds it as a plain
  `ValidationError` at its boundary: re-raise a subclass outside, in `__call__`/`model_validate*`.
- When `python -m pkg` runs a separate `lib_cli_exit_tools.cli_session` instead of `cli.main()`,
  its exit codes diverge from the console script's (a usage error exits 1 instead of 2).
- When a CLI decides `--json` by scanning all of argv, an option VALUE such as `--body --json`
  switches it on: read only the tokens before the subcommand.
- When moving top-level definitions by AST with leading-comment capture, verify that every
  definition's `ast.dump` is identical before and after: an off-by-one duplicated constants.
- When editing markdown table rows by regex, an escaped pipe (`\|`) inside a cell ends a non-greedy
  cell match: split with a lookbehind for the backslash.
- When a repo-gate compares a skill with its marketplace twin, write the twin in a separate command
  before the commit: the gate judges the whole command before the write runs.

## Exact next action

```bash
git push   # from the btx_lib_mail checkout
```

Then run `ci_wait` for `$(git rev-parse HEAD)` (compuse-toolbox) and fix any macOS/Windows red.
This is rank 21 ahead of rank 20 because 10 commits are unpushed and their cross-platform behaviour
is unverified: an unpushed fix protects no one, and a Windows failure would invalidate the review's
security fixes.

## Files that matter

- `src/btx_lib_mail/_attachments.py` (`_open_attachment`, `normalise_extensions`),
  `src/btx_lib_mail/_compose.py` (`message_for` / `_JoinedMessage`),
  `src/btx_lib_mail/lib_mail.py` (`send`, `_deliver_to_any_host` rewind),
  `src/btx_lib_mail/_transport.py` (`_session_deadline`),
  `src/btx_lib_mail/cli.py` (`_Sources`, `_json_mode`, `_json_exception_handler`).
- `tests/test_attachment_integrity.py`, `tests/test_cli_send.py`, `tests/test_transfer_memory.py`,
  `tests/test_deadline.py`.
- `.private/review-2026-10-02.md` (the sweep-1 findings).

## How to verify

- `env -u VIRTUAL_ENV make test` ends `{"result":"pass"}`.
- `git log --oneline origin/master..master` is empty after the push. Every workflow for that sha
  ends green on all three OSes.
- `diff skills/python-send-mail/SKILL.md ../../KI/bitranox-skills/plugins/bitranox/skills/coding-python-send-mail/SKILL.md`
  differs only in the `name:` line and the install blockquote.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
