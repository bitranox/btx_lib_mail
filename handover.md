# Handover - btx_lib_mail rank 20 (CLI template onto ConfMail), 2026-10-01 12:45

## In flight

Rank 20 is designed and planned; NO implementation code is written yet. The work happens in the
CLI template, not in this repo:

- Template clone: `../../apps/bitranox_template_py_cli`, master
  = origin/master at `9dae7b8`, clean, CI green (CI and CodeQL, all 15 cells).
- Design (approved by the owner, both sections): `.private/plans/2026-10-01-confmail-move-design.md`
  in the template clone.
- Implementation plan (7 tasks, self-reviewed): `.private/plans/2026-10-01-confmail-move-template-plan.md`
  in the template clone. The owner chose to run it in a SEPARATE fresh session (this one).
- Owner decisions 1-7 with reasons: `EXECUTION-USER-REVIEW.md` in the template clone (gitignored).
- `.private/` in the template clone is untracked on purpose: excluded per clone via
  `.git/info/exclude` (same as btx_lib_mail), because the owner keeps plan docs out of public
  history.

## Committed, or not

- btx_lib_mail: `7568daa`, `e0730c8` (OPEN-WORK edits) plus this handover are committed locally,
  NOT pushed (a push starts full CI; they ride with the next real change).
- Template: everything pushed (`eb38a84` wiring fixes merged, `676b5b8` colour fix, `9dae7b8`
  width + 3.10 fix). The `wiring-fixes` worktree and its branch are removed.
- Untracked by design: the template's `.private/plans/*` and `EXECUTION-USER-REVIEW.md`.

## Decided, and why

- Owner decisions 1-7 (template `EXECUTION-USER-REVIEW.md`): file/env keys keep their names;
  unknown `[email]` keys refused (exit 78); expose `starttls_verify` + `local_hostname`, not
  `allow_empty_blocklists`; drop `_sanitize_exception_message`; WHOLE template delta per app (owner
  overrode my email-slice recommendation); one batch approval for the 19 app pushes, releases
  separate; Python uses ConfMail's names (`smtphosts`, `smtp_use_starttls`, `smtp_timeout`), no
  aliases.
- lib_layered_config stays the only config reader; `load_email_config_from_dict` only translates
  the merged `[email]` section (the owner asked; the design now says so explicitly).
- Derived from decision 2 while planning: a comma-separated string for an attachment list is
  refused (was silently ignored); empty `allowed_*` AND `blocked_*` lists are dropped (ConfMail
  reads `[]` allowed as "allow nothing").
- The template's tests got an autouse fixture (`deterministic_cli_output`) pinning rich-click's
  colour and width globals: CI colours output (GITHUB_ACTIONS) and Windows renders 79 columns.
  It is template-owned, so the whole-delta rollout carries it to every app.

## Decided against, and why

- No per-test env change for colour: rich-click reads FORCE_COLOR/PY_COLORS/GITHUB_ACTIONS and the
  width once at import into module globals; only resetting the globals works.
- No alias layer for the old Python names (decision 7).
- The rollout plan is NOT written yet on purpose: its steps depend on the finished template.

## Still open, untouched

See OPEN-WORK.md: ranks 20 (USER, in progress as above), 30, 40, 85.

## Lessons for the next nap

- When CI fails on every cell, read EVERY failing cell's log before fixing: I read one Ubuntu
  log, pushed, and two more defects (Windows width, Python 3.10) surfaced on the next run.
- When a test asserts plain text on rich-click output, know rich-click freezes colour and width
  into module globals at import (FORCE_TERMINAL, WIDTH, MAX_WIDTH); a per-test env change does
  nothing, reset the globals.
- When a pydantic test spells an annotation via `isinstance(x, type)`, know `list[str]` passes
  that check on Python 3.10 only; check `typing.get_args` first.
- When an in-memory/test adapter re-parses config itself, every CLI test skips the production
  translation; make the testing composition call the real pure function.
- When ConfMail receives `[]` for `attachment_allowed_extensions`, it means "allow nothing", not
  "no allowlist"; a template that writes `[]` for "defaults" must drop it.
- The previous handover's 11 lessons (aiosmtpd macOS, getfqdn, pydantic validate_assignment
  rollback, repo-gate mirror drift, and others) may not have been napped: they are at
  `git show 973fe6c:handover.md`.

## Exact next action

Rank 20 is the top USER item. In the template clone, execute the plan with
bitranox:process-plan-executor (or subagent-driven-development), starting at Task 0:

```bash
cd ../../apps/bitranox_template_py_cli && git worktree add .claude/worktrees/confmail -b feat/confmail-email-config master
```

Read the design and the plan first; Task 7 needs the owner's explicit yes before the public push.

## Files that matter

- Template: `src/bitranox_template_py_cli/adapters/email/config.py` (rewritten by Task 2),
  `adapters/email/transport.py`, `adapters/cli/commands/email/_common.py`,
  `adapters/memory/email.py`, `composition/__init__.py`, `adapters/config/defaultconfig.d/50-mail.toml`,
  `tests/conftest.py` (`deterministic_cli_output`), `tests/test_mail.py`,
  `tests/test_email_password_secrecy.py`, `tests/test_cli_email_config_errors.py`.
- btx_lib_mail: `src/btx_lib_mail/lib_mail.py` (`ConfMail`, `send(config=)`), read-only for rank 20.

## How to verify

- Template baseline: `cd ../../apps/bitranox_template_py_cli && env -u VIRTUAL_ENV make test` (expect `{"result":"pass"}`).
- CI state: `gh run list --repo bitranox/bitranox_template_py_cli --commit 9dae7b8c514aeaefb71936ed9d456af2ac7de92e --json name,conclusion`.
- Plan files exist: `ls ../../apps/bitranox_template_py_cli/.private/plans/`.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
