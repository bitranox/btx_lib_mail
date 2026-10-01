# Handover - btx_lib_mail, 2026-10-01 16:45 (2.0.0 shipped; rank 20 next)

Read `OPEN-WORK.md` first. It holds exactly one open item, rank 20.

## In flight

Nothing is part-done. Rank 20 (CLI template onto ConfMail, then the 19-app rollout) is designed
and planned, with no implementation code yet:

- Template clone: `../../apps/bitranox_template_py_cli`, master = origin/master at `9dae7b8`,
  clean.
- Design: `.private/plans/2026-10-01-confmail-move-design.md` in the template clone.
- Plan: `.private/plans/2026-10-01-confmail-move-template-plan.md` in the template clone.
  It has 8 tasks, numbered 0-7.
- Both plan files are untracked by design (`.git/info/exclude`).
- Owner decisions 1-7: in the template's `EXECUTION-USER-REVIEW.md` (gitignored).
- New since the plan was written: the template raises its floors to `btx_lib_mail>=2.0.0` and
  `lib_layered_config>=6.1.0`, both on PyPI since 2026-10-01. 2.0.0 refuses unknown `ConfMail`
  keys, which matches decision 2 (unknown `[email]` keys refused). Fold the floor raise into the
  plan's dependency step. The plan itself does not mention it yet.

## Committed, or not

- btx_lib_mail: released and pushed through `a47f8b1` (tag `v2.0.0`).
- btx_lib_mail: two local commits are NOT pushed, `7cf1eaa` and `2231233` (backlog only), plus
  this handover's commit. They ride with the next real change; a push alone starts full CI.
- bitranox-skills: `6a755d60` (coding-python-send-mail synced to 2.0.0, plugin 7.30.7) pushed,
  CI green.
- Local toolbox (not a repo): new `~/.claude/skills/toolbox/tools/backlogcheck.py` plus its tests
  and an index row.

## Decided, and why

- Rank 85: `ConfMail` refuses unknown keys (`extra="forbid"`), shipped as 2.0.0 (major, honest
  semver). All 24 construction sites in the tree pass real field names only, so none broke.
- Rank 30: it was stale, because lib_layered_config 6.0.0 already keeps leading zeros. Rank 40
  (display Console) shipped in lib_layered_config 6.1.0. The owner said open lib items go to the
  lib_layered_config session. It now tracks the residual as its rank 71: a secret spelled
  `null`/`none` silently becomes no password.
- Status-hygiene misses reached recurrence 3. Escalated to the owner-approved jig `backlogcheck`
  instead of a fourth rewording.

## Decided against, and why

- No release-time alias or warning mode for unknown keys. The owner chose refuse + 2.0.0 over
  warn-once and over a 1.9.0 minor.
- The private repo name was redacted from two unpushed btx_lib_mail commits before the push. The
  repo is public, and only the unpushed range could still be rewritten.

## Still open, untouched

- See OPEN-WORK.md rank 20.

## Lessons for the next nap

- When a peer pushes to a shared repo under your unpushed commit and the main checkout holds
  someone else's staged files, cherry-pick onto origin in a temp worktree and push from there.
  Then realign the main branch with a compare-and-swap `git update-ref` plus `git checkout HEAD -- <only the differing files>`.
- When uv says "there is no version of X==N" seconds after a publish even with `--no-cache`, while
  the PyPI simple index lists the files, retry a minute later before suspecting the release (CDN
  lag; it resolved on the next try).
- When a skill documents a library behaviour change, version-qualify it ("from 2.0.0 ...; before
  2.0.0 ..."), so the mirror is correct whether or not the release is out yet.
- When a test asserts plain text on rich-click output, know that rich-click freezes colour and
  width into module globals at import (FORCE_TERMINAL, WIDTH, MAX_WIDTH). Reset the globals; a
  per-test env change does nothing.
- When a pydantic test checks an annotation via `isinstance(x, type)`, know that `list[str]`
  passes on Python 3.10 only. Check `typing.get_args` first.
- When an in-memory/test adapter re-parses config itself, every CLI test skips the production
  translation. Make the testing composition call the real pure function.
- When ConfMail receives `[]` for `attachment_allowed_extensions`, it means "allow nothing", not
  "no allowlist". A template that writes `[]` for "defaults" must drop it.
- When CI fails on every cell, read every failing cell's log before fixing, not one.
- tooling: `bmk testintegration` exits 2 (pytest exit 5) in a repo with no integration-marked
  tests (queued in contrib_queue).
- The lessons of an older handover may not have been napped either: `git show 973fe6c:handover.md`.

## Exact next action

Rank 20 is the only item. In the template clone, execute the plan with
bitranox:process-plan-executor (or subagent-driven-development), starting at Task 0:

```bash
cd ../../apps/bitranox_template_py_cli && git worktree add .claude/worktrees/confmail -b feat/confmail-email-config master
```

Read the design and the plan first. Add the floor raises (btx_lib_mail>=2.0.0,
lib_layered_config>=6.1.0) to the plan's dependency step. Task 7 (the public push) needs the
owner's explicit yes.

## Files that matter

- Template: `src/bitranox_template_py_cli/adapters/email/config.py`, `adapters/email/transport.py`,
  `adapters/cli/commands/email/_common.py`, `adapters/memory/email.py`, `composition/__init__.py`,
  `adapters/config/defaultconfig.d/50-mail.toml`, `tests/conftest.py`, `tests/test_mail.py`,
  `pyproject.toml`.
- btx_lib_mail: `src/btx_lib_mail/lib_mail.py` (`ConfMail`, `send(config=)`), read-only for rank 20.

## How to verify

- Released: `curl -s https://pypi.org/pypi/btx_lib_mail/json | python3 -c "import json,sys;print(json.load(sys.stdin)['info']['version'])"` prints 2.0.0.
- Template baseline: `cd ../../apps/bitranox_template_py_cli && env -u VIRTUAL_ENV make test`
  (expect `{"result":"pass"}`).
- Backlog still current: `uv run ~/.claude/skills/toolbox/tools/backlogcheck.py --file OPEN-WORK.md`.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
