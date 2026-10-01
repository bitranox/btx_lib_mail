# Handover - btx_lib_mail, 2026-10-01 18:30 (rank 20 template part landed; rollout plan next)

Read `OPEN-WORK.md` first: rank 20 (USER) and rank 30 (FOUND) are open.

## In flight

Nothing is part-done. Rank 20's template half is finished and pushed: bitranox_template_py_cli
`master` = `e5bee77`, CI and CodeQL green on all 15 cells (3.10-3.14 x Linux/macOS/Windows). The
worktree and branch `feat/confmail-email-config` are removed. The rollout to the derived apps has
not started; no rollout plan exists yet.

## Committed, or not

- btx_lib_mail: 7 local commits NOT pushed (backlog/handover only, `origin/master..4d3a998`) plus this
  handover's commit. They ride with the next real change (a push alone starts full CI). Before any
  push, scan the whole unpushed range for private names.
- Template clone (`../../apps/bitranox_template_py_cli`): clean, master = origin/master.
  Untracked by design: `.private/plans/` (design, plan with amendments A1-A17 and the review
  record, `tools/rename_email_fields.py` + its test). Gitignored: `EXECUTION-USER-REVIEW.md`
  (owner decisions 1-7, this session's autonomous decisions).

## Decided, and why

- Every deviation from the template plan, and the opus review's findings with verdicts, are in the
  plan file's Amendments and Review sections; autonomous calls are in the template's
  `EXECUTION-USER-REVIEW.md`. Do not re-derive them from the diff.
- From Python, `EmailConfig` follows ConfMail only for the attachment settings (empty allowed list
  = allow nothing, empty blocked set needs the opt-in, size 0 refused); blank credentials/sender,
  a lone recipient string and an all-digit user name keep the old reading in the model itself.
  Reason: design says inherit ConfMail; the old lenient text readings were kept because dropping
  them made a blank user name attempt a login.
- `ConfMail` does not validate host syntax, so the template's `EmailConfig` runs
  `validate_smtp_host`; the library fix is rank 30.

## Decided against, and why

- Review finding M2 (show which host index failed): declined, btx_lib_mail scrubs hosts as a
  credential field on purpose.
- Did not push btx_lib_mail's backlog-only commits on their own (full CI for no code).

## Still open, untouched

- Rank 30 (FOUND): ConfMail accepts malformed hosts - see OPEN-WORK.md.
- Not done this session: the SessionStart nudges (dream due, 4 self-improve near-miss
  candidates, 4 pending upstream contributions).

## Lessons for the next nap

- When an error renderer maps a location through a field-to-file-key rename, map only locations
  that are fields: an unknown key's location is already what the user wrote, and mapping it named
  a different, valid key (`smtp_timeout` -> `email.timeout: unknown key`).
- When a library drops `ctx` from errors on credential fields (btx_lib_mail SecretSafeModel),
  pydantic's `Value error, ` prefix stays on `msg`; strip it from `msg` as well as reading `ctx`.
- When subclassing a library model to inherit its validation, diff the Python-caller semantics
  field by field (blank, lone string, int, 0, empty list) against the old model, not only the
  config-file path: the file path was covered by tests and the Python path silently changed.
- When a security test refuses for the right outcome, assert WHICH check refused (violation type
  and reason): an empty allowlist passed through refused the same file for the wrong reason and
  let a mutation arm survive.
- When a test creates files under pytest's tmp_path while the code blocks `/var`, expect macOS CI
  to fail (tmp_path is under /private/var there); reproduce on Linux with `--basetemp` under /var.
- When a CHANGELOG or plan describes a library's error text, read the raise site first: the plan's
  "a rejected login shows the server's 535 reply" was false.
- When running pyright by hand in a worktree, pass `--pythonpath .venv/bin/python`, or every
  import is unresolved (1304 phantom errors).
- When backgrounding a gate (ci_wait, make test), run it alone with nothing after it, so the
  task's exit code is the gate's.
- The previous handover's lessons were not napped this session either: `git show fe5e8d1:handover.md`.

## Exact next action

Rank 20 is the top item. In a fresh session, write the rollout plan with
bitranox:process-plan-writing-plans from Section 2 of
`../../apps/bitranox_template_py_cli/.private/plans/2026-10-01-confmail-move-design.md`.
Start by re-enumerating the targets (never reuse the stored list):

```bash
find <softdev root> -name config.py -path '*adapters/email/*' -not -path '*/.venv*' -not -path '*/.claude/worktrees/*'
```

The template delta to carry is `44fa65e..e5bee77` on top of whatever template base each app
started from (design: infer the base per app; owner decision 5: whole template delta per app;
decision 6: one approval table before any push).

## Files that matter

- `../../apps/bitranox_template_py_cli/.private/plans/2026-10-01-confmail-move-design.md` (Section 2)
- `../../apps/bitranox_template_py_cli/.private/plans/2026-10-01-confmail-move-template-plan.md`
- `../../apps/bitranox_template_py_cli/.private/plans/tools/rename_email_fields.py`
- `../../apps/bitranox_template_py_cli/src/bitranox_template_py_cli/adapters/email/config.py`
- `OPEN-WORK.md`

## How to verify

- Template CI: `gh run list --repo bitranox/bitranox_template_py_cli --commit e5bee77d46ff5a92dc2d534ffca9546b788467cc --json workflowName,conclusion`
  (CI and CodeQL `success`).
- Template gate: `cd ../../apps/bitranox_template_py_cli && env -u VIRTUAL_ENV make test`.
- Backlog current: `uv run ~/.claude/skills/toolbox/tools/backlogcheck.py --file OPEN-WORK.md`.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
