# STALE - read 2026-10-02, work continued

Read `OPEN-WORK.md` first. Open: rank 20, 21, 22 and 30 (USER), and rank 50 (FOUND).

## In flight

Rank 21, code-quality review sweep 2. Five reviewers ran against HEAD 2f53d41, and their reports
are stored verbatim in `.private/review-2026-10-02-sweep2.md` (gitignored). The `# Synthesis`
section at its end holds:
- the scorecard (6.9 -> 7.8);
- 8 findings in presentation order;
- the "counted and left" census results;
- the facts the main session verified itself, including the PyPI sdist download.

No finding has been presented to the owner or fixed yet.

## Committed, or not

- master is pushed together with this file. The push includes:
  - another session's `.gitignore` fix (7de496a). The owner had its Claude co-author trailer
    removed first.
  - the docstring link fix (101cc3b).
- `.private/` and `EXECUTION-USER-REVIEW.md` are gitignored. This session's owner decisions are
  logged in the latter.
- The bitranox-skills worktree for rank 22 is still prepared and uncommitted (see `OPEN-WORK.md`).

## Decided, and why

- Owner: write the handover only after all five reports were in, so no reviewer work is lost.
- Owner: drop the `Co-Authored-By: Claude` line from the foreign commit.
- Finding order follows the review skill: SEVERE first, then MEDIUM, then MINOR.
- The two surviving mutations (issues 3 and 4) are MEDIUM, per the skill's "unenforced invariant"
  rule, not the reviewer's MINOR.
- Error Handling is scored 8, not the reviewer's 9. That reviewer audited only the package's own
  `raise` sites. A probe showed a stdlib `ValueError` escaping `send()` (issue 2).
- Issue 7 (docstring style) is ASK-FIRST. The tree CLAUDE.md wants Google style, while
  `self_documenting_template.md` prescribes the house style the package uses. Two owner
  instructions conflict.

## Decided against, and why

- Rewriting the three already-pushed semdex commits that carry the trailer. That needs a force push
  in a repo another live session owns, so it was left to that owner.

## Still open, untouched

- Rank 20 (template ConfMail rollout), rank 30 (4.0.0 release, owner hold), rank 50 (sibling
  `__main__` exit codes) and rank 22 (skill twin): see `OPEN-WORK.md`.

## Lessons for the next nap

- When joining a state-changing step after a script in one Bash call, use `&&`, never a newline. A
  failed script was followed by an append of the unfinished draft into the review record.
- When a PostToolUse formatter hook rewrites a file you will later patch by exact text, re-read it
  or match by line prefix. Table padding changed, and the exact-text replace failed.
- tooling: the review skill's "Error contract" row let a reviewer census only the package's own
  `raise` sites; queued in `contrib_queue`.

## Exact next action

Present Issue 1 from `.private/review-2026-10-02-sweep2.md` `# Synthesis`. Use the review skill's
format (`## Issue 1: ...`, Severity, Affected files, Description, Suggested fix), then ask: "Do you
want to implement this fix? Or skip it? If skipping, what's the reason?" Invoke
`/bitranox:process-review-enhance-code-quality` first, to load its Step 5-7 rules. Rank 21 goes
ahead of rank 20 because it is mid-flight and the owner chose to continue it.

## Files that matter

- `.private/review-2026-10-02-sweep2.md`: the reports and the synthesis.
- `pyproject.toml`: issue 1 (no `[tool.hatch.build.targets.sdist]`).
- `src/btx_lib_mail/_compose.py:266`, `src/btx_lib_mail/_attachments.py`: issue 2.
- `src/btx_lib_mail/_attachments.py:_open_attachment` and `tests/test_attachment_integrity.py`:
  issue 3.
- `src/btx_lib_mail/_transport.py:_login_plain_utf8` and `tests/test_streaming.py`: issue 4.
- `src/btx_lib_mail/cli.py`: issue 5.
- `skills/python-send-mail/SKILL.md`: issue 6.

## How to verify

- `env -u VIRTUAL_ENV make test` ends with `{"result":"pass",...}`.
- `gh run list --commit $(git rev-parse --verify -q HEAD) --json name,conclusion` shows CI and
  CodeQL succeeding.
- `grep -c "^# Reviewer:" .private/review-2026-10-02-sweep2.md` prints 5.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
