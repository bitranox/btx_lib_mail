# STALE - read 2026-10-13 14:22, work continued

Read `OPEN-WORK.md` first. Rank 8 (SMTPUTF8) and rank 9 (your uv/cooldown install docs) both land in
plan Task 6.

## In flight

- Rank 8 SMTPUTF8 is executing `docs/plans/2026-10-13-smtputf8.md` with
  bitranox:process-agents-subagent-driven-development, in the worktree `.claude/worktrees/smtputf8`
  (branch `smtputf8`). Tasks 1-5 are committed and reviewed clean. Task 6 (documentation) is not
  started; after it come the final whole-branch review (opus) and its triage of the minor findings,
  then the merge into master and the tfbpr release.
- The progress ledger is `.claude/worktrees/smtputf8/.bitranox/sdd/progress.md` (git-excluded). It
  holds the per-task review counts, the Minor findings (a)-(q) for the final review, and the three
  rank-9 user requests word for word. Trust it and `git log` over memory.

## Committed, or not

- Branch `smtputf8` (unpushed): 18e0b53 plan, 5de539f validation, 381dcd6 combining marks, c1908d3
  composition, 8e91e47 transport, 98bed44 NFC sender, a127659 declare Python 3.15. Worktree clean.
- master (unpushed): 68c2fec, b0a58d7, fa567b2, plus this handover and the OPEN-WORK edits.
- Uncommitted by design: `EXECUTION-USER-REVIEW.md` (gitignored; this session's four owner decisions
  merged in at the top), `.bitranox/` in the worktree (excluded via `.git/info/exclude`).

## Decided, and why

- Lengths of non-ASCII addresses are reported in "UTF-8 octets"; ASCII messages are unchanged (owner).
- Combining marks are allowed in IDN domain labels (L*/M*/N*); a label starts with a letter or digit
  and ends with anything but a hyphen, so Thai words ending in a mark pass (owner + my reading).
- Python 3.15 declared although PyYAML (dev-only, via bandit) has no cp315 wheel: CI here is
  GitHub-hosted only and builds it from source; the plan's `--no-build` check was dropped (owner).
- The rank-9 install docs go into Task 6 as their own commit, not in parallel: two subagents must
  never edit one worktree at once.

## Decided against, and why

- Rolling the uv-cooldown install text out to the sibling templates: not asked; ask the owner after
  this repo ships.

## Still open, untouched

- Rank 10: the delivery deadline does not cover the EHLO-name lookup - see `OPEN-WORK.md`.
- Rank 95: Windows STARTTLS deadline test overran once - see `OPEN-WORK.md`.

## Lessons for the next nap

- When you brief a background subagent to run a long gate (make test-all), write "run it in the
  FOREGROUND" in the first brief; this session briefed run_in_background and had to correct it
  (recurrence of feedback-a-background-subagent-is-not-woken-by-its-own-backgrounded-wait).
- When applying the cpXY-wheel rule to a repo, check its CI runners first (`[tool.ci].os`,
  `runs-on`): on GitHub-hosted runners a missing wheel is a source build, not a blocker; a plan STOP
  condition built on it blocked Task 5 needlessly (proposed hook change to
  reference-check-compiled-dependencies-for-cpxy-wheels-before-adding-a-new-python-minor, awaiting go).
- When a subagent needs a scratch copy, require a dir it creates with `mktemp -d`; one wrote into a
  shared scratch dir holding another session's files (no clobber this time).
- When a worktree-isolated session runs Bash, keep each command plain: a shell variable in a path
  position, `$(...)`, or any command line containing `git` inside a compound gets refused.
- When a counterexample goes into a question to the user, check it is refused for the reason the
  question claims (`user@<word>` with no dot fails the two-label rule, not the mark rule).
- tooling: the harness refuses subagent report files named `*-report.md` in some runs (Task 5 had to
  put its report in the reply); earlier tasks wrote the same name fine.
- (carried) tooling: the EnterWorktree guard refuses any Bash command whose text contains `git`, even
  inside `digits` in a pytest `-k`.
- (carried) When a release must be tagged while an uncommitted backlog line dirties the tree, copy the
  file aside, restore the committed copy, `make release`, then put the copy back.
- (carried) When `uv sync` in a fresh worktree picks Python 3.15 and a compiled dev dependency has no
  cp315 wheel, pass `--python 3.14`.
- (carried) When a test spawns the btx_lib_mail CLI (or any SMTP client) as a fresh process, pass an
  explicit EHLO name: a fresh process's reverse DNS lookup takes 35-70 s on macOS CI runners.
- (carried) Proposed, awaiting the owner: rewrite the btx_lib_mail fact
  reference-aiosmtpd-controller-start-flakes-on-macos-ci-retry-fresh-port-then-skip; the cause is the
  ~30 s `getfqdn` on macOS runners (`server_hostname` / `local_hostname` fix it).
- (carried) When a mirrored skill changes on both sides, expect repo-gate's commit gates to deadlock;
  the tool-repo side can go out through its release push, then the marketplace side commits.
- (carried) When `git filter-branch --msg-filter` rewrites an unpushed range, delete the backup branch
  and `refs/original` afterwards.
- (carried) tooling: a `grep -v '^\['` filter on probe output hid a line that began with `[]`.
- (carried) When a report must say what a call acted on, recompute it with the call's own functions.
- (carried) When a CLI reads options before Click parses, locate the subcommand by POSITION.
- (carried) When a doc audit finds the doc faithfully describing a defect, fix the code.
- (carried) When counting needles in JSON-string captured output, `json.loads` first.
- (carried) When ruff S105 fires on a loop variable named `token`, rename the variable.
- (carried) tooling: block-partial-typecheck reads a shell variable in a pyright loop as a path.
- (carried) When a leak check uses the lowest free descriptor, assert EBADF on the recorded one.
- (carried) When a house rule states a hard limit, check the gate's ruff `select` names the rule.
- (carried) When a doc states a closed-stdout exit code, measure a broken pipe and a closed-at-start
  stdout separately.

## Exact next action

Rank 8 + 9: `EnterWorktree` with path `.claude/worktrees/smtputf8`, read
`.bitranox/sdd/progress.md`, invoke bitranox:process-agents-subagent-driven-development and arm its
`plan-execution` receipt, invoke bitranox:meta-skill-writer and run its `start` receipt (the skill
edit needs it), then `python3 <plugin>/skills/process-agents-subagent-driven-development/scripts/task_brief.py docs/plans/2026-10-13-smtputf8.md 6`
and dispatch Task 6 with the rank-9 requests added as a separate commit. The skill part needs a RED
retrieval run on the current SKILL.md first (e.g. "install btx-lib-mail safely", "send to
empfaenger@mueller.de with umlauts") and a `.skillwriter/checklist-<date>-...-mirror.md` in the
bitranox-skills twin dir `plugins/bitranox/skills/coding-python-send-mail/`. Then the final review
over `git merge-base master smtputf8`..HEAD with the ledger's Minor list.

## Files that matter

- `docs/plans/2026-10-13-smtputf8.md` (branch `smtputf8`) - the plan; Task 6 lists every doc file
- `.claude/worktrees/smtputf8/.bitranox/sdd/progress.md` - ledger, minors, rank-9 requests verbatim
- `INSTALL.md` ("Why we recommend uv: supply-chain protection"), `README.md`, `docs/installation.md`
- `skills/python-send-mail/SKILL.md` and its twin
  in the bitranox-skills clone (sibling `KI/bitranox-skills`), `plugins/bitranox/skills/coding-python-send-mail/`
- the sibling `apps/bitranox_template_py_cli/README.md` - "Install uv" model
- `EXECUTION-USER-REVIEW.md` (gitignored) - the owner's answers, verbatim

## How to verify

- `git -C .claude/worktrees/smtputf8 log --oneline -1` shows a127659 (declare Python 3.15).
- In the worktree: `make test` passes; `.venv-3.15/bin/python -m pytest -q --no-cov tests/test_international_addresses.py` passes.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
