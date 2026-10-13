# Handover - 2026-10-13, SMTPUTF8 ready to implement

Read `OPEN-WORK.md` first. The top open item is rank 8 (SMTPUTF8, the owner's choice); its design and
implementation plan are written and committed on a branch, nothing of the code is started.

## In flight

- Rank 8 SMTPUTF8: design `docs/plans/2026-10-13-smtputf8-design.md` (on master, b0a58d7) and plan
  `docs/plans/2026-10-13-smtputf8.md` (only on branch `smtputf8`, 18e0b53). The branch has a worktree
  at `.claude/worktrees/smtputf8` with a Python 3.14 `.venv` already synced. No plan task started.
- 4.1.0 (ConfMail `coerce_numbers_to_str`) is released and done: PyPI, tag v4.1.0, CI/Release green,
  checked against the template's EmailConfig.

## Committed, or not

- master: 68c2fec (backlog: Windows deadline flake) and b0a58d7 (design) are committed locally, NOT
  pushed. This handover and the rank-8 backlog line are committed with them (see the last commit).
- Branch `smtputf8`: 18e0b53 (plan), unpushed, based on b0a58d7.
- Uncommitted by design: `EXECUTION-USER-REVIEW.md` (gitignored) holds every owner answer of the
  SMTPUTF8 design (Q1 A, Q2 A, Q3 A, sections 1-3, the two documentation requirements) and the 4.1.0
  release decisions.
- `make clean-all` ran after 4.1.0: the main checkout has no `.venv`.

## Decided, and why

- SMTPUTF8 (owner, 2026-10-12/13): non-ASCII local parts AND domains over SMTPUTF8, no punycode; a
  relay without SMTPUTF8 is a failed host for that recipient (next host, `DeliveryError` last); NFC
  before validating and sending; every new function fully documented (doctests); README and docs in
  the same change.
- Found while planning, not in the design: `smtplib.SMTPNotSupportedError` is an `OSError`, so
  `_HostOrder.note_failure` would demote a relay without SMTPUTF8. The plan raises a subclass
  `SMTPUTF8NotSupportedError` and adds it to `_REPLIES_ABOUT_THE_MESSAGE`; plan Task 6 corrects the
  design doc to match.
- The non-ASCII character rule is `str.isprintable()` (measured: refuses controls, every bidi mark,
  ZWJ, NBSP, lone surrogates, unassigned), not a shared copy of the attachment bidi set.
- Python 3.15 needs `rtoml>=0.14.0` (first release with cp315 wheels, past the 1-day cooldown); plan
  Task 5.
- Windows 3.12 CI flake on 4.1.0 (rank 95): the job was re-run green, the 2.0 s bound NOT widened.

## Decided against, and why

- No push of the backlog/design commits on their own: a full CI matrix for text files.
- Running the plan in the old session: it was past 400k tokens of context.

## Still open, untouched

- Rank 10: the delivery deadline does not cover the EHLO-name lookup - see `OPEN-WORK.md`.
- Rank 95: Windows STARTTLS deadline test overran once - see `OPEN-WORK.md`.

## Lessons for the next nap

- tooling: the EnterWorktree guard refuses any Bash command whose text contains `git`, even inside
  `digits` in a pytest `-k` (already added to the lsdsk worktree-guard fact this session).
- When a release must be tagged while an uncommitted backlog line dirties the tree, copy the file
  aside, restore the committed copy, `make release`, then put the copy back: a commit would move HEAD
  off the CI-verified sha.
- When `uv sync` in a fresh worktree picks Python 3.15 and a compiled dev dependency has no cp315
  wheel, pass `--python 3.14`.
- (carried) When a test spawns the btx_lib_mail CLI (or any SMTP client) as a fresh process, pass
  an explicit EHLO name: a fresh process's reverse DNS lookup takes 35-70 s on macOS CI runners.
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

Rank 8: `EnterWorktree` with path `.claude/worktrees/smtputf8`, read
`docs/plans/2026-10-13-smtputf8.md`, and execute Task 1 with
bitranox:process-agents-subagent-driven-development (the owner said "yes, handover" to a proposal
that named subagent-driven execution of Task 1 in the next session - my reading). Tasks run in order 1-6; Task 5 declares Python 3.15. After Task 6: merge into master, then
the release follows the tfbpr pipeline (minor bump; the skill twin goes to bitranox-skills after PyPI
serves it).

## Files that matter

- `docs/plans/2026-10-13-smtputf8.md` (branch `smtputf8`) - the plan, complete code per task
- `docs/plans/2026-10-13-smtputf8-design.md` - the agreed design
- `src/btx_lib_mail/_validation.py`, `_compose.py`, `_transport.py`, `lib_mail.py`
- `tests/smtp_test_server.py` (aiosmtpd helpers; `run_server` forwards `enable_SMTPUTF8=`)
- `EXECUTION-USER-REVIEW.md` (gitignored) - the owner's answers, verbatim

## How to verify

- `git -C .claude/worktrees/smtputf8 log --oneline -1` shows 18e0b53 (the plan).
- `curl -s https://pypi.org/pypi/btx-lib-mail/json` reports `info.version` 4.1.0.
- In the worktree, after each task: the task's pytest command, then `make test`.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
