# Handover - 2026-10-13 17:30, bounded EHLO-name lookup merged locally, release not started

Read `OPEN-WORK.md` first. Rank 10 is now "ship the bounded EHLO-name lookup".

## In flight

- Nothing running. The fix for the old rank 10 (the delivery deadline did not cover the EHLO-name
  lookup) is done, reviewed three times and merged into local `master` at `b2fe7aa`.
- NOT released, NOT pushed: `master` is 4 commits ahead of `origin/master` (v4.2.0 +
  b700973, f081348, 6a0ddaa, b2fe7aa). CHANGELOG has it under `[Unreleased]`.
- The skill twin is committed in bitranox-skills as `62335be3` (SKILL.md, a `.skillwriter`
  checklist, plugin 8.19.4, CHANGELOG), also NOT pushed. Push it only after PyPI serves the
  btx_lib_mail release.

## Committed, or not

- Both repos: everything committed, nothing pushed. This handover commit adds `handover.md` and
  `OPEN-WORK.md` on btx_lib_mail `master`.
- Gitignored, by design: `EXECUTION-USER-REVIEW.md` holds today's owner decisions verbatim and my
  autonomous choices (the 0.5 share, wait before connect, the accepted items, version 4.3.0 proposed).

## Decided, and why

- Owner: "Bound it, fallback". With a deadline the lookup runs on a daemon thread; the delivery waits
  for it at most half the deadline's time left, BEFORE connecting, then announces its own socket
  address as an RFC 5321 literal; later deliveries use the name. Without a deadline: waited for
  before connecting, as before.
- Wait before connect (review M3): a relay with a short command timeout drops a connection left
  idle after its greeting.
- Fork: `os.register_at_fork` resets every `_LocalHostnameLookup` in a child (fresh lock, keeps only
  a name already found), registered only where fork exists.
- Placeholder EHLO name is `""`, so broken wiring sends a bare EHLO servers refuse.
- Accepted in CLAUDE.md: one exception object re-raised by concurrent waiters; `importlib.reload`
  of `_transport` orphans earlier lookups.

## Decided against, and why

- Document-only: the owner chose to bound the lookup.
- Failing the delivery when the lookup overruns: the owner's option said nothing that works today
  may fail.
- A pid check for fork safety: it cannot see a lock or an event a parent thread held at the fork.

## Still open, untouched

- Rank 10: ship it (owner's go needed for the public push and the PyPI publish) - see `OPEN-WORK.md`.
- Rank 90: ask whether to roll the uv cooldown install docs out to the templates.
- Rank 95: the Windows STARTTLS deadline test overran once.

## Lessons for the next nap

- When a review says the wait for a slow dependency moved after a connection opened, put the
  bounded wait BEFORE the connect: an idle connection after a greeting is a relay timeout waiting
  to happen, and a deadline does not prevent it.
- When a test's expected stand-in value equals the code's placeholder (loopback literal vs
  `[127.0.0.1]` placeholder), the test cannot see broken wiring: make the placeholder a value no
  correct outcome can have.
- When a test must fork while a FAILED background attempt is still registered, make the attempt
  fail only after its waiter stopped waiting: a waiter that collects the error forgets the attempt,
  so the mutation under test survives (measured on the first try).
- When a blocked Bash command combined `git add` with `git commit`, the add never ran and the gate
  judged the old index: stage in its own command (recurrence of feedback-repo-gate-pre-evaluates).
- When a pytest marker like `os_posix` is used in this repo, it selects nothing: guard the test body
  with `sys.platform` (a reviewer caught a fork test that would fail every Windows cell).
- tooling: the memory fact reference-btx-lib-mail-s-delivery-deadline-does-not-cover-the-ehlo-name-lookup
  becomes wrong once the release ships; rewrite it then (it is part of rank 10's work).
- (carried) When a subagent reports a skill description as unchanged, measure it with `len()`.
- (carried) When the auto-mode classifier refuses `git filter-branch` over an unpushed range, ask the
  owner once with the exact scope.
- (carried) When the auto-mode classifier refuses a scripted deletion of tracked backlog lines, use
  the Edit tool with the exact lines.
- (carried) When a peer session says your commit is not on origin, run `git ls-remote` first.
- (carried) When a tool repo's mirrored skill changed, commit the twin locally BEFORE the tool repo's
  release push; push the twin after PyPI serves the release.
- (carried) When a GREEN retrieval run answers by inference, re-ask for a direct quote.
- (carried) tooling: after `make clean-all` the main checkout has no `.venv`, so an old-vs-new probe
  printed nothing with stderr hidden; run old source through another checkout's interpreter.
- (carried) When you brief a background subagent to run a long gate, write "run it in the
  FOREGROUND" in the first brief.
- (carried) When applying the cpXY-wheel rule, check the CI runners first.
- (carried) When a subagent needs a scratch copy, require a dir it creates with `mktemp -d`.
- (carried) When a release must be tagged while an uncommitted backlog line dirties the tree, copy
  the file aside, restore the committed copy, `make release`, then put the copy back.
- (carried) When `uv sync` in a fresh worktree picks Python 3.15 and a compiled dev dependency has
  no cp315 wheel, pass `--python 3.14`.
- (carried) When a test spawns the btx_lib_mail CLI as a fresh process, pass an explicit EHLO name.
- (carried) Proposed, awaiting the owner: rewrite the fact
  reference-aiosmtpd-controller-start-flakes-on-macos-ci-retry-fresh-port-then-skip (cause is the
  ~30 s `getfqdn` on macOS runners).
- (carried) When a mirrored skill changes on both sides, expect repo-gate's commit gates to deadlock;
  a commit matching the other side's uncommitted text passes.
- (carried) When a worktree-isolated session runs Bash, keep each command plain.
- (carried) When a counterexample goes into a question to the user, check it is refused for the
  reason the question claims.
- (carried) tooling: the harness refuses subagent report files named `*-report.md` in some runs.
- (carried) tooling: the EnterWorktree guard refuses any Bash command whose text contains `git`.
- (carried) When `git filter-branch --msg-filter` rewrites an unpushed range, delete the backup
  branch and `refs/original` afterwards.
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

Rank 10: ask the owner ONE question - release btx_lib_mail 4.3.0 now (push `master`, `make release`
after bumping, watch CI per the ci_wait rule, then push bitranox-skills `62335be3` once PyPI serves
4.3.0, then rewrite the stale memory fact) versus hold. Check `git log origin/master..master` and
the bitranox-skills `git log origin/master..master` first; other sessions push there too.

## Files that matter

- `src/btx_lib_mail/_transport.py` - `_LocalHostnameLookup`, `_LOOKUPS`, `_reset_lookups_in_child`,
  `_EHLO_NAME_SHARE_OF_DEADLINE`, `SmtplibTransport.deliver` / `_ehlo_name_in_time`
- `tests/test_streaming.py` - the EHLO section (`_HeldLookup` and after, fork tests)
- `CHANGELOG.md` `[Unreleased]`; `CLAUDE.md` Key Architecture "EHLO name" and the accepted list
- `skills/python-send-mail/SKILL.md` "The EHLO name" (twin: bitranox-skills
  `plugins/bitranox/skills/coding-python-send-mail/`)

## How to verify

- `make test` passes (1190 passed at b2fe7aa).
- `.venv/bin/pyright --pythonplatform Windows src tests` reports 0 errors.
- `git log --oneline origin/master..master` lists the 4 unpushed commits plus this handover commit.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
