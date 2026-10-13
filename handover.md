# Handover - 2026-10-13 18:10, btx_lib_mail 4.3.0 released; only the twin's CI was still running

Read `OPEN-WORK.md` first. Its top item is now rank 90 (one question to the owner).

## In flight

- bitranox-skills `62335be3` (the coding-python-send-mail twin, plugin 8.19.4) is pushed. Its CI
  was still `in_progress` when this was written (a `ci_wait.py --sha 62335be3f005...` waiter).
  Check it first:
  `gh run list --repo bitranox/bitranox-skills --commit 62335be3f005dbae873bcd857a99ceec0e092023 --json workflowName,status,conclusion`
- Nothing else is part-done.

## Committed, or not

- btx_lib_mail: release commit `7a32163`, tag `v4.3.0`, backlog commit `2080033`; all pushed, CI
  and CodeQL green on both commits, the Release workflow green, PyPI serving 4.3.0 (wheel and sdist).
  This handover commit is local and NOT pushed (it would only trigger another CI run).
- `make clean-all` has run: the main checkout has no `.venv`. Run `make test` once before anything
  that needs it.
- Memory fact `reference-btx-lib-mail-s-delivery-deadline-does-not-cover-the-ehlo-name-lookup`
  was rewritten through `factedit.py apply` (new title: "...covers the EHLO-name lookup only from
  4.3.0"). The store's own git commit is the dreamer's job, so it was not committed here.

## Decided, and why

- Owner, this session: "Release 4.3.0 now" (minor, because of the new keyword-only
  `SmtplibTransport(local_hostname_lookup=)`), fix mode "ask-big".
- `make testintegration` exits 5 with 0 tests: no test carries the `integration` marker, so the
  lane is empty by construction. That did not block the release.
- `docs/api.md` gained one sentence documenting `local_hostname_lookup` (it was only in the
  CHANGELOG and module_reference). That was a small fix under ask-big, shipped in `7a32163`.

## Decided against, and why

- Re-running the fork-hook re-review: the owner's 17:46 message asked for it, but it was already
  done. `6a0ddaa`'s review led to `b2fe7aa`, the next review found nothing, and both are on origin.

## Still open, untouched

- Rank 90: ask whether to roll the uv-cooldown install docs out to the templates.
- Rank 95: the Windows STARTTLS deadline test overran once.

## Lessons for the next nap

- When a user message asks for steps that the handover or git already shows as done (a re-review,
  a merge, a release question), check `git merge-base --is-ancestor <sha> origin/master` and say
  it is done, rather than redoing it.
- When pushing bitranox-skills, expect its pre-push hook (`repo-gate.py --pre-push`, the full
  pytest suite, about 5 minutes) to outlast the 120 s Bash timeout: run the push backgrounded or
  with a long timeout.
- When gate.py runs `make testintegration` on a repo with no `integration` marker, it reports
  `[FAIL] (rc=2)`: grep the log for `(exit code: 5)` and the marker count before treating it as red.
- (carried) When a review says the wait for a slow dependency moved after a connection opened,
  put the bounded wait BEFORE the connect.
- (carried) When a test's expected stand-in value equals the code's placeholder, the test cannot
  see broken wiring: make the placeholder a value no correct outcome can have.
- (carried) When a test must fork while a FAILED background attempt is still registered, make the
  attempt fail only after its waiter stopped waiting.
- (carried) When a blocked Bash command combined `git add` with `git commit`, the add never ran:
  stage in its own command.
- (carried) When a pytest marker like `os_posix` is used in this repo, it selects nothing: guard
  the test body with `sys.platform`.
- (carried) When a subagent reports a skill description as unchanged, measure it with `len()`.
- (carried) When the auto-mode classifier refuses `git filter-branch` over an unpushed range, ask
  the owner once with the exact scope.
- (carried) When the auto-mode classifier refuses a scripted deletion of tracked backlog lines,
  use the Edit tool with the exact lines.
- (carried) When a peer session says your commit is not on origin, run `git ls-remote` first.
- (carried) When a tool repo's mirrored skill changed, commit the twin locally BEFORE the tool
  repo's release push; push the twin after PyPI serves the release.
- (carried) When a GREEN retrieval run answers by inference, re-ask for a direct quote.
- (carried) tooling: after `make clean-all` the main checkout has no `.venv`, so an old-vs-new
  probe printed nothing with stderr hidden; run old source through another checkout's interpreter.
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
- (carried) When a mirrored skill changes on both sides, expect repo-gate's commit gates to
  deadlock; a commit matching the other side's uncommitted text passes.
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

1. Confirm the bitranox-skills `62335be3` CI is green (command under "In flight"). If it is red,
   that comes first.
2. Rank 90: ask the owner ONE question, whether to roll the uv / uvx 7-day-cooldown install docs
   out to bitranox_template_py_lib and bitranox_template_py_cli. If yes, move the line to those
   repos' `OPEN-WORK.md` and do the work there.

## Files that matter

- `OPEN-WORK.md` - ranks 90 and 95
- `tests/test_deadline.py` - the rank-95 STARTTLS deadline test
- `CHANGELOG.md` `[4.3.0]`; `docs/api.md` Transport section

## How to verify

- `git ls-remote --tags origin v4.3.0` lists the tag.
- `curl -s https://pypi.org/pypi/btx_lib_mail/json` reports `info.version` 4.3.0.
- `git log --oneline origin/master..master` lists only this handover commit.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
