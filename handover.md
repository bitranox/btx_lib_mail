# STALE - read 2026-10-06, work continued

Read `OPEN-WORK.md` first. Ranks 30 (release) and 22 (skill) are closed; rank 40 (CLI template
rollout) is the one open item and its deferral condition is now met.

## In flight

Nothing part-done. btx_lib_mail 4.0.0 is on PyPI (tag v4.0.0 on 1555c53; CI, CodeQL and Release
green). The skill twin `coding-python-send-mail` is on bitranox-skills master as 8.0.3
(c30d38a6, its CI green).

## Committed, or not

- a6c234e (backlog: close ranks 30 and 22) and this handover are committed locally, NOT pushed;
  they ride with the next push.
- Uncommitted by design: `EXECUTION-USER-REVIEW.md` (gitignored; this session's decisions are
  logged under 2026-10-06 "4.0.0 release"), `.private/`.
- `make clean-all` ran after the release: every `.venv*` is gone and rebuilds on the next `make`.

## Decided, and why

- Owner: tfbpr fix mode ask-big; the audited skill shipped IN 4.0.0, the twin pushed only after
  PyPI served 4.0.0.
- The btx_lib_mail side went out through `make push` because repo-gate's two mirror gates
  deadlock a change made on both sides at once (each reads the other at its published text); the
  twin commit then passed its gate. Deadlock queued in contrib_queue.
- The macOS-only CI failure was the CLI subprocess test's default EHLO lookup (35-70 s reverse
  DNS on macOS runners); the test passes `--local-hostname` (1555c53). Test-only, no version bump.
- `/tmp` ran out of inodes (57,797 leaked `claude-ci-watch-*.json` from a hook test suite); I
  deleted my own stale ones with no real-session entry. Leak queued in contrib_queue.

## Decided against, and why

- No push of the backlog/handover commit on its own: it would run the full CI matrix for two
  tracked text files.
- Did not fast-forward the shared main bitranox-skills checkout (215 behind, with another
  session's staged `TODO-JEV.md`): not needed once the twin was pushed.

## Still open, untouched

- Rank 40 (template rollout to 19 apps plus the private template): see `OPEN-WORK.md`. Its fix
  lands in the template and the derived apps, not here, so it is a candidate to move to the
  template repo's backlog.

## Lessons for the next nap

- When ENOSPC or pytest "could not create numbered dir" appears with gigabytes free, check
  `df -i` first (captured this session as feedback-enospc-with-free-gigabytes-means-inodes-check-df-i-first).
- When a test spawns the btx_lib_mail CLI (or any SMTP client) as a fresh process, pass an
  explicit EHLO name: a fresh process's reverse DNS lookup takes 35-70 s on macOS CI runners.
- Proposed, awaiting the owner: rewrite the btx_lib_mail fact
  reference-aiosmtpd-controller-start-flakes-on-macos-ci-retry-fresh-port-then-skip; its
  "runner flake" diagnosis is wrong, the cause is the ~30 s `getfqdn` on macOS runners
  (`server_hostname` / `local_hostname` fix it).
- When a mirrored skill changes on both sides, expect repo-gate's commit gates to deadlock; the
  tool-repo side can go out through its release push, then the marketplace side commits.
- When `git filter-branch --msg-filter` rewrites an unpushed range, delete the backup branch and
  `refs/original` afterwards: both keep the old messages reachable.
- tooling: a `grep -v '^\['` filter on probe output hid a line that legitimately began with `[]`.
- (carried, not yet confirmed napped) When a report must say what a call acted on, recompute it
  with the call's own functions, never by matching its logged output.
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

Rank 40: decide with the owner whether the item moves to the bitranox_template_py_cli backlog
(its code lands there and in the derived apps), then write the rollout plan with
bitranox:process-plan-writing-plans in a fresh session, starting from the template: raise its
floor to `btx_lib_mail>=4.0.0` and drop `EmailConfig._check_hosts` (adapters/email/config.py).

## Files that matter

- `OPEN-WORK.md` (rank 40)
- `EXECUTION-USER-REVIEW.md` (gitignored; the 2026-10-06 release decisions)
- `tests/test_cli_send.py` (the `--local-hostname` fix for macOS CI)

## How to verify

- `curl -s https://pypi.org/pypi/btx_lib_mail/json` reports `info.version` 4.0.0.
- `git ls-remote --tags origin v4.0.0` lists the tag.
- `python3 <bitranox-skills checkout>/plugins/bitranox/hooks/repo-gate.py --mirror-of .`
  prints `in sync` once the main bitranox-skills checkout is fetched past c30d38a6.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
