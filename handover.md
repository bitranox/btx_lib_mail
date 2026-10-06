# Handover - btx_lib_mail, 2026-10-06 (data-architecture pass 1 analysed; fix step next, then 4.0.0)

Read `OPEN-WORK.md` first. Open: ranks 15, 22, 30, 40 (all USER). Rank 21 (code-quality loop) is
CLOSED: severity gate met, re-score 8.7 (record `.private/review-2026-10-06-sweep11.md`).

## In flight

Rank 15: the owner invoked `/bitranox:coding-python-enforce-data-architecture-strict` while the
4.0.0 release (rank 30) was starting. Pass 1, step A (analysis) is DONE: 7 sonnet analysers over all
22 files under `src/btx_lib_mail`, findings vetted by hand against the code. 15 violations in 6
files are in `.data_arch_violations.json` (repo root, gitignored via `.git/info/exclude`; pass=1,
status per file, plus `rejected_pass1` with the reasons). Step B (fix) has NOT started.

## Committed, or not

- All code committed on master; about 110 commits ahead of origin, NOT pushed.
- Gates green at c2f5ca6: `make test`, `make test-all` 3.10-3.14, pyright on Linux/Windows/Darwin
  and 3.10, the Windows suite on the Windows dev box (3.14 1002 passed, 3.10 subset 725 passed).
- Uncommitted on disk, by design: `.data_arch_violations.json` (state file),
  `EXECUTION-USER-REVIEW.md`, `.private/` records.

## Decided, and why

- Pass 1 vetting kept every CLI-output finding (they are real fixed-key dicts and a closed
  string vocabulary) and rejected three classes: `secret_safety._ERROR_CONTEXT_PREFIXES` (keys are
  pydantic's own error types), fixed-arity tuples in `_validation.py` (not a dict rule), and
  `logger.*(extra={...})` literals (the stdlib logging API's own shape).
- The skip-kind vocabulary ("recipient"/"attachment") is produced in `_validation.py:385` and
  `_attachments.py:1218,1276` and consumed in `cli/_output.py` and `cli/_send_command.py:326`:
  one `SkipKind` StrEnum in a LOW layer (import-linter: `_common` is below both) so producer and
  consumer share it. `StrEnum` needs 3.11; the floor is 3.10, so use `class SkipKind(str, Enum)`
  and pass `.value` anywhere it is interpolated (3.11+ formats the member as `SkipKind.X`).
- The JSON wire format is a documented contract (docs/cli.md): the refactor must keep every
  subcommand's `--json` / `--json-bare` output byte-identical, success and failure, including key
  ORDER and the DeliveryError-only `failed_recipients`/`hosts` keys being absent otherwise.

## Decided against, and why

- Fixing the release first: the owner interrupted it for this refactor, and the refactor changes
  code that ships in 4.0.0.

## Still open, untouched

- Ranks 22, 30, 40: see `OPEN-WORK.md`. Rank 30's fix-mode question was never answered.

## Lessons for the next nap

- When a test checks for a leaked descriptor by the lowest free number, it misses a leak above a
  closed lower descriptor; assert EBADF on the recorded descriptor (captured this session).
- When a house rule states a hard limit (complexity <= 10), check the gate's ruff `select` names
  the rule (C90 was missing here and in bitranox_template_py_lib).
- When a doc states a closed-stdout exit code, measure both a broken pipe (`| true`) and a stdout
  closed at start (`>&-`): they differ (1/120 vs the normal table codes).
- tooling: none.

## Exact next action

Rank 15, step B: read `.data_arch_violations.json`; capture the BEFORE wire output of every
subcommand x {plain, --json, --json-bare} x {success, failure} (send against an unreachable
`--host 127.0.0.1:1 --timeout 1`, plus a refused recipient, plus a warn-mode skip); then define
`SkipKind` in `_common.py` and the CLI models (SkippedItem, ErrorPayload, success/failure
envelopes, per-command payloads) and fix the 6 files - partitioned with one owner per shared
file if dispatched; then re-run step A, then `make test`, then diff the AFTER wire output against
BEFORE (must be identical). Then rank 30 (ask the fix mode first).

## Files that matter

- `src/btx_lib_mail/cli/_output.py`, `cli/_dispatch.py`, `cli/_send_command.py`, `cli/_commands.py`
- `src/btx_lib_mail/_common.py` (home for SkipKind), `_validation.py`, `_attachments.py`
- `docs/cli.md` (the JSON envelope contract), `.data_arch_violations.json`

## How to verify

- `env -u VIRTUAL_ENV python3 <compuse-toolbox>/scripts/gate.py --gate "make test" --gate "make test-all"`
  ends with both `[PASS]`.
- `.venv/bin/pyright --pythonpath .venv/bin/python --pythonplatform Windows` (and Darwin, and
  `--pythonversion 3.10`) reports 0 errors.
- The before/after wire-output diff is empty.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
