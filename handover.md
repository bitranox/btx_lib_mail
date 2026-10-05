# STALE - read 2026-10-05, work continued

Read `OPEN-WORK.md` first. Open: ranks 21, 22, 30, 40 (USER; 22 and 30 held by the owner until
release, 40 deferred) and 50 (FOUND, sibling repos).

## In flight

Rank 21, the code-quality review loop. Sweep 5 (30 findings) is fixed and committed. Sweep 6
ran its three reviewers and every finding is recorded, verified where marked, but NOTHING of
sweep 6 is fixed yet. The owner granted "full auto for sweep 6 fixes" and chose to start the
fixing in a fresh session.

- Record: `.private/review-2026-10-05-sweep6.md` (findings, and a Status section with the fix order).
- Probes that reproduce the findings: `.private/sweep6-probes/revB_probes_keep.py.txt` (24 tests that
  kill every real surviving mutant) and `.private/sweep6-probes/reviewerA/` (p_*.py; c.pem/k.pem are a
  throwaway TLS key for p_tlsdrip*.py). The probes were written in another session's scratchpad, so
  absolute paths inside them may need adjusting.

## Committed, or not

- Everything is committed. Sweep 5 is 7714e0b..5af977a, plus 0375b82 (backlog). This handover and
  the rank 21/22 edits in `OPEN-WORK.md` are committed together with this file.
- All commits since origin/master stay local until the 4.0.0 bump (rank 30).
- Gitignored, not in git: `.private/review-2026-10-05-sweep{5,6}.md`, `.private/sweep6-probes/`,
  `.private/python-send-mail-SKILL.md.sweep2` (held skill text, now also naming `logger` and
  `REDACTED_INPUT`), `EXECUTION-USER-REVIEW.md` (sweep-5 autonomous decisions; the owner's
  full-auto grants for sweeps 5 and 6).

## Decided, and why

- Sweep 5's judgement calls are logged under "review sweep 5" in `EXECUTION-USER-REVIEW.md`. The
  ones a reader might reopen: F1 judges the kernel's path for the open descriptor by the same
  checks rather than requiring equality (hard links, macOS aliases); F2 type checks keep every old
  refusal message (17-input differential); F10 documents body memory rather than hand-rolling
  body transfer encoding.
- Sweep 6 C1 (`invalid type of mail_addresses` wording): not changed. It is an old refusal
  message, pinned on purpose by `test_recipients_that_are_not_a_string_or_sequence_keep_their_message`.
- The sweep-5 note that "the device/inode comparison is the only guard" without /proc is WRONG
  (sweep 6 A-F7 leaked 825 of 1627 with /proc hidden); correct that note when fixing F7.

## Decided against, and why

- Sweep 5 C2 (dedupe hosts in ConfMail): docs/configuration.md states the model keeps duplicates
  and send() drops them.
- Sweep 5 T5 (more doc-line regex cases): after F8 a caller's key cannot carry a line break, so
  the loosened-regex mutants have no caller text left to match.

## Still open, untouched

- Ranks 22 and 30: held by the owner until the 4.0.0 release. Rank 40: deferred. Rank 50:
  sibling repos.

## Lessons for the next nap

- When a watchdog cuts a blocked socket read with shutdown(), know Windows does not wake a recv()
  blocked on a peer that sends nothing at all; close() does there, and POSIX must not close
  (descriptor reuse under the reader).
- When a check runs on a path and a later open runs on the same path, judge the path the kernel
  reports for the open descriptor (/proc/self/fd, F_GETPATH, GetFinalPathNameByHandleW); O_NOFOLLOW
  guards only the last component.
- When an attachment name goes into a MIME filename parameter, judge the name the email package
  will carry (it decodes RFC 2047 encoded words and drops surrounding whitespace incl. NBSP), not
  the file system name.
- When pydantic validate_assignment runs a mode="after" model validator, know the new value is
  already on the instance; validating on a copy breaks private attributes unless they take a
  separate path (sweep 6 A-F1).
- When fixing a code-review finding, expect the fix to create the next sweep's findings: two of
  sweep 6's three MEDIUM security findings were regressions from sweep-5 fixes.
- When a reviewer's report path lives in a session scratchpad, copy it into the repo's ignored
  .private/ before a handover; the next session has a different scratchpad.
- tooling: block-masked-gate-exit refused `gate | tail` twice and a path-limited pyright once;
  both were right.

## Exact next action

Rank 21, sweep 6: read `.private/review-2026-10-05-sweep6.md`, then fix TDD-first in its Status
order, starting with reviewer A's F1 (SecretSafeModel private attributes lost on assignment) together
with reviewer B's T4, then A-F2 (directory rules resolved even with no attachments), A-F3 (deadline
lost during STARTTLS). Run `env -u VIRTUAL_ENV make test` before committing each group, test
Windows-touching changes on the local Windows dev box, then dispatch sweep 7.

## Files that matter

- `src/btx_lib_mail/secret_safety.py` (`SecretSafeModel.__setattr__`, `_restore_assignment_state`).
- `src/btx_lib_mail/_attachments.py` (`AttachmentSecurityOptions.__post_init__`,
  `_check_descriptor_path`, `_check_directory_restrictions`, `_filename_as_sent`).
- `src/btx_lib_mail/_descriptor_path.py`, `src/btx_lib_mail/_transport.py` (`_session_deadline`,
  `_quit_quietly`), `src/btx_lib_mail/lib_mail.py` (`_HostOrder`, `_without_password`),
  `src/btx_lib_mail/_validation.py` (`check_seconds`, `_shown`).
- `tests/test_deadline.py` (`_SessionServer`), `tests/transport_doubles.py` (`PerHostTransport`).

## How to verify

- `env -u VIRTUAL_ENV make test` ends with `{"result":"pass",...}` and refreshes `coverage.xml`
  (last: 15:44, line 97.3%, branch 93.3%).
- `git status --porcelain` is empty after this handover's commit.

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
