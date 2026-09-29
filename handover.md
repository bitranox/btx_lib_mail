# STALE - read 2026-09-29, work continued

## In flight

Nothing part-done. btx_lib_mail 1.8.0 is released (tag v1.8.0; CI, CodeQL and Release green;
PyPI serves wheel and sdist; a no-cache `uvx` install shows `--local-hostname`). The
bitranox-skills mirror of the skill is pushed as 7.30.5 with its ci and publish workflows green.
`make clean-all` ran after the release, so there is no `.venv*`; the next `make` rebuilds them.

## Committed, or not

- This file and OPEN-WORK.md (rank 27 closed) are committed locally on master but NOT pushed: a
  push starts a full CI run, so they ride along with the next real change.
- Everything else is pushed (btx_lib_mail master at the 1.8.0 release commit; bitranox-skills at
  17c53f8f).
- The bitranox-skills clone still holds ANOTHER session's staged PLAN-JEV-SKILL.md and
  TODO-JEV.md. They are not ours; commit there only with a pathspec.

## Decided, and why

- Rank 35 = option (c) (user): an EHLO-name knob (ConfMail.smtp_local_hostname,
  send(local_hostname=), --local-hostname, BTX_MAIL_SMTP_LOCAL_HOSTNAME) AND the default looked up
  once per process (`_default_local_hostname`, functools.cache, smtplib's own rule). The lookup runs
  lazily in SmtplibTransport, never in send(), so an injected Transport never touches DNS.
- EHLO name validation is "non-empty, every char 0x21-0x7E" (RFC 5321 argument), not a hostname
  grammar: relays accept names a strict grammar would refuse.
- Rank 90: ignore-vulns emptied entirely. CI's pip-audit audits `uv pip compile --extra dev`, not
  the runner image (the old premise was stale); 0 findings on 3.10-3.14 and on every venv.
- The skill says "Available from btx_lib_mail 1.8.0". The mirror was held until PyPI served 1.8.0
  so it never taught a keyword the published package rejects.
- Fix mode for the release was ask-big (user).

## Decided against, and why

- ConfMail unknown keys (rank 85) NOT changed to extra="forbid" in 1.8.0: it breaks callers that
  pass extra keys (an app model, a loader passing a whole table), so it needs an owner decision.
  The skill now warns about it.
- The skill does not mention the CLI falling back to conf.smtp_local_hostname: a CLI process only
  ever sees the default conf, where it is None.

## Still open, untouched

See OPEN-WORK.md: ranks 20 (USER, CLI template on ConfMail), 30, 80, 85.

## Lessons for the next nap

- When an aiosmtpd Controller "started, but not responding" timeout hits only macOS CI, pass server_hostname: without it SMTP.__init__ calls socket.getfqdn() in the server thread (about 30 s reverse DNS on macOS runners); fact reference-aiosmtpd-controller-start-flakes-on-macos-ci-retry-fresh-port-then-skip is WRONG (TIME_WAIT, "first few start fine", retry-then-skip) and must be rewritten.
- When smtplib.SMTP is built without local_hostname, it calls socket.getfqdn() per connection; on a host with slow reverse DNS every connection pays it (btx_lib_mail 1.8.0 caches it per process and offers smtp_local_hostname).
- When a CI skip count is identical across every cell of an OS, read it as a deterministic defect, not a flake; count PASSED/SKIPPED per job before accepting a "runner flake" label.
- When pydantic validate_assignment meets a mode="after" model validator that raises, the new value stays on the instance (pydantic 2.13.5); roll back or use field validators.
- When annotating credential_fields on a SecretSafeModel subclass without ClassVar, pydantic makes it a field and the inherited empty set wins; 1.7.0 refuses it with TypeError.
- When a pydantic model keeps the default extra="ignore", a caller passing a sibling API's keyword name (ConfMail(use_starttls=False)) gets no error and the setting is silently dropped; a GREEN skill probe surfaced it.
- When a backlog line's premise describes how CI works ("CI scans the runner image"), read the current workflow file before acting on it: the template had already changed and the premise was stale.
- When a doc audit subagent reports a file "complete", check its enumeration yourself: one audit missed a nonexistent ConfMail.model_update in docs/api.md that the other found.
- tooling: repo-gate blocks EVERY commit in a tool repo while its skill differs from the marketplace twin (it compares working trees), so an unreleased skill edit cannot be committed alone; sync the mirror working tree first, or commit the rest with the skill temporarily restored from HEAD.
- tooling: `patch` leaves SKILL.md.orig beside a hunk applied with an offset, and repo-gate then reports "only in the marketplace" drift; delete the .orig.
- tooling: a subagent of type feature-dev:code-reviewer had no Bash, so it could not run the probes its prompt required; use a type with Bash for adversarial reviews that must execute code.

## Exact next action

Rank 20 (USER) is top: write the plan for moving the bitranox CLI template onto
ConfMail/SecretSafeModel with btx_lib_mail>=1.8.0, starting with precondition 2 in its OPEN-WORK
line (the shipped-default-config regression test for the empty blocked-list trap). Rank 85 bears on
it directly: a template loader that maps its TOML keys onto ConfMail wrongly is silently ignored
today, so ask the owner about rank 85 (refuse unknown keys vs warn) before or while planning.

## Files that matter

- src/btx_lib_mail/lib_mail.py (ConfMail, _DeliveryOverrides, _check_local_hostname,
  _default_local_hostname, SmtplibTransport)
- src/btx_lib_mail/cli.py (--local-hostname)
- tests/test_streaming.py (EHLO wire tests), tests/test_lib_mail.py (EHLO config tests)
- skills/python-send-mail/SKILL.md and its mirror
  plugins/bitranox/skills/coding-python-send-mail/SKILL.md in bitranox-skills
- EXECUTION-USER-REVIEW.md (gitignored decision log)

## How to verify

- env -u VIRTUAL_ENV make test
- python3 ../../KI/bitranox-skills/plugins/bitranox/hooks/repo-gate.py --mirror-of .
- curl -s https://pypi.org/pypi/btx-lib-mail/json | python3 -c "import json,sys;print(json.load(sys.stdin)['info']['version'])"

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
