# STALE - read 2026-09-29 13:25, work continued

## In flight

Nothing part-done. 1.7.0 is released (tag v1.7.0, PyPI serves wheel and sdist) and the
bitranox-skills mirror 7.30.3 is pushed with CI green. The macOS test-harness fix d97369c is
pushed and CI-confirmed: all 22 tests in tests/test_streaming.py now PASS on every macOS cell
(they had been skipped on every macOS run since 1.5.0).

## Committed, or not

- OPEN-WORK.md (new rank 35 line) and this file are committed locally on master but NOT
  pushed: a push starts a full CI run (the macOS queue took about 55 minutes today), so they
  ride along with the next real change. `git log origin/master..master` shows them.
- Everything else is pushed on master (last pushed: d97369c).

## Decided, and why

- Item 40: ConfMail REFUSES an empty blocked set at load (user choice over warn-once and
  warn-per-send); opt-out field attachment_allow_empty_blocklists. Logged in
  EXECUTION-USER-REVIEW.md.
- SecretSafeModel.__setattr__ rolls back a failed assignment on ANY exception: pydantic keeps a
  value a mode="after" validator refused. Restore is shallow (documented).
- The aiosmtpd retry-then-skip wrapper in tests/test_streaming.py is gone on purpose: it hid a
  failure that happened on every macOS run. Only the port-bind race is retried; TimeoutError
  (an OSError subclass) is re-raised first.

## Decided against, and why

- The 13 [tool.pip-audit].ignore-vulns ids were NOT removed during the release: none fires on
  the resolved tree, but CI audits the runner image and may still need them (rank 90).
- The client-side getfqdn cost (rank 35) was NOT fixed: it needs an API decision from the owner.

## Still open, untouched

See OPEN-WORK.md: ranks 20 (USER, CLI template on ConfMail), 30, 35, 80, 90.

## Lessons for the next nap

- When an aiosmtpd Controller "started, but not responding" timeout hits only macOS CI, pass server_hostname: without it SMTP.__init__ calls socket.getfqdn() in the server thread (about 30 s reverse DNS on macOS runners); fact reference-aiosmtpd-controller-start-flakes-on-macos-ci-retry-fresh-port-then-skip is WRONG (TIME_WAIT, "first few start fine", retry-then-skip) and must be rewritten.
- When smtplib.SMTP is built without local_hostname, it calls socket.getfqdn() per connection; on a host with slow reverse DNS every connection pays it.
- When a CI skip count is identical across every cell of an OS, read it as a deterministic defect, not a flake; count PASSED/SKIPPED per job before accepting a "runner flake" label.
- When pydantic validate_assignment meets a mode="after" model validator that raises, the new value stays on the instance (pydantic 2.13.5); roll back or use field validators.
- When annotating credential_fields on a SecretSafeModel subclass without ClassVar, pydantic makes it a field and the inherited empty set wins; 1.7.0 refuses it with TypeError.
- tooling: a subagent of type feature-dev:code-reviewer had no Bash, so it could not run the probes its prompt required; use a type with Bash for adversarial reviews that must execute code.

## Exact next action

Rank 20 (USER) is top: write the plan for moving the bitranox CLI template onto
ConfMail/SecretSafeModel, starting with precondition 2 in its OPEN-WORK line (the
shipped-default-config regression test for the empty blocked-list trap). Rank 35 is a quick
owner question worth asking first, since the answer is one sentence (recommend option c).

## Files that matter

- src/btx_lib_mail/lib_mail.py (ConfMail, _refuse_an_empty_blocklist, SmtplibTransport)
- src/btx_lib_mail/secret_safety.py (_check_credential_fields, __setattr__ rollback)
- tests/test_streaming.py (_run_server, _SERVER_NAME)
- skills/python-send-mail/SKILL.md and its mirror in bitranox-skills
- EXECUTION-USER-REVIEW.md (gitignored decision log)

## How to verify

- env -u VIRTUAL_ENV make test
- gh run list --commit d97369c83734e358da04474e133cfd6e3f754e2e --json workflowName,conclusion
- curl -s https://pypi.org/pypi/btx-lib-mail/json | python3 -c "import json,sys;print(json.load(sys.stdin)['info']['version'])"

> Read this, then replace the first line with `# STALE - read <date>, work continued`. Do not
> delete it - if this session ends badly it is the only record of where things stood.
