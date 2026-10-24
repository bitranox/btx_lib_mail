# skill-writer checklist - coding-python-send-mail (memory rules folded in)

- [x] Change: ConfMail field names paragraph (after the build_conf example, extending the 'A
      credentials pair...' paragraph) - coding-python-send-mail/SKILL.md. RED on the pre-edit
      snapshot: partial. Verified: extra="forbid" with subclass inheritance comment -> btx_lib_mail
      src/btx_lib_mail/_config.py:163-164 ('Subclasses inherit it, since pydantic merges a
      subclass's model_config into this one'; `model_config = ConfigDict(..., extra="forbid",
      ...)`). Ran in a fresh scratch dir with `uv run --no-cache --with <btx_lib_mail repo>`
      (4.6.0): `class F(ConfMail): pass; F(smtphosts=[...], sender='x')` -> `ConfigurationError
      extra_forbidden ('sender',)`; subclass with `model_config = ConfigDict(extra='ignore')`
      accepted sender and dropped it; subclass declaring `sender: str`, `recipients: list[str]`
      accepted them and still refused `use_starttls=False` with extra_forbidden.
- [x] Dropped as stale or unverified: Nothing stale. The main rule (refusal, extra_forbidden/loc,
      map never pass-through, never filter to model_fields) was ALREADY-IN-SKILL at SKILL.md:135-141
      and is not repeated; only the subclass note was added. The '2.0.0' version in the slug is
      history and not carried.
- [x] Change: ### The EHLO name (slow first byte, relay rejects the greeting) - new closing
      paragraph - coding-python-send-mail/SKILL.md. RED on the pre-edit snapshot: partial. Verified:
      Background lookup class -> src/btx_lib_mail/_transport.py:98 `class _LocalHostnameLookup`
      (daemon-thread lookup, 'a delivery with a deadline waits only part of it, and the next
      delivery picks the answer up'). Half of time left -> _transport.py:212
      `_EHLO_NAME_SHARE_OF_DEADLINE: Final = 0.5` and :399 `name_within(left *
      _EHLO_NAME_SHARE_OF_DEADLINE)`; no deadline -> :397 `name_within(None)`. Seam ->
      _transport.py:337 `def __init__(self, *, local_hostname_lookup: Callable[[], str] | None =
      None)` with docstring 'run once per transport'. SmtplibTransport is NOT exported from the
      top-level package (ImportError in a scratch probe) but is from btx_lib_mail.lib_mail
      (lib_mail.py:51 import, :828 in __all__); the probe `from btx_lib_mail.lib_mail import
      SmtplibTransport; SmtplibTransport(local_hostname_lookup=lambda: 'test.example.com')`
      succeeded. send() takes `transport: Transport | None` -> lib_mail.py:114.
- [x] Dropped as stale or unverified: Version-history branch (below 4.3.0 the lookup runs before the
      deadline; raise the floor; warm the lookup with a send to a closed port) dropped per the
      latest-release-only rule. Dated measurement and private consumer review reference (watchdog
      rank 36) dropped. 'The relay's own name lookup is not interrupted' dropped as ambiguous and
      unverified against source. The existing current-behaviour text at SKILL.md:479-487 was
      ALREADY-IN-SKILL and left unchanged.
- [x] Review A: the "deadline" contradiction a test reader raised is not one (_ehlo_name_in_time
      runs inside _session_deadline); fixed the reuse wording and added that the first send has only
      the rest of its deadline for the session.
- [x] Receipt held (the coordinator ran skill_receipt.py start meta-skill-writer); every editing
      agent loaded the skill through the Skill tool before its first edit.
- [x] RED as a text check: an opus quote-back against a pre-edit snapshot of the skill. Only a
      verbatim quote from the snapshot counts, so context inherited from this machine cannot
      satisfy it; redcheck --corpus-cascade was not run.
- [x] GREEN quote-back on haiku and opus against the edited files: every scenario after the edit,
      every scenario again after the first review's fixes, then the scenarios each later fix
      touched. Every answer was a quote from the new text on both tiers in every round; no NONE.
      Quotes were checked against the files (6-word windows; misses traced to line wraps,
      markup and line-number prefixes).
- [x] GREEN diffed against RED both ways: every partial RED quote is still in the edited text.
- [x] Tiers haiku and opus, one cell per scenario per tier per round.
- [x] Independent review of the full diff, then a review of each fix delta alone; every finding
      fixed or declined above. Each GREEN reply's Skill gaps list was read; gaps not listed
      here asked for detail the rule does not need (out of scope) or were answered elsewhere in
      the skill.
- [x] Description measured: unchanged (frontmatter not edited).
- [x] ASCII only, present tense (history finder clean on the added lines), tables canonical
      (reformat_tables.py --check --strict), every fence closes, added prose wrapped at 100
      columns except where the file keeps one line per paragraph or list item.
- [x] Security scan: prose only; no secrets, hostnames, private paths or PII; values added are
      option names, commands, source file paths or reserved examples.
