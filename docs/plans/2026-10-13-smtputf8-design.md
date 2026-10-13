# SMTPUTF8: internationalised addresses - design

Status: agreed with the owner 2026-10-13 (questions and section answers logged in the gitignored
`EXECUTION-USER-REVIEW.md`). Backlog: `OPEN-WORK.md` rank 8.

## Goal

`send()` and the CLI deliver to and from addresses that contain non-ASCII characters in the local
part (`empfänger@example.com`), the domain (`user@müller.de`), or both, using RFC 6531 SMTPUTF8 and
RFC 6532 UTF-8 headers. Mail whose addresses are all ASCII is unchanged, byte for byte.

## Decisions

| Question               | Decision                                                                   |
|------------------------|----------------------------------------------------------------------------|
| Non-ASCII domains      | Sent as UTF-8 over SMTPUTF8; no punycode/IDNA fallback, no new dependency  |
| Relay without SMTPUTF8 | A failed host for that recipient: next host is tried, `DeliveryError` last |
| Unicode normalisation  | NFC before validating and sending; the NFC form is what is logged and sent |
| Documentation          | Every new function fully documented; README and docs updated in the change |

## 1. Validation and normalisation (`_validation.py`)

- Each address (sender and recipients) is trimmed as today, NFC-normalised, then validated. The
  normalised form is de-duplicated, logged, written into the headers and sent.
- `distinct_recipients` lower-cases only ASCII addresses (unchanged). A non-ASCII address keeps its
  case: Unicode lower-casing can change length and leave non-NFC text, and the local part is
  case-sensitive under RFC 5321.
- `EMAIL_PATTERN` stays the ASCII fast path. A non-ASCII address is checked separately:
  - local part: the ASCII characters allowed today plus any non-ASCII character that is
    `str.isprintable()` (this refuses controls, every bidirectional mark, separators, whitespace,
    surrogates and unassigned code points; it is not a shared copy of the attachment bidi set);
  - domain: dot-separated labels of letters, digits (any script) and hyphens, no leading or
    trailing hyphen; a top-level label of at least two letters in any script. ASCII `xn--` labels
    pass as today.
- `address_length_problem` counts UTF-8 octets (64 local part, 254 address). ASCII figures do not
  change; the message names the length, never the address.
- `validate_email_address()` and `validate-email` accept such addresses. The validator only checks;
  it does not return the NFC form.

## 2. Composition (`_compose.py`)

- `needs_smtputf8(sender, recipient) -> bool` in `_validation.py`: true when either address holds
  non-ASCII. The one rule `_compose` and `_transport` both import.
- A From or To header whose address is ASCII is folded with `email.policy.SMTP` exactly as today. A
  header whose address holds non-ASCII is folded with `email.policy.SMTPUTF8` (raw UTF-8, RFC 6532).
  From is still folded once per call, To once per recipient.
- Subject (RFC 2047 encoded-words, valid in an SMTPUTF8 message too) and Date are unchanged; the
  shared 7-bit body is still encoded once per call and shared by both kinds of message.
- A non-ASCII sender makes every recipient's message need SMTPUTF8; a non-ASCII recipient makes only
  that recipient's.
- Python 3.15: the utf8=False policy never sees a non-ASCII address, so its `HeaderWriteError`
  cannot occur. `test_split_header_lines_equal_folding_all_four_together` is rewritten to expect the
  raw UTF-8 To header; then 3.15 is declared (classifier, `requires-python` stays).

## 3. Delivery (`_transport.py`)

- `_open_envelope` (shared by DATA and BDAT) calls
  `smtp.mail(sender, options=["SMTPUTF8", "BODY=8BITMIME"])` when `needs_smtputf8`, otherwise
  `smtp.mail(sender)` as today. smtplib switches the command encoding to UTF-8 (MAIL FROM and RCPT TO
  carry the raw address) and raises `SMTPNotSupportedError` when SMTPUTF8 is not advertised.
  RFC 6531 requires an SMTPUTF8 server to support 8BITMIME; stdlib `send_message` sends the same pair.
- A relay without SMTPUTF8 raises `SMTPUTF8NotSupportedError`, a subclass of
  `smtplib.SMTPNotSupportedError`: WARNING log with `error_type == "SMTPUTF8NotSupportedError"`,
  next host, `DeliveryError` only when every host fails. `_HostOrder` treats it as a message refusal,
  so the host is not moved to the back and ASCII recipients still try it first (the plain
  `SMTPNotSupportedError` is an `OSError` that would have demoted the host).
- One connection per recipient already, so the UTF-8 command encoding never reaches an ASCII
  recipient's session. STARTTLS, AUTH, EHLO name, deadline, streaming and dot-stuffing are unchanged.

## 4. Tests and documentation

Tests (test-first; real aiosmtpd for the wire, `RecordingTransport` for orchestration, no patching of
the package's own code):

- validation: accepted local parts and domains in several scripts; refused controls, bidi characters,
  whitespace, lone surrogates, a bad hyphen or a one-letter TLD; octet lengths (a 33-character local
  part of two-byte letters is refused, the same count in ASCII accepted); NFC of a decomposed input;
  ASCII lower-casing unchanged and non-ASCII case kept.
- composition: ASCII headers byte-identical to before; a non-ASCII To and a non-ASCII From are raw
  UTF-8; Subject and body bytes identical between an SMTPUTF8 and a plain message.
- wire (`enable_SMTPUTF8=True` / `False`, DATA and BDAT): MAIL FROM carries `SMTPUTF8 BODY=8BITMIME`
  only for a non-ASCII address; the server receives the raw UTF-8 envelope and To header; ASCII mail
  sends no option; a relay without SMTPUTF8 fails over to one with it; all relays without it give
  `DeliveryError` naming the recipient, with an ASCII recipient in the same call delivered.
- CLI: `validate-email` and `send` with a non-ASCII recipient, plain and `--json`.
- regression: the `HeaderWriteError` input passes on 3.15 once declared.

Documentation, in the same change: Google docstrings with Args, Returns, Raises and a doctest for
every new or changed function (`needs_smtputf8`, the non-ASCII address check, the octet length
rule); README ("What it does" and an example where it fits); `docs/api.md`, `docs/configuration.md`
(relay without SMTPUTF8), `docs/cli.md`, `docs/systemdesign/module_reference.md`, `CLAUDE.md` where
the layout changes; the shipped skill `skills/python-send-mail/SKILL.md` and its bitranox-skills
twin; CHANGELOG.

## Out of scope

Punycode/IDNA conversion, a config switch to refuse non-ASCII addresses, remembering per call which
host lacks SMTPUTF8, display names in From/To (the library sends bare addresses).
