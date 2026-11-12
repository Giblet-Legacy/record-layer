# NOTES — record-layer (P7 Record)

NOTES.md — open questions, divergences and decisions for P7 Record.

Function:
    Records open questions and divergences between record.py v1.0.0
    and SPEC.md v1.0.0. record.py is never edited (Immutable Rule), so
    a fix means a new layer above it, after a SPEC version describes
    it. Each divergence below names the layer and section that
    resolves it.

## Open questions
- (none)

## Divergences — record.py v1.0.0 vs SPEC.md v1.0.0

Found in review 2026-11-12. Each was reproduced by a probe before the
fix. D1–D6 are resolved by `record_v2.py` (SPEC_V2.md 2.0.0);
record.py is unchanged.

- **D1 — CWD-relative P1/P2 import.** `record.py:31-32` and
  `test_record.py:21-22` insert `os.path.abspath('../sign-layer')`
  etc., which resolves against the working directory. Running pytest
  from any other directory failed with `ModuleNotFoundError`.
  **Resolved:** SPEC_V2 §2.1; record_v2 locates P1/P2 from
  `__file__`. `conftest.py` does the same for pytest, so the frozen
  test_record.py also runs from anywhere.
- **D2 — load_private_key accepts any key type.** An encrypted RSA
  PEM loaded and returned an `RSAPrivateKey`. SPEC §1.1 says the
  result is an Ed25519PrivateKey. **Resolved:** SPEC_V2 §2.2.
- **D3 — unencrypted PEM raises TypeError.** `cryptography` raises
  `TypeError: Password was given but private key is not encrypted`.
  SPEC §1.1 requires a passphrase-protected key and lists ValueError
  as the failure type. **Resolved:** SPEC_V2 §2.3.
- **D4 — non-str passphrase raises AttributeError.** `None` hit
  `.encode`. **Resolved:** SPEC_V2 §2.3 (TypeError).
- **D5 — verify_record_file crashes on a malformed record.** A
  signature `"value"` of `123` raised `TypeError` (inherited from P2
  v1, sign-layer NOTES D2). The file is also read with the platform
  encoding and only `JSONDecodeError`/`IOError` are caught, so
  non-ASCII bytes can raise `UnicodeDecodeError` on Windows. SPEC
  §1.3 says malformed → False. **Resolved:** SPEC_V2 §2.4.
- **D6 — records written with platform newlines.** `open(..., "w")`
  writes CRLF on Windows, so the S24 and the laptop produced
  different record bytes (CLAUDE.md: always LF). Verification was
  unaffected. **Resolved:** SPEC_V2 §2.5.
- **D7 — Documentation drift in frozen files (not fixed).**
  `record.py`'s header still reads `Version: 1.0.0 (on freeze;
  0.0.0-dev until then)` and says `.json` where SPEC says
  `.sc.json`, and the functions in test_record.py have no numbered
  headers (CLAUDE.md Header Discipline). Both files are frozen and
  left as they are; record_v2.py and test_record_v2.py follow the
  discipline. README.md status (said `0.0.0-dev`) is corrected.

## Divergences from v1.2.1 specification
- (none)

## Decisions
- `load_private_key` expects a standard PEM file with an
  encryption_algorithm of BestAvailableEncryption (or equivalent).
- `.gitignore` excludes `*.pem` and `*.sc.json` to prevent accidental
  commits of secrets or local records.
- `verify_record_file` returns False (not raise) on missing files,
  matching P2's verify semantics: verification is a policy question,
  not an exception.
- 2026-11-12 — record_v2 depends on sign_v2 (P2 v2.0.0), not sign.py,
  so the strict signature-shape check applies to records. P2 v2 is
  frozen and pushed.
- 2026-11-12 — a wrong public-key type raises TypeError in v2
  verify_record_file (checked before the file is read), matching P2
  v2. A bad key type is a caller bug, not a failed verification.
- 2026-11-12 — v2 load_private_key re-raises `from None` with fixed
  messages, so no exception chain can carry the passphrase.
- 2026-11-12 — v2 verify_record_file does not delegate to
  record.verify_record_file (SPEC_V2 §3); it reads UTF-8 itself and
  hands the capsule to sign_v2.
