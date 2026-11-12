# CHANGELOG — record-layer (P7 Record)

CHANGELOG.md — build history for P7 Record, latest entry at top.

## [v2.0.0] — 2026-11-12

### Good
- `record_v2.py`: strict layer above the frozen P7 v1.0.0, specified
  in `SPEC_V2.md` before any code. Keys load and records are written
  through record.py; signatures are checked through sign_v2 (P2 v2).
- `conftest.py`: P1/P2 located from the file, so the whole suite
  runs from any working directory.
- 20/20 pytest tests pass (v1 4/4 unchanged, v2 16/16). v1 ⇄ v2
  records cross-verify, including CRLF records written by v1.

### Bad
- Review found six divergences in v1.0.0 (NOTES D1–D6): cwd-relative
  imports, RSA keys accepted, TypeError for unencrypted PEM,
  AttributeError for a None passphrase, TypeError on a malformed
  signature value during verify, CRLF records on Windows.

### Ugly
- record.py and test_record.py are frozen and keep their header
  drift (NOTES D7). New code must import record_v2, not record.

## [v1.0.0] — 2026-11-11

### Good
- `record.py` implemented to SPEC v1.0.0.
- 4/4 pytest tests pass.
- Loads passphrase-protected PEM keys (never logged or printed).
- Writes and verifies signed `.sc.json` records.

### Bad
- (none)

### Ugly
- (none)

## [Scaffold]

### Good
- Repository scaffolded: `Giblet-Legacy/record-layer` created for P7.
- Depends on P1 Envelope v2.0.0 and P2 Sign v1.0.0.

### Bad
- (none)

### Ugly
- (none)
