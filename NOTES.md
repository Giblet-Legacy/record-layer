# NOTES — record-layer (P7 Record)

NOTES.md — open questions, divergences and decisions for P7 Record.

## Open questions
- (none)

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
