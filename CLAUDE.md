# Forge Stack Context — P7 Record

CLAUDE.md — Context briefing for AI assistants working in this repository.

## The Immutable Rule
Never rewrite a primitive. Add a layer.

## Dual-Device Workflow
We build on an S24 (Termux) and a laptop (VS Code). State is confirmed, never assumed. Always use LF line endings. Commit messages must be clear. We use the Good/Bad/Ugly CHANGELOG format (latest at top).

## Header Discipline
Every file MUST have a top header paragraph explaining its function.
Every function MUST have a numbered header.

## P7 Architecture Specifics
- Depends on `envelope_v2` (P1) and `sign` (P2).
- Handles loading passphrase-protected Ed25519 keys from PEM.
- Writes signed records to disk as `.sc.json` files.
- Never logs, prints, or persists the passphrase.
