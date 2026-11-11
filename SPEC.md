# SPEC — record-layer (P7 Record)

SPEC.md — the complete layer specification for P7 Record.

Function:
    This document is the authoritative specification for primitive
    layer P7 of the Forge Stack. It defines the API for loading
    passphrase-protected keys and writing signed records to disk.

Layer:     P7 — Record
Depends:   P1 Envelope v2, P2 Sign
Consumed:  The Cockpit, SC-OS
Version:   SPEC 1.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

## 1. The Record Rule

A record is a signed capsule saved to disk as a JSON file. P7
handles the file I/O and the encrypted key loading. It delegates
all cryptographic work to P1 (primitives) and P2 (capsule signing).

### 1.1 load_private_key(key_path: str, passphrase: str) -> Ed25519PrivateKey
- Reads a PEM-encoded, passphrase-protected Ed25519 private key.
- Raises ValueError on wrong passphrase or malformed PEM.
- Never logs, prints, or persists the passphrase.

### 1.2 save_signed_record(record: dict, filepath: str, private_key) -> dict
- Signs the record via `sign.sign_capsule()` (P2).
- Writes the signed dict to `filepath` as indented JSON.
- Returns the signed dict for caller use.

### 1.3 verify_record_file(filepath: str, public_key) -> bool
- Reads the JSON file at `filepath`.
- Verifies the capsule signature via `sign.verify_capsule()` (P2).
- Returns True if valid, False otherwise.
- Returns False (not raise) if the file is missing or malformed.

## 2. Function Contracts

### 2.1 load_private_key
- Input: key_path (str), passphrase (str)
- Output: Ed25519PrivateKey
- Failure: ValueError on bad passphrase or malformed PEM
- Purity: Impure (file I/O + decryption)

### 2.2 save_signed_record
- Input: record (dict), filepath (str), private_key
- Output: signed dict
- Failure: IOError if filepath not writable
- Purity: Impure (file I/O)

### 2.3 verify_record_file
- Input: filepath (str), public_key
- Output: bool
- Failure: Returns False on missing/malformed file
- Purity: Impure (file I/O)

## 3. Known Limitations (P7 v1.0.0)

- No key generation. P7 loads existing PEM keys; it does not create them.
- No key rotation. A single key per record file.
- No multi-signature support. One signer per record.
- PEM format only. Other key formats (JWK, raw bytes) are not supported.
