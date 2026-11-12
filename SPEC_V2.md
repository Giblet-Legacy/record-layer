# SPEC V2 — record-layer (P7 Record, strict layer)

SPEC_V2.md — specification for record_v2.py, the layer above P7 v1.0.0.

Function:
    Specifies record_v2.py, a thin strict layer over the frozen P7
    v1.0.0 primitive (record.py). It closes the divergences D1–D6
    recorded in NOTES.md without editing record.py (Immutable Rule).

    SPEC.md v1.0.0 remains authoritative for everything this document
    does not change. Where this document is silent, SPEC.md v1.0.0
    applies unchanged.

Layer:     P7 — Record, v2 (strict)
Depends:   record.py (P7 v1.0.0), sign_v2.py (P2 v2.0.0),
           envelope_v2.py (P1 v2.0.0)
Consumed:  The Cockpit, SC-OS — new code imports record_v2, not record
Version:   SPEC V2 2.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

---

## 1. Compatibility guarantee

- A record written by v1 verifies under v2, including v1 records
  written with CRLF on Windows.
- A record written by v2 verifies under v1.
- save_signed_record returns the same signed dict as v1 for the same
  record and key (Ed25519 is deterministic).

v2 differs from v1 only by **rejecting** inputs that v1 accepted
outside the contract, by **raising ValueError** where v1 raised
another type, by **returning False** where v1 crashed, and by
writing LF on every platform. That narrowing is why the major
version is 2.

## 2. Changes from SPEC.md v1.0.0

### 2.1 Location-independent imports (resolves D1)

record_v2 locates P1 and P2 relative to its own file, not the
current working directory: `<dir of record_v2.py>/../envelope-layer`
and `<dir of record_v2.py>/../sign-layer`. `conftest.py` does the
same for pytest, so the frozen test_record.py also runs from any
working directory.

### 2.2 load_private_key returns only Ed25519 keys (resolves D2)

SPEC.md §1.1 says the result is an Ed25519PrivateKey. v2 raises
ValueError if the PEM decrypts to any other key type (RSA, EC, …).

### 2.3 load_private_key failure types (resolves D3, D4)

- `passphrase` that is not a str → TypeError (caller bug).
- A PEM that is not passphrase-protected → ValueError. v1 raised
  TypeError from `cryptography`. SPEC.md §1.1 requires a
  passphrase-protected key.
- Wrong passphrase or malformed PEM → ValueError, as in v1.
- Missing key file → FileNotFoundError, as in v1.

No error message raised by v2 contains the passphrase.

### 2.4 verify_record_file never crashes on a malformed record (resolves D5)

verify_record_file returns False — never raises — for a missing
path, a path that is not a regular file, non-UTF-8 bytes, invalid
JSON, a top-level value that is not a dict, or a signature object
that fails the P2 v2 shape check (SPEC_V2 §2.2 of sign-layer). v1
raised TypeError on, for example, an int signature value.

A public key that is not an Ed25519PublicKey raises TypeError, as in
P2 v2 (a wrong key type is a caller bug, not a failed verification).

### 2.5 LF records (resolves D6)

save_signed_record writes the record with LF line endings on every
platform. The bytes are `json.dumps(signed, indent=2)` encoded as
UTF-8, with no trailing newline — v1's POSIX output.

## 3. Construction rule

record_v2 delegates to record.py and sign_v2.py. It never
reimplements a primitive:

- load_private_key checks the passphrase type, calls
  record.load_private_key, maps the "not encrypted" TypeError to
  ValueError, then checks the key type.
- save_signed_record calls record.save_signed_record, then rewrites
  the file it wrote with CRLF normalised to LF. JSON text cannot
  contain a raw CR inside a string, so only line endings change.
- verify_record_file reads the file as UTF-8 and parses it, then
  returns sign_v2.verify_capsule, which checks the signature shape
  and delegates to P2 v1 sign.verify_capsule. It does not call
  record.verify_record_file: v1 reads with the platform encoding and
  can raise UnicodeDecodeError (D5), and its only other work is the
  same sign.verify_capsule call.

## 4. Public API

Same three names as P7 v1.0.0, same numbering:

1. load_private_key   — v2: passphrase type, encrypted only, Ed25519 only
2. save_signed_record — v2: v1, then LF file
3. verify_record_file — v2: False on any malformed file, then sign_v2

## 5. Test plan (test_record_v2.py)

- Public API: three names, all callable.
- load_private_key: valid key loads; wrong passphrase, garbage PEM,
  unencrypted PEM, RSA key → ValueError; non-str passphrase →
  TypeError; missing file → FileNotFoundError; passphrase absent
  from every error message.
- save_signed_record: no CR in file bytes, exact bytes as §2.5,
  return value equal to v1's, non-dict record → ValueError.
- verify_record_file: valid → True; tampered, wrong key → False.
- verify_record_file malformed (missing path, directory, non-UTF-8,
  invalid JSON, list, int / uppercase / short signature value,
  missing signature) → False, never raises.
- verify_record_file with None or a private key as public key →
  TypeError.
- v1 ⇄ v2 records cross-verify.
- `import record_v2` succeeds from an unrelated working directory.
