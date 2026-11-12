"""
record_v2.py — P7 Record v2, strict layer over the frozen v1 primitive

Function:
    The layer new code imports instead of record.py. It finds P1 and
    P2 from its own location rather than the working directory,
    loads only passphrase-protected Ed25519 keys (ValueError for
    anything else), writes LF `.sc.json` records on every platform,
    and returns False instead of crashing on any malformed record
    file (SPEC_V2.md §2). It never reimplements a primitive: keys
    load through record.py, records are written by record.py, and
    signatures are checked by sign_v2 (P2 v2), so every v1 record
    verifies through v2 (SPEC_V2.md §1, §3).

    record.py is not edited (Immutable Rule). This file is the
    "add a layer" half of that rule. The passphrase is never logged,
    printed, persisted or placed in an error message.

Public API (same names and numbering as P7 v1.0.0):
    1. load_private_key   — passphrase type, encrypted PEM only,
                            Ed25519 only, then v1
    2. save_signed_record — v1, then file rewritten with LF
    3. verify_record_file — key type check, False on any malformed
                            file, then sign_v2.verify_capsule

Internal helpers (not exported):
    4. _require_public_key — TypeError unless Ed25519PublicKey

Layer:    P7 — Record, v2 (strict)
Depends:  record.py (P7 v1.0.0), sign_v2.py (P2 v2.0.0),
          envelope_v2.py (P1 v2.0.0)
Consumed: The Cockpit, SC-OS
Spec:     SPEC_V2.md 2.0.0 (over SPEC.md v1.0.0)
Version:  2.0.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os
import sys

# Locate P1 and P2 from this file, not the working directory
# (SPEC_V2 §2.1). Must run before importing record.py, whose own path
# inserts are cwd-relative and only correct from inside record-layer.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "envelope-layer"), os.path.join(_ROOT, "sign-layer")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import record as _v1
import sign_v2


# ---------------------------------------------------------------------------
# 4. _require_public_key
#    TypeError unless public_key is an Ed25519PublicKey (SPEC_V2 §2.4).
# ---------------------------------------------------------------------------
def _require_public_key(public_key):
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError(f"public_key must be Ed25519PublicKey, got {type(public_key).__name__}")


# ---------------------------------------------------------------------------
# 1. load_private_key
#    Passphrase must be a str (TypeError). Unencrypted PEM, wrong
#    passphrase, malformed PEM or a non-Ed25519 key -> ValueError
#    (SPEC_V2 §2.2, §2.3). Errors are raised `from None` with fixed
#    messages so the passphrase can never reach a traceback.
# ---------------------------------------------------------------------------
def load_private_key(key_path, passphrase):
    if not isinstance(passphrase, str):
        raise TypeError(f"passphrase must be str, got {type(passphrase).__name__}")

    try:
        key = _v1.load_private_key(key_path, passphrase)
    except TypeError:
        # cryptography raises TypeError when a password is supplied
        # for an unencrypted key.
        raise ValueError("PEM key is not passphrase-protected") from None
    except ValueError:
        raise ValueError("Unable to load PEM key: wrong passphrase or malformed PEM") from None

    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"PEM key must be Ed25519, got {type(key).__name__}")
    return key


# ---------------------------------------------------------------------------
# 2. save_signed_record
#    v1 signs and writes; the file is then rewritten with CRLF -> LF
#    (SPEC_V2 §2.5, §3). JSON strings cannot hold a raw CR, so only
#    line endings change.
# ---------------------------------------------------------------------------
def save_signed_record(record, filepath, private_key):
    signed = _v1.save_signed_record(record, filepath, private_key)

    with open(filepath, "rb") as f:
        raw = f.read()
    lf = raw.replace(b"\r\n", b"\n")
    if lf != raw:
        with open(filepath, "wb") as f:
            f.write(lf)

    return signed


# ---------------------------------------------------------------------------
# 3. verify_record_file
#    Key type check; False for a missing / non-regular path,
#    non-UTF-8, invalid JSON or a non-dict (SPEC_V2 §2.4). The capsule
#    is then checked by sign_v2, which applies the strict signature
#    shape and delegates to P2 v1 — never raises on malformed input.
# ---------------------------------------------------------------------------
def verify_record_file(filepath, public_key):
    _require_public_key(public_key)
    if not os.path.isfile(filepath):
        return False

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            capsule = json.load(f)
    except (ValueError, OSError):
        # ValueError covers JSONDecodeError and UnicodeDecodeError.
        return False

    if not isinstance(capsule, dict):
        return False

    return sign_v2.verify_capsule(capsule, public_key)
