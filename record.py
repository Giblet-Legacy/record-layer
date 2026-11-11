"""
record.py — P7 Record primitive layer

Function:
    Connects the cryptographic primitives to the filesystem. Loads
    passphrase-encrypted PEM keys and saves signed records to disk
    as .json files.

Public API:
    1. load_private_key    — Read and decrypt a PEM key.
    2. save_signed_record  — Sign a dict and write it to a .json file.
    3. verify_record_file  — Read a .json file and verify its signature.

Layer:    P7 — Record
Depends:  P1 Envelope v2, P2 Sign
Consumed: The Cockpit, SC-OS
Version:  1.0.0 (on freeze; 0.0.0-dev until then)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import sys
import json
from cryptography.hazmat.primitives import serialization

# Imports P1 and P2
sys.path.insert(0, os.path.abspath('../envelope-layer'))
sys.path.insert(0, os.path.abspath('../sign-layer'))
import sign

# ---------------------------------------------------------------------------
# 1. load_private_key
#    Reads a PEM file and decrypts it with the provided passphrase.
#    The passphrase never appears in logs, error messages or stdout.
# ---------------------------------------------------------------------------
def load_private_key(key_path, passphrase):
    with open(key_path, "rb") as f:
        pem_data = f.read()

    return serialization.load_pem_private_key(
        pem_data,
        password=passphrase.encode("utf-8")
    )

# ---------------------------------------------------------------------------
# 2. save_signed_record
#    Signs the record using P2 and writes it to disk as indented JSON.
#    Returns the signed dict for caller use.
# ---------------------------------------------------------------------------
def save_signed_record(record, filepath, private_key):
    signed = sign.sign_capsule(record, private_key)

    with open(filepath, "w") as f:
        json.dump(signed, f, indent=2)

    return signed

# ---------------------------------------------------------------------------
# 3. verify_record_file
#    Reads a .json file and verifies its signature using P2.
#    Returns False (not raise) if the file is missing or malformed.
# ---------------------------------------------------------------------------
def verify_record_file(filepath, public_key):
    if not os.path.exists(filepath):
        return False

    try:
        with open(filepath, "r") as f:
            record = json.load(f)
    except (json.JSONDecodeError, IOError):
        return False

    return sign.verify_capsule(record, public_key)
