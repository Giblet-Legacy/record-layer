"""
test_record.py — P7 Record test suite

Function:
    Executable expression of SPEC.md. Written before record.py per
    build discipline.

Layer:    P7 — Record
Spec:     SPEC.md v1.0.0
Licence:  MSL-1.0
"""

import os
import sys
import json
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.abspath('../envelope-layer'))
sys.path.insert(0, os.path.abspath('../sign-layer'))

import record

@pytest.fixture
def temp_key_file():
    fd, path = tempfile.mkstemp(suffix=".pem")
    os.close(fd)

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"secret123")
    )
    with open(path, "wb") as f:
        f.write(pem)

    yield path, key.public_key()
    if os.path.exists(path):
        os.remove(path)

@pytest.fixture
def temp_record_file():
    fd, path = tempfile.mkstemp(suffix=".sc.json")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_load_private_key(temp_key_file):
    path, expected_pub = temp_key_file
    sk = record.load_private_key(path, "secret123")
    assert sk.public_key().public_bytes_raw() == expected_pub.public_bytes_raw()

def test_load_private_key_wrong_pass(temp_key_file):
    path, _ = temp_key_file
    with pytest.raises(ValueError):
        record.load_private_key(path, "wrongpass")

def test_save_and_verify_record(temp_key_file, temp_record_file):
    key_path, pub_key = temp_key_file
    sk = record.load_private_key(key_path, "secret123")

    data = {"scp_id": "test-123", "declaration": "hello"}
    signed = record.save_signed_record(data, temp_record_file, sk)

    assert os.path.exists(temp_record_file)
    assert "signature" in signed

    assert record.verify_record_file(temp_record_file, pub_key) is True

def test_verify_tampered_record(temp_key_file, temp_record_file):
    key_path, pub_key = temp_key_file
    sk = record.load_private_key(key_path, "secret123")

    data = {"scp_id": "test-123", "declaration": "hello"}
    record.save_signed_record(data, temp_record_file, sk)

    with open(temp_record_file, "r") as f:
        content = json.load(f)
    content["declaration"] = "tampered"
    with open(temp_record_file, "w") as f:
        json.dump(content, f)

    assert record.verify_record_file(temp_record_file, pub_key) is False
