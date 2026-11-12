"""
test_record_v2.py — P7 Record v2 (strict layer) test suite

Function:
    Executable expression of SPEC_V2.md §5. Written before
    record_v2.py and run red first. Proves two things: (1) v2 stays
    compatible with the frozen v1 primitive, so v1 records still
    verify and v2 records verify under v1; (2) v2 rejects, returns
    False or raises where SPEC requires and v1 did not (NOTES.md
    D1–D6).

Functions in this file:
    Helpers and fixtures:
    1.  _write_pem                          — write a PKCS8 PEM to disk
    2.  workdir                             — fresh temp directory
    3.  key                                 — Ed25519 key + its PEM path
    Tests (pytest-collected):
    4.  test_public_api                     — three names, all callable
    5.  test_load_private_key_valid         — loads the right key
    6.  test_load_private_key_value_errors  — D2, D3: ValueError cases
    7.  test_load_private_key_type_errors   — D4: non-str passphrase
    8.  test_load_private_key_missing_file  — FileNotFoundError
    9.  test_passphrase_never_in_errors     — no leak in messages
    10. test_save_lf_bytes                  — D6: exact LF bytes
    11. test_save_identity_with_v1          — same dict as v1
    12. test_save_non_dict                  — ValueError
    13. test_verify_results                 — valid, tamper, wrong key
    14. test_verify_malformed               — D5: False, never raises
    15. test_verify_key_type_errors         — TypeError
    16. test_records_cross_verify           — v1 ⇄ v2
    17. test_import_from_any_cwd            — D1

Layer:    P7 — Record, v2 (strict)
Spec:     SPEC_V2.md 2.0.0 (over SPEC.md v1.0.0)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import record
import record_v2

HERE = os.path.dirname(os.path.abspath(__file__))
PASS = "secret123-do-not-leak"
RECORD = {"scp_id": "test-123", "declaration": "hello", "nested": {"n": [1, 2]}}


# ---------------------------------------------------------------------------
# 1. _write_pem
#    Writes `private_key` as PKCS8 PEM, encrypted when `password` is set.
# ---------------------------------------------------------------------------
def _write_pem(path, private_key, password):
    enc = (serialization.BestAvailableEncryption(password)
           if password else serialization.NoEncryption())
    with open(path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    return path


# ---------------------------------------------------------------------------
# 2. workdir
# ---------------------------------------------------------------------------
@pytest.fixture
def workdir(tmp_path):
    return str(tmp_path)


# ---------------------------------------------------------------------------
# 3. key
#    (private key, public key, encrypted PEM path)
# ---------------------------------------------------------------------------
@pytest.fixture
def key(workdir):
    sk = Ed25519PrivateKey.generate()
    path = _write_pem(os.path.join(workdir, "k.pem"), sk, PASS.encode())
    return sk, sk.public_key(), path


# ---------------------------------------------------------------------------
# 4. test_public_api
# ---------------------------------------------------------------------------
def test_public_api():
    for name in ("load_private_key", "save_signed_record", "verify_record_file"):
        assert callable(getattr(record_v2, name))


# ---------------------------------------------------------------------------
# 5. test_load_private_key_valid
# ---------------------------------------------------------------------------
def test_load_private_key_valid(key):
    sk, pk, path = key
    loaded = record_v2.load_private_key(path, PASS)
    assert isinstance(loaded, Ed25519PrivateKey)
    assert loaded.public_key().public_bytes_raw() == pk.public_bytes_raw()


# ---------------------------------------------------------------------------
# 6. test_load_private_key_value_errors
#    Wrong passphrase, garbage, unencrypted (D3), non-Ed25519 (D2).
# ---------------------------------------------------------------------------
def test_load_private_key_value_errors(key, workdir):
    sk, _, path = key
    with pytest.raises(ValueError):
        record_v2.load_private_key(path, "wrong")

    garbage = os.path.join(workdir, "g.pem")
    with open(garbage, "wb") as f:
        f.write(b"not a pem")
    with pytest.raises(ValueError):
        record_v2.load_private_key(garbage, PASS)

    plain = _write_pem(os.path.join(workdir, "plain.pem"), sk, None)
    with pytest.raises(ValueError):
        record_v2.load_private_key(plain, PASS)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_path = _write_pem(os.path.join(workdir, "rsa.pem"), rsa_key, PASS.encode())
    with pytest.raises(ValueError):
        record_v2.load_private_key(rsa_path, PASS)


# ---------------------------------------------------------------------------
# 7. test_load_private_key_type_errors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [None, b"secret123", 123])
def test_load_private_key_type_errors(key, bad):
    _, _, path = key
    with pytest.raises(TypeError):
        record_v2.load_private_key(path, bad)


# ---------------------------------------------------------------------------
# 8. test_load_private_key_missing_file
# ---------------------------------------------------------------------------
def test_load_private_key_missing_file(workdir):
    with pytest.raises(FileNotFoundError):
        record_v2.load_private_key(os.path.join(workdir, "nope.pem"), PASS)


# ---------------------------------------------------------------------------
# 9. test_passphrase_never_in_errors
# ---------------------------------------------------------------------------
def test_passphrase_never_in_errors(key, workdir):
    sk, _, path = key
    plain = _write_pem(os.path.join(workdir, "plain.pem"), sk, None)
    for p, pw in ((path, PASS + "x"), (plain, PASS)):
        with pytest.raises(ValueError) as exc:
            record_v2.load_private_key(p, pw)
        assert PASS not in str(exc.value)
        assert PASS not in repr(exc.value)


# ---------------------------------------------------------------------------
# 10. test_save_lf_bytes
# ---------------------------------------------------------------------------
def test_save_lf_bytes(key, workdir):
    sk, _, _ = key
    path = os.path.join(workdir, "r.sc.json")
    signed = record_v2.save_signed_record(RECORD, path, sk)
    with open(path, "rb") as f:
        raw = f.read()
    assert b"\r" not in raw
    assert raw == json.dumps(signed, indent=2).encode("utf-8")


# ---------------------------------------------------------------------------
# 11. test_save_identity_with_v1
# ---------------------------------------------------------------------------
def test_save_identity_with_v1(key, workdir):
    sk, _, _ = key
    v1 = record.save_signed_record(RECORD, os.path.join(workdir, "a.sc.json"), sk)
    v2 = record_v2.save_signed_record(RECORD, os.path.join(workdir, "b.sc.json"), sk)
    assert v1 == v2
    assert "signature" not in RECORD


# ---------------------------------------------------------------------------
# 12. test_save_non_dict
# ---------------------------------------------------------------------------
def test_save_non_dict(key, workdir):
    sk, _, _ = key
    with pytest.raises(ValueError):
        record_v2.save_signed_record([1, 2], os.path.join(workdir, "x.sc.json"), sk)


# ---------------------------------------------------------------------------
# 13. test_verify_results
# ---------------------------------------------------------------------------
def test_verify_results(key, workdir):
    sk, pk, _ = key
    path = os.path.join(workdir, "r.sc.json")
    record_v2.save_signed_record(RECORD, path, sk)
    assert record_v2.verify_record_file(path, pk) is True

    other = Ed25519PrivateKey.generate().public_key()
    assert record_v2.verify_record_file(path, other) is False

    with open(path, encoding="utf-8") as f:
        content = json.load(f)
    content["declaration"] = "tampered"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(content, f)
    assert record_v2.verify_record_file(path, pk) is False


# ---------------------------------------------------------------------------
# 14. test_verify_malformed
#     Every case must return False, never raise (D5).
# ---------------------------------------------------------------------------
def test_verify_malformed(key, workdir):
    sk, pk, _ = key
    good = record_v2.save_signed_record(RECORD, os.path.join(workdir, "g.sc.json"), sk)

    def with_value(v):
        bad = json.loads(json.dumps(good))
        bad["signature"]["value"] = v
        return json.dumps(bad).encode("utf-8")

    no_sig = dict(good)
    del no_sig["signature"]
    cases = {
        "non_utf8": b"\xff\xfe{",
        "invalid_json": b"{not json",
        "list": b"[1, 2]",
        "int_value": with_value(123),
        "upper_value": with_value(good["signature"]["value"].upper()),
        "short_value": with_value("ab"),
        "no_signature": json.dumps(no_sig).encode("utf-8"),
    }
    for name, data in cases.items():
        path = os.path.join(workdir, name + ".sc.json")
        with open(path, "wb") as f:
            f.write(data)
        assert record_v2.verify_record_file(path, pk) is False, name

    assert record_v2.verify_record_file(os.path.join(workdir, "nope.sc.json"), pk) is False
    assert record_v2.verify_record_file(workdir, pk) is False


# ---------------------------------------------------------------------------
# 15. test_verify_key_type_errors
# ---------------------------------------------------------------------------
def test_verify_key_type_errors(key, workdir):
    sk, _, _ = key
    path = os.path.join(workdir, "r.sc.json")
    record_v2.save_signed_record(RECORD, path, sk)
    for bad in (None, sk):
        with pytest.raises(TypeError):
            record_v2.verify_record_file(path, bad)


# ---------------------------------------------------------------------------
# 16. test_records_cross_verify
#     v1 records (CRLF on Windows) verify under v2 and vice versa.
# ---------------------------------------------------------------------------
def test_records_cross_verify(key, workdir):
    sk, pk, _ = key
    p1 = os.path.join(workdir, "v1.sc.json")
    p2 = os.path.join(workdir, "v2.sc.json")
    record.save_signed_record(RECORD, p1, sk)
    record_v2.save_signed_record(RECORD, p2, sk)
    assert record_v2.verify_record_file(p1, pk) is True
    assert record.verify_record_file(p2, pk) is True

    crlf = os.path.join(workdir, "crlf.sc.json")
    with open(p2, "rb") as f:
        data = f.read().replace(b"\n", b"\r\n")
    with open(crlf, "wb") as f:
        f.write(data)
    assert record_v2.verify_record_file(crlf, pk) is True


# ---------------------------------------------------------------------------
# 17. test_import_from_any_cwd
# ---------------------------------------------------------------------------
def test_import_from_any_cwd(workdir):
    code = f"import sys; sys.path.insert(0, {HERE!r}); import record_v2"
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=workdir,
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
