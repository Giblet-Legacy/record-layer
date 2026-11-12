# record-layer — P7 Record

README.md — repository purpose and layer contract for P7 Record.

Function:
    This repository implements primitive layer P7 of the Forge Stack:
    signed record writing with passphrase-protected keys. It connects
    the cryptographic primitives to the filesystem.

Layer:    P7 — Record
Depends:  P1 Envelope v2, P2 Sign
Consumed: The Cockpit, SC-OS
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
Status:   2.0.0 (frozen). New code imports record_v2 (SPEC_V2.md);
          record.py is the frozen v1.0.0 primitive (SPEC.md).
