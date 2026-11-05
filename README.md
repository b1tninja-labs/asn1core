# asn1core

ASN.1 BER and DER codec in pure Python, with one property that the available options do not
have: **every decoded node keeps the exact octets it was parsed from**, so a signature can be
verified over the bytes it was actually made over.

Status: **pre-alpha, in progress.** The test suite describes the behaviour this package is
required to have; where a test fails, the behaviour is missing rather than broken
quietly. Nothing here is published, and no release claim is made.

## Why this exists

RFC 5280 §4.1.3.2 requires a CA signature to be verified over the DER encoding of the
`TBSCertificate`. A codec that parses, discards the original bytes and re-encodes can only
match that signature by luck - and a codec that *does* match it by luck will disagree with
the first peer whose encoder differs, which is the failure mode this package exists to make
impossible. `PLAN.md` carries the reasoning; `VECTORS.md` is the conformance corpus and the
exit test.

Nine projects in this portfolio are queued behind this one, which is the reason it is
Wave 1.

## Two paths, and the difference is the deliverable

- **BER** tolerates: non-minimal lengths, indefinite lengths, non-minimal integers,
  `01 01 02` as true.
- **DER** refuses all of that, **by name**. A refusal that silently re-encodes into
  canonical form is worse than an exception, because it lets one certificate occupy two
  rows in a database and turns a published count into a wrong number.

```python
from asn1core import decode, encode_der, validate_der

node, end = decode(raw)                    # BER: tolerant, keeps node.raw
node, end = decode(raw, der=True)          # DER: raises DerViolation on non-canonical
validate_der(raw)                          # assert a document is already canonical
assert encode_der(node) == node.raw        # canonical input round-trips byte-for-byte
```

Unknown tags survive decode-encode verbatim. Certificate extensions are the whole reason
this library is needed, and a codec that drops what it does not recognise defeats the point.

## Where the code came from

The module decomposition descends from the `ber` package of
[`snmpy`](https://github.com/b1tninja/snmpy) (MIT, © 2026 snmpy Contributors) - architecture
only. Six of the eight defects measured in that codec are rewritten out of this one, each with
a named test that failed before the behaviour existed. **The two that are not fixed here are
the OID pair:** defect 7 (an illegal first arc clamped instead of refused) and defect 8
(validation written as a bare `assert`, so under `python -O` an input of `3.0` is silently
accepted as `2.40`). Both stay open under obligation `dk.oid`, which is currently the most
security-relevant gap in this package. `NOTICE` carries the full MIT text.

## Not yet implemented

The value types beyond what the corpus needs, the three end-to-end X.509 fixtures in
`VECTORS.md`, and any form of general-purpose schema or `.asn` compilation. `PLAN.md` records
which of these gate Wave 1.
