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

The layer above the codec returns the same kind of answer - slices, not reconstructions:

```python
from asn1core import certificate_parts, spki_sha256

parts = certificate_parts(cert_der)        # raises CertificateError if it isn't one
parts.tbs_certificate                      # stored TLV: what the CA signature covers
parts.signature_algorithm                  # stored TLV
parts.signature_value                      # key octets, unused-bits octet removed
parts.subject_public_key_info              # stored TLV: what a pin is computed from
spki_sha256(cert_der)                      # hex digest of exactly those bytes
```

`tbsCertificate` opens with `version [0] EXPLICIT INTEGER DEFAULT v1`, so a v1 certificate omits
it and every field shifts. The walk skips that slot by tag, never by index: `root-rsa.der` in
`tests/fixtures/` is a real shipped root certificate that depends on this.

Dates are read the way RFC 5280 says, and names are compared the way it says:

```python
from asn1core import issuer, subject, validity, validity_encoding_issue, within

subject(cert_der).common_name        # str; RFC 4514 form via str(subject(cert_der))
subject(cert_der) == issuer(cert_der)  # §7.1 match: prepared values, RDN order significant
within(child_name, anchor_name)      # §7.1 subtree test, root-side prefix
validity(cert_der).not_before        # aware datetime: "960129000000Z" is 1996, §4.1.2.5.1
validity_encoding_issue(cert_der)    # §4.1.2.5 says a CA should have used UTCTime here
```

`validity_encoding_issue` answers rather than raises because one of the roots in a live trust
store - Certum Trusted Network CA 2 - spells its 2011 `notBefore` as GeneralizedTime. A decoder
that refused it would be wrong about the certificate and useless for the trust store.

One level up, the contents of a document, with the bytes still attached:

```python
from asn1core import parse_certificate, parse_crl

cert = parse_certificate(cert_der)
cert.serial                            # int; a non-positive one is parsed, not rejected
cert.version                           # 2 means v3; absent means v1, which is 0
cert.issuer == cert.subject            # Name equality, §7.1
cert.validity.not_after                # aware datetime
cert.extension("2.5.29.19").value      # the extension's OCTET STRING content, unparsed
cert.unrecognised_critical             # §4.2 says these cannot be ignored; deciding is pkix's job
cert.tbs_certificate                   # still the stored TLV, still what the signature covers

crl = parse_crl(crl_der)
crl.next_update                        # None when absent, which means something
crl.revoked[0].reason                  # 1 == keyCompromise; None means unspecified(0)
crl.revoked[0].compromised             # §6.1.4 applies to keyCompromise and cACompromise only
```

Fields are located by tag, never by index: `TBSCertificate` puts optional `issuerUniqueID [1]` and
`subjectUniqueID [2]` ahead of the extensions, and a CRL's `nextUpdate` and `revokedCertificates`
are both optional. A CRL's version also reads 1 where you might expect 2, because `Version` counts
from `v1(0)`.

Unknown tags survive decode-encode verbatim. Certificate extensions are the whole reason
this library is needed, and a codec that drops what it does not recognise defeats the point.

## Where the code came from

The module decomposition descends from the `ber` package of
[`snmpy`](https://github.com/b1tninja/snmpy) (MIT, © 2026 snmpy Contributors) - architecture
only. All seven defects measured in that codec are rewritten out of this one, each with a named
test that failed before the behaviour existed. The OID one is the instructive case: its
validation is a bare `assert`, so under `python -O` the invalid string `3.0` is accepted and
silently becomes `2.40`. Here it is a real check, and `2.5.29.19` - most of X.509 - encodes as
`55 1D 13` the way X.690 says rather than the way an earlier draft of this corpus claimed.

## Not yet implemented

Time, distinguished names, certificate and CRL structure, and the three end-to-end X.509 fixtures
in `VECTORS.md` are done. What is not:

- **RFC 4518 StringPrep in full.** Case folding, NFC, §2.6.1 space handling and the §7.1 matching
  rules are implemented; the Appendix A mapping tables, the prohibited-character set and the
  bidirectional checks are not. The subset is named in `name.py`'s docstring rather than called
  StringPrep, because claiming the whole name for part of the work is how a codec ends up deciding
  equality wrongly for input nobody tested.
- **PrintableString's restricted alphabet** (X.680 §40.4). Nothing in the store exercises it - zero
  PrintableStrings in 577 attribute values - and the defining text is not in the RFC library, so
  the check waits for the real alphabet instead of a guess that would reject shipped certificates.
- **Extension semantics and path validation.** This package reads an extension's payload and lists
  the unrecognised critical ones; interpreting them and applying RFC 5280 §6 is `pkix`'s job.
- The value types beyond what the corpus needs, and any form of general-purpose schema or `.asn`
  compilation.

`PLAN.md` records which of these gate Wave 1.
