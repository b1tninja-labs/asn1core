# asn1core: DER and X.509 codec

Status: **Tier 1, wave 1. Does not exist yet.** This is the extraction plan for the
ASN.1 codec that nine projects in `D:\code\PORTFOLIO.md` depend on and nothing in the
portfolio provides.

**Name.** This project was called `derkit` until 2026-11-05, and `derkit` returns 404 on
both PyPI signals. It is rejected anyway, because **seven live names sit one keystroke
away**: `dekit`, `depkit`, `deskit`, `detkit`, `devkit`, `verkit` and `werkit`. That check
ran against a snapshot of 931,439 canonical project names taken 2026-11-05
(`sdk-forge/names.py --index`); `asn1core` returns 404 with **no live neighbours**. The
portfolio rule is that a name must never be one edit from something live, and a name that
looks free because only the registry was consulted is a name nobody verified.

## Why this project exists

An earlier draft of the portfolio attached this role to `asnkit`. That was wrong:
`asnkit` is prefix-to-ASN lookup, a `pyasn` replacement, and shares nothing with ASN.1.
The consequence is that `pkix`, `ctspy`, `revokekit`, `enrollkit`, `signeddata`,
`pgpenv`, `shaken` and `certledger` all currently plan to parse certificates against a
substrate that does not exist.

## Source, and what is owed

`D:\code\snmpy` holds a 674-line, three-file, stdlib-only BER codec in a top-level `ber`
package with zero reverse dependencies. MIT, `Copyright (c) 2026 snmpy Contributors`, no
NOTICE or AUTHORS file, no vendored code and nothing in the packaging that names an
upstream project, so attribution is the MIT text plus that one line. Extraction is a
directory move and a rename.

Note before planning any upstream contribution: **`snmpy` has been a registered PyPI name
since 2016-09-03** ("Simple pysnmp wrapper", v1.0.0), so that repository does not own its
own name and cannot publish under it. This does not affect the extraction, which moves the
codec into a different and genuinely available name, but it does affect any idea of
shipping fixes back as `snmpy` releases.

The alternative to extraction is clean-room. Extraction is days; clean-room is weeks and
would spend that time rediscovering the same four defects.

## Defects that must be fixed, not moved

All four are catalogued with file and line in the 2026-11-05 inventory.

1. **High-tag-number decoding is wrong for every tag number above 30.** `ObjectTag.decode`
   mishandles the multi-byte 0x1F continuation, giving the wrong value and, for the
   universal and application classes, breaking framing entirely. Boundary cases 30, 31,
   63, 127, 128 and 16383 must each have a test. `ObjectTag.decode` has **no test
   coverage today.**
2. **`ObjectLength.encode` raises `OverflowError` at every exact power of 256** - 256,
   65536, 16777216 - which a 256-byte OCTET STRING hits trivially.
3. **Truncated input raises `IndexError`** instead of a named exception. A parser that
   escapes as an IndexError is a parser whose bounds checks vanish.
4. **Subclass-introspection dispatch** at `ber/object.py:492` is fragile in a way that
   matters the moment types are added, which is the entire point of this project.

Numbers 2 and 3 are availability bugs in a library whose job is to survive hostile input,
and 1 is a correctness bug that no test detects. That is the argument for extracting with
tests first rather than extraction as a copy.

## The one property that cannot be inherited

The codec **discards the original TLV bytes**, requiring re-encoding to recover them. For
a BER library serving SNMP that is a minor convenience loss. For certificate work it is
disqualifying: RFC 5280 section 4.1.3.2 requires a CA signature to be verified over the
DER encoding of the TBSCertificate, so verification against re-encoded bytes can only
succeed by luck. `certledger/TRUST-MODEL.md` records this as invariant I3, so
original-bytes retention is a requirement on the extraction, not an improvement to it.

Alongside it, the DER restrictions BER permits to slide: shortest-form lengths, definite
lengths only, no unused trailing bits in a BIT STRING, no redundant leading zero in an
INTEGER, and canonical ordering where a profile demands it. A `der` module that *rejects*
non-canonical encodings is the deliverable; a lenient BER decode is not enough to call
something DER.

## Specification spine

Statuses read from the RFC Editor on 2026-11-05.

| Document | Status | Published | Note |
|---|---|---|---|
| RFC 5280 (certificate and CRL profile) | Proposed Standard | 2008-05 | **6 verified errata**; obsoletes 3280, 4325, 4630; updated by nine later RFCs including 9549 and 9925. Section 4.1.3.2 is the clause that constrains this codec |
| ITU-T X.680 / X.690 | Recommendation, not an RFC | 2021 edition | The encoding rules live here; the RFC profile assumes them |

Being explicit that the normative source for DER is **not** an RFC matters: an agent told
to look it up in the RFC library will not find BER there, and inventing an RFC number for
X.690 is the kind of error this portfolio has already made more than once.

## Obligations

| Id | Spec | Status | Where | Evidence |
|---|---|---|---|---|
| `dk.tag-high` | X.690 sections 8.1.2-8.1.3 | [ ] | `der/tag` | `test_tag_boundaries` |
| `dk.length-shortest` | X.690 section 8.1.3.4 | [ ] | `der/length` | `test_non_shortest_length_rejected` |
| `dk.overflow` | X.690 section 8.1.3.5 | [ ] | `der/length` | `test_length_256_and_65536_encode` |
| `dk.raw-bytes` | RFC 5280 section 4.1.3.2 | [ ] | `der/node` | `test_original_tlv_is_retained` |
| `dk.integer` | X.690 section 8.3, RFC 5280 section 4.1.2.2 | [ ] | `der/integer` | `test_non_minimal_integer_rejected` |
| `dk.bitstring` | X.690 section 8.6.2 | [ ] | `der/bitstring` | `test_unused_bits_must_be_zero` |
| `dk.oid` | X.690 section 8.19 | [ ] | `der/oid` | `test_arc_over_127_and_first_two_arcs` |
| `dk.truncated` | X.690 section 8 | [ ] | `der/decode` | `test_truncated_input_raises_named_error` |
| `dk.time` | RFC 5280 section 4.1.2.5.1 | [ ] | `der/time` | `test_utc_time_epoch_and_generalized_only_after_2049` |
| `dk.name` | RFC 5280 section 4.1.2.4 | [ ] | `x509/name` | `test_rdn_order_and_value_encoding` |
| `dk.spki` | RFC 5280 section 4.1.2.7 | [ ] | `x509/spki` | `test_spki_hash_is_stable` |
| `dk.cert` | RFC 5280 sections 4.1-4.1.12 | [ ] | `x509/cert` | `test_parses_fixture_and_reports_extensions` |
| `dk.corpus` | `VECTORS.md` | [ ] | `tests/data` | `test_der_corpus` |

## Non-goals

- **No signature verification and no crypto.** Verification belongs to `pkix` and an
  optional extra; this is encoding, decoding and canonicalisation.
- **No general X.509 path building.** `pkix` is scoped to RFC 5280 section 6 validation
  and deliberately does not compete with `x509kit`, which is live at 0.10.0.
- **No BER leniency in the DER path.** Accepting both and calling it DER is how a
  database ends up with two keys for one certificate.

