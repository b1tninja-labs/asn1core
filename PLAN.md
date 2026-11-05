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

The alternative to extraction is clean-room. That choice used to rest on a guess about how
much of the codec would survive. It no longer does: **`sdk-forge/probe_ber.py`** runs the
encodings from `VECTORS.md` against the real module and prints expected-versus-observed for
32 cases (measured 2026-11-05; read-only, and snmpy is a git repository with 64 uncommitted
files of unrelated work, so nothing here touches it).

## Defects that must be fixed, not moved

Seven classes, each reproduced by execution.

| # | Defect | Measured | Basis |
|---|---|---|---|
| 1 | High-tag-number decode wrong for every tag above 30 | `9f1f`->**3999**, `9f8100`->**508032**, `9fff7f`->**524287**, `9f818000`->**65028096**. `__bytes__` encodes all four **correctly**, so encode and decode disagree and round-trip fails at 31, 63, 127, 128, 16383, 16384 | probe, and a trace of `object.py:91-98`: the shift is applied *after* the OR, and the `while ... else` whose `else` always runs re-ORs the terminal octet |
| 2 | Length encode crashes at every exact power of 256 | `OverflowError` at 256, 65536, 16777216; 255 and 65535 are fine | probe; cause is `ceil(log2(n)/8)` at `object.py:147`, which yields `k` rather than `k+1` at `256**k`, and uses float log for an integer boundary |
| 3 | Truncated input escapes as `IndexError` | a lone `9f` raises `IndexError`, not a domain error | probe |
| 4 | Framing is never validated | `04044141` (declares 4 content bytes, supplies 2) returns next offset **6** from a 4-byte buffer; `3006040441` returns **8** from 5; a constructed indefinite object with no EOC returns **4** from 7 | probe: `stop_octet = offset + octet_length` is never compared to the buffer, and Python slicing truncates silently, so a caller trusting the returned offset walks past the end |
| 5 | Indefinite length terminates on *content*, not on EOC | `04 80 41 00 00 42 00 00` decodes as length **1** where the answer is **4** | probe; `buffer.index(b"\0\0")` at `object.py:164` finds the first NUL pair inside the data. Two consecutive zero bytes are everywhere - zero-padded integers, zero OID arcs, addresses - so this desyncs the whole parse rather than mis-sizing one object |
| 6 | Original TLV bytes are unrecoverable | `02 81 01 00` decodes, then re-encodes as `02 01 00` | probe; this is the I3 blocker below |
| 7 | Illegal OID first octet is silently repaired | `06 02 7f 01` -> **2.47.1** instead of a refusal; `06 01 4f` -> **1.39**, correct, which confirms the corpus row | probe; `min(2, octet // 40)` at `object.py:244` clamps instead of rejecting |

Run under `python -O` the table is unchanged: the codec's `assert not (length >> 128)` at
`object.py:143` is not load-bearing for any case here. It still does not license asserts for
bounds in asn1core, but the claim is "not demonstrated", not "harmless".

Three consequences that change this plan. **The compatibility surface is not the one I
assumed:** `snmp/`, `snmpy/` and `examples/` import `ber` in **47 places across 31 files**,
so it cannot be lifted out - snmpy keeps its copy permanently, which means fixing asn1core
does not fix snmpy and an upstream pull request is a courtesy with a small audience rather
than a dependency. **`ber` is not generic:** `ber/enums.py` hard-codes SMIv2 application tags
(RFC 1902) in a package that otherwise presents itself as ASN.1, and that enum must not be
inherited. **And my earlier claim that framing "breaks entirely for the universal and
application classes" was reasoning, not measurement:** what is demonstrated is wrong tag
values above 30 in every class, plus the framing failures in rows 4 and 5.

So extraction is not "copy 674 lines and patch four spots". The tag decoder, length encoder,
indefinite-length handling, framing checks and OID arc validation all get rewritten, and
raw-byte retention is added to every node. What actually transfers is the **shape**: the
`Object` / `ObjectTag` / `ObjectLength` decomposition, the value-class hierarchy, the file
boundary, and snmpy's 6 existing tests as a regression floor. The honest form of the decision
is therefore *extract the architecture, write the behaviour from the corpus* - cheaper than
clean-room, and clear about what is inherited.

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

