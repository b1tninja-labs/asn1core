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
| 7 | **Validation is a bare `assert`, and the fallback rewrites the value** | `ObjectIdentifier.from_string("3.0")` and `("1.41")` raise `AssertionError` in normal execution, but under **`python -O`** both are *accepted* and silently become **`2.40`** and **`2.1`** | `sdk-forge/probe_oid_assert.py`, run both ways. The worst of the set: not a crash and not a rejection but a **different identity**, arriving quietly in exactly the optimised configuration a deployment is most likely to run |

| 8 | **The OID encoder writes bytes a conforming decoder reads as a different OID** | `bytes(ObjectIdentifier.from_string("2.100.3"))` is `b403`, and snmpy's decoder reads `b403` back as 2.100.3. X.690 reads it as **2.6579**, because `0xB4` carries the continuation bit and the pair is therefore one value: `(0x34 << 7) | 0x03 = 6659` | `sdk-forge/probe_oid_assert.py`. Same under `python -O` as not: this one is not an assert problem |
| 8b | *(how it hides)* | snmpy's own test suite passes, because its encoder and decoder are wrong in matching directions | the reason a green test suite is not evidence of conformance - only a second, independent decoder catches it |

**A row that was here and has been withdrawn.** An earlier draft of this table listed an eighth
defect: "illegal OID first octet silently repaired - `06 02 7F 01` should be refused, not read
as 2.47.1", because `0x7F` implies a first arc of 3 and arcs above 2 are not permitted. That is
**wrong**, and the evidence is in any certificate: 61 of the root certificates in the local
trust store encode `2.5.29.19` as `06 03 55 1D 13`, and 0x55 is 85 = 40*2 + 5. X.690 8.19
reserves the range 80-127 of the first content octet for a first arc of exactly 2, so
`0x7F` legitimately means `2.47` and snmpy's `min(2, octet // 40)` paired with `octet - 80` is
the *correct* rule, not a clamp into legality. Row 7 above stands on its own evidence: the
string `3.0` really is invalid and really does become `2.40` under `-O`.

Had that row been implemented as written, the DER path would have refused the first content
octet of every `2.5.29.x` extension and every `2.5.4.x` X.500 attribute - which is to say,
nearly every certificate in existence. It is recorded here rather than quietly edited out
because the failure was not arithmetic, it was reasoning from a half-remembered clause about
arc limits, and that class of error is invisible until someone checks it against real data.

The first six rows are unchanged under `python -O`: the codec's `assert not (length >> 128)`
at `object.py:143` is not load-bearing for any case the probe exercised, so the honest claim
about it is "not demonstrated", not "harmless". **Row 7 is the opposite case and it was found
by running the probe twice.** Read together, the two say something sharper than either: an
assert that happens to be unnecessary in one path is invisible, while an assert in another path
is load-bearing and silently removed - so "the suite passed under `-O`" only ever proves
something about the paths the suite reaches.

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

`[x]` means a test with that exact name passes today, 2026-11-05. The `dk.` prefix is a
survivor of this project's first name; it is kept so that references written elsewhere do not
rot, and it carries no meaning.

| Id | Spec | Status | Where | Evidence |
|---|---|---|---|---|
| `dk.tag-high` | X.690 sections 8.1.2-8.1.3 | [x] | `tag.py` | `test_high_tag_number_decodes_and_round_trips`, `test_tag_class_and_constructed_bits_are_isolated_not_or_ed` |
| `dk.length-shortest` | X.690 section 8.1.3.4 | [x] | `length.py` | `test_nonminimal_length_accepted_by_ber_refused_by_der` |
| `dk.overflow` | X.690 section 8.1.3.5 | [x] | `length.py` | `test_length_encode_is_exact_at_every_power_of_256`, `test_length_overflow_is_a_named_error_not_an_allocation` |
| `dk.raw-bytes` | RFC 5280 section 4.1.3.2 | [x] | `node.py` | `test_original_bytes_survive_a_noncanonical_parse` |
| `dk.integer` | X.690 section 8.3, RFC 5280 section 4.1.2.2 | [x] | `der.py` | `test_minimal_integers_are_accepted`, `test_nonminimal_integer_is_refused_without_being_normalised` |
| `dk.bitstring` | X.690 section 8.6.2 | [x] | `der.py` | `test_bit_string_content_rules` |
| `dk.boolean` | X.690 section 8.5 | [x] | `der.py` | `test_boolean_content_rules` |
| `dk.setof` | X.690 section 11.6 | [x] | `der.py` | `test_set_of_ordering_is_enforced_on_the_der_path` |
| `dk.truncated` | X.690 section 8 | [x] | `node.py` | `test_truncated_input_raises_a_named_error` covers all seven error rows |
| `dk.depth` | this package's own bound | [x] | `node.py` | `test_depth_is_bounded_by_a_named_error` |
| `dk.no-asserts` | SECURITY.md rule 3 | [x] | whole package | `test_library_contains_no_assert_statements` |
| `dk.roundtrip` | `VECTORS.md` properties | [x] | `node.py` | `test_canonical_document_round_trips_byte_for_byte`, `test_unknown_tags_survive_decode_and_encode`, `test_repeated_children_stay_distinct_nodes` |
| `dk.crosscheck` | the second opinion `VECTORS.md` owes | [x] | `tools/crosscheck_store.py` | 75 trust-store certificates, 868,500 bytes, **zero failures** parsing on the DER path and re-encoding byte-identically (2026-11-05). Coverage limit stated in `VECTORS.md`: those documents use context tags below 31 and definite lengths only, so this does not exercise the high-tag-number or indefinite-length paths |
| `dk.indefinite` | X.690 section 8.1.3.4 | **partial** | `node.py` | `test_indefinite_terminator_is_not_searched_for_inside_content` proves the constructed case. Primitive indefinite content is refused with a named error because the corpus row is unresolved - not implemented, and not guessed |
| `dk.oid` | X.690 section 8.19 | [x] | `oid.py`, wired into `node._der_value_check` for tag 6 | `tests/test_oid_corpus.py`: the 13 corpus vectors encode and decode byte-exactly, `3.0` and `1.41` raise rather than becoming `2.40` under `-O`, and `test_library_contains_no_assert_statements` keeps it that way. **Closed 2026-11-05**; the 75-certificate trust-store cross-check passes with the OID check active, which is the second opinion that the retracted first-arc rule never got |
| `dk.time` | RFC 5280 section 4.1.2.5.1 | [x] | `time.py`, wired into `node._der_value_check` for tags 23 and 24; `x509.validity` | `tests/test_time_corpus.py`: the century rule tested for all 100 values of `YY`, both types round-trip byte-exactly, 25 forbidden forms refuse by name, and the two vendored roots read the same dates `cryptography` reads. `tools/crosscheck_x509.py`: **75/75 validity dates agree, and zero shipped certificates are refused by the strict reader** (2026-11-05) - which is what decided that §4.1.2.5's 2049 boundary is reported by `validity_encoding_issue` rather than enforced in the decoder, since one trust anchor (Certum Trusted Network CA 2) spells 2011 as GeneralizedTime |
| `dk.name` | RFC 5280 section 4.1.2.4 | [ ] | not written | RDN handling, needs the SET OF fixture |
| `dk.spki` | RFC 5280 section 4.1.2.7 | [x] | `x509.py` | `tests/test_x509_corpus.py` (two vendored roots, digests frozen from `cryptography`) plus `tools/crosscheck_x509.py`: **75 trust-store certificates, `tbsCertificate` and `signatureValue` byte-identical to `cryptography` on every one, SPKI identical on the 74 it can serialise, zero failures** (2026-11-05). One root's key material `cryptography` cannot re-serialise at all, which is recorded rather than hidden |
| `dk.cert` | RFC 5280 sections 4.1-4.1.12 | [ ] | not written | blocked on the three end-to-end fixtures |
| `dk.corpus` | `VECTORS.md` | partial | `tests/` | 87 tests pass; every `[verify against X.690]` row is still open |

## Non-goals

- **No signature verification and no crypto.** Verification belongs to `pkix` and an
  optional extra; this is encoding, decoding and canonicalisation.
- **No general X.509 path building.** `pkix` is scoped to RFC 5280 section 6 validation
  and deliberately does not compete with `x509kit`, which is live at 0.10.0.
- **No BER leniency in the DER path.** Accepting both and calling it DER is how a
  database ends up with two keys for one certificate.

