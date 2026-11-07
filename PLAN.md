# asn1core: DER and X.509 codec

Status: **Tier 1, wave 1. Implemented, not published** (2026-11-07): 439 tests pass with and
without `python -O`, coverage 90%, 22 of 23 obligation rows `[x]` and 1 `[part]`. This began as
the extraction plan for the ASN.1 codec that nine projects in `D:\code\PORTFOLIO.md` depend on
and nothing else in the portfolio provides; the sections below keep that plan as the record of
why the code is shaped the way it is.

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
**`sdk-forge/probe_ber.py`** - deleted in `sdk-forge@e39ac38` by a sweep that did not check inbound citations; `git -C sdk-forge show e39ac38^:probe_ber.py` - runs the
encodings from `VECTORS.md` against the real module and prints expected-versus-observed for
32 cases (measured 2026-11-05; read-only, and snmpy is a git repository with 64 uncommitted
files of unrelated work, so nothing here touches it).

## Defects that must be fixed, not moved

Eight classes, each reproduced by execution, and all eight are fixed in this package. Both probes,
`probe_ber.py` (rows 1-6) and `probe_oid_assert.py` (rows 7 and 8), were deleted in `sdk-forge@e39ac38`;
`git -C D:/code show e39ac38^:sdk-forge/<name>` recovers either.

| # | Defect | Measured | Basis |
|---|---|---|---|
| 1 | High-tag-number decode wrong for every tag above 30 | `9f1f`->**3999**, `9f8100`->**508032**, `9fff7f`->**524287**, `9f818000`->**65028096**. `__bytes__` encodes all four **correctly**, so encode and decode disagree and round-trip fails at 31, 63, 127, 128, 16383, 16384 | probe, and a trace of `object.py:91-98`: the shift is applied *after* the OR, and the `while ... else` whose `else` always runs re-ORs the terminal octet |
| 2 | Length encode crashes at every exact power of 256 | `OverflowError` at 256, 65536, 16777216; 255 and 65535 are fine | probe; cause is `ceil(log2(n)/8)` at `object.py:147`, which yields `k` rather than `k+1` at `256**k`, and uses float log for an integer boundary |
| 3 | Truncated input escapes as `IndexError` | a lone `9f` raises `IndexError`, not a domain error | probe |
| 4 | Framing is never validated | `04044141` (declares 4 content bytes, supplies 2) returns next offset **6** from a 4-byte buffer; `3006040441` returns **8** from 5; a constructed indefinite object with no EOC returns **4** from 7 | probe: `stop_octet = offset + octet_length` is never compared to the buffer, and Python slicing truncates silently, so a caller trusting the returned offset walks past the end |
| 5 | Indefinite length terminates on *content*, not on EOC | `04 80 41 00 00 42 00 00` decodes as length **1** where the answer is **4** | probe; `buffer.index(b"\0\0")` at `object.py:164` finds the first NUL pair inside the data. Two consecutive zero bytes are everywhere - zero-padded integers, zero OID arcs, addresses - so this desyncs the whole parse rather than mis-sizing one object |
| 6 | Original TLV bytes are unrecoverable | `02 81 01 00` decodes, then re-encodes as `02 01 00` | probe; this is the I3 blocker below |
| 7 | **Validation is a bare `assert`, and the fallback rewrites the value** | `ObjectIdentifier.from_string("3.0")` and `("1.41")` raise `AssertionError` in normal execution, but under **`python -O`** both are *accepted* and silently become **`2.40`** and **`2.1`** | `sdk-forge/probe_oid_assert.py`, run both ways. The worst of the set: not a crash and not a rejection but a **different identity**, arriving quietly in exactly the optimised configuration a deployment is most likely to run |
| 8 | **The OID encoder writes bytes a conforming decoder reads as a different OID** | `bytes(ObjectIdentifier.from_string("2.100.3"))` is `b403`, and snmpy's decoder reads `b403` back as 2.100.3. X.690 reads it as **2.6579**, because `0xB4` carries the continuation bit and the pair is therefore one value: `(0x34 << 7) | 0x03 = 6659` | `sdk-forge/probe_oid_assert.py`. Same under `python -O` as not: this one is not an assert problem. **How it hides:** snmpy's own test suite passes, because its encoder and decoder are wrong in matching directions - the reason a green test suite is not evidence of conformance, and why only a second, independent decoder catches it |

**A row that was here and has been withdrawn.** An earlier draft of this table listed a
defect that row 8 does not replace: "illegal OID first octet silently repaired - `06 02 7F 01` should be refused, not read
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
disqualifying: RFC 5280 section 4.1.1.3 requires a CA signature to be verified over the
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
| RFC 5280 (certificate and CRL profile) | Proposed Standard | 2008-05 | **6 verified errata**; obsoletes 3280, 4325, 4630; updated by nine later RFCs including 9549 and 9925. Section 4.1.1.3 (signatureValue: the signature is computed upon the DER-encoded tbsCertificate) is the clause that constrains this codec. This plan cited it as 4.1.3.2 until 2026-11-07; RFC 5280 has no section 4.1.3 (outline read through rfclib) |
| ITU-T X.680 / X.690 | Recommendation, not an RFC | 2021 edition | The encoding rules live here; the RFC profile assumes them |

Being explicit that the normative source for DER is **not** an RFC matters: an agent told
to look it up in the RFC library will not find BER there, and inventing an RFC number for
X.690 is the kind of error this portfolio has already made more than once.

## Obligations

`[x]` means a test with that exact name passes (re-run 2026-11-07); `[part]` means part of the row is
proven and the cell names what is still missing. The `dk.` prefix is a
survivor of this project's first name; it is kept so that references written elsewhere do not
rot, and it carries no meaning.

| Id | Spec | Status | Where | Evidence |
|---|---|---|---|---|
| `dk.tag-high` | X.690 sections 8.1.2-8.1.3 | [x] | `tag.py` | `test_high_tag_number_decodes_and_round_trips`, `test_tag_class_and_constructed_bits_are_isolated_not_or_ed` |
| `dk.length-shortest` | X.690 section 8.1.3.4 | [x] | `length.py` | `test_nonminimal_length_accepted_by_ber_refused_by_der` |
| `dk.overflow` | X.690 section 8.1.3.5 | [x] | `length.py` | `test_length_encode_is_exact_at_every_power_of_256`, `test_length_overflow_is_a_named_error_not_an_allocation` |
| `dk.raw-bytes` | RFC 5280 section 4.1.1.3 | [x] | `node.py` | `test_original_bytes_survive_a_noncanonical_parse` |
| `dk.integer` | X.690 section 8.3, RFC 5280 section 4.1.2.2 | [x] | `der.py` | `test_minimal_integers_are_accepted`, `test_nonminimal_integer_is_refused_without_being_normalised` |
| `dk.bitstring` | X.690 section 8.6.2 | [x] | `der.py` | `test_bit_string_content_rules` |
| `dk.boolean` | X.690 section 8.5 | [x] | `der.py` | `test_boolean_content_rules` |
| `dk.setof` | X.690 section 11.6 | [x] | `der.py` | `test_set_of_ordering_is_enforced_on_the_der_path` |
| `dk.truncated` | X.690 section 8 | [x] | `node.py` | `test_truncated_input_raises_a_named_error` covers all seven error rows |
| `dk.depth` | this package's own bound | [x] | `node.py` | `test_depth_is_bounded_by_a_named_error` |
| `dk.no-asserts` | SECURITY.md rule 3 | [x] | whole package | `test_library_contains_no_assert_statements` |
| `dk.roundtrip` | `VECTORS.md` properties | [x] | `node.py` | `test_canonical_document_round_trips_byte_for_byte`, `test_unknown_tags_survive_decode_and_encode`, `test_repeated_children_stay_distinct_nodes` |
| `dk.crosscheck` | the second opinion `VECTORS.md` owes | [x] | `tools/crosscheck_store.py` | 75 trust-store certificates, 868,500 bytes, **zero failures** parsing on the DER path and re-encoding byte-identically (2026-11-05). Coverage limit stated in `VECTORS.md`: those documents use context tags below 31 and definite lengths only, so this does not exercise the high-tag-number or indefinite-length paths |
| `dk.indefinite` | X.690 section 8.1.3.4; section 8.1.3.2 a) for the primitive case | [x] | `node.py` | `test_indefinite_terminator_is_not_searched_for_inside_content` proves the constructed case. The primitive case is cited rather than guessed: X.690 (02/2021) §8.1.3.2 a) requires a **sender** to use the definite form when the encoding is primitive, and §7.1 dynamic conformance gives a receiver no licence to accept what no conforming sender may emit (re-read via `python -m itulib.cli read X.690 8.1.3.2` on 2026-11-11; `VECTORS.md` `len-indefinite` records the same resolution). The named test exists: `tests/test_defect_corpus.py::test_primitive_indefinite_length_is_refused` — BER raises `DecodeError`, DER raises `DerViolation` (rule `indefinite-length`), both at offset 1, the length octet that makes the encoding illegal. Not vacuous, and measured: the constructed analogue `30 80 05 00 00 00` parses to offset 6 with one child `05 00`, so the primitive refusal is the guard rather than the parser failing on the input. |
| `dk.oid` | X.690 section 8.19 | [x] | `oid.py`, wired into `node._der_value_check` for tag 6 | `tests/test_oid_corpus.py`: the 13 corpus vectors encode and decode byte-exactly, `3.0` and `1.41` raise rather than becoming `2.40` under `-O`, and `test_library_contains_no_assert_statements` keeps it that way. **Closed 2026-11-05**; the 75-certificate trust-store cross-check passes with the OID check active, which is the second opinion that the retracted first-arc rule never got |
| `dk.time` | RFC 5280 section 4.1.2.5.1 | [x] | `time.py`, wired into `node._der_value_check` for tags 23 and 24; `x509.validity` | `tests/test_time_corpus.py::test_the_century_rule_is_exhaustive_not_sampled`, and across `tests/test_time_corpus.py`: the century rule tested for all 100 values of `YY`, both types round-trip byte-exactly, 25 forbidden forms refuse by name, and the two vendored roots read the same dates `cryptography` reads. `tools/crosscheck_x509.py`: **75/75 validity dates agree, and zero shipped certificates are refused by the strict reader** (2026-11-05) - which is what decided that §4.1.2.5's 2049 boundary is reported by `validity_encoding_issue` rather than enforced in the decoder, since one trust anchor (Certum Trusted Network CA 2) spells 2011 as GeneralizedTime |
| `dk.name` | RFC 5280 section 4.1.2.4 | [x] | `name.py`, exposed as `x509.issuer()` / `x509.subject()` | `tests/test_name_corpus.py::test_renderings_match_an_independent_implementation`, and across `tests/test_name_corpus.py`: RFC 4518 §2.6.1's own worked example, all ten string types decoded by their own codecs, RDN-set pairing without reuse, encoding-order and match-order pinned both ways, and six malformed shapes refused. `tools/crosscheck_x509.py`: **all 150 names in 75 shipped certificates render byte-identically to `cryptography`'s RFC 4514 output, with zero refusals** (2026-11-05) |
| `dk.stringprep` | RFC 4518 sections 2.1-2.6 | [x] | `stringprep.py`, driving `name.normalize_value` | **Closed 2026-11-05.** `tests/test_stringprep_corpus.py`: 18 code points mapped to nothing and 12 to SPACE, each from the §2.2 list; the RFC's own §2.6.1 example (`"foo bar  "` to `" foo  bar "`) and the single-inner-run-becomes-two rule; the marked-space refinement of ¶1; Map-before-Normalize demonstrated with U+2126; every §2.4 table named (`C.3`, `C.4`, `C.5`, `C.8`, the replacement character); and `stringprep.py` at 100% branch coverage. **Erratum 860 is load-bearing** - §2.2 prints the variation-selector range as `FF00-FE0F`, and the corrected `FE00-FE0F` is what the code uses; the printed text would have deleted every fullwidth character from a name, which is how CJK values are spelled, so `test_fullwidth_forms_survive_the_map_where_the_printed_text_would_have_deleted_them` pins it. Two recorded corrections to the plan's own row: **§2.5 is not a check** ("Bidirectional characters are ignored"), so no bidi rule was missing; and **§2 pins the repertoire to Unicode 3.2**, whose Table A.1 calls 59,842 now-assigned code points unassigned - including U+0237, an ordinary letter - so `prepare_value` defaults to current data and offers `unassigned="pinned"` for the literal reading. The strict gate lives in `prepare_value`/`preparation_issues`; `normalize_value` stays total so that no shipped certificate stops matching its own spelling. Measured over the store: **577 attribute values, 0 refused under either repertoire**, and the 150-name rendering agreement with `cryptography` is unchanged |
| `dk.printable-charset` | X.680 (02/2021) §41.4 Table 10 (this row once cited §40.4; clause 40 of that edition ends at 40.3, confirmed with itulib 2026-11-07) | [x] | `der.check_printable_string`, wired at `node._der_value_check` tag 19 | `tests/test_structure_corpus.py::test_printable_string_permitted_alphabet_is_exactly_table_10` (74 characters, cardinality pinned) and `::test_printable_string_outside_table_10_is_refused_by_rule_on_the_der_path_only` (`@`, `&`, `_`, `é`: DER refuses under the named rule, BER keeps the octets). Closed 2026-11-07 once `D:\code\itulibrary` reached the recommendation. Measuring the store first was the precondition, and it overturned the row's own evidence: **520 of 577 attribute values are PrintableString**, not zero - the earlier count came from a tag table that numbered the 18-22 band four places low - and all 520 fall inside Table 10, so enforcing it refuses nothing that ships |
| `dk.spki` | RFC 5280 section 4.1.2.7 | [x] | `x509.py` | `tests/test_x509_corpus.py::test_the_extracted_digests_match_an_independent_implementation` (two vendored roots, digests frozen from `cryptography`) plus `tools/crosscheck_x509.py`: **75 trust-store certificates, `tbsCertificate` and `signatureValue` byte-identical to `cryptography` on every one, SPKI identical on the 74 it can serialise, zero failures** (2026-11-05). One root's key material `cryptography` cannot re-serialise at all, which is recorded rather than hidden |
| `dk.cert` | RFC 5280 sections 4.1-4.1.12 | [x] | `cert.py`, `crl.py`, and the shared `x509.signed_document_parts` | **Closed 2026-11-05.** `tests/test_cert_corpus.py::test_padded_r_survives_the_codec`, with the rest of `tests/test_cert_corpus.py`, covers the padded-`r` signature and what stripping that zero would have done to the number, the CRL's keyCompromise entry beside an entry with no reason at all, `critical`'s DEFAULT-FALSE absence, extensions located past an `issuerUniqueID`, and the tagged/untagged split between `crlExtensions` and `crlEntryExtensions`. Against the store: certificate contents (serial, version, signature algorithm, extension list with flags) agree with `cryptography` on 75/75, and **67 self-issued certificates verify their CA signature over asn1core's stored `tbsCertificate` slice**, 0 failures; the CRL verifies over its own `tbsCertList` slice. What is *not* here: §4.2 extension semantics and §6 path validation, which belong to `pkix` |
| `dk.corpus` | `VECTORS.md` | [part] | `tests/` | **440 cases** pass (re-counted 2026-11-11, 158 `def test_` in 11 files), counted by `pytest -q` with and without `-O`, coverage floor 85 met at 90%. **No row carries `[verify against X.690]` or `[verify against X.680]` any more**: all nine were retired on 2026-11-07 against `Rec. ITU-T X.690 (02/2021)` and `Rec. ITU-T X.680 (02/2021)`, fetched and indexed by `D:\code\itulibrary`. One of the nine recorded a rule that does not exist (X.680 §47.3 bounds UTCTime seconds at 00-59), and the same pass exposed the DN tag-numbering defect fixed alongside it. Still owed: negative vectors from a second implementation - `cryptography` now supplies one for the DN tags, and `tools/crosscheck_store.py` supplies 75 real documents |
| `dk.pem` | RFC 7468 section 3 (ABNF), section 5.1 (certificates), section 13 (SPKI), appendix A (non-conforming examples) and appendix B (DER expectations); **erratum 4508** | [x] | `pem.py` | `test_appendix_a_examples_parse_and_keep_their_labels`, `test_boundaries_are_case_sensitive_per_erratum_4508`, `test_dash_count_is_exactly_five`, `test_no_header_region`, `test_extra_space_belongs_to_the_label`, `test_non_canonical_base64_is_accepted_and_marked`, `test_seventy_six_character_wrapping_is_not_strict`, `test_label_mismatch_between_boundaries`, `test_every_admitted_line_ending`, `test_strict_roundtrip_of_every_fixture` (17 tests in `tests/test_pem_corpus.py`) | **Written 2026-11-05.** §3's three grammars are `mode="strict"|"standard"|"lax"` (Figures 3, 1, 2), and the module decodes the *container* only: it hands back payload octets plus the exact armour text (`Block.der`, `Block.raw`, `Block.encapsulated`) and never interprets them, because a label that gets trusted on the bytes' behalf is the failure §2 ¶4 warns about. Erratum 4508 is implemented as written: boundaries are `%s` literals, so `-----begin` is not a boundary in any mode and §2 ¶1 turns that into *no blocks found* rather than an error. Appendix A's four examples are vendored verbatim as the negative corpus, which settles the case-sensitivity question the way the appendix intends - by interop, not by opinion - and they parse under their own labels while `certificates()` refuses to fold them onto `CERTIFICATE`. Appendix B's DER expectation stays where it belongs: the caller passes `block.der` to `decode(..., der=True)`, and `tools/crosscheck_pem.py` does exactly that over **75 operating-system certificates (86,850 octets, 43 with a padded final group, 1,994 armour lines) with zero failures**, including CRLF/CR spellings and the 76-character wrapping that OpenSSL emits and Figure 3 refuses. What follows was the finding at filing time. The package has **no armour support at all** - `git grep -i pem` over `*.py` returns nothing - so it can read a DER file and cannot read the format most of the world ships. Every trust-anchor source is armoured: curl's `cacert.pem`, Android's one-PEM-per-file directory, CCADB's PEM-in-CSV report, macOS `security trust-settings-export`. Three decisions the row exists to pin down, not to guess at: **erratum 4508 makes the encapsulation boundaries case-sensitive** (`%s"-----BEGIN "` per RFC 7405) because nearly all implementations enforce that on input and emit all-caps, so accepting `-----begin` would disagree with the ecosystem while refusing it would reject files in the wild - appendix A is the negative corpus that settles it; **appendix B pins that the base64 decodes to DER**, which is what keeps `dk.spki` hashes derived from stored bytes rather than re-encoded ones; and labels must be dispatched, not assumed, since a bundle mixes `CERTIFICATE` with `PUBLIC KEY` (section 13) and X9.42 forms. Not scheduled: this is the first SDK gap `trustatlas/PLAN.md` names, and adding it here does not move this project's wave - that call belongs to `PORTFOLIO.md` section 9 item 9 |

## Non-goals

- **No signature verification and no crypto.** Verification belongs to `pkix` and an
  optional extra; this is encoding, decoding and canonicalisation.
- **No general X.509 path building.** `pkix` is scoped to RFC 5280 section 6 validation
  and deliberately does not compete with `x509kit`, which is live at 0.10.0.
- **No BER leniency in the DER path.** Accepting both and calling it DER is how a
  database ends up with two keys for one certificate.

