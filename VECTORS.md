# asn1core conformance corpus

Status: **specification for wave 1's exit test.** `asn1core` cannot be called done until
every case here passes, in both directions where the case has both. This file exists
because the defect inventory found a high-tag-number bug with **zero test coverage**, and a
codec tested only on the tags that SNMP happens to use is a codec that will fail the first
time it meets a real certificate.

## Why these particular cases

The seven defect classes measured in `PLAN.md` are all boundary cases, and boundary cases are
where a decoder that "works" in practice is wrong:

| Case class | The defect it would have caught |
|---|---|
| Tag numbers at and above 31 | `ObjectTag.decode` mis-decodes the multi-byte 0x1F continuation for **every** tag above 30 (`9f1f` becomes 3999), while `__bytes__` encodes the same value correctly - so encode and decode disagree |
| Lengths at exact powers of 256 | `ObjectLength.encode` raises `OverflowError` at 256, 65536 and 16777216 |
| Truncated input anywhere | escapes as `IndexError` rather than a named parse error |
| Non-minimal encodings | BER tolerates them, DER does not; silently tolerating them is how one certificate ends up with two database keys |

Normative sources are **ITU-T X.680 and X.690**, not the RFC series - the RFC library has
nothing to say about BER. Where a rule below is stated from knowledge of X.690 rather than
from a retrieved copy of the text, it is marked `[verify against X.690]`. That marking is
not hedging for its own sake: `asn1core` will live or die on whether its DER restrictions
are the actual DER restrictions, and an invented clause is worse than an untested one.

## Tag encoding

| Id | Bytes | Expected | Notes |
|---|---|---|---|
| `tag-u-12-seq` | `30 00` | universal 16, constructed, empty | the ordinary case; must round-trip |
| `tag-u-01-int` | `02 01 00` | universal 1, INTEGER 0 | |
| `tag-c-05` | `A5 00` | context 5, constructed | `0xA5` = class bits `10` (context), constructed bit `1`, number bits `00101` = 5 |
| `tag-c-30` | `9E 00` | context 30, primitive, empty | `0x9E` = class bits `10` (context), constructed bit `0`, number bits `11110` = 30 - **the highest tag number encodable in one octet**, since `11111` means "continuation follows" |
| `tag-c-31` | `9F 1F 01 00` | context 31, primitive, length 1 | **first two-octet tag**; a decoder that adds 31 instead of reading the continuation fails here |
| `tag-c-63` | `9F 3F 00` | context 63 | boundary of the 6-bit field |
| `tag-c-127` | `9F 7F 00` | context 127 | last value encodable in one continuation octet |
| `tag-c-128` | `9F 81 00 00` | context 128 | **first value needing two continuation octets**; base-128 with the high bit as continuation flag |
| `tag-c-16383` | `9F FF 7F 00` | context 16383 | last two-octet continuation value |
| `tag-c-16384` | `9F 81 80 00 00` | context 16384 | three continuation octets |
| `tag-a-9999` | `5F CE 0F 00` | application 9999, **primitive** | `9999 = 78*128 + 15`, so the continuation octets are `CE 0F`. **The constructed bit here is 0, and that is not an accident**: a high tag number needs `11111` in the low five bits, so the only bit left for constructed-ness is bit 5, which makes the *constructed* application form `7F CE 0F 00`. Both spellings are tested, because a decoder that ORs the class bits with the number bits instead of masking them gets exactly this wrong, and the application class is one of the two where framing broke outright in snmpy |
| `tag-p-1` | `C1 01 00` | private 1, primitive | class bits `11` primitive give `0xC1`. Writing `0x81` here would silently make it a *context* tag, which is exactly the kind of off-by-two-bits error this corpus exists to catch |
| `tag-nonminimal` | `9F 80 01 00` | **reject as DER** | continuation octet `0x80` encodes a leading zero; X.690 (02/2021) §8.1.2.4.2 c) forbids it in terms: bits 7 to 1 of the first subsequent octet shall not all be zero, which is exactly `0x80` in a leading continuation octet. Read 2026-11-07 via `itulib read X.690 8.1.2.4`. BER permits it, so the BER path must accept and the DER path must refuse |

## Length encoding

| Id | Bytes | Expected | Notes |
|---|---|---|---|
| `len-short-max` | `04 7F` + 127 bytes | OCTET STRING, 127 | last short-form length |
| `len-long-128` | `04 81 80` + 128 bytes | 128 | first long form |
| `len-long-255` | `04 81 FF` + 255 bytes | 255 | |
| `len-long-256` | `04 82 01 00` + 256 bytes | 256 | **the OverflowError case on encode** |
| `len-long-65536` | `04 83 01 00 00` + 65536 bytes | 65536 | **second OverflowError case** |
| `len-nonminimal` | `04 81 7F` + 127 bytes | **reject as DER** | long form for a length that fits short form; forbidden by X.690 (02/2021) §10.1, which requires the definite form encoded in the minimum number of octets - 127 spelled in long form is not minimal. Read 2026-11-07 via `itulib read X.690 10.1` |
| `len-leading-zero` | `04 82 00 7F` + 127 bytes | **reject as DER** | length octets must be minimal |
| `len-indefinite` | `30 80 ... 00 00` | accept as BER, **reject as DER** | indefinite length with end-of-contents, **constructed only**. The primitive spelling (`04 80 ... 00 00`) is a different question: X.690 encodes primitive indefinite content as a sequence of encoding units, so "the content is the bytes before the terminator" is not a defensible reading, and the row is **resolved**: X.690 (02/2021) §8.1.3.2 a) requires a sender to use the definite form when the encoding is primitive, so primitive-with-indefinite-length is never a conforming encoding, and §7.1 dynamic conformance gives the receiver no licence to accept one. The decoder refuses it with a named error, which is now cited behaviour rather than a defensive guess. Read 2026-11-07 via `itulib read X.690 8.1.3.2` |
| `len-overflow` | `04 88 FF FF FF FF FF FF FF FF` | reject with a named error, never `MemoryError` | an 8-byte length must not be trusted as an allocation size; cap and refuse |
| `len-undefined-high` | `04 8F 01` | reject | low nibble 15 is reserved by X.690 |

## Truncation and framing

Every case below must raise the library's own named parse error. `IndexError`,
`struct.error`, `UnicodeDecodeError` and a returned empty value are all **failures**, because
a parser that escapes as `IndexError` is a parser whose bounds checks were never real, and
one that returns nothing is worse: it turns "the message ended" into "the message was empty".

| Id | Bytes | Expected |
|---|---|---|
| `trunc-header-1` | `30` | named error |
| `trunc-length` | `30 82 01` | named error, incomplete length |
| `trunc-body` | `30 04 01 02` | named error, body shorter than declared length |
| `trunc-tag` | `9F` | named error, incomplete high-tag-number form |
| `trunc-tag-cont` | `9F 81` | named error, continuation promised and not delivered |
| `trunc-eoc` | `30 80 02 01 00` | named error, indefinite length never closed |
| `trunc-nested` | `30 06 04 04 41` | named error, inner length overruns parent |
| `trunc-zero-len-child` | `30 02 30 00` | valid: an empty constructed child |

Length 0 must parse as empty, not as absent. Those are different answers, and confusing them
is the same class of bug as the silent-empty failures recorded in the certledger trust model.

## Values: DER restrictions that BER tolerates

Each row below is legal BER and illegal DER, except where marked accept. The BER path
accepts, the DER path refuses, and the refusal is named rather than silent - that separation
is the deliverable, not a detail.

Rules marked `[verify against X.690]` are stated from knowledge of the encoding rules rather
than from a retrieved copy of the text. That marking is not hedging for its own sake:
`asn1core` lives or dies on whether its DER restrictions are the actual DER restrictions, and
an invented clause is worse than an untested one. X.690 is not in the RFC library, so these
get checked against the ITU text or against a second independent implementation. All nine of those markers were retired on 2026-11-07 against `Rec. ITU-T X.690 (02/2021) | ISO/IEC 8825-1:2021` and `Rec. ITU-T X.680 (02/2021) | ISO/IEC 8824-1:2021`, fetched and indexed by `D:\code\itulibrary` (`itulib read X.690 11.1`); the edition and subclause now sit in the row. One of them was not merely unverified but wrong, and wrong about which document carries the rule.

| Id | Bytes | Expected | Rule |
|---|---|---|---|
| `int-nonmin` | `02 02 00 01` | 1 in BER, **reject as DER** | the leading zero octet is not minimal: §8.3.2 forbids the bits of the first contents octet together with bit 8 of the second being all zero (and all one), and its NOTE names minimality as the purpose - X.690 (02/2021) §8.3.2, read 2026-11-07 via `itulib` |
| `int-minus128` | `02 01 80` | **-128, accept** | single octet 0x80 is -128 in two's complement, and it is minimal. A decoder that treats the sign bit as an overflow here is wrong, and there is no negative zero in two's complement to be confused about |
| `int-minus129` | `02 02 FF 7F` | -129, accept | the padding 0xFF keeps the sign bit set |
| `int-minus128-nonmin` | `02 02 FF 80` | -128 in BER, **reject as DER** | the pair to `int-minus128`: same value, redundant leading 0xFF |
| `int-zero-empty` | `02 00` | **reject** | zero must be encoded as one octet `00`; an empty INTEGER content is invalid in both BER and DER |
| `int-boundary-127` | `02 01 7F` | 127, accept | last single-octet positive |
| `int-boundary-128` | `02 02 00 80` | 128, accept | needs the padding zero to keep the sign bit clear, so it is minimal and legal |
| `bool-nonzero` | `01 01 02` | true in BER, **reject as DER** | §8.2.2 allows TRUE to be any non-zero octet *as a sender's option*, so `02` is legal BER; §11.1 then requires all eight bits set under CER/DER - X.690 (02/2021) §8.2.2 and §11.1, read 2026-11-07 via `itulib`. The row's old prose ("must be 00 or FF") conflated the two rules and would have rejected legal BER |
| `bits-unused-nonzero` | `03 03 03 41 41` | tolerated in BER, **reject as DER** | the unused trailing bits must be zero in DER |
| `bits-empty` | `03 00` | **reject** | a BIT STRING carries at least the unused-bits octet |
| `oid-first-arc` | `06 01 4F` | **1.39**, accept | first content octet is `40*a + b`, and `0x4F = 79 = 40*1 + 39`, so this is iso(1) member-body(39). Note the b field tops out at 39 for a=1, which is why 79 is the last octet in that range |
| `oid-first-arc-high` | `06 02 7F 01` | **2.47.1, accept** | an earlier version of this row said "reject, arc 3 is illegal". **That was wrong.** X.690 (02/2021) §8.19.4 packs the first two components as `(X*40) + Y`, and its NOTE bounds the 0-39 range to nodes reached from X = 0 and X = 1 - so a first component of 2 occupies 80 upward, and `0x7F = 127` is `2.47`. Read 2026-11-07 via `itulib read X.690 8.19.4`, so `0x7F = 127 = 80 + 47` is `2.47`. The evidence is a CA's own bytes, not my reading: 61 of the root certificates in the local trust store encode `2.5.29.19` as `06 03 55 1D 13`, where `0x55 = 85 = 40*2 + 5`. Implementing the old row would have refused every `2.5.29.x` extension and `2.5.4.x` attribute in X.509 |
| `oid-arc-continuation` | `06 03 2C 81 00` | accept | an arc above 127 exercises the same base-128 path as high tag numbers, so it is the same bug class as `tag-c-128` |
| `oid-arc-nonminimal` | a subidentifier encoded `80 01` | BER accept, **DER reject** | non-minimal base-128 subidentifier. The same rule applied to the first pair - `06 02 80 01`, which is `0.1` written in two octets where one covers it - is refused under this same name |
| | `oid-encoder-divergence` | snmpy's bytes for `2.100.3`: `B4 03` | valid DER **for 2.6579** | measured 2026-11-05: snmpy encodes `2.100.3` as `B4 03` and its own decoder reads `B4 03` back as 2.100.3, so the two halves agree with each other and disagree with X.690. A conforming parser sees one base-128 value, `(0x34 << 7) | 0x03 = 6659`, i.e. `2.6579`; the minimal form of what snmpy meant is `81 34 03`. This is **not** a corpus refusal - nothing is wrong with those bytes, only with the encoder that chose them |
| `utc-time-form` | `17 0D 30 35 30 36 31 39 30 34 30 30 30 30 5A` | 2005, per RFC 5280 §4.1.2.5.1 | two-digit years: YY >= 50 means 19YY, otherwise 20YY - the rule lives in the RFC profile, not in X.690. This row's bytes used to read `050506194000Z`, which encodes nothing at all: `05` is NULL, the declared length did not match the content, and a literal `Z` had been pasted into a hex string. UTCTime is universal 23, identifier `17` |
| `gen-time-2049` | GeneralizedTime `"20491231235959Z"` inside a validity window | **accept, report** | this row used to demand that a UTCTime "encoding a 2099 date" be refused, and that was wrong twice over. No UTCTime encodes 2099: `991231235959Z` is 1999 and the profile leaves no other reading. And the 2049/2050 boundary is a rule about what a **CA may issue**, not about what a value means, so it is not enforced in the decoder. Enforcing it would reject **Certum Trusted Network CA 2**, a shipped trust anchor whose notBefore is GeneralizedTime for 2011 - measured 2026-11-05, thumbprint `D3DD483E2BBF4C05E8AF10F5FA7626CFD3DC3092`. `validity_encoding_issue()` reports the spelling; the certificate still parses |
| | `utc-century-rule` | `"500101000000Z"`, `"491231235959Z"` | 1950, 2049 | `YY >= 50` is 19YY, otherwise 20YY, so UTCTime covers 1950-2049 and nothing else. Tested across all hundred values of `YY`, and confirmed against two vendored roots whose dates sit on opposite sides of the boundary |
| | `time-not-zulu` | `"500101000000+0100"`, `"500101000000z"`, `"5001010000Z"` | BER accept, **DER reject** | Zulu and seconds are both mandatory in this profile; the local differential and the 11-octet minute form are legal ASN.1, so a tolerant read keeps the octets and resolves nothing |
| | `time-invalid-calendar` | `"500230000000Z"`, `"500431000000Z"` | **reject as DER** | 30 February and 31 April: checked as a date, not only as digits in the right positions |
| | `time-leap-second` | `"500101000060Z"` | **reject as invalid value** | **the remembered rule was wrong.** X.680 (02/2021) §47.3 restricts UTCTime to `hhmmss` "where ss is seconds (00 to 59)", so `60` is not a UTCTime value at all: this is refused as an ill-formed value, not as a legal one the host type cannot express. The distinction is the whole point - the old reason invites someone to add a permissive path for a value the recommendation never allows. X.690 §11.8 fixes only the DER form (seconds mandatory, Zulu); the alphabet lives in X.680. Read 2026-11-07 via `itulib read X.680 47.3` |
| | `dn-order-significant` | `C=US,O=Example` against `O=Example,C=US` | **not equal** | §7.1: two names match "if they have the same number of RDNs, for each RDN in DN1 there is a matching RDN in DN2, and the matching RDNs appear in the same order in both DNs". Order *inside* one RDN is not significant, because an RDN is a SET |
| | `dn-multi-valued-rdn` | one RDN holding `C=FR` and `O=Example` | equal to the same two attributes in the other order | matching pairs attributes off without reusing one. No shipped certificate here contains a multi-valued RDN - 577 RDNs measured, all single-valued - so the case comes from the generated fixture and from hand-built TLVs, never from the store |
| | `dn-insignificant-space` | `"foo bar  "` | prepares to `" foo  bar "` | RFC 4518 §2.6.1 for stored values: exactly one SPACE at each end and **every** inner run, however long, replaced by exactly two. Trimming is the intuitive behaviour and it is wrong. Empty and all-space input both prepare to exactly two SPACEs. Vector taken from the RFC's own worked example |
| | `dn-teletex-ambiguity` | tag 20 carrying `Caf E9` | reads as `Café` through the Latin-1 fallback | X.500 says T.61 for this tag; issuers have shipped UTF-8 and Latin-1 under it too and §7.1 makes support OPTIONAL, so the fallback stands and the value keeps its `kind`. **The tag in this row used to read 19, and that was wrong**: X.680 (02/2021) Table 1 numbers PrintableString 19 and TeletexString 20. The store's two tag-20 values are Entrust's `www.entrust.net/CPS_2048 incorp. by ref. (limits liab.)`, whose `_` is outside PrintableString's alphabet, so the bytes themselves say which type is which. The old argument - 520 of 577 values carry 'this tag', so refusing is not viable - described tag 19 while naming tag 20; TeletexString appears twice in 577 values |
| | `dn-attribute-tag-numbers` | an attribute value under tag 13, 14, or 21 | **refused, by name** | X.680 Table 1 assigns universal 13 to the Relative object identifier type and 14 to the TIME type, so neither is a string type at all; 21 is a character string type this codec declines to model because its number could not be re-read from the text available here. `name.py` used to claim 13 numericString and 14 printableString, and read such values as names without complaint - with zero occurrences in 75 certificates, nothing in the corpus contradicted it. `tests/test_name_corpus.py::test_tags_the_old_table_claimed_as_string_types_are_refused_by_number`, `::test_a_string_type_this_codec_does_not_model_is_refused_by_name` |
| | `dn-encoding-not-identity` | `C=US` in PrintableString against `C=us` in UTF8String | **equal** | §7.1 compares prepared values, so neither the string type nor the stored TLV takes part in the match. `Name.__eq__` implements the match rather than a field comparison: a name pinned for trust has to keep matching in a document that spelled it differently |
| | `printable-charset` | PrintableString holding `@`, `&`, `_` or `é` | BER accept, **DER reject** as `printable-charset` | X.680 (02/2021) §41.4 Table 10: A-Z, a-z, 0-9, SPACE and **eleven** specials `' ( ) + , - . / : = ?` - 74 characters, cardinality pinned so a silent deletion cannot hide. Enforced on the strict path by `der.check_printable_string`, wired at `node._der_value_check` for tag 19; `tests/test_structure_corpus.py::test_printable_string_permitted_alphabet_is_exactly_table_10` and `::test_printable_string_outside_table_10_is_refused_by_rule_on_the_der_path_only`. The refusal differs in kind from the others here: an out-of-alphabet PrintableString is not legal BER with a forbidden spelling, it is no value of the type at all, so the tolerant path keeps the octets and only DER refuses. **This row's earlier note - 'zero PrintableStrings in 577 values' - was read off the wrong tag table rather than off the bytes: 520 of the 577 are PrintableString**, all 520 inside Table 10, and `tools/crosscheck_store.py` reports failures=0 over 75 certificates with the check live |
| `setof-unsorted` | two SET OF children out of order | BER accept, **DER reject** | X.690 (02/2021) §11.6 orders the component encodings of a `SET OF`, comparing them as octet strings with the shorter padded with zero octets **for the comparison only**. That padding cannot change any result here: §10.1 requires definite, minimally-encoded lengths, so two distinct DER TLVs can never stand in a prefix relation, and a plain byte-wise `sorted()` is equivalent. Read 2026-11-07 via `itulib read X.690 11.6`; it matters here because RDN sets are compared byte-wise during path validation |
| `seq-indefinite` | `30 80 ... 00 00` | BER accept, **DER reject** | indefinite length is not permitted by DER |

## Structure and round-trip properties

Beyond individual bytes, these are the properties the library as a whole has to hold, and
they are the ones a defect like "discards the original TLV" survives untouched:

| Id | Property | Why it must be a test, not a comment |
|---|---|---|
| `rt-idempotent` | decode then DER-encode a canonical document yields **the same bytes** | catches any encoder that reorders, pads, or minimises differently from the decoder |
| `rt-original-retained` | after decoding, the exact input bytes of every node are still reachable | this is invariant I3 of the certledger trust model, and the one property the snmpy codec lacks |
| `rt-noncanonical-refuses` | a non-canonical document on the DER path raises, and never round-trips into a canonical form invisibly | otherwise one certificate occupies two rows in a database, and a published count is wrong |
| `depth-bound` | a deeply nested constructed encoding, say 10,000 levels, fails with a named error rather than a stack overflow | this is the shape of crash that takes down anything that parses input from the network |
| `repeated-child` | a SEQUENCE containing the same bytes twice keeps two distinct nodes | aliasing here silently produces wrong certificates |
| `unknown-tag-preserved` | an unrecognised tag survives decode-encode verbatim | certificate extensions are the entire reason this library is needed; dropping the unknown ones defeats the purpose |
| `no-asserts-on-wire` | all bounds checks are real checks, not `assert` statements | the portfolio already runs CI under `python -O`, which strips asserts and turns an assert-checked parser into an unchecked one |

## End-to-end fixtures

The corpus must not be fragments only. Three whole documents belong in it, stored as raw DER
with their SHA-256 recorded in the manifest:

1. **A self-signed X.509 v3 certificate** with a non-trivial subject: multi-valued RDNs,
   UTF8String and PrintableString mixed, several extensions, RSA key. Exercises SET OF
   ordering, string printing rules, and `subjectKeyIdentifier`.
2. **An ECDSA certificate whose `r` value carries a leading zero byte and whose `s` does
   not.** This is the single most common hand-written-INTEGER bug in the wild, and a codec
   that strips the leading zero as "non-minimal" will produce a signature that no longer
   verifies - a silent, catastrophic failure at exactly the wrong layer.
3. **A CRL with one entry whose `reasonCode` is `keyCompromise`.** `keyproof` will be reading
   artifacts of this shape, so both projects should test against one shared fixture rather
   than each inventing its own.

For each fixture: verify the signature against the **stored original bytes**. If a fixture's
signature only verifies after re-serialisation, then the fixture, the encoder, or the parser
is broken - and RFC 5280 §4.1.3.2 says which of those is disqualifying.

### What is in the repo today

Two real trust-store roots, one generated multi-valued-RDN certificate, and the two documents
fixtures 2 and 3 asked for are vendored under `tests/fixtures/`:

| File | Bytes | SHA-256 | Why this one |
|---|---|---|---|
| `root-ecdsa.der` | 538 | `26c56ad2208d1e9b152f66853bf4797cbeb7552c1f3f477251e8cb1ae7e797bf` | ECDSA-P384, `version [0]` **present** (v3), SPKI 120 bytes |
| `root-rsa.der` | 576 | `e7685634efacf69ace939a6b255b7b4fabef42935b50a265acb5cb6027e44e70` | **no version field at all** - a v1 certificate, so every `TBSCertificate` child sits one position earlier than a v3 document. The naive `children[6]` read returns the wrong object on this shipped, real input |
| `multivalue-rdn.der` | 1057 | *not pinned* | **generated**, by `sdk-forge/probe_name_fixture.py` - **deleted in `sdk-forge@e39ac38`** by a scratch sweep that did not check inbound citations; recover with `git -C sdk-forge show e39ac38^:probe_name_fixture.py`. Multi-valued RDN, mixed PrintableString, UTF8String and IA5String, padded and doubled-space values, and an attribute type with no RFC 4514 short name |
| `ecdsa-padded-r.der` | 388 | *not pinned* | **generated**, by `sdk-forge/probe_sig_fixture.py` (**deleted in `sdk-forge@e39ac38`**; `git -C sdk-forge show e39ac38^:probe_sig_fixture.py`): fixture 2. ECDSA-P256 where `r` is 33 octets (leading `00`) and `s` is 32 (no padding) |
| `crl-keycompromise.der` | 267 | *not pinned* | **generated**: fixture 3. Two revoked entries - one `crlReason` keyCompromise, one with no reason extension at all - plus the list's own `[0]` extensions, a `nextUpdate`, and a version field reading **1** because `Version` counts from `v1(0)` |

None of the three generated fixtures pins a digest. Each generator makes a fresh key or a fresh
signature - the ECDSA nonces in this build were measured to be non-deterministic, which is why the
claim is "reproducible in shape" and not "reproducible in bytes". What the tests pin is structure,
which is what the fixtures exist to demonstrate.

Fixture 1 asked for multi-valued RDNs and mixed PrintableString and UTF8String, and both halves
are covered. The sentence this paragraph used to carry - that cryptography chose TeletexString for
`C=FR`, and that PrintableString therefore had to be exercised through hand-built TLVs - was a
reading of `name.py`'s tag table rather than of the bytes. Tag 19 **is** PrintableString (X.680
Table 1; cryptography emits identifier octet `13` for `C=US`), the fixture's `C=FR` is a
PrintableString inside a document, and the trust store carries 520 of them. What no shipped
document supplies is a PrintableString *outside* Table 10, so that half stays a hand-built vector,
which is the honest place for a refusal no real certificate demonstrates.

The store itself supplies 75 documents for `tools/crosscheck_x509.py`, which is where the
structural claims get checked against something that is not this code.

**The signature check this table was built to support.** Of those 75 certificates, 67 are
self-issued and verifiable on this machine, and **all 67 verify their CA signature over the
`tbsCertificate` slice this package hands back** - 0 failures. The 8 that do not are skipped with a
reason printed rather than counted as passes: 6 are cross-certificates (a root issued by a
different CA, so its own subject key cannot verify it), 1 is signed with MD2, which the bindings
refuse, and 1 carries a key the bindings cannot read. The generated CRL is verified the same way,
against the fixture CA's key, over asn1core's own `tbsCertList` slice.

**One fact the store volunteered.** A root in the local machine store carries a serial number
that is not positive, which RFC 5280 §4.1.2.2 forbids; `cryptography` warns that it will refuse
to load that certificate in a future release. This package parses it without complaint on
purpose: serial-number *semantics* are a profile-level validation, not an encoding one, and a
codec that quietly rejects an input cannot be used to inventory the things already in
circulation. Whoever validates certificates is the layer that should raise - and now has the
bytes to raise about.

## Rules for whoever builds it

- **Every case carries both a positive and a negative assertion.** A test that only proves
  the decoder accepted something establishes nothing about correctness.
- **Expected values come from the encoding rule, not from observed output.** Deriving
  expectations from the code under test is precisely how `ObjectTag.decode` shipped with no
  coverage on the one function everything else depended on.
- **Fragments stay human-readable.** One case per file, named by its id, so a failing test
  points at a rule rather than at a byte offset in a blob.
- **The known defects get named tests before any refactoring.** The defect list is the
  regression suite: `tag-c-31`, `tag-c-63`, `tag-c-127`, `tag-c-128`, `tag-c-16383`,
  `tag-c-16384`, `tag-nonminimal`, `len-long-256`, `len-long-65536`, `len-nonminimal`,
  `len-undefined-high`, `len-overflow`, `len-indefinite`, and all eight rows of the truncation
  table. The first draft of this file claimed "nineteen cases" while naming sixteen - the count
  that matters is the suite's, not the prose's. As of 2026-11-05 the suite holds 337 cases in 91
  test functions across eight files - the defect, structure and vector-arithmetic corpora, the
  snmpy regression floor, and the OID, X.509 structure, time and name corpora - and the
  per-obligation state is recorded in `PLAN.md`.


## Provenance of these bytes, and what is still owed

Every sequence above was written by hand from an encoding rule. Hand-written vectors are
exactly where a wrong expectation hides, so the arithmetic behind the tag, length, INTEGER,
BIT STRING and OID cases is re-derived from bit masks by
**`D:\code\sdk-forge\check_vectors.py`**, which runs offline and prints
`[ok] 38 vector derivations checked`. Before any code existed to bend around it, that script
caught two errors in this file: `5F CE 0F` is application **primitive**, because a high tag
number needs `11111` in the low five bits and leaves bit 5 as the only place constructed-ness
can live (the constructed spelling is `7F CE 0F`), and `06 01 4F` is OID **1.39**, not 1.47.

The script has since moved into this repository as `tests/test_vector_arithmetic.py`, and it
imports nothing from `asn1core` on purpose: expectations validated against the code that has to
satisfy them are a tautology. The copy in `sdk-forge` was deleted rather than kept in step, so
there is one source of truth.

One of the two things originally owed here is now partly paid. **`tools/crosscheck_store.py`**
parses every certificate in the local X.509 trust store - 75 documents, 868,500 bytes, none of
them authored in this repository - and requires each to parse on the DER path and re-encode
byte for byte: **zero failures** on 2026-11-05. That is agreement with somebody else's
encoder, which is what turns a guess into a specification.

**Its limits are the part worth reading.** Every one of those certificates uses context tag
numbers below 31 and definite lengths only, so the rows that exist precisely because snmpy got
them wrong - `tag-c-31` and above, `len-indefinite`, `tag-nonminimal` - are untouched by it.
And real-world DER cannot validate a *rejection* at all, because a trust store contains only
documents that should be accepted. Resolved 2026-11-07: all nine `[verify against X.690]`/`[verify against X.680]` markers, against the ITU text fetched and indexed by
`D:\code\itulibrary`; one of them (the leap-second row) was not merely unverified but wrong, and wrong about which document
 carries the rule. Still owed: negative vectors taken from a second implementation rather than from
my own reasoning about what it ought to refuse.

### Where X.690 and X.680 can be checked (added 2026-11-07)

The markers above say a rule was written from memory of the encoding rules rather than from the text, and
`rfclib` cannot reach that text: X.680/X.690 are not in the RFC series. `D:\code\itulibrary` now indexes the
in-force editions - `Rec. ITU-T X.690 (02/2021) | ISO/IEC 8825-1:2021` and `Rec. ITU-T X.680 (02/2021) |
ISO/IEC 8824-1:2021` - fetched locally because ITU forbids redistributing the text.

What it turned up already, recorded here rather than in a row, because no row moves without its check:

- `setof-unsorted` points at 11.6, and 11.6 is narrower than the row assumes. The ordering comparison pads the
  shorter component encoding with zero octets **for comparison only**, and the padding is never emitted. A sort
  that compares raw encodings without that padding can order a `SET OF` wrongly while still emitting well-formed
  DER, which is the kind of defect no local test notices.
- `SET` and `SET OF` are governed by different clauses: 9.3/10.3 order by tag, 11.6 orders by encoding under
  DER. One note about "SET OF is sorted" does not cover both.
- `time-leap-second` is marked against the wrong document. X.690 11.7/11.8 fix the form and defer the alphabet
  to X.680, and nothing in X.690 addresses a seconds value of 60 at all.
- `oid-first-arc-high` sits in 8.19, the clause whose earlier remembered answer was wrong.

Retiring a marker means editing the row with the edition and subclause attached and the check actually done.
`itulib` supplies the text and the citation; it does not decide what this codec accepts.
