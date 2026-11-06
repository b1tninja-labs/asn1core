"""Certificate and CRL contents: `dk.cert`, RFC 5280 §4.1 and §5.1.

The two generated fixtures carry the specific shapes a codec gets wrong:

`ecdsa-padded-r.der` has a signature whose `r` is 33 bytes, the first of them `00`. DER INTEGER is
signed, so a 32-byte `r` starting at or above 0x80 has to be padded to stay positive. Strip that
byte and the value stops being a large positive number and becomes a negative one - same length,
opposite meaning, and a signature that no longer verifies. The test below checks the padding
survives and then checks what stripping it would have done, so the reason for the check is on the
record rather than implied.

`crl-keycompromise.der` has two entries: one carrying `crlReason` keyCompromise, one carrying
nothing at all, which per §5.3.1 means `unspecified(0)` rather than "unknown". It also puts the
list's own extensions behind `[0]` while an entry's sit untagged, and its version field reads 1
because `Version` counts from v1(0).

Expected values come from the documents' structure as the RFC describes it, not from this package's
output. The trust-store sweep in `tools/crosscheck_x509.py` is where these fields get compared
against `cryptography`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asn1core import (
    Certificate,
    CertificateError,
    DerViolation,
    Node,
    decode,
    decode_length,
    decode_tag,
    encode_der,
    parse_certificate,
    parse_crl,
)
from asn1core.crl import REASON_CA_COMPROMISE, REASON_KEY_COMPROMISE, REASON_NAMES

FIXTURES = Path(__file__).parent / "fixtures"

# Documented, not asserted. Regenerating with sdk-forge/probe_sig_fixture.py produces a different
# signature because the nonces in this build are not deterministic - measured, see that file - so a
# digest check here would fail every legitimate regeneration and teach the next person to delete
# it. The structural tests below are what hold.
AS_COMMITTED = {
    "ecdsa-padded-r.der": "88e69a022ad1c838c3e5a2ea880a6810279a882ae571e872199190a89eac7e80",
    "crl-keycompromise.der": "777689ad796357d595a46bfbced5c4ecc3f3c98fd6bcea37a6341fe991789479",
}


def fixture(name: str) -> bytes:
    path = FIXTURES / name
    if not path.is_file():  # pragma: no cover - guards a partial checkout
        pytest.fail(f"{path} is missing; run sdk-forge/probe_sig_fixture.py")
    return path.read_bytes()


def length_octets(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + length_octets(len(payload)) + payload


def seq(*children: bytes) -> bytes:
    return tlv(0x30, b"".join(children))


def context(index: int, *children: bytes) -> bytes:
    """`[index] CONSTRUCTED`, which is how an EXPLICIT slot and a `[0]` extension list are written."""
    return tlv(0xA0 | index, b"".join(children))


def _base128(value: int) -> bytes:
    out = bytearray([value & 0x7F])
    value >>= 7
    while value:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(out))


def oid(dotted: str) -> bytes:
    parts = [int(piece) for piece in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]]) + b"".join(_base128(part) for part in parts[2:])
    return tlv(0x06, body)


def integer(value: int) -> bytes:
    return tlv(0x02, value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True))


def utc(text: str) -> bytes:
    return tlv(0x17, text.encode("ascii"))


def content_offset(buffer: bytes) -> int:
    """Where a TLV's content starts, which is where its first child's stored slice starts."""
    _, after_tag = decode_tag(buffer, 0)
    _, after_length = decode_length(buffer, after_tag)
    return after_length


def extension(dotted: str, value: bytes, critical: bool = False) -> bytes:
    parts = [oid(dotted)]
    if critical:
        parts.append(tlv(0x01, b"\xff"))
    parts.append(tlv(0x04, value))
    return seq(*parts)


def signed(
    tbs: bytes,
    algorithm_oid: str = "1.2.840.10045.4.3.2",
    signature: bytes = b"\x30\x06\x02\x01\x01\x02\x01\x01",
) -> bytes:
    """Wrap a to-be-signed region the way every X.509 signed document is wrapped."""
    return seq(tbs, seq(oid(algorithm_oid)), tlv(0x03, b"\x00" + signature))


@pytest.fixture
def root_ecdsa() -> bytes:
    return fixture("root-ecdsa.der")


def tbs_children(der: bytes) -> list[bytes]:
    """The raw children of a certificate's tbsCertificate, so a test can rebuild it."""
    node, _ = decode(parse_certificate(der).tbs_certificate, der=True)
    return [child.raw for child in node.children]


def payload_of(node: Node) -> bytes:
    """A primitive node's content, narrowed from `bytes | None`.

    A helper rather than `assert node.payload is not None` because this suite also runs under `python -O`, where
    asserts are stripped and a None would sail through into a TypeError several statements later.
    """
    if node.payload is None:
        raise AssertionError(f"{node.tag} node is constructed and has no primitive payload")
    return node.payload


def rebuild(children: list[bytes], cert: Certificate) -> bytes:
    return seq(
        seq(*children),
        cert.signature_algorithm_raw,
        tlv(0x03, b"\x00" + cert.signature_value),
    )


# --- the ECDSA fixture: invariant I3 on a real signature ---------------------------------


def test_padded_r_survives_the_codec() -> None:
    cert = parse_certificate(fixture("ecdsa-padded-r.der"))
    sequence, end = decode(cert.signature_value, der=True)
    assert end == len(cert.signature_value)
    r, s = sequence.children

    r_bytes, s_bytes = payload_of(r), payload_of(s)
    assert len(r_bytes) == 33
    assert r_bytes[0] == 0x00
    assert len(s_bytes) == 32
    assert s_bytes[0] != 0x00
    # The bytes handed to a verifier are the document's own, byte for byte.
    assert sequence.raw == cert.signature_value


def test_stripping_the_padding_would_change_the_number_not_just_its_length() -> None:
    """Why the leading zero is load bearing, stated as an executable fact."""
    cert = parse_certificate(fixture("ecdsa-padded-r.der"))
    sequence, _ = decode(cert.signature_value, der=True)
    r = sequence.children[0]
    r_bytes = payload_of(r)
    padded = int.from_bytes(r_bytes, "big", signed=True)
    stripped = int.from_bytes(r_bytes[1:], "big", signed=True)

    assert padded > 0
    assert stripped < 0, "the payload starts at or above 0x80, so unpadded it reads as negative"
    assert stripped != padded
    # Re-encoding the parsed INTEGER yields the padded form back: canonicalisation, not mangling.
    assert encode_der(r) == r.raw


def test_the_ecdsa_fixture_carries_the_extensions_it_claims() -> None:
    cert = parse_certificate(fixture("ecdsa-padded-r.der"))
    assert cert.version == 2, "v3, encoded as 2"
    assert cert.serial > 0
    assert cert.self_issued
    assert [ext.dotted_oid for ext in cert.critical_extensions] == ["2.5.29.19", "2.5.29.15"]
    assert cert.extension("2.5.29.19") is not None
    assert cert.extension("2.5.29.35") is None
    assert not cert.unrecognised_critical


@pytest.mark.parametrize(
    "name", ["root-rsa.der", "root-ecdsa.der", "multivalue-rdn.der", "ecdsa-padded-r.der"]
)
def test_every_certificate_field_is_a_slice_of_the_original(name: str) -> None:
    der = fixture(name)
    cert = parse_certificate(der)
    assert cert.raw == der
    # The signed region does not begin the document - four header octets come first - so "is a
    # slice" means "starts where the outer SEQUENCE's content starts", not "startswith".
    start = content_offset(der)
    assert der[start : start + len(cert.tbs_certificate)] == cert.tbs_certificate
    assert cert.subject_public_key_info in der
    assert cert.signature_algorithm_raw in der
    assert b"\x00" + cert.signature_value in der
    assert cert.validity.raw in cert.tbs_certificate
    for ext in cert.extensions:
        assert ext.raw in cert.tbs_certificate
        assert ext.value in ext.raw


def test_a_v1_certificate_carries_no_version_field() -> None:
    """The RSA root here is v1: no `[0]` slot at all, which is why version defaults to 0."""
    der = fixture("root-rsa.der")
    cert = parse_certificate(der)
    assert cert.version == 0
    assert cert.extensions == ()
    assert tbs_children(der)[0][0] == 0x02, "the first tbs child is the serial, not a version slot"


def test_critical_defaults_to_absent_rather_than_false(root_ecdsa: bytes) -> None:
    """An `Extension` with two children is not malformed; `critical` has DEFAULT FALSE."""
    cert = parse_certificate(root_ecdsa)
    assert len(cert.extensions) == 3
    non_critical = [ext for ext in cert.extensions if not ext.critical]
    assert [ext.dotted_oid for ext in non_critical] == ["2.5.29.14"]
    for ext in cert.critical_extensions:
        node, _ = decode(ext.raw, der=True)
        assert len(node.children) == 3, "a critical extension carries the flag explicitly"
    for ext in non_critical:
        node, _ = decode(ext.raw, der=True)
        assert len(node.children) == 2, "an absent flag means FALSE, and DER writes no FALSE"


def test_extensions_are_found_past_a_unique_identifier(root_ecdsa: bytes) -> None:
    """issuerUniqueID [1] between the key and the extensions must not hide them.

    No certificate in a modern trust store is v2, so a codec that reads extensions by index passes
    every test anyone has run against it and then fails on a document from an old CA.
    """
    cert = parse_certificate(root_ecdsa)
    children = tbs_children(root_ecdsa)
    assert children[-1][0] == 0xA3, "the last tbs child is the [3] extensions slot"
    padded = [*children[:-1], tlv(0x81, b"\x00\xab"), children[-1]]
    again = parse_certificate(rebuild(padded, cert))
    assert again.version == 2


# --- the CRL fixture: absent fields that mean something ---------------------------------


def test_crl_reads_both_entries_and_both_reason_cases() -> None:
    crl = parse_crl(fixture("crl-keycompromise.der"))
    assert crl.version == 1, "a version 2 CRL encodes the number 1, because v1 is 0"
    assert crl.revoked_serials == (101, 102)
    assert crl.this_update.year == 2024
    assert crl.next_update is not None
    assert crl.next_update.year == 2024

    key_compromise, plain = crl.revoked
    assert key_compromise.reason == REASON_KEY_COMPROMISE == 1
    assert key_compromise.reason_name == "keyCompromise"
    assert key_compromise.compromised
    assert len(key_compromise.extensions) == 1
    assert not key_compromise.extensions[0].critical, "§5.3.1 makes the reason code non-critical"

    assert plain.reason is None, "no crlReason extension, which is what §5.3.1 prefers"
    assert plain.reason_name == "unspecified"
    assert not plain.compromised


def test_reason_numbering_is_the_enum_and_not_a_guess() -> None:
    """cessationOfOperation is 5 and keyCompromise is 1; 7 is unused. Written down once."""
    assert REASON_NAMES[REASON_KEY_COMPROMISE] == "keyCompromise"
    assert REASON_NAMES[REASON_CA_COMPROMISE] == "cACompromise"
    assert REASON_NAMES[5] == "cessationOfOperation"
    assert 7 not in REASON_NAMES, "value 7 is not assigned"
    assert REASON_NAMES[10] == "aACompromise"
    assert parse_crl(fixture("crl-keycompromise.der")).revoked[1].reason_name == "unspecified"


def test_crl_keeps_its_slices() -> None:
    der = fixture("crl-keycompromise.der")
    crl = parse_crl(der)
    assert crl.raw == der
    start = content_offset(der)
    assert der[start : start + len(crl.tbs_cert_list)] == crl.tbs_cert_list
    assert b"\x00" + crl.signature_value in der
    assert crl.this_update_raw in crl.tbs_cert_list
    assert crl.next_update_raw is not None
    assert crl.next_update_raw in crl.tbs_cert_list
    for entry in crl.revoked:
        assert entry.raw in crl.tbs_cert_list
    assert crl.revoked_by_serial(101) is crl.revoked[0]
    assert crl.revoked_by_serial(999) is None


def test_crl_extensions_sit_behind_a_zero_tag_and_entries_do_not() -> None:
    """The list's extensions are `[0] EXPLICIT`; an entry's are a bare SEQUENCE."""
    crl = parse_crl(fixture("crl-keycompromise.der"))
    assert [ext.dotted_oid for ext in crl.extensions] == ["2.5.29.20"], "cRLNumber"
    value, end = decode(crl.extensions[0].value, der=True)
    assert end == len(crl.extensions[0].value)
    assert value.tag.number == 2
    assert int.from_bytes(payload_of(value), "big") == 7

    node, _ = decode(crl.tbs_cert_list, der=True)
    assert node.children[-1].tag.is_context(0), "the last signed field is the tagged slot"
    entry = node.children[-2].children[0]  # revokedCertificates, then its first entry
    assert entry.children[2].tag.number == 16, "an entry's extensions are an untagged SEQUENCE"


def test_next_update_and_revoked_certificates_are_both_optional() -> None:
    """The smallest legal TBSCertList: algorithm, issuer, thisUpdate. Nothing else."""
    tbs = seq(seq(oid("1.2.840.10045.4.3.2")), seq(), utc("240101000000Z"))
    crl = parse_crl(signed(tbs))
    assert crl.version == 0
    assert crl.next_update is None
    assert crl.next_update_raw is None
    assert crl.revoked == ()
    assert crl.extensions == ()
    assert crl.issuer.rdnsets == (), "an empty RDNSequence is a legal, if useless, name"


# --- shapes the grammar does not allow ---------------------------------------------------


def crl_tbs(*children: bytes) -> bytes:
    """A TBSCertList with the minimum fields filled in, so a test only writes what it varies."""
    return seq(
        seq(oid("1.2.840.10045.4.3.2")),
        seq(),
        utc("240101000000Z"),
        *children,
    )


def test_a_crl_version_of_two_is_the_off_by_one_this_profile_forbids() -> None:
    with pytest.raises(CertificateError, match="v2"):
        parse_crl(signed(seq(integer(2), *tbs_children_of(crl_tbs()))))


def tbs_children_of(tbs: bytes) -> list[bytes]:
    node, _ = decode(tbs, der=True)
    return [child.raw for child in node.children]


def test_a_reason_written_without_its_octet_string_wrapper_is_reported() -> None:
    """An encoder that writes the ENUMERATED where the OCTET STRING belongs is wrong."""
    broken = seq(oid("2.5.29.21"), tlv(0x0A, b"\x01"))
    entry = seq(integer(5), utc("240101000000Z"), seq(broken))
    with pytest.raises(CertificateError, match="OCTET STRING"):
        parse_crl(signed(crl_tbs(seq(entry))))


def test_crl_extensions_written_untagged_are_not_guessed_at() -> None:
    """A bare SEQUENCE where `[0]` belongs must not be read as the list's extensions."""
    entry = seq(integer(5), utc("240101000000Z"))
    tbs = crl_tbs(seq(entry), seq(extension("2.5.29.20", integer(1))))
    with pytest.raises(CertificateError, match=r"\[0\] EXPLICIT"):
        parse_crl(signed(tbs))


def test_a_crl_running_past_its_last_field_is_rejected() -> None:
    tbs = crl_tbs(
        seq(seq(integer(5), utc("240101000000Z"))),
        context(0, seq(extension("2.5.29.20", integer(1)))),
        seq(),
    )
    with pytest.raises(CertificateError, match="runs past crlExtensions"):
        parse_crl(signed(tbs))


def test_a_crl_entry_needs_a_serial_and_a_date() -> None:
    entry = seq(integer(5))
    with pytest.raises(CertificateError, match="two or three fields"):
        parse_crl(signed(crl_tbs(seq(entry))))


def test_a_crl_entry_date_cannot_be_a_string() -> None:
    entry = seq(integer(5), tlv(0x0C, b"2024-01-01"))
    with pytest.raises(CertificateError, match="date is a Time"):
        parse_crl(signed(crl_tbs(seq(entry))))


def test_an_unexpected_field_after_the_public_key_is_rejected(root_ecdsa: bytes) -> None:
    cert = parse_certificate(root_ecdsa)
    children = [*tbs_children(root_ecdsa), tlv(0x0C, b"unexpected")]
    with pytest.raises(CertificateError, match="unexpected field after subjectPublicKeyInfo"):
        parse_certificate(rebuild(children, cert))


def test_a_version_slot_holding_an_unknown_number_is_rejected(root_ecdsa: bytes) -> None:
    cert = parse_certificate(root_ecdsa)
    children = tbs_children(root_ecdsa)
    children[0] = context(0, integer(5))
    with pytest.raises(CertificateError, match="not one of v1, v2 or v3"):
        parse_certificate(rebuild(children, cert))


def test_an_extension_with_too_many_fields_is_rejected(root_ecdsa: bytes) -> None:
    cert = parse_certificate(root_ecdsa)
    children = tbs_children(root_ecdsa)
    slot, _ = decode(children[-1], der=True)
    inner, _ = decode(slot.children[0].raw, der=True)
    broken = seq(inner.children[0].raw, tlv(0x01, b"\xff"), inner.children[0].raw, tlv(0x04, b""))
    children[-1] = context(3, seq(broken, *[c.raw for c in inner.children[1:]]))
    with pytest.raises(CertificateError, match="two or three fields"):
        parse_certificate(rebuild(children, cert))


def test_a_non_canonical_critical_flag_is_rejected_by_the_codec_first(root_ecdsa: bytes) -> None:
    """Two layers can catch this, and the codec is the nearer one.

    On the DER path the BOOLEAN itself is refused before the certificate grammar looks at it. On
    the BER path `01 01 42` is a legal true, so the certificate layer's own message is what fires -
    which is why the check exists in both places and not one.
    """
    cert = parse_certificate(root_ecdsa)
    children = tbs_children(root_ecdsa)
    slot, _ = decode(children[-1], der=True)
    inner, _ = decode(slot.children[0].raw, der=True)
    broken = seq(inner.children[0].children[0].raw, tlv(0x01, b"\x42"), tlv(0x04, b""))
    children[-1] = context(3, seq(broken, *[c.raw for c in inner.children[1:]]))
    rebuilt = rebuild(children, cert)
    with pytest.raises(DerViolation, match="BOOLEAN"):
        parse_certificate(rebuilt)
    with pytest.raises(CertificateError, match="canonical BOOLEAN"):
        parse_certificate(rebuilt, der=False)


def test_an_extension_value_that_is_not_an_octet_string_is_rejected(root_ecdsa: bytes) -> None:
    cert = parse_certificate(root_ecdsa)
    children = tbs_children(root_ecdsa)
    slot, _ = decode(children[-1], der=True)
    inner, _ = decode(slot.children[0].raw, der=True)
    broken = seq(inner.children[0].children[0].raw, integer(1))
    children[-1] = context(3, seq(broken, *[c.raw for c in inner.children[1:]]))
    with pytest.raises(CertificateError, match="OCTET STRING"):
        parse_certificate(rebuild(children, cert))


def test_a_validity_field_that_is_not_a_time_is_rejected(root_ecdsa: bytes) -> None:
    cert = parse_certificate(root_ecdsa)
    children = tbs_children(root_ecdsa)
    validity_node, _ = decode(children[4], der=True)  # after [0], serial, signature, issuer
    children[4] = seq(tlv(0x04, b"240101000000Z"), validity_node.children[1].raw)
    with pytest.raises(CertificateError, match="UTCTime or GeneralizedTime"):
        parse_certificate(rebuild(children, cert))


def test_a_crl_reason_with_a_second_object_after_it_is_rejected() -> None:
    """An extension value holds exactly one object; a reason plus a stray INTEGER is not a reason."""
    wrapped = tlv(0x04, tlv(0x0A, b"\x01") + tlv(0x0A, b"\x02"))
    entry = seq(integer(5), utc("240101000000Z"), seq(seq(oid("2.5.29.21"), wrapped)))
    with pytest.raises(CertificateError, match="follow the crlReason value"):
        parse_crl(signed(crl_tbs(seq(entry))))


def test_an_explicit_critical_false_is_parsed_and_left_for_the_profile_layer(
    root_ecdsa: bytes,
) -> None:
    """DER says a DEFAULT value is omitted, so writing `critical FALSE` is a profile fault.

    Reading it is still unambiguous, and rejecting shipped documents over a spelling the schema
    resolves is the same mistake this package avoids for time and name encodings: the codec reports
    and parses, `pkix` decides.
    """
    cert = parse_certificate(root_ecdsa)
    children = tbs_children(root_ecdsa)
    slot, _ = decode(children[-1], der=True)
    inner, _ = decode(slot.children[0].raw, der=True)
    first = inner.children[0]
    rewritten = seq(first.children[0].raw, tlv(0x01, b"\x00"), first.children[-1].raw)
    rebuilt = context(3, seq(rewritten, *[c.raw for c in inner.children[1:]]))
    children[-1] = rebuilt
    again = parse_certificate(rebuild(children, cert))
    assert again.extensions[0].critical is False
    assert again.extensions[0].dotted_oid == cert.extensions[0].dotted_oid
