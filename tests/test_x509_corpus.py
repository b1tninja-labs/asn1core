"""Certificate structure: `dk.spki`, and why the walk has to be positional.

Two real trust-store roots are the fixtures, copied by `sdk-forge/probe_fixture_facts.py` and
pinned by SHA-256 so the fixture cannot rot unnoticed. Every expected digest in this file was
produced by `cryptography`, an implementation nobody here authored - the same arrangement that
caught the OID first-arc error. Expectations derived from this package's own output would prove
nothing, which is the rule `VECTORS.md` states and this file obeys.

The RSA root matters most, and not because of its key. Its `tbsCertificate` begins
`30 82 01 A5 02 10 70 BA` - a SEQUENCE whose first child is an INTEGER, meaning **no `[0]`
version is present**, because v1 is the default. An implementation that reads
`tbs.children[6]` to find the `subjectPublicKeyInfo` therefore reads the wrong child, in a real
certificate that ships in an operating system's trust store.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from asn1core import (
    CertificateError,
    DerViolation,
    TruncatedError,
    certificate_parts,
    decode,
    spki_sha256,
    subject_public_key_info,
    tbs_certificate,
)

FIXTURES = Path(__file__).parent / "fixtures"

# name -> (whole-document sha256, tbs sha256, spki sha256, spki length, has explicit version)
EXPECTED = {
    "root-ecdsa.der": (
        "26c56ad2208d1e9b152f66853bf4797cbeb7552c1f3f477251e8cb1ae7e797bf",
        "b55db7c5305af60a8a457f5e9b1ca79524825d5c7e41de4964ba1226e4455c8d",
        "8a6e2e9bcec665a03c24d24a1efe631881a8c4a54c96fe00160fa7b0cc535fcd",
        120,
        True,
    ),
    "root-rsa.der": (
        "e7685634efacf69ace939a6b255b7b4fabef42935b50a265acb5cb6027e44e70",
        "b731d2bca9a8fcc9749c973e0fed1f2efadb73cb683dad5dbbdbfa8df3fcc165",
        "b1124142a5a1a5a28819c735340eff8c9e2f8168fee3ba187f253bc1a392d7e2",
        162,
        False,
    ),
}


@pytest.fixture(params=sorted(EXPECTED))
def fixture(request: pytest.FixtureRequest) -> tuple[str, bytes]:
    name = str(request.param)
    path = FIXTURES / name
    if not path.is_file():  # pragma: no cover - guards a partial checkout
        pytest.fail(f"{path} is missing; run sdk-forge/probe_fixture_facts.py")
    return name, path.read_bytes()


def test_the_fixture_itself_is_what_we_think_it_is(fixture: tuple[str, bytes]) -> None:
    """Pinning the input, so a digest mismatch below means code changed and not data."""
    name, der = fixture
    assert hashlib.sha256(der).hexdigest() == EXPECTED[name][0], name


def test_every_part_is_a_contiguous_slice_of_the_original_bytes(fixture: tuple[str, bytes]) -> None:
    """Invariant I3, stated as a property of the bytes rather than of the parse.

    If any part came out of a re-encoding it would still compare equal on canonical input, so
    equality is not enough: the assertion is that each part is found inside the document at the
    same offset it occupied on the way in.
    """
    name, der = fixture
    parts = certificate_parts(der)
    assert parts.raw == der, name
    for label, value in (
        ("tbs", parts.tbs_certificate),
        ("spki", parts.subject_public_key_info),
        ("alg", parts.signature_algorithm),
    ):
        start = der.find(value)
        assert start >= 0, f"{name}: {label} is not present verbatim in the input"
        assert der[start : start + len(value)] == value, f"{name}: {label}"
        assert value in der, label


def test_the_extracted_digests_match_an_independent_implementation(
    fixture: tuple[str, bytes],
) -> None:
    """The numbers `cryptography` printed for these exact bytes on 2026-11-05."""
    name, der = fixture
    _doc, tbs_sha, spki_sha, spki_len, _versioned = EXPECTED[name]
    parts = certificate_parts(der)
    assert hashlib.sha256(parts.tbs_certificate).hexdigest() == tbs_sha, name
    assert hashlib.sha256(parts.subject_public_key_info).hexdigest() == spki_sha, name
    assert len(parts.subject_public_key_info) == spki_len, name
    assert spki_sha256(der) == spki_sha, name
    assert subject_public_key_info(der) == parts.subject_public_key_info, name
    assert tbs_certificate(der) == parts.tbs_certificate, name


def test_the_signature_pieces_are_all_present_for_verification(
    fixture: tuple[str, bytes],
) -> None:
    """What RFC 5280 §4.1.3.2 actually needs: the stored TBS bytes, the algorithm, the bits.

    The signature value is the BIT STRING's payload with the leading unused-bits octet removed.
    Handing a caller the raw content octets instead would append a zero byte to every signature
    and make verification fail in a way that looks like a revoked key.
    """
    name, der = fixture
    parts = certificate_parts(der)
    node, _ = decode(der, der=True)
    signature_bit_string = node.children[2]
    assert signature_bit_string.payload is not None, name
    assert signature_bit_string.payload[0] == 0, name
    assert parts.signature_value == signature_bit_string.payload[1:], name
    assert len(parts.signature_value) > 0, name


def test_a_v1_certificate_without_an_explicit_version_still_finds_the_key(
    fixture: tuple[str, bytes],
) -> None:
    """The bug this fixture exists to catch, on both shapes.

    With no `[0]` child, `children[6]` is an extensions slot that does not exist or the wrong
    object entirely; the walk has to skip the optional version by tag, not by index.
    """
    name, der = fixture
    _doc, _tbs, _spki, _len, versioned = EXPECTED[name]
    parts = certificate_parts(der)
    tbs_node, _end = decode(parts.tbs_certificate, der=True)
    first = tbs_node.children[0]
    assert first.tag.is_context(0) is versioned, name
    assert parts.version == (2 if versioned else None), name
    assert parts.subject_public_key_info[:1] == b"\x30", name
    assert parts.subject_public_key_info in der, name


def _tlv(tag: int, content: bytes) -> bytes:
    """Build one definite-length object. Local on purpose: the expectations must not come from
    the encoder under test."""
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:  # pragma: no cover - the synthetic cases below are all short
        body = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(body)]) + body
    return bytes([tag]) + length + content


def _synthetic_certificate(version: int | None, *, serial: bytes | None = None) -> bytes:
    """The smallest document that satisfies the Certificate grammar, with a chosen version.

    Empty SEQUENCEs stand in for issuer, validity, subject and algorithm: the structural walk
    cares about shape, not content, and keeping the fixture this size means a wrong offset shows
    up as a specific failure instead of a 500-byte mystery. ``serial`` lets a caller put the
    wrong object in the first required slot - rebuilt rather than byte-spliced, because splicing
    changes lengths and turns a shape error into a truncation error.
    """
    fields = []
    if version is not None:
        fields.append(_version_slot(version))
    fields += [
        _tlv(0x02, b"\x01") if serial is None else serial,  # serialNumber
        _tlv(0x30, b""),  # signature AlgorithmIdentifier
        _tlv(0x30, b""),  # issuer
        _tlv(0x30, b""),  # validity
        _tlv(0x30, b""),  # subject
        _tlv(0x30, b""),  # subjectPublicKeyInfo
    ]
    return _tlv(
        0x30,
        _tlv(0x30, b"".join(fields)) + _tlv(0x30, b"") + _tlv(0x03, b"\x00"),
    )


def _version_slot(version: int) -> bytes:
    """`[0] EXPLICIT INTEGER`, the way RFC 5280 spells an explicit certificate version."""
    return _tlv(0xA0, _tlv(0x02, bytes([version])))


def test_the_structural_walk_accepts_each_version_shape() -> None:
    """v1 with the version absent, v3 with it present: both reach the same slot."""
    for version in (None, 0, 2):
        der = _synthetic_certificate(version)
        parts = certificate_parts(der)
        assert parts.subject_public_key_info == _tlv(0x30, b""), version
        assert parts.signature_value == b"", version
        assert parts.tbs_certificate in der, version


@pytest.mark.parametrize("version", [3, 255])
def test_a_version_the_profile_does_not_define_is_refused(version: int) -> None:
    """RFC 5280 §4.1.2.1 defines v1-v3. A v4 certificate is not "newer", it is a parse we should
    not pretend to understand, and reading its children as v3 children is how structure bugs hide.
    """
    with pytest.raises(CertificateError):
        certificate_parts(_synthetic_certificate(version))


NOT_CERTIFICATES = [
    ("an INTEGER is not a certificate", bytes.fromhex("020101")),
    ("an empty SEQUENCE has three fields missing", bytes.fromhex("3000")),
    ("a SEQUENCE with one child", bytes.fromhex("3003020101")),
    (
        "a tbsCertificate that is not a SEQUENCE",
        _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x02") + _tlv(0x03, b"\x00")),
    ),
    (
        "a tbsCertificate too short to reach the key",
        _tlv(0x30, _tlv(0x30, _tlv(0x02, b"\x01")) + _tlv(0x02, b"\x02") + _tlv(0x03, b"\x00")),
    ),
]


@pytest.mark.parametrize(("label", "der"), NOT_CERTIFICATES, ids=[c[0] for c in NOT_CERTIFICATES])
def test_documents_that_are_not_certificates_are_refused(label: str, der: bytes) -> None:
    """Each of these would be *read* by a walk that skips over an unexpected tag instead of
    stopping. `label` is asserted with the outcome so a failure names the shape."""
    with pytest.raises(CertificateError, match=r".+"):
        certificate_parts(der)
    assert label  # keeps the case name in the assertion trail rather than only in the id


def test_a_short_document_is_a_truncation_not_a_shape_error() -> None:
    """The distinction matters to whoever catches this: one is attack surface, one is a bug."""
    der = FIXTURES.joinpath("root-rsa.der").read_bytes()
    with pytest.raises(TruncatedError):
        certificate_parts(der[: len(der) // 2])


def test_the_der_flag_threads_through_to_the_inner_objects() -> None:
    """A BER-spelled certificate: refused by default, and still the same key when tolerated.

    The non-minimal outer length changes nothing about which bytes are the key. That is the
    point of keeping `raw`: the tolerant path and the strict path disagree about the document
    and agree about the identity, instead of the tolerant path quietly re-encoding it.
    """
    der = FIXTURES.joinpath("root-ecdsa.der").read_bytes()
    assert der[1] == 0x82, "fixture is expected to use a two-octet definite length"
    content_length = int.from_bytes(der[2:4], "big")
    # Same content, four length octets with two leading zeros where two suffice: legal BER, and
    # exactly the non-minimal form DER refuses. Derived from the fixture rather than hardcoded,
    # because a header typed from memory is how a test ends up asserting nothing.
    ber = der[:1] + bytes([0x84]) + content_length.to_bytes(4, "big") + der[4:]
    assert len(ber) == len(der) + 2
    with pytest.raises(DerViolation):
        certificate_parts(ber)
    parts = certificate_parts(ber, der=False)
    assert parts.subject_public_key_info == subject_public_key_info(der)
    assert parts.tbs_certificate == tbs_certificate(der)
    assert parts.raw == ber, "the document it was given, non-minimal header and all"


def test_the_walk_stops_at_the_shape_rather_than_guessing_past_it() -> None:
    """A tbsCertificate whose serial slot holds a SEQUENCE is refused, not re-read.

    Silence here would mean returning some later child as the public key, which is the failure
    mode with a security consequence: the wrong key pinned, the wrong issuer trusted. The name of
    the offending slot is part of the message, so a caller can tell "not a certificate" from
    "certificate I cannot finish reading".
    """
    with pytest.raises(CertificateError, match="serialNumber"):
        certificate_parts(_synthetic_certificate(2, serial=_tlv(0x30, b"")))
    with pytest.raises(CertificateError, match="serialNumber"):
        certificate_parts(_synthetic_certificate(None, serial=_tlv(0x03, b"\x00")))
