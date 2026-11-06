"""RFC 7468 armour corpus: Appendix A's non-conforming examples, the three grammars of §3, erratum 4508.

The four boundary blocks below are copied verbatim from Appendix A ("examples for the non-recommended label
variants ... useful for interoperability testing"), so this file is the interop corpus the appendix asks for
rather than a set of inputs invented to agree with the implementation. Fixture DER comes from the two vendored
trust-store roots already in `tests/fixtures/`; the armour layer treats payload octets as opaque, so every DER
fixture round-trips, including the CRL.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asn1core import decode
from asn1core.errors import ArmourError
from asn1core.pem import APPENDIX_A_LABELS, certificates, encode, label_issues, parse

FIXTURES = Path(__file__).parent / "fixtures"
ROOTS = ("root-rsa.der", "root-ecdsa.der")

X509_CERT = """-----BEGIN X509 CERTIFICATE-----
MIIBHDCBxaADAgECAgIcxzAJBgcqhkjOPQQBMBAxDjAMBgNVBAMUBVBLSVghMB4X
DTE0MDkxNDA2MTU1MFoXDTI0MDkxNDA2MTU1MFowEDEOMAwGA1UEAxQFUEtJWCEw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwoQSr863QrR0PoRIYQ96H7WykDePH
Wa0eVAE24bth43wCNc+U5aZ761dhGhSSJkVWRgVH5+prLIr+nzfIq+X4oxAwDjAM
BgNVHRMBAf8EAjAAMAkGByqGSM49BAEDRwAwRAIfMdKS5F63lMnWVhi7uaKJzKCs
NnY/OKgBex6MIEAv2AIhAI2GdvfL+mGvhyPZE+JxRxWChmggb5/9eHdUcmW/jkOH
-----END X509 CERTIFICATE-----
"""

XDOT509_CERT = X509_CERT.replace("X509 CERTIFICATE", "X.509 CERTIFICATE")

NEW_CSR = """-----BEGIN NEW CERTIFICATE REQUEST-----
MIIBWDCCAQcCAQAwTjELMAkGA1UEBhMCU0UxJzAlBgNVBAoTHlNpbW9uIEpvc2Vm
c3NvbiBEYXRha29uc3VsdCBBQjEWMBQGA1UEAxMNam9zZWZzc29uLm9yZzBOMBAG
ByqGSM49AgEGBSuBBAAhAzoABLLPSkuXY0l66MbxVJ3Mot5FCFuqQfn6dTs+9/CM
EOlSwVej77tj56kj9R/j9Q+LfysX8FO9I5p3oGIwYAYJKoZIhvcNAQkOMVMwUTAY
BgNVHREEETAPgg1qb3NlZnNzb24ub3JnMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/
BAUDAwegADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgM/ADA8
AhxBvfhxPFfbBbsE1NoFmCUczOFApEuQVUw3ZP69AhwWXk3dgSUsKnuwL5g/ftAY
dEQc8B8jAcnuOrfU
-----END NEW CERTIFICATE REQUEST-----
"""

CERT_CHAIN = """-----BEGIN CERTIFICATE CHAIN-----
MIHjBgsqhkiG9w0BCRABF6CB0zCB0AIBADFho18CAQCgGwYJKoZIhvcNAQUMMA4E
CLfrI6dr0gUWAgITiDAjBgsqhkiG9w0BCRADCTAUBggqhkiG9w0DBwQIZpECRWtz
u5kEGDCjerXY8odQ7EEEromZJvAurk/j81IrozBSBgkqhkiG9w0BBwEwMwYLKoZI
hvcNAQkQAw8wJDAUBggqhkiG9w0DBwQI0tCBcU09nxEwDAYIKwYBBQUIAQIFAIAQ
OsYGYUFdAH0RNc1p4VbKEAQUM2Xo8PMHBoYdqEcsbTodlCFAZH4=
-----END CERTIFICATE CHAIN-----
"""

APPENDIX_A = (
    (X509_CERT, "X509 CERTIFICATE"),
    (XDOT509_CERT, "X.509 CERTIFICATE"),
    (NEW_CSR, "NEW CERTIFICATE REQUEST"),
    (CERT_CHAIN, "CERTIFICATE CHAIN"),
)


def fixture(name: str) -> bytes:
    path = FIXTURES / name
    data = path.read_bytes()
    assert data[:1] == b"\x30", (
        f"{name} is not a DER SEQUENCE"
    )  # vacuity guard on the fixtures themselves
    return data


def test_appendix_a_examples_parse_and_keep_their_labels() -> None:
    for text, label in APPENDIX_A:
        blocks = parse(text.encode("ascii"))
        assert len(blocks) == 1, label
        assert blocks[0].label == label
        assert label in APPENDIX_A_LABELS


def test_appendix_a_labels_are_never_reported_as_certificates() -> None:
    """§2 ¶4: a parser may interpret contents as another label type but must know the security implications.

    The default is not to guess. A legacy spelling is visible in `label`, never folded into `CERTIFICATE`.
    """
    for text, _label in APPENDIX_A:
        assert certificates(text.encode("ascii")) == ()


def test_appendix_a_payloads_are_structures() -> None:
    for text, label in APPENDIX_A:
        block = parse(text.encode("ascii"))[0]
        node = decode(block.der)[0]
        assert node.tag.number == 16, label
        assert block.canonical is True


def test_boundaries_are_case_sensitive_per_erratum_4508() -> None:
    """Erratum 4508 makes preeb/posteb `%s` literals: "nearly all implementations enforce the case sensitivity".

    So a lowercase boundary is not a block in any mode - and §2 ¶1 means the answer is "no blocks", not an error.
    """
    for text in (X509_CERT.lower(), X509_CERT.replace("-----BEGIN", "-----Begin")):
        for mode in ("strict", "standard", "lax"):
            assert parse(text.encode("ascii"), mode=mode) == ()


def test_dash_count_is_exactly_five() -> None:
    """§2 ¶3: "exactly five hyphen-minus ... on both ends ... no more, no less"."""
    good = encode(fixture(ROOTS[0]))
    assert len(parse(good)) == 1
    for bad in (
        b"----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
        b"------BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
        b"-----BEGIN CERTIFICATE----\nQUJD\n-----END CERTIFICATE-----\n",
        # The case a regex gets wrong: six trailing dashes must not become the label "CERTIFICATE-".
        b"-----BEGIN CERTIFICATE------\nQUJD\n-----END CERTIFICATE-----\n",
    ):
        assert parse(bad) == ()
    # An open boundary with no close boundary is a broken block, not an empty file.
    with pytest.raises(ArmourError):
        parse(b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE------\n")


def test_no_header_region() -> None:
    """§2 ¶5: textual encoding "does *not* define or permit headers to be encoded alongside the data"."""
    armed = (
        b"-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nQUJD\n-----END CERTIFICATE-----\n"
    )
    with pytest.raises(ArmourError):
        parse(armed)
    with pytest.raises(ArmourError):
        parse(armed, mode="lax")


def test_extra_space_belongs_to_the_label() -> None:
    """§2 ¶3: "exactly one space character (SP) separating the BEGIN or END from the label"."""
    text = b"-----BEGIN  CERTIFICATE-----\nQUJD\n-----END  CERTIFICATE-----\n"
    blocks = parse(text)
    assert len(blocks) == 1
    assert blocks[0].label == " CERTIFICATE"
    assert "label begins or ends with a separator" in blocks[0].label_problems()
    with pytest.raises(ArmourError):
        parse(text, mode="strict")


def test_label_issues_agrees_with_appendix_a() -> None:
    """The appendix calls these labels non-recommended by *type*, not ill-formed by grammar: all four pass."""
    assert label_issues("CERTIFICATE") == ()
    for _text, label in APPENDIX_A:
        assert label_issues(label) == (), label
    assert label_issues("certificate")  # lowercase: §2 ¶2 says labels are uppercase


def test_strict_roundtrip_of_every_fixture() -> None:
    """§2 ¶8 in the generator's direction: 64-character lines, canonical base64, payload octets untouched."""
    paths = sorted(FIXTURES.glob("*.der"))
    assert paths, "no DER fixtures to round-trip"
    for path in paths:
        der = path.read_bytes()
        armed = encode(der)
        blocks = parse(armed, mode="strict")
        assert len(blocks) == 1, path.name
        assert blocks[0].der == der, path.name
        assert blocks[0].canonical is True
        assert blocks[0].raw == armed, "raw must be the armour as received, boundaries included"
        parts = armed.split(b"\n")
        body = parts[1:-2]
        assert all(len(line) == 64 for line in body[:-1]), path.name
        assert 1 <= len(body[-1]) <= 64


def test_bundle_keeps_order_and_labels() -> None:
    """§2 ¶9: "Files MAY contain multiple textual encoding instances", ordered by context."""
    first, second = (fixture(name) for name in ROOTS)
    bundle = encode(first) + encode(second)
    found = certificates(bundle)
    assert [block.der for block in found] == [first, second]


def test_text_before_and_after_boundaries_is_ignored() -> None:
    """§2 ¶1: "Data before the encapsulation boundaries are permitted, and parsers MUST NOT malfunction"."""
    der = fixture(ROOTS[0])
    text = (
        b"subject=CN = Example Root\n" + encode(der) + b"issuer=CN = Example Root\ntrailing junk\n"
    )
    blocks = parse(text)
    assert len(blocks) == 1
    assert blocks[0].der == der
    assert parse(b"") == ()


def test_every_admitted_line_ending() -> None:
    """§3 ¶10: eol is CRLF, CR or LF - and §2 ¶1 requires parsers to handle different newline conventions."""
    der = fixture(ROOTS[1])
    armed = encode(der)
    for variant in (armed, armed.replace(b"\n", b"\r\n"), armed.replace(b"\n", b"\r")):
        for mode in ("strict", "standard", "lax"):
            blocks = parse(variant, mode=mode)
            assert len(blocks) == 1, (mode, variant[:22])
            assert blocks[0].der == der, (mode, variant[:22])


def test_non_canonical_base64_is_accepted_and_marked() -> None:
    """RFC 4648 §3.2 leaves the final bits of a padded group unspecified; strict refuses the non-zero spelling."""
    text = b"-----BEGIN CERTIFICATE-----\nQW==\n-----END CERTIFICATE-----\n"
    blocks = parse(text)
    assert blocks[0].der == b"A"
    assert blocks[0].canonical is False
    with pytest.raises(ArmourError):
        parse(text, mode="strict")
    assert parse(encode(b"A"), mode="strict")[0].canonical is True


def test_seventy_six_character_wrapping_is_not_strict() -> None:
    """The shape OpenSSL and Python's ssl module emit: legal Figure 1, refused by Figure 3."""
    der = fixture(ROOTS[0])
    b64 = encode(der).split(b"\n")[1:-2]
    joined = b"".join(b64)
    wrapped = (
        b"-----BEGIN CERTIFICATE-----\n"
        + b"\n".join(joined[i : i + 76] for i in range(0, len(joined), 76))
        + b"\n-----END CERTIFICATE-----\n"
    )
    for mode in ("standard", "lax"):
        assert parse(wrapped, mode=mode)[0].der == der
    with pytest.raises(ArmourError):
        parse(wrapped, mode="strict")


def test_label_mismatch_between_boundaries() -> None:
    """§2 ¶2: generators MUST repeat the label; parsers MAY disregard a mismatch. Default refuses, lax ignores."""
    text = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END PUBLIC KEY-----\n"
    for mode in ("strict", "standard"):
        with pytest.raises(ArmourError):
            parse(text, mode=mode)
    assert parse(text, mode="lax")[0].label == "CERTIFICATE"


def test_unclosed_and_empty_blocks() -> None:
    with pytest.raises(ArmourError):
        parse(b"-----BEGIN CERTIFICATE-----\nQUJD\n")
    with pytest.raises(ArmourError):
        parse(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
    with pytest.raises(ArmourError):
        parse(b"-----BEGIN CERTIFICATE-----\nQU=\n-----END CERTIFICATE-----\n")
    with pytest.raises(ArmourError):
        parse(b"-----BEGIN CERTIFICATE-----\nQUJDRA==RA==\n-----END CERTIFICATE-----\n")


def test_encode_and_mode_guards() -> None:
    with pytest.raises(ArmourError):
        encode(b"")
    with pytest.raises(ArmourError):
        encode(b"AAA", "Bad Label")
    with pytest.raises(ArmourError):
        encode(b"AAA", "x509 CERTIFICATE")
    with pytest.raises(ValueError, match="mode must be"):
        parse(b"", mode="bogus")  # type: ignore[arg-type]
