"""Certificate structure: the parts a verifier asks for, as the octets that arrived.

RFC 5280 §4.1.3.2 verifies a CA signature over the DER encoding of `tbsCertificate`, and a log
that pins a key pins the encoding of its `SubjectPublicKeyInfo`. Both need the codec to hand
back the bytes it parsed rather than an equivalent it produced - invariant I3 in
`certledger/TRUST-MODEL.md` - and this module is where that invariant becomes usable.

Two rules shape the walk, and one of them is the reason this file exists:

**The version is optional.** `TBSCertificate` opens with `version [0] EXPLICIT INTEGER DEFAULT
v1`, and DEFAULT means *absent* in DER. Every field after it shifts by one position when the
version is missing. `tests/fixtures/root-rsa.der` - a root certificate shipped in a live trust
store - is exactly that document, so reading `tbs.children[6]` for the key returns the wrong
object on real input. The version is skipped by tag, never by index.

**A shape mismatch stops the walk.** If a slot holds an unexpected tag the walk raises rather
than looking further ahead. Continuing would return some later child as a public key, which
pins the wrong key and trusts the wrong issuer without a sound.

There is no signature verification here, and no path building: those belong to `pkix`. The
SHA-256 helper below is an identifier, not a security check.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .errors import CertificateError
from .node import Node, decode
from .tag import Tag, TagClass

__all__ = [
    "CertificateParts",
    "certificate_parts",
    "signature_algorithm",
    "spki_sha256",
    "subject_public_key_info",
    "tbs_certificate",
]

_SEQUENCE = Tag(16, True, TagClass.universal)
_INTEGER = Tag(2, False, TagClass.universal)
_BIT_STRING = Tag(3, False, TagClass.universal)

# RFC 5280 §4.1.2.1 defines v1, v2 and v3. A v4 document is not "newer than this library": the
# fields below it may mean something else, so guessing at its structure is refused.
_DEFINED_VERSIONS = frozenset({0, 1, 2})

# The required prefix of TBSCertificate after the optional version. issuer, validity and subject
# are all SEQUENCEs by construction - Name is a CHOICE with one alternative, RDNSequence.
_TBS_FIELDS = (
    ("serialNumber", _INTEGER),
    ("signature AlgorithmIdentifier", _SEQUENCE),
    ("issuer", _SEQUENCE),
    ("validity", _SEQUENCE),
    ("subject", _SEQUENCE),
    ("subjectPublicKeyInfo", _SEQUENCE),
)


@dataclass(frozen=True, slots=True)
class CertificateParts:
    """The pieces an X.509 verifier needs, each one a slice of the document it was parsed from.

    ``raw`` is the whole certificate. ``tbs_certificate`` and ``subject_public_key_info`` are
    stored TLVs - tag and length octets included, because that is what a signature and a key
    hash are computed over. ``signature_value`` is the key octets alone: the BIT STRING's
    leading unused-bits octet is stripped, since handing it back would prepend a zero byte to
    every signature and make verification fail in a way that reads like a bad key.
    """

    raw: bytes
    tbs_certificate: bytes
    signature_algorithm: bytes
    signature_value: bytes
    subject_public_key_info: bytes
    version: int | None


def certificate_parts(buffer: bytes, *, der: bool = True) -> CertificateParts:
    """Split a certificate into the four things consumers key and verify on.

    ``der=True`` is the default and the safe one: a verifier handed a BER spelling is being
    handed bytes no CA ever signed. With ``der=False`` the framing is still enforced and every
    returned slice is still the original octets, so the same key comes out either way - which is
    what makes the tolerant path usable for inventory rather than for trust.

    Raises:
        CertificateError: not the documented structure - the wrong shape, a version RFC 5280
            does not define, a slot holding the wrong tag, trailing bytes, or a signature value
            with unused bits.
        TruncatedError, DecodeError: from the codec, for framing and encoding faults.
        DerViolation: legal BER presented on the DER path.
    """
    node, end = decode(buffer, der=der)
    if end != len(buffer):
        raise CertificateError(
            f"{len(buffer) - end} byte(s) follow the certificate; a document is one object"
        )
    if node.tag != _SEQUENCE:
        raise CertificateError(f"a certificate is a SEQUENCE, found tag {node.tag!r}")
    if len(node.children) != 3:
        raise CertificateError(f"a certificate has three fields, found {len(node.children)}")

    tbs, algorithm, signature = node.children
    if tbs.tag != _SEQUENCE:
        raise CertificateError(f"tbsCertificate is a SEQUENCE, found tag {tbs.tag!r}")

    fields = list(tbs.children)
    version: int | None = None
    if fields and fields[0].tag.is_context(0):
        version = _read_version(fields.pop(0))

    if len(fields) < len(_TBS_FIELDS):
        raise CertificateError(
            f"tbsCertificate stops after {len(fields)} field(s); reaching subjectPublicKeyInfo "
            f"needs all {len(_TBS_FIELDS)}"
        )
    for (name, expected), field in zip(_TBS_FIELDS, fields[: len(_TBS_FIELDS)], strict=True):
        if field.tag != expected:
            raise CertificateError(f"{name} should carry tag {expected!r}, found {field.tag!r}")

    if algorithm.tag != _SEQUENCE:
        raise CertificateError(f"signatureAlgorithm is a SEQUENCE, found tag {algorithm.tag!r}")
    if signature.tag != _BIT_STRING:
        raise CertificateError(f"signatureValue is a BIT STRING, found tag {signature.tag!r}")
    content = signature.payload
    if not content:
        raise CertificateError("signatureValue is an empty BIT STRING")
    if content[0] != 0:
        raise CertificateError(
            f"signatureValue declares {content[0]} unused bits; a signature is whole octets"
        )

    return CertificateParts(
        raw=buffer[:end],
        tbs_certificate=tbs.raw,
        signature_algorithm=algorithm.raw,
        signature_value=content[1:],
        subject_public_key_info=fields[len(_TBS_FIELDS) - 1].raw,
        version=version,
    )


def _read_version(slot: Node) -> int:
    """Read `[0] EXPLICIT INTEGER`. EXPLICIT means an INTEGER sits inside, not a bare value."""
    if len(slot.children) != 1:
        raise CertificateError(
            f"the version slot holds {len(slot.children)} objects, expected one INTEGER"
        )
    (integer,) = slot.children
    payload = integer.payload
    if integer.tag != _INTEGER or not payload:
        raise CertificateError(f"the certificate version is an INTEGER, found {integer.tag!r}")
    value = int.from_bytes(payload, "big", signed=True)
    if value not in _DEFINED_VERSIONS:
        raise CertificateError(f"certificate version {value} is not one of v1, v2 or v3")
    return value


def tbs_certificate(buffer: bytes, *, der: bool = True) -> bytes:
    """The stored `tbsCertificate` TLV - the bytes a CA signature is made over."""
    return certificate_parts(buffer, der=der).tbs_certificate


def subject_public_key_info(buffer: bytes, *, der: bool = True) -> bytes:
    """The stored `SubjectPublicKeyInfo` TLV, which is what a pin is computed from."""
    return certificate_parts(buffer, der=der).subject_public_key_info


def signature_algorithm(buffer: bytes, *, der: bool = True) -> bytes:
    """The stored outer `AlgorithmIdentifier` TLV, the third input to a signature check."""
    return certificate_parts(buffer, der=der).signature_algorithm


def spki_sha256(buffer: bytes, *, der: bool = True) -> str:
    """Lowercase hex SHA-256 of the stored SPKI: an identifier, not a verification.

    This is the fingerprint `certledger` keys observations on. It is deliberately taken over the
    stored bytes: hashing a re-encoding gives a different value for any input that is not
    canonical, and one key occupying two pins is the bug this package exists to prevent.
    """
    return hashlib.sha256(subject_public_key_info(buffer, der=der)).hexdigest()
