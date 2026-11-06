"""Certificate contents: RFC 5280 §4.1 read as structure, with the fields a validator wants.

`x509.certificate_parts()` answers "which bytes are which". This module answers "what does the
document say" - serial, names, validity, extensions - while keeping the stored TLV beside every
answer, so a verifier can hash what arrived and a log can record what it saw.

Two places this walk could go wrong by index and goes right by tag:

**Unique identifiers.** `TBSCertificate` carries optional `issuerUniqueID [1]` and
`subjectUniqueID [2]` between the key and the extensions. They appear in v2 certificates, which are
rare enough that code reading `tbs.children[9]` for extensions has never met one - and then breaks
on one. Extensions are found by their `[3]` tag, so whatever sits in between does not matter.

**Extension defaults.** `critical` has `DEFAULT FALSE`, which in DER means the field is *absent*,
not written as `FALSE`. An extension with two children is not malformed; it is not critical.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from .errors import CertificateError
from .name import Name, parse_name
from .node import Node, decode
from .oid import decode_oid
from .tag import Tag, TagClass
from .time import check_generalized_time, check_utc_time
from .x509 import Validity, certificate_parts

__all__ = ["Certificate", "Extension", "parse_certificate", "parse_extensions"]

_SEQUENCE = Tag(16, True, TagClass.universal)
_OCTET_STRING = Tag(4, False, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)
_INTEGER = Tag(2, False, TagClass.universal)
_BOOLEAN = Tag(1, False, TagClass.universal)
_EXTENSIONS_SLOT = Tag(3, True, TagClass.context)
_VERSION_SLOT = Tag(0, True, TagClass.context)
_UNIQUE_ID_SLOTS = (Tag(1, False, TagClass.context), Tag(2, False, TagClass.context))

# Extension OIDs named here only so a caller can ask "have I seen this one before" without a
# literal. Recognising an extension is not the same as validating it - that is `pkix`'s work - and
# nothing in this module interprets an extension payload.
_KNOWN_EXTENSIONS = frozenset(
    {
        (2, 5, 29, 14),  # subjectKeyIdentifier
        (2, 5, 29, 15),  # keyUsage
        (2, 5, 29, 17),  # subjectAltName
        (2, 5, 29, 19),  # basicConstraints
        (2, 5, 29, 21),  # crlReason, also used in CRL entry extensions
        (2, 5, 29, 32),  # certificatePolicies
        (2, 5, 29, 35),  # authorityKeyIdentifier
        (2, 5, 29, 46),  # fcpi-forbid
    }
)


@dataclass(frozen=True, slots=True)
class Extension:
    """One extension: its type, whether it is critical, and its unparsed payload.

    ``value`` is the OCTET STRING's content - the nested DER, not the wrapper - and ``raw`` is the
    whole `Extension` SEQUENCE as it arrived. Leaving the payload unparsed is deliberate: a codec
    that dropped what it did not recognise would defeat the reason it exists.
    """

    oid: tuple[int, ...]
    critical: bool
    value: bytes
    raw: bytes

    @property
    def dotted_oid(self) -> str:
        return ".".join(str(part) for part in self.oid)

    @property
    def recognised(self) -> bool:
        return self.oid in _KNOWN_EXTENSIONS


@dataclass(frozen=True, slots=True)
class Certificate:
    """A parsed certificate. Every field keeps the bytes it was decoded from."""

    raw: bytes
    tbs_certificate: bytes
    serial: int
    version: int
    signature_algorithm: tuple[int, ...]
    signature_algorithm_raw: bytes
    signature_value: bytes
    issuer: Name
    subject: Name
    validity: Validity
    subject_public_key_info: bytes
    extensions: tuple[Extension, ...]

    @property
    def critical_extensions(self) -> tuple[Extension, ...]:
        return tuple(ext for ext in self.extensions if ext.critical)

    @property
    def unrecognised_critical(self) -> tuple[Extension, ...]:
        """Extensions this package does not know, which the certificate says must not be ignored.

        RFC 5280 §4.2: a certificate whose critical extension cannot be understood must be
        rejected. Listing them is this layer's job; deciding is `pkix`'s.
        """
        return tuple(ext for ext in self.extensions if ext.critical and not ext.recognised)

    def extension(self, dotted_oid: str) -> Extension | None:
        target = tuple(int(part) for part in dotted_oid.split("."))
        for ext in self.extensions:
            if ext.oid == target:
                return ext
        return None

    @property
    def self_issued(self) -> bool:
        return self.issuer == self.subject


def parse_certificate(buffer: bytes, *, der: bool = True) -> Certificate:
    """Read a certificate's contents, locating fields by tag rather than by position.

    Raises:
        CertificateError: the document is not a certificate, or a field it requires holds
            something else - a non-INTEGER serial, a version slot with no INTEGER inside, an
            extension list that is not a SEQUENCE of well-formed `Extension`.
        DerViolation, TruncatedError, DecodeError: from the codec, as usual.
    """
    parts = certificate_parts(buffer, der=der)
    tbs, _ = decode(parts.tbs_certificate, der=der)

    fields = list(tbs.children)
    version = 0
    if fields and fields[0].tag == _VERSION_SLOT:
        version = _read_version(fields.pop(0))

    required = (
        "serialNumber",
        "signature",
        "issuer",
        "validity",
        "subject",
        "subjectPublicKeyInfo",
    )
    if len(fields) < len(required):
        raise CertificateError(
            f"tbsCertificate stops after {len(fields)} field(s), needs all {len(required)}"
        )
    head, rest = fields[: len(required)], fields[len(required) :]
    if head[0].tag != _INTEGER or head[0].payload is None:
        raise CertificateError(f"serialNumber is an INTEGER, found tag {head[0].tag!r}")
    for name, node in zip(required[1:], head[1:], strict=True):
        if node.tag != _SEQUENCE:
            raise CertificateError(f"{name} is a SEQUENCE, found tag {node.tag!r}")

    # `rest` may hold issuerUniqueID [1], subjectUniqueID [2] and the [3] extensions slot, in any
    # combination. Anything else in that tail is a shape this grammar does not describe.
    for node in rest:
        if node.tag in _UNIQUE_ID_SLOTS or node.tag == _EXTENSIONS_SLOT:
            continue
        raise CertificateError(
            f"unexpected field after subjectPublicKeyInfo: tag {node.tag!r} "
            "(only issuerUniqueID, subjectUniqueID and extensions may follow it)"
        )

    algorithm_node, _ = decode(parts.signature_algorithm, der=der)
    if algorithm_node.tag != _SEQUENCE or not algorithm_node.children:
        raise CertificateError("signatureAlgorithm is a SEQUENCE starting with an OID")
    if algorithm_node.children[0].tag != _OID or algorithm_node.children[0].payload is None:
        raise CertificateError(
            f"signatureAlgorithm starts with an OID, found {algorithm_node.children[0].tag!r}"
        )

    return Certificate(
        raw=parts.raw,
        tbs_certificate=parts.tbs_certificate,
        serial=int.from_bytes(head[0].payload, "big", signed=True),
        version=version,
        signature_algorithm=decode_oid(algorithm_node.children[0].payload),
        signature_algorithm_raw=parts.signature_algorithm,
        signature_value=parts.signature_value,
        issuer=parse_name(head[2]),
        subject=parse_name(head[4]),
        validity=_read_validity(head[3]),
        subject_public_key_info=parts.subject_public_key_info,
        extensions=_read_extensions(rest),
    )


def _read_version(slot: Node) -> int:
    if len(slot.children) != 1 or slot.children[0].tag != _INTEGER:
        raise CertificateError("the version slot must hold exactly one INTEGER")
    payload = slot.children[0].payload
    if not payload:
        raise CertificateError("the version carries no content")
    value = int.from_bytes(payload, "big", signed=True)
    if value not in (0, 1, 2):
        raise CertificateError(f"version {value} is not one of v1, v2 or v3")
    return value


def _read_validity(node: Node) -> Validity:
    if len(node.children) != 2:
        raise CertificateError(f"Validity has two fields, found {len(node.children)}")
    low, high = node.children
    return Validity(
        not_before=_read_time(low),
        not_after=_read_time(high),
        raw=node.raw,
        not_before_raw=low.raw,
        not_after_raw=high.raw,
    )


def _read_time(node: Node) -> datetime.datetime:
    """Read a `Time`: UTCTime or GeneralizedTime, both defined in RFC 5280 §4.1.2.5."""
    content = node.payload
    if node.tag.number == 23 and content is not None:
        return check_utc_time(content)
    if node.tag.number == 24 and content is not None:
        return check_generalized_time(content)
    raise CertificateError(f"a Time is UTCTime or GeneralizedTime, found tag {node.tag!r}")


def _read_extensions(fields: list[Node]) -> tuple[Extension, ...]:
    """Find the `[3]` slot wherever it sits, and read the list inside it."""
    for node in fields:
        if node.tag == _EXTENSIONS_SLOT:
            if len(node.children) != 1 or node.children[0].tag != _SEQUENCE:
                raise CertificateError("extensions is [3] EXPLICIT wrapping a SEQUENCE")
            return parse_extensions(node.children[0])
    return ()


def parse_extensions(node: Node) -> tuple[Extension, ...]:
    """Read `SEQUENCE OF Extension`, honouring the `DEFAULT FALSE` that makes `critical` absent.

    Shared with `crl.py`: CRL extensions and CRL entry extensions use the same structure, and
    reading them a second time by a slightly different implementation is how the two drift apart.
    """
    if node.tag != _SEQUENCE:
        raise CertificateError(f"an Extensions list is a SEQUENCE, found tag {node.tag!r}")
    out: list[Extension] = []
    for child in node.children:
        if child.tag != _SEQUENCE:
            raise CertificateError(f"an Extension is a SEQUENCE, found tag {child.tag!r}")
        if len(child.children) not in (2, 3):
            raise CertificateError(
                f"an Extension has two or three fields, found {len(child.children)}"
            )
        oid_node = child.children[0]
        if oid_node.tag != _OID or oid_node.payload is None:
            raise CertificateError(f"an extension id is an OID, found tag {oid_node.tag!r}")
        value_node = child.children[1]
        critical = False
        if len(child.children) == 3:
            flag = child.children[1]
            if flag.tag != _BOOLEAN or flag.payload not in (b"\xff", b"\x00"):
                raise CertificateError("an extension's critical flag is a canonical BOOLEAN")
            critical = flag.payload == b"\xff"
            value_node = child.children[2]
        if value_node.tag != _OCTET_STRING or value_node.payload is None:
            raise CertificateError(
                f"an extension value is an OCTET STRING, found tag {value_node.tag!r}"
            )
        out.append(
            Extension(
                oid=decode_oid(oid_node.payload),
                critical=critical,
                value=value_node.payload,
                raw=child.raw,
            )
        )
    return tuple(out)
