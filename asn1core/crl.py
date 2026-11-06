"""Certificate lists: RFC 5280 §5.1, whose shape differs from a certificate in three ways.

**The two extension slots are not alike.** `crlExtensions` on the list is `[0] EXPLICIT Extensions`,
but `crlEntryExtensions` inside an entry is a bare `Extensions` - an untagged SEQUENCE. Assuming the
`[0]` wrapper in both places reads every entry's extensions as missing; assuming a bare SEQUENCE in
both places mistakes the list's own extensions for another entry.

**`nextUpdate` is optional,** and its absence carries meaning ("this is the last CRL that will be
issued") rather than being a hole to fill with a default.

**The version number counts from zero.** `Version ::= INTEGER { v1(0), v2(1), v3(2) }`, so a version
2 CRL - the only kind RFC 5280 §5.1.2.1 allows a conforming issuer to produce - carries the integer
**1**, not 2. A certificate's v3 carries 2. Reading either slot as "the number in the profile's
name" is an off-by-one that no test with only v1 documents would catch.

**A revoked entry's reason defaults, in the schema's own words, to `unspecified(0)`** - so an entry
with no `crlReason` extension is not missing information, it is carrying zero. This module reports
`reason=None` for an absent extension and `reason_name` resolves both to "unspecified", leaving
§6.1.4 - where `keyCompromise(1)` changes which already-validated paths may still be used - to
`pkix`. Decoding says what the document said; it does not decide what to do about it.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from .cert import Extension, parse_extensions
from .errors import CertificateError
from .name import Name, parse_name
from .node import Node, decode
from .oid import decode_oid
from .tag import Tag, TagClass
from .time import check_generalized_time, check_utc_time
from .x509 import signed_document_parts

__all__ = ["Crl", "Revoked", "parse_crl"]

_TIME_TAGS = frozenset({Tag(23, False, TagClass.universal), Tag(24, False, TagClass.universal)})
_CRL_EXTENSIONS_SLOT = Tag(0, True, TagClass.context)
# Doubled from cert.py rather than imported: those names are private there, and reaching into
# another module for its constants couples two grammars that are otherwise independent.
_SEQUENCE = Tag(16, True, TagClass.universal)
_INTEGER = Tag(2, False, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)
_ENUMERATED = Tag(10, False, TagClass.universal)

# crlReason, RFC 5280 §5.3.1: unspecified 0, keyCompromise 1, cACompromise 2, affiliationChanged 3,
# superseded 4, cessationOfOperation 5, certificateHold 6, 7 unused, removeFromCRL 8,
# privilegeWithdrawn 9, aACompromise 10.
#
# Worth writing out rather than recalling: cessationOfOperation is 5 and keyCompromise is 1, so the
# intuition that the dramatic reasons come first lands keyCompromise on the wrong number - and
# §6.1.4 keys one of the strictest validation rules in the profile off exactly that value. The
# committed fixture confirms 1 on the wire (`0A 01 01`).
REASON_UNSPECIFIED = 0
REASON_KEY_COMPROMISE = 1
REASON_CA_COMPROMISE = 2
REASON_REMOVE_FROM_CRL = 8
REASON_NAMES = {
    0: "unspecified",
    1: "keyCompromise",
    2: "cACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
    8: "removeFromCRL",
    9: "privilegeWithdrawn",
    10: "aACompromise",
}
_CRL_REASON_OID = (2, 5, 29, 21)


@dataclass(frozen=True, slots=True)
class Revoked:
    """One revoked certificate, with the entry's bytes kept intact."""

    serial: int
    revocation_date: datetime.datetime
    reason: int | None
    extensions: tuple[Extension, ...]
    raw: bytes

    @property
    def reason_name(self) -> str:
        """The reason as §5.3.1 names it. An absent extension means `unspecified(0)`."""
        value = REASON_UNSPECIFIED if self.reason is None else self.reason
        return REASON_NAMES.get(value, f"unknown({value})")

    @property
    def compromised(self) -> bool:
        """Whether §6.1.4's compromise rule applies to this entry.

        True only for keyCompromise(1) and cACompromise(2). The other reasons say a certificate was
        retired; these two say the private key may be in someone else's hands, which is why the
        profile stops trusting paths that were validated before the revocation was published.
        """
        return self.reason in (REASON_KEY_COMPROMISE, REASON_CA_COMPROMISE)


@dataclass(frozen=True, slots=True)
class Crl:
    """A parsed certificate list. `version` is the encoded number: 1 means v2."""

    raw: bytes
    tbs_cert_list: bytes
    version: int
    signature_algorithm: tuple[int, ...]
    signature_algorithm_raw: bytes
    signature_value: bytes
    issuer: Name
    this_update: datetime.datetime
    this_update_raw: bytes
    next_update: datetime.datetime | None
    next_update_raw: bytes | None
    revoked: tuple[Revoked, ...]
    extensions: tuple[Extension, ...]

    @property
    def revoked_serials(self) -> tuple[int, ...]:
        return tuple(entry.serial for entry in self.revoked)

    def revoked_by_serial(self, serial: int) -> Revoked | None:
        for entry in self.revoked:
            if entry.serial == serial:
                return entry
        return None


def parse_crl(buffer: bytes, *, der: bool = True) -> Crl:
    """Read a certificate list, locating its optional fields by tag rather than by position.

    `CertificateList` and `Certificate` share the outer shape, so the same slicing helper applies;
    what differs is what sits inside the signed region, and that is all checked here rather than in
    `x509`, which knows nothing about CRL slot order.

    Raises:
        CertificateError: the document is not a CRL, or a field holds something the grammar does
            not allow where it is - a revoked entry with no serial, a list running past
            crlExtensions, an extension slot that is not a list of `Extension`.
        DerViolation, TruncatedError, DecodeError: from the codec, as usual.
    """
    document = signed_document_parts(buffer, der=der, label="CRL")
    children = list(document.tbs.children)

    version = 0
    if children and children[0].tag == _INTEGER:
        version = _read_version(children.pop(0))
    if len(children) < 3:
        raise CertificateError(
            f"a CRL needs signature, issuer and thisUpdate, found {len(children)} field(s)"
        )
    signature, issuer_node, this_update_node = children[:3]
    if signature.tag != _SEQUENCE:
        raise CertificateError(f"a CRL signature algorithm is a SEQUENCE, found {signature.tag!r}")
    if issuer_node.tag != _SEQUENCE:
        raise CertificateError(f"a CRL issuer is a Name, found {issuer_node.tag!r}")
    if this_update_node.tag not in _TIME_TAGS:
        raise CertificateError(f"thisUpdate is a Time, found {this_update_node.tag!r}")

    rest = children[3:]
    next_update = None
    next_update_raw = None
    if rest and rest[0].tag in _TIME_TAGS:
        next_update = _read_time(rest[0])
        next_update_raw = rest[0].raw
        rest = rest[1:]

    # revokedCertificates is an untagged SEQUENCE OF; the list's own extensions are `[0]`. Reading
    # them in the wrong order turns `a0 ...` into a phantom entry or loses the real extensions.
    entries: tuple[Revoked, ...] = ()
    if rest and rest[0].tag == _SEQUENCE:
        entries = tuple(_read_entry(child) for child in rest[0].children)
        rest = rest[1:]

    extensions: tuple[Extension, ...] = ()
    if rest:
        slot = rest[0]
        if slot.tag != _CRL_EXTENSIONS_SLOT or len(slot.children) != 1:
            raise CertificateError(
                f"crlExtensions is [0] EXPLICIT wrapping a SEQUENCE, found tag {slot.tag!r}"
            )
        extensions = parse_extensions(slot.children[0])
        rest = rest[1:]
    if rest:
        raise CertificateError(f"a CRL runs past crlExtensions: extra tag {rest[0].tag!r}")

    algorithm_node, _ = decode(document.signature_algorithm, der=der)
    if algorithm_node.tag != _SEQUENCE or not algorithm_node.children:
        raise CertificateError("signatureAlgorithm is a SEQUENCE starting with an OID")
    if algorithm_node.children[0].tag != _OID or algorithm_node.children[0].payload is None:
        raise CertificateError(
            f"signatureAlgorithm starts with an OID, found {algorithm_node.children[0].tag!r}"
        )

    return Crl(
        raw=document.raw,
        tbs_cert_list=document.to_be_signed,
        version=version,
        signature_algorithm=decode_oid(algorithm_node.children[0].payload),
        signature_algorithm_raw=document.signature_algorithm,
        signature_value=document.signature_value,
        issuer=parse_name(issuer_node),
        this_update=_read_time(this_update_node),
        this_update_raw=this_update_node.raw,
        next_update=next_update,
        next_update_raw=next_update_raw,
        revoked=entries,
        extensions=extensions,
    )


def _read_version(node: Node) -> int:
    if node.payload is None:
        raise CertificateError("the CRL version carries no content")
    value = int.from_bytes(node.payload, "big", signed=True)
    if value not in (0, 1):
        raise CertificateError(
            f"CRL version {value} is neither v1(0) nor v2(1); a version 2 CRL encodes the number 1"
        )
    return value


def _read_time(node: Node) -> datetime.datetime:
    """Read a `Time` field; §5.1.2.4 lets a CRL use UTCTime or GeneralizedTime."""
    content = node.payload
    if node.tag.number == 23 and content is not None:
        return check_utc_time(content)
    if node.tag.number == 24 and content is not None:
        return check_generalized_time(content)
    raise CertificateError(f"a Time is UTCTime or GeneralizedTime, found tag {node.tag!r}")


def _read_entry(node: Node) -> Revoked:
    """Read one `CRLEntry`: serial, date, and optionally a bare untagged `Extensions`."""
    if node.tag != _SEQUENCE or len(node.children) not in (2, 3):
        raise CertificateError(
            f"a CRL entry is a SEQUENCE of two or three fields, found tag {node.tag!r} "
            f"with {len(node.children)}"
        )
    serial_node, date_node = node.children[0], node.children[1]
    if serial_node.tag != _INTEGER or serial_node.payload is None:
        raise CertificateError(f"a CRL entry's serial is an INTEGER, found tag {serial_node.tag!r}")
    if date_node.tag not in _TIME_TAGS:
        raise CertificateError(f"a CRL entry's date is a Time, found tag {date_node.tag!r}")

    extensions: tuple[Extension, ...] = ()
    if len(node.children) == 3:
        extensions = parse_extensions(node.children[2])
    return Revoked(
        serial=int.from_bytes(serial_node.payload, "big", signed=True),
        revocation_date=_read_time(date_node),
        reason=_reason_of(extensions),
        extensions=extensions,
        raw=node.raw,
    )


def _reason_of(extensions: tuple[Extension, ...]) -> int | None:
    """Pull a reason code out of a `crlReason` extension, or None when the extension is absent.

    Two decodings sit between the entry and the number: the extension's value is an OCTET STRING,
    and inside it is the ENUMERATED. A reason written directly as an ENUMERATED with no OCTET STRING
    around it is a plausible encoder slip, so it surfaces as an error rather than being read as some
    other reason.
    """
    for ext in extensions:
        if ext.oid != _CRL_REASON_OID:
            continue
        node, end = decode(ext.value, der=True)
        if end != len(ext.value):
            raise CertificateError(
                f"{len(ext.value) - end} byte(s) follow the crlReason value; "
                "an extension value holds exactly one object"
            )
        if node.tag != _ENUMERATED or not node.payload:
            raise CertificateError(
                f"crlReason is an ENUMERATED inside the OCTET STRING, found tag {node.tag!r}"
            )
        return int.from_bytes(node.payload, "big", signed=False)
    return None
