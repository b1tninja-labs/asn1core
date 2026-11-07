"""Distinguished names: the structure RFC 5280 §4.1.2.4 defines, and the comparison §7.1 requires.

A `Name` is a `SEQUENCE OF RelativeDistinguishedName`, and an RDN is a `SET OF`
attribute-type-and-value pairs - so a name is a sequence of *sets*, and two names being equal is
not a byte comparison. Two independent things can go wrong: reading the structure in the wrong
shape, and comparing two spellings of the same name as if they differed.

**On structure.** An RDN may hold several attributes, which RFC 4514 renders with `+` and which
path validation must match as a set rather than by position. No certificate in the local trust
store contains one - 577 RDNs measured, all single-valued - so `tests/fixtures/multivalue-rdn.der`
is generated for that case and labelled as a synthetic document rather than passed off as
something a CA issued.

**On comparison.** §7.1: "Conforming implementations MUST use the LDAP StringPrep profile
(including insignificant space handling), as specified in [RFC4518], as the basis for comparison of
distinguished name attributes encoded in either PrintableString or UTF8String", MUST support
`caseIgnoreMatch`, and before comparing MUST perform the six-step string preparation with case
folding and the white space compression of RFC 4518 §2.6.1 - a pointer printed as "RFC 4158" and
corrected by verified erratum 7658. Two attributes match when the types are the same and the
prepared values are equal; two RDNs match when they hold the same number of attributes and pair
off; two names match when they have the same number of RDNs, pair off, **and appear in the same
order**.

The whole profile is implemented, in `stringprep.py`: §2.2's mapping lists as corrected by erratum
860, §2.3 normalisation, case folding, and §2.6.1 space handling. Two things there are worth knowing
before trusting a StringPrep you have met elsewhere. §2.5 does nothing at all - RFC 4518 ignores
bidirectional characters rather than checking them - and §2.4's prohibited-character gate is applied
by `stringprep.prepare_value` but deliberately not by `normalize_value`, so that a certificate
already in circulation never stops matching its own spelling because one code point is odd. That
split is recorded in `PLAN.md` as a decision, not a gap.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import CertificateError
from .node import Node
from .oid import decode_oid
from .stringprep import insignificant_space, prepare_mapped
from .tag import Tag, TagClass

__all__ = [
    "SHORT_NAMES",
    "Attribute",
    "Name",
    "names_equal",
    "normalize_value",
    "parse_name",
    "within",
]

_SEQUENCE = Tag(16, True, TagClass.universal)
_SET = Tag(17, True, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)


# AttributeValue is a CHOICE of string types, and the codec each one carries is part of the
# definition: BMPString is UTF-16BE, UniversalString is UTF-32BE. §7.1 makes support for
# TeletexString, BMPString and UniversalString optional; UTF8String and PrintableString are the
# two a conforming implementation MUST support. The ASCII-restricted types are read as Latin-1 so
# that decoding never rejects a byte - whether the characters are legal for the type is enforced
# on the DER path in der.py, not guessed at here. A codec of None means the ambiguous ones: try
# UTF-8, then fall back to Latin-1.
#
# The tag numbers come from Rec. ITU-T X.680 (02/2021) Table 1 (§8.6), which assigns universal
# 13 to the Relative object identifier type and 14 to the TIME type and puts character string
# types in 18-22 and 25-30, together with the restricted-character-string table in §41 that
# numbers NumericString 18, PrintableString 19 and TeletexString (T61String) 20. An earlier
# version of this table had 13 numericString, 14 printableString, 19 teletexString and
# 20 videotexString, which is the 18-22 band shifted down four places with two invented entries
# added. It survived because every affected value is ASCII: 520 of the 577 attribute values in the
# local trust store carry tag 19, and a PrintableString decoded as Latin-1 gives the same text as a
# TeletexString decoded through the ambiguous path, so the only observable symptom was `kind` -
# which is documented as load-bearing, and which was therefore wrong for almost every name in a
# default Windows trust store. Confirmed against three independent sources on 2026-11-07: the
# store's own bytes, cryptography's encoder (it emits 0x13 for `C=US` and 0x16 for a domain
# component), and X.680.
#
# VideotexString and GraphicString are deliberately absent: both are character string types inside the
# bands X.680 Table 1 describes, but I could not re-read their individual numbers from the extracted text
# this session, and inventing a tag for a type this repository cannot measure is exactly how the table broke
# in the first place. An attribute value carrying an unmodelled string tag is refused by name below rather
# than mislabelled.
_CODECS: dict[int, tuple[str, str | None]] = {
    12: ("utf8String", "utf-8"),
    18: ("numericString", "latin-1"),
    19: ("printableString", "latin-1"),
    20: ("teletexString", None),
    22: ("ia5String", "latin-1"),
    26: ("visibleString", "latin-1"),
    27: ("generalString", "latin-1"),
    28: ("universalString", "utf-32-be"),
    30: ("bmpString", "utf-16-be"),
}

# X.680 Table 1: the universal tags that name a character string type. Two of them are not modelled
# above, and a value under one of those is a string type that this codec declines, not a value that is
# not a string. Saying which is the difference between an honest refusal and a false statement.
_CHARACTER_STRING_TAGS = frozenset({*range(18, 23), *range(25, 31)})

# RFC 4514 §3's descriptor table. Types outside it render as dotted OIDs: cryptography does the
# same, including for emailAddress, and inventing a short name would make two renderings of one
# name disagree.
SHORT_NAMES: dict[tuple[int, ...], str] = {
    (2, 5, 4, 3): "CN",
    (2, 5, 4, 6): "C",
    (2, 5, 4, 7): "L",
    (2, 5, 4, 8): "ST",
    (2, 5, 4, 9): "STREET",
    (2, 5, 4, 10): "O",
    (2, 5, 4, 11): "OU",
    (2, 5, 4, 12): "TITLE",
    (0, 9, 2342, 19200300, 100, 1, 25): "DC",
    (0, 9, 2342, 19200300, 100, 1, 1): "UID",
}


@dataclass(frozen=True, slots=True)
class Attribute:
    """One attribute type and value, with the string type that carried it.

    ``kind`` is kept because it is not incidental: a value that arrives as TeletexString is
    decoded by a rule §7.1 makes optional, and a caller deciding whether two names match needs to
    know which side leaned on that rule.
    """

    oid: tuple[int, ...]
    value: str
    kind: str

    @property
    def dotted_oid(self) -> str:
        return ".".join(str(part) for part in self.oid)

    @property
    def short_name(self) -> str:
        return SHORT_NAMES.get(self.oid, self.dotted_oid)


@dataclass(frozen=True, slots=True, eq=False)
class Name:
    """A distinguished name: a sequence of RDNs, each an unordered set of attributes.

    The sequence is held in **encoding order**, which is most general first - a root's ``C=`` sits
    at index 0 and a leaf's ``CN=`` last. RFC 4514 strings are the other way round, so `rfc4514`
    reverses on the way out. Getting this backwards inverts every subtree test, which is the
    difference between "this certificate was issued by Example" and "anyone can claim Example".

    Equality is §7.1's match, not the dataclass comparison: neither ``raw`` nor the string type
    that carried a value takes part in it, because one name legitimately appears as ``C=US`` in
    PrintableString in one document and ``C=us`` in UTF8String in another. Comparing the bytes
    would call those two different names - and would agree that a self-signed certificate's issuer
    and subject match only because their TLVs happen to be identical, which is the right answer for
    the wrong reason.
    """

    rdnsets: tuple[tuple[Attribute, ...], ...]
    raw: bytes

    def values(self, dotted_oid: str) -> tuple[str, ...]:
        """Every value carried for this attribute type, in encoding order."""
        target = tuple(int(part) for part in dotted_oid.split("."))
        return tuple(attr.value for rdn in self.rdnsets for attr in rdn if attr.oid == target)

    def first(self, dotted_oid: str) -> str | None:
        found = self.values(dotted_oid)
        return found[0] if found else None

    @property
    def common_name(self) -> str | None:
        return self.first("2.5.4.3")

    def rfc4514(self) -> str:
        """The RFC 4514 string form: most specific RDN first, attributes of one RDN joined by `+`."""
        return ",".join("+".join(_pair(attr) for attr in rdn) for rdn in reversed(self.rdnsets))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Name):
            return NotImplemented
        return names_equal(self, other)

    def __hash__(self) -> int:
        # Consistent with __eq__ in both directions: RDN order is significant and attribute order
        # inside an RDN is not, so the attributes are sorted before hashing.
        return hash(
            tuple(
                tuple(sorted((attr.oid, normalize_value(attr.value)) for attr in rdn))
                for rdn in self.rdnsets
            )
        )

    def __str__(self) -> str:
        return self.rfc4514()


def parse_name(node: Node) -> Name:
    """Read a `Name` from a parsed node, refusing anything shaped differently.

    Raises:
        CertificateError: the node is not `SEQUENCE OF SET OF SEQUENCE (OID, string)`; an RDN is
            empty; an attribute value carries a tag that is not one of the string types; or a
            string cannot be decoded in the codec its type declares.
    """
    if node.tag != _SEQUENCE:
        raise CertificateError(f"a Name is a SEQUENCE OF RDN, found tag {node.tag!r}")

    rdnsets: list[tuple[Attribute, ...]] = []
    for rdn in node.children:
        if rdn.tag != _SET:
            raise CertificateError(f"an RDN is a SET OF attributes, found tag {rdn.tag!r}")
        if not rdn.children:
            raise CertificateError("an RDN holds at least one attribute")
        attributes: list[Attribute] = []
        for ava in rdn.children:
            if ava.tag != _SEQUENCE:
                raise CertificateError(
                    f"an AttributeTypeAndValue is a SEQUENCE, found tag {ava.tag!r}"
                )
            if len(ava.children) != 2:
                raise CertificateError(
                    f"an AttributeTypeAndValue has two fields, found {len(ava.children)}"
                )
            oid_node, value_node = ava.children
            if oid_node.tag != _OID or oid_node.payload is None:
                raise CertificateError(f"an attribute type is an OID, found tag {oid_node.tag!r}")
            kind, value = _attribute(value_node)
            attributes.append(Attribute(oid=decode_oid(oid_node.payload), value=value, kind=kind))
        rdnsets.append(tuple(attributes))
    return Name(rdnsets=tuple(rdnsets), raw=node.raw)


def _attribute(node: Node) -> tuple[str, str]:
    """Validate the string type before decoding it, so a bad tag says so rather than missing.

    The order matters: looking the tag up first means an unrecognised type is reported as the
    shape problem it is instead of surfacing as a ``KeyError`` from inside the decoder.
    """
    if node.tag.tag_class is not TagClass.universal or node.tag.constructed:
        raise CertificateError(f"an attribute value is a universal string type, found {node.tag!r}")
    entry = _CODECS.get(node.tag.number)
    if entry is None:
        if node.tag.number in _CHARACTER_STRING_TAGS:
            raise CertificateError(
                f"attribute value tag {node.tag.number} is a character string type this codec "
                f"does not model; it is not decoded by guesswork"
            )
        raise CertificateError(f"attribute value tag {node.tag.number} is not a string type")
    kind, codec = entry
    content = node.payload
    if content is None:
        raise CertificateError(f"{kind} carries no content octets")
    if codec is None:
        try:
            return kind, content.decode("utf-8")
        except UnicodeDecodeError:
            return kind, content.decode("latin-1")
    try:
        return kind, content.decode(codec)
    except UnicodeDecodeError as exc:
        raise CertificateError(f"{kind} content is not valid {codec}: {exc}") from exc


def normalize_value(text: str) -> str:
    """Prepare one attribute value for comparison, per RFC 5280 §7.1 and RFC 4518 §2.

    The steps are RFC 4518's own, in its own order: Transcode (done by `decode_string`, which knows
    each string type's codec), Map (§2.2 - the map-to-nothing lists, separators to SPACE, then case
    folding per RFC 3454 B.2), Normalize (§2.3, NFC), then Insignificant Space Handling (§2.6.1,
    attribute-value branch). §2.5 asks for nothing - "Bidirectional characters are ignored" - which
    is a departure from RFC 3454 StringPrep worth knowing before comparing this profile to another.
    All of it lives in `stringprep.py`, which carries the reasoning and the erratum. That last rule
    surprises people and is stated exactly: a
    value with at least one non-space character comes back with **exactly one SPACE at each end**,
    and **every inner run of spaces, however long, replaced by exactly two**; a value with no
    non-space character comes back as exactly two SPACEs. So ``"Paris"``, ``" paris "`` and
    ``"Paris\u00a0\u00a0 "`` all prepare to ``" paris "``, while the RFC's own worked example maps
    ``"foo bar  "`` to ``" foo  bar "``.

    The one step deliberately left out of *this* function is §2.4, the prohibited-character gate.
    Under the profile a value that fails preparation matches nothing at all, which for a codec means
    a shipped certificate could stop matching its own trust anchor over one odd code point. The gate
    is available - `stringprep.prepare_value` raises `StringPrepError`, `stringprep.preparation_issues`
    reports - and the comparison path stays total. It is the same division this package makes for
    UTCTime spelling and for non-positive serial numbers: parse and report here, refuse elsewhere.
    """
    return insignificant_space(prepare_mapped(text))


def names_equal(left: Name, right: Name) -> bool:
    """§7.1's DN match: same number of RDNs, pairing in the same order, attributes pairing within."""
    if len(left.rdnsets) != len(right.rdnsets):
        return False
    return all(_rdns_match(a, b) for a, b in zip(left.rdnsets, right.rdnsets, strict=True))


def within(child: Name, anchor: Name) -> bool:
    """§7.1's subtree rule: ``child`` has at least as many RDNs as ``anchor``, and the anchor's
    RDNs match ``child``'s first ones.

    "Trailing RDNs in DN1 are ignored" is read in encoding order, where the root comes first, so
    what gets ignored is the child's own tail at the leaf end. Reading it off the wrong end accepts
    any certificate whose leaf happens to match a trust anchor, which is a trust decision made
    backwards.
    """
    if len(child.rdnsets) < len(anchor.rdnsets):
        return False
    if not anchor.rdnsets:
        return True
    head = Name(rdnsets=child.rdnsets[: len(anchor.rdnsets)], raw=b"")
    return names_equal(head, anchor)


def _rdns_match(left: tuple[Attribute, ...], right: tuple[Attribute, ...]) -> bool:
    """An RDN is a set: pair the attributes off without reusing one."""
    if len(left) != len(right):
        return False
    pool = list(right)
    for attr in left:
        prepared = normalize_value(attr.value)
        for index, candidate in enumerate(pool):
            if attr.oid == candidate.oid and prepared == normalize_value(candidate.value):
                pool.pop(index)
                break
        else:
            return False
    return True


# RFC 4514 §3: these need escaping wherever they appear. SPACE and SHARP are special at the start,
# and SPACE again at the end - the grammar's leadchar and trailchar ranges say exactly which.
_ESCAPE_ANYWHERE = frozenset('"+,;<>\\')


def _pair(attr: Attribute) -> str:
    return f"{attr.short_name}={_escape(attr.value)}"


def _escape(value: str) -> str:
    last = len(value) - 1
    out: list[str] = []
    for index, ch in enumerate(value):
        code = ord(ch)
        if ch in _ESCAPE_ANYWHERE or (index == 0 and ch in " #") or (index == last and ch == " "):
            out.append("\\" + ch)
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\{code:02x}")
        else:
            out.append(ch)
    return "".join(out)
