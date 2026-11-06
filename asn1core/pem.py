"""RFC 7468 textual encoding - the armour around DER, and nothing inside it.

`trustatlas/PLAN.md` names this the first SDK gap: almost every trust-anchor source is armoured (curl's
`cacert.pem`, certifi's bundle, Android's one-PEM-per-file tree, CCADB's PEM-in-CSV report, macOS
`trust-settings-export`), and a package that reads only DER reads none of them.

This module **decodes the container**: it returns payload octets plus the exact armour text. It does not parse
what is inside - that is `cert.py`'s job, and conflating the two is how a label ends up trusted more than the
bytes are, which is what §2 ¶4 warns about.

Three grammars from §3, chosen by `mode`:

* ``"strict"``   - Figure 3: 64-character lines, no stray whitespace, canonical base64. What a generator must
  emit (§2 ¶8: "Generators MUST wrap ... exactly 64 characters except for the final line").
* ``"standard"`` - Figure 1, the default: blanks at line ends tolerated, other line lengths tolerated.
* ``"lax"``      - Figure 2: whitespace anywhere inside the payload. §2 ¶7 warns the laxest parsers "may run the
  risk of accepting text that was not intended to be accepted", so it is opt-in, and it still refuses anything
  that is not base64.

Rules that are easy to get wrong, each pinned by a test:

* **Boundaries are case-sensitive.** Erratum 4508 (verified, technical) corrects §3's ABNF to
  `%s"-----BEGIN "` / `%s"-----END "`, because "nearly all implementations enforce the case sensitivity of BEGIN
  and END on input, and all surveyed implementations output all-caps". So `-----begin certificate-----` is not a
  boundary in any mode; it is text before a boundary, and §2 ¶1 makes us tolerate that. The honest reading is
  *no blocks found*, not a lowercase block.
* **Exactly five dashes, exactly one space** (§2 ¶3). Four is not armour and six is not armour; both are text.
* **No headers.** Unlike RFC 1421 PEM, OpenPGP armor and OpenSSH keys, this encoding has no header region
  (§2 ¶5), so a `Proc-Type:` line between boundaries is non-base64 content and is refused.

Appendix A's labels (`X509 CERTIFICATE`, `X.509 CERTIFICATE`, `NEW CERTIFICATE REQUEST`, `CERTIFICATE CHAIN`)
parse - supporting them is optional, reporting them is free - but are never folded onto a standard label.

Import this module by name (`from asn1core.pem import certificates, encode, parse`). Its verbs are deliberately
not re-exported from the package root: `asn1core.parse` would read as "parse the DER", which is the exact
confusion this file exists to prevent.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Literal

from .errors import ArmourError

Mode = Literal["strict", "standard", "lax"]

__all__ = ["APPENDIX_A_LABELS", "Block", "certificates", "encode", "label_issues", "parse"]

_ALPHA = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_PAD = 0x3D
_LINE = 64

_DASHES = b"-----"

CERTIFICATE_LABEL = "CERTIFICATE"
PUBLIC_KEY_LABEL = "PUBLIC KEY"

#: Appendix A, verbatim: "non-recommended label variants ... supporting these is not required and is sometimes
#: discouraged". Recognised so a caller can tell a legacy spelling from nonsense; never silently accepted.
APPENDIX_A_LABELS = frozenset(
    {"X509 CERTIFICATE", "X.509 CERTIFICATE", "NEW CERTIFICATE REQUEST", "CERTIFICATE CHAIN"}
)


@dataclass(frozen=True, slots=True)
class Block:
    """One encapsulated datum, with what a later audit needs.

    `raw` is the armour as received, boundaries included; `encapsulated` is the text between them. Kept for the
    reason `node.Node` keeps its original octets: a claim about a file must be checkable against the bytes the
    file had, not against a re-rendering of what they were taken to mean. `canonical` says the text also
    satisfied Figure 3 - a statement about the sender, not about the payload.
    """

    label: str
    der: bytes
    raw: bytes
    encapsulated: bytes
    canonical: bool

    def label_problems(self) -> tuple[str, ...]:
        """Conformance of this block's label. Empty means exactly as §2 ¶2 and §2 ¶3 describe it."""
        return label_issues(self.label)


def _lines(data: bytes) -> list[tuple[bytes, bytes]]:
    """Split into (content, line-ending) pairs on CRLF / CR / LF only.

    `bytes.splitlines()` is not used: it also breaks on VT, FF and the file separators, none of which §3 ¶10
    admits as an end-of-line, so using it would let a stray 0x0C become a boundary-shaped line.
    """
    out: list[tuple[bytes, bytes]] = []
    start = i = 0
    n = len(data)
    while i < n:
        ch = data[i]
        if ch == 0x0D:
            if i + 1 < n and data[i + 1] == 0x0A:
                out.append((data[start:i], b"\r\n"))
                i += 2
            else:
                out.append((data[start:i], b"\r"))
                i += 1
            start = i
        elif ch == 0x0A:
            out.append((data[start:i], b"\n"))
            i += 1
            start = i
        else:
            i += 1
    if start < n:
        out.append((data[start:], b""))
    return out


def label_issues(label: str) -> tuple[str, ...]:
    """Why a label departs from §2 ¶2 and §3 ¶8-¶9, as a tuple; empty means conforming.

    Never raises: labels are metadata on someone else's file, and a job cataloguing a trust store wants the list
    of oddities rather than an exception on the first one.
    """
    problems: list[str] = []
    if not label:
        problems.append("empty label")
    if label != label.upper():
        problems.append("label is not uppercase")
    if label.startswith(("-", " ")) or label.endswith(("-", " ")):
        problems.append("label begins or ends with a separator")
    if "--" in label or "  " in label:
        problems.append("label contains consecutive separators")
    for ch in label:
        if ch in "- ":
            continue
        if not 0x21 <= ord(ch) <= 0x7E:
            problems.append(f"label character {ch!r} is outside the labelchar range")
            break
    return tuple(problems)


def _boundary(content: bytes, keyword: bytes) -> str | None:
    """The label if this line *is* an encapsulation boundary, else None.

    Structural rather than a regular expression: a pattern like `-----BEGIN (.*?)-{5}` backtracks its way into
    the wrong answer, matching a six-dash line as the label `CERTIFICATE-`. §2 ¶3 says five dashes "no more, no
    less" and §2 ¶2 says a label holds no hyphen at either end, so a label that would end in a hyphen means the
    line is not a boundary at all. Lines that are not boundaries are ordinary text, which §2 ¶1 requires us to
    survive without mis-parsing.
    """
    head = _DASHES + keyword + b" "
    if not content.startswith(head):
        return None
    body = content[len(head) :].rstrip(
        b" \t"
    )  # §3: preeb *WSP eol allows blanks after the boundary
    if len(body) < 5 or not body.endswith(_DASHES):
        return None
    label = body[:-5]
    if label.startswith(b"-") or label.endswith(b"-"):
        return None
    return label.decode("ascii", "replace")


def _strict_problems(lines: list[bytes]) -> tuple[str, ...]:
    """Figure 3 layout: every line but the last exactly 64 characters, no blanks, final line 4 / 3+1 / 2+2."""
    if not lines:
        return ("no encapsulated text",)
    problems: list[str] = []
    for index, line in enumerate(lines[:-1]):
        content = line.rstrip(b"\r\n")
        if len(content) != _LINE:
            problems.append(f"line {index + 1} has {len(content)} characters, not 64")
        if content != content.strip(b" \t"):
            problems.append(f"line {index + 1} carries whitespace")
    final = lines[-1].rstrip(b"\r\n")
    if final.strip(b" \t") != final:
        problems.append("final line carries whitespace")
    pads = final.count(b"=")
    if len(final) % 4 or (pads and (len(final) - pads) % 4 not in (2, 3)):
        problems.append(f"final line length {len(final)} is not a legal strict final form")
    return tuple(problems)


def _decode_base64(lines: list[bytes], *, mode: Mode) -> tuple[bytes, bool]:
    """Encapsulated text to payload octets, under the grammar `mode` selects."""
    joined = bytearray()
    for index, line in enumerate(lines):
        content = line.rstrip(b"\r\n")
        if mode == "lax":
            content = content.strip(b" \t\v\f")
        else:
            if content != content.lstrip(b" \t"):
                raise ArmourError(f"leading whitespace on encapsulated line {index + 1}")
            content = content.rstrip(b" \t")
        if not content:
            if mode == "strict":
                raise ArmourError(f"empty encapsulated line {index + 1}")
            continue
        pads = 0
        for byte in content:
            if byte == _PAD:
                pads += 1
                continue
            if pads:
                raise ArmourError(f"base64 character after padding on line {index + 1}")
            if byte not in _ALPHA:
                raise ArmourError(
                    f"character {byte:#04x} on encapsulated line {index + 1} is not in the base64 alphabet"
                )
        if pads > 2:
            raise ArmourError(
                f"{pads} padding characters on line {index + 1}; at most two are legal"
            )
        joined += content

    if not joined:
        raise ArmourError("block carries no encapsulated text")
    if len(joined) % 4:
        raise ArmourError(f"encapsulated text is {len(joined)} characters, not a multiple of four")
    try:
        payload = base64.b64decode(bytes(joined), validate=True)
    except Exception as exc:  # binascii must not escape the container layer
        raise ArmourError(f"encapsulated text does not decode: {exc}") from exc
    if not payload:
        raise ArmourError("block decodes to zero octets")

    canonical = base64.b64encode(payload) == bytes(joined)
    if mode == "strict":
        problems = list(_strict_problems(lines))
        if not canonical:
            problems.append("encapsulated text is not canonical base64 (RFC 4648 section 3.2)")
        if problems:
            raise ArmourError("not a strict textual encoding: " + "; ".join(problems))
    return bytes(payload), canonical


def parse(data: bytes, *, mode: Mode = "standard") -> tuple[Block, ...]:
    """Every block in `data`, in file order. Raises `ArmourError` on a malformed block.

    Text before the first boundary and after the last is ignored, as §2 ¶1 requires ("parsers MUST NOT
    malfunction when processing such data"), so an export with `subject=` dump lines above each certificate still
    yields its blocks. A non-conforming *label* is an error in strict mode and a reportable oddity elsewhere
    (`Block.label_problems`), because refusing `NEW CERTIFICATE REQUEST` would refuse real files that Appendix A
    documents as merely discouraged.
    """
    if mode not in ("strict", "standard", "lax"):
        raise ValueError(f"mode must be strict, standard or lax, got {mode!r}")

    rows = _lines(data)
    blocks: list[Block] = []
    index = 0
    total = len(rows)
    while index < total:
        content, _ = rows[index]
        label = _boundary(content, b"BEGIN")
        if label is None:
            index += 1
            continue
        if mode == "strict" and label_issues(label):
            raise ArmourError(
                f"BEGIN label {label!r} is not conforming: {'; '.join(label_issues(label))}"
            )
        start = index
        index += 1
        payload_lines: list[bytes] = []
        end_label: str | None = None
        while index < total:
            inner, ending = rows[index]
            closing = _boundary(inner, b"END")
            if closing is not None:
                end_label = closing
                break
            payload_lines.append(inner + ending)
            index += 1
        if end_label is None:
            raise ArmourError(f"unclosed block beginning {label!r} at line {start + 1}")
        if end_label != label and mode != "lax":
            # §2 ¶2: generators MUST repeat the label; parsers MAY ignore a mismatch. The default says no.
            raise ArmourError(f"block opened as {label!r} and closed as {end_label!r}")
        der, canonical = _decode_base64(payload_lines, mode=mode)
        blocks.append(
            Block(
                label=label,
                der=der,
                raw=b"".join(text + ending for text, ending in rows[start : index + 1]),
                encapsulated=b"".join(payload_lines),
                canonical=canonical,
            )
        )
        index += 1
    return tuple(blocks)


def certificates(data: bytes, *, mode: Mode = "standard") -> tuple[Block, ...]:
    """Blocks labelled exactly ``CERTIFICATE``, and nothing else.

    Deliberately not "anything certificate-shaped": Appendix A's ``X509 CERTIFICATE`` means the same thing to a
    human and something different to a parser, and folding the two is how a label starts carrying trust the bytes
    have not earned. Call `parse` and inspect `label` to handle legacy spellings on purpose.
    """
    return tuple(block for block in parse(data, mode=mode) if block.label == CERTIFICATE_LABEL)


def encode(der: bytes, label: str = CERTIFICATE_LABEL) -> bytes:
    """The strict textual encoding of `der` - what §2 ¶8 obliges a generator to emit.

    LF endings, 64 characters per line, canonical base64, no preamble, trailing newline as Figure 3's final
    ``eol`` requires. Round-trips with `parse(..., mode="strict")`; asserted over the trust store in
    `tools/crosscheck_pem.py`.
    """
    if not der:
        raise ArmourError("refusing to armour zero octets")
    problems = label_issues(label)
    if problems:
        raise ArmourError(f"label {label!r} is not conforming: {'; '.join(problems)}")
    text = base64.b64encode(der)
    lines = [text[i : i + _LINE] for i in range(0, len(text), _LINE)] or [b""]
    return (
        f"-----BEGIN {label}-----\n".encode("ascii")
        + b"\n".join(lines)
        + b"\n"
        + f"-----END {label}-----\n".encode("ascii")
    )
