"""The exception hierarchy, and why the distinctions exist.

A parser for untrusted bytes has to answer three different questions, and collapsing them is
how callers end up guessing:

* **TruncatedError** - the buffer ended before the encoding did. Nothing is wrong with the
  document's *rules*, only with its length.
* **DerViolation** - the encoding is legal BER but not legal DER. The bytes are meaningful;
  they are merely not canonical. This is a policy answer, not a parse failure, which is why
  it is not a subclass of TruncatedError.
* **DecodeError** - the encoding breaks X.690 itself: a reserved length form, a non-minimal
  tag number, a universal tag with no defined content.

`IndexError`, `struct.error` and `UnicodeDecodeError` are deliberately **not** in this
hierarchy: the corpus rule is that they never escape the decoder, and the truncation tests
assert exactly that. Every one of them is a base `Exception` leak that turns a bounds check
into whatever the interpreter happened to notice.
"""

from __future__ import annotations


class Asn1Error(Exception):
    """Base for every error this package raises."""


class DecodeError(Asn1Error):
    """The byte stream is not valid BER at all.

    ``offset`` is the position the decoder was at when it gave up, which is the one piece of
    diagnostic information that makes a hostile-input bug report actionable. It is the offset
    *within the buffer passed in*, not within any parent object.
    """

    def __init__(self, message: str, *, offset: int | None = None) -> None:
        super().__init__(message if offset is None else f"{message} (at offset {offset})")
        self.offset = offset


class TruncatedError(DecodeError):
    """The buffer ended before the encoding did."""


class DepthExceeded(DecodeError):
    """Nesting passed the decoder's limit.

    Raised instead of letting the interpreter exhaust its stack: a parser reachable from the
    network must not turn a small packet into a crash, and RecursionError is not this
    package's error to leak.
    """


class DerViolation(Asn1Error):
    """Legal BER that DER forbids: non-minimal length or integer, indefinite length,
    non-zero unused bits, an out-of-order SET OF, and so on.

    Carries the rule name so a caller can log *which* restriction was hit rather than
    "parse failed" - the difference between a diagnosable rejection and a mystery.
    """

    def __init__(self, message: str, *, rule: str | None = None, offset: int | None = None) -> None:
        suffix = "" if rule is None else f" [{rule}]"
        if offset is not None:
            suffix += f" (at offset {offset})"
        super().__init__(f"{message}{suffix}")
        self.rule = rule
        self.offset = offset
