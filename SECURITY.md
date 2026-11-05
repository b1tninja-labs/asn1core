# Security policy

## What this package is

A parser for bytes that arrive from a network. That is the whole risk: every defect in an
ASN.1 codec is reachable by anyone who can send it a message, and the nine projects behind
this one use it to decide whether to trust a certificate.

## Reporting a vulnerability

Open a [GitHub security advisory](https://github.com/b1tninja/asn1core/security/advisories/new)
rather than a public issue. Expected first response is a few days, not hours - this is a
one-person pre-alpha project and saying otherwise would be a promise nobody intends to keep.

## Current state, stated plainly

- **Not hardened, and not fuzzed yet.** Until a corpus-driven fuzzer runs against the decoder,
  assume memory-safety-style bugs do not exist (it is pure Python) but that **framing and
  resource bugs do**: the reference implementation this design came from had two, both
  reproduced in `PLAN.md` - a length decoded from an untrusted buffer being trusted as a size,
  and an indefinite-length terminator found inside the data rather than at its end.
- **Pre-alpha: do not deploy.** A parser that has not passed its own conformance corpus
  (`VECTORS.md`) is not a security boundary, and nothing here claims to be one.

## Properties that are treated as security requirements

These are in the test suite, not merely in this file, because a policy nobody asserts rots:

1. **No untrusted length becomes an allocation size.** `len-overflow` must fail with a named
   error, never `MemoryError`.
2. **Truncation is always an error.** `IndexError`, `struct.error`, `UnicodeDecodeError` or a
   silently-empty return are all failures - the silent one worst of all, because "the message
   ended" becomes "the message was empty".
3. **Bounds checks are real checks, not `assert` statements.** CI runs the suite under
   `python -O`, which strips asserts; the corpus row `no-asserts-on-wire` exists to keep that
   from regressing.
4. **Nesting is bounded.** `depth-bound` must raise a named error rather than exhaust the
   interpreter's stack.
5. **Non-canonical input is refused on the DER path, never normalised invisibly**, so that one
   certificate cannot exist as two records with two different keys.
