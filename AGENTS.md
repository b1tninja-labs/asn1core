# Instructions for coding agents

`asn1core` is an ASN.1 BER/DER codec with real code and a green suite - 87 tests, 91%
coverage, mypy strict, ruff clean, on 2026-11-05. `PLAN.md` is the decision record and
`VECTORS.md` is the conformance corpus: **the corpus is the exit test, and not every row in it
passes yet.** Read the status section below before believing any claim in the README.

## Commands

Everything here was run in this repository and passed. Use the module form: bare `ruff` and
`mypy` are not on PATH in this environment.

```
python -m pytest -q --cov        # 87 passed, coverage floor 85
python -O -m pytest -q           # same suite, asserts stripped
python -m ruff check .
python -m ruff format --check .
python -m mypy asn1core tests    # bare `mypy` is a usage error; name the targets
python tools/crosscheck_store.py # 75 real certificates, byte-exact round trip
```

Two more are documented but **not exercised here**, because installing them needs a network
fetch this sandbox refused: `python -m pip install -e ".[dev]"` and
`python -m build && python tools/check_dist.py`. CI runs them. Do not report either as
verified until it has actually run.

Never run a formatter or linter from above this directory. `D:\code` holds around 190
unrelated projects, and a `ruff format .` at that level has already caused damage once
(`PORTFOLIO.md` section 10). Every command above assumes the working directory is this one.

## Where the specification lives, and where it does not

The normative source for BER and DER is **ITU-T X.680 and X.690, which are not in the RFC
series**. `rfclib` cannot answer a question about tag-number encoding or DER canonicalisation.
It is still the authority for the parts that are RFCs:

- `rfclib.read("RFC5280§4.1.3.2", view="normative")` - why a signature must be verified over
  the DER encoding of the TBSCertificate. This is the reason `Node.raw` exists.
- `rfclib.info("RFC5280")` before citing it: Proposed Standard, 6 verified errata.
- `rfclib.grep("RFC5280", pattern="keyCompromise")` rather than guessing a section number.
- Cite with `rfclib.cite(...)`; never paraphrase normative text into a docstring.

Rows in `VECTORS.md` marked `[verify against X.690]` are **still unresolved**. Do not code
against them, and do not quietly pick an interpretation: `tests/test_defect_corpus.py` refuses
primitive indefinite length precisely because the answer is unknown, and inventing one here
would make this codec disagree with every other implementation in silence.

## Status, stated honestly

Fixed and covered by named tests: high-tag-number decoding (which snmpy answers as
3999 for 31), length encoding via `bit_length` (the reference used `ceil(log2(n)/8)` and
crashed at 256, 65536, 16777216), truncation as a named error, framing bounded by the parent,
indefinite-length termination **at object boundaries**, original-byte retention, and the DER
refusals for length, integer, boolean, bit string and SET OF order.

**Not done:** OID content parsing, so corpus row 7 (the `min(2, octet // 40)` arc clamp) is
unaddressed; the three end-to-end X.509 fixtures; any schema or `.asn` compilation. Nothing is
published and no version is assigned.

## Invariants

1. **`Node.raw` is the input's own octets.** Any refactor that reconstructs a node's bytes
   from its parts breaks RFC 5280 §4.1.3.2 verification and certledger invariant I3.
   `test_original_bytes_survive_a_noncanonical_parse` is the guard.
2. **BER tolerates, DER refuses, and the refusal is named.** Never normalise a non-canonical
   document into a canonical one: that gives one certificate two identities.
   `DerViolation` is not a subclass of `DecodeError`, on purpose.
3. **No bounds check may be an `assert`.** CI runs under `python -O`; `__debug__` is False
   there and library asserts vanish while test asserts survive. This is enforced against the
   AST in `test_library_contains_no_assert_statements`.
4. **A length read from the wire is never an allocation size.** Compare it to the bytes
   present first. `MAX_CONTENT_BYTES` exists for that, not for tidiness.
5. **Terminators are recognised only at object boundaries.** Scanning for `00 00` finds it
   inside ordinary data - that single line was the worst defect in the code this descends from.
6. **No runtime dependencies.** Nine projects sit behind this one and inherit anything added
   here. A new dependency needs a paragraph of justification in README.md.
7. **A roadmap row moves to done only with a named test that failed first.** The corpus rows
   are the work queue, and expectations come from the encoding rule, never from this code.

## Derived from snmpy, and what that means

The architecture comes from `snmpy`'s `ber` package (MIT, © 2026 snmpy Contributors); the
behaviour was written from `VECTORS.md` because the original has seven measured defects
(`PLAN.md`). **`NOTICE` must keep carrying the MIT text** - that is MIT's only condition, and
`tools/check_dist.py` fails the build if the attribution ever disappears. Do not "tidy" it.
