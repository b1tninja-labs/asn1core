# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog; this project does not yet claim semantic versioning, because a pre-alpha
package that has not passed its conformance corpus has no API to keep stable.

## Unreleased

Nothing published. This package exists on disk and nowhere else.

### Added

- The codec: `tag.py`, `length.py`, `node.py`, `der.py`, written from `VECTORS.md` rather than
  ported. 87 tests pass at 91% coverage under pytest, under pytest with assertions stripped,
  under ruff and under mypy strict. Thirteen of the twenty obligations in `PLAN.md` are closed
  with a named test; five remain unimplemented and two are partial, `dk.oid` among them, so
  **defect 7 in the inventory in PLAN.md is still unfixed in this package.**
- `tools/crosscheck_store.py` - the second opinion the corpus owed. Parses the local X.509
  trust store and requires byte-exact DER round-tripping: 75 certificates, 868,500 bytes, zero
  failures on 2026-11-05. Those documents exercise canonical framing only; they carry no tag
  numbers above 30 and no indefinite lengths, so they validate less than the headline suggests.

- Project scaffold: `hatchling` build, zero runtime dependencies, `ruff` and `mypy --strict`,
  CI on Linux and Windows across Python 3.12, 3.13 and 3.14, including a run with assertions
  stripped.
- `VECTORS.md` - the conformance corpus: tag boundaries at and above the single-octet limit,
  length forms including the reserved and non-minimal ones, eight truncation cases, the DER
  restrictions BER tolerates, and the round-trip properties that a defect like "discards the
  original bytes" survives untouched.
- `PLAN.md` - the decision record, including **seven defect classes measured by execution
  against the codec this design descends from** (probe: `sdk-forge/probe_ber.py`), among them
  `OverflowError` at every exact power of 256 on encode, tag numbers above 30 decoding to
  wrong values, and an indefinite-length terminator matching `00 00` inside the content.
- `NOTICE` records the MIT-derived architecture and carries the licence text through, as MIT
  requires for substantial portions.

### Pending

The corpus tests are the gate on any release. Until every named case passes, no version
number is assigned and no claim in the README should be read as an endorsement.
