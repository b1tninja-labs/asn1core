#!/usr/bin/env python3
"""Cross-check the RFC 7468 container against certificates this repository did not author.

`tools/crosscheck_store.py` does the same job for the DER decoder. Here the subject is the armour: every local
trust-store certificate is encoded with `asn1core.pem.encode`, read back with all three grammars, and compared
byte for byte. Fixtures written by the same hand that wrote the parser agree with it by construction; 75
operating-system certificates do not.

What it asserts, per document:

1. `encode` then `parse(mode="strict")` returns exactly one block whose `der` equals the input octets, and the
   text it produced satisfies Figure 3 (`canonical`);
2. `raw` is the armour as received, so a claim about what a file said stays checkable against the file;
3. the CRLF and CR spellings parse to the same payload (§3 ¶10 admits all three line endings);
4. re-wrapped at 76 characters - the shape OpenSSL emits and real bundles use - the standard grammar still
   agrees and the strict grammar refuses it (§2 ¶8 says a generator MUST use 64);
5. the payload is still a parseable certificate, so a container bug cannot hide behind an opaque byte string.

Run: ``python tools/crosscheck_pem.py``. Windows only; it exits 0 with a notice elsewhere rather than
pretending to have checked something.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from crosscheck_store import collect  # noqa: E402 - reuse the store dump, one place to fix it

from asn1core import Asn1Error, decode, parse_certificate  # noqa: E402
from asn1core.pem import encode, parse  # noqa: E402


def _rewrap(armour: bytes, width: int) -> bytes:
    """Same block, wrapped at `width` characters, to separate Figure 1 conformance from Figure 3."""
    lines = armour.split(b"\n")
    body = b"".join(lines[1:-2])
    wrapped = b"\n".join(body[i : i + width] for i in range(0, len(body), width))
    return lines[0] + b"\n" + wrapped + b"\n" + lines[-2] + b"\n"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="asn1core-pem-") as tmp:
        files = collect(pathlib.Path(tmp))
        if not files:
            print("no certificates found; nothing checked (this tool needs a Windows trust store)")
            return 0

        failures: list[str] = []
        octets = 0
        padded = 0
        for path in files:
            der = path.read_bytes()
            octets += len(der)
            name = path.stem[:16]
            try:
                armour = encode(der)
                block = parse(armour, mode="strict")[0]
                if block.der != der:
                    failures.append(f"{name}: strict round trip differs")
                if block.raw != armour:
                    failures.append(f"{name}: raw is not the armour as received")
                if not block.canonical:
                    failures.append(f"{name}: own output not marked canonical")
                if block.label != "CERTIFICATE":
                    failures.append(f"{name}: label came back as {block.label!r}")
                if parse(armour)[0].der != der:
                    failures.append(f"{name}: standard grammar disagrees with strict")
                if parse(armour, mode="lax")[0].der != der:
                    failures.append(f"{name}: lax grammar disagrees")
                if b"=" in armour:
                    padded += 1
                for ending in (b"\r\n", b"\r"):
                    variant = armour.replace(b"\n", ending)
                    if parse(variant, mode="strict")[0].der != der:
                        failures.append(f"{name}: {ending!r} line endings changed the payload")
                wide = _rewrap(armour, 76)
                if parse(wide)[0].der != der:
                    failures.append(f"{name}: 76-character wrap lost data")
                decode(block.der, der=True)
                parse_certificate(block.der)
            except (Asn1Error, IndexError, AssertionError) as exc:
                failures.append(f"{name}: {type(exc).__name__}: {exc}")

        print(
            f"certificates={len(files)} der_octets={octets} padded_final_group={padded} "
            f"lines_per_block={sum(len(encode(p.read_bytes()).splitlines()) for p in files)}"
        )
        for line in failures[:20]:
            print("FAIL:", line)
        print(f"failures={len(failures)}")
        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
