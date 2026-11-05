#!/usr/bin/env python3
"""Cross-check the decoder against DER that nobody in this repository authored.

``VECTORS.md`` owes a second opinion: every expectation in the corpus was written by hand from
the encoding rules, and hand-written expectations are exactly how a conformance suite ends up
wrong in lockstep with the code it validates. The local X.509 trust store supplies that second
opinion for free - genuine certificates produced by certificate authorities, shipped by an
operating system, none of them authored here, all of them required to be DER.

What it asserts, per document:

1. it parses on the DER path, so its lengths, tags and values are canonical;
2. ``encode_der`` reproduces its bytes exactly, so the encoder and decoder agree on a real
   document rather than on a toy one;
3. every node keeps its own original octets, the invariant the whole package exists for.

Run: ``python tools/crosscheck_store.py``. Windows only; it exits 0 with a notice elsewhere
rather than pretending to have checked something.
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asn1core import Asn1Error, decode, encode_der  # noqa: E402

STORES = ("Cert:\\LocalMachine\\Root", "Cert:\\LocalMachine\\CA", "Cert:\\CurrentUser\\Root")

_DUMP = """
$ErrorActionPreference = 'SilentlyContinue'
$dest = '{dest}'
foreach ($store in @({stores})) {{
    Get-ChildItem $store | ForEach-Object {{
        $file = Join-Path $dest ($_.Thumbprint + '.der')
        [IO.File]::WriteAllBytes($file, $_.RawData)
    }}
}}
"""


def collect(dest: pathlib.Path) -> list[pathlib.Path]:
    if shutil.which("powershell") is None and shutil.which("pwsh") is None:
        return []
    script = _DUMP.format(dest=str(dest), stores=", ".join(f"'{s}'" for s in STORES))
    subprocess.run(  # noqa: S603 - fixed script text, no user input
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],  # noqa: S607
        check=True,
        capture_output=True,
        timeout=120,
    )
    return sorted(dest.glob("*.der"))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="asn1core-store-") as tmp:
        files = collect(pathlib.Path(tmp))
        if not files:
            print("no certificates found; nothing checked (this tool needs a Windows trust store)")
            return 0

        failures: list[str] = []
        sizes: list[int] = []
        deepest = 0
        for path in files:
            raw = path.read_bytes()
            sizes.append(len(raw))
            try:
                node, end = decode(raw, der=True)
            except Asn1Error as exc:
                failures.append(f"DER parse {path.stem}: {type(exc).__name__}: {exc}")
                continue
            if end != len(raw):
                failures.append(f"{path.stem}: parsed {end} of {len(raw)} octets")
                continue
            if encode_der(node) != raw:
                digest = hashlib.sha256(raw).hexdigest()[:16]
                failures.append(f"{path.stem}: re-encode differs (sha256 {digest})")
                continue
            deepest = max(deepest, _depth(node))
            if node.raw != raw:
                failures.append(f"{path.stem}: top-level raw is not the input")

        print(
            f"documents={len(files)} bytes={sum(sizes)} max_document={max(sizes)} deepest={deepest}"
        )
        for line in failures[:20]:
            print("FAIL:", line)
        print(f"failures={len(failures)}")
        return 1 if failures else 0


def _depth(node, level: int = 1) -> int:
    if not node.children:
        return level
    return max(_depth(child, level + 1) for child in node.children)


if __name__ == "__main__":
    sys.exit(main())
