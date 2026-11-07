#!/usr/bin/env python3
"""Cross-store trust-anchor lineage: certificate identity and key identity, reported separately.

The question is not "do these stores agree" but *why* they disagree, and two answers mean different things:

* **certificate identity** - the same DER document appears in both. Cheap, and misleading on its own.
* **key identity** - the same `SubjectPublicKeyInfo` appears in both, which is what an anchor grants. A store
  can hold a different certificate for a key another store already trusts: reissued, re-signed, different
  expiry, different name encoding. Those show up here as **twins**.

Lineage claims ("derived from Mozilla's list") are read from each source's own header text rather than
inferred from overlap, because overlap arithmetic cannot tell a copy from independent convergence on the same
keys.

Sources: `--pem PATH` (repeatable), `--url HTTPS` (repeatable), and the Windows machine root store unless
`--no-store`. A missing network or a non-Windows host reports what it could not do rather than quietly
shrinking the comparison.

Run: `python tools/lineage_report.py --url https://curl.se/ca/cacert.pem`

This lives in `asn1core` and not in `trustatlas` on purpose: `trustatlas/AGENTS.md` allows no dependencies and
forbids a second decoder, and key identity means parsing a DER structure. The renderer may state a lineage
finding once something here has measured it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from asn1core import Asn1Error, decode
from asn1core.x509 import spki_sha256

PEM_RX = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def digest_pair(der: bytes) -> tuple[str, str] | None:
    """(certificate sha256, spki sha256) if the bytes are one complete canonical certificate."""
    try:
        _, end = decode(der, der=True)
        if end != len(der):
            return None
        return hashlib.sha256(der).hexdigest(), spki_sha256(der)
    except Asn1Error:
        return None


def harvest(text: str) -> tuple[dict[str, str], dict[str, str], str, int]:
    """(certificates, keys, provenance header, skipped) from a PEM document.

    The fourth value counts blocks that decoded as base64 or parsed as ASN.1 but were refused -
    a truncated body, a non-canonical encoding, trailing octets. A report that drops them silently is
    the failure mode this tool exists to avoid, so every source prints its skip count.
    """
    certificates: dict[str, str] = {}
    keys: dict[str, str] = {}
    skipped = 0
    for block in PEM_RX.findall(text):
        body = "".join(block.splitlines()[1:-1])
        try:
            der = base64.b64decode(body, validate=False)
        except Exception:  # a malformed base64 body is a refused certificate, not a crash
            skipped += 1
            continue
        found = digest_pair(der)
        if found is None:
            skipped += 1
            continue
        certificate, key = found
        certificates[certificate] = key
        keys.setdefault(key, certificate)
    header = "\n".join(
        line
        for line in text.splitlines()[:40]
        if line.strip() and not re.fullmatch(r"#+\s*", line.strip())
    )
    return certificates, keys, header, skipped


def machine_store() -> tuple[dict[str, str], dict[str, str]]:
    """The OS root store, exported through PowerShell as `tools/crosscheck_store.py` does."""
    if sys.platform != "win32":
        return {}, {}
    certificates: dict[str, str] = {}
    keys: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="asn1core-lineage-") as tmp:
        dest = pathlib.Path(tmp)
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$dest='{dest}';"
            "Get-ChildItem Cert:\\LocalMachine\\Root | ForEach-Object {"
            "[IO.File]::WriteAllBytes((Join-Path $dest ($_.Thumbprint+'.der')), $_.RawData)}"
        )
        done = subprocess.run(  # noqa: S603 - fixed script text, no user input interpolated
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],  # noqa: S607
            capture_output=True,
            check=False,
            timeout=120,
        )
        if done.returncode != 0:
            return {}, {}
        for path in sorted(dest.glob("*.der")):
            found = digest_pair(path.read_bytes())
            if found is None:
                continue
            certificate, key = found
            certificates[certificate] = key
            keys.setdefault(key, certificate)
    return certificates, keys


def fetch(url: str) -> str:
    if not url.startswith("https://"):
        raise ValueError(f"refusing to fetch a non-HTTPS source: {url}")
    request = urllib.request.Request(  # noqa: S310 - scheme checked one line above
        url, headers={"User-Agent": "asn1core-lineage/0.1"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - scheme checked above
        return response.read().decode("utf-8", "replace")


def report(sources: dict[str, tuple[dict[str, str], dict[str, str], str, int]]) -> None:
    """Print per-source counts, pairwise key joins, and each source's own provenance claim."""
    print(f"{'source':26} {'certs':>6} {'keys':>6} {'twins':>6} {'skipped':>8}")
    for name, (certificates, keys, _, skipped) in sources.items():
        twins = len(certificates) - len(keys)
        print(f"{name:26} {len(certificates):>6} {len(keys):>6} {twins:>6} {skipped:>8}")

    print("\npairwise, on key identity [certificate identity in brackets]:")
    names = list(sources)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            left_certs, left_keys, _, _ = sources[left]
            right_certs, right_keys, _, _ = sources[right]
            shared_keys = set(left_keys) & set(right_keys)
            shared_certs = set(left_certs) & set(right_certs)
            only_left = len(set(left_keys) - set(right_keys))
            only_right = len(set(right_keys) - set(left_keys))
            if not shared_keys:
                containment = "disjoint"
            elif set(left_keys) <= set(right_keys):
                containment = f"{left} keys are a subset of {right}"
            elif set(right_keys) <= set(left_keys):
                containment = f"{right} keys are a subset of {left}"
            else:
                containment = "neither is a subset"
            print(
                f"  {left} x {right}: shared {len(shared_keys)} [{len(shared_certs)}], "
                f"only {left} {only_left}, only {right} {only_right} -> {containment}"
            )

    print("\nprovenance each source states about itself:")
    for name, (_, _, header, _) in sources.items():
        print(f"  {name}:")
        for line in [ln for ln in header.splitlines() if ln.strip()][:3]:
            print(f"      {line[:100]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lineage_report",
        description="Compare trust-anchor stores by certificate identity and by key identity.",
    )
    parser.add_argument(
        "--pem", action="append", default=[], help="PEM bundle on disk (repeatable)"
    )
    parser.add_argument("--url", action="append", default=[], help="HTTPS PEM bundle (repeatable)")
    parser.add_argument(
        "--no-store", action="store_true", help="omit the Windows machine root store"
    )
    args = parser.parse_args(argv)

    sources: dict[str, tuple[dict[str, str], dict[str, str], str, int]] = {}
    failures = 0
    for path in args.pem:
        try:
            text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            print(f"cannot read {path}: {error}", file=sys.stderr)
            failures += 1
            continue
        sources[pathlib.Path(path).name] = harvest(text)
    for url in args.url:
        try:
            sources[url.split("/")[2]] = harvest(fetch(url))
        except (OSError, ValueError) as error:
            print(f"cannot fetch {url}: {type(error).__name__} {error}", file=sys.stderr)
            failures += 1
    if not args.no_store:
        certificates, keys = machine_store()
        if certificates:
            sources["windows.machine.root"] = (certificates, keys, "Windows machine root store", 0)
        else:
            print("machine store unavailable (needs Windows); comparing the given sources only")

    if len(sources) < 2:
        print("fewer than two sources harvested; nothing to compare", file=sys.stderr)
        return 2
    report(sources)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
