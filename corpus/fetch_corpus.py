#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reproduce the reverse-engineering corpus from its upstreams.

The repository ships the corpus *identity* — every file's SHA-256 in
``CORPUS_INDEX.tsv`` — but not the binaries, because they are third-party works
we have no right to relicense (see ``README.md``). This script rebuilds a
byte-identical local copy from the upstreams that are still reachable, and
verifies every file against the manifest.

    python3 corpus/fetch_corpus.py --out corpus/files

By default material whose redistribution is specifically restricted — the Cisco
Networking Academy curriculum — is **skipped**, even though it is reachable. Pass
``--include-cisco-curriculum`` to fetch it for local study. That flag is for
personal research use; it does not grant redistribution rights.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ManifestEntry", "load_manifest", "load_sources", "fetch", "verify"]

HERE = Path(__file__).resolve().parent
INDEX_TSV = HERE / "CORPUS_INDEX.tsv"
SOURCES_TSV = HERE / "SOURCES.tsv"

CISCO_TAG = "bbent-cis202-PTA2011"


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One corpus file as recorded in ``CORPUS_INDEX.tsv``."""

    filename: str
    size: int
    sha256: str
    decode_status: str
    xml_root_tag: str
    source: str


@dataclass(frozen=True, slots=True)
class Upstream:
    """One place the corpus was harvested from."""

    source_tag: str
    owner: str
    repo: str
    url: str
    license_status: str

    @property
    def is_restricted(self) -> bool:
        return self.license_status == "cisco-copyrighted-curriculum"

    @property
    def tarball_url(self) -> str:
        return f"https://codeload.github.com/{self.owner}/{self.repo}/tar.gz/HEAD"


def load_manifest(path: Path = INDEX_TSV) -> list[ManifestEntry]:
    """Read the corpus manifest. Filenames may contain spaces; parse as TSV."""
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    entries: list[ManifestEntry] = []
    for row in rows:
        entries.append(
            ManifestEntry(
                filename=row["filename"],
                size=int(row["bytes"]),
                sha256=row["sha256"],
                decode_status=row["decode_status"],
                xml_root_tag=row["xml_root_tag"],
                source=row["source"],
            )
        )
    return entries


def load_sources(path: Path = SOURCES_TSV) -> dict[str, Upstream]:
    """Read the upstream table, keyed by source tag."""
    out: dict[str, Upstream] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            up = Upstream(
                source_tag=row["source_tag"],
                owner=row["github_owner"],
                repo=row["github_repo"],
                url=row["upstream"],
                license_status=row["license_status"],
            )
            # Prefer the GitHub entry when a tag has several rows.
            out.setdefault(up.source_tag, up)
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file():
            yield p


def _download_tarball(up: Upstream, dest: Path) -> bool:
    """Fetch and extract a GitHub source tarball. Returns True on success."""
    url = up.tarball_url
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed https URL
            data = resp.read()
    except Exception as exc:  # noqa: BLE001 - report and continue with other sources
        print(f"  ! {up.source_tag}: download failed ({exc})", file=sys.stderr)
        return False
    try:
        with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:*") as tf:
            tf.extractall(dest)
    except tarfile.TarError as exc:
        print(f"  ! {up.source_tag}: bad tarball ({exc})", file=sys.stderr)
        return False
    return True


def fetch(
    out_dir: Path,
    *,
    include_cisco: bool = False,
    sources: dict[str, Upstream] | None = None,
    manifest: list[ManifestEntry] | None = None,
) -> tuple[int, int]:
    """Materialise the corpus into ``out_dir``.

    Returns:
        ``(recovered, missing)`` counts.
    """
    entries = manifest if manifest is not None else load_manifest()
    upstreams = sources if sources is not None else load_sources()
    out_dir.mkdir(parents=True, exist_ok=True)

    by_source: dict[str, list[ManifestEntry]] = {}
    for e in entries:
        by_source.setdefault(e.source, []).append(e)

    recovered = 0
    missing = 0

    for tag, wanted in sorted(by_source.items()):
        up = upstreams.get(tag)
        if up is None:
            print(f"  ? {tag}: no upstream recorded, {len(wanted)} files skipped")
            missing += len(wanted)
            continue
        if up.is_restricted and not include_cisco:
            print(
                f"  - {tag}: SKIPPED ({len(wanted)} files). "
                f"{up.license_status}; use --include-cisco-curriculum for local study."
            )
            missing += len(wanted)
            continue

        if up.owner == "bbent-cis202":
            print(f"  - {tag}: direct URL not auto-fetched; see {up.url}")
            missing += len(wanted)
            continue

        want_by_hash = {e.sha256: e for e in wanted}
        print(f"  > {tag}: {len(wanted)} files from {up.url}")
        with tempfile.TemporaryDirectory(prefix=f"pktfetch_{tag}_") as tmp:
            tmpdir = Path(tmp)
            if not _download_tarball(up, tmpdir):
                missing += len(wanted)
                continue
            # Index candidate files by hash once.
            for cand in _iter_files(tmpdir):
                if not want_by_hash:
                    break
                digest = sha256_file(cand)
                entry = want_by_hash.pop(digest, None)
                if entry is None:
                    continue
                target = out_dir / entry.filename
                shutil.copy2(cand, target)
                recovered += 1
            for _digest, entry in want_by_hash.items():
                print(f"    ! not found upstream: {entry.filename}")
                missing += 1

    return recovered, missing


def verify(out_dir: Path, manifest: list[ManifestEntry] | None = None) -> int:
    """Check every file present in ``out_dir`` against the manifest.

    Returns:
        The number of mismatched or unexpected files (0 means clean).
    """
    entries = manifest if manifest is not None else load_manifest()
    by_name = {e.filename: e for e in entries}
    problems = 0
    for path in _iter_files(out_dir):
        entry = by_name.get(path.name)
        if entry is None:
            print(f"  ! unexpected file: {path.name}")
            problems += 1
            continue
        digest = sha256_file(path)
        if digest != entry.sha256:
            print(f"  ! hash mismatch: {path.name}")
            print(f"      expected {entry.sha256}")
            print(f"      actual   {digest}")
            problems += 1
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Reproduce the Packet Tracer corpus from its upstreams and verify it."
    )
    ap.add_argument("--out", type=Path, default=HERE / "files", help="output directory")
    ap.add_argument(
        "--include-cisco-curriculum",
        action="store_true",
        help="also fetch the Cisco Networking Academy curriculum (local study only; "
        "not redistributable)",
    )
    ap.add_argument("--verify-only", action="store_true", help="only verify --out")
    args = ap.parse_args(argv)

    manifest = load_manifest()
    print(f"manifest: {len(manifest)} files")

    if not args.verify_only:
        recovered, missing = fetch(
            args.out, include_cisco=args.include_cisco_curriculum, manifest=manifest
        )
        print(f"\nfetched {recovered}, missing {missing}")

    problems = verify(args.out, manifest)
    if problems:
        print(f"verify: {problems} problem(s)", file=sys.stderr)
        return 1
    print(f"verify: OK ({args.out})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
