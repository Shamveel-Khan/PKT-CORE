"""Whole-corpus acceptance test.

Asserts the headline result of the project: **every** container in the corpus
decodes and re-encodes byte-for-byte. This is opt-in because it takes ~1 minute:

    python3 -m pytest tests/test_corpus_acceptance.py -m corpus -q

It is the regression gate for the format specification.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pkt_core import decode_bytes, encode_bytes

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO.parent / "corpus" / "CORPUS_INDEX.tsv"
CORPUS = REPO.parent / "corpus" / "internet"

pytestmark = pytest.mark.skipif(
    not (INDEX.exists() and CORPUS.exists()),
    reason="corpus not fetched (see corpus/README.md)",
)


def _containers() -> list[tuple[str, bytes]]:
    with INDEX.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    out: list[tuple[str, bytes]] = []
    for row in rows:
        name = row["filename"]
        if name.lower().endswith(".zip"):
            continue  # an archive, not a container
        path = CORPUS / name
        if path.exists():
            out.append((name, path.read_bytes()))
    return out


@pytest.mark.corpus
def test_every_corpus_container_roundtrips_byte_exact() -> None:
    files = _containers()
    assert len(files) >= 1000, f"corpus looks incomplete: {len(files)} files"

    failures: list[str] = []
    not_exact: list[str] = []
    for name, raw in files:
        try:
            container = decode_bytes(raw)
        except Exception as exc:  # noqa: BLE001 - collecting all failures
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if encode_bytes(container.xml, container.format_name) != raw:
            not_exact.append(name)

    assert not failures, f"{len(failures)} decode failures:\n" + "\n".join(failures[:20])
    assert not not_exact, (
        f"{len(not_exact)} files did not round-trip byte-exactly:\n"
        + "\n".join(not_exact[:20])
    )
    assert len(files) >= 1058, f"expected >= 1058 containers, saw {len(files)}"


@pytest.mark.corpus
def test_family_and_root_counts_are_pinned() -> None:
    """Pin the corpus facts the specification documents, so drift is noticed."""
    fam: dict[str, int] = {}
    roots: dict[str, int] = {}
    for _name, raw in _containers():
        c = decode_bytes(raw)
        fam[c.format_name] = fam.get(c.format_name, 0) + 1
        roots[c.root_tag] = roots.get(c.root_tag, 0) + 1

    assert fam.get("pkt") == 865, fam
    assert fam.get("legacy") == 193, fam
    assert roots.get("PACKETTRACER_ACTIVITY") == 64, roots
    assert set(roots) == {
        "PACKETTRACER5",
        "PACKETTRACER5_ACTIVITY",
        "PACKETTRACER_ACTIVITY",
    }, roots
