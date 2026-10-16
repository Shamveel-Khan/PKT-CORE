"""Tests for the legacy (PT 5.x) container family.

Family L is ``layer_b -> qCompress -> zlib`` — no AEAD and no byte reversal.
These tests exercise it against the real corpus where available, and against
synthetic round-trips so the suite still runs without a corpus download.
"""

from __future__ import annotations

import csv
import struct
import zlib
from pathlib import Path

import pytest

from pkt_core import decode_bytes, encode_bytes
from pkt_core.codec.container import detect_format, root_tag
from pkt_core.crypto.keys import FORMATS, get_format
from pkt_core.crypto.stream import layer_b
from pkt_core.errors import FormatError, TruncatedFileError

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO.parent / "corpus" / "internet"
INDEX = REPO.parent / "corpus" / "CORPUS_INDEX.tsv"


def _legacy_files() -> list[Path]:
    """Real legacy containers from the corpus, if it has been fetched."""
    if not INDEX.exists() or not CORPUS.exists():
        return []
    with INDEX.open(newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh, delimiter="\t") if r["decode_status"] != "OK"]
    out: list[Path] = []
    for row in rows:
        name = row["filename"]
        # Select on decode_status, NOT the file suffix: the corpus contains carved
        # fragments such as ``NA-4-9-DHCP.pka__103770`` whose names end in a byte
        # offset. Only genuinely non-container items are archives.
        if name.lower().endswith(".zip"):
            continue
        p = CORPUS / name
        if p.exists():
            out.append(p)
    return out


LEGACY_FILES = _legacy_files()


# --------------------------------------------------------------------------
# Format registration
# --------------------------------------------------------------------------
def test_legacy_format_is_registered_and_marked() -> None:
    spec = get_format("legacy")
    assert spec.is_legacy is True
    assert spec.cipher == "none"
    assert "no AEAD" in spec.description


def test_modern_formats_are_not_legacy() -> None:
    for name, spec in FORMATS.items():
        if name == "legacy":
            continue
        assert spec.is_legacy is False, f"{name} should be a modern flavour"


# --------------------------------------------------------------------------
# Synthetic round-trip (always runs)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "xml",
    [
        b"<PACKETTRACER5><VERSION>5.1</VERSION></PACKETTRACER5>",
        b"<PACKETTRACER5_ACTIVITY><VERSION>5.1</VERSION></PACKETTRACER5_ACTIVITY>",
        b"<X/>",
        b"<PACKETTRACER5>" + b"<N/>" * 500 + b"</PACKETTRACER5>",
    ],
)
def test_legacy_synthetic_roundtrip(xml: bytes) -> None:
    sealed = encode_bytes(xml, "legacy")
    assert detect_format(sealed) == "legacy"
    again = decode_bytes(sealed)
    assert again.xml == xml
    assert again.format_name == "legacy"
    assert again.spec.is_legacy is True
    assert encode_bytes(again.xml, "legacy") == sealed


def test_legacy_file_is_layer_b_obfuscated_qcompress() -> None:
    """The whole transform is layer B over a qCompress payload — nothing else."""
    xml = b"<PACKETTRACER5/>"
    sealed = encode_bytes(xml, "legacy")
    payload = layer_b(sealed)  # involution
    assert payload[4:6] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e")
    assert struct.unpack(">I", payload[:4])[0] == len(xml)
    assert zlib.decompress(payload[4:]) == xml


def test_legacy_has_no_aead_and_no_reversal() -> None:
    """Contrast with the modern family: no tag, and no layer-A reversal."""
    xml = b"<PACKETTRACER5><VERSION>5.1</VERSION></PACKETTRACER5>"
    legacy = encode_bytes(xml, "legacy")
    modern = encode_bytes(xml, "pkt")

    # Legacy payload is shorter: no 16-byte tag, and no ciphertext expansion.
    assert len(legacy) < len(modern)

    # Legacy does not authenticate as any modern flavour.
    with pytest.raises(FormatError):
        detect_format(legacy, candidates=("pkt", "log", "pkc", "pta"))


def test_detect_format_rejects_garbage() -> None:
    with pytest.raises(FormatError):
        detect_format(bytes(range(256)) * 8)


def test_detect_format_rejects_too_short() -> None:
    with pytest.raises(TruncatedFileError):
        detect_format(b"\x00\x01")


# --------------------------------------------------------------------------
# Real corpus (runs when corpus/ has been fetched)
# --------------------------------------------------------------------------
@pytest.mark.skipif(not LEGACY_FILES, reason="corpus not fetched (see corpus/README.md)")
@pytest.mark.parametrize(
    "path",
    LEGACY_FILES[:25],
    ids=lambda p: p.name[:48],
)
@pytest.mark.corpus
def test_real_legacy_files_decode(path: Path) -> None:
    raw = path.read_bytes()
    container = decode_bytes(raw)
    assert container.format_name == "legacy"
    assert container.root_tag in (
        "PACKETTRACER5",
        "PACKETTRACER5_ACTIVITY",
        "PACKETTRACER_ACTIVITY",
    )
    assert root_tag(container.xml) == container.root_tag


@pytest.mark.skipif(not LEGACY_FILES, reason="corpus not fetched (see corpus/README.md)")
@pytest.mark.corpus
def test_real_legacy_roundtrip_is_byte_exact() -> None:
    """encode(decode(f)) == f across the fetched legacy population."""
    exact = 0
    for path in LEGACY_FILES:
        raw = path.read_bytes()
        container = decode_bytes(raw)
        if encode_bytes(container.xml, "legacy") == raw:
            exact += 1
    assert exact == len(LEGACY_FILES), (
        f"only {exact}/{len(LEGACY_FILES)} legacy files round-tripped byte-exactly"
    )


@pytest.mark.skipif(not LEGACY_FILES, reason="corpus not fetched (see corpus/README.md)")
@pytest.mark.corpus
def test_real_legacy_spans_pt_41_to_532() -> None:
    """The legacy family is PT 4.1 .. 5.3.2 — NOT "PT 5.x" and not "pre-PT-6".

    Its newest member is 5.3.2.0027; the modern family starts at 5.3.3.0019.
    There must be NO version >= 5.3.3 in this population, and PT 4.1 must be
    present (it is 33% of the set).
    """
    versions: set[str] = set()
    for path in LEGACY_FILES:
        head = decode_bytes(path.read_bytes()).xml[:400].decode("utf-8", "replace")
        i = head.find("<VERSION>")
        if i >= 0:
            j = head.find("</VERSION>", i)
            if j > i:
                versions.add(head[i + 9 : j])

    assert versions, "no <VERSION> elements found"
    assert "4.1" in versions, f"expected PT 4.1 content, saw {sorted(versions)}"

    def key(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split("."))

    assert all(key(v) < (5, 3, 3) for v in versions), (
        f"legacy family must stop before 5.3.3, saw {sorted(versions, key=key)}"
    )
    assert max(versions, key=key) == "5.3.2.0027"


# --------------------------------------------------------------------------
# Document schema: three root elements, not two
# --------------------------------------------------------------------------
def test_all_three_root_elements_are_recognised() -> None:
    """PACKETTRACER_ACTIVITY is the PT 4.x schema and appears in the legacy family."""
    from pkt_core import Container
    from pkt_core.crypto.keys import get_format

    spec = get_format("legacy")
    for root in ("PACKETTRACER5", "PACKETTRACER5_ACTIVITY", "PACKETTRACER_ACTIVITY"):
        xml = f"<{root}><VERSION>4.1</VERSION></{root}>".encode()
        sealed = encode_bytes(xml, "legacy")
        c = decode_bytes(sealed)
        assert c.root_tag == root
        assert isinstance(c, Container)


def test_activity_flag_covers_the_legacy_root_name() -> None:
    """Every *_ACTIVITY root marks a scored activity, including PACKETTRACER_ACTIVITY."""
    spec = get_format("legacy")
    for root, expect_activity in (
        ("PACKETTRACER5", False),
        ("PACKETTRACER5_ACTIVITY", True),
        ("PACKETTRACER_ACTIVITY", True),
    ):
        xml = f"<{root}/>".encode()
        c = decode_bytes(encode_bytes(xml, "legacy"))
        assert c.is_activity is expect_activity, root


def test_root_element_is_not_a_container_discriminator() -> None:
    """PACKETTRACER5 occurs in both families, so detection cannot use the root."""
    xml = b"<PACKETTRACER5><VERSION>5.3.3.0019</VERSION></PACKETTRACER5>"
    modern = encode_bytes(xml, "pkt")
    legacy = encode_bytes(xml, "legacy")
    assert detect_format(modern) == "pkt"
    assert detect_format(legacy) == "legacy"
    # Same root element, different container — detection must use the transform.
    assert root_tag(modern if False else decode_bytes(modern).xml) == "PACKETTRACER5"
    assert root_tag(decode_bytes(legacy).xml) == "PACKETTRACER5"
