"""Lossless XML round-trip tests.

The requirement is strict: parsing a Packet Tracer document and writing it back
must reproduce the original bytes exactly, including raw control bytes,
trailing NULs and non-standard character references.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pkt_core.errors import FormatError
from pkt_core.xml import (
    XmlElement,
    XmlText,
    element,
    parse_xml,
    parse_xml_bytes,
    text,
    write_xml,
)

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO.parent / "corpus" / "CORPUS_INDEX.tsv"
CORPUS = REPO.parent / "corpus" / "internet"


# --------------------------------------------------------------------------
# Synthetic round-trip (always runs)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "data",
    [
        b"<A/>",
        b"<A></A>",
        b"<A>x</A>",
        b"<A><B/><C/></A>",
        b'<A x="1" y="2">z</A>',
        b"<A x='1'>z</A>",
        b"<?xml version='1.0'?><A/>",
        b"<!-- c --><A/>",
        b"<A>hi &#x03; there</A>",
        b"<A>\x03raw control\x03</A>",
        b"<A/>\x00",
        # PT 4.1 documents terminate with a stray NUL after the root.
        b"<PACKETTRACER_ACTIVITY></PACKETTRACER_ACTIVITY>\n\x00",
        # Bare '<' and '>' in text must be entity-escaped by the writer; a real
        # document containing them unescaped would be ambiguous by definition.
        b"<A>text with &gt; and &lt;escaped&gt; &amp; entities</A>",
        b'<A note="has > inside">x</A>',
        b"<PACKETTRACER5>\n <VERSION>5.1</VERSION>\n</PACKETTRACER5>\n\x00",
    ],
)
def test_unmodified_document_roundtrips_byte_exact(data: bytes) -> None:
    assert write_xml(parse_xml_bytes(data)) == data


def test_control_bytes_and_nul_are_preserved_not_normalised() -> None:
    raw = b"<A>\x01\x02\x03\x11</A>\x00"
    doc = parse_xml_bytes(raw)
    assert doc.epilogue == b"\x00"
    assert write_xml(doc) == raw


def test_attribute_quoting_style_is_preserved() -> None:
    raw = b'<A x="1" y=\'2\' z=3/>'
    doc = parse_xml_bytes(raw)
    assert doc.root.get("x") == "1"
    assert doc.root.get("y") == "2"
    assert write_xml(doc) == raw


# --------------------------------------------------------------------------
# Structure access
# --------------------------------------------------------------------------
def test_tree_navigation() -> None:
    doc = parse_xml("<P><A>one</A><A>two</A><B/></P>")
    assert doc.root_tag == "P"
    assert [e.tag for e in doc.root.find_all("A")] == ["A", "A"]
    assert doc.root.find("B") is not None
    assert doc.root.find("missing") is None
    assert [e.tag for e in doc.root.iter_elements()] == ["A", "A", "B"]


def test_self_closing_and_paired_forms_are_distinguished() -> None:
    assert parse_xml_bytes(b"<A/>").root.raw == b"<A/>"
    assert parse_xml_bytes(b"<A></A>").root.raw == b"<A></A>"


# --------------------------------------------------------------------------
# Mutation re-serialises only what changed
# --------------------------------------------------------------------------
def test_editing_an_attribute_still_preserves_siblings() -> None:
    raw = b'<A x="1"><B>\x03keep\x03</B></A>'
    doc = parse_xml_bytes(raw)
    doc.root.set("x", "9")
    out = write_xml(doc)
    assert b'\x03keep\x03' in out, "untouched sibling text must survive verbatim"
    assert b'x="9"' in out


def test_unmodified_subtree_keeps_its_source_bytes() -> None:
    raw = b'<A><B odd="&#x03;">\x01\x02</B></A>'
    doc = parse_xml_bytes(raw)
    b = doc.root.find("B")
    assert b is not None
    assert b.to_bytes() == b'<B odd="&#x03;">\x01\x02</B>', "span must be preserved"


def test_builder_helpers_produce_usable_nodes() -> None:
    root = element("P", version="5.1")
    root.append(element("C"))
    root.append_text(b"\x03")
    assert isinstance(root.children[0], XmlElement)
    assert isinstance(root.children[1], XmlText)
    out = root.to_bytes()
    assert b'version="5.1"' in out
    assert b"\x03" in out


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
def test_mismatched_end_tag_recovers_html_style() -> None:
    """Embedded HTML markup is mis-nested; the parser recovers instead of failing.

    ``<B>`` is closed implicitly at the foreign ``</A>``, which is left for the
    ancestor to claim. This is what activity instructions need: they contain a
    Word-exported HTML document with ``<ul>``/``<br>``/``<meta>`` fragments.
    Fidelity is unaffected because source spans are preserved verbatim.
    """
    doc = parse_xml_bytes(b"<A><B></A></B>")
    root = doc.root
    assert root.tag == "A"
    assert doc.to_bytes() == b"<A><B></A></B>"


def test_html_void_elements_do_not_need_closing_tags() -> None:
    raw = b"<INSTRUCTIONS><meta charset=x><br>line<ul><li>a</ul></INSTRUCTIONS>"
    doc = parse_xml_bytes(raw)
    assert doc.root.tag == "INSTRUCTIONS"
    assert doc.to_bytes() == raw


def test_unterminated_tag_is_rejected_when_tree_is_built() -> None:
    doc = parse_xml_bytes(b'<A x="unclosed')
    with pytest.raises(FormatError):
        _ = doc.root


def test_no_element_is_rejected_eagerly() -> None:
    """Without even a root tag there is nothing to locate, so this fails now."""
    with pytest.raises(FormatError):
        parse_xml_bytes(b"just text, no tags")


def test_lazy_parse_does_not_build_the_tree_eagerly() -> None:
    """Reading and writing must not pay for a full parse."""
    doc = parse_xml_bytes(b"<A><B><C>x</C></B></A>")
    assert doc._root is None, "tree should still be unbuilt"
    assert doc.root_tag == "A"
    assert doc.to_bytes() == b"<A><B><C>x</C></B></A>"
    assert doc._root is None, "byte-exact write must not force a parse"
    assert doc.root.tag == "A"
    assert doc._root is not None


# --------------------------------------------------------------------------
# Real corpus (runs when fetched)
# --------------------------------------------------------------------------
def _corpus_documents() -> list[tuple[str, bytes]]:
    if not INDEX.exists() or not CORPUS.exists():
        return []
    from pkt_core import decode_bytes

    out: list[tuple[str, bytes]] = []
    with INDEX.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            name = row["filename"]
            if name.lower().endswith(".zip"):
                continue
            path = CORPUS / name
            if not path.exists():
                continue
            try:
                out.append((name, decode_bytes(path.read_bytes()).xml))
            except Exception:  # noqa: BLE001
                continue
    return out


# Loaded lazily so the fast synthetic tests do not pay for decoding the
# corpus at import time.
_DOCS: list[tuple[str, bytes]] | None = None


def _docs() -> list[tuple[str, bytes]]:
    global _DOCS
    if _DOCS is None:
        _DOCS = _corpus_documents()
    return _DOCS


@pytest.mark.corpus
def test_corpus_documents_parse_and_roundtrip() -> None:
    """Every real document must round-trip byte-exactly through the XML layer.

    This is the acceptance gate for the lossless parser: it must survive raw
    control bytes, trailing NULs and numeric char refs across the whole corpus.
    """
    docs = _docs()
    if not docs:
        pytest.skip("corpus not fetched (see corpus/README.md)")
    failures: list[str] = []
    not_exact: list[str] = []
    for name, xml in docs:
        try:
            doc = parse_xml_bytes(xml)
        except FormatError as exc:
            failures.append(f"{name}: {exc}")
            continue
        if write_xml(doc) != xml:
            not_exact.append(name)

    assert not failures, f"{len(failures)} parse failures:\n" + "\n".join(failures[:15])
    assert not not_exact, (
        f"{len(not_exact)} documents did not round-trip byte-exactly:\n"
        + "\n".join(not_exact[:15])
    )
    assert len(docs) >= 1000, f"corpus looks incomplete: {len(docs)} documents"


@pytest.mark.corpus
def test_corpus_roots_are_the_three_known_elements() -> None:
    docs = _docs()
    if not docs:
        pytest.skip("corpus not fetched (see corpus/README.md)")
    roots = {parse_xml_bytes(xml).root_tag for _name, xml in docs[:400]}
    assert roots <= {"PACKETTRACER5", "PACKETTRACER5_ACTIVITY", "PACKETTRACER_ACTIVITY"}
