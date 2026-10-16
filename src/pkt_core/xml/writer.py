"""Serialization for the lossless XML model.

For unmodified nodes this is a no-op: :meth:`XmlNode.to_bytes` returns the
original source span. This module supplies the remaining pieces — document-level
writing and a small helper for synthesising elements that never existed in the
source.
"""

from __future__ import annotations

from pkt_core.xml.nodes import XmlDocument, XmlElement, XmlText

__all__ = ["write_xml", "element", "text"]


def write_xml(doc: XmlDocument) -> bytes:
    """Serialise a document back to bytes.

    Unmodified documents round-trip byte-for-byte by construction, because each
    node contributes its original source span.
    """
    return doc.to_bytes()


def element(name: str, **attrs: str) -> XmlElement:
    """Build a new element with text attributes (used when authoring).

    The element is born dirty, so it serialises from its model rather than
    claiming a source span it never had.
    """
    elem = XmlElement(name=name.encode("utf-8"))
    for key, value in attrs.items():
        elem.set(key, value)
    return elem


def text(data: str | bytes) -> XmlText:
    """Build a text node from a string (encoded UTF-8) or raw bytes."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return XmlText(data=raw)
