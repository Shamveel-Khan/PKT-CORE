"""Lossless XML handling for Packet Tracer documents.

Packet Tracer documents are **not always well-formed XML**. A corpus survey of
1,058 real files establishes the quirks precisely:

===============================  ======  ====================================
Quirk                            Files   Note
===============================  ======  ====================================
Raw control bytes in text        510     ``banner motd ^C...^C`` stores a
                                         literal ``\\x03``; also 0x01/0x02/0x11
Numeric char refs to forbidden   392     ``&#xNN;`` for chars XML 1.0 forbids
                                         *by reference* too
Trailing NUL after the root       64     PT 4.1 documents
===============================  ======  ====================================

``xml.etree.ElementTree`` accepts only **548 of 1,058** of these documents; a
validating parser rejects half the corpus.

The design response is to work at the **byte level** and to *retain source
spans* rather than re-serialise from a semantic tree:

* :class:`XmlNode` keeps the exact source bytes of the subtree it covers.
* :meth:`XmlNode.to_bytes` returns those bytes verbatim when the node is
  untouched, and re-serialises only when something was actually modified.
* Round-tripping an unmodified document is therefore concatenation - byte-exact
  by construction, including every quirk above.

The parser is deliberately non-validating: it recognises element structure and
attributes, and preserves everything else as opaque bytes.
"""

from __future__ import annotations

from pkt_core.xml.nodes import (
    XmlDocument,
    XmlElement,
    XmlNode,
    XmlText,
    parse_xml,
    parse_xml_bytes,
)
from pkt_core.xml.writer import element, text, write_xml

__all__ = [
    "XmlDocument",
    "XmlElement",
    "XmlNode",
    "XmlText",
    "parse_xml",
    "parse_xml_bytes",
    "write_xml",
    "element",
    "text",
]
