"""Byte-level node model for lossless Packet Tracer XML.

Every parsed node carries the exact source bytes it covers. Serialisation of an
unmodified document is a byte-for-byte copy, which is what makes byte-exact
round-trip achievable despite the corpus's control bytes, NUL terminators and
non-standard character references.

Real Packet Tracer documents reach tens of megabytes and millions of elements,
so the tree is built **lazily**: the common path (read bytes, write bytes, read
the root tag) never materialises it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from pkt_core.errors import FormatError

__all__ = [
    "XmlNode",
    "XmlText",
    "XmlElement",
    "XmlDocument",
    "parse_xml_bytes",
    "parse_xml",
]


@dataclass(slots=True)
class XmlText:
    """Raw character data between tags.

    Attribute:
        data: The exact source bytes, quirks and all. Never normalised.
    """

    data: bytes

    @property
    def dirty(self) -> bool:
        return False

    def to_bytes(self) -> bytes:
        return self.data

    @property
    def text(self) -> str:
        """Lossy UTF-8 view, for humans and tests. Not used on write."""
        return self.data.decode("utf-8", "replace")


@dataclass(slots=True)
class XmlElement:
    """An element: start tag, children, end tag -- with its original bytes.

    Attributes:
        name: Element name as raw bytes.
        attrs: Ordered ``(raw_name, raw_value_with_quotes, unused)`` triples.
            Values keep their original quoting so unmodified attributes
            round-trip byte-for-byte.
        children: Ordered child nodes.
        raw: The complete source span of this element. ``None`` when synthesised.
    """

    name: bytes
    attrs: list[tuple[bytes, bytes, bytes]] = field(default_factory=list)
    children: list["XmlNode"] = field(default_factory=list)
    raw: bytes | None = None
    _dirty: bool = field(default=False, repr=False)

    @property
    def dirty(self) -> bool:
        return self._dirty or any(c.dirty for c in self.children)

    # -- convenience (lossy, read-only) -----------------------------------
    @property
    def tag(self) -> str:
        return self.name.decode("utf-8", "replace")

    def get(self, name: str) -> str | None:
        """Attribute value decoded to text, without its quoting."""
        want = name.encode("utf-8")
        for raw_name, raw_value, _src in self.attrs:
            if raw_name == want:
                v = raw_value
                if len(v) >= 2 and v[0:1] in (b'"', b"'") and v[-1:] == v[0:1]:
                    v = v[1:-1]
                return v.decode("utf-8", "replace")
        return None

    def set(self, name: str, value: str) -> None:
        """Set an attribute, marking this element dirty so it re-serialises."""
        want = name.encode("utf-8")
        new_val = value.encode("utf-8")
        for i, (raw_name, raw_value, _src) in enumerate(self.attrs):
            if raw_name == want:
                quote = raw_value[0:1] if raw_value[:1] in (b'"', b"'") else b'"'
                self.attrs[i] = (raw_name, quote + new_val + quote, b"")
                self._dirty = True
                return
        self.attrs.append((want, b'"' + new_val + b'"', b""))
        self._dirty = True

    def find(self, name: str) -> "XmlElement | None":
        """First direct child element with this name."""
        want = name.encode("utf-8")
        for child in self.children:
            if isinstance(child, XmlElement) and child.name == want:
                return child
        return None

    def find_all(self, name: str) -> list["XmlElement"]:
        """Every direct child element with this name."""
        want = name.encode("utf-8")
        return [c for c in self.children if isinstance(c, XmlElement) and c.name == want]

    def iter_elements(self) -> Iterator["XmlElement"]:
        """Depth-first walk over all descendant elements (excluding self)."""
        for child in self.children:
            if isinstance(child, XmlElement):
                yield child
                yield from child.iter_elements()

    @property
    def text(self) -> str:
        """Concatenated descendant text (lossy UTF-8)."""
        return "".join(c.text for c in self.children)

    def append_text(self, data: bytes) -> None:
        self.children.append(XmlText(data=data))
        self._dirty = True

    def append(self, child: "XmlNode") -> None:
        self.children.append(child)
        self._dirty = True

    def remove(self, child: "XmlNode") -> None:
        """Detach a direct child, marking this element for re-serialisation."""
        self.children.remove(child)
        self._dirty = True

    # -- serialization ----------------------------------------------------
    def to_bytes(self) -> bytes:
        """Emit this element.

        Untouched elements return their original source span verbatim -- this is
        the path that makes byte-exact round-trip free. Otherwise the element is
        re-serialised from its (possibly edited) model.
        """
        if self.raw is not None and not self.dirty:
            return self.raw

        out = bytearray(b"<")
        out += self.name
        for raw_name, raw_value, src in self.attrs:
            out += b" " + raw_name + b"="
            if src:
                out += src
            elif raw_value[:1] in (b'"', b"'"):
                out += raw_value
            else:
                out += b'"' + raw_value + b'"'

        if not self.children and self.raw is not None and self.raw.rstrip().endswith(b"/>"):
            out += b"/>"
            return bytes(out)

        out += b">"
        for child in self.children:
            out += child.to_bytes()
        out += b"</" + self.name + b">"
        return bytes(out)


#: Either flavour of node.
XmlNode = XmlText | XmlElement


@dataclass(slots=True)
class XmlDocument:
    """A whole document, held as source bytes with a **lazily** built tree.

    Nothing in the common path needs the tree: writing an unmodified document
    back out is a byte-for-byte copy, and the root element name is readable from
    the first tag alone. The tree is built only when :attr:`root` is accessed.

    Attributes:
        data: The complete source document, quirks and all.
        root_start: Offset of the root element's opening ``<``.
    """

    data: bytes
    root_start: int
    _root: XmlElement | None = field(default=None, repr=False)
    _end: int = field(default=-1, repr=False)

    @property
    def root_tag(self) -> str:
        """Root element name, without parsing the rest of the document."""
        return _name_at(self.data, self.root_start)

    @property
    def root(self) -> XmlElement:
        """The root element, parsed on first access."""
        if self._root is None:
            root, after = _parse_element(self.data, self.root_start)
            self._root = root
            self._end = after
        return self._root

    @property
    def prologue(self) -> bytes:
        """Bytes before the root element."""
        return self.data[: self.root_start]

    @property
    def epilogue(self) -> bytes:
        """Bytes after the root element (parses the root if not yet known)."""
        if self._end < 0:
            _ = self.root
        return self.data[self._end :]

    @property
    def dirty(self) -> bool:
        return self._root is not None and self._root.dirty

    def to_bytes(self) -> bytes:
        """Reproduce the source bytes, or re-serialise if something changed."""
        if self._root is None or not self._root.dirty:
            return self.data
        return self.prologue + self._root.to_bytes() + self.epilogue


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
#: HTML void elements - matched **case-sensitively, lowercase only**.
#:
#: Packet Tracer activity instructions embed a Word-exported HTML document in
#: which ``<br>``/``<meta>`` are legal without a closing tag. That markup is
#: lowercase.
#:
#: The case sensitivity is load-bearing: Packet Tracer's own schema has an
#: uppercase ``<LINK>`` element (a network cable) which is emphatically *not*
#: void. Lowercasing the comparison silently turned every cable into a
#: self-closing tag and dropped all links from the tree.
_HTML_VOID: frozenset[bytes] = frozenset(
    b"area base br col embed hr img input link meta param source track wbr".split()
)


def _name_at(data: bytes, start: int) -> str:
    """Element name of the tag beginning at ``data[start] == '<'``."""
    i = start + 1
    n = len(data)
    while i < n and not data[i : i + 1].isspace() and data[i] not in (0x3E, 0x2F):
        i += 1
    return data[start + 1 : i].decode("utf-8", "replace") or "?"


def _find_declaration_end(data: bytes, start: int) -> int:
    """End of a ``<!...>`` construct begun at ``data[start] == '<'``.

    CDATA sections and comments may legally contain ``>``, so scanning for the
    first ``>`` is wrong and silently truncates the construct mid-content.
    Packet Tracer stores activity instructions as CDATA HTML that is full of
    ``>`` (``<![CDATA[<h3>Task</h3>...]]>``), so this has to be exact:

    * ``<![CDATA[ ... ]]>&`` ends at the first ``]]>``
    * ``<!-- ... -->`` ends at the first ``-->``
    * a DOCTYPE/PI ends at the first ``>`` outside a quoted value
    """
    n = len(data)
    if data[start : start + 9] == b"<![CDATA[":
        end = data.find(b"]]>", start + 9)
        if end < 0:
            raise FormatError(f"unterminated CDATA section at offset {start}")
        return end + 2
    if data[start : start + 4] == b"<!--":
        end = data.find(b"-->", start + 4)
        if end < 0:
            raise FormatError(f"unterminated comment at offset {start}")
        return end + 2
    return _find_tag_end(data, start)


def _find_tag_end(data: bytes, start: int) -> int:
    """Index of the ``>`` closing the tag begun at ``data[start] == '<'``.

    Handles quoted attribute values, which may legally contain ``>``.
    """
    i = start + 1
    quote: int | None = None
    n = len(data)
    while i < n:
        b = data[i]
        if quote is not None:
            if b == quote:
                quote = None
        elif b in (0x22, 0x27):  # " or '
            quote = b
        elif b == 0x3E:  # >
            return i
        i += 1
    raise FormatError(f"unterminated tag starting at offset {start}")


def _parse_attrs(raw: bytes) -> list[tuple[bytes, bytes, bytes]]:
    """Split the inside of a start tag into ``(name, value_with_quotes, span)``."""
    body = raw[1:]
    if body.endswith(b">"):
        body = body[:-1]
    if body.endswith(b"/"):
        body = body[:-1]

    i = 0
    n = len(body)
    while i < n and not body[i : i + 1].isspace() and body[i] not in (0x3D,):
        i += 1
    body = body[i:]

    attrs: list[tuple[bytes, bytes, bytes]] = []
    i = 0
    n = len(body)
    while i < n:
        while i < n and body[i : i + 1].isspace():
            i += 1
        if i >= n:
            break
        name_start = i
        while i < n and body[i] not in (0x3D, 0x3E) and not body[i : i + 1].isspace():
            i += 1
        name = body[name_start:i]
        while i < n and body[i : i + 1].isspace():
            i += 1
        if i < n and body[i] == 0x3D:
            i += 1
            while i < n and body[i : i + 1].isspace():
                i += 1
            if i < n and body[i] in (0x22, 0x27):
                q = body[i]
                j = i + 1
                while j < n and body[j] != q:
                    j += 1
                value = body[i : j + 1]
                i = j + 1
            else:
                j = i
                while j < n and not body[j : j + 1].isspace():
                    j += 1
                value = body[i:j]
                i = j
        else:
            value = b""
        if name:
            attrs.append((name, value, b""))
    return attrs


def _parse_element(data: bytes, pos: int) -> tuple[XmlElement, int]:
    """Parse one element starting at ``data[pos] == '<'``.

    Returns the element and the offset just past it.
    """
    end = _find_tag_end(data, pos)
    raw_start_tag = data[pos : end + 1]

    i = pos + 1
    n = len(data)
    while i < n and not data[i : i + 1].isspace() and data[i] not in (0x3E, 0x2F):
        i += 1
    name = data[pos + 1 : i]

    self_closing = (
        raw_start_tag.rstrip(b">").endswith(b"/")
        or name in _HTML_VOID  # case-sensitive: PT has an uppercase <LINK>
    )
    attrs = _parse_attrs(raw_start_tag)

    elem = XmlElement(name=name, attrs=attrs, children=[], raw=None)
    cursor = end + 1

    if self_closing:
        elem.raw = raw_start_tag
        return elem, cursor

    text_start = cursor
    while True:
        lt = data.find(b"<", cursor)
        if lt < 0:
            # Unterminated element: implicit close at end of input. Embedded
            # HTML fragments do this; fidelity is unaffected because raw spans
            # are preserved verbatim.
            elem.raw = data[pos:]
            return elem, len(data)
        if lt > text_start:
            elem.children.append(XmlText(data=data[text_start:lt]))

        if data[lt : lt + 2] == b"</":
            tag_end = _find_tag_end(data, lt)
            if data[lt + 2 : tag_end].strip() == name:
                elem.raw = data[pos : tag_end + 1]
                return elem, tag_end + 1
            # A foreign end tag: close this element implicitly and leave the
            # tag unconsumed so an ancestor can claim it. This is HTML-style
            # recovery and is what embedded <ul>/<div>/<p> markup needs.
            elem.raw = data[pos:lt]
            return elem, lt

        if data[lt : lt + 2] in (b"<?", b"<!"):
            tag_end = _find_declaration_end(data, lt)
            elem.children.append(XmlText(data=data[lt : tag_end + 1]))
            cursor = tag_end + 1
            text_start = cursor
            continue

        child, cursor = _parse_element(data, lt)
        elem.children.append(child)
        text_start = cursor


def parse_xml_bytes(data: bytes) -> XmlDocument:
    """Parse a Packet Tracer document, preserving every source byte.

    The returned document reproduces ``data`` exactly from
    :meth:`XmlDocument.to_bytes`; the element tree is built only on demand.

    Because parsing is lazy, this call performs only the cheap work of locating
    the root element. **Structural errors are raised when the tree is actually
    built**, i.e. on :attr:`XmlDocument.root`, not here. That is deliberate: it
    keeps the read/inspect/write path free of work it does not need.

    Args:
        data: The complete document, quirks included.

    Returns:
        An :class:`XmlDocument`.

    Raises:
        FormatError: if no root element can be located at all.
    """
    pos = 0
    while True:
        lt = data.find(b"<", pos)
        if lt < 0:
            raise FormatError("no element found in document")
        if data[lt : lt + 2] in (b"<?", b"<!"):
            pos = _find_declaration_end(data, lt) + 1
            continue
        return XmlDocument(data=data, root_start=lt)


def parse_xml(data: str) -> XmlDocument:
    """Parse a document given as text (encoded to UTF-8 first)."""
    return parse_xml_bytes(data.encode("utf-8"))
