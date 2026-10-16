"""Typed views over the lossless XML tree.

Design
------
These models are **views**, not a parallel data structure. Each one wraps the
:class:`~pkt_core.xml.nodes.XmlElement` it was read from, so:

* Writing a document out again emits the original source bytes for anything the
  caller did not touch. Data loss is therefore impossible *by construction*, not
  by discipline.
* Unrecognised elements and attributes survive automatically, because they are
  simply children the model never looked at.
* Typed access is layered on top for the entities that matter (devices, ports,
  links, canvas placement, running config).

For discoverability, every model also enumerates the children it did **not**
claim into :attr:`PktNode.extra_fields`, so callers can see what is unmodelled
rather than guessing.

A deliberate consequence of the corpus survey: text that Packet Tracer stores as
raw bytes - IOS ``<LINE>`` config (which embeds ``^C`` banner delimiters) and
embedded instruction HTML - is exposed as :class:`bytes`, never decoded to
``str``. Decoding it would silently normalise the very bytes we promise to
preserve.
"""

from __future__ import annotations

from typing import ClassVar, Iterable, TypeVar

from pydantic import BaseModel, ConfigDict, PrivateAttr

from pkt_core.xml.nodes import XmlElement, XmlNode, XmlText

__all__ = ["PktNode", "unknown_children"]

_T = TypeVar("_T", bound="PktNode")


def unknown_children(
    el: XmlElement, claimed: Iterable[str]
) -> dict[str, list[XmlNode]]:
    """Group an element's children by name, excluding the claimed ones.

    This is the ``extra_fields`` catch-all: everything the model does not
    explicitly represent is listed here rather than dropped.
    """
    want: set[bytes] = {c.encode("utf-8") for c in claimed}
    out: dict[str, list[XmlNode]] = {}
    for child in el.children:
        if not isinstance(child, XmlElement):
            continue
        if child.name in want:
            continue
        out.setdefault(child.tag, []).append(child)
    return out


class PktNode(BaseModel):
    """Base for every Packet Tracer model.

    Subclasses set :attr:`_claimed` to the child element names they represent;
    everything else lands in :attr:`extra_fields`.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, validate_assignment=False)

    #: Names this model claims as structured children.
    _claimed: ClassVar[frozenset[str]] = frozenset()

    _el: XmlElement = PrivateAttr()

    @classmethod
    def from_element(cls: type[_T], el: XmlElement) -> _T:
        """Wrap an existing XML element as this model.

        Named rather than an ``__init__`` override because Pydantic's metaclass
        generates ``__init__`` from the model fields and would shadow it.
        """
        obj = cls()
        obj._el = el
        return obj

    # -- source of truth ---------------------------------------------------
    @property
    def element(self) -> XmlElement:
        """The underlying XML element. Editing it is reflected on write."""
        return self._el

    @property
    def extra_fields(self) -> dict[str, list[XmlNode]]:
        """Child elements this model does not represent, grouped by name."""
        return unknown_children(self._el, self._claimed)

    @property
    def tag(self) -> str:
        return self._el.tag

    def to_xml(self) -> bytes:
        """Serialise this node.

        Untouched nodes return their original source span byte-for-byte.
        """
        return self._el.to_bytes()

    # -- scalar helpers ----------------------------------------------------
    def _text(self, name: str, default: str = "") -> str:
        child = self._el.find(name)
        return child.text.strip() if child is not None else default

    def _raw_text(self, name: str) -> bytes:
        """Child text as raw bytes - never decoded, so quirks survive.

        Use this for anything Packet Tracer may have stored with control
        characters (IOS config lines, instruction HTML).
        """
        child = self._el.find(name)
        if child is None:
            return b""
        parts: list[bytes] = []
        for c in child.children:
            parts.append(c.data if isinstance(c, XmlText) else c.to_bytes())
        return b"".join(parts)

    def _bool(self, name: str, default: bool = False) -> bool:
        value = self._text(name)
        if not value:
            return default
        return value.strip().lower() == "true"

    def _opt_text(self, name: str) -> str | None:
        child = self._el.find(name)
        return None if child is None else child.text.strip()

    def _float(self, name: str, default: float = 0.0) -> float:
        value = self._text(name)
        try:
            return float(value)
        except ValueError:
            return default

    def _int(self, name: str, default: int = 0) -> int:
        value = self._text(name)
        try:
            return int(float(value))
        except ValueError:
            return default

    def _set_text(self, name: str, value: str) -> None:
        """Write a child's text, creating the child if needed."""
        child = self._el.find(name)
        if child is None:
            child = XmlElement(name=name.encode("utf-8"))
            self._el.append(child)
        child.children = [XmlText(data=value.encode("utf-8"))]
        child._dirty = True
        self._el._dirty = True

    def _children(self, name: str) -> list[XmlElement]:
        return self._el.find_all(name)

    # -- pydantic plumbing -------------------------------------------------
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}(<{self.tag}>)"
