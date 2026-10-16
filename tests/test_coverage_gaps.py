"""Targeted tests for the remaining uncovered paths.

Two areas sat below the 90% bar: the PktNode scalar/mutation helpers, and the
libgcrypt backend (invisible by default because pure Python is preferred).
"""

from __future__ import annotations

import pytest

from pkt_core.crypto.ciphers import (
    BLOCK_SIZE,
    LibgcryptCipher,
    available_ciphers,
    cipher_available,
    encrypt_block,
    get_cipher,
)
from pkt_core.errors import UnsupportedCipherError
from pkt_core.models.base import PktNode
from pkt_core.xml import element, parse_xml_bytes, text
from pkt_core.xml.nodes import XmlText
from pkt_core.xml.writer import write_xml

# --------------------------------------------------------------------------
# PktNode scalar helpers and mutation
# --------------------------------------------------------------------------
DOC = b"""<R>
 <S>hello</S>
 <B>true</B>
 <B2>false</B2>
 <I>42</I>
 <F>3.5</F>
 <BAD>not-a-number</BAD>
 <EMPTY></EMPTY>
 <RAW>a\x03b</RAW>
</R>"""


def _root() -> PktNode:
    doc = parse_xml_bytes(DOC)
    return PktNode.from_element(doc.root)


def test_scalar_helpers() -> None:
    n = _root()
    assert n._text("S") == "hello"
    assert n._text("MISSING", "fallback") == "fallback"
    assert n._bool("B") is True
    assert n._bool("B2") is False
    assert n._bool("MISSING", True) is True
    assert n._int("I") == 42
    assert n._int("MISSING", -1) == -1
    assert n._int("BAD", 7) == 7
    assert n._float("F") == 3.5
    assert n._float("BAD", 1.25) == 1.25
    assert n._opt_text("S") == "hello"
    assert n._opt_text("MISSING") is None


def test_raw_text_preserves_control_bytes() -> None:
    n = _root()
    assert n._raw_text("RAW") == b"a\x03b"
    assert n._raw_text("MISSING") == b""


def test_children_and_tag() -> None:
    n = _root()
    assert n.tag == "R"
    assert len(n._children("S")) == 1
    assert n._children("MISSING") == []


def test_set_text_updates_and_creates() -> None:
    doc = parse_xml_bytes(DOC)
    n = PktNode.from_element(doc.root)
    n._set_text("S", "changed")
    n._set_text("BRAND_NEW", "spawned")
    out = write_xml(doc)
    assert b"changed" in out
    assert b"spawned" in out
    assert b"hello" not in out


def test_element_property_is_mutable_and_reflected() -> None:
    doc = parse_xml_bytes(b"<R><A>x</A></R>")
    n = PktNode.from_element(doc.root)
    n.element.set("k", "v")
    assert b'k="v"' in write_xml(doc)


def test_writer_helpers() -> None:
    el = element("P", a="1")
    el.append(text("hello"))
    el.append_text(b"\x03")
    out = el.to_bytes()
    assert b'<P a="1">' in out
    assert b"hello" in out
    assert b"\x03" in out
    assert isinstance(el.children[0], XmlText)


# --------------------------------------------------------------------------
# libgcrypt backend (normally shadowed by pure Python)
# --------------------------------------------------------------------------
def test_libgcrypt_backend_is_available_for_twofish() -> None:
    pytest.importorskip("ctypes")
    try:
        cipher = LibgcryptCipher("twofish", b"\x11" * 16)
    except UnsupportedCipherError:
        pytest.skip("libgcrypt not available on this host")
    out = cipher.encrypt_block(b"\x00" * BLOCK_SIZE)
    assert len(out) == BLOCK_SIZE


def test_libgcrypt_and_pure_python_agree_on_twofish() -> None:
    """The two backends must be interchangeable."""
    key = bytes(range(16))
    block = bytes(range(16, 32))
    try:
        native = LibgcryptCipher("twofish", key).encrypt_block(block)
    except UnsupportedCipherError:
        pytest.skip("libgcrypt not available")
    pure = get_cipher("twofish", key).encrypt_block(block)
    assert native == pure


def test_libgcrypt_rejects_unknown_cipher() -> None:
    with pytest.raises(UnsupportedCipherError):
        LibgcryptCipher("cast256", b"\x00" * 16)


def test_libgcrypt_rejects_bad_key_length() -> None:
    try:
        LibgcryptCipher("twofish", b"\x00" * 16)
    except UnsupportedCipherError:
        pytest.skip("libgcrypt not available")
    with pytest.raises(ValueError):
        LibgcryptCipher("twofish", b"\x00" * 15)


def test_libgcrypt_rejects_short_block() -> None:
    try:
        cipher = LibgcryptCipher("twofish", b"\x00" * 16)
    except UnsupportedCipherError:
        pytest.skip("libgcrypt not available")
    with pytest.raises(ValueError):
        cipher.encrypt_block(b"\x00" * 15)


def test_cipher_availability_helpers() -> None:
    assert "twofish" in available_ciphers()
    assert cipher_available("twofish") is True
    assert cipher_available("no-such-cipher") is False
    assert cipher_available("") is False


def test_get_cipher_rejects_unknown_and_bad_key() -> None:
    with pytest.raises(UnsupportedCipherError):
        get_cipher("nope", b"\x00" * 16)
    with pytest.raises(ValueError):
        get_cipher("twofish", b"\x00" * 3)
    with pytest.raises(UnsupportedCipherError):
        encrypt_block("nope", b"\x00" * 16, b"\x00" * 16)


def test_cast256_is_reachable_only_via_pure_python() -> None:
    """libgcrypt has no CAST-256 at all, so this proves the pure backend works."""
    cipher = get_cipher("cast256", b"\x00" * 16)
    assert cipher.encrypt_block(b"\x00" * 16) != b"\x00" * 16
