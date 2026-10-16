#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Self-contained codec tests: encode -> decode -> compare (no sample files needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pt9  # noqa: E402


class CodecTests(unittest.TestCase):
    def _sample(self, extra=b""):
        return (
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            b"<PACKETTRACER5>\n <VERSION>9.0.1.0858</VERSION>\n"
            b" <DEVICES><DEVICE><NAME>R1</NAME><TYPE>2911</TYPE></DEVICE></DEVICES>\n"
            + extra +
            b"</PACKETTRACER5>\n"
        )

    def test_roundtrip_pkt(self):
        for wait in (b"", b"x" * 100000, bytes(range(256)) * 400):
            xml = self._sample(wait)
            blob = pt9.encode_bytes(xml, "pkt")
            self.assertEqual(pt9.decode_bytes(blob, "pkt"), xml)

    def test_roundtrip_pta(self):
        if not pt9.cipher_available("serpent128"):
            self.skipTest("libgcrypt build has no Serpent")
        xml = self._sample()
        blob = pt9.encode_bytes(xml, "pta")
        self.assertEqual(pt9.decode_bytes(blob, "pta"), xml)

    def test_tag_rejects_corruption(self):
        blob = bytearray(pt9.encode_bytes(self._sample(), "pkt"))
        blob[len(blob) // 2] ^= 0x01
        with self.assertRaises(pt9.PacketTracerError):
            pt9.decode_bytes(bytes(blob), "pkt", verify_tag=True)

    def test_wrong_format_rejected_or_differs(self):
        xml = self._sample()
        blob = pt9.encode_bytes(xml, "pkt")
        try:
            out = pt9.decode_bytes(blob, "pta", verify_tag=True)
        except pt9.PacketTracerError:
            return
        self.assertNotEqual(out, xml)

    def test_layer_inverses(self):
        data = bytes(range(256)) * 3
        self.assertEqual(pt9._layer_a_inv(pt9._layer_a(data)), data)
        self.assertEqual(pt9._layer_b(pt9._layer_b(data)), data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
