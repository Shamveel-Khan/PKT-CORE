"""Pure-Python block ciphers used by the Packet Tracer container formats.

The container layer needs exactly three 128-bit block ciphers in ECB /
encrypt-only form (CTR keystream + CMAC derive everything else):

* :class:`Twofish` — the ``.pkt`` / ``.pka`` / ``.log`` containers.
* :class:`Serpent` — the ``.pkc`` / ``.pta`` containers.
* :class:`CAST256` — the ``sm`` / ``userapp`` containers (not in libgcrypt).

Everything here is dependency-free pure Python with full type hints; the
algorithms are the published specifications:

* Twofish — Schneier, Kelsey, Whiting, Wagner, Hall, Ferguson,
  "The Twofish Encryption Algorithm: A 128-Bit Block Cipher" (1998),
  sections 4.2 (MDS), 4.3 (key schedule, h/g functions).
* Serpent — Anderson, Biham, Knudsen, "Serpent: A Flexible Block Cipher With
  Maximum Assurance" (AES submission, 1998).  This module implements the
  bit-slice formulation without the optional IP/FP bit permutations — the
  variant used by libgcrypt, Crypto++, Botan and the NESSIE test vectors.
* CAST-256 — Adams & Gilchrist, RFC 2612 (June 1999), including the CAST-128
  S-boxes of RFC 2144 that CAST-256 reuses.

The module is byte-identical to ``libgcrypt`` for Twofish and Serpent and to
the RFC 2612 appendix-A vectors for CAST-256; see ``tests/test_ciphers.py``
for the validation harness.
"""

from __future__ import annotations

from typing import Callable, Final, Protocol, runtime_checkable

__all__ = [
    "BLOCK_SIZE",
    "BlockCipher",
    "CAST256",
    "CIPHERS",
    "CipherRegistry",
    "KEY_SIZES",
    "Serpent",
    "Twofish",
    "encrypt_block",
    "get_cipher",
]

BLOCK_SIZE: Final[int] = 16
"""Every cipher Packet Tracer uses operates on 128-bit blocks."""

_M32: Final[int] = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# small shared helpers
# ---------------------------------------------------------------------------
def _rol(value: int, count: int) -> int:
    """Rotate ``value`` left by ``count`` bits inside a 32-bit word."""
    count &= 31
    return ((value << count) | (value >> (32 - count))) & _M32


def _gf_mul(left: int, right: int, poly: int) -> int:
    """Multiply two GF(2^8) elements given the reduction polynomial."""
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left <<= 1
        if left & 0x100:
            left ^= poly
        right >>= 1
    return result & 0xFF


@runtime_checkable
class BlockCipher(Protocol):
    """Uniform 128-bit block-cipher interface (ECB, encrypt only)."""

    block_size: int
    key_size: int

    def __init__(self, key: bytes) -> None:
        """Build the key schedule from ``key``."""
        ...

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block and return the 16-byte ciphertext."""
        ...


# ===========================================================================
# Twofish
# ===========================================================================
# q0/q1 are built from the eight 4-bit permutations published with the cipher
# ("Twofish" paper, section 4.3.5): a two-round keyed permutation of the high
# and low nibbles, interleaved with the affine mixing shown below.
_Q0_T0: Final[tuple[int, ...]] = (8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4)
_Q0_T1: Final[tuple[int, ...]] = (14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13)
_Q0_T2: Final[tuple[int, ...]] = (11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1)
_Q0_T3: Final[tuple[int, ...]] = (13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10)
_Q1_T0: Final[tuple[int, ...]] = (2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5)
_Q1_T1: Final[tuple[int, ...]] = (1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8)
_Q1_T2: Final[tuple[int, ...]] = (4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15)
_Q1_T3: Final[tuple[int, ...]] = (11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10)


def _build_q(
    t0: tuple[int, ...],
    t1: tuple[int, ...],
    t2: tuple[int, ...],
    t3: tuple[int, ...],
) -> tuple[int, ...]:
    """Expand the four 4-bit permutations into one 8-bit q permutation."""

    def keyed_nibble(a: int, b: int) -> tuple[int, int]:
        a1 = a ^ b
        b1 = a ^ ((b >> 1) | ((b & 1) << 3)) ^ ((8 * a) & 0x0F)
        return a1 & 0x0F, b1 & 0x0F

    table: list[int] = []
    for value in range(256):
        a0, b0 = (value >> 4) & 0x0F, value & 0x0F
        a1, b1 = keyed_nibble(a0, b0)
        a2, b2 = t0[a1], t1[b1]
        a3, b3 = keyed_nibble(a2, b2)
        a4, b4 = t2[a3], t3[b3]
        table.append(((b4 & 0x0F) << 4) | (a4 & 0x0F))
    return tuple(table)


_Q0: Final[tuple[int, ...]] = _build_q(_Q0_T0, _Q0_T1, _Q0_T2, _Q0_T3)
_Q1: Final[tuple[int, ...]] = _build_q(_Q1_T0, _Q1_T1, _Q1_T2, _Q1_T3)

# MDS matrix over GF(2^8) modulo x^8+x^6+x^5+x^3+1 (0x169), rows top-down as
# printed in the paper; output word byte n (little-endian) is row n.
_MDS_POLY: Final[int] = 0x169
_MDS_MATRIX: Final[tuple[tuple[int, ...], ...]] = (
    (0x01, 0xEF, 0x5B, 0x5B),
    (0x5B, 0xEF, 0xEF, 0x01),
    (0xEF, 0x5B, 0x01, 0xEF),
    (0xEF, 0x01, 0xEF, 0x5B),
)

# _MDS[column][value] -> the 32-bit MDS contribution of that column.
_MDS: Final[tuple[tuple[int, ...], ...]] = tuple(
    tuple(
        sum(_gf_mul(_MDS_MATRIX[row][column], value, _MDS_POLY) << (8 * row) for row in range(4))
        for value in range(256)
    )
    for column in range(4)
)

# Reed-Solomon matrix of the Twofish key schedule, in the column-major
# 32-bit-word form used by the reference key schedule (polynomial entries;
# multiplication happens in GF(2^8) modulo x^8+x^6+x^5+x^3+1 = 0x14D).
_RS_POLY: Final[int] = 0x14D
_RS_COLUMNS: Final[tuple[int, ...]] = (
    0x01A402A4,
    0xA456A155,
    0x5582FC87,
    0x87F3C15A,
    0x5A1E4758,
    0x58C6AEDB,
    0xDB683D9E,
    0x9EE51903,
)

# q-permutation sequences of the h() function, indexed by (number of 64-bit
# key words k, byte position in the word).  Each tuple has k+1 entries applied
# first-to-last: the first q is applied to the input byte, then
# (XOR key/S byte, q) repeats k times.  The key schedule and the
# key-dependent S-boxes share the sequences and differ only in which bytes
# are XORed (Twofish paper, section 4.3.4).
_Q_CHAINS: Final[dict[tuple[int, int], tuple[int, ...]]] = {
    (2, 0): (0, 0, 1),
    (2, 1): (1, 0, 0),
    (2, 2): (0, 1, 1),
    (2, 3): (1, 1, 0),
    (3, 0): (1, 0, 0, 1),
    (3, 1): (1, 1, 0, 0),
    (3, 2): (0, 0, 1, 1),
    (3, 3): (0, 1, 1, 0),
    (4, 0): (1, 1, 0, 0, 1),
    (4, 1): (0, 1, 1, 0, 0),
    (4, 2): (0, 0, 0, 1, 1),
    (4, 3): (1, 0, 1, 1, 0),
}
_Q_TABLES: Final[tuple[tuple[int, ...], ...]] = (_Q0, _Q1)


class Twofish:
    """Twofish with 128, 192 or 256-bit keys (16-byte blocks).

    The key schedule is evaluated once per instance; ``encrypt_block`` then
    only reads the precomputed key-dependent S-boxes and round subkeys.
    """

    block_size: int = 16
    key_size: int

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Twofish key must be 16, 24 or 32 bytes, got {len(key)}")
        self.key_size = len(key)
        self._k: int = len(key) // 8
        key_bytes = tuple(key)
        self._key_bytes = key_bytes

        # --- S-box key words (RS encoding of 8-byte key chunks) -----------
        # Each key byte multiplies one RS column; the four product bytes land
        # in S in matrix-row order (row 0 first).
        s_bytes = [0] * 16
        for index, byte in enumerate(key_bytes):
            column = _RS_COLUMNS[index % 8]
            offset = 4 * (index // 8)
            for lane in range(4):
                coefficient = (column >> (8 * (3 - lane))) & 0xFF
                s_bytes[offset + lane] ^= _gf_mul(coefficient, byte, _RS_POLY)
        self._s = tuple(s_bytes)

        # --- key-dependent S-boxes composed with the MDS columns ----------
        # h() per byte position: one leading q, then (XOR S byte, q) k times.
        sb: list[tuple[int, ...]] = []
        for position in range(4):
            table: list[int] = []
            chain = _Q_CHAINS[(self._k, position)]
            mds_column = _MDS[position]
            for value in range(256):
                mixed = _Q_TABLES[chain[0]][value]
                for depth in range(self._k):
                    mixed = _Q_TABLES[chain[depth + 1]][mixed ^ self._s[4 * depth + position]]
                table.append(mds_column[mixed])
            sb.append(tuple(table))
        self._sb = sb

        # --- 40 round subkeys ---------------------------------------------
        # Each pair is h(i) and h(i+1); the even subkey draws its key bytes
        # from one half of the key and the odd subkey from the other
        # (the M_e / M_o split of the paper).
        rk = [0] * 40
        for i in range(0, 40, 2):
            x = self._h_word(i, 0)
            y = self._h_word(i + 1, 4)
            y = _rol(y, 8)
            x = (x + y) & _M32
            y = (y + x) & _M32
            rk[i] = x
            rk[i + 1] = _rol(y, 9)
        self._rk = tuple(rk)

    def _h_word(self, value: int, group: int) -> int:
        """The Twofish h() function applied to a one-byte round-key input.

        Per byte position this is one leading q permutation followed by
        ``(XOR key byte, q)`` repeated once per 64-bit key word; the key
        bytes enter innermost-first.  ``group`` is 0 for the even subkeys
        and 4 for the odd subkeys (they read opposite halves of the key).
        """
        out = 0
        key_bytes = self._key_bytes
        k = self._k
        for position in range(4):
            chain = _Q_CHAINS[(k, position)]
            mixed = _Q_TABLES[chain[0]][value]
            for depth in range(k):
                index = 8 * (k - 1 - depth) + group + position
                mixed = _Q_TABLES[chain[depth + 1]][mixed ^ key_bytes[index]]
            out ^= _MDS[position][mixed]
        return out

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block with the precomputed key schedule."""
        if len(block) != 16:
            raise ValueError(f"block must be 16 bytes, got {len(block)}")
        a, b, c, d = (
            int.from_bytes(block[0:4], "little"),
            int.from_bytes(block[4:8], "little"),
            int.from_bytes(block[8:12], "little"),
            int.from_bytes(block[12:16], "little"),
        )
        sb0, sb1, sb2, sb3 = self._sb
        rk = self._rk

        a ^= rk[0]
        b ^= rk[1]
        c ^= rk[2]
        d ^= rk[3]

        # 16 rounds; each round is two half-rounds.  A half-round computes
        # g(first word) with byte j of the word feeding S-box table j, and
        # the rotated g() of the second word where the table index advances
        # by one, then feeds the PHT and the two round subkeys into the
        # opposite pair.
        for base in range(8, 40, 4):
            x = sb0[a & 0xFF] ^ sb1[(a >> 8) & 0xFF] ^ sb2[(a >> 16) & 0xFF] ^ sb3[(a >> 24) & 0xFF]
            y = sb1[b & 0xFF] ^ sb2[(b >> 8) & 0xFF] ^ sb3[(b >> 16) & 0xFF] ^ sb0[(b >> 24) & 0xFF]
            x = (x + y) & _M32
            y = (y + x) & _M32
            x = (x + rk[base]) & _M32
            y = (y + rk[base + 1]) & _M32
            c = _rol((c ^ x) & _M32, 31)  # ror(c ^ x, 1)
            d = (_rol(d, 1) ^ y) & _M32

            x = sb0[c & 0xFF] ^ sb1[(c >> 8) & 0xFF] ^ sb2[(c >> 16) & 0xFF] ^ sb3[(c >> 24) & 0xFF]
            y = sb1[d & 0xFF] ^ sb2[(d >> 8) & 0xFF] ^ sb3[(d >> 16) & 0xFF] ^ sb0[(d >> 24) & 0xFF]
            x = (x + y) & _M32
            y = (y + x) & _M32
            x = (x + rk[base + 2]) & _M32
            y = (y + rk[base + 3]) & _M32
            a = _rol((a ^ x) & _M32, 31)
            b = (_rol(b, 1) ^ y) & _M32

        c ^= rk[4]
        d ^= rk[5]
        a ^= rk[6]
        b ^= rk[7]

        out = (
            c.to_bytes(4, "little")
            + d.to_bytes(4, "little")
            + a.to_bytes(4, "little")
            + b.to_bytes(4, "little")
        )
        return out


# ===========================================================================
# Serpent
# ===========================================================================
# The eight Serpent S-boxes as bit-slice boolean circuits over four 32-bit
# words (bit 0 of the input nibble is carried by x0, bit 3 by x3).  These are
# the standard S-box permutations S0..S7 of the AES submission; the circuits
# are the optimised form popularised by Osvik, "Speeding up Serpent" (AES3).
# The equivalent 4-bit permutation tables are:
#   S0: 3 8 15 1 10 6 5 11 14 13 4 2 7 0 9 12
#   S1: 15 12 2 7 9 0 5 10 1 11 14 8 6 13 3 4
#   S2: 8 6 7 9 3 12 10 15 13 1 14 4 0 11 5 2
#   S3: 0 15 11 8 12 9 6 3 13 1 2 4 10 7 5 14
#   S4: 1 15 8 3 12 0 11 6 2 5 4 10 9 14 7 13
#   S5: 15 5 2 11 4 10 9 12 0 3 14 8 13 6 7 1
#   S6: 7 2 12 5 8 4 6 11 14 9 1 15 13 3 10 0
#   S7: 1 13 15 0 14 8 2 11 7 4 12 10 9 3 5 6
_SBox = Callable[[int, int, int, int], tuple[int, int, int, int]]


def _sb0(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x3 ^= x0
    x4 = x1
    x1 &= x3
    x4 ^= x2
    x1 ^= x0
    x0 |= x3
    x0 ^= x4
    x4 ^= x3
    x3 ^= x2
    x2 |= x1
    x2 ^= x4
    x4 ^= _M32
    x4 |= x1
    x1 ^= x3
    x1 ^= x4
    x3 |= x0
    x1 ^= x3
    x4 ^= x3
    return x1, x4, x2, x0


def _sb1(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x0 ^= _M32
    x2 ^= _M32
    x4 = x0
    x0 &= x1
    x2 ^= x0
    x0 |= x3
    x3 ^= x2
    x1 ^= x0
    x0 ^= x4
    x4 |= x1
    x1 ^= x3
    x2 |= x0
    x2 &= x4
    x0 ^= x1
    x1 &= x2
    x1 ^= x0
    x0 &= x2
    x0 ^= x4
    return x2, x0, x3, x1


def _sb2(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x4 = x0
    x0 &= x2
    x0 ^= x3
    x2 ^= x1
    x2 ^= x0
    x3 |= x4
    x3 ^= x1
    x4 ^= x2
    x1 = x3
    x3 |= x4
    x3 ^= x0
    x0 &= x1
    x4 ^= x0
    x1 ^= x3
    x1 ^= x4
    x4 ^= _M32
    return x2, x3, x1, x4


def _sb3(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x4 = x0
    x0 |= x3
    x3 ^= x1
    x1 &= x4
    x4 ^= x2
    x2 ^= x3
    x3 &= x0
    x4 |= x1
    x3 ^= x4
    x0 ^= x1
    x4 &= x0
    x1 ^= x3
    x4 ^= x2
    x1 |= x0
    x1 ^= x2
    x0 ^= x3
    x2 = x1
    x1 |= x3
    x1 ^= x0
    return x1, x2, x3, x4


def _sb4(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x1 ^= x3
    x3 ^= _M32
    x2 ^= x3
    x3 ^= x0
    x4 = x1
    x1 &= x3
    x1 ^= x2
    x4 ^= x3
    x0 ^= x4
    x2 &= x4
    x2 ^= x0
    x0 &= x1
    x3 ^= x0
    x4 |= x1
    x4 ^= x0
    x0 |= x3
    x0 ^= x2
    x2 &= x3
    x0 ^= _M32
    x4 ^= x2
    return x1, x4, x0, x3


def _sb5(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x0 ^= x1
    x1 ^= x3
    x3 ^= _M32
    x4 = x1
    x1 &= x0
    x2 ^= x3
    x1 ^= x2
    x2 |= x4
    x4 ^= x3
    x3 &= x1
    x3 ^= x0
    x4 ^= x1
    x4 ^= x2
    x2 ^= x0
    x0 &= x3
    x2 ^= _M32
    x0 ^= x4
    x4 |= x3
    x2 ^= x4
    return x1, x3, x0, x2


def _sb6(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x2 ^= _M32
    x4 = x3
    x3 &= x0
    x0 ^= x4
    x3 ^= x2
    x2 |= x4
    x1 ^= x3
    x2 ^= x0
    x0 |= x1
    x2 ^= x1
    x4 ^= x0
    x0 |= x3
    x0 ^= x2
    x4 ^= x3
    x4 ^= x0
    x3 ^= _M32
    x2 &= x4
    x2 ^= x3
    return x0, x1, x4, x2


def _sb7(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    x4 = x1
    x1 |= x2
    x1 ^= x3
    x4 ^= x2
    x2 ^= x1
    x3 |= x4
    x3 &= x0
    x4 ^= x2
    x3 ^= x1
    x1 |= x4
    x1 ^= x0
    x0 |= x4
    x0 ^= x2
    x1 ^= x4
    x2 ^= x1
    x1 &= x0
    x1 ^= x4
    x2 ^= _M32
    x2 |= x0
    x4 ^= x2
    return x4, x3, x1, x0


_SERPENT_SBOXES: Final[tuple[_SBox, ...]] = (
    _sb0,
    _sb1,
    _sb2,
    _sb3,
    _sb4,
    _sb5,
    _sb6,
    _sb7,
)

_SERPENT_PHI: Final[int] = 0x9E3779B9


def _serpent_lt(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    """Serpent's linear transformation (no IP/FP in this formulation)."""
    x0 = _rol(x0, 13)
    x2 = _rol(x2, 3)
    x1 ^= x0 ^ x2
    x3 ^= x2 ^ ((x0 << 3) & _M32)
    x1 = _rol(x1, 1)
    x3 = _rol(x3, 7)
    x0 ^= x1 ^ x3
    x2 ^= x3 ^ ((x1 << 7) & _M32)
    x0 = _rol(x0, 5)
    x2 = _rol(x2, 22)
    return x0, x1, x2, x3


class Serpent:
    """Serpent with 128, 192 or 256-bit keys (16-byte blocks).

    Shorter keys are padded as the specification demands: one ``1`` bit
    followed by zero bits.  Keys of different sizes are the
    ``serpent128`` / ``serpent192`` / ``serpent256`` variants.
    """

    block_size: int = 16
    key_size: int

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Serpent key must be 16, 24 or 32 bytes, got {len(key)}")
        self.key_size = len(key)

        words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, len(key), 4)]
        if len(words) < 8:
            words.append(0x00000001)
            words.extend([0] * (8 - len(words)))

        # Prekey expansion: w[i] = rol11(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1]
        #                               ^ PHI ^ i) for i = 0..131.
        prekey = list(words)
        for i in range(132):
            prekey.append(
                _rol(prekey[i] ^ prekey[i + 3] ^ prekey[i + 5] ^ prekey[i + 7] ^ _SERPENT_PHI ^ i, 11)
            )
        # prekey[8 + j] is now prekey word j; subkey j uses words 4j..4j+3
        # through S-box (3 - j) mod 8.
        subkeys: list[tuple[int, int, int, int]] = []
        for j in range(33):
            block = (
                prekey[8 + 4 * j],
                prekey[8 + 4 * j + 1],
                prekey[8 + 4 * j + 2],
                prekey[8 + 4 * j + 3],
            )
            subkeys.append(_SERPENT_SBOXES[(3 - j) % 8](*block))
        self._subkeys = tuple(subkeys)

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block with the precomputed key schedule."""
        if len(block) != 16:
            raise ValueError(f"block must be 16 bytes, got {len(block)}")
        state = [
            int.from_bytes(block[0:4], "little"),
            int.from_bytes(block[4:8], "little"),
            int.from_bytes(block[8:12], "little"),
            int.from_bytes(block[12:16], "little"),
        ]
        subkeys = self._subkeys
        for round_index in range(32):
            sk = subkeys[round_index]
            state[0] ^= sk[0]
            state[1] ^= sk[1]
            state[2] ^= sk[2]
            state[3] ^= sk[3]
            state = list(_SERPENT_SBOXES[round_index & 7](*state))
            if round_index != 31:
                state = list(_serpent_lt(*state))
        sk = subkeys[32]
        return (
            (state[0] ^ sk[0]).to_bytes(4, "little")
            + (state[1] ^ sk[1]).to_bytes(4, "little")
            + (state[2] ^ sk[2]).to_bytes(4, "little")
            + (state[3] ^ sk[3]).to_bytes(4, "little")
        )


# ===========================================================================
# CAST-256 (RFC 2612)
# ===========================================================================
# The four CAST-128 S-boxes of RFC 2144 that CAST-256 reuses (RFC 2612
# section 2.1.1), reproduced verbatim from the RFC.
_S1: Final[tuple[int, ...]] = (
    0x30FB40D4, 0x9FA0FF0B, 0x6BECCD2F, 0x3F258C7A, 0x1E213F2F, 0x9C004DD3, 0x6003E540, 0xCF9FC949,
    0xBFD4AF27, 0x88BBBDB5, 0xE2034090, 0x98D09675, 0x6E63A0E0, 0x15C361D2, 0xC2E7661D, 0x22D4FF8E,
    0x28683B6F, 0xC07FD059, 0xFF2379C8, 0x775F50E2, 0x43C340D3, 0xDF2F8656, 0x887CA41A, 0xA2D2BD2D,
    0xA1C9E0D6, 0x346C4819, 0x61B76D87, 0x22540F2F, 0x2ABE32E1, 0xAA54166B, 0x22568E3A, 0xA2D341D0,
    0x66DB40C8, 0xA784392F, 0x004DFF2F, 0x2DB9D2DE, 0x97943FAC, 0x4A97C1D8, 0x527644B7, 0xB5F437A7,
    0xB82CBAEF, 0xD751D159, 0x6FF7F0ED, 0x5A097A1F, 0x827B68D0, 0x90ECF52E, 0x22B0C054, 0xBC8E5935,
    0x4B6D2F7F, 0x50BB64A2, 0xD2664910, 0xBEE5812D, 0xB7332290, 0xE93B159F, 0xB48EE411, 0x4BFF345D,
    0xFD45C240, 0xAD31973F, 0xC4F6D02E, 0x55FC8165, 0xD5B1CAAD, 0xA1AC2DAE, 0xA2D4B76D, 0xC19B0C50,
    0x882240F2, 0x0C6E4F38, 0xA4E4BFD7, 0x4F5BA272, 0x564C1D2F, 0xC59C5319, 0xB949E354, 0xB04669FE,
    0xB1B6AB8A, 0xC71358DD, 0x6385C545, 0x110F935D, 0x57538AD5, 0x6A390493, 0xE63D37E0, 0x2A54F6B3,
    0x3A787D5F, 0x6276A0B5, 0x19A6FCDF, 0x7A42206A, 0x29F9D4D5, 0xF61B1891, 0xBB72275E, 0xAA508167,
    0x38901091, 0xC6B505EB, 0x84C7CB8C, 0x2AD75A0F, 0x874A1427, 0xA2D1936B, 0x2AD286AF, 0xAA56D291,
    0xD7894360, 0x425C750D, 0x93B39E26, 0x187184C9, 0x6C00B32D, 0x73E2BB14, 0xA0BEBC3C, 0x54623779,
    0x64459EAB, 0x3F328B82, 0x7718CF82, 0x59A2CEA6, 0x04EE002E, 0x89FE78E6, 0x3FAB0950, 0x325FF6C2,
    0x81383F05, 0x6963C5C8, 0x76CB5AD6, 0xD49974C9, 0xCA180DCF, 0x380782D5, 0xC7FA5CF6, 0x8AC31511,
    0x35E79E13, 0x47DA91D0, 0xF40F9086, 0xA7E2419E, 0x31366241, 0x051EF495, 0xAA573B04, 0x4A805D8D,
    0x548300D0, 0x00322A3C, 0xBF64CDDF, 0xBA57A68E, 0x75C6372B, 0x50AFD341, 0xA7C13275, 0x915A0BF5,
    0x6B54BFAB, 0x2B0B1426, 0xAB4CC9D7, 0x449CCD82, 0xF7FBF265, 0xAB85C5F3, 0x1B55DB94, 0xAAD4E324,
    0xCFA4BD3F, 0x2DEAA3E2, 0x9E204D02, 0xC8BD25AC, 0xEADF55B3, 0xD5BD9E98, 0xE31231B2, 0x2AD5AD6C,
    0x954329DE, 0xADBE4528, 0xD8710F69, 0xAA51C90F, 0xAA786BF6, 0x22513F1E, 0xAA51A79B, 0x2AD344CC,
    0x7B5A41F0, 0xD37CFBAD, 0x1B069505, 0x41ECE491, 0xB4C332E6, 0x032268D4, 0xC9600ACC, 0xCE387E6D,
    0xBF6BB16C, 0x6A70FB78, 0x0D03D9C9, 0xD4DF39DE, 0xE01063DA, 0x4736F464, 0x5AD328D8, 0xB347CC96,
    0x75BB0FC3, 0x98511BFB, 0x4FFBCC35, 0xB58BCF6A, 0xE11F0ABC, 0xBFC5FE4A, 0xA70AEC10, 0xAC39570A,
    0x3F04442F, 0x6188B153, 0xE0397A2E, 0x5727CB79, 0x9CEB418F, 0x1CACD68D, 0x2AD37C96, 0x0175CB9D,
    0xC69DFF09, 0xC75B65F0, 0xD9DB40D8, 0xEC0E7779, 0x4744EAD4, 0xB11C3274, 0xDD24CB9E, 0x7E1C54BD,
    0xF01144F9, 0xD2240EB1, 0x9675B3FD, 0xA3AC3755, 0xD47C27AF, 0x51C85F4D, 0x56907596, 0xA5BB15E6,
    0x580304F0, 0xCA042CF1, 0x011A37EA, 0x8DBFAADB, 0x35BA3E4A, 0x3526FFA0, 0xC37B4D09, 0xBC306ED9,
    0x98A52666, 0x5648F725, 0xFF5E569D, 0x0CED63D0, 0x7C63B2CF, 0x700B45E1, 0xD5EA50F1, 0x85A92872,
    0xAF1FBDA7, 0xD4234870, 0xA7870BF3, 0x2D3B4D79, 0x42E04198, 0x0CD0EDE7, 0x26470DB8, 0xF881814C,
    0x474D6AD7, 0x7C0C5E5C, 0xD1231959, 0x381B7298, 0xF5D2F4DB, 0xAB838653, 0x6E2F1E23, 0x83719C9E,
    0xBD91E046, 0x9A56456E, 0xDC39200C, 0x20C8C571, 0x962BDA1C, 0xE1E696FF, 0xB141AB08, 0x7CCA89B9,
    0x1A69E783, 0x02CC4843, 0xA2F7C579, 0x429EF47D, 0x427B169C, 0x5AC9F049, 0xDD8F0F00, 0x5C8165BF,
)

_S2: Final[tuple[int, ...]] = (
    0x1F201094, 0xEF0BA75B, 0x69E3CF7E, 0x393F4380, 0xFE61CF7A, 0xEEC5207A, 0x55889C94, 0x72FC0651,
    0xADA7EF79, 0x4E1D7235, 0xD55A63CE, 0xDE0436BA, 0x99C430EF, 0x5F0C0794, 0x18DCDB7D, 0xA1D6EFF3,
    0xA0B52F7B, 0x59E83605, 0xEE15B094, 0xE9FFD909, 0xDC440086, 0xEF944459, 0xBA83CCB3, 0xE0C3CDFB,
    0xD1DA4181, 0x3B092AB1, 0xF997F1C1, 0xA5E6CF7B, 0x01420DDB, 0xE4E7EF5B, 0x25A1FF41, 0xE180F806,
    0x1FC41080, 0x179BEE7A, 0xD37AC6A9, 0xFE5830A4, 0x98DE8B7F, 0x77E83F4E, 0x79929269, 0x24FA9F7B,
    0xE113C85B, 0xACC40083, 0xD7503525, 0xF7EA615F, 0x62143154, 0x0D554B63, 0x5D681121, 0xC866C359,
    0x3D63CF73, 0xCEE234C0, 0xD4D87E87, 0x5C672B21, 0x071F6181, 0x39F7627F, 0x361E3084, 0xE4EB573B,
    0x602F64A4, 0xD63ACD9C, 0x1BBC4635, 0x9E81032D, 0x2701F50C, 0x99847AB4, 0xA0E3DF79, 0xBA6CF38C,
    0x10843094, 0x2537A95E, 0xF46F6FFE, 0xA1FF3B1F, 0x208CFB6A, 0x8F458C74, 0xD9E0A227, 0x4EC73A34,
    0xFC884F69, 0x3E4DE8DF, 0xEF0E0088, 0x3559648D, 0x8A45388C, 0x1D804366, 0x721D9BFD, 0xA58684BB,
    0xE8256333, 0x844E8212, 0x128D8098, 0xFED33FB4, 0xCE280AE1, 0x27E19BA5, 0xD5A6C252, 0xE49754BD,
    0xC5D655DD, 0xEB667064, 0x77840B4D, 0xA1B6A801, 0x84DB26A9, 0xE0B56714, 0x21F043B7, 0xE5D05860,
    0x54F03084, 0x066FF472, 0xA31AA153, 0xDADC4755, 0xB5625DBF, 0x68561BE6, 0x83CA6B94, 0x2D6ED23B,
    0xECCF01DB, 0xA6D3D0BA, 0xB6803D5C, 0xAF77A709, 0x33B4A34C, 0x397BC8D6, 0x5EE22B95, 0x5F0E5304,
    0x81ED6F61, 0x20E74364, 0xB45E1378, 0xDE18639B, 0x881CA122, 0xB96726D1, 0x8049A7E8, 0x22B7DA7B,
    0x5E552D25, 0x5272D237, 0x79D2951C, 0xC60D894C, 0x488CB402, 0x1BA4FE5B, 0xA4B09F6B, 0x1CA815CF,
    0xA20C3005, 0x8871DF63, 0xB9DE2FCB, 0x0CC6C9E9, 0x0BEEFF53, 0xE3214517, 0xB4542835, 0x9F63293C,
    0xEE41E729, 0x6E1D2D7C, 0x50045286, 0x1E6685F3, 0xF33401C6, 0x30A22C95, 0x31A70850, 0x60930F13,
    0x73F98417, 0xA1269859, 0xEC645C44, 0x52C877A9, 0xCDFF33A6, 0xA02B1741, 0x7CBAD9A2, 0x2180036F,
    0x50D99C08, 0xCB3F4861, 0xC26BD765, 0x64A3F6AB, 0x80342676, 0x25A75E7B, 0xE4E6D1FC, 0x20C710E6,
    0xCDF0B680, 0x17844D3B, 0x31EEF84D, 0x7E0824E4, 0x2CCB49EB, 0x846A3BAE, 0x8FF77888, 0xEE5D60F6,
    0x7AF75673, 0x2FDD5CDB, 0xA11631C1, 0x30F66F43, 0xB3FAEC54, 0x157FD7FA, 0xEF8579CC, 0xD152DE58,
    0xDB2FFD5E, 0x8F32CE19, 0x306AF97A, 0x02F03EF8, 0x99319AD5, 0xC242FA0F, 0xA7E3EBB0, 0xC68E4906,
    0xB8DA230C, 0x80823028, 0xDCDEF3C8, 0xD35FB171, 0x088A1BC8, 0xBEC0C560, 0x61A3C9E8, 0xBCA8F54D,
    0xC72FEFFA, 0x22822E99, 0x82C570B4, 0xD8D94E89, 0x8B1C34BC, 0x301E16E6, 0x273BE979, 0xB0FFEAA6,
    0x61D9B8C6, 0x00B24869, 0xB7FFCE3F, 0x08DC283B, 0x43DAF65A, 0xF7E19798, 0x7619B72F, 0x8F1C9BA4,
    0xDC8637A0, 0x16A7D3B1, 0x9FC393B7, 0xA7136EEB, 0xC6BCC63E, 0x1A513742, 0xEF6828BC, 0x520365D6,
    0x2D6A77AB, 0x3527ED4B, 0x821FD216, 0x095C6E2E, 0xDB92F2FB, 0x5EEA29CB, 0x145892F5, 0x91584F7F,
    0x5483697B, 0x2667A8CC, 0x85196048, 0x8C4BACEA, 0x833860D4, 0x0D23E0F9, 0x6C387E8A, 0x0AE6D249,
    0xB284600C, 0xD835731D, 0xDCB1C647, 0xAC4C56EA, 0x3EBD81B3, 0x230EABB0, 0x6438BC87, 0xF0B5B1FA,
    0x8F5EA2B3, 0xFC184642, 0x0A036B7A, 0x4FB089BD, 0x649DA589, 0xA345415E, 0x5C038323, 0x3E5D3BB9,
    0x43D79572, 0x7E6DD07C, 0x06DFDF1E, 0x6C6CC4EF, 0x7160A539, 0x73BFBE70, 0x83877605, 0x4523ECF1,
)

_S3: Final[tuple[int, ...]] = (
    0x8DEFC240, 0x25FA5D9F, 0xEB903DBF, 0xE810C907, 0x47607FFF, 0x369FE44B, 0x8C1FC644, 0xAECECA90,
    0xBEB1F9BF, 0xEEFBCAEA, 0xE8CF1950, 0x51DF07AE, 0x920E8806, 0xF0AD0548, 0xE13C8D83, 0x927010D5,
    0x11107D9F, 0x07647DB9, 0xB2E3E4D4, 0x3D4F285E, 0xB9AFA820, 0xFADE82E0, 0xA067268B, 0x8272792E,
    0x553FB2C0, 0x489AE22B, 0xD4EF9794, 0x125E3FBC, 0x21FFFCEE, 0x825B1BFD, 0x9255C5ED, 0x1257A240,
    0x4E1A8302, 0xBAE07FFF, 0x528246E7, 0x8E57140E, 0x3373F7BF, 0x8C9F8188, 0xA6FC4EE8, 0xC982B5A5,
    0xA8C01DB7, 0x579FC264, 0x67094F31, 0xF2BD3F5F, 0x40FFF7C1, 0x1FB78DFC, 0x8E6BD2C1, 0x437BE59B,
    0x99B03DBF, 0xB5DBC64B, 0x638DC0E6, 0x55819D99, 0xA197C81C, 0x4A012D6E, 0xC5884A28, 0xCCC36F71,
    0xB843C213, 0x6C0743F1, 0x8309893C, 0x0FEDDD5F, 0x2F7FE850, 0xD7C07F7E, 0x02507FBF, 0x5AFB9A04,
    0xA747D2D0, 0x1651192E, 0xAF70BF3E, 0x58C31380, 0x5F98302E, 0x727CC3C4, 0x0A0FB402, 0x0F7FEF82,
    0x8C96FDAD, 0x5D2C2AAE, 0x8EE99A49, 0x50DA88B8, 0x8427F4A0, 0x1EAC5790, 0x796FB449, 0x8252DC15,
    0xEFBD7D9B, 0xA672597D, 0xADA840D8, 0x45F54504, 0xFA5D7403, 0xE83EC305, 0x4F91751A, 0x925669C2,
    0x23EFE941, 0xA903F12E, 0x60270DF2, 0x0276E4B6, 0x94FD6574, 0x927985B2, 0x8276DBCB, 0x02778176,
    0xF8AF918D, 0x4E48F79E, 0x8F616DDF, 0xE29D840E, 0x842F7D83, 0x340CE5C8, 0x96BBB682, 0x93B4B148,
    0xEF303CAB, 0x984FAF28, 0x779FAF9B, 0x92DC560D, 0x224D1E20, 0x8437AA88, 0x7D29DC96, 0x2756D3DC,
    0x8B907CEE, 0xB51FD240, 0xE7C07CE3, 0xE566B4A1, 0xC3E9615E, 0x3CF8209D, 0x6094D1E3, 0xCD9CA341,
    0x5C76460E, 0x00EA983B, 0xD4D67881, 0xFD47572C, 0xF76CEDD9, 0xBDA8229C, 0x127DADAA, 0x438A074E,
    0x1F97C090, 0x081BDB8A, 0x93A07EBE, 0xB938CA15, 0x97B03CFF, 0x3DC2C0F8, 0x8D1AB2EC, 0x64380E51,
    0x68CC7BFB, 0xD90F2788, 0x12490181, 0x5DE5FFD4, 0xDD7EF86A, 0x76A2E214, 0xB9A40368, 0x925D958F,
    0x4B39FFFA, 0xBA39AEE9, 0xA4FFD30B, 0xFAF7933B, 0x6D498623, 0x193CBCFA, 0x27627545, 0x825CF47A,
    0x61BD8BA0, 0xD11E42D1, 0xCEAD04F4, 0x127EA392, 0x10428DB7, 0x8272A972, 0x9270C4A8, 0x127DE50B,
    0x285BA1C8, 0x3C62F44F, 0x35C0EAA5, 0xE805D231, 0x428929FB, 0xB4FCDF82, 0x4FB66A53, 0x0E7DC15B,
    0x1F081FAB, 0x108618AE, 0xFCFD086D, 0xF9FF2889, 0x694BCC11, 0x236A5CAE, 0x12DECA4D, 0x2C3F8CC5,
    0xD2D02DFE, 0xF8EF5896, 0xE4CF52DA, 0x95155B67, 0x494A488C, 0xB9B6A80C, 0x5C8F82BC, 0x89D36B45,
    0x3A609437, 0xEC00C9A9, 0x44715253, 0x0A874B49, 0xD773BC40, 0x7C34671C, 0x02717EF6, 0x4FEB5536,
    0xA2D02FFF, 0xD2BF60C4, 0xD43F03C0, 0x50B4EF6D, 0x07478CD1, 0x006E1888, 0xA2E53F55, 0xB9E6D4BC,
    0xA2048016, 0x97573833, 0xD7207D67, 0xDE0F8F3D, 0x72F87B33, 0xABCC4F33, 0x7688C55D, 0x7B00A6B0,
    0x947B0001, 0x570075D2, 0xF9BB88F8, 0x8942019E, 0x4264A5FF, 0x856302E0, 0x72DBD92B, 0xEE971B69,
    0x6EA22FDE, 0x5F08AE2B, 0xAF7A616D, 0xE5C98767, 0xCF1FEBD2, 0x61EFC8C2, 0xF1AC2571, 0xCC8239C2,
    0x67214CB8, 0xB1E583D1, 0xB7DC3E62, 0x7F10BDCE, 0xF90A5C38, 0x0FF0443D, 0x606E6DC6, 0x60543A49,
    0x5727C148, 0x2BE98A1D, 0x8AB41738, 0x20E1BE24, 0xAF96DA0F, 0x68458425, 0x99833BE5, 0x600D457D,
    0x282F9350, 0x8334B362, 0xD91D1120, 0x2B6D8DA0, 0x642B1E31, 0x9C305A00, 0x52BCE688, 0x1B03588A,
    0xF7BAEFD5, 0x4142ED9C, 0xA4315C11, 0x83323EC5, 0xDFEF4636, 0xA133C501, 0xE9D3531C, 0xEE353783,
)

_S4: Final[tuple[int, ...]] = (
    0x9DB30420, 0x1FB6E9DE, 0xA7BE7BEF, 0xD273A298, 0x4A4F7BDB, 0x64AD8C57, 0x85510443, 0xFA020ED1,
    0x7E287AFF, 0xE60FB663, 0x095F35A1, 0x79EBF120, 0xFD059D43, 0x6497B7B1, 0xF3641F63, 0x241E4ADF,
    0x28147F5F, 0x4FA2B8CD, 0xC9430040, 0x0CC32220, 0xFDD30B30, 0xC0A5374F, 0x1D2D00D9, 0x24147B15,
    0xEE4D111A, 0x0FCA5167, 0x71FF904C, 0x2D195FFE, 0x1A05645F, 0x0C13FEFE, 0x081B08CA, 0x05170121,
    0x80530100, 0xE83E5EFE, 0xAC9AF4F8, 0x7FE72701, 0xD2B8EE5F, 0x06DF4261, 0xBB9E9B8A, 0x7293EA25,
    0xCE84FFDF, 0xF5718801, 0x3DD64B04, 0xA26F263B, 0x7ED48400, 0x547EEBE6, 0x446D4CA0, 0x6CF3D6F5,
    0x2649ABDF, 0xAEA0C7F5, 0x36338CC1, 0x503F7E93, 0xD3772061, 0x11B638E1, 0x72500E03, 0xF80EB2BB,
    0xABE0502E, 0xEC8D77DE, 0x57971E81, 0xE14F6746, 0xC9335400, 0x6920318F, 0x081DBB99, 0xFFC304A5,
    0x4D351805, 0x7F3D5CE3, 0xA6C866C6, 0x5D5BCCA9, 0xDAEC6FEA, 0x9F926F91, 0x9F46222F, 0x3991467D,
    0xA5BF6D8E, 0x1143C44F, 0x43958302, 0xD0214EEB, 0x022083B8, 0x3FB6180C, 0x18F8931E, 0x281658E6,
    0x26486E3E, 0x8BD78A70, 0x7477E4C1, 0xB506E07C, 0xF32D0A25, 0x79098B02, 0xE4EABB81, 0x28123B23,
    0x69DEAD38, 0x1574CA16, 0xDF871B62, 0x211C40B7, 0xA51A9EF9, 0x0014377B, 0x041E8AC8, 0x09114003,
    0xBD59E4D2, 0xE3D156D5, 0x4FE876D5, 0x2F91A340, 0x557BE8DE, 0x00EAE4A7, 0x0CE5C2EC, 0x4DB4BBA6,
    0xE756BDFF, 0xDD3369AC, 0xEC17B035, 0x06572327, 0x99AFC8B0, 0x56C8C391, 0x6B65811C, 0x5E146119,
    0x6E85CB75, 0xBE07C002, 0xC2325577, 0x893FF4EC, 0x5BBFC92D, 0xD0EC3B25, 0xB7801AB7, 0x8D6D3B24,
    0x20C763EF, 0xC366A5FC, 0x9C382880, 0x0ACE3205, 0xAAC9548A, 0xECA1D7C7, 0x041AFA32, 0x1D16625A,
    0x6701902C, 0x9B757A54, 0x31D477F7, 0x9126B031, 0x36CC6FDB, 0xC70B8B46, 0xD9E66A48, 0x56E55A79,
    0x026A4CEB, 0x52437EFF, 0x2F8F76B4, 0x0DF980A5, 0x8674CDE3, 0xEDDA04EB, 0x17A9BE04, 0x2C18F4DF,
    0xB7747F9D, 0xAB2AF7B4, 0xEFC34D20, 0x2E096B7C, 0x1741A254, 0xE5B6A035, 0x213D42F6, 0x2C1C7C26,
    0x61C2F50F, 0x6552DAF9, 0xD2C231F8, 0x25130F69, 0xD8167FA2, 0x0418F2C8, 0x001A96A6, 0x0D1526AB,
    0x63315C21, 0x5E0A72EC, 0x49BAFEFD, 0x187908D9, 0x8D0DBD86, 0x311170A7, 0x3E9B640C, 0xCC3E10D7,
    0xD5CAD3B6, 0x0CAEC388, 0xF73001E1, 0x6C728AFF, 0x71EAE2A1, 0x1F9AF36E, 0xCFCBD12F, 0xC1DE8417,
    0xAC07BE6B, 0xCB44A1D8, 0x8B9B0F56, 0x013988C3, 0xB1C52FCA, 0xB4BE31CD, 0xD8782806, 0x12A3A4E2,
    0x6F7DE532, 0x58FD7EB6, 0xD01EE900, 0x24ADFFC2, 0xF4990FC5, 0x9711AAC5, 0x001D7B95, 0x82E5E7D2,
    0x109873F6, 0x00613096, 0xC32D9521, 0xADA121FF, 0x29908415, 0x7FBB977F, 0xAF9EB3DB, 0x29C9ED2A,
    0x5CE2A465, 0xA730F32C, 0xD0AA3FE8, 0x8A5CC091, 0xD49E2CE7, 0x0CE454A9, 0xD60ACD86, 0x015F1919,
    0x77079103, 0xDEA03AF6, 0x78A8565E, 0xDEE356DF, 0x21F05CBE, 0x8B75E387, 0xB3C50651, 0xB8A5C3EF,
    0xD8EEB6D2, 0xE523BE77, 0xC2154529, 0x2F69EFDF, 0xAFE67AFB, 0xF470C4B2, 0xF3E0EB5B, 0xD6CC9876,
    0x39E4460C, 0x1FDA8538, 0x1987832F, 0xCA007367, 0xA99144F8, 0x296B299E, 0x492FC295, 0x9266BEAB,
    0xB5676E69, 0x9BD3DDDA, 0xDF7E052F, 0xDB25701C, 0x1B5E51EE, 0xF65324E6, 0x6AFCE36C, 0x0316CC04,
    0x8644213E, 0xB7DC59D0, 0x7965291F, 0xCCD6FD43, 0x41823979, 0x932BCDF6, 0xB657C34D, 0x4EDFD282,
    0x7AE5290C, 0x3CB9536B, 0x851E20FE, 0x9833557E, 0x13ECF0B0, 0xD3FFB372, 0x3F85C5C1, 0x0AEF7ED2,
)


class CAST256:
    """CAST-256 with 128, 160, 192, 224 or 256-bit keys (RFC 2612).

    This cipher has no libgcrypt counterpart, so the instance also exposes the
    derived quad-round keys ``kr`` / ``km`` and the single quad-round step
    :meth:`quad_round` so the RFC 2612 intermediate values can be checked.
    ``decrypt_block`` is provided because CAST-256 decryption is exactly the
    encryption structure with the quad-round keys reversed.
    """

    block_size: int = 16
    key_size: int

    # Kr_(i) = {Kr0, Kr1, Kr2, Kr3} rotation keys; Km_(i) masking keys.
    kr: tuple[tuple[int, int, int, int], ...]
    km: tuple[tuple[int, int, int, int], ...]

    def __init__(self, key: bytes) -> None:
        if not 16 <= len(key) <= 32 or len(key) % 4 != 0:
            raise ValueError(
                f"CAST-256 key must be 16, 20, 24, 28 or 32 bytes, got {len(key)}"
            )
        self.key_size = len(key)

        # KAPPA = (A..H); shorter keys zero-pad the trailing words
        # (RFC 2612 section 2.4).
        words = [int.from_bytes(key[i : i + 4], "big") for i in range(0, len(key), 4)]
        words.extend([0] * (8 - len(words)))
        a, b, c, d, e, f, g, h = words

        # Tm/Tr constants (RFC 2612 section 2.4).
        cm = 0x5A827999
        mm = 0x6ED9EBA1
        cr = 19
        mr = 17
        tm: list[tuple[int, ...]] = []
        tr: list[tuple[int, ...]] = []
        for _ in range(24):
            tm_row: list[int] = []
            tr_row: list[int] = []
            for _j in range(8):
                tm_row.append(cm)
                cm = (cm + mm) & _M32
                tr_row.append(cr)
                cr = (cr + mr) & 31
            tm.append(tuple(tm_row))
            tr.append(tuple(tr_row))

        def f1(data: int, rotation: int, mask: int) -> int:
            intermediate = _rol((mask + data) & _M32, rotation)
            ia, ib, ic, id_ = (
                (intermediate >> 24) & 0xFF,
                (intermediate >> 16) & 0xFF,
                (intermediate >> 8) & 0xFF,
                intermediate & 0xFF,
            )
            return (((_S1[ia] ^ _S2[ib]) - _S3[ic]) + _S4[id_]) & _M32

        def f2(data: int, rotation: int, mask: int) -> int:
            intermediate = _rol((mask ^ data) & _M32, rotation)
            ia, ib, ic, id_ = (
                (intermediate >> 24) & 0xFF,
                (intermediate >> 16) & 0xFF,
                (intermediate >> 8) & 0xFF,
                intermediate & 0xFF,
            )
            return ((((_S1[ia] - _S2[ib]) + _S3[ic]) & _M32) ^ _S4[id_]) & _M32

        def f3(data: int, rotation: int, mask: int) -> int:
            intermediate = _rol((mask - data) & _M32, rotation)
            ia, ib, ic, id_ = (
                (intermediate >> 24) & 0xFF,
                (intermediate >> 16) & 0xFF,
                (intermediate >> 8) & 0xFF,
                intermediate & 0xFF,
            )
            return (((_S1[ia] + _S2[ib]) ^ _S3[ic]) - _S4[id_]) & _M32

        self._f1, self._f2, self._f3 = f1, f2, f3

        # Forward octave W(i) (RFC 2612 section 2.2): f1, f2, f3, f1, f2, f3,
        # f1, f2 over (H, G, F, E, D, C, B, A).
        def octave(i: int) -> None:
            nonlocal a, b, c, d, e, f, g, h
            g ^= f1(h, tr[i][0], tm[i][0])
            f ^= f2(g, tr[i][1], tm[i][1])
            e ^= f3(f, tr[i][2], tm[i][2])
            d ^= f1(e, tr[i][3], tm[i][3])
            c ^= f2(d, tr[i][4], tm[i][4])
            b ^= f3(c, tr[i][5], tm[i][5])
            a ^= f1(b, tr[i][6], tm[i][6])
            h ^= f2(a, tr[i][7], tm[i][7])

        kr: list[tuple[int, int, int, int]] = []
        km: list[tuple[int, int, int, int]] = []
        for i in range(12):
            octave(2 * i)
            octave(2 * i + 1)
            # Kr_(i) <- KAPPA, Km_(i) <- KAPPA (RFC 2612 section 2.2).
            kr.append((a & 31, c & 31, e & 31, g & 31))
            km.append((h, f, d, b))
        self.kr = tuple(kr)
        self.km = tuple(km)

    def quad_round(
        self,
        state: tuple[int, int, int, int],
        index: int,
        forward: bool = True,
    ) -> tuple[int, int, int, int]:
        """Apply one quad-round ``Q_i`` / ``QBAR_i`` to a 128-bit word tuple."""
        a, b, c, d = state
        kr0, kr1, kr2, kr3 = self.kr[index]
        km0, km1, km2, km3 = self.km[index]
        if forward:
            c ^= self._f1(d, kr0, km0)
            b ^= self._f2(c, kr1, km1)
            a ^= self._f3(b, kr2, km2)
            d ^= self._f1(a, kr3, km3)
        else:
            d ^= self._f1(a, kr3, km3)
            a ^= self._f3(b, kr2, km2)
            b ^= self._f2(c, kr1, km1)
            c ^= self._f1(d, kr0, km0)
        return a, b, c, d

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block (12 quad-rounds, RFC 2612 section 2.3)."""
        if len(block) != 16:
            raise ValueError(f"block must be 16 bytes, got {len(block)}")
        state = (
            int.from_bytes(block[0:4], "big"),
            int.from_bytes(block[4:8], "big"),
            int.from_bytes(block[8:12], "big"),
            int.from_bytes(block[12:16], "big"),
        )
        for i in range(6):
            state = self.quad_round(state, i, forward=True)
        for i in range(6, 12):
            state = self.quad_round(state, i, forward=False)
        return b"".join(word.to_bytes(4, "big") for word in state)

    def decrypt_block(self, block: bytes) -> bytes:
        """Inverse of :meth:`encrypt_block` (quad-round keys reversed)."""
        if len(block) != 16:
            raise ValueError(f"block must be 16 bytes, got {len(block)}")
        state = (
            int.from_bytes(block[0:4], "big"),
            int.from_bytes(block[4:8], "big"),
            int.from_bytes(block[8:12], "big"),
            int.from_bytes(block[12:16], "big"),
        )
        for i in range(12):
            state = self.quad_round(state, 11 - i, forward=(i < 6))
        return b"".join(word.to_bytes(4, "big") for word in state)


# ===========================================================================
# registry
# ===========================================================================
#: Registry names match ``pt9.py``'s ``_CIPHER_IDS`` spellings.
CIPHERS: dict[str, type[BlockCipher]] = {
    "twofish": Twofish,
    "serpent128": Serpent,
    "serpent192": Serpent,
    "serpent256": Serpent,
    "cast256": CAST256,
}

#: Key sizes (in bytes) each registry name accepts.
KEY_SIZES: dict[str, tuple[int, ...]] = {
    "twofish": (16, 24, 32),
    "serpent128": (16,),
    "serpent192": (24,),
    "serpent256": (32,),
    "cast256": (16, 20, 24, 28, 32),
}


class CipherRegistry:
    """Name -> cipher-class mapping with per-name key-size enforcement."""

    def names(self) -> tuple[str, ...]:
        """All registered cipher names, in registration order."""
        return tuple(CIPHERS)

    def key_sizes(self, name: str) -> tuple[int, ...]:
        """Key sizes accepted by the named cipher."""
        try:
            return KEY_SIZES[name]
        except KeyError:
            raise KeyError(f"unknown cipher {name!r}; known: {sorted(CIPHERS)}") from None

    def create(self, name: str, key: bytes) -> BlockCipher:
        """Instantiate the named cipher with ``key``.

        Raises:
            KeyError: ``name`` is not registered.
            ValueError: ``key`` has a length the named cipher rejects.
        """
        try:
            cipher_type = CIPHERS[name]
            allowed = KEY_SIZES[name]
        except KeyError:
            raise KeyError(f"unknown cipher {name!r}; known: {sorted(CIPHERS)}") from None
        if len(key) not in allowed:
            raise ValueError(
                f"{name} accepts key sizes {allowed} bytes, got {len(key)}"
            )
        return cipher_type(key)


_REGISTRY: Final[CipherRegistry] = CipherRegistry()


def get_cipher(name: str, key: bytes) -> BlockCipher:
    """Return an instance of the named cipher (alias of the registry factory)."""
    return _REGISTRY.create(name, key)


def encrypt_block(name: str, key: bytes, block: bytes) -> bytes:
    """Encrypt one block with the named cipher (one-shot convenience helper)."""
    return _REGISTRY.create(name, key).encrypt_block(block)
