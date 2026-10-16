// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 pkt-core contributors
//
// Twofish — Schneier, Kelsey, Whiting, Wagner, Hall, Ferguson, "The Twofish
// Encryption Algorithm: A 128-Bit Block Cipher" (1998).  This is a line-by-line
// port of the KAT-verified pure-Python implementation in
// src/pkt_core/crypto/ciphers_pure.py; the algorithmic traps documented there
// are preserved verbatim:
//
// * ``h()`` applies the q permutation to the input FIRST, then ``(XOR key
//   byte, q)`` once per 64-bit key word — k+1 q applications, k XORs.
// * Round-key pairs split the key into M_e / M_o: ``K_2i``'s h() XORs key
//   bytes at byte-index ``8*(k-1-d)+p``, ``K_2i+1``'s at ``8*(k-1-d)+4+p``.
// * RS uses GF(2^8) mod x^8+x^6+x^5+x^3+1 (0x14D); MDS uses mod 0x169.

use std::sync::LazyLock;

/// GF(2^8) multiplication with the given reduction polynomial.
fn gf_mul(mut left: u8, mut right: u8, poly: u16) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let mut wide = (left as u16) << 1;
        if wide & 0x100 != 0 {
            wide ^= poly;
        }
        left = wide as u8;
        right >>= 1;
    }
    result
}

// ---------------------------------------------------------------------------
// q0 / q1 permutations (Twofish paper, section 4.3.5)
// ---------------------------------------------------------------------------
static Q0_T0: [u8; 16] = [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4];
static Q0_T1: [u8; 16] = [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13];
static Q0_T2: [u8; 16] = [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1];
static Q0_T3: [u8; 16] = [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10];
static Q1_T0: [u8; 16] = [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5];
static Q1_T1: [u8; 16] = [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8];
static Q1_T2: [u8; 16] = [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15];
static Q1_T3: [u8; 16] = [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10];

fn build_q(t0: &[u8; 16], t1: &[u8; 16], t2: &[u8; 16], t3: &[u8; 16]) -> [u8; 256] {
    fn keyed_nibble(a: u8, b: u8) -> (u8, u8) {
        let a1 = a ^ b;
        let b1 = a ^ ((b >> 1) | ((b & 1) << 3)) ^ ((8 * a) & 0x0F);
        (a1 & 0x0F, b1 & 0x0F)
    }
    let mut table = [0u8; 256];
    for value in 0..256u16 {
        let a0 = ((value >> 4) & 0x0F) as u8;
        let b0 = (value & 0x0F) as u8;
        let (a1, b1) = keyed_nibble(a0, b0);
        let (a2, b2) = (t0[a1 as usize], t1[b1 as usize]);
        let (a3, b3) = keyed_nibble(a2, b2);
        let (a4, b4) = (t2[a3 as usize], t3[b3 as usize]);
        table[value as usize] = ((b4 & 0x0F) << 4) | (a4 & 0x0F);
    }
    table
}

static Q0: LazyLock<[u8; 256]> = LazyLock::new(|| build_q(&Q0_T0, &Q0_T1, &Q0_T2, &Q0_T3));
static Q1: LazyLock<[u8; 256]> = LazyLock::new(|| build_q(&Q1_T0, &Q1_T1, &Q1_T2, &Q1_T3));

fn q(table: u8, index: u8) -> u8 {
    match table {
        0 => Q0[index as usize],
        _ => Q1[index as usize],
    }
}

// ---------------------------------------------------------------------------
// MDS and RS matrices
// ---------------------------------------------------------------------------
const MDS_POLY: u16 = 0x169;
static MDS_MATRIX: [[u8; 4]; 4] = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
];

/// `MDS[column][value]` -> 32-bit MDS contribution of that column (the row
/// byte lands in the little-endian word byte `row`, as in the Python source).
static MDS: LazyLock<[[u32; 256]; 4]> = LazyLock::new(|| {
    let mut mds = [[0u32; 256]; 4];
    for column in 0..4 {
        for value in 0..256u16 {
            let mut word: u32 = 0;
            for row in 0..4 {
                let product = gf_mul(MDS_MATRIX[row][column], value as u8, MDS_POLY);
                word |= (product as u32) << (8 * row);
            }
            mds[column][value as usize] = word;
        }
    }
    mds
});

const RS_POLY: u16 = 0x14D;
static RS_COLUMNS: [u32; 8] = [
    0x01A402A4, 0xA456A155, 0x5582FC87, 0x87F3C15A, 0x5A1E4758, 0x58C6AEDB, 0xDB683D9E,
    0x9EE51903,
];

// ---------------------------------------------------------------------------
// h() q-permutation sequences
// ---------------------------------------------------------------------------
// Indexed by (k = number of 64-bit key words, byte position).  Each slice has
// k+1 entries applied first-to-last: one leading q on the input byte, then
// (XOR key/S byte, q) k times.
static Q_CHAINS: [[[u8; 5]; 4]; 5] = [
    // k = 0 and k = 1 are unused (keys are 16/24/32 bytes -> k in 2..=4).
    [[0; 5]; 4],
    [[0; 5]; 4],
    [
        [0, 0, 1, 0, 0],
        [1, 0, 0, 0, 0],
        [0, 1, 1, 0, 0],
        [1, 1, 0, 0, 0],
    ],
    [
        [1, 0, 0, 1, 0],
        [1, 1, 0, 0, 0],
        [0, 0, 1, 1, 0],
        [0, 1, 1, 0, 0],
    ],
    [
        [1, 1, 0, 0, 1],
        [0, 1, 1, 0, 0],
        [0, 0, 0, 1, 1],
        [1, 0, 1, 1, 0],
    ],
];

fn q_chain(k: usize, position: usize) -> &'static [u8] {
    // k+1 meaningful entries; the trailing zeros of the fixed 5-slot row are
    // never read because the loops below use depth in 0..=k.
    &Q_CHAINS[k][position][..=k]
}

// ---------------------------------------------------------------------------
// the cipher
// ---------------------------------------------------------------------------
pub struct Twofish {
    key_size: usize,
    /// Key-dependent S-boxes already composed with the MDS columns.
    sb: [[u32; 256]; 4],
    /// 40 round subkeys.
    rk: [u32; 40],
}

impl Twofish {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(format!(
                "Twofish key must be 16, 24 or 32 bytes, got {}",
                key.len()
            ));
        }
        let k = key.len() / 8;

        // --- S-box key words (RS encoding of 8-byte key chunks) -----------
        let mut s_bytes = [0u8; 16];
        for (index, byte) in key.iter().enumerate() {
            let column = RS_COLUMNS[index % 8];
            let offset = 4 * (index / 8);
            for lane in 0..4 {
                let coefficient = ((column >> (8 * (3 - lane))) & 0xFF) as u8;
                s_bytes[offset + lane] ^= gf_mul(coefficient, *byte, RS_POLY);
            }
        }

        // --- key-dependent S-boxes composed with the MDS columns ----------
        let mut sb = [[0u32; 256]; 4];
        for position in 0..4 {
            let chain = q_chain(k, position);
            let mds_column = &MDS[position];
            for value in 0..256u16 {
                let mut mixed = q(chain[0], value as u8);
                for depth in 0..k {
                    mixed = q(chain[depth + 1], mixed ^ s_bytes[4 * depth + position]);
                }
                sb[position][value as usize] = mds_column[mixed as usize];
            }
        }

        // --- 40 round subkeys (M_e / M_o split of the key) ----------------
        let mut rk = [0u32; 40];
        for i in (0..40).step_by(2) {
            let x = h_word(key, k, i as u8, 0);
            let y = h_word(key, k, (i + 1) as u8, 4).rotate_left(8);
            let x = x.wrapping_add(y);
            let y = y.wrapping_add(x);
            rk[i] = x;
            rk[i + 1] = y.rotate_left(9);
        }

        Ok(Self {
            key_size: key.len(),
            sb,
            rk,
        })
    }

    pub fn key_size(&self) -> usize {
        self.key_size
    }

    pub fn encrypt_block(&self, block: &[u8]) -> [u8; 16] {
        let mut words = [0u32; 4];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        let [mut a, mut b, mut c, mut d] = words;
        let sb = &self.sb;
        let rk = &self.rk;

        a ^= rk[0];
        b ^= rk[1];
        c ^= rk[2];
        d ^= rk[3];

        for base in (8..40).step_by(4) {
            let mut x = sb[0][a as u8 as usize]
                ^ sb[1][(a >> 8) as u8 as usize]
                ^ sb[2][(a >> 16) as u8 as usize]
                ^ sb[3][(a >> 24) as usize];
            let mut y = sb[1][b as u8 as usize]
                ^ sb[2][(b >> 8) as u8 as usize]
                ^ sb[3][(b >> 16) as u8 as usize]
                ^ sb[0][(b >> 24) as usize];
            x = x.wrapping_add(y);
            y = y.wrapping_add(x);
            x = x.wrapping_add(rk[base]);
            y = y.wrapping_add(rk[base + 1]);
            c = (c ^ x).rotate_left(31); // ror(c ^ x, 1)
            d = d.rotate_left(1) ^ y;

            x = sb[0][c as u8 as usize]
                ^ sb[1][(c >> 8) as u8 as usize]
                ^ sb[2][(c >> 16) as u8 as usize]
                ^ sb[3][(c >> 24) as usize];
            y = sb[1][d as u8 as usize]
                ^ sb[2][(d >> 8) as u8 as usize]
                ^ sb[3][(d >> 16) as u8 as usize]
                ^ sb[0][(d >> 24) as usize];
            x = x.wrapping_add(y);
            y = y.wrapping_add(x);
            x = x.wrapping_add(rk[base + 2]);
            y = y.wrapping_add(rk[base + 3]);
            a = (a ^ x).rotate_left(31);
            b = b.rotate_left(1) ^ y;
        }

        c ^= rk[4];
        d ^= rk[5];
        a ^= rk[6];
        b ^= rk[7];

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&c.to_le_bytes());
        out[4..8].copy_from_slice(&d.to_le_bytes());
        out[8..12].copy_from_slice(&a.to_le_bytes());
        out[12..16].copy_from_slice(&b.to_le_bytes());
        out
    }
}

/// The Twofish ``h()`` function applied to one byte of round-key input.
///
/// One leading q permutation, then ``(XOR key byte, q)`` once per 64-bit key
/// word; the key bytes enter innermost-first.  ``group`` is 0 for the even
/// subkeys (M_e) and 4 for the odd subkeys (M_o).
fn h_word(key: &[u8], k: usize, value: u8, group: usize) -> u32 {
    let mut out: u32 = 0;
    for position in 0..4 {
        let chain = q_chain(k, position);
        let mut mixed = q(chain[0], value);
        for depth in 0..k {
            let index = 8 * (k - 1 - depth) + group + position;
            mixed = q(chain[depth + 1], mixed ^ key[index]);
        }
        out ^= MDS[position][mixed as usize];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(key_hex: &str, pt_hex: &str) -> String {
        let cipher = Twofish::new(&hex(key_hex)).unwrap();
        hex_encode(&cipher.encrypt_block(&hex(pt_hex)))
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|v| format!("{:02X}", v)).collect()
    }

    /// AES-submission `ecb_tbl.txt` / `ecb_ival.txt` vectors (twofishv.dat).
    #[test]
    fn kat() {
        assert_eq!(
            enc(&"00".repeat(16), &"00".repeat(16)),
            "9F589F5CF6122C32B6BFEC2F2AE8C35A"
        );
        assert_eq!(
            enc(&"00".repeat(24), &"00".repeat(16)),
            "EFA71F788965BD4453F860178FC19101"
        );
        assert_eq!(
            enc(&"00".repeat(32), &"00".repeat(16)),
            "57FF739D4DC92C1BD7FC01700CC8216F"
        );
        assert_eq!(
            enc(
                "9F589F5CF6122C32B6BFEC2F2AE8C35A",
                "D491DB16E7B1C39E86CB086B789F5419"
            ),
            "019F9809DE1711858FAAC3A3BA20FBC3"
        );
        assert_eq!(
            enc(
                "D491DB16E7B1C39E86CB086B789F5419",
                "019F9809DE1711858FAAC3A3BA20FBC3"
            ),
            "6363977DE839486297E661C6C9D668EB"
        );
        assert_eq!(
            enc(
                "EFA71F788965BD4453F860178FC191010000000000000000",
                "88B2B2706B105E36B446BB6D731A1E88"
            ),
            "39DA69D6BA4997D585B6DC073CA341B2"
        );
        assert_eq!(
            enc(
                "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
                "39DA69D6BA4997D585B6DC073CA341B2"
            ),
            "182B02D81497EA45F9DAACDC29193A65"
        );
        assert_eq!(
            enc(
                "3059D6D61753B958D92F4781C8640E586CB4561C40BF0A9705931CB6D408E7FA",
                "E69465770505D7F80EF68CA38AB3A3D6"
            ),
            "5AB67A5F8539A4A5FD9F0373BA463466"
        );
        assert_eq!(
            enc(&"00".repeat(24), &format!("80{}", "00".repeat(15))),
            "62EF193EDB7D399ACA50EC1CBE5398D8"
        );
        assert_eq!(
            enc(&"00".repeat(32), &format!("80{}", "00".repeat(15))),
            "23A385F617F313DAC05BCB7EABD61807"
        );
    }
}
