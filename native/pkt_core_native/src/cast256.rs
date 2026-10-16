// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 pkt-core contributors
//
// CAST-256 — Adams & Gilchrist, RFC 2612 (June 1999), reusing the CAST-128
// S-boxes of RFC 2144.  Line-by-line port of src/pkt_core/crypto/ciphers_pure.py:
//
// * Words are BIG-endian; shorter keys zero-pad the TRAILING words
//   (E = F = G = H = 0).
// * Kr_(i) = 5LSB(A, C, E, G), Km_(i) = (H, F, D, B) after W(2i), W(2i+1).
// * Encrypt is Q_0..Q_5 then QBAR_6..QBAR_11; decryption uses quad-round
//   keys (11 - i).
// * The f-type cycle inside every octave is f1, f2, f3, f1, f2, f3, f1, f2.

use crate::cast_tables::{S1, S2, S3, S4};

fn rol(value: u32, count: u32) -> u32 {
    value.rotate_left(count & 31)
}

fn f1(data: u32, rotation: u32, mask: u32) -> u32 {
    let intermediate = rol(mask.wrapping_add(data), rotation);
    let ia = ((intermediate >> 24) & 0xFF) as usize;
    let ib = ((intermediate >> 16) & 0xFF) as usize;
    let ic = ((intermediate >> 8) & 0xFF) as usize;
    let id = (intermediate & 0xFF) as usize;
    ((S1[ia] ^ S2[ib]).wrapping_sub(S3[ic])).wrapping_add(S4[id])
}

fn f2(data: u32, rotation: u32, mask: u32) -> u32 {
    let intermediate = rol(mask ^ data, rotation);
    let ia = ((intermediate >> 24) & 0xFF) as usize;
    let ib = ((intermediate >> 16) & 0xFF) as usize;
    let ic = ((intermediate >> 8) & 0xFF) as usize;
    let id = (intermediate & 0xFF) as usize;
    ((S1[ia].wrapping_sub(S2[ib])).wrapping_add(S3[ic])) ^ S4[id]
}

fn f3(data: u32, rotation: u32, mask: u32) -> u32 {
    let intermediate = rol(mask.wrapping_sub(data), rotation);
    let ia = ((intermediate >> 24) & 0xFF) as usize;
    let ib = ((intermediate >> 16) & 0xFF) as usize;
    let ic = ((intermediate >> 8) & 0xFF) as usize;
    let id = (intermediate & 0xFF) as usize;
    ((S1[ia].wrapping_add(S2[ib])) ^ S3[ic]).wrapping_sub(S4[id])
}

type Quad = [u32; 4];

pub struct Cast256 {
    key_size: usize,
    /// Rotation keys (5 LSB of A, C, E, G after each key octade).
    kr: [Quad; 12],
    /// Masking keys (H, F, D, B).
    km: [Quad; 12],
}

impl Cast256 {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if !(16..=32).contains(&key.len()) || key.len() % 4 != 0 {
            return Err(format!(
                "CAST-256 key must be 16, 20, 24, 28 or 32 bytes, got {}",
                key.len()
            ));
        }

        // KAPPA = (A..H); shorter keys zero-pad the trailing words
        // (RFC 2612 section 2.4).
        let mut words = [0u32; 8];
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        // Tm/Tr constants (RFC 2612 section 2.4).
        let mut cm: u32 = 0x5A82_7999;
        let mm: u32 = 0x6ED9_EBA1;
        let mut cr: u32 = 19;
        let mr: u32 = 17;
        let mut tm = [[0u32; 8]; 24];
        let mut tr = [[0u32; 8]; 24];
        for row in 0..24 {
            for slot in 0..8 {
                tm[row][slot] = cm;
                cm = cm.wrapping_add(mm);
                tr[row][slot] = cr;
                cr = (cr + mr) & 31;
            }
        }

        // Forward octave W(i) (RFC 2612 section 2.2): f1, f2, f3, f1, f2, f3,
        // f1, f2 over (H, G, F, E, D, C, B, A).
        let mut a = words[0];
        let mut b = words[1];
        let mut c = words[2];
        let mut d = words[3];
        let mut e = words[4];
        let mut f = words[5];
        let mut g = words[6];
        let mut h = words[7];
        let octave = |i: usize,
                          a: &mut u32,
                          b: &mut u32,
                          c: &mut u32,
                          d: &mut u32,
                          e: &mut u32,
                          f: &mut u32,
                          g: &mut u32,
                          h: &mut u32| {
            *g ^= f1(*h, tr[i][0], tm[i][0]);
            *f ^= f2(*g, tr[i][1], tm[i][1]);
            *e ^= f3(*f, tr[i][2], tm[i][2]);
            *d ^= f1(*e, tr[i][3], tm[i][3]);
            *c ^= f2(*d, tr[i][4], tm[i][4]);
            *b ^= f3(*c, tr[i][5], tm[i][5]);
            *a ^= f1(*b, tr[i][6], tm[i][6]);
            *h ^= f2(*a, tr[i][7], tm[i][7]);
        };

        let mut kr = [[0u32; 4]; 12];
        let mut km = [[0u32; 4]; 12];
        for i in 0..12 {
            octave(
                2 * i,
                &mut a,
                &mut b,
                &mut c,
                &mut d,
                &mut e,
                &mut f,
                &mut g,
                &mut h,
            );
            octave(
                2 * i + 1,
                &mut a,
                &mut b,
                &mut c,
                &mut d,
                &mut e,
                &mut f,
                &mut g,
                &mut h,
            );
            kr[i] = [a & 31, c & 31, e & 31, g & 31];
            km[i] = [h, f, d, b];
        }

        Ok(Self {
            key_size: key.len(),
            kr,
            km,
        })
    }

    pub fn key_size(&self) -> usize {
        self.key_size
    }

    /// The RFC 2612 rotation/masking keys, exposed for the appendix-A check.
    pub fn schedule(&self) -> ([Quad; 12], [Quad; 12]) {
        (self.kr, self.km)
    }

    pub fn quad_round(&self, state: Quad, index: usize, forward: bool) -> Quad {
        let [mut a, mut b, mut c, mut d] = state;
        let [kr0, kr1, kr2, kr3] = self.kr[index];
        let [km0, km1, km2, km3] = self.km[index];
        if forward {
            c ^= f1(d, kr0, km0);
            b ^= f2(c, kr1, km1);
            a ^= f3(b, kr2, km2);
            d ^= f1(a, kr3, km3);
        } else {
            d ^= f1(a, kr3, km3);
            a ^= f3(b, kr2, km2);
            b ^= f2(c, kr1, km1);
            c ^= f1(d, kr0, km0);
        }
        [a, b, c, d]
    }

    pub fn encrypt_block(&self, block: &[u8]) -> [u8; 16] {
        let mut state: Quad = [
            u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
            u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
            u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
        ];
        for i in 0..6 {
            state = self.quad_round(state, i, true);
        }
        for i in 6..12 {
            state = self.quad_round(state, i, false);
        }
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }

    pub fn decrypt_block(&self, block: &[u8]) -> [u8; 16] {
        let mut state: Quad = [
            u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
            u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
            u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
        ];
        for i in 0..12 {
            state = self.quad_round(state, 11 - i, i < 6);
        }
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn enc(key_hex: &str, pt_hex: &str) -> String {
        let cipher = Cast256::new(&hex(key_hex)).unwrap();
        cipher
            .encrypt_block(&hex(pt_hex))
            .iter()
            .map(|v| format!("{:02x}", v))
            .collect()
    }

    /// RFC 2612 appendix A (all three published key sizes).
    #[test]
    fn kat() {
        assert_eq!(
            enc(
                "2342bb9efa38542c0af75647f29f615d",
                &"00".repeat(16)
            ),
            "c842a08972b43d20836c91d1b7530f6b"
        );
        assert_eq!(
            enc(
                "2342bb9efa38542cbed0ac83940ac298bac77a7717942863",
                &"00".repeat(16)
            ),
            "1b386c0210dcadcbdd0e41aa08a7a7e8"
        );
        assert_eq!(
            enc(
                "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
                &"00".repeat(16)
            ),
            "4f6a2038286897b9c9870136553317fa"
        );
    }

    /// RFC 2612 appendix A intermediates for the 128-bit KAT: quad-round-0
    /// rotation/masking keys and the block after that quad-round.
    #[test]
    fn kat_intermediates() {
        let cipher = Cast256::new(&hex("2342bb9efa38542c0af75647f29f615d")).unwrap();
        let (kr, km) = cipher.schedule();
        assert_eq!(kr[0], [0x1C, 0x1D, 0x18, 0x06]);
        assert_eq!(km[0], [0xF364D7F9, 0x233500C0, 0x83CEE501, 0x01F857C6]);
        let state = cipher.quad_round([0, 0, 0, 0], 0, true);
        let expected = hex("e2c604af966715811b377f12de19e459");
        let want: Quad = [
            u32::from_be_bytes([expected[0], expected[1], expected[2], expected[3]]),
            u32::from_be_bytes([expected[4], expected[5], expected[6], expected[7]]),
            u32::from_be_bytes([expected[8], expected[9], expected[10], expected[11]]),
            u32::from_be_bytes([expected[12], expected[13], expected[14], expected[15]]),
        ];
        assert_eq!(state, want);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // Deterministic pseudo-random data covering every key size.
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for key_len in [16usize, 20, 24, 28, 32] {
            let key: Vec<u8> = (0..key_len).map(|_| next() as u8).collect();
            let cipher = Cast256::new(&key).unwrap();
            for _ in 0..25 {
                let mut block = [0u8; 16];
                for byte in block.iter_mut() {
                    *byte = next() as u8;
                }
                assert_eq!(cipher.decrypt_block(&cipher.encrypt_block(&block)), block);
            }
        }
    }
}
