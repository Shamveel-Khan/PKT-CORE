// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 pkt-core contributors
//
// Serpent — Anderson, Biham, Knudsen, "Serpent: A Flexible Block Cipher With
// Maximum Assurance" (AES submission, 1998).  This is the bit-slice
// formulation *without* the optional IP/FP bit permutations: the variant used
// by libgcrypt, Crypto++, Botan and the NESSIE test vectors.  Line-by-line
// port of src/pkt_core/crypto/ciphers_pure.py:
//
// * prekey  w[i] = rol11(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ 0x9E3779B9 ^ i)
// * subkey j = S_{(3-j) mod 8}(prekey words 4j..4j+3)
// * round r uses S_{r mod 8}; round 31 drops the LT and XORs K_32.

const M32: u32 = 0xFFFF_FFFF;
const PHI: u32 = 0x9E37_79B9;

type Words = [u32; 4];

// The eight Serpent S-boxes as bit-slice boolean circuits (Osvik's optimised
// form).  Bit 0 of the input nibble is carried by x0, bit 3 by x3.
fn sb0(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0;
    let mut x1 = x1;
    let mut x2 = x2;
    let mut x3 = x3;
    x3 ^= x0;
    let mut x4 = x1;
    x1 &= x3;
    x4 ^= x2;
    x1 ^= x0;
    x0 |= x3;
    x0 ^= x4;
    x4 ^= x3;
    x3 ^= x2;
    x2 |= x1;
    x2 ^= x4;
    x4 ^= M32;
    x4 |= x1;
    x1 ^= x3;
    x1 ^= x4;
    x3 |= x0;
    x1 ^= x3;
    x4 ^= x3;
    [x1, x4, x2, x0]
}

fn sb1(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0 ^ M32;
    let mut x1 = x1;
    let mut x2 = x2 ^ M32;
    let mut x3 = x3;
    let mut x4 = x0;
    x0 &= x1;
    x2 ^= x0;
    x0 |= x3;
    x3 ^= x2;
    x1 ^= x0;
    x0 ^= x4;
    x4 |= x1;
    x1 ^= x3;
    x2 |= x0;
    x2 &= x4;
    x0 ^= x1;
    x1 &= x2;
    x1 ^= x0;
    x0 &= x2;
    x0 ^= x4;
    [x2, x0, x3, x1]
}

fn sb2(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0;
    let mut x1 = x1;
    let mut x2 = x2;
    let mut x3 = x3;
    let mut x4 = x0;
    x0 &= x2;
    x0 ^= x3;
    x2 ^= x1;
    x2 ^= x0;
    x3 |= x4;
    x3 ^= x1;
    x4 ^= x2;
    x1 = x3;
    x3 |= x4;
    x3 ^= x0;
    x0 &= x1;
    x4 ^= x0;
    x1 ^= x3;
    x1 ^= x4;
    x4 ^= M32;
    [x2, x3, x1, x4]
}

fn sb3(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0;
    let mut x1 = x1;
    let mut x2 = x2;
    let mut x3 = x3;
    let mut x4 = x0;
    x0 |= x3;
    x3 ^= x1;
    x1 &= x4;
    x4 ^= x2;
    x2 ^= x3;
    x3 &= x0;
    x4 |= x1;
    x3 ^= x4;
    x0 ^= x1;
    x4 &= x0;
    x1 ^= x3;
    x4 ^= x2;
    x1 |= x0;
    x1 ^= x2;
    x0 ^= x3;
    x2 = x1;
    x1 |= x3;
    x1 ^= x0;
    [x1, x2, x3, x4]
}

fn sb4(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0;
    let mut x1 = x1;
    let mut x2 = x2;
    let mut x3 = x3;
    x1 ^= x3;
    x3 ^= M32;
    x2 ^= x3;
    x3 ^= x0;
    let mut x4 = x1;
    x1 &= x3;
    x1 ^= x2;
    x4 ^= x3;
    x0 ^= x4;
    x2 &= x4;
    x2 ^= x0;
    x0 &= x1;
    x3 ^= x0;
    x4 |= x1;
    x4 ^= x0;
    x0 |= x3;
    x0 ^= x2;
    x2 &= x3;
    x0 ^= M32;
    x4 ^= x2;
    [x1, x4, x0, x3]
}

fn sb5(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0;
    let mut x1 = x1;
    let mut x2 = x2;
    let mut x3 = x3;
    x0 ^= x1;
    x1 ^= x3;
    x3 ^= M32;
    let mut x4 = x1;
    x1 &= x0;
    x2 ^= x3;
    x1 ^= x2;
    x2 |= x4;
    x4 ^= x3;
    x3 &= x1;
    x3 ^= x0;
    x4 ^= x1;
    x4 ^= x2;
    x2 ^= x0;
    x0 &= x3;
    x2 ^= M32;
    x0 ^= x4;
    x4 |= x3;
    x2 ^= x4;
    [x1, x3, x0, x2]
}

fn sb6(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0;
    let mut x1 = x1;
    let mut x2 = x2 ^ M32;
    let mut x3 = x3;
    let mut x4 = x3;
    x3 &= x0;
    x0 ^= x4;
    x3 ^= x2;
    x2 |= x4;
    x1 ^= x3;
    x2 ^= x0;
    x0 |= x1;
    x2 ^= x1;
    x4 ^= x0;
    x0 |= x3;
    x0 ^= x2;
    x4 ^= x3;
    x4 ^= x0;
    x3 ^= M32;
    x2 &= x4;
    x2 ^= x3;
    [x0, x1, x4, x2]
}

fn sb7(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    let mut x0 = x0;
    let mut x1 = x1;
    let mut x2 = x2;
    let mut x3 = x3;
    let mut x4 = x1;
    x1 |= x2;
    x1 ^= x3;
    x4 ^= x2;
    x2 ^= x1;
    x3 |= x4;
    x3 &= x0;
    x4 ^= x2;
    x3 ^= x1;
    x1 |= x4;
    x1 ^= x0;
    x0 |= x4;
    x0 ^= x2;
    x1 ^= x4;
    x2 ^= x1;
    x1 &= x0;
    x1 ^= x4;
    x2 ^= M32;
    x2 |= x0;
    x4 ^= x2;
    [x4, x3, x1, x0]
}

static SBOXES: [fn(u32, u32, u32, u32) -> Words; 8] = [sb0, sb1, sb2, sb3, sb4, sb5, sb6, sb7];

fn lt(x0: u32, x1: u32, x2: u32, x3: u32) -> Words {
    // Serpent's linear transformation (no IP/FP in this formulation).
    let x0 = x0.rotate_left(13);
    let x2 = x2.rotate_left(3);
    let x1 = x1 ^ x0 ^ x2;
    let x3 = x3 ^ x2 ^ (x0 << 3);
    let x1 = x1.rotate_left(1);
    let x3 = x3.rotate_left(7);
    let x0 = x0 ^ x1 ^ x3;
    let x2 = x2 ^ x3 ^ (x1 << 7);
    let x0 = x0.rotate_left(5);
    let x2 = x2.rotate_left(22);
    [x0, x1, x2, x3]
}

pub struct Serpent {
    key_size: usize,
    subkeys: [Words; 33],
}

impl Serpent {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(format!(
                "Serpent key must be 16, 24 or 32 bytes, got {}",
                key.len()
            ));
        }

        let mut words: Vec<u32> = key
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        if words.len() < 8 {
            // Spec padding: one `1` bit followed by zero bits.
            words.push(0x0000_0001);
            while words.len() < 8 {
                words.push(0);
            }
        }

        // Prekey expansion: w[i] = rol11(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1]
        //                               ^ PHI ^ i), i = 0..131.
        let mut prekey = words;
        for i in 0..132u32 {
            let value = prekey[i as usize]
                ^ prekey[i as usize + 3]
                ^ prekey[i as usize + 5]
                ^ prekey[i as usize + 7]
                ^ PHI
                ^ i;
            prekey.push(value.rotate_left(11));
        }

        let mut subkeys = [[0u32; 4]; 33];
        for (j, subkey) in subkeys.iter_mut().enumerate() {
            let base = 8 + 4 * j;
            let block = (
                prekey[base],
                prekey[base + 1],
                prekey[base + 2],
                prekey[base + 3],
            );
            // (3 - j) mod 8, Python-style non-negative modulo.
            let index = ((3i32 - j as i32).rem_euclid(8)) as usize;
            *subkey = SBOXES[index](block.0, block.1, block.2, block.3);
        }

        Ok(Self {
            key_size: key.len(),
            subkeys,
        })
    }

    pub fn key_size(&self) -> usize {
        self.key_size
    }

    pub fn encrypt_block(&self, block: &[u8]) -> [u8; 16] {
        let mut state: Words = [
            u32::from_le_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_le_bytes([block[4], block[5], block[6], block[7]]),
            u32::from_le_bytes([block[8], block[9], block[10], block[11]]),
            u32::from_le_bytes([block[12], block[13], block[14], block[15]]),
        ];
        for round_index in 0..32 {
            let sk = self.subkeys[round_index];
            state[0] ^= sk[0];
            state[1] ^= sk[1];
            state[2] ^= sk[2];
            state[3] ^= sk[3];
            state = SBOXES[round_index & 7](state[0], state[1], state[2], state[3]);
            if round_index != 31 {
                state = lt(state[0], state[1], state[2], state[3]);
            }
        }
        let sk = self.subkeys[32];
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[4 * i..4 * i + 4].copy_from_slice(&(state[i] ^ sk[i]).to_le_bytes());
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
        let cipher = Serpent::new(&hex(key_hex)).unwrap();
        cipher
            .encrypt_block(&hex(pt_hex))
            .iter()
            .map(|v| format!("{:02X}", v))
            .collect()
    }

    /// AES-submission / NESSIE vectors (Crypto++ TestData/serpentv.dat).
    #[test]
    fn kat() {
        assert_eq!(
            enc(&format!("80{}", "00".repeat(15)), &"00".repeat(16)),
            "264E5481EFF42A4606ABDA06C0BFDA3D"
        );
        assert_eq!(
            enc(&"00".repeat(16), "D29D576FCEA3A3A7ED9099F29273D78E"),
            "B2288B968AE8B08648D1CE9606FD992D"
        );
        assert_eq!(
            enc(&"00".repeat(24), "D29D576FCEABA3A7ED9899F2927BD78E"),
            "130E353E1037C22405E8FAEFB2C3C3E9"
        );
        assert_eq!(
            enc(&"00".repeat(32), "D095576FCEA3E3A7ED98D9F29073D78E"),
            "B90EE5862DE69168F2BDD5125B45472B"
        );
        assert_eq!(
            enc(&"00".repeat(32), "00000000010000000200000003000000"),
            "2061A42782BD52EC691EC383B03BA77C"
        );
        assert_eq!(
            enc("FFEEDDCCBBAA99887766554433221100", "1032547698BADCFEEFCDAB8967452301"),
            "D5BAA00A4BB9D8A7C981C8DC90D89D92"
        );
    }
}
