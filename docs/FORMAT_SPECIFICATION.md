# Packet Tracer `.pkt` / `.pka` — Binary Format Specification

**Status: COMPLETE.** Both container families are specified and verified.

| Family | Versions | Status |
| --- | --- | --- |
| **M** — modern | PT **5.3.3** → 9.0.1 | Complete. Byte-exact round-trip on 822 real files. |
| **L** — legacy | PT **4.1** → 5.3.2 | Complete. Byte-exact round-trip on 192 real files. See [`LEGACY_FORMAT.md`](LEGACY_FORMAT.md). |

Whole-corpus proof: **1014/1014 decode and round-trip byte-exact** —
[`CORPUS_VERIFICATION.md`](CORPUS_VERIFICATION.md).

**Verified against:** Cisco Packet Tracer 9.0.1.0858 (Linux x86-64), plus 1,014
real-world containers spanning **PT 4.1 through PT 9.0.1**.

**Document caveat:** Packet Tracer documents are not always well-formed XML.
`<LINE>` running-config text embeds raw control bytes (the Cisco `banner motd
^C…^C` delimiter is a literal `\x03`) and PT 4.1 documents end with a trailing
NUL. 210 of a 400-file modern sample are non-well-formed. Do not use an
XML parser that rejects these. See [`CORPUS_VERIFICATION.md`](CORPUS_VERIFICATION.md) §5.

---

## 1. Scope and document model

A Packet Tracer save file is **not a bespoke binary format**. It is an XML
document that has been compressed and then wrapped in two obfuscation layers and
an authenticated-encryption layer. There are two document kinds:

| Root element | Typical extension | Meaning |
| --- | --- | --- |
| `PACKETTRACER5` | `.pkt` | A network lab — topology, devices, configs, canvas |
| `PACKETTRACER5_ACTIVITY` | `.pka` | A scored activity — the lab plus a scoring tree, initial-setup tree, locking tree and activity-wizard password |
| `PACKETTRACER_ACTIVITY` | `.pka` | Scored activity with the **PT 4.x** document schema (legacy family only) |

The `PACKETTRACER*` → `PACKETTRACER5*` rename happened at **PT 4.2**, not 5.0.
Activity documents nest the network document in **one or more**
`<PACKETTRACER5>` children — measured at ~3 per activity across 447 activity
documents (1,341 nested occurrences), plausibly the live / initial / comparison
copies — and add a `<VARIABLE_MANAGER>` (present in 100% of activities, 0% of
labs, in both families). PT 4.x nests `<PACKETTRACER>` instead (192 times in
64 documents).

**The container is independent of the root element.** `PACKETTRACER5` and
`PACKETTRACER5_ACTIVITY` both occur in *both* container families, so the root
element is **not** a container discriminator. A `.pka` is not a distinct file
format; it is the same container holding a different document.

## 2. There is no magic header

This matters for any implementation, so it is stated up front:

> The first bytes of a `.pkt`/`.pka` file are effectively random in **every**
> generation of the format. Measured across 1,059 real containers, the most
> common byte at each of offsets 0–31 occurs in at most 3 of 60 files in a
> homogeneous set — i.e. indistinguishable from noise.

Consequences:

* `file`, `strings` and hex inspection of a container show nothing useful.
* Format detection **cannot** be a prefix match. It must be *try and verify*:
  attempt the decode and accept only if an integrity check passes.
* This is not a weakness in the design of a reverse engineer's tool — the AEAD
  tag is a cryptographic oracle (false-positive rate 2⁻¹²⁸), which is far
  stronger than any magic number would be.

## 3. Layer stack (modern container)

Outside → in:

```
┌──────────────────────────────────────────────────────────────┐
│ file bytes F[0..n-1]                                          │
├──────────────────────────────────────────────────────────────┤
│ Layer A   : byte reversal + positional XOR   (§4)             │
├──────────────────────────────────────────────────────────────┤
│ AEAD      : Crypto++ EAX over Twofish         (§5)            │
│           : ciphertext || 16-byte tag                          │
├──────────────────────────────────────────────────────────────┤
│ Layer B   : XOR (len - i)            Util::deobfuscateBytes   │
├──────────────────────────────────────────────────────────────┤
│ qCompress : 4-byte big-endian length + zlib   (§6)            │
├──────────────────────────────────────────────────────────────┤
│ UTF-8 XML "<PACKETTRACER5>…</PACKETTRACER5>"                  │
└──────────────────────────────────────────────────────────────┘
```

## 4. Layer A — outer scramble

For a buffer of length `n`, file bytes `F` map to AEAD input `C` as:

```
C[i] = F[n - 1 - i] ^ ((n * (1 - i)) & 0xFF)
```

The inverse (AEAD output → file bytes), used when writing:

```
F[j] = C[n - 1 - j] ^ ((n * (1 - (n - 1 - j))) & 0xFF)
```

Notes:

* It is a **full byte reversal** combined with a position-dependent XOR. Because
  `i` runs forward while the byte index runs backward, the first output byte is
  derived from the *last* input byte — there is no constant prefix.
* The XOR operand is `(n * (1 - i)) & 0xFF`, where `n` is the **whole buffer
  length** (ciphertext *and* tag). Getting `n` wrong corrupts everything.
* Both directions are length-preserving.

Implementation: `pkt_core.crypto.stream.layer_a` / `layer_a_inverse`.

## 5. The AEAD — Crypto++ EAX over Twofish

### 5.1 Cipher and key

| Parameter | Value |
| --- | --- |
| Block cipher | Twofish, 128-bit block |
| Key | 16 bytes, `0x89` repeated ×16 |
| IV | 16 bytes, `0x10` repeated ×16 |
| Tag | 16 bytes, **appended after** the ciphertext |

For other container flavours the cipher and the two repeated bytes change; see
§7.

### 5.2 EAX construction (Crypto++ variant)

Crypto++'s EAX differs from the textbook presentation in its nonce handling, and
the difference is load-bearing:

```
N          = CMAC_K( 0^128 || IV )              # nonce: zero block THEN the IV
keystream_i= E_K( N + i )                       # CTR, big-endian full 128-bit counter
ciphertext = plaintext XOR keystream
tag        = N ^ CMAC_K( 0x02-block || ciphertext ) ^ CMAC_K( 0x01-block )
```

where `0x0N-block` denotes the 16-byte block `00…00 || N` — fifteen zero bytes
followed by the small integer as the **last** byte.

* `N = CMAC_K(0^128 || IV)`, **not** `CMAC_K(IV)`.
* The CTR counter is a **big-endian 128-bit integer** starting at `N`, incremented
  by one per block. It is not a little-endian byte counter.
* CMAC is RFC 4493 / NIST SP 800-38B, with the standard `k1`/`k2` sub-key
  doubling and the `0x87` reduction polynomial.

Implementation: `pkt_core.crypto.primitives` (`cmac`, `ctr_crypt`, `eax_seal`,
`eax_open`).

### 5.3 Determinism

Because the key and IV are fixed per format:

* `N` is constant for a given format, so the **keystream is file-independent**.
* Identical plaintext always produces identical ciphertext and tag.
* Re-encoding the same XML yields byte-identical files.
* The tag can be used as a **format oracle**: a candidate `(cipher, key, IV)`
  either authenticates or it does not.

This last property is what makes verifier-based format detection cheap and
conclusive.

## 6. Layer B and qCompress

### 6.1 Layer B — `Util::deobfuscateBytes`

The AEAD plaintext `P` of length `m` is post-processed:

```
P[i] ^= (m - i) & 0xFF
```

This transform is an **involution** — the same call both encrypts and decrypts.

Implementation: `pkt_core.crypto.stream.layer_b`.

### 6.2 Qt `qCompress`

The result is Qt's `QByteArray::qCompress` framing:

```
+---------------------------+------------------------+
| uint32 big-endian length  | zlib stream            |
| (uncompressed size)       | (RFC 1950, e.g. 78 9c) |
+---------------------------+------------------------+
```

The declared length is the **uncompressed** size and is verified against the
actual inflated size, exactly as Qt's `qUncompress` does. This is a cheap
corruption check and a byte-fidelity requirement.

Implementation: `pkt_core.codec.qcompress`.

## 7. Per-format key table

Every flavour uses a 16-byte key of one repeated byte and a 16-byte IV of one
repeated byte. Recovered from the `Util::encrypt*` / `decrypt*` thunks:

| Utility function | Cipher | Key byte | IV byte | Used for |
| --- | --- | --- | --- | --- |
| `Util::encryptPTSave` / `decryptPTSave` | Twofish | `0x89` | `0x10` | `.pkt`, `.pka` |
| `Util::encryptLog` / `decryptLog` | Twofish | `0xBA` | `0xBE` | internal logs |
| `Util::encryptPKCSave` / `decryptPKCSave` | Serpent-128 | `0xAB` | `0x23` | PKC saves |
| `Util::encryptPta` / `decryptPta` | Serpent-128 | `0xAB` | `0xCD` | `.pta` |
| `Util::encryptSM` / `decryptSM` | CAST-256 | `0x12` | `0xFE` | saved simulations |
| `Util::encryptUserApp` / `decryptUserApp` | CAST-256 | `0xF1` | `0x1F` | user apps |

A separate, unrelated scheme exists for AES + HMAC-SHA256
(`Util::encrypt_aes` / `decrypt_aes`, PBKDF2 2500 iterations, 8-byte salt) and a
static salt `J19FIAftPZf7c3` (`Util::getType9StaticSalt`). These serve the
AES/user-app paths, not the plain `.pkt` container.

## 8. Algorithmic summary (reference pseudocode)

```python
# ---- decode ----
C = layer_a(F)                                   # reverse + positional XOR
P, computed, stored = eax_open(cipher, key, iv, C)
assert computed == stored                        # format oracle
payload = layer_b(P)                             # XOR (m - i)
n_declared = be_u32(payload[0:4])
xml = zlib.decompress(payload[4:])
assert len(xml) == n_declared

# ---- encode ----
payload = be_u32(len(xml)) + zlib.compress(xml)
P = layer_b(payload)                             # involution
sealed = eax_seal(cipher, key, iv, P)            # ct || tag
F = layer_a_inverse(sealed)
```

## 9. Verification

Three independent invariants, all confirmed on real files:

1. `decode(encode(xml)) == xml` — round-trip through the container.
2. `encode(decode(f)) == f` **byte-for-byte** — for real `.pkt` and `.pka` files.
3. The AEAD tag verifies on every genuine file and rejects any byte-level
   corruption.

Caveat on zlib: zlib's compressed stream is not guaranteed bit-stable across
builds/versions. Container byte-fidelity is therefore established on real files
(which retain their original compressed stream) and by comparing inflated
content; a re-encode from scratch may legitimately differ in the zlib bytes while
remaining a valid container holding identical XML.

## 10. Family L — legacy container (PT 4.1 – 5.3.2)

Everything written before **PT 5.3.3** uses a **strictly simpler** container:
no AEAD, and no byte reversal. The whole transform is layer B over a qCompress
payload. The switchover is exactly 5.3.2 → 5.3.3 (zero version overlap between
families).

```
file bytes F
  |  layer B : P[i] ^= (n - i) & 0xFF        Util::deobfuscateBytes
  v
Qt qCompress : 4-byte BE length + zlib
  |
  v
UTF-8 XML
```

| Parameter | Family L | Family M |
| --- | --- | --- |
| Byte reversal (layer A) | **no** | yes |
| AEAD + tag | **no** | yes (Crypto++ EAX) |
| Positional XOR (layer B) | yes | yes |
| qCompress + zlib | yes | yes |
| Inner document | `PACKETTRACER5` / `PACKETTRACER5_ACTIVITY` | same |

Because `layer_b` is an involution, encode is literally the same call as decode.

**Both families lack a magic header**, so an implementation must not assume that
high-entropy prefix implies encryption. Detection order is: try the modern
flavours and accept the first whose EAX tag verifies (2^-128 false positives);
otherwise, if the bytes deobfuscate into a valid qCompress payload, classify as
Family L. "Did not authenticate" is therefore a *positive identification* of
Family L, not corruption.

Verified 193/193 decode and 193/193 byte-exact round-trip; see
[`LEGACY_FORMAT.md`](LEGACY_FORMAT.md).

## 11. Provenance

* Static: symbols `CNetworkFile::openFile`, `Util::decryptPTSave`, `Util::decrypt<T>`,
  `Util::decipher<Twofish>`, `CryptoPP::EAX_Base`, `AuthenticatedDecryptionFilter`
  in the PT 9 binary.
* Dynamic: Packet Tracer driven headless under `Xvfb` with `gdb` breakpoints
  dumping `Util::decipher<Twofish>` and `qUncompress` arguments, giving a known
  plaintext/ciphertext pair that pinned the counter and both obfuscation layers.
* Empirical: 1,059 real-world containers (865 modern + 193 legacy), 40 upstream
  sources, byte-exact round-trip in both families.

See [`FORMAT.md`](../FORMAT.md) for the original writeup and
[`ANALYSIS_PLAN.md`](ANALYSIS_PLAN.md) for the corpus analysis.
