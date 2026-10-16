# Packet Tracer 9 `.pkt` / `.pka` container format

Reverse engineered from **Cisco Packet Tracer 9.0.1.0858** (Linux x86-64 build,
`opt/pt/bin/PacketTracer`, fully symbolized).  All statements below were
confirmed against the live application, not only by reading code.

## 1. High level

A `.pkt`/`.pka` file is, from the outside in:

```
  ┌─────────────────────────────────────────────────────────────┐
  │ layer A : byte reversal + position dependent XOR            │   "scramble"
  ├─────────────────────────────────────────────────────────────┤
  │ EAX(block cipher) : authenticated encryption + 16 byte tag  │   Crypto++
  ├─────────────────────────────────────────────────────────────┤
  │ layer B : XOR with (len - i)     (Util::deobfuscateBytes)   │   "deobfuscate"
  ├─────────────────────────────────────────────────────────────┤
  │ qCompress framing : 4 byte big-endian length + zlib stream  │   Qt
  ├─────────────────────────────────────────────────────────────┤
  │ UTF-8 XML  "<PACKETTRACER5>…</PACKETTRACER5>"               │
  └─────────────────────────────────────────────────────────────┘
```

The written file is the **encryption of a qCompress-compressed XML document**,
wrapped in two cheap obfuscation layers.  There is **no magic header**: the first
bytes of the file are effectively random, which is why naive `file`/`strings`
inspection shows only noise.

## 2. Read path in the binary

`CNetworkFile::openFile(QString)` (at `0x420a9e0`) reads the file and runs:

```
QFile::readAll()
  -> Util::decryptPTSave(QByteArray const&)      // EAX + layer A
  -> qUncompress(...)                            // zlib inflate
  -> QString::fromUtf8(...) -> QDomDocument::setContent(...)
```

`Util::decryptPTSave` (a 24-byte thunk at `0x3a9bb70`) is literally:

```
Util::decrypt<CryptoPP::Twofish>(data, 0x89, 0x10)
```

`Util::decrypt<Cipher>(data, keyByte, ivByte)` (template, `0x3a9d010`) does two
things:

1. builds the ciphertext by reversing the input and XORing byte `i` with
   `( (n * (1 - i)) & 0xff )` where `n = len(data)`;
2. fills a 16-byte key with `keyByte` and a 16-byte IV with `ivByte`, then calls
   `Util::decipher<Cipher>(ciphertext, key, iv)`.

`Util::decipher<Twofish>` (`0x3aa0e30`) uses Crypto++ `EAX_Final<Twofish,false>`
via `CryptoPP::AuthenticatedDecryptionFilter` with `truncatedSize = -1`
(full 16-byte tag) and `BlockPaddingScheme = NO_PADDING`.

After the AEAD step the caller applies `Util::deobfuscateBytes(QByteArray&)`
(`0x3a9bcd0`): every byte is XORed with `(len - i) & 0xff`.

## 3. Layer A — outer scramble

For a file of length `n`, the raw bytes `F[0..n-1]` map to the AEAD input
`C[0..n-1]` as:

```python
C[i] = F[n - 1 - i] ^ ( (n * (1 - i)) & 0xFF )
```

It is a full reversal plus a position-dependent XOR.  Because `i` runs forward
and the byte index runs backward, the first output byte depends on the *last*
file byte — there is no constant prefix to key off.

The inverse (ciphertext `C` → file bytes `F`), used when writing:

```python
F[j] = C[n - 1 - j] ^ ( (n * (1 - (n - 1 - j))) & 0xFF )
```

## 4. Layer B — inner deobfuscation

The AEAD plaintext `P` (length `m = n - 16`) is post-processed in place:

```python
P[i] ^= (m - i) & 0xFF          # Util::deobfuscateBytes
```

The result is the qCompress payload: a 4-byte big-endian uncompressed length
followed by a standard zlib stream (`78 9c …`).

## 5. The AEAD (Crypto++ EAX)

The block cipher is standard.  The EAX construction matches Crypto++'s
implementation, which differs from the "textbook" EAX nonce handling:

* `N = CMAC_K( 0^128 || IV )`  — the nonce is a **zero block concatenated with
  the IV**, hashed with CMAC.
* The keystream is **CTR mode** with a **big-endian, full-block counter**
  starting at `N`: `keystream_i = E(N + i)`.
* The 16-byte tag is **appended at the end** and is:

  ```
  tag = N ^ CMAC_K( 0x02-block || ciphertext )
          ^ CMAC_K( 0x01-block )
  ```

  where `0x0N-block` means the 16-byte block `00…00 || N`.

CMAC uses the block cipher itself as the PRF (RFC 4493 construction).

Encryption is the exact reverse of the above (CTR is symmetric; build the tag
the same way over the resulting ciphertext and append it).

Two independent checks confirm the model: `decode(encode(x)) == x` for XML, and
`encode(decode(f)) == f` byte-for-byte for real `.pkt` and `.pka` files.

## 6. Per format key and IV

Every container type uses a fixed 16-byte key (one byte repeated 16×) and a fixed
16-byte IV (one byte repeated 16×).  These come straight from the 24-byte thunks
around `0x3a9bb50`:

| Utility function | Cipher | key byte | IV byte | Used for |
| --- | --- | --- | --- | --- |
| `Util::encryptPTSave` / `decryptPTSave` | Twofish | `0x89` | `0x10` | `.pkt`, `.pka` |
| `Util::encryptLog` / `decryptLog` | Twofish | `0xba` | `0xbe` | internal logs |
| `Util::encryptPKCSave` / `decryptPKCSave` | Serpent | `0xab` | `0x23` | PKC saves |
| `Util::encryptPta` / `decryptPta` | Serpent | `0xab` | `0xcd` | `.pta` |
| `Util::encryptSM` / `decryptSM` | CAST256 | `0x12` | `0xfe` | saved simulations |
| `Util::encryptUserApp` / `decryptUserApp` | CAST256 | `0xf1` | `0x1f` | user apps |

A separate, unrelated scheme exists for AES+HMAC-SHA256 (PBKDF2, 2500 iterations,
8-byte salt) via `Util::encrypt_aes` / `decrypt_aes`
(`CryptoPP::DataEncryptorWithMAC<Rijndael, SHA256, HMAC<SHA256>,
DataParametersInfo<16,16,32,8,2500>>`).  There is also
`Util::getType9StaticSalt()` returning the literal ASCII salt
`J19FIAftPZf7c3` from `.data` (`0x5a14fd0`), and `Util::createRandomSalt()`.
These are used by the AES/user-app paths, not by the plain `.pkt` container.

## 7. Payload

The decrypted payload is UTF-8 XML:

* Network files begin `<!DOCTYPE …>` or `<PACKETTRACER5>` and carry
  `<VERSION>9.0.1.0858</VERSION>`.
* Activity/PKA files begin `<PACKETTRACER5_ACTIVITY>`.

The XML is ordinary Packet Tracer DOM (devices, links, scripts, options,
`PIXMAPBANK`, …) already described by the in-tree IPC API documentation
(`help/default/IpcAPI/`).

## 8. Reproducing

```console
$ python3 pt9.py info uwu.pkt
file      : uwu.pkt
format    : pkt
root tag  : PACKETTRACER5
xml bytes : 1045755
```

## 9. Evidence / how this was established

* Static: symbolicated `PacketTracer`, `nm`/`objdump` of `CNetworkFile`,
  `Util::encrypt*/decrypt*`, `cipher/decipher<Cipher>`, `CryptoPP::EAX_Base`,
  `AuthenticatedDecryptionFilter`, `DataDecryptorWithMAC`.
* Dynamic: Packet Tracer run headless under `Xvfb` and driven with `gdb`
  breakpoints that dumped the arguments/results of
  `Util::decipher<Twofish>` and `qUncompress`.  A known-plaintext pair
  (ciphertext + decompressed XML) let the CTR counter and obfuscation layers be
  solved exactly and verified byte-for-byte.

See `pt9.py` for a complete, working decoder.
