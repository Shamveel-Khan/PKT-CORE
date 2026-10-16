# Packet Tracer *legacy* `.pkt` / `.pka` container format

**Status: SOLVED.** The legacy container is recovered and verified **byte-exact on all
193 staged samples** (`roundtrip_ok / 193`). The transform is simpler than the modern
one: it is exactly the modern pipeline with the outer scramble and the AEAD seal
*removed*.

Companion artefacts:
[`tools/legacy_probe.py`](../tools/legacy_probe.py) ·
modern format: [`packet-tracer-pkt-format/FORMAT.md`](../packet-tracer-pkt-format/FORMAT.md) ·
modern codec: [`packet-tracer-pkt-format/pt9.py`](../packet-tracer-pkt-format/pt9.py)

Covered here: the 193 real sample files in
[`corpus/internet/`](../corpus/internet/) whose `decode_status` in
[`corpus/CORPUS_INDEX.tsv`](../corpus/CORPUS_INDEX.tsv) is **not** `OK` — i.e. every
file that `pt9.py` rejects with `EAX tag mismatch`. (A 194th non-`OK` row,
`bbent-cis202__AllPkaFiles.zip`, is a provenance ZIP archive, not a container; it
begins `50 4b 03 04` and is out of scope.)

---

## 1. High level

A legacy `.pkt`/`.pka` file is, from the outside in:

```
  ┌─────────────────────────────────────────────────────────────┐
  │ Util::deobfuscateBytes : XOR with (len - i)                 │   "deobfuscate"
  ├─────────────────────────────────────────────────────────────┤
  │ qCompress framing : 4 byte big-endian length + zlib stream  │   Qt
  ├─────────────────────────────────────────────────────────────┤
  │ UTF-8 XML  "<PACKETTRACER_ACTIVITY>…</PACKETTRACER_ACTIVITY>"│
  └─────────────────────────────────────────────────────────────┘
```

Compare with the modern container (PT 5.3.3 → 9):

```
  ┌─────────────────────────────────────────────────────────────┐
  │ layer A : byte reversal + position dependent XOR        ◄── ABSENT in legacy
  ├─────────────────────────────────────────────────────────────┤
  │ EAX(block cipher) : authenticated encryption + 16 B tag ◄── ABSENT in legacy
  ├─────────────────────────────────────────────────────────────┤
  │ layer B : XOR with (len - i)     (Util::deobfuscateBytes)   │   identical
  ├─────────────────────────────────────────────────────────────┤
  │ qCompress framing : 4 byte big-endian length + zlib stream  │   identical
  ├─────────────────────────────────────────────────────────────┤
  │ UTF-8 XML                                                     │
  └─────────────────────────────────────────────────────────────┘
```

**The legacy container is `Util::deobfuscateBytes(qCompress(xml))`.**  Nothing else.
There is no cipher, no key, no IV, no tag and no byte reversal.  The inner
`qCompress` framing and `Util::deobfuscateBytes` are *shared* with the modern
container — those two layers never changed.

As with the modern family there is **no magic header**: the first bytes of a legacy
file are `qCompress` bytes XORed with a position-dependent mask, i.e. statistically
random.  Detection must therefore be **verifier-based**, never a prefix match.

---

## 2. The transform

### 2.1 Pseudocode

```python
BLOCK = 16   # unused -- there is no block cipher in this format

def deobfuscate(buf):                 # Util::deobfuscateBytes -- an INVOLUTION
    n = len(buf)
    return bytes(buf[i] ^ ((n - i) & 0xFF) for i in range(n))

obfuscate = deobfuscate               # same function re-applies it

def quncompress(payload):             # Qt qUncompress
    length = BE32(payload[0:4])
    xml    = zlib.decompress(payload[4:])
    assert length == len(xml)
    return xml

def qcompress(xml):                   # Qt qCompress  (zlib default level)
    return BE32(len(xml)) + zlib.compress(xml)

# ---- read path -------------------------------------------------
def decode(raw):
    blob = deobfuscate(raw)           # n = len(raw) = len(blob)
    xml  = quncompress(blob)
    return xml

# ---- write path ------------------------------------------------
def encode(xml):
    return obfuscate(qcompress(xml))
```

### 2.2 Formulas

For a file of length `n`, raw bytes `F[0..n-1]`, and `Q = qCompress(xml)`:

```
F[i] = Q[i] ^ ((n - i) & 0xFF)                 0 <= i < n
Q[i] = F[i] ^ ((n - i) & 0xFF)                 (self-inverse)
```

where

```
Q[0..3]  = uncompressed XML length, big-endian uint32
Q[4..]   = zlib stream  (deflate, default level; CMF/FLG typically 78 9c)
```

and `n == len(Q)`, i.e. the file length equals the qCompress payload length exactly
— **there is no framing, padding, header or trailer around the blob.**

Both directions are byte-exact:

```
encode(decode(F)) == F          for all 193/193 samples
```

### 2.3 Note on `Util::deobfuscateBytes`

The mask is exactly the same function the modern container calls `layer B`
(`pt9.py::_layer_b`), applied to a different buffer:

| Container | buffer being deobfuscated | length used in the mask |
| --- | --- | --- |
| modern | the EAX plaintext | `n - 16` (the AEAD plaintext length) |
| legacy | the whole file | `n` (the file length) |

This is consistent: `Util::deobfuscateBytes(QByteArray &)` XORs byte `i` with
`(len - i) & 0xff` using the length of *the buffer it is given*.  Modern hands it the
AEAD plaintext; legacy hands it the raw file.  The function is an involution, so the
same routine writes the file.

---

## 3. Verifier / detection rule

Because there is no magic prefix, a candidate buffer is accepted **only** when all
three hold:

1. `Q = deobfuscate(F)` starts with a sane 4-byte BE length `L` (`4 <= L <= 512 MiB`)
   and a valid zlib CMF/FLG pair (`CMF == 0x78`, `(CMF<<8 | FLG) % 31 == 0`);
2. `zlib.decompress(Q[4:])` succeeds and returns exactly `L` bytes;
3. `encode(xml) == F` byte-for-byte, and the result has a Packet-Tracer-shaped root
   element (`<PACKETTRACER…>`).

Conditions 1+2 alone already have a negligible false-positive rate (a 4-byte length
match plus a successful inflate to exactly that length).  Condition 3 is a full
byte-exact re-encode, which is decisive.

> **"Well-formed XML" caveat.** Packet Tracer documents are XML-*shaped*, not always
> XML-1.0-well-formed.  Router/switch running configs stored in `<LINE>` elements
> contain raw control bytes — notably `0x03`, the Cisco IOS `banner motd` delimiter,
> e.g. `<LINE>banner motd \x03wtf\x03</LINE>`.  PT 4.1 documents additionally end in a
> single trailing `0x00`.  **This is not a legacy quirk**: 210 of 400 modern files in
> the same corpus are equally "not well-formed" for the same reason.  The correct
> acceptance criterion is "Packet Tracer document with a root element", which is what
> `legacy_probe.py` uses.

---

## 4. Hypothesis ladder — pass / fail per rung

Rungs are listed as in the attack plan.  Every rung used an independent integrity
oracle; the winning rung's oracle is described in §3.

| Rung | Hypothesis | Result | Evidence |
| --- | --- | --- | --- |
| **L1** | Same layers A+B + EAX, different shipped `(cipher, keyByte, ivByte)` (Twofish `0xba/0xbe`, Serpent `0xab/0x23`, Serpent `0xab/0xcd`, CAST256 `0x12/0xfe`, `0xf1/0x1f`) | **fail** | Not applicable: rung L3 proves the file contains **no ciphertext layer at all** — `deobfuscate(F)` is *already* the qCompress framing, so there is nothing for an AEAD to decrypt. Independently, `deep_eax_sweep` confirms **0** surviving `(keyByte, ivByte)` pairs under the full 2^-128 tag oracle. |
| **L2** | Same AEAD, *any* repeated-byte key and IV (256 × 256 per cipher) | **fail** | 65,536 pairs × {Twofish, AES} × {identity layer-A, modern layer-A} = **262,144 trials, 0 EAX-tag confirmations** on a representative legacy file. (Self-test: the same sweep on a *modern* file recovers exactly `(0x89, 0x10)` as the sole tag-confirmed pair — see §5.3.) |
| **L3** | **No AEAD at all** — layers A+B then qCompress | **PASS** | More precisely: **no layer A**, `Util::deobfuscateBytes` then qCompress. `roundtrip_ok / 193`. |
| **L4** | No AEAD, different obfuscation (reversal and/or different positional XOR) | **fail / not needed** | 16 positional masks × 2 reorders × 2 operation orders were enumerated; only `(as-is, n-i)` satisfies the oracle. All other combinations fail on the zlib header / BE length. |
| **L5** | Legacy block cipher (Blowfish/DES/TEA/RC4/AES) then L3 check | **fail / not needed** | L3 already recovers the document with no cipher; a cipher layer would make the direct deobfuscation non-inflatable. |
| **L6** | Inner document differs from modern | **partly** | Root element is *not* unique to the legacy container — see §6. The document **schema generation** does differ (PT 4.x `PACKETTRACER_ACTIVITY`). |

### 4.1 Why rung L3 is not a false positive

The single most important control: `Util::deobfuscateBytes` is an involution, so
*any* buffer "decodes" to something.  What makes the hit real is that the deobfuscated
buffer

* begins `BE32(L) 78 9c` (or another legal zlib CMF/FLG),
* inflates to *exactly* `L` bytes,
* begins with `<PACKETTRACER…>` and ends with the matching close tag, and
* **re-compresses with `zlib.compress` to a byte-identical qCompress payload**, which
  re-obfuscated is byte-identical to the input file.

That last point is the strongest form of round-trip: it is not merely
`f(f(x)) == x` (which holds for any involution), it is
`encode(decode(x)) == x` **through the compressor**, which pins the *exact*
uncompressed document and the exact zlib parameters.  It holds for **193/193**.

---

## 5. Verification evidence

### 5.1 Positive proof — 193/193

```
$ python3 tools/legacy_probe.py verify --index corpus/CORPUS_INDEX.tsv --dir corpus/internet
roundtrip_ok / 193
root tags:
  PACKETTRACER5            39
  PACKETTRACER5_ACTIVITY   90
  PACKETTRACER_ACTIVITY    64
versions:
  4.1            64
  4.2            3
  5.1            22
  5.2.0.0068     27
  5.2.1.0008     34
  5.3.0.0088     29
  5.3.1.0044     3
  5.3.2.0027     11
real    0m2.077s
```

`roundtrip_ok / 193` means: every file decodes, the qCompress length header matches
the inflated size exactly, the document has a Packet Tracer root element, and
re-encoding reproduces the input **byte-for-byte**.

### 5.2 Negative controls — zero false positives in both directions

| Test | Result |
| --- | --- |
| legacy decoder applied to all **865** modern-container files | **0 accepted** |
| modern decoder (`pt9.decode_bytes`) applied to all **193** legacy files | **0 accepted** |
| root element used as a container discriminator | **invalid** — see §6 |

So the two containers are cleanly disjoint and detection is unambiguous.

### 5.3 Self-test of the L2 sweep (the oracle is calibrated)

Running the 65,536-point `(keyByte, ivByte)` sweep on a **modern** sample
(`4lban__CCENT-pkt-Labs__Basic.pkt`):

```
$ python3 tools/legacy_probe.py probe "corpus/internet/4lban__CCENT-pkt-Labs__Basic.pkt" --deep-eax
  [L2 ]       layer-A = identity (sealed = file) / twofish
                 pre-filter survivors : 1/65536 -> (0x63,0x71)
                 EAX tag confirmed   : 0 -> none
  [L2 ]       layer-A = modern scramble / twofish
                 pre-filter survivors : 3/65536 -> (0x45,0xb3), (0x89,0x10), (0xf6,0xe3)
                 EAX tag confirmed   : 1 -> (0x89,0x10)
```

The 2-byte zlib pre-filter is a *necessary* condition and leaves ~1 accidental hit per
65,536 (observed 1–4); the full 16-byte EAX tag then selects exactly one pair —
`(0x89, 0x10)`, the known modern constants.  The same machinery, applied to a legacy
file, returns **0 tag confirmations across 262,144 trials**:

```
$ python3 tools/legacy_probe.py probe "corpus/internet/bbent-cis202-PTA2011__1.7.1-Intro.pka" --deep-eax
  [L3] PASS  No AEAD: Util::deobfuscateBytes then qCompress
         root=<PACKETTRACER_ACTIVITY> version=4.1
  [L2 ]       layer-A = identity (sealed = file) / twofish
                 pre-filter survivors : 1/65536 -> (0x20,0x4f)
                 EAX tag confirmed   : 0 -> none
  [L2 ]       layer-A = identity (sealed = file) / aes
                 pre-filter survivors : 4/65536 -> (0x0b,0x6d), (0x2c,0x15), (0x85,0x4a), (0xcd,0x57)
                 EAX tag confirmed   : 0 -> none
  [L2 ]       layer-A = modern scramble / twofish
                 pre-filter survivors : 1/65536 -> (0x82,0x28)
                 EAX tag confirmed   : 0 -> none
  [L2 ]       layer-A = modern scramble / aes
                 pre-filter survivors : 2/65536 -> (0x02,0x9f), (0xf3,0xb4)
                 EAX tag confirmed   : 0 -> none
```

### 5.4 Worked example

```
$ python3 tools/legacy_probe.py info "corpus/internet/abderaoufsec__CCNA-PacketTracerlabs__1.5.1.2 100%.pka"
file         : …/abderaoufsec__CCNA-PacketTracerlabs__1.5.1.2 100%.pka
container    : legacy (pre-5.3.3, no AEAD)
root tag     : PACKETTRACER5_ACTIVITY
<VERSION>    : 5.2.1.0008
xml bytes    : 1411551
trailing NUL : False
round-trip   : OK
```

Decoded head of `bbent-cis202-PTA2011__1.7.1-Intro.pka` (PT 4.1, 51,234 bytes in →
730,496 bytes of XML out, a 14× expansion):

```xml
<PACKETTRACER_ACTIVITY>
 <VERSION>4.1</VERSION>
<PACKETTRACER>
 <VERSION>4.1</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE>
    <ENGINE>
     <TYPE model="1841" >Router</TYPE>
     <NAME translate="true" >R1-ISP</NAME>
     <POWER>true</POWER>
```

and its tail, showing the PT 4.1 trailing NUL:

```
…</VARIABLE_MANAGER>\n</PACKETTRACER_ACTIVITY>\n\x00
```

---

## 6. Inner document taxonomy

### 6.1 Root element — **not** a container discriminator

| Root element | Legacy container | Modern container |
| --- | --- | --- |
| `PACKETTRACER_ACTIVITY` | 64 | 0 |
| `PACKETTRACER5_ACTIVITY` | **90** | **214** |
| `PACKETTRACER5` | **39** | **505** |

`PACKETTRACER5` and `PACKETTRACER5_ACTIVITY` appear in **both** containers.  The
root element tells you the *document kind* (`.pkt` lab vs scored `.pka` activity) and
the *schema generation*; it does **not** tell you which container holds it.  This
independently confirms the Phase-1 conclusion that detection must be verifier-based.

### 6.2 Document generations observed inside the legacy container

| `<VERSION>` | Root | n | trailing NUL |
| --- | --- | --- | --- |
| 4.1 | `PACKETTRACER_ACTIVITY` | 64 | **yes** |
| 4.2 | `PACKETTRACER5` / `PACKETTRACER5_ACTIVITY` | 3 | no |
| 5.1 | `PACKETTRACER5` / `PACKETTRACER5_ACTIVITY` | 22 | no |
| 5.2.0.0068 | `PACKETTRACER5` / `PACKETTRACER5_ACTIVITY` | 27 | no |
| 5.2.1.0008 | `PACKETTRACER5_ACTIVITY` | 34 | no |
| 5.3.0.0088 | `PACKETTRACER5` / `PACKETTRACER5_ACTIVITY` | 29 | no |
| 5.3.1.0044 | `PACKETTRACER5_ACTIVITY` | 3 | no |
| 5.3.2.0027 | `PACKETTRACER5` / `PACKETTRACER5_ACTIVITY` | 11 | no |

Two independent structural rules fall out of the element skeleton:

1. **The root rename `PACKETTRACER*` → `PACKETTRACER5*` happens at 4.2, not at 5.0.**
   All 64 PT 4.1 documents use `PACKETTRACER_ACTIVITY`; every 4.2+ document already
   uses the `PACKETTRACER5*` names.
2. **Activity documents wrap the network document; lab documents do not.**  This is
   independent of the version and identical in the modern container:

   ```
   <PACKETTRACER_ACTIVITY>            or   <PACKETTRACER5_ACTIVITY>
    <VERSION>4.1</VERSION>                   <VERSION>5.1</VERSION>
    <PACKETTRACER>                (4.1)      <PACKETTRACER5>              (4.2+)
     <VERSION>4.1</VERSION>                  <VERSION>5.1</VERSION>
     <NETWORK>…</NETWORK>                    <NETWORK>…</NETWORK>
    </PACKETTRACER>                          </PACKETTRACER5>
    <ACTIVITY …>…</ACTIVITY>                 <ACTIVITY …>…</ACTIVITY>
    <VARIABLE_MANAGER>…</VARIABLE_MANAGER>   <VARIABLE_MANAGER>…</VARIABLE_MANAGER>
   </PACKETTRACER_ACTIVITY>                  </PACKETTRACER5_ACTIVITY>
   ```

   vs a plain `.pkt` lab:

   ```
   <PACKETTRACER5>
    <VERSION>5.3.0.0088</VERSION>
    <NETWORK>…</NETWORK>
   </PACKETTRACER5>
   ```

   `<VARIABLE_MANAGER>` is present in **100% of `*_ACTIVITY` documents and 0% of
   `PACKETTRACER5` documents**, in both containers — a reliable activity/lab marker.

The trailing `0x00` is perfectly correlated with `PACKETTRACER_ACTIVITY` / 4.1 in this
corpus (64/64), though with only one schema generation represented this is an
observation, not a proven rule.

### 6.3 Container generation boundary — 5.3.2 / 5.3.3

This is the sharpest structural result.  Sorting every file by its embedded
`<VERSION>`:

| `<VERSION>` | container | n |
| --- | --- | --- |
| 4.1 | legacy | 64 |
| 4.2 | legacy | 3 |
| 5.1 | legacy | 22 |
| 5.2.0.0068 | legacy | 27 |
| 5.2.1.0008 | legacy | 34 |
| 5.3.0.0088 | legacy | 29 |
| 5.3.1.0044 | legacy | 3 |
| **5.3.2.0027** | **legacy** | 11 |
| **5.3.3.0019** | **modern** | 23 |
| 6.0.0.0045 … 9.0.1.0858 | modern | 842 |

**Zero version overlap.**  The container is a deterministic function of the Packet
Tracer build that wrote the file.  The AEAD + scramble wrapper was introduced in
**PT 5.3.3**, not PT 6.0 as previously assumed; the earliest modern-container sample
in the corpus is 5.3.3.0019 and the newest legacy-container sample is 5.3.2.0027.
(`docs/ANALYSIS_PLAN.md` §3 stated "the modern container already existed at PT 6.0";
that is now refined to 5.3.3.)

---

## 7. Differences between the two legacy populations

The two populations are **not** different sub-generations of the container — the
container transform is identical and byte-exact across all 193.  They differ only in
which *document* generations they carry.

### 7.1 `bbent-cis202-PTA2011__*` — 60 files (Cisco NetAcad PTA, ZIP dated 2011-08-16)

| | |
| --- | --- |
| container | legacy (identical transform) |
| document versions | **4.1 × 54**, 5.1 × 6 |
| root elements | `PACKETTRACER_ACTIVITY` × 54, `PACKETTRACER5_ACTIVITY` × 6 |
| trailing NUL | yes on all 54 of the 4.1 files |
| expansion ratio | ~14× (51 KB → 730 KB) |

This set is *older than its packaging date suggests*.  The 2011 ZIP contains
predominantly PT **4.1** curriculum material; only 6 of the 60 have been re-saved
under PT 5.1.  So the "2011 = PT 5.x" assumption in the planning doc is wrong: the
bundle is largely PT 4.1-era content shipped in 2011.

### 7.2 `abderaoufsec__CCNA-PacketTracerlabs__*` legacy subset — 129 files

| | |
| --- | --- |
| container | legacy (identical transform) |
| document versions | 4.1 × 10, 4.2 × 3, 5.1 × 12, 5.2.0.0068 × 27, 5.2.1.0008 × 34, 5.3.0.0088 × 29, 5.3.1.0044 × 3, **5.3.2.0027 × 11** |
| root elements | `PACKETTRACER5_ACTIVITY` × 80, `PACKETTRACER5` × 39, `PACKETTRACER_ACTIVITY` × 10 |
| trailing NUL | only on the 10 `PACKETTRACER_ACTIVITY` (4.1) files |

This population spans **the whole legacy container lifetime** (4.1 → 5.3.2) and is
therefore the more informative one.

### 7.3 The A/B differential inside `abderaoufsec` — a clean version cut

The same repository contributes **224 modern-container** files alongside the 129
legacy ones.  Splitting by container:

| | n | `<VERSION>` range |
| --- | --- | --- |
| legacy container | 129 | 4.1 … **5.3.2.0027** |
| modern container | 224 | **5.3.3.0019** … 9.0.1.0858 (218 of 224 are 5.3.3–6.1.1; one straggler re-saved under 9.0.1) |

The two sets are **disjoint in version** and interleaved through the same exercise
numbering.  Concrete pair, both `.pka`, both scored activities, both root
`PACKETTRACER5_ACTIVITY`, both from the same author's `NA-…` / `1.x.y.z` series:

| file | container | `<VERSION>` |
| --- | --- | --- |
| `1.2.1.7 Packet Tracer - Comparing 2960 and 3560 Switches.pka` | **modern** | 6.0.1.0011 |
| `1.5.1.2 100%.pka` | **legacy** | 5.2.1.0008 |

Note the direction: the *lower* exercise number is the *newer* container.  Filename,
topic and extension therefore carry no information about the container; only the
embedded `<VERSION>` does.  Same authors, same topic series, same naming conventions —
only the writing Packet Tracer build differs.  This is exactly why the corpus pair was
so useful: holding everything else constant isolates the container as a pure function
of `<VERSION>`.

### 7.4 `Rakibul73__Cisco_Network_Routing_Switching__{1,2,4,8}.pka` — 4 files

All PT **5.1**, root `PACKETTRACER5_ACTIVITY`, no trailing NUL.  Unremarkable; they
sit mid-range in the legacy population.

---

## 8. Implementation

[`tools/legacy_probe.py`](../tools/legacy_probe.py) is self-contained and typed.

| Symbol | Purpose |
| --- | --- |
| `deobfuscate_bytes` / `obfuscate_bytes` | `Util::deobfuscateBytes`, the involution `^ (len - i)` |
| `quncompress` / `qcompress` | Qt qCompress framing (4-byte BE length + zlib) |
| `decode_bytes` / `decode` / `encode_bytes` / `encode` | container read / write |
| `LegacyDocument` | `xml`, `blob`, `root_tag`, `version`, `trailing_nul`, `is_activity` |
| `roundtrip_ok` | byte-exact `encode(decode(f)) == f` |
| `probe_hypotheses` | runs the L1–L6 ladder and reports pass/fail per rung |
| `eax_tag_ok`, `deep_eax_sweep`, `modern_layer_a` | the L2 negative control + self-test |
| `verify` (CLI) | proves `roundtrip_ok / 193` over `CORPUS_INDEX.tsv` |

CLI:

```
python3 tools/legacy_probe.py decode FILE [-o OUT.xml]
python3 tools/legacy_probe.py info   FILE
python3 tools/legacy_probe.py encode FILE.xml -o OUT.pkt
python3 tools/legacy_probe.py probe  FILE [--deep-eax]
python3 tools/legacy_probe.py verify --index corpus/CORPUS_INDEX.tsv --dir corpus/internet
```

It deliberately does **not** import `pt9.py`; the shared primitives
(`deobfuscateBytes`, `qCompress`) are reimplemented so the module can be lifted into
`pkt_core` independently.  The one dependency beyond the standard library is
`libgcrypt.so.20`, used only by the optional `--deep-eax` negative control.

---

## 9. Residual unknowns

These do not affect decode/encode correctness, which is byte-exact:

1. **Trailing NUL rule.** Perfectly correlated with PT 4.1 / `PACKETTRACER_ACTIVITY`
   in this corpus (64/64), but only one schema generation is represented, so it is
   not established as a general rule.  A 4.0-era sample would settle it.
2. **Whether any PT build writes the legacy container with a non-default zlib
   level.**  All 193 samples recompress at `zlib.compress(xml, -1)` to byte-identical
   output, so no sample exercises another level.
3. **PT 4.0 and earlier.**  The oldest document present is 4.1.  Whether a 3.x/4.0
   container exists with a further-removed transform is untested.
4. **`.pks` / `.pkt` variants and the other `Util::` cipher table entries** (log,
   PKC, PTA, simulation, user-app).  Those are separate formats, not this container,
   and remain out of scope here.
