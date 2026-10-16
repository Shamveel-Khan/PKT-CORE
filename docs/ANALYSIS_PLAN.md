# `pkt-core` — Analysis Plan (Phase 1 Output)

**Status:** Phase 1 complete. Corpus acquired and verified.
**Date:** 2026-10-12
**Companion artefacts:** [`CORPUS_REPORT.md`](CORPUS_REPORT.md) · [`../corpus/INTERNET_SOURCES.md`](../corpus/INTERNET_SOURCES.md) · [`../corpus/CORPUS_INDEX.tsv`](../corpus/CORPUS_INDEX.tsv)

---

## 0. Executive summary

Phase 1 set out to answer one question: *do we have enough sample material to specify
the format, and what is actually unknown?*

**We do — and the unknown is now precisely characterised.** We hold **1,026 distinct
Packet Tracer containers** spanning PT 5.x through PT 9. Of these, **833 already decode
byte-exact** through the existing verified codec, and **193 are a clean, well-sampled
legacy population** that does not. That legacy set is the entire remaining reverse-
engineering problem; everything else is engineering.

One premise in the original brief is **disproven by evidence** and is corrected in §2.

| | Count | Meaning |
| --- | --- | --- |
| Samples staged | 1,059 | 1,058 `.pkt`/`.pka` + 1 provenance zip |
| Distinct by SHA-256 | **1,026** | after cross-source dedup |
| Decodes — modern container | **865** | 508 `PACKETTRACER5`, 357 `PACKETTRACER5_ACTIVITY` |
| Fails — **legacy container** | **193** | the reverse-engineering target |
| Local CyberPatriot corpus | 18 distinct | all modern, all decode |

---

## 1. Corpus inventory

Three independent populations, so a defect in one cannot blind us:

1. **Local CyberPatriot labs** — 69 paths, 18 distinct payloads. All modern, all decode.
   Useful for the *packaging* path (`.pka` scoring trees, activity-wizard passwords).
2. **Internet harvest** — 1,026 distinct payloads across ~40 repos, English/Portuguese/Hungarian.
   The statistical backbone for the schema work and the source of the legacy set.
3. **Local storage artefacts** (`/mnt/oldpc`) — see `CORPUS_REPORT.md` §9. **Not required.**
   31 files were unreadable, but 9 are exact duplicates and ~6 are reproducible from the
   in-tree generator; the ~11 genuinely unique files are marginal. No further access needed.

Full SHA-256 manifest, sizes, entropy and header census are in
[`CORPUS_REPORT.md`](CORPUS_REPORT.md); per-file decode status in [`CORPUS_INDEX.tsv`](../corpus/CORPUS_INDEX.tsv).

---

## 2. Correction to the brief: there is no magic header

The brief anticipated "magic headers". **Evidence says otherwise**, and this materially
changes the Phase 2 approach:

> Per-offset byte-consensus over the 60-file 2011 NetAcad set shows the most common byte
> at every offset 0–31 appears in **at most 3 of 60 files** — statistically random. The
> same holds for the modern sets. **No ASCII magic exists in any of the 1,059 files.**

Consequences:

* Format detection **cannot** be a prefix match. It must be **try-and-verify**: attempt
  the decoder and accept it only when an independent integrity check passes (EAX tag,
  or a valid qCompress/zlib header after deobfuscation). This is a *feature* — the AEAD
  tag is a perfect cryptographic oracle, giving effectively zero false positives.
* The outermost layer is ciphertext-ish in **both** families, so the legacy container is
  not a trivially different "plaintext XML in a wrapper" — it is some *other* transform.

Everything downstream assumes verifier-based detection, not magic bytes.

---

## 3. Format taxonomy (evidence-backed)

### Family M — modern (PT 5.3.3 → 9.0.1) · 822 samples · **SOLVED**

```
raw bytes
  → layer A : reverse + position XOR      C[i] = F[n-1-i] ^ ((n*(1-i)) & 0xFF)
  → AEAD    : Twofish-EAX, key=0x89×16, IV=0x10×16, 16-byte tag appended
  → layer B : XOR (m-i)                   P[i] ^= (m-i)   (Util::deobfuscateBytes)
  → Qt qCompress : 4-byte BE length + zlib stream
  → UTF-8 XML
```

Verified by two independent invariants in the prior art:
`decode(encode(x)) == x` and `encode(decode(f)) == f` **byte-for-byte** on real files.

**Root element discriminates the file kind — same container, different document:**

| Root tag | Count | Meaning |
| --- | --- | --- |
| `PACKETTRACER5` | 508 | ordinary `.pkt` lab (network topology) |
| `PACKETTRACER5_ACTIVITY` | 357 | scored `.pka` activity (scoring tree + wizard password) |

Earliest confirmed member is `<VERSION>5.3.3.0019`; the legacy family stops at
`5.3.3`'s predecessor `5.3.2.0027`, with **zero version overlap**. The container
switchover is therefore **5.3.2 → 5.3.3**, not 5.x → 6.0.

### Family L — legacy (PT 4.1 – 5.3.2) · 192 samples · **SOLVED**

Two independent populations, which is ideal for cross-validation:

| Population | Files | Provenance |
| --- | --- | --- |
| `bbent-cis202-PTA2011__*` | 60 | Official Cisco NetAcad PTA curriculum, IT-Essentials/CCNA-1 ch. 1–11. `AllPkaFiles.zip` last-modified 2011-08-16; the content is mostly **PT 4.1** (`<VERSION>4.1`, root `PACKETTRACER_ACTIVITY`, trailing NUL) plus some 5.1. The 60 individual links now 404; only the bundle survives. |
| `abderaoufsec/CCNA-PacketTracerlabs` (legacy subset) | 129 | Older-generation material *inside a mixed repo*: `NA-1-1…NA-4-9` series, **all 40 `NN.N.N.N 100%.pka` answer keys**, `9tut.com_*` / `Certprepare.com *` exam-sims, `NetLab 4 x VLAN/RSTP`, `CCNA Mega Lab*`, `VOIP.pka`, `IPSec-VPN.pka`, … |
| `Rakibul73/Cisco_Network_Routing_Switching__{1,2,4,8}.pka` | 4 | — |

**`abderaoufsec` is a ready-made A/B differential pair** — the same topics exist in *both*
containers in one repo. That is the single most valuable asset for the legacy work: it
holds the topic constant and varies only the container.

---

## 4. Workstreams

### WS-1 · Legacy container recovery — **Agent A (Binary Forensics)** · CRITICAL PATH

The transform is unknown, but it is **bounded**. The known key schedule for Family M
uses a 16-byte key of one repeated byte and a 16-byte IV of one repeated byte, so a
naive extension is only a 256 × 256 space per cipher. Attack order (cheapest first):

| # | Hypothesis | Test | Cost |
| --- | --- | --- | --- |
| L1 | Same AEAD, different (cipher, keyByte, ivByte) from the shipped `Util::` table (Serpent `0xab/0x23`, Serpent `0xab/0xcd`, CAST256 `0x12/0xfe`, CAST256 `0xf1/0x1f`, Twofish `0xba/0xbe`) | EAX tag verify | ~10 candidates |
| L2 | Same AEAD, any repeated-byte key/IV | EAX tag verify over 256×256 | ~65,536 / cipher |
| L3 | No AEAD — layers A+B then qCompress only | deobfuscate then check `78 9c` + BE length sanity | trivial |
| L4 | Different positional XOR / different reversal | try layer-A variants; check zlib header | low |
| L5 | Legacy block cipher (Blowfish/DES/RC4/TEA) or stream cipher with derived key | widen L2 | medium |
| L6 | Structural: is Family L even the same inner document? | after any successful decode, check for `PACKETTRACER` root | — |

**Oracle:** L1/L2 use the EAX tag as a *cryptographic* verifier — false-positive rate 2⁻¹²⁸.
L3–L5 fall back to the qCompress signature (2 bytes + BE length plausibility), ~2⁻¹⁶ per
trial, then confirmed by XML well-formedness. Two-stage verification gives certainty.

**Acceptance criteria**
- [ ] ≥1 Family L file decodes to well-formed XML.
- [ ] Decode → re-encode reproduces the input **byte-for-byte** on all 193.
- [ ] `FORMAT_SPECIFICATION.md` §Legacy filled in with the exact transform.

### WS-2 · Codec extraction & typing — **Agent A** · parallel with WS-1

Promote `packet-tracer-pkt-format/pt9.py` (314 lines, verified) into `pkt_core` with the
required module split. It is a working reference implementation, not a rewrite.

```
pkt_core/
  crypto/primitives.py   # block ciphers (Twofish/Serpent/CAST256), CMAC, EAX, CTR
  crypto/keys.py         # per-format key table (cipher, keyByte, ivByte) + derivation
  crypto/stream.py       # layer A scramble, layer B deobfuscate, positional XOR
  codec/container.py     # detect → decode → encode, verifier-based format detection
  codec/qcompress.py     # Qt qCompress framing
  xml/                   # lossless DOM layer
  models/                # Pydantic v2 object model
  cli/                   # thin, decoupled from the library
```

**Acceptance criteria**
- [ ] `mypy --strict` clean, 100 % annotated.
- [ ] Library importable with **no** CLI dependency (`import pkt_core` works standalone).
- [ ] Native C/Rust accelerator optional and behind a pure-Python fallback (portability first).

### WS-3 · Schema & object model — **Agent B (XML/AST)** · starts immediately on the 865

The 865 modern files are enough to derive the schema **today**; the legacy set will
mostly reuse it. Priority entity families:

1. Device inventory & typed chassis/module slots
2. Interface tables, MAC/IP/VLAN assignment
3. Layer-1/2 links (cable type, port, serial clocking)
4. IOS running-config blocks
5. Canvas metadata (X/Y, clustering, draw state)
6. Activity/scoring tree (`.pka` only — `PACKETTRACER5_ACTIVITY`)

**Lossless-ness rule (hard requirement):** every unknown element/attribute lands in an
`extra_fields` catch-all and is re-emitted in its original document order. Round-trip
must be **tag- and attribute-identical**, not merely semantically equivalent.

**Acceptance criteria**
- [ ] `parse(f).to_xml() == raw_xml(f)` byte-identical across all 865 modern files.
- [ ] Zero silently dropped nodes; unknown-tag corpus recorded and covered by tests.

### WS-4 · QA, fuzzing, regression — **Agent C** · gates every merge

| Gate | Assertion |
| --- | --- |
| Round-trip XML | `parse(f).to_xml() == raw_xml(f)` for every corpus file |
| Round-trip binary | `repack(parse(f)) == f` byte-for-byte |
| Format detection | every corpus file classifies correctly, no false positives |
| Fuzz | truncated headers, flipped ciphertext, bad padding, wrong-length tags → typed exceptions, **never** a crash/segfault |
| Coverage | `codec` + `models` ≥ 90 % |

Regression harness is parametrised over `CORPUS_INDEX.tsv`, so the whole 1,026-file
corpus is the test matrix.

### WS-5 · CLI & export — **Agent D** · after WS-2/WS-3 stabilise

`pkt unpack | pack | diff | export` as specified in the brief, implemented **only** as a
thin consumer of the public library API. `export` targets netbox / graphviz / containerlab.

---

## 5. Execution order

| Phase | Gate | Exit condition |
| --- | --- | --- |
| **1. Ingestion** | ✅ **DONE** | 1,026 distinct samples, hashed, classified; `CORPUS_REPORT.md` published |
| **2a. Legacy RE** | WS-1 L1→L6 | ≥1 legacy file decodes and round-trips |
| **2b. Codec typing** | WS-2 | `mypy --strict` clean, 865/865 modern decode |
| **3. Schema** | WS-3 | XML→Model→XML byte-identical on 865 |
| **4. Pack/unpack** | WS-2+WS-4 | binary round-trip byte-identical on all decodable files |
| **5. Docs, CLI, packaging** | WS-5 | `FORMAT_SPECIFICATION.md` complete, CLI works, `pytest` exit 0 |

2a and 2b are independent and run in parallel. 2a is the critical path; 2b/3 can reach
production quality on the modern family without it.

---

## 6. Risks

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| Legacy container is not a simple key/cipher variant (L1–L5 all fail) | Medium | The 60-file 2011 NetAcad set is homogeneous; solving one solves all. Fall back to PT 5.x binary RE — `Util::decrypt*` symbol names are documented in `FORMAT.md` for PT 9, and PT 5.x binaries are obtainable from archive.org. |
| Unknown-tag corpus explodes `extra_fields` and defeats typed modelling | Medium | Measure tag-frequency across 865 first; model the head, catch-all the tail. |
| Byte-exact re-serialisation is defeated by Qt DOM attribute ordering | Medium | Round-trip gate is binary-exact, so this is caught in Phase 4, not Phase 5. Prior art already achieves it for Family M. |
| `.pka` scoring tree is large and under-documented | Low | 357 `PACKETTRACER5_ACTIVITY` samples; in-tree `tools/scoring.py` and `docs/ACTIVITY.md` already describe it. |

## 7. Explicitly out of scope / not blocking

* `/mnt/oldpc` recovery — assessed, low value (see `CORPUS_REPORT.md` §9). **Not needed.**
* `icc2026.zip` — password forgotten; dropped by request.
* Full PT 5.x *application* reverse engineering — only needed if WS-1 L1–L5 fail.

## 8. Open questions for you

1. **Priority:** should 2a (legacy RE) drive, or should we first land a polished,
   type-safe modern-only `pkt-core` (2b+3) and treat legacy as a follow-on?
2. **Scope of `models`:** fully typed for every known entity (large), or typed for
   device/link/interface/config with `extra_fields` below that?
3. **Rust:** is `pkt-core` a Python library with an optional Rust accelerator, or a
   genuine dual-language deliverable? This changes Phase 4 substantially.
