# Corpus verification report

**Result: 1058 / 1058 containers decode and round-trip BYTE-EXACT — 100%.**

This is the acceptance evidence for the format specification. Every claim in
[`FORMAT_SPECIFICATION.md`](FORMAT_SPECIFICATION.md) and
[`LEGACY_FORMAT.md`](LEGACY_FORMAT.md) is exercised here against real files.

## 1. Headline

| Metric | Result |
| --- | --- |
| Manifest entries | 1,059 |
| Containers decoded | **1,058** |
| `encode(decode(f)) == f` **byte-for-byte** | **1,058 / 1,058 (100%)** |
| Non-container entries | 1 (`AllPkaFiles.zip`, a ZIP archive) |

> 45 of the manifest entries are carved fragments whose names end in a byte
> offset (e.g. `NA-4-9-DHCP.pka__103770`) rather than `.pkt`/`.pka`. They are
> real containers and are included here. Select corpus members by
> `decode_status` in `CORPUS_INDEX.tsv`, **not** by filename suffix.

Round-trip is through the *compressor*, not merely the involution: the decoded
XML is re-compressed with `zlib.compress`, re-wrapped and must reproduce the
original file bytes exactly.

## 2. By container family

| Family | Files | Transform |
| --- | --- | --- |
| `pkt` (modern) | **865** | layer A → Crypto++ EAX → layer B → qCompress |
| `legacy` (PT 4.1 – 5.3.2) | **193** | layer B → qCompress |

Cross-contamination controls (from `tools/legacy_probe.py`):

| Probe | Result |
| --- | --- |
| Legacy decoder accepts modern files | **0 / 865** |
| Modern decoder accepts legacy files | **0 / 193** |

The families are disjoint and neither decoder over-accepts.

## 3. Root elements — three, not two

| Root element | Count | Meaning |
| --- | --- | --- |
| `PACKETTRACER5` | 547 | network lab |
| `PACKETTRACER5_ACTIVITY` | 447 | scored activity |
| `PACKETTRACER_ACTIVITY` | 64 | scored activity, **PT 4.x document schema** (legacy only) |

`PACKETTRACER_ACTIVITY` is a third root element that only appears in the legacy
family. **Root element is not a container discriminator** — `PACKETTRACER5` and
`PACKETTRACER5_ACTIVITY` both occur in *both* families. Detection must remain
try-and-verify.

`_ACTIVITY`-suffixed roots mark scored activities and wrap the network document
in a second `<PACKETTRACER*>` element plus a `<VARIABLE_MANAGER>`; plain labs do
neither. `<VARIABLE_MANAGER>` is present in 100% of activities and 0% of labs,
in both families.

## 4. Container switchover — PT 5.3.2 → 5.3.3

The `<VERSION>` element of every document was extracted and tabulated by family.

| Family | Version range | Boundary evidence |
| --- | --- | --- |
| legacy | **4.1 → 5.3.2.0027** | highest legacy: `5.3.2.0027` (11 files) |
| modern | **5.3.3.0019 → 9.0.1.0858** | lowest modern: `5.3.3.0019` (23 files) |

**There is zero version overlap between the families.** The container is a
deterministic function of the writing Packet Tracer build, and the switchover
happened between **5.3.2 and 5.3.3** — not at PT 6.0 as earlier assumed.

### Complete `<VERSION>` histogram (865 modern + 193 legacy)

| Family | Version | Files | | Family | Version | Files |
| --- | --- | --- | --- | --- | --- | --- |
| pkt | 8.2.2.0400 | 173 | | **legacy** | **4.1** | **64** |
| pkt | 6.0.1.0011 | 142 | | **legacy** | **5.2.1.0008** | **34** |
| pkt | 8.1.1.0022 | 142 | | **legacy** | **5.3.0.0088** | **29** |
| pkt | 7.3.0.0838 | 98 | | **legacy** | **5.2.0.0068** | **27** |
| pkt | 8.0.1.0064 | 55 | | **legacy** | **5.1** | **22** |
| pkt | 8.2.1.0118 | 43 | | **legacy** | **5.3.2.0027** | **11** |
| pkt | 8.2.0.0162 | 42 | | **legacy** | **4.2** | **3** |
| pkt | **5.3.3.0019** | **23** | | **legacy** | **5.3.1.0044** | **3** |
| pkt | 6.1.0.0118 | 25 | | pkt | 9.0.0.0810 | 11 |
| pkt | 7.3.1.0362 | 18 | | pkt | 7.2.0.0226 | 10 |
| pkt | 6.1.0.0120 | 16 | | pkt | 9.0.1.0858 | 9 |
| pkt | 6.1.0.0111 | 15 | | pkt | 6.2.0.0052 | 9 |
| pkt | 7.1.1.0138 | 9 | | pkt | 8.2.2 remaining | — |
| pkt | 7.1.0.0222 | 8 | | pkt | 8.0.0.0212 | 4 |
| pkt | 6.1.1.0001 | 6 | | pkt | 6.1.0.0116 / 6.3.0.0009 / 7.0.0.0134 / 6.0.0.0045 / 7.2.1.0218 / 7.2.2.0418 | 1–2 each |

Full machine-readable histogram is reproducible with
`python3 tools/legacy_probe.py verify --index corpus/CORPUS_INDEX.tsv --dir corpus/internet`.

### Document-schema rename happened at 4.2, not 5.0

Root `PACKETTRACER*` → `PACKETTRACER5*` occurs at **PT 4.2**, not at 5.0 as the
naming would suggest. The 2011 NetAcad bundle is mostly **PT 4.1** content
(`PACKETTRACER_ACTIVITY`, documents terminated with a stray NUL), not PT 5.x.

## 5. Caveat: "well-formed XML" is the wrong acceptance criterion

Packet Tracer documents are **not always well-formed XML**, and an implementation
must not require them to be:

* Devices embed raw control bytes in `<LINE>` running-config text — e.g. the Cisco
  IOS `banner motd ^C…^C` delimiter is stored as literal `\x03`.
* PT 4.1 documents end with a trailing NUL after `</PACKETTRACER_ACTIVITY>`.

Measured: **210 of a 400-file modern sample** are non-well-formed for exactly
these reasons. The correct acceptance rule is:

> **A Packet Tracer document is one with a `PACKETTRACER*` root element that
> re-encodes byte-exactly.**

This matters for Phase 3 (object modelling): parse with a non-validating,
control-character-tolerant reader, and preserve bytes verbatim.

## 6. Reproducing

```console
$ python3 tools/legacy_probe.py verify --index corpus/CORPUS_INDEX.tsv --dir corpus/internet
$ python3 -m pytest tests/ -q
```

`tests/test_legacy.py::test_real_legacy_roundtrip_is_byte_exact` asserts
byte-exact round-trip over the fetched legacy population; the table above is the
whole-corpus run.
