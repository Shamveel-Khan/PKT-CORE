# `<POWER>` investigation — why generated devices load powered off

**Scope:** `pkt-core` toolkit (`tools/lab_api.py`, `tools/device_templates.json`) and the
JASDF-AEWC enterprise generator (`JASDF_AEWC_source.zip` → `build_jasdf_aewc.py`).
Investigation only; no code was changed.

**TL;DR:** `lab_api.add_device(..., power=True)` never writes `<POWER>true</POWER>` — it only
ever writes `<POWER>false</POWER>` when `power=False` — so every device inherits whatever the
harvested model template in `tools/device_templates.json` happens to contain. 136 of the 137
templates ship `true`, but **one (`MultiLayerSwitch` / `3650-24PS`) ships `<POWER>false</POWER>`**
(a harvest artefact: the source save had that switch switched off). All 10 `3650-24PS` instances
in the enterprise model are the backbone / regional-hub / datalink-aggregation / DC-core
switches, so they load **off**, and with them 76 of 326 links (23 %) — which is why the lab looks
dead at the aggregation layer even though 280 of 290 devices carry `POWER=true`. Nothing in the
generator has a device-level power pass; the only fix on record (`power_cabled_ports()`) is
*port*-level and cannot touch `<ENGINE><POWER>`.

---

## 1. Measurement

Method: `pkt_core.decode()` on each `.pkt`, then walk `NETWORK/DEVICES/DEVICE/ENGINE` and read
`<TYPE kind model>`, and `<POWER>` as `ABSENT` / `true` / `false`. The decoded files are
byte-identical (sha256 `f34018be…` / `400fe203…`) to the generator's `out/*.pkt`, so this is
exactly what Packet Tracer loads.

### 1.1 `JASDF_AEWC_JADGE.pkt` (enterprise profile) — 290 devices

| `<ENGINE><POWER>` | devices | share |
|---|---:|---:|
| `true`  | **280** | 96.6 % |
| `false` | **10**  | 3.4 % |
| absent  | **0**   | 0 % |
| **total** | **290** | |

Cross-tab by device kind:

| kind | `true` | `false` | absent | total |
|---|---:|---:|---:|---:|
| ASA | 4 | 0 | 0 | 4 |
| AccessPoint | 26 | 0 | 0 | 26 |
| CyberObserver | 1 | 0 | 0 | 1 |
| MultiLayerSwitch | 31 | **10** | 0 | 41 |
| Pc | 55 | 0 | 0 | 55 |
| Router | 67 | 0 | 0 | 67 |
| Server | 64 | 0 | 0 | 64 |
| Sniffer | 1 | 0 | 0 | 1 |
| Switch | 31 | 0 | 0 | 31 |

Cross-tab by (kind, model) — only the differing row shown in full; every other model is 100 % `true`:

| kind | model | `true` | `false` | total |
|---|---|---:|---:|---:|
| MultiLayerSwitch | **3650-24PS** | 0 | **10** | 10 |
| MultiLayerSwitch | 3560-24PS | 15 | 0 | 15 |
| MultiLayerSwitch | IE-9320 | 16 | 0 | 16 |
| ASA | 5505 | 4 | 0 | 4 |
| AccessPoint | AccessPoint-PT | 26 | 0 | 26 |
| Pc | PC-PT | 55 | 0 | 55 |
| Router | 2911 | 26 | 0 | 26 |
| Router | IR1101 | 16 | 0 | 16 |
| Router | ISR4321 | 10 | 0 | 10 |
| Router | ISR4331 | 15 | 0 | 15 |
| Server | Server-PT | 64 | 0 | 64 |
| Switch | 2960-24TT | 31 | 0 | 31 |
| CyberObserver | CyberObserver | 1 | 0 | 1 |
| Sniffer | Sniffer | 1 | 0 | 1 |

The 10 unpowered devices (identical list in both files):

```
JADGE-BB-SW-01, JADGE-BB-SW-02            (backbone switches)
REG-HUB-NORTH, REG-HUB-CENTRAL,
REG-HUB-WEST, REG-HUB-SW                  (regional hubs)
DATALINK-AGG-01, DATALINK-AGG-02          (datalink aggregation)
JADGE-DC-CORE-01, JADGE-DC-CORE-02        (data-centre core)
```

### 1.2 `JASDF_AEWC_JADGE_standard.pkt` — 199 devices

| `<ENGINE><POWER>` | devices | share |
|---|---:|---:|
| `true`  | **189** | 95.0 % |
| `false` | **10**  | 5.0 % |
| absent  | **0**   | 0 % |

| kind | `true` | `false` | total |
|---|---:|---:|---:|
| ASA | 4 | 0 | 4 |
| AccessPoint | 6 | 0 | 6 |
| CyberObserver | 1 | 0 | 1 |
| MultiLayerSwitch | 21 | **10** | 31 |
| Pc | 38 | 0 | 38 |
| Router | 49 | 0 | 49 |
| Server | 50 | 0 | 50 |
| Sniffer | 1 | 0 | 1 |
| Switch | 19 | 0 | 19 |

Same 10 `3650-24PS` devices are `false`; all other models (`3560-24PS`, `IE-9320`, `2960-24TT`,
`2911`, `IR1101`, `ISR4321`, `ISR4331`, `PC-PT`, `Server-PT`, `AccessPoint-PT`, `5505`, …) are
100 % `true`.

### 1.3 Why this *looks* like "most of the lab is off"

The 10 unpowered switches are not random leaf devices — they **are** the aggregation layer:

| impact (enterprise) | value |
|---|---:|
| links touching a `POWER=false` device | **76 / 326 (23.3 %)** |
| devices directly adjacent to an off device | **62 / 290 (21.4 %)** |
| devices within 2 hops of an off device | **134 / 290 (46.2 %)** |
| link degree of the off devices | BB-SW-01: 9, BB-SW-02: 11, REG-HUB-NORTH: 13, REG-HUB-CENTRAL: 11, REG-HUB-WEST: 9, REG-HUB-SW: 9, DATALINK-AGG-01: 10, DATALINK-AGG-02: 10, DC-CORE-01: 3, DC-CORE-02: 2 |

So the accurate statement is: **the residual bug hits 10 of 290 devices (3.4 %) at the
`<ENGINE><POWER>` level, but those 10 are precisely the core/aggregation switches, so 23 % of all
links come up dark and nearly half the topology sits within two hops of an unpowered box** — that
is the "dark icons / no link lights everywhere" impression. (Every other device is on; the amber
link lights on access ports in the first ~30 s are documented STP convergence behaviour, see
`JASDF_AEWC_VALIDATION.md`.)

Port-level state is already repaired in these files: all 2 454 ports in the enterprise model carry
`<PORT><POWER>true</POWER>` (MultiLayerSwitch 1 118, Switch 806, Router 323, Server 64, Pc 55,
AccessPoint 52, ASA 32, CyberObserver 2, Sniffer 2) — that is `JASDF.power_cabled_ports()` at work
(178 ports raised in the enterprise run, 122 in standard; see `build/report_enterprise.json`).

---

## 2. Root cause

**One sentence:** `lab_api.add_device()` only writes `<POWER>false</POWER>` and never writes
`true`, so device power is inherited verbatim from the harvested template — and the single
`3650-24PS` template in `tools/device_templates.json` ships `<ENGINE><POWER>false</POWER>`, which
poisons every core/aggregation switch built from it.

Chain of evidence:

1. **`tools/lab_api.py` (`add_device`, line 259; power handling at lines 293–297):**
   ```python
   if not power:
       p = eng.find("POWER")
       if p is None:
           p = ET.SubElement(eng, "POWER")
       p.text = "false"
   ```
   `power=True` (the default) writes nothing at all. The effective power state is 100 % the
   template's text. Note also the latent trap: for a template with *no* `<POWER>`, `power=True`
   still leaves the element absent — and `pkt_core.models.network.Device.powered`
   (`src/pkt_core/models/network.py:243`) reads absent as **not powered**.

2. **`tools/device_templates.json` — 137 model templates audited** (gzipped XML blocks;
   `POWER` sits at child index 2 of `<ENGINE>`, right after `<TYPE>`/`<NAME>`):

   | template `<ENGINE><POWER>` | models |
   |---|---:|
   | `true`  | **136** |
   | `false` | **1** — `MultiLayerSwitch` / `3650-24PS` |
   | absent  | 0 |

   The `3650-24PS` block still carries the harvested instance name `Multilayer Switch0`
   (`SYS_NAME=Switch`, serial `CAT1010C93B`): it was harvested from a save in which that switch
   was switched **off**, and the harvest normalised nothing.

3. **Generator (`build_jasdf_aewc.py`):** devices are placed through `lab_api.add_device` with
   the default `power=True`, which — per (1) — leaves the template text untouched. The only
   power-related repairs are:
   * `fix_serial()` / `_set_port()` (lines ~1044–1072): *port*-level `POWER`/`CLOCKRATE` for serial
     bearers;
   * `power_cabled_ports()` (lines 1090–1105): *port*-level `<POWER>true` on ports of cabled
     devices ("Some harvested templates ship with `<POWER>false</POWER>` on their ports — notably
     AccessPoint-PT").

   There is **no** pass that touches `<ENGINE><POWER>`. The generator's own
   `docs/EVIDENCE.md`/`VALIDATION.md` "fixed in the generator" note refers only to the
   port-level variant of the same defect class; the device-level variant was never addressed.

4. **Result:** exactly the 10 `3650-24PS` instances inherit `false` — verified byte-identical in
   generator output and delivered file. Every other model happens to ship `true`, which is why
   280 devices are on: **by luck of the harvest, not by construction.**

---

## 3. Semantics: absent vs `true` vs `false`

Corpus: `../corpus/internet/`, `CORPUS_INDEX.tsv` with `decode_status == OK`.

**Clean 20-file sample** (first 20 OK files that decode to well-formed XML; 3 further OK-indexed
files fail XML parsing and were skipped): **230 devices, `<ENGINE><POWER>` = `true` for all 230,
absent 0.**

| kind | `true` | other |
|---|---:|---|
| Pc | 84 | — |
| Switch | 45 | — |
| Power Distribution Device | 20 | — |
| Router | 21 | — |
| MCUComponent | 22 | — |
| Laptop | 14 | — |
| Server | 8 | — |
| Pda | 4 | — |
| Printer | 4 | — |
| ASA / AccessPoint / Cloud / HomeGateway / Hub / WirelessRouterNewGeneration | 2 / 1 / 1 / 1 / 2 / 1 | — |

**Extended full scan of all 443 decodable OK files (5 819 devices)** for semantics:

| `<ENGINE><POWER>` | devices |
|---|---:|
| `true` | 5 813 (99.90 %) |
| `false` | **6** (0.10 %) — 4× `Laptop` in `vaamonde__ccna-v7-200-301__Projeto.pkt`, 2× `Router` in `dishavp__Network-Infrastructure-PacketTracer__HSRP.pkt` |
| absent | **0** |

Conclusions:

* **`true` = powered on.** It is the state of every working device in every hand-authored lab.
  All 28 device kinds seen in the corpus carry the element, including PCs (1 951/1 951),
  servers (339/339), MCU/IoT components (53/53), access points (103/103) and
  Power Distribution Devices (473/473). So **PCs, servers and IoT/MCU devices do have a POWER
  concept**; the "end devices have no power switch" hypothesis is false at the file level.
* **`false` = powered off** — confirmed by the 6 corpus instances (deliberately switched-off
  laptops/spare routers in authored labs) and by the project's own verified experiment
  (`docs/CAPABILITIES.md` §2: "Setting `false` powers the device off at load (verified: the
  attached link drops)").
* **absent = never produced by Packet Tracer.** 0 of 5 819 corpus devices omit the element; PT
  always writes it. An absent `<POWER>` is therefore a generator artefact with no
  author-defined meaning; the toolkit's own model (`Device.powered`) and `add_device`'s
  `power=False` path both treat it as "off", and PT's behaviour on a missing element is
  unverified — treat absent as unsupported, not as "on".

Port-level `<PORT><POWER>` is a *different* field (per-interface state used by APs, serial
bearers, link lights). Corpus distribution shows it is **normal** for unused ports to be
`false` or absent — e.g. `Router` 2 213 true / 2 576 false, `Pc` 1 951 true / 1 809 false /
1 962 absent, `Switch` 23 188 true / 345 false, `Server` 339 true / 89 absent. It must not be
blanket-set to `true` (see fix below).

---

## 4. Proposed fix

### 4.1 `tools/lab_api.py` — make `add_device` total (the real fix)

Write `<ENGINE><POWER>` explicitly from the `power` parameter in **both** directions, so a
template can never leak a stale state through:

```python
p = eng.find("POWER")
if p is None:
    p = ET.Element("POWER")
    eng.insert(eng.index(eng.find("NAME")) + 1, p)   # canonical slot: TYPE, NAME, POWER, ...
p.text = "true" if power else "false"
```

* Applies to **all device kinds** — routers, switches, APs, PCs, servers, ASA, IoT/MCU
  components: corpus evidence shows every kind carries `<ENGINE><POWER>` and `true` is the only
  state of a working device. No kind should be exempted.
* Create the element at its canonical position (child index 2, after `<NAME>`) rather than
  `ET.SubElement` at the end, to match PT-authored documents; if the element already exists
  (all 137 current templates), only the text changes.

### 4.2 `tools/device_templates.json` — clean the poisoned template

Change `<ENGINE><POWER>false</POWER>` → `true` in the `3650-24PS` block (and audit
`harvest_models()` so future harvests normalise device power to `true`, or at least record the
harvested state so a "was off in the donor save" flag cannot silently ship). This alone fixes
both delivered `.pkt` files.

### 4.3 Enterprise generator (`build_jasdf_aewc.py`)

* With 4.1 in place, `add_device(..., power=True)` is sufficient. Defence in depth: add a
  `power_all_devices()` pass next to `power_cabled_ports()` in `main()` that forces
  `<ENGINE><POWER>text="true"` on every placed device (all kinds), and keep `power=False` only
  for devices the lab *intends* to stage off (call it out explicitly, e.g. spare/standby gear).
* Keep `power_cabled_ports()` as-is for the port level: only **cabled** ports should be forced
  `true`; unused router/PC ports legitimately carry `false`/absent in the corpus.
* Add a validation assertion in `validate.py`: no device may end with
  `<ENGINE><POWER>` ∈ {`false`, absent} unless it is on an explicit "staged off" list.

### 4.4 What *not* to do

* Do not delete `<POWER>` instead of writing `true` — PT never omits it and the toolkit reads
  absence as off.
* Do not blanket-set every `<PORT><POWER>` to `true` (corpus: unused ports are normally
  `false`/absent). The existing cabled-port rule is the correct scope.
* Do not assume end devices are exempt: PCs/servers/MCU devices all carry `POWER=true` in the
  corpus.

---

## 5. Residual unknowns

* Packet Tracer behaviour for a *missing* `<ENGINE><POWER>` is unverified (no corpus instance
  exists). Recommendation above avoids the case entirely.
* The 6 corpus `false` devices were authored intentionally; no corpus file demonstrates what a
  deliberately powered-off *switch* looks like beyond the `3650-24PS` harvest artefact.
* The port-level `POWER` semantics (why unused router ports are `false` while switch ports are
  `true`) is characterised empirically only; it does not affect the device-level fix.

---

*Method notes: both `.pkt` files decoded with `pkt_core.decode()` (`src/pkt_core`), XML walked
with `xml.etree.ElementTree`; template audit decompressed the gz+base64 blocks of
`tools/device_templates.json` (137 `models` entries); corpus scans used
`../corpus/CORPUS_INDEX.tsv` `decode_status == OK` files from `../corpus/internet/`.*
