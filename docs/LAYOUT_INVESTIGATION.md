# Layout Investigation — device/label overlap in generated labs

Status: investigation only (`tools/`, `src/` untouched).
Scope: `JASDF_AEWC_JADGE.pkt` (290 devices) and `JASDF_AEWC_JADGE_standard.pkt`
(199 devices) from `filedrop/uploads/`, the generator source in
`JASDF_AEWC_source.zip`, `tools/build_large_topology.py` + `tools/lab_api.py`,
and 15 human-authored corpus files from `../corpus/internet/`
(index: `../corpus/CORPUS_INDEX.tsv`, `decode_status == OK`).

All coordinates below are `WORKSPACE/LOGICAL/{X,Y}` workspace units. Calibration
note: at Packet Tracer's default (100 %) zoom, **1 workspace unit ≈ 1 screen
pixel** — verified against `JASDF_AEWC_packet_tracer_verified.png`, where the
airframe pitch of 310 units measures exactly 310 px between icon centres.

---

## 1. Measurements of the generated labs

### 1.1 Global numbers

| Metric | `JASDF_AEWC_JADGE.pkt` (enterprise) | `..._standard.pkt` |
| --- | --- | --- |
| devices with logical coords | **290** (0 missing) | **199** (0 missing) |
| bounding box | X [60, 3700], Y [130, 5140] | X [60, 3700], Y [130, 5140] |
| span | 3640 × 5010 units | 3640 × 5010 units |
| density | 1 device / **62 914 units²** | 1 device / 91 684 units² |
| busiest 500×500 window | **23 devices** at (510, 130) — airborne block | 17 devices at (250, 1550) — CRC/server block |
| name length | min 7 / median 14 / mean 13.4 / max 23 | min 7 / median 13 / mean 13.3 / max 23 |
| exactly coincident pairs (d=0) | 0 | 0 |

### 1.2 Pair counts at centre distance (icon is ~40–60 units wide)

| threshold | JADGE (290 dev) | standard (199 dev) |
| --- | --- | --- |
| ≤ 30 | 0 | 0 |
| **≤ 40 (icon size)** | **12** | **3** |
| ≤ 50 | 14 | 5 |
| ≤ 60 | 15 | 6 |
| ≤ 80 | 21 | 9 |
| ≤ 100 (below human minimum) | 56 | 18 |
| ≤ 120 (human "comfortable" floor) | 84 | 31 |
| ≤ 150 | 171 | 87 |

Nearest-neighbour distance per device (JADGE): min 30.4, p10 58.3, median 135.0,
mean 139.6, max 403.1. **24 of 290 devices have a neighbour within 40 units**
(standard: min 30.4, p10 85.0, median 150.3 — 6 of 199 within 40).

Axis-pitch histograms show the hard-coded constants: the most common X gaps are
10 (×34), 30 (×12), 5 (×8), 20 (×8); the most common Y gaps are 180 (×6),
190 (×4), 70 (×3).

### 1.3 Worst clusters (connected components at d ≤ 40)

JADGE: **12 clusters, every one a pair** (top 10 shown; all 12 are listed since
they are all equal size):

| # | devices | coordinates | d |
| --- | --- | --- | --- |
| 1 | `TFTP-SVR` / `CRC-CENTRAL-RTR-01` (ISR4331) | (655, 1910) / (650, 1880) | 30.4 |
| 2 | `TDL-GW-03` (2911) / `NOSC-TAP-SNIFFER` (Sniffer) | (2310, 1150) / (2300, 1120) | 31.6 |
| 3 | `MISSION-WEB-SVR` / `CRC-CENTRAL-RTR-02` (ISR4331) | (830, 1910) / (840, 1880) | 31.6 |
| 4 | `E767-02-WLAN-AP` / `E767-01-WC-PC` | (510, 305) / (550, 305) | 40.0 |
| 5 | `E767-03-WLAN-AP` / `E767-02-WC-PC` | (820, 305) / (860, 305) | 40.0 |
| 6 | `E767-04-WLAN-AP` / `E767-03-WC-PC` | (1130, 305) / (1170, 305) | 40.0 |
| 7 | `E2D-01-WLAN-AP` / `E767-04-WC-PC` | (1440, 305) / (1480, 305) | 40.0 |
| 8 | `E2D-02-WLAN-AP` / `E2D-01-WC-PC` | (1750, 305) / (1790, 305) | 40.0 |
| 9 | `E2D-04-WLAN-AP` / `E2D-03-WC-PC` | (510, 575) / (550, 575) | 40.0 |
| 10 | `E2D-05-WLAN-AP` / `E2D-04-WC-PC` | (820, 575) / (860, 575) | 40.0 |
| (11) | `E2D-06-WLAN-AP` / `E2D-05-WC-PC` | (1130, 575) / (1170, 575) | 40.0 |
| (12) | `E2D-06-WC-PC` / `E2C-01-WLAN-AP` | (1480, 575) / (1440, 575) | 40.0 |

standard.pkt keeps only clusters 1–3 (the enterprise profile adds the airborne
block and the NOSC/TDL rows).

Near-overlaps at d ≤ 80 (would still visibly touch): `TDL-GW-02`/`NOSC-CYBER-OBS`
(42.4), `AAA-SVR`/`CRC-NORTH-RTR-02` (50.0), `TDL-GW-01`/`NOSC-NMS-SVR` (58.3),
`SYSLOG-SVR`/`CRC-NORTH-RTR-01` (62.6), `SATCOM-GW-01`/`NOSC-SW-01` (70.7),
`PKI-CA-SVR`/`CRC-NORTH-DSW` (72.1).

### 1.4 Icon and label collisions

Icon artwork sizes measured from `JASDF_AEWC_packet_tracer_verified.png`
(1:1 with workspace units): router cylinder ≈ 50×40, L2/L3 switch ≈ 46–50,
AccessPoint-PT ≈ 48×34, PC-PT ≈ 34×40, Server-PT tower ≈ 28×48. PT draws the
**model caption above** the icon and the **device name below** it, i.e. two text
lines per device. Label font measures ≈ 6.3 px/char
(`E767-02-WLAN-AP` = 15 chars ≈ 95 units wide).

AABB icon overlap (icons treated as squares centred on X,Y), JADGE:

| icon box | overlapping pairs |
| --- | --- |
| 40 units | 4 |
| 50 units | 16 |
| 60 units | 20 |
| 70 units | 21 |

Label collisions (label box = `6..9 px/char × len(name)`, drawn below the icon):

| char width | label↔label pairs (JADGE) | labels over another icon (JADGE) | label↔label (standard) | over icon (standard) |
| --- | --- | --- | --- | --- |
| 5 px | 9 | 29 | 0 | 10 |
| 6–7 px (measured ≈ 6.3) | 9–12 | 29–30 | 0–1 | 10 |
| 8 px | 23 | 31 | 9 | 11 |
| 9 px | 29 | 38 | 13 | 15 |

The PT screenshot confirms this visually: in the airborne row
`E767-02-WLAN-AP` and `E767-01-WC-PC` are printed on top of each other
(centres 40 units apart), as are `E767-03-WLAN-AP`/`E767-02-WC-PC` and the
next pair. Long names make it worse: `CRC-CENTRAL-DISPLAY-SVR` (23 chars ≈ 155
units wide) sits only 190 units from `CRC-CENTRAL-TRACK-SVR` (21 chars), so the
two labels nearly touch even where icons are clear. The seed/lab default name
`Power Distribution Device0` (27 chars ≈ 185 units) is the worst case in the
wider corpus.

**Bottom line:** 12 device pairs physically overlap at icon scale, 24 devices
have a neighbour inside icon distance, ~29 device labels collide with icons and
9–29 label pairs collide with each other (screenshot-verified), and 56/84 pairs
fall below the human-authored minimum/comfortable spacing (100/120).

---

## 2. Root cause

**One sentence:** there is no layout algorithm at all — every generator writes
hand-typed literals or index-derived constant-pitch formulas straight into
`lab_api.Lab.add_device(model, name, x, y)`, which blindly stores whatever
coordinates it is given, so independent section grids overlap wherever their
hard-coded origins coincide and nothing ever checks icon size, label length,
device kind, occupancy, or canvas bounds.

Details:

1. **`tools/lab_api.py` is layout-blind.** `add_device(..., x: int = 100,
   y: int = 100, ...)` (lab_api.py:259) patches the template XML's
   `<WORKSPACE><LOGICAL><X>/<Y>` with the caller's numbers (lab_api.py:277-278)
   and does nothing else. Defaults mean that *omitting* coordinates stacks every
   device at (100, 100). The only position bookkeeping is `self._pos += 6`
   (lab_api.py:270) — that is the **physical rack** slot X for
   `PHYSICALWORKSPACE`, unrelated to the logical canvas. There is no occupancy
   map, no collision test, no clamping.

2. **Coordinates are hand-assigned / index-derived, spacing is constant per
   section.** In `JASDF_AEWC_source.zip` → `build_jasdf_aewc.py`:
   - airborne block: `bx, by = 200 + ((ac-1)%6)*310, 130 + ((ac-1)//6)*270`
     (line 438); within an airframe MR at `(bx,by)`, SW/MC at `bx+175`, AP at
     `(bx, by+175)`, **WC-PC at `bx+350`** (line 456). The intra-airframe offset
     350 *exceeds* the inter-column pitch 310, so airframe *N*'s WC-PC lands 40
     units from airframe *N+1*'s WLAN-AP — clusters 4–12 above.
   - server farm: `x = 130 + (i%5)*175, y = 1650 + (i//5)*130` (line 289-290).
   - CRC block: `x = 250 + i*400` (line 348), routers at `y=1880`,
     RTR-02 at `x+190`, DSW at `x+95, 2100`, servers `y=2320`, consoles
     `x-60+j*130, 2500`.
   - NOSC row: servers at `1850/2000/2150/2300, y=1120` (lines 330-339);
     TDL gateways `2050+(i-1)*130, y=1150` (line 241). The two grids are only
     30 units apart in y and overlap in x → clusters 1–2.
   - radar sites `bx = 120 + (idx%8)*310` (line 380), airbases
     `bx = 120 + (idx%5)*430` (line 404) — the same constant-pitch pattern.
   - `tools/build_large_topology.py` is identical in spirit:
     `x = 100 + (site-1)*420 + (branch-1)*190 + (n%2)*70`,
     `y = 760 + (n//2)*130` (lines 263-264), IoT `1450+(i%2)*120, 80+(i//2)*130`
     (line 284). Client columns are 70 units apart — icons clear, labels
     (`LT-S11-1`, 8 chars ≈ 60 units) almost touch.

3. **Nothing accounts for icon size, label length, or device kind.** All
   spacings (70, 95, 120, 130, 150, 175, 190, 200, 250, 270, 310, 400, 430…) are
   magic numbers. A `2911` router (~50 units wide + 2 label lines) and a `PC-PT`
   (~34 units) get the same pitch; a 23-char name gets the same cell as `RDR-1`.

4. **Section grids share one canvas without a global occupancy model.**
   `build_jadge_dc`'s server grid (y 1650–2170, x 130–830) overlaps
   `build_crcs`' routers (y 1880, x 250/650/…); `build_hq`'s NOSC row overlaps
   `build_backbone`'s TDL row. Each `build_*()` method picked its own "empty"
   region by eye; nothing reconciles them.

5. **Workspace range: nothing keeps devices inside anything.** The file format
   stores no canvas extent (no viewport/zoom/extent element in the XML); PT's
   logical workspace pans and zooms freely. Empirically PT's stock page is about
   **3900 × 3900 units** — the default `Power Distribution Device0` sits at
   (3898, 3900) in `tools/network_seed.xml` and in corpus labs, and human labs
   keep content within ≈ (84…2538) × (29…1115) in the sample (well inside that
   page). The generated JADGE lab runs to **Y = 5140**, i.e. past the default
   page: users must scroll to find the airbase rows, and no generator notices.

---

## 3. Geometry of real (human-authored) corpus labs

Method: stratified sample of 15 files with `decode_status == OK` from
`../corpus/CORPUS_INDEX.tsv` (865 OK of 1059), decoded with `pkt_core`;
PT's auto-placed `Power Distribution Device*` excluded (it is an artefact parked
at the (3898, 3900) corner in most files and would otherwise fake a 0-distance
neighbour). 4 files in the first sampling pass could not be XML-parsed
(`not well-formed (invalid token)` inside `.pka` activity XML) and were replaced.

| file | n | X range | Y range | NN min | NN p25 | NN median | pairs ≤ 40 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| imsiddhant …EtherChannel | 3 | 464–896 | 162–258 | 188.0 | 188.0 | 188.0 | 0 |
| hackthacker …RING TOPOLOGY | 8 | 508–1188 | 189–713 | 85.1 | 89.3 | 108.7 | 0 |
| Jawadyyy …IotServer | 6 | 84–528 | 44–319 | 117.2 | 117.2 | 136.0 | 0 |
| drespencer …Static Routing (P2) | 16 | 88–897 | 69–372 | 70.6 | 83.7 | 97.1 | 0 |
| blup-blup-spec …VLANbsic | 21 | 94–908 | 69–421 | 69.0 | 72.3 | 84.5 | 0 |
| MIETDevelopers …startopology | 6 | 484–1110 | 102–564 | 191.0 | 191.0 | 291.0 | 0 |
| smsufi …ACL-extended | 12 | 164–983 | 154–516 | 131.6 | 134.6 | 157.9 | 0 |
| hackthacker …BUS topology | 8 | 450–1056 | 278–478 | 187.0 | 187.2 | 188.6 | 0 |
| Rakibul73 …10.pka | 9 | 106–692 | 50–336 | 105.5 | 108.6 | 111.4 | 0 |
| drespencer …DNS | 9 | 640–1014 | 58–348 | 93.0 | 100.7 | 112.4 | 0 |
| imsiddhant …Vlan Lab | 8 | 484–1230 | 225–608 | 130.0 | 132.0 | 144.3 | 0 |
| vaamonde …Cenario-A | 10 | 348–1056 | 62–389 | 125.7 | 141.9 | 147.3 | 0 |
| dishavp …CHAP | 18 | 107–2538 | 113–1115 | 50.2 | 50.2 | 50.2 | 0 |
| dishavp …p3sub,ospf | 25 | 295–2008 | 29–922 | 81.3 | 88.4 | 146.4 | 0 |
| kristof-levai …HSRP_exercise1 | 8 | 224–534 | 69–362 | 61.8 | 72.0 | 111.1 | 0 |

**Aggregate over 167 devices / 15 files:**

- nearest-neighbour distance: min **50.2**, p5 50.2, p10 70.6, p25 **88.4**,
  median **125.7**, p75 172.1, p90 203.5, max 307.1, mean 134.3
- **pairs within 40 units: 0 (0 %)** — humans never place icon centres at icon
  distance; the tightest real case is 50.2 units
- NN ≤ 60: 7.2 %, ≤ 80: 13.8 %, ≤ 100: 31.7 %, ≤ 120: 47.3 %, ≤ 150: 67.7 %,
  ≤ 200: 89.8 %

Interpretation for the fix: **comfortable spacing ≈ 90–180 units between
centres; the hard floor is ~80 (label/icon clearance), and anything ≤ 60 reads
as "overlapping" to a human.** The generated labs violate even the 50-unit
observed minimum. Human layouts also stay near the top-left of the ~3900×3900
PT page and use whole-coordinate placement with pitch 80–200 — exactly the
range the generator's constants (70/95/130/175) fall under.

A second independent stratified pass over 15 further files (81 devices, PDD
excluded) confirmed the same picture: min 50.2, p25 85.8, median 146.4, mean
150.7, and again **0 pairs within 40 units**.

---

## 4. Proposed fix

### 4.1 Sizing model (the missing primitive)

Give every device a **bounding box that includes its labels**, per kind —
measured icon sizes (§1.4) plus the two label lines PT draws (model caption
above, name below):

```python
CHAR_W  = 7      # units per label char (6.3 measured; 7 leaves safety margin)
GUTTER  = 28     # clearance added around every box
ICON_W  = {  # width x height of icon artwork, default zoom
    "router": (52, 44), "switch": (50, 42), "multilayer-switch": (50, 42),
    "access-point": (50, 36), "pc": (36, 42), "laptop": (36, 42),
    "server": (30, 48), "iot": (40, 40), "sniffer": (50, 40),
    "firewall": (52, 42), "pdd": (40, 40), "default": (52, 44),
}

def device_box(kind, name, model_caption):
    w = max(ICON_W[kind][0], CHAR_W * len(name) + 16, CHAR_W * len(model_caption) + 16)
    h = ICON_W[kind][1] + 2 * 18          # model line above + name line below
    return w + GUTTER, h + GUTTER
```

Worked examples: `PC-PT` / `E767-01-WC-PC` (12 chars) → 100×108;
`ISR4331` / `CRC-CENTRAL-RTR-01` (18) → 154×100; `Server-PT` /
`CRC-CENTRAL-DISPLAY-SVR` (23) → 189×112; `Power Distribution Device0`
(27) → 217×96. This is why a uniform grid alone cannot work: a router with a
long name needs ~2× the cell of a PC.

### 4.2 Placement strategy: greedy row packing with occupancy test

Deterministic and cheap (290 devices ≈ trivial); no force-directed randomness
(bad for reproducible byte-exact `.pkt` output, which this repo's round-trip
tests require):

1. **Group** devices semantically (site / tier / airframe — the generators
   already know these). Lay groups out as horizontal *bands*, top to bottom,
   left-aligned; keep the group's intended rough position via an anchor
   (`anchor("airborne", x=200, y=130)`) so topology geography survives.
2. **Inside a band**, place devices row-major: advance a cursor by the device's
   `device_box` width; before committing, AABB-test against every already-placed
   box and **skip forward until free** (greedy packing that skips occupied
   cells). On band-width overflow, wrap to the next row of the band with row
   height = max box height in that row.
3. **Minimum pitch rule** (validated against the corpus):
   `min_centre_distance = max(70, w_a/2 + w_b/2)` where `w` are the *label-inclusive*
   box widths — i.e. defaults: **column pitch 200 for names ≤ 16 chars, 260 for
   17–24, 320 for ≥ 25 chars; row pitch 150.** Never place two devices closer
   than 80 units centre-to-centre under any circumstance (corpus floor is 50,
   comfortable median 126).
4. **Canvas containment.** Target region **X ∈ [60, 3860], Y ∈ [60, 3860]**
   (PT's ~3900×3900 default page, per the seed's `Power Distribution Device0`
   at (3898, 3900)). Before placing, compute total band height; if it overflows,
   *wrap to a second page column* at `x_offset += 3900` (keeping the minimum
   pitch) rather than shrinking spacing. A final `clamp()` pass moves any device
   whose label box would exit the region back inside. At 290 devices and
   200×150 cells the whole JADGE enterprise lab needs ≈ 2200×2200 units — it
   fits on one page comfortably (today it needs 3640×5010 because clusters are
   clumped and the rest is empty).
5. Optional refinement for cabling readability: after packing, a light
   relaxation (move a device at most 1 cell toward the centroid of its link
   neighbours, re-checking AABBs) — but this is a nicety, not required to fix
   overlap.

### 4.3 Where it plugs in

* **`tools/lab_api.py`** — the right home, because every generator
  (`build_large_topology.py`, `build_wired_lab.py`, `build_configured_lab.py`,
  `make_scored_lab.py`, and the JASDF kit) already funnels through
  `Lab.add_device`. Add a `Layout` helper (sizing model + occupancy grid +
  clamp) and change the contract to `add_device(..., x=None, y=None, group=None)`
  where `None` means "ask the planner". Explicit `x,y` keeps working for tests
  and for the seed.
* **The generators** then stop passing magic numbers: they pass their semantic
  group (`group="airframe:E767-01"`, `"crc:CENTRAL"`, `"servers"`) and optionally
  an anchor; the formulas at `build_jasdf_aewc.py:241,289,348,438` and
  `build_large_topology.py:263-264` collapse into group declarations.
  (`build_jasdf_aewc.py` lives in `JASDF_AEWC_source.zip`, not in this repo —
  it would need the same change in its `JASDF.add()` wrapper, which is a
  one-liner since it already delegates to `lab.add_device`.)
* **A checker**, e.g. `tools/check_layout.py` (or a pkt_core test), recomputing
  §1's metrics (pairs ≤ 40, pairs < 80, label AABB collisions, bbox ≤ 3900)
  from a decoded file so CI can fail on regressions.

### 4.4 Recommended spacing/algorithm (summary)

* **Algorithm:** greedy row-major packing with per-device label-inclusive boxes
  and an occupancy/skip-occupied-cells test, grouped into anchored bands,
  wrapped into 3900×3900 pages.
* **Spacing:** cell width `max(icon_w, 7·len(name)+16, 7·len(model)+16) + 28`;
  column pitch 200 (typical), 260 (long names), 320 (≥25 chars);
  row pitch 150; **hard floor 80 units centre-to-centre** — matching human
  corpus practice (min 50, p25 88, median 126) and clearing the largest icon
  (~50) plus label gutters.

---

## 5. Method notes / reproducibility

* Decoding: `pkt_core.decode()` from `src/`; devices are
  `NETWORK/DEVICES/DEVICE`, name `ENGINE/NAME`, kind `ENGINE/TYPE`,
  coordinates `WORKSPACE/LOGICAL/{X,Y}`.
* Measurement scripts were kept outside the repo (`/tmp/layout_measure.py`,
  `/tmp/layout_detail.py`, `/tmp/corpus_final.py`); nothing under `tools/` or
  `src/` was modified.
* Screenshot calibration source: `JASDF_AEWC_packet_tracer_verified.png`
  (940×470) showing the airborne row at 1:1 zoom; the visible
  `E767-02-WLAN-AP` / `E767-01-WC-PC` label pile-up matches cluster #4.
* Corpus failures (XML not well-formed inside some `.pka` activities) were
  excluded and replaced in the sample; they are a decode edge case unrelated to
  layout.
