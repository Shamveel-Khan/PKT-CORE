# Packet Tracer `.pkt` / `.pka` — XML Schema Reference

**Status: complete.** Every element name observed in the corpus is catalogued and classified.

**Derived from:** [`schema_catalogue.json`](schema_catalogue.json) — a byte-level scan of the
decoded XML of **all 1,058 corpus documents** (865 modern
container family, 193 legacy; 0 skipped). The catalogue
records **1,285 distinct element names**, **65,610,511 total element
occurrences**, 81 distinct attribute names, per-name document frequency, up to 8 dominant
parents and up to 12 dominant attributes.

**Read with:** [`FORMAT_SPECIFICATION.md`](FORMAT_SPECIFICATION.md) (container: obfuscation,
Twofish-EAX, qCompress — not repeated here), [`LEGACY_FORMAT.md`](LEGACY_FORMAT.md),
[`SCENE_GRAPH.md`](SCENE_GRAPH.md) (physical workspace, device merge rules),
[`ACTIVITY.md`](ACTIVITY.md) and [`PKA_GENERATION.md`](PKA_GENERATION.md) (authoring),
[`LARGE_TOPOLOGY_TEST.md`](LARGE_TOPOLOGY_TEST.md) (scale).

---

## 1. Overview — the document model

Once the container is decoded (see [`FORMAT_SPECIFICATION.md`](FORMAT_SPECIFICATION.md)), a
Packet Tracer file is a **UTF-8 XML document** with one of three root elements:

| Root element | Documents in corpus | Occurrences | Typical file | Meaning |
| --- | ---: | ---: | --- | --- |
| `PACKETTRACER5` | 994 | 1,888 | `.pkt` | Network lab — topology, devices, configs, canvas |
| `PACKETTRACER5_ACTIVITY` | 447 | 447 | `.pka` | Scored activity (modern schema) — lab plus grading tree, initial-setup tree, locking tree, variables |
| `PACKETTRACER_ACTIVITY` | 64 | 64 | `.pka` | Scored activity on the **PT 4.x** document schema (legacy container family only) |

Every `PACKETTRACER5_ACTIVITY` document nests one or more `PACKETTRACER5` elements as children
(the catalogue counts 1,341 nested occurrences across the 447 activity documents — ≈3 per
document, e.g. live/initial/comparison copies); PT 4.x activities likewise nest a `PACKETTRACER`
child (192 occurrences in 64 documents). `PACKETTRACER5` appears as the document root in 547
lab documents.

> **The root element is not a container discriminator.** `PACKETTRACER5` and
> `PACKETTRACER5_ACTIVITY` documents occur in *both* container families (modern: PT 5.3.3–9.0.1;
> legacy: PT 4.1–5.3.2). A `.pka` is the same container holding a different document. Detection
> must decode first, then look at the root element — see
> [`FORMAT_SPECIFICATION.md`](FORMAT_SPECIFICATION.md) §2 (there is no magic header).

Two structural facts follow from the corpus scan:

* The name inventory is **heavily skewed**: the five most frequent names — `NAME`
  (7,519,571), `ID` (7,467,309), `NODE`
  (6,617,166), `POINTS` (5,873,634) and `COMPONENTS`
  (5,872,133) — account for **50.8%** of the
  65,610,511 element occurrences. Almost all of that is the activity grading tree and the
  IoT environment table (§3.9, §3.11).
* Element names are **reused across contexts** (`NODE`, `NAME`, `ID`, `TYPE`, `X`, `LINE`, `VLAN`, …).
  The catalogue's `parents` map is the authoritative disambiguator; §3.1 lists the overloaded ones.

### Catalogue caveats (read before quoting numbers)

1. `parents` and `attributes` in [`schema_catalogue.json`](schema_catalogue.json) keep only the
   **top 8 parents** and **top 12 attributes** per element name (`most_common`), so a name with
   more parents/attributes is truncated, and the listed counts need not sum to `occurrences`.
2. `has_text` means **"contains a CDATA section"**. The scanner
   ([`tools/schema_catalogue.py`](../tools/schema_catalogue.py)) sets the flag only when it meets
   `<![CDATA[`; ordinary character data is not detected. Only 18 names have `has_text: true`
   (`ID`, `VALUE`, `IMAGE`, `CONTENT`, `PAGE`, `USER_NOTES`, `DISCOVERY_REQUEST`,
   `INVENTORY_REQUEST`, `DASHBOARD`, `DEVICE_INFO`, `HOST_LIST`, `NETWORK_DEVICE_LIST`,
   `POLICY_DEVICE_LIST`, `POLICY_LIST`, `POLICY_TAG_ASSO_LIST`, `POLICY_TAG_LIST`,
   `SMART_LICENSE_LIST`, `WAN`); this says nothing about the other 1,267 names.
3. `has_element_children` is reliable: 331 names
   have element children and 954 are leaves.
4. `documents` counts files containing the name at least once; `occurrences` counts every instance.

---

## 2. Document anatomy

Top-down, what sits where. In the inventories below, the number after each child name is its
number of occurrences *directly under that parent*; "(N distinct names)" is the number of
different child element names the catalogue recorded for that container.

```
PACKETTRACER5 | PACKETTRACER5_ACTIVITY | PACKETTRACER_ACTIVITY      (roots — §1)
├── VERSION                       document schema version of the wrapped lab
├── PACKETTRACER5 | PACKETTRACER  (activities only: the wrapped lab, §1)
├── NETWORK                       (labs)
│   ├── DESCRIPTION
│   ├── DEVICES  → DEVICE → ENGINE  +  WORKSPACE
│   │                 │                ├── LOGICAL   (canvas X/Y, MEM_ADDR, DEV_ADDR)
│   │                 │                ├── PHYSICAL  (GUID path, see SCENE_GRAPH.md)
│   │                 │                └── PHYSICAL_CPUR (rack placement)
│   │                 └── ENGINE   (156 distinct child names: modules/ports, configs,
│   │                                services, licensing, IoT, user apps, … — §3.3)
│   ├── LINKS    → LINK → CABLE   (FROM/TO/PORT/LENGTH, …)
│   └── SHAPETESTS
├── OPTIONS          (78 distinct child names: UI flags, FONT, COLOR, …)
├── PHYSICALWORKSPACE   → NODE (location tree), NOTES, HOMERACK, grids, BGPATH
├── CLUSTERS → ROOTCLUSTER → CLUSTER / cluster background images
├── LINES / RECTANGLES / ELLIPSES / POLYGONS   (canvas drawing)
├── SCENARIOSET → SCENARIO
├── GEOVIEW_GRAPHICSITEMS → ParentPhyObject → shape groups
├── FILTERS          (per-protocol visibility attributes, §4)
├── USER_PROFILE, MULTIUSER, CODE_TESTING, COMMAND_LOGS, EXT_PORT_MGR, CEPS
├── PIXMAPBANK, MOVIEBANK         (embedded image/movie banks)
├── SCRIPT_MODULE(S)              (also reachable via OPTIONS → SCRIPT_MODULE_MANAGER)
│
└── (activities only)
    ├── ACTIVITY → INSTRUCTIONS → PAGE (CDATA HTML), INSTRUCTION_DIALOG → USER_NOTES
    ├── COMPARISONS / INITIALSETUP / LOCKINGTREE   (each holds NODE trees)
    ├── VARIABLE_MANAGER → *_POOLS → *_VAR
    ├── OVERALL_COMPLETE_FEEDBACK / OVERALL_INCOMPLETE_FEEDBACK
    └── COMPONENT_LIST, DYNAMIC_PERCENTAGE_FEEDBACK, OBJECT_LOCATIONS, ACTIVITY_SCRIPTS
```

Exact child inventories for the load-bearing containers (child names with the number of
occurrences *directly under that parent*):

**Children of `PACKETTRACER5`** (21 distinct names):
`VERSION` (1,888), `NETWORK` (1,888), `MULTIUSER` (1,888), `OPTIONS` (1,888), `FILTERS` (1,888),
`CLUSTERS` (1,888), `ELLIPSES` (1,888), `LINES` (1,888), `PHYSICALWORKSPACE` (1,888),
`RECTANGLES` (1,888), `SCENARIOSET` (1,888), `USER_PROFILE` (1,888), `GEOVIEW_GRAPHICSITEMS`
(1,839), `SCRIPT_MODULE` (1,608), `POLYGONS` (1,548), `CODE_TESTING` (959), `PIXMAPBANK` (658),
`MOVIEBANK` (628), `CEPS` (547), `COMMAND_LOGS` (479), `EXT_PORT_MGR` (321).

**Children of `PACKETTRACER5_ACTIVITY`** (23 distinct names): `PACKETTRACER5` (1,341), `VERSION`
(447), `OPTIONS` (447), `CEPS` (447), `ACTIVITY` (447), `COMPARISONS` (447), `INITIALSETUP` (447),
`LOCKINGTREE` (447), `VARIABLE_MANAGER` (447), `OVERALL_COMPLETE_FEEDBACK` (447),
`OVERALL_INCOMPLETE_FEEDBACK` (447), `COMPONENT_LIST` (447), `DYNAMIC_PERCENTAGE_FEEDBACK` (447),
`USER_PROFILE_LOCKED` (447), `CLEAN_ACTIVITY` (445), `AUTHOR` (435), `SCRIPT_MODULE` (366),
`OBJECT_LOCATIONS` (353), `USER_PROFILE_NOGUEST` (178), `EXT_PORT_MGR` (158),
`UNLOCK_ASSESSMENT_ITEM_PERCENT` (158), `ACTIVITY_SCRIPTS` (69), `START_TIMESTAMP` (22).

**Children of `PACKETTRACER_ACTIVITY`** (PT 4.x, 10 distinct names): `PACKETTRACER` (192),
`VERSION` (64), `OPTIONS` (64), `ACTIVITY` (64), `COMPARISONS` (64), `INITIALSETUP` (64),
`LOCKINGTREE` (64), `VARIABLE_MANAGER` (64), `OVERALL_COMPLETE_FEEDBACK` (8),
`OVERALL_INCOMPLETE_FEEDBACK` (8).

**Children of `NETWORK`** (4 distinct names): `DESCRIPTION` (2,080), `DEVICES` (2,080),
`LINKS` (2,080), `SHAPETESTS` (1,548).

**Children of `DEVICE`** (2): `ENGINE` (29,965), `WORKSPACE` (29,965).
**Children of `WORKSPACE`** (3): `LOGICAL` (29,965), `PHYSICAL` (29,965), `PHYSICAL_CPUR` (17,698).
**Children of `LINK`** (2): `TYPE` (26,621), `CABLE` (26,621).
**Children of `CABLE`** (15): `PORT` (53,242), `LENGTH` (26,621), `FROM` (26,621), `TO` (26,621),
`FROM_DEVICE_MEM_ADDR` (25,187), `FROM_PORT_MEM_ADDR` (25,187), `TO_DEVICE_MEM_ADDR` (25,187),
`TO_PORT_MEM_ADDR` (25,187), `TYPE` (22,478), `GEO_VIEW_COLOR` (15,506), `FUNCTIONAL` (15,195),
`IS_MANAGED_IN_RACK_VIEW` (12,161), `DCEDEV` (3,766), `DCEPORT` (3,766),
`OVERWITE_MISMATCH_FIBER` (2).

**Children of `PHYSICALWORKSPACE`** (10): `NODE` (2,080), `NOTES` (2,080), `HOMERACK` (2,080),
`BGPATH_TILED` (1,617), `BUILDING_GRID` (1,139), `CITY_GRID` (1,139), `GRID_COLOR` (1,139),
`INTERCITY_GRID` (1,139), `BGPATH` (1,088), `GENERIC_CONTAINER_GRID` (959).

**`ENGINE`** is the true content hub — **156 distinct child names**, spanning §3.3 (device
identity, modules/ports, config text), §3.5 (VTP, DHCP, ACLs), §3.6 (wireless, Bluetooth,
cellular), §3.10 (file manager), §3.11 (IoT), §3.13 (script modules, licensing) and §3.14
(services). Its most frequent children: `NAME`/`TYPE`/`DESCRIPTION`/`POWER`/`MODULE` (29,968
each), `FILE_MANAGER` (28,275), `ALGORITHM_SETTINGS` (25,936), `CUSTOM_INTERFACE` (25,176),
`CUSTOM_VARS` (25,176), `SYS_CONTACT`/`SYS_LOCATION` (24,768), `COORD_SETTINGS` (24,393),
`SYS_NAME` (22,714), `SERIALNUMBER` (21,489), `EXT_ATTRIBUTES`/`USB_PORT_COUNT` (17,701),
`USER_APPS` (17,668), `SAVE_REF_ID` (16,926).

**`OPTIONS`** carries 78 distinct child names; see §3.15.

---

## 3. The element catalogue

The 1,285 names are grouped into **18 families** by subject
matter, derived from each name's dominant parent and occurrence profile — not alphabetically.
Every name falls into exactly one family; there is no unclassified residue (the residual family
came out empty). The method: a name is filed with the family of the parent under which it mostly
occurs (e.g. `LINE` → `RUNNINGCONFIG` → device config), with explicit overrides where a generic
parent (`ENGINE`, `NODE`, `OPTIONS`) would obscure the subject.

**Family overview** (ordered as presented):

| # | Family | Names | Occurrences | Share | Modelled |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Document skeleton and roots | 46 | 92,959 | 0.1% | 11 |
| 2 | Devices, engines, modules, slots and ports | 169 | 8,248,173 | 12.6% | 44 |
| 3 | Links and cables | 20 | 288,312 | 0.4% | 10 |
| 4 | IP, VLAN and interface configuration | 194 | 1,839,270 | 2.8% | 37 |
| 5 | Wireless, RF and Bluetooth | 94 | 1,058,505 | 1.6% | 28 |
| 6 | Canvas placement, coordinates and clusters | 49 | 1,400,635 | 2.1% | 19 |
| 7 | Canvas drawing and notes | 60 | 186,658 | 0.3% | 23 |
| 8 | Activity grading, instructions and variables | 28 | 34,955,254 | 53.3% | 15 |
| 9 | File store and filesystem | 38 | 3,342,563 | 5.1% | 10 |
| 10 | IoT, MCU and the simulation environment | 74 | 13,296,183 | 20.3% | 23 |
| 11 | Physical workspace and racks | 9 | 23,473 | 0.0% | 0 |
| 12 | Script modules, user apps and licensing | 82 | 378,121 | 0.6% | 4 |
| 13 | Device application services | 196 | 266,530 | 0.4% | 0 |
| 14 | Lab options and application UI | 79 | 144,687 | 0.2% | 19 |
| 15 | Multiuser, IPC and external connectivity | 33 | 56,687 | 0.1% | 1 |
| 16 | Simulation PDUs and scenarios | 17 | 26,829 | 0.0% | 0 |
| 17 | SOHO home-router and modem features | 50 | 5,600 | 0.0% | 0 |
| 18 | Cloud-managed networking (Meraki / NETCON) | 47 | 72 | 0.0% | 0 |
| — | **Total** | **1,285** | **65,610,511** | **100%** | **244** |

### 3.1 Names that cross families

Several high-frequency names are reused in multiple contexts. They are filed under their
dominant parent (marked first), but an implementation must key off the *parent*, not the name:

| Name | Filed under | Occurrences | Parents recorded in the catalogue (occurrences) |
| --- | --- | ---: | --- |
| `NAME` | activity (`NODE`) | 7,519,571 | `NODE` 6,068,464 · `ENVIRONMENT_OPTION` 882,000 · `FILE` 458,669 · `WIRELESS_PROFILE` 44,296 · `ENGINE` 29,968 · `EMAIL_CLIENT` 12,158 · `POOL` 3,028 · `RESOURCE-RECORD` 2,437 |
| `ID` | activity (`NODE`) | 7,467,309 | `NODE` 6,570,912 · `ENVIRONMENT_OPTION` 882,000 · `DATA_STORE` 8,938 · `PT_APP_META` 1,974 · `SCRIPT` 1,768 · `PDU` 1,544 · `WLAN_CONFIG` 159 · `NETWORK_DEVICE` 13 |
| `NODE` | activity | 6,617,166 | `NODE` 6,569,367 (nested tree) · `CHILDREN` 44,174 · `PHYSICALWORKSPACE` 2,080 · `COMPARISONS` 511 · `INITIALSETUP` 511 · `LOCKINGTREE` 511 · `SHAPE` 12 |
| `VALUE` | activity | 882,825 | `ENVIRONMENT_OPTION` 882,000 · `STRING_VAR` 669 · `SEED_VAR` 100 · `IP_VAR` 32 · `NETWORK_DEVICE` 13 · `NUMBER_VAR` 10 · `CLICredentialDTO` 1 |
| `TEXT` | activity (`NODE`) | 668,129 | `NODE` 548,702 · `FILE_CONTENT` 80,163 · `NOTE` 39,264 |
| `TYPE` | device (`PORT`) | 559,592 | `PORT` 243,343 · `SLOT` 94,291 · `MODULE` 86,465 · `NODE` 46,254 · `ENGINE` 29,968 · `LINK` 26,621 · `CABLE` 22,478 · `PDU` 4,641 |
| `LINE` | device (`RUNNINGCONFIG`) | 2,232,777 | `RUNNINGCONFIG` 1,243,764 · `STARTUPCONFIG` 724,205 · `CONFIG` 264,275 · `LINES` 532 (canvas line) · `BOOT_SYSTEMS` 1 |
| `X` / `Y` | placement | 138,661 each | `NODE` 46,254 · `NOTE` 39,264 · `LOGICAL` 29,983 · `PHYSICAL_CPUR` 17,698 · `INTERCITY_GRID`/`CITY_GRID`/`BUILDING_GRID` 1,139 each · `GENERIC_CONTAINER_GRID` 959 |
| `SLOT` | device (`MODULE`) | 126,819 | `MODULE` 94,291 · `NODE` 19,355 · `PHYSICAL_CPUR` 13,173 |
| `VERSION` | skeleton | 41,428 | `VTP` 15,463 · `LICENSE` 12,382 · `FILE_CONTENT` 9,018 · `PT_APP_META` 1,974 · `PACKETTRACER5` 1,888 · `PACKETTRACER5_ACTIVITY` 447 · `PACKETTRACER` 192 · `PACKETTRACER_ACTIVITY` 64 |
| `NETWORK` | skeleton | 5,109 | `POOL` 3,028 (DHCP pool network field) · `PACKETTRACER5` 1,888 · `PACKETTRACER` 192 · `MERAKI_DEVICE` 1 |
| `CHANNEL` | device (`PORT`) | 273,265 | `PORT` 230,753 · `WIRELESS_PROFILE` 42,512 |
| `POINTS` | activity (`NODE`) | 5,873,634 | `NODE` 5,872,133 · `PDU` 1,487 · `POLYGON` 14 |
| `IMAGE` | drawing | 13,252 | `BACKGROUNDS` 12,184 · `PIXMAPBANK` 710 · `IMAGES` 358 |


### 3.2 Document skeleton and roots

**46 names · 92,959 occurrences · 0.1% of all occurrences · 11 modelled**

The root elements and the level-1 containers that every document is built from. These names are what a reader needs before anything else: they define the document kind and the section layout. `VERSION`, `NETWORK` and `OPTIONS` also occur as leaf fields elsewhere (see the cross-cutting table in §3.1), but their dominant use is the skeleton, and that is where they are filed here.

**Representative parent paths**

* `PACKETTRACER5` → `VERSION`, `NETWORK`, `OPTIONS`, `CLUSTERS`, `LINES`, `PHYSICALWORKSPACE`, …
* `PACKETTRACER5_ACTIVITY` → `ACTIVITY`, `COMPARISONS`, `INITIALSETUP`, `LOCKINGTREE`, `VARIABLE_MANAGER`, …
* `PACKETTRACER_ACTIVITY` (PT 4.x) → `PACKETTRACER` → `NETWORK`, …

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `VERSION` | 41,428 | 1058 | `VTP` | yes |
| `NETWORK` | 5,109 | 1058 | `POOL` | yes |
| `OPTIONS` | 2,591 | 1058 | `PACKETTRACER5` | yes |
| `DEVICES` | 2,127 | 1058 | `NETWORK` | yes |
| `FILTERS` | 2,082 | 1058 | `PACKETTRACER5` | — |
| `CLUSTERS` | 2,080 | 1058 | `PACKETTRACER5` | yes |
| `ELLIPSES` | 2,080 | 1058 | `PACKETTRACER5` | — |
| `LINES` | 2,080 | 1058 | `PACKETTRACER5` | — |
| `LINKS` | 2,080 | 1058 | `NETWORK` | yes |
| `PHYSICALWORKSPACE` | 2,080 | 1058 | `PACKETTRACER5` | yes |
| `RECTANGLES` | 2,080 | 1058 | `PACKETTRACER5` | — |
| `SCENARIOSET` | 2,080 | 1058 | `PACKETTRACER5` | yes |
| `SCRIPT_MODULES` | 1,974 | 876 | `SCRIPT_MODULE_MANAGER` | — |
| `SCRIPT_MODULE_MANAGER` | 1,974 | 876 | `OPTIONS` | — |
| `PACKETTRACER5` | 1,888 | 994 | `PACKETTRACER5_ACTIVITY` | — |
| `USER_PROFILE` | 1,888 | 994 | `PACKETTRACER5` | — |
| `GEOVIEW_GRAPHICSITEMS` | 1,839 | 969 | `PACKETTRACER5` | — |
| `POLYGONS` | 1,548 | 842 | `PACKETTRACER5` | — |
| `SHAPETESTS` | 1,548 | 842 | `NETWORK` | — |
| `CEPS` | 994 | 994 | `PACKETTRACER5` | — |
| `CUSTOM_TYPE_FILTERS` | 961 | 625 | `FILTERS` | — |
| `CODE_TESTING` | 959 | 625 | `PACKETTRACER5` | — |
| `PIXMAPBANK` | 658 | 636 | `PACKETTRACER5` | yes |
| `MOVIEBANK` | 628 | 626 | `PACKETTRACER5` | yes |
| `ACTIVITY` | 511 | 511 | `PACKETTRACER5_ACTIVITY` | — |
| `COMPARISONS` | 511 | 511 | `PACKETTRACER5_ACTIVITY` | — |
| `INITIALSETUP` | 511 | 511 | `PACKETTRACER5_ACTIVITY` | — |
| `INSTRUCTIONS` | 511 | 511 | `ACTIVITY` | — |
| `LOCKINGTREE` | 511 | 511 | `PACKETTRACER5_ACTIVITY` | — |
| `VARIABLE_MANAGER` | 511 | 511 | `PACKETTRACER5_ACTIVITY` | — |
| `COMMAND_LOGS` | 479 | 479 | `PACKETTRACER5` | — |
| `EXT_PORT_MGR` | 479 | 479 | `PACKETTRACER5` | — |
| `OVERALL_COMPLETE_FEEDBACK` | 455 | 455 | `PACKETTRACER5_ACTIVITY` | — |
| `OVERALL_INCOMPLETE_FEEDBACK` | 455 | 455 | `PACKETTRACER5_ACTIVITY` | — |
| `COMPONENT_LIST` | 447 | 447 | `PACKETTRACER5_ACTIVITY` | — |
| `DYNAMIC_PERCENTAGE_FEEDBACK` | 447 | 447 | `PACKETTRACER5_ACTIVITY` | — |
| `PACKETTRACER5_ACTIVITY` | 447 | 447 | `(root)` | — |
| `USER_PROFILE_LOCKED` | 447 | 447 | `PACKETTRACER5_ACTIVITY` | — |
| `CLEAN_ACTIVITY` | 445 | 445 | `PACKETTRACER5_ACTIVITY` | yes |
| `OBJECT_LOCATIONS` | 353 | 353 | `PACKETTRACER5_ACTIVITY` | — |
| `PACKETTRACER` | 192 | 64 | `PACKETTRACER_ACTIVITY` | — |
| `USER_PROFILE_NOGUEST` | 178 | 178 | `PACKETTRACER5_ACTIVITY` | — |
| `UNLOCK_ASSESSMENT_ITEM_PERCENT` | 158 | 158 | `PACKETTRACER5_ACTIVITY` | — |
| `ACTIVITY_SCRIPTS` | 69 | 69 | `PACKETTRACER5_ACTIVITY` | — |
| `PACKETTRACER_ACTIVITY` | 64 | 64 | `(root)` | — |
| `START_TIMESTAMP` | 22 | 22 | `PACKETTRACER5_ACTIVITY` | — |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `EIGRP` (2,082), `DTP` (2,082), `STP` (2,082), `OSPF` (2,082), `ARP` (2,082)

### 3.3 Devices, engines, modules, slots and ports

**169 names · 8,248,173 occurrences · 12.6% of all occurrences · 44 modelled**

The device model itself: `DEVICE` carries an `ENGINE` (the virtual device state) and a `WORKSPACE` (placement). Under `ENGINE` sit the module/slot/port tree, the CLI configuration text, per-device services and dozens of engine-level settings. This is the largest family by name count and by far the largest by occurrences once the config-text lines are counted.

**Representative parent paths**

* `NETWORK` → `DEVICES` → `DEVICE` → `ENGINE` → `PORT`
* `ENGINE` → `MODULE` → `SLOT` → `MODULE` → `PORT`
* `ENGINE` → `RUNNINGCONFIG` / `STARTUPCONFIG` → `LINE`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `LINE` | 2,232,777 | 1030 | `RUNNINGCONFIG` | yes |
| `TYPE` | 559,592 | 1058 | `PORT` | yes |
| `PORT` | 316,053 | 1057 | `MODULE` | yes |
| `DESCRIPTION` | 279,988 | 1058 | `PORT` | yes |
| `POWER` | 273,311 | 1057 | `PORT` | yes |
| `CHANNEL` | 273,265 | 968 | `PORT` | yes |
| `AUTONEGOTIATEBANDWIDTH` | 243,343 | 1057 | `PORT` | yes |
| `AUTONEGOTIATEDUPLEX` | 243,343 | 1057 | `PORT` | yes |
| `BANDWIDTH` | 243,343 | 1057 | `PORT` | yes |
| `BIA` | 243,343 | 1057 | `PORT` | yes |
| `CLOCKRATE` | 243,343 | 1057 | `PORT` | yes |
| `FULLDUPLEX` | 243,343 | 1057 | `PORT` | yes |
| `PINS` | 243,343 | 1057 | `PORT` | yes |
| `CLOCKRATEFLAG` | 191,159 | 841 | `PORT` | yes |
| `CHANNEL5GHZ` | 128,188 | 624 | `PORT` | yes |
| `COVERAGERANGE` | 128,188 | 624 | `PORT` | yes |
| `MEDIATYPE` | 128,188 | 624 | `PORT` | yes |
| `SAVED_FULLDUPLEX` | 128,188 | 624 | `PORT` | yes |
| `SLOT` | 126,819 | 1058 | `MODULE` | yes |
| `UP_METHOD` | 124,032 | 607 | `PORT` | yes |
| `MODEL` | 86,466 | 1057 | `MODULE` | yes |
| `MODULE` | 86,465 | 1057 | `SLOT` | yes |
| `LOG_ENTRY` | 78,756 | 382 | `COMMAND_LOGS` | — |
| `ENABLED` | 77,475 | 1037 | `SECURITY` | — |
| `TIMEOUT` | 61,709 | 1050 | `PORT` | — |
| `CUSTOM_INTERFACE` | 31,642 | 875 | `ENGINE` | yes |
| `ENGINE` | 29,968 | 1057 | `DEVICE` | yes |
| `DEVICE` | 29,965 | 1057 | `DEVICES` | — |
| *(+141 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `model` (29,968), `customModel` (25,275), `translate` (4,243), `patterned` (1,547), `uuid` (316)

### 3.4 Links and cables

**20 names · 288,312 occurrences · 0.4% of all occurrences · 10 modelled**

Connectivity. Each `LINK` wraps exactly one `CABLE`; the cable records both endpoint device/port references (`FROM`/`TO` plus the `*_MEM_ADDR` runtime pointers), the media length, and physical-view state. `SUBLINK`/`DLCI` cover Frame-Relay style sub-interfaces.

**Representative parent paths**

* `NETWORK` → `LINKS` → `LINK` → `CABLE` → `FROM` / `TO` / `PORT`
* `PORT` → `SUBLINKS` → `SUBLINK` → `DLCI`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `LENGTH` | 26,624 | 1053 | `CABLE` | yes |
| `CABLE` | 26,621 | 1053 | `LINK` | yes |
| `FROM` | 26,621 | 1053 | `CABLE` | yes |
| `LINK` | 26,621 | 1053 | `LINKS` | — |
| `TO` | 26,621 | 1053 | `CABLE` | yes |
| `FROM_DEVICE_MEM_ADDR` | 25,187 | 964 | `CABLE` | yes |
| `FROM_PORT_MEM_ADDR` | 25,187 | 964 | `CABLE` | yes |
| `TO_DEVICE_MEM_ADDR` | 25,187 | 964 | `CABLE` | yes |
| `TO_PORT_MEM_ADDR` | 25,187 | 964 | `CABLE` | yes |
| `GEO_VIEW_COLOR` | 15,506 | 632 | `CABLE` | yes |
| `FUNCTIONAL` | 15,195 | 621 | `CABLE` | yes |
| `IS_MANAGED_IN_RACK_VIEW` | 12,161 | 475 | `CABLE` | — |
| `DCEDEV` | 3,766 | 589 | `CABLE` | — |
| `DCEPORT` | 3,766 | 589 | `CABLE` | — |
| `DLCI` | 1,524 | 62 | `SUBLINK` | — |
| `SUBLINK` | 1,524 | 62 | `SUBLINKS` | — |
| `SUBLINKS` | 994 | 82 | `PORT` | — |
| `CABLE_PEGBOARD` | 9 | 3 | `NODE` | — |
| `CABLE_TYPES` | 9 | 3 | `CABLE_PEGBOARD` | — |
| `OVERWITE_MISMATCH_FIBER` | 2 | 1 | `CABLE` | — |

### 3.5 IP, VLAN and interface configuration

**194 names · 1,839,270 occurrences · 2.8% of all occurrences · 37 modelled**

Interface addressing and L3/L2 control plane state: IPv4/IPv6 addresses, DHCP(v4/v6) client, server, pools and bindings, DNS, VLAN/VTP, ACLs and ACL filter statements, NAT port-forwarding, QoS policy lists and IPv6 ND/RA data. Most of it hangs off `PORT` or off `ENGINE`-level service blocks.

**Representative parent paths**

* `PORT` → `IP` / `SUBNET` / `IPV6_ADDRESSES` → `IPV6_ADDRESS`
* `ENGINE` → `VTP` → `VLANS` → `VLAN`
* `ENGINE` → `DHCP_SERVERS` / `DHCP_SERVER` → `POOLS` → `POOL`
* `ENGINE` → `ACL_PROCESS` → `ACL_FILTERS` → `ACL_FILTER` → `STATEMENTS` → `STATEMENT`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `MACADDRESS` | 243,343 | 1057 | `PORT` | yes |
| `VLAN` | 121,713 | 1039 | `VLANS` | yes |
| `IP` | 59,276 | 1050 | `PORT` | yes |
| `SUBNET` | 59,264 | 1050 | `PORT` | yes |
| `IPV6_ADDRESSES` | 57,350 | 986 | `PORT` | yes |
| `IPV6_ADDRESS_AUTOCONFIG` | 57,350 | 986 | `PORT` | yes |
| `IPV6_DEFAULT_LINK_LOCAL` | 57,350 | 986 | `PORT` | yes |
| `IPV6_ENABLED` | 57,350 | 986 | `PORT` | yes |
| `IPV6_LINK_LOCAL` | 57,350 | 986 | `PORT` | yes |
| `IPV6_PORT_DHCP_ENABLED` | 49,106 | 834 | `PORT` | yes |
| `IPV6_PORT_DNS` | 49,106 | 834 | `PORT` | yes |
| `IPV6_PORT_GATEWAY` | 49,106 | 834 | `PORT` | yes |
| `ND_SUPPRESSED` | 49,106 | 834 | `PORT` | yes |
| `PC_FIREWALL` | 49,106 | 834 | `PORT` | yes |
| `PC_IPV6_FIREWALL` | 49,106 | 834 | `PORT` | yes |
| `PORT_DHCP_ENABLE` | 49,106 | 834 | `PORT` | yes |
| `PORT_DNS` | 49,106 | 834 | `PORT` | yes |
| `PORT_GATEWAY` | 49,106 | 834 | `PORT` | yes |
| `PASSWORD` | 36,390 | 1055 | `VTP` | — |
| `IP_UNNUMBERED` | 34,908 | 620 | `PORT` | yes |
| `DHCP_SERVER_IP` | 33,232 | 589 | `PORT` | yes |
| `ND_IPV6_DNS_ADDRESSES` | 25,793 | 415 | `PORT` | yes |
| `ACLS` | 22,522 | 783 | `ACL_PROCESS` | — |
| `ENABLED_ROUTER` | 18,473 | 872 | `NDV6` | — |
| `DOMAIN_NAME` | 17,673 | 1029 | `VTP` | — |
| `CONFIG_REVISION` | 15,463 | 1027 | `VTP` | — |
| *(+168 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `number` (87,340), `name` (87,340), `rspan` (47,181), `enabled` (7), `qindex` (1)

### 3.6 Wireless, RF and Bluetooth

**94 names · 1,058,505 occurrences · 1.6% of all occurrences · 28 modelled**

Everything radio: the per-device `WIRELESS_CLIENT` profile list (`WIRELESS_PROFILE` with SSID/auth/keys), `WIRELESS_COMMON` AP settings, `WIRELESS_SERVER`, WEP/EAP processing, CAPWAP/WLC controller data (`CAPWAP_AC`, `AP`, `AP_GROUP`, `WLANS`/`WLAN_CONFIG`), Bluetooth manager/port/beacons, cellular client and paired-device records.

**Representative parent paths**

* `ENGINE` → `WIRELESS_CLIENT` → `PROFILES` → `WIRELESS_PROFILE`
* `ENGINE` → `WIRELESS_COMMON` / `WIRELESS_SERVER`
* `ENGINE` → `CAPWAP` → `WLANS` → `WLAN` → `WLAN_CONFIG`
* `ENGINE` → `BLUETOOTH_MANAGER` → `PAIRED_DEVICES` → `PAIRED_DEVICE`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `AUTHEN_TYPE` | 75,228 | 983 | `WIRELESS_PROFILE` | yes |
| `SSID` | 67,170 | 983 | `WIRELESS_PROFILE` | yes |
| `RADIO_BAND` | 65,502 | 983 | `WIRELESS_PROFILE` | yes |
| `ENCRYPT_TYPE` | 64,491 | 897 | `WIRELESS_PROFILE` | yes |
| `IP_ADDRESS` | 45,870 | 983 | `WIRELESS_PROFILE` | yes |
| `DEFAULT_GATEWAY` | 44,540 | 983 | `WIRELESS_PROFILE` | yes |
| `WEP_KEY` | 44,455 | 983 | `WIRELESS_PROFILE` | yes |
| `NETWORK_TYPE` | 44,297 | 983 | `WIRELESS_PROFILE` | yes |
| `DHCP_ENABLED` | 44,296 | 983 | `WIRELESS_PROFILE` | yes |
| `DNS` | 44,296 | 983 | `WIRELESS_PROFILE` | yes |
| `SUBNET_MASK` | 44,296 | 983 | `WIRELESS_PROFILE` | yes |
| `WIRELESS_PROFILE` | 44,296 | 983 | `PROFILES` | yes |
| `WPA_EAP_PASSWORD` | 42,512 | 897 | `WIRELESS_PROFILE` | yes |
| `WPA_EAP_USERID` | 42,512 | 897 | `WIRELESS_PROFILE` | yes |
| `PROFILES` | 30,612 | 983 | `WIRELESS_CLIENT` | yes |
| `DHCPV6_ENABLED` | 26,788 | 463 | `WIRELESS_PROFILE` | yes |
| `WIRELESS_COMMON` | 22,715 | 983 | `WIRELESS_CLIENT` | yes |
| `CURRENT_PROFILE` | 22,146 | 983 | `WIRELESS_CLIENT` | yes |
| `WIRELESS_CLIENT` | 22,146 | 983 | `ENGINE` | yes |
| `NETWORK_MODE` | 21,206 | 843 | `WIRELESS_COMMON` | yes |
| `STANDARD_CHANNEL` | 21,206 | 843 | `WIRELESS_COMMON` | yes |
| `WIDE_CHANNEL` | 21,206 | 843 | `WIRELESS_COMMON` | yes |
| *(+72 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `WRNG_WS_TYPE` (42)

### 3.7 Canvas placement, coordinates and clusters

**49 names · 1,400,635 occurrences · 2.1% of all occurrences · 19 modelled**

Where things are. `WORKSPACE` splits into `LOGICAL` (logical topology canvas), `PHYSICAL` (a comma-joined GUID path into the physical workspace, see [`SCENE_GRAPH.md`](SCENE_GRAPH.md)) and `PHYSICAL_CPUR` (rack placement). The `NODE` tree's geometry fields (`X`,`Y`,`H`,`W`,…), cluster membership (`DEVCLUSTERID`, `CLUSTERID`) and cluster presentation live here too.

**Representative parent paths**

* `DEVICE` → `WORKSPACE` → `LOGICAL` → `X` / `Y` / `MEM_ADDR` / `DEV_ADDR`
* `DEVICE` → `WORKSPACE` → `PHYSICAL_CPUR` → `PARENT_PATH` / `CONTAINER_ID` / `X_PN`
* `CLUSTERS` → `ROOTCLUSTER` → `CLUSTER` / `CLUSTER_BG_IMAGE`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `X` | 138,661 | 1058 | `NODE` | yes |
| `Y` | 138,661 | 1058 | `NODE` | yes |
| `MEM_ADDR` | 49,832 | 968 | `LOGICAL` | — |
| `H` | 46,254 | 1058 | `NODE` | yes |
| `SX` | 46,254 | 1058 | `NODE` | yes |
| `SY` | 46,254 | 1058 | `NODE` | yes |
| `W` | 46,254 | 1058 | `NODE` | yes |
| `PATH` | 45,638 | 1047 | `NODE` | yes |
| `INIT_HEIGHT` | 42,703 | 969 | `NODE` | — |
| `INIT_SX` | 42,703 | 969 | `NODE` | — |
| `INIT_SY` | 42,703 | 969 | `NODE` | — |
| `INIT_WIDTH` | 42,703 | 969 | `NODE` | — |
| `MANUAL_SCALING` | 42,703 | 969 | `NODE` | — |
| `SCALED_PIXMAP_HEIGHT` | 42,703 | 969 | `NODE` | — |
| `SCALED_PIXMAP_WIDTH` | 42,703 | 969 | `NODE` | — |
| `Z` | 39,264 | 816 | `NOTE` | yes |
| `BG_TILED` | 38,110 | 879 | `NODE` | — |
| `DEVCLUSTERID` | 29,983 | 1057 | `LOGICAL` | — |
| *(+31 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `isanim` (25,270), `translate` (15,722), `isOriginalSize` (66)

### 3.8 Canvas drawing and notes

**60 names · 186,658 occurrences · 0.3% of all occurrences · 23 modelled**

Free-hand drawing primitives and annotations: `RECTANGLE`, `ELLIPSE`, `POLYGON`, canvas `LINE` clusters, sticky `NOTE`s, and the physical-view graphics groups (`ParentPhyObject` → `RectangularShapes` / `LineShapes` / `GeoConnectionItems` / …) under `GEOVIEW_GRAPHICSITEMS`. Shapes carry `uuid` attributes and colour/label fields.

**Representative parent paths**

* `PACKETTRACER5` → `RECTANGLES` → `RECTANGLE` → `TopLeftX` / `Color` / `Filled`
* `PACKETTRACER5` → `GEOVIEW_GRAPHICSITEMS` → `ParentPhyObject` → `RectangularShapes`
* `PHYSICALWORKSPACE` / `ENVIRONMENT` → `NOTES` → `NOTE`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `NOTE` | 39,264 | 816 | `NOTES` | — |
| `NOTECLUSTERID` | 39,264 | 816 | `NOTE` | yes |
| `IMAGE` | 13,252 | 644 | `BACKGROUNDS` | — |
| `NOTES` | 6,368 | 1058 | `ENVIRONMENT` | — |
| `Color` | 4,795 | 381 | `RECTANGLE` | yes |
| `BreakPointItems` | 3,823 | 933 | `ParentPhyObject` | — |
| `EllipticalShapes` | 3,823 | 933 | `ParentPhyObject` | — |
| `GeoConnectionItems` | 3,823 | 933 | `ParentPhyObject` | — |
| `GroupPointItems` | 3,823 | 933 | `ParentPhyObject` | — |
| `LineShapes` | 3,823 | 933 | `ParentPhyObject` | — |
| `NoteEdits` | 3,823 | 933 | `ParentPhyObject` | — |
| `ParentPhyObject` | 3,823 | 933 | `GEOVIEW_GRAPHICSITEMS` | — |
| `Path` | 3,823 | 933 | `ParentPhyObject` | — |
| `RectangularShapes` | 3,823 | 933 | `ParentPhyObject` | — |
| `PolygonShapes` | 3,530 | 807 | `ParentPhyObject` | — |
| `Filled` | 2,546 | 296 | `RECTANGLE` | yes |
| `BottomRightX` | 2,532 | 293 | `RECTANGLE` | yes |
| `BottomRightY` | 2,532 | 293 | `RECTANGLE` | yes |
| *(+42 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `uuid` (37,647), `second` (12,184), `first` (12,184), `OUTLINED` (2,265), `OUTLINECOLOR` (2,046)

### 3.9 Activity grading, instructions and variables

**28 names · 34,955,254 occurrences · 53.3% of all occurrences · 15 modelled**

The scored-activity layer. `NODE` is the grading tree — 6.6 million occurrences of nested `NODE`s, each with `ID`, `NAME`, `POINTS`, `COMPONENTS` and grading attributes on `NAME` (§4). `ACTIVITY` holds the activity-wizard state (including the `PASS` **attribute**), `INSTRUCTIONS`/`INSTRUCTION_DIALOG` hold the CDATA-HTML pages, and `VARIABLE_MANAGER` holds the variable pools used for per-student parameterisation. Note that `NODE` is **overloaded**: the same name is the physical-workspace tree node ([`SCENE_GRAPH.md`](SCENE_GRAPH.md) §2), and its `CHILDREN`/`X`/`Y`/`H`/`W` fields serve both uses.

**Representative parent paths**

* `PACKETTRACER5_ACTIVITY` → `ACTIVITY` → `INSTRUCTIONS` → `PAGE` (CDATA HTML)
* grading tree: `NODE` → `COMPONENTS` → `NODE` → `ID` / `POINTS` / `NAME`
* `PACKETTRACER5_ACTIVITY` → `VARIABLE_MANAGER` → `VARIABLES_POOLS` / `STRING_POOLS` / `SEED_POOLS`
* `PACKETTRACER5_ACTIVITY` → `COMPARISONS` / `INITIALSETUP` / `LOCKINGTREE` → `NODE`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `NAME` | 7,519,571 | 1058 | `NODE` | yes |
| `ID` | 7,467,309 | 1024 | `NODE` | yes |
| `NODE` | 6,617,166 | 1058 | `NODE` | yes |
| `POINTS` | 5,873,634 | 641 | `NODE` | yes |
| `COMPONENTS` | 5,872,133 | 447 | `NODE` | yes |
| `VALUE` | 882,825 | 650 | `ENVIRONMENT_OPTION` | yes |
| `TEXT` | 668,129 | 1057 | `NODE` | — |
| `CHILDREN` | 46,254 | 1058 | `NODE` | — |
| `POOL_NAME` | 984 | 71 | `STRING_VAR` | — |
| `INDEX` | 823 | 45 | `STRING_VAR` | — |
| `PAGE` | 761 | 511 | `INSTRUCTIONS` | yes |
| `STRING_VAR` | 669 | 23 | `VARIABLES_POOLS` | — |
| `STRING_POOL` | 667 | 26 | `STRING_POOLS` | — |
| `VALUES` | 653 | 23 | `STRING_POOL` | — |
| `IP_POOLS` | 511 | 511 | `VARIABLE_MANAGER` | yes |
| `NUMBER_POOLS` | 511 | 511 | `VARIABLE_MANAGER` | yes |
| `STRING_POOLS` | 511 | 511 | `VARIABLE_MANAGER` | yes |
| `VARIABLES_POOLS` | 511 | 511 | `VARIABLE_MANAGER` | yes |
| `ITEM` | 427 | 14 | `OBJECT_LOCATIONS` | — |
| `LOAD_INIT_TREE` | 383 | 383 | `INITIALSETUP` | yes |
| `SEED_POOLS` | 353 | 353 | `VARIABLE_MANAGER` | yes |
| `INSTRUCTION_DIALOG` | 158 | 158 | `ACTIVITY` | yes |
| *(+6 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `checkType` (6,022,210), `eclass` (6,022,210), `incorrectFeedback` (6,022,210), `nodeValue` (6,022,210), `variableEnabled` (6,022,210)

### 3.10 File store and filesystem

**38 names · 3,342,563 occurrences · 5.1% of all occurrences · 10 modelled**

The per-engine virtual filesystem (`FILE_MANAGER` → `FILES` → `FILE` → `FILE_CONTENT`), with `NAME`, `DATE_TIME`, `FILE_NUMBER`, `PERMISSION`, `CAPACITY`, `FILE_COUNTER` and the content-variant metadata (`DEVICE_TYPE`, `SET_NAME`, `MANIFEST_*`, signature files).

**Representative parent paths**

* `ENGINE` → `FILE_MANAGER` → `FILES` → `FILE` → `FILE_CONTENT`
* `FILE_CONTENT` → `DEVICE_TYPE` / `SET_NAME` / `MANIFEST_NAME` / `CONFIG`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `FILE` | 468,081 | 1056 | `FILES` | yes |
| `FILE_CONTENT` | 463,178 | 1055 | `FILE` | yes |
| `DATE_TIME` | 458,669 | 1055 | `FILE` | yes |
| `FILE_NUMBER` | 458,669 | 1055 | `FILE` | yes |
| `PERMISSION` | 458,669 | 1055 | `FILE` | yes |
| `DEVICE_TYPE` | 270,393 | 1042 | `FILE_CONTENT` | — |
| `SET_NAME` | 263,927 | 1040 | `FILE_CONTENT` | — |
| `FILES` | 99,367 | 1055 | `FILE` | yes |
| `CAPACITY` | 70,739 | 1055 | `FILE` | — |
| `FILE_COUNTER` | 70,739 | 1055 | `FILE` | yes |
| `Firmware_Version` | 38,970 | 882 | `FILE_CONTENT` | yes |
| `FILE_MANAGER` | 28,275 | 1055 | `ENGINE` | — |
| `FILE_PATH` | 12,631 | 876 | `SCRIPT_MODULE` | yes |
| `CONTENT` | 10,706 | 945 | `DATA_STORE` | — |
| `CODE` | 10,562 | 483 | `FILE_CONTENT` | — |
| `MANIFEST_APP_TYPE` | 9,018 | 259 | `FILE_CONTENT` | — |
| `MANIFEST_AUTHOR_LINK` | 9,018 | 259 | `FILE_CONTENT` | — |
| `MANIFEST_AUTHOR_NAME` | 9,018 | 259 | `FILE_CONTENT` | — |
| *(+20 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `class` (830,735), `family` (2,591), `pointsize` (2,591)

### 3.11 IoT, MCU and the simulation environment

**74 names · 13,296,183 occurrences · 20.3% of all occurrences · 23 modelled**

The IoT/simulation layer: `THING_MODEL` (analog/digital slots, rules, subcomponents), `IOE_*` client/device records, `ICP_*` container-scene placement, and the huge `ENVIRONMENT_OPTION` table (882,000 occurrences of 17-field records describing sensor ranges, units and interpolation). The environment table hangs off the node tree (`NODE` → `ENVIRONMENT` → `KEYFRAMES` → `KEYFRAME` → `ENVIRONMENT_OPTIONS`), which is why it is enormous; `pkt_core.models` documents it as IoT/simulation environment options.

**Representative parent paths**

* `NODE` → `ENVIRONMENT` → `KEYFRAMES` → `KEYFRAME` → `ENVIRONMENT_OPTIONS` → `ENVIRONMENT_OPTION`
* `ENGINE` → `THING_MODEL` → `RULES` / `SUBCOMPONENTS` / `SPECIFICATIONS`
* `ENGINE` → `IOE_CLIENT` / `IOE_DEVICE`
* `NODE` → `SUB_SLOT` / `ICP_CSX` (ICP container-scene coordinates)

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `ACTIVE` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `CATEGORY` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `CATEGORY_ID` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `ENVIRONMENT_OPTION` | 882,000 | 626 | `ENVIRONMENT_OPTIONS` | yes |
| `IMPERIAL_CONVERSION_FORMULA` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `IMPERIAL_UNIT` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `INTERPOLATE` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `MAX` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `METRIC_CONVERSION_FORMULA` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `METRIC_UNIT` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `MIN` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `SHOW` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `TRANSFERENCE` | 882,000 | 626 | `ENVIRONMENT_OPTION` | yes |
| `MAX_RATE` | 870,912 | 625 | `ENVIRONMENT_OPTION` | yes |
| `MIN_RATE` | 870,912 | 625 | `ENVIRONMENT_OPTION` | yes |
| `ENVIRONMENT_OPTIONS` | 15,750 | 626 | `KEYFRAME` | — |
| `KEYFRAME` | 11,462 | 626 | `KEYFRAMES` | — |
| `TIME` | 11,462 | 626 | `KEYFRAME` | — |
| `ENVIRONMENT` | 4,288 | 626 | `NODE` | — |
| `KEYFRAMES` | 4,288 | 626 | `ENVIRONMENT` | — |
| `REAL_TIME_COMBO` | 4,288 | 626 | `ENVIRONMENT` | — |
| `REAL_TIME_SETTING` | 4,288 | 626 | `ENVIRONMENT` | — |
| *(+52 further names in this family)* | | | | |

### 3.12 Physical workspace and racks

**9 names · 23,473 occurrences · 0.0% of all occurrences · 0 modelled**

The *Physical* tab scene container `PHYSICALWORKSPACE` and its grids/backgrounds — the tree of location nodes (Intercity → City → Building → Closet → Rack) is the `NODE` tree, see [`SCENE_GRAPH.md`](SCENE_GRAPH.md). This family is small but load-critical: a merge that references non-existent physical nodes is rejected with *"corrupted Physical Workspace data"*.

**Representative parent paths**

* `PACKETTRACER5` → `PHYSICALWORKSPACE` → `HOMERACK` / `NODE` / `BUILDING_GRID` / `BGPATH`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `SUBSLOT` | 13,173 | 420 | `PHYSICAL_CPUR` | — |
| `HOMERACK` | 2,080 | 1058 | `PHYSICALWORKSPACE` | — |
| `BGPATH_TILED` | 1,617 | 879 | `PHYSICALWORKSPACE` | — |
| `BUILDING_GRID` | 1,139 | 699 | `PHYSICALWORKSPACE` | — |
| `CITY_GRID` | 1,139 | 699 | `PHYSICALWORKSPACE` | — |
| `GRID_COLOR` | 1,139 | 699 | `PHYSICALWORKSPACE` | — |
| `INTERCITY_GRID` | 1,139 | 699 | `PHYSICALWORKSPACE` | — |
| `BGPATH` | 1,088 | 422 | `PHYSICALWORKSPACE` | — |
| `GENERIC_CONTAINER_GRID` | 959 | 625 | `PHYSICALWORKSPACE` | — |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `translate` (1,267)

### 3.13 Script modules, user apps and licensing

**82 names · 378,121 occurrences · 0.6% of all occurrences · 4 modelled**

Three loosely related subsystems that share the engine's extension surface: PT `SCRIPT_MODULE`s (with `SCRIPT_MODULE_DATA`/`DATA_STORE` and permission flags), user applications (`USER_APP`/`DESKTOP_APPS` with a lowercase manifest `application`/`gui`/`settings` tree), and licensing (`LICENSE`/`LICENSE_MANAGER`, `SMART_LICENSE_CLIENT`, per-feature licence state). `PT_APP_META` records app metadata.

**Representative parent paths**

* `OPTIONS` → `SCRIPT_MODULE_MANAGER` → `SCRIPT_MODULES` → `SCRIPT_MODULE` → `PT_APP_META`
* `ENGINE` → `USER_APPS` → `DESKTOP_APPS` → `application` → `gui` / `settings`
* `ENGINE` → `LICENSE_MANAGER` → `LICENSES` → `LICENSE`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `DESKTOP_APPS` | 17,668 | 624 | `USER_APPS` | yes |
| `RUNNING_APPS` | 17,668 | 624 | `USER_APPS` | yes |
| `USER_APPS` | 17,668 | 624 | `ENGINE` | yes |
| `LICENSE` | 12,559 | 550 | `LICENSES` | — |
| `ENFORCED` | 12,382 | 541 | `LICENSE` | — |
| `EVAL_LEFT` | 12,382 | 541 | `LICENSE` | — |
| `EVAL_TOTAL` | 12,382 | 541 | `LICENSE` | — |
| `EVAL_USED` | 12,382 | 541 | `LICENSE` | — |
| `FEATURE_NAME` | 12,382 | 541 | `LICENSE` | — |
| `LICENSE_COUNT` | 12,382 | 541 | `LICENSE` | — |
| `LICENSE_PRIORITY` | 12,382 | 541 | `LICENSE` | — |
| `LICENSE_STATE` | 12,382 | 541 | `LICENSE` | — |
| `LICENSE_TYPE` | 12,382 | 541 | `LICENSE` | — |
| `RIGHT_TO_USE` | 12,382 | 541 | `LICENSE` | — |
| `STORE_INDEX` | 12,382 | 541 | `LICENSE` | — |
| `STORE_NAME` | 12,382 | 541 | `LICENSE` | — |
| `TECHNOLOGY` | 12,382 | 541 | `LICENSE` | — |
| `UNIQUE_ID` | 12,382 | 541 | `LICENSE` | — |
| `SCRIPT_DATA_STORES` | 12,352 | 945 | `SCRIPT_MODULE_DATA` | — |
| `SCRIPT_MODULE` | 12,283 | 876 | `SCRIPT_MODULES` | yes |
| *(+62 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `scale` (1,130)

### 3.14 Device application services

**196 names · 266,530 occurrences · 0.4% of all occurrences · 0 modelled**

Server-side services simulated inside a device: the email subsystem (`EMAIL_SERVER` with up to 24 numbered mailbox slots `USER0..USER23`, `MAIL_*` fields, `EMAIL_CLIENT` with its own mailbox), HTTP/HTTPS/FTP servers and `USER_ACCOUNT_MNGR`, SNMP manager/agent, NTP servers, DNS server records (`NAMESERVER-DATABASE`, `RESOURCE-RECORD`), AAA (`ACS_SERVER`, RADIUS settings) and Syslog. The numbered mailbox fields are the reason this family has ~200 distinct names.

**Representative parent paths**

* `ENGINE` → `EMAIL_SERVER` → `USER0` / `MAIL_CONTENT0`
* `ENGINE` → `EMAIL_CLIENT` → `MAIL_FROM0` / `MAIL_SUBJECT0`
* `ENGINE` → `SNMP_MANAGER`, `NTP_SERVER`, `ACS_SERVER` → `RADIUS_SETTINGS`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `SERVER_IP` | 13,908 | 982 | `DNS_CLIENT` | — |
| `SERVER_IPV6` | 13,266 | 918 | `DNS_CLIENT` | — |
| `USER` | 12,377 | 844 | `EMAIL_CLIENT` | — |
| `EMAIL_CLIENT` | 12,158 | 842 | `ENGINE` | — |
| `MAIL_ID` | 12,158 | 842 | `EMAIL_CLIENT` | — |
| `NO_OF_MAILS` | 12,158 | 842 | `EMAIL_CLIENT` | — |
| `POP3_SERVER` | 12,158 | 842 | `EMAIL_CLIENT` | — |
| `SMTP_SERVER` | 12,158 | 842 | `EMAIL_CLIENT` | — |
| `IS_DEFAULT_TFTP` | 11,998 | 842 | `VOIP_TFTP_IP` | — |
| `TFTP_IP` | 11,998 | 842 | `VOIP_TFTP_IP` | — |
| `VOIP_TFTP_IP` | 11,998 | 842 | `ENGINE` | — |
| `SCP_SERVER_ENABLED` | 6,968 | 596 | `ENGINE` | — |
| `KEY` | 6,814 | 1007 | `NTP_SERVER` | — |
| `AGENT_IP` | 6,072 | 389 | `SNMP_MANAGER` | — |
| `AGENT_PORT` | 6,072 | 389 | `SNMP_MANAGER` | — |
| `MANAGER_PORT` | 6,072 | 389 | `SNMP_MANAGER` | — |
| `READ_COMMUNITY` | 6,072 | 389 | `SNMP_MANAGER` | — |
| `SNMP_MANAGER` | 6,072 | 389 | `ENGINE` | — |
| `SNMP_VERSION` | 6,072 | 389 | `SNMP_MANAGER` | — |
| `WRITE_COMMUNITY` | 6,072 | 389 | `SNMP_MANAGER` | — |
| `USERNAME` | 5,371 | 539 | `HTTP_SERVER` | — |
| `USERS` | 3,726 | 464 | `ACS_SERVER` | — |
| *(+174 further names in this family)* | | | | |

### 3.15 Lab options and application UI

**79 names · 144,687 occurrences · 0.2% of all occurrences · 19 modelled**

The `OPTIONS` block (present once per document; 78 distinct children) plus the `FONT`, `COLOR` and `USER_PROFILE` subtrees: UI visibility flags (`HIDECLI`, `HIDEGUI`, `PORTSHOWN`, …), language, logging, fonts (`family`/`pointsize` attributes), console and tooltip colours, and the lab-level `PASS` element (the activity-wizard password — not to be confused with the `PASS` *attribute* of `ACTIVITY`).

**Representative parent paths**

* `PACKETTRACER5` → `OPTIONS` → `HIDECLI` / `LANGUAGE` / `PASS`
* `OPTIONS` → `FONT` → `CLIFONT` (attributes `family`, `pointsize`)
* `OPTIONS` → `COLOR` → `IOSBACKGROUNDCOLOR` / `Blue` / `Green` / `Red`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `COLOR` | 3,576 | 912 | `OPTIONS` | yes |
| `Blue` | 3,078 | 359 | `Color` | — |
| `Green` | 3,078 | 359 | `Color` | — |
| `Red` | 3,078 | 359 | `Color` | — |
| `ACCESSIBLE` | 2,591 | 1058 | `OPTIONS` | — |
| `ACTIVITYFONT` | 2,591 | 1058 | `FONT` | — |
| `ANIMATION` | 2,591 | 1058 | `OPTIONS` | yes |
| `BACKGROUNDS` | 2,591 | 1058 | `OPTIONS` | yes |
| `BUTTONLABELS` | 2,591 | 1058 | `FONT` | — |
| `CLIFONT` | 2,591 | 1058 | `FONT` | — |
| `CONFIGPATH` | 2,591 | 1058 | `OPTIONS` | yes |
| `DOCK` | 2,591 | 1058 | `OPTIONS` | yes |
| `FONT` | 2,591 | 1058 | `OPTIONS` | — |
| `HEADERFONT` | 2,591 | 1058 | `FONT` | — |
| `HIDECLI` | 2,591 | 1058 | `OPTIONS` | — |
| `HIDECONFIG` | 2,591 | 1058 | `OPTIONS` | yes |
| `HIDEDESKTOP` | 2,591 | 1058 | `OPTIONS` | — |
| `HIDEDEVICELABEL` | 2,591 | 1058 | `OPTIONS` | — |
| `HIDEGUI` | 2,591 | 1058 | `OPTIONS` | — |
| `HIDEPHYSICAL` | 2,591 | 1058 | `OPTIONS` | yes |
| *(+59 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `family` (18,137), `pointsize` (18,137), `consoleBackgroundColor` (1,986), `consoleTextColor` (1,986), `iosBackgroundColor` (1,986)

### 3.16 Multiuser, IPC and external connectivity

**33 names · 56,687 occurrences · 0.1% of all occurrences · 1 modelled**

PT's multiuser and inter-process features: `MULTIUSER` peer settings (`MU_PEERS`/`PEER`, accept modes, passwords), the `IPC_MANAGER` block (metafile path, trusted/untrusted publishers, certificates) and `REMOTE_NETWORK*` entries for shared remote topologies.

**Representative parent paths**

* `PACKETTRACER5` → `MULTIUSER` → `MU_PEERS` → `PEER`
* `OPTIONS` → `IPC_MANAGER` → `METAFILE_PATH` / `TRUSTED_PUBLISHERS`
* `MULTIUSER` → `REMOTE_NETWORKS` → `REMOTE_NETWORK` → `REMOTE_NETWORK_ENGINE`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `CERTIFICATE` | 7,240 | 842 | `TRUSTED_PUBLISHERS` | — |
| `METAFILE_PATH` | 5,353 | 994 | `IPC_MANAGER` | yes |
| `MULTIUSER` | 4,223 | 994 | `OPTIONS` | — |
| `PEER` | 2,351 | 994 | `MU_PEERS` | — |
| `ALLOWREMOTESAVING` | 2,335 | 994 | `MULTIUSER` | — |
| `ALWAYSLISTENATSTARTUP` | 2,335 | 994 | `MULTIUSER` | — |
| `IPC_ALLOWREMOTEAPPS` | 2,335 | 994 | `OPTIONS` | — |
| `IPC_MANAGER` | 2,335 | 994 | `OPTIONS` | — |
| `MU_ACCEPT_MODE` | 2,335 | 994 | `MULTIUSER` | — |
| `MU_PASSWORD` | 2,335 | 994 | `MULTIUSER` | — |
| `MU_PEERS` | 2,335 | 994 | `MULTIUSER` | — |
| `REMOTE_SAVING_DEPTH` | 2,335 | 994 | `MULTIUSER` | — |
| `SHOW_CONNECTED_PORT_NAMES` | 2,335 | 994 | `MULTIUSER` | — |
| `DISABLED_CEPS` | 2,274 | 969 | `IPC_MANAGER` | — |
| `MU_ALLOW_PTMP_BROADCAST` | 2,274 | 969 | `MULTIUSER` | — |
| `MU_NEW_RNET_ACCEPT_MODE` | 2,274 | 969 | `MULTIUSER` | — |
| `IPC_VERSION` | 1,974 | 876 | `PT_APP_META` | — |
| `TRUSTED_PUBLISHERS` | 1,901 | 842 | `IPC_MANAGER` | — |
| `UNTRUSTED_PUBLISHERS` | 1,901 | 842 | `IPC_MANAGER` | — |
| `PORT_VISIBILITY` | 1,888 | 994 | `MULTIUSER` | — |
| `REMOTE_NETWORKS` | 1,888 | 994 | `MULTIUSER` | — |
| `CONNECT_AS_USERNAME` | 18 | 9 | `REMOTE_NETWORK_ENGINE` | — |
| `OUTGOING` | 18 | 9 | `REMOTE_NETWORK_ENGINE` | — |
| `PEER_ADDRESS` | 18 | 9 | `REMOTE_NETWORK_ENGINE` | — |
| `PORT_NUMBER` | 18 | 9 | `REMOTE_NETWORK_ENGINE` | — |
| `REMOTE_NETWORK` | 18 | 9 | `REMOTE_NETWORKS` | — |
| `REMOTE_NETWORK_ENGINE` | 18 | 9 | `REMOTE_NETWORK` | — |
| `REMOTE_NETWORK_UUID` | 18 | 9 | `REMOTE_NETWORK_ENGINE` | — |
| `CONTEXT` | 1 | 1 | `EXT_PORT_MGR` | — |
| `DEVICE_ORDER` | 1 | 1 | `PORT_INFO` | — |
| `DEV_NAME` | 1 | 1 | `CONTEXT` | — |
| `PORT_INFO` | 1 | 1 | `PORT_VISIBILITY` | — |
| `PORT_TYPE` | 1 | 1 | `CONTEXT` | — |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `visibility` (1)

### 3.17 Simulation PDUs and scenarios

**17 names · 26,829 occurrences · 0.0% of all occurrences · 0 modelled**

The simulation side-channel: `SCENARIOSET`/`SCENARIO` scenario entries and the `PDU` probe records (source/destination, protocol, ICMP type/seq, TOS, size, test conditions) used by *Add Simple PDU* and activity checks. `PDU` is recorded as its own dominant parent, i.e. the catalogue saw `PDU` elements nested under `PDU`.

**Representative parent paths**

* `PACKETTRACER5` → `SCENARIOSET` → `SCENARIO`
* `PDU` → `SOURCE` / `DESTINATION` / `PROTOCOL` / `CHK` / `TEST_CONDITION`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `PDU` | 4,641 | 311 | `PDU` | — |
| `PROTOCOL` | 2,177 | 331 | `PDU` | — |
| `SCENARIO` | 2,163 | 1058 | `SCENARIOSET` | — |
| `CHK` | 1,547 | 311 | `PDU` | — |
| `DESTINATION` | 1,547 | 311 | `PDU` | — |
| `DSTADDR` | 1,547 | 311 | `PDU` | — |
| `SOURCE` | 1,547 | 311 | `PDU` | — |
| `SRCADDR` | 1,547 | 311 | `PDU` | — |
| `TEST_CONDITION` | 1,547 | 311 | `PDU` | — |
| `START` | 1,545 | 309 | `PDU` | — |
| `ICMPTYPE` | 1,544 | 309 | `PDU` | — |
| `SEQ` | 1,544 | 309 | `PDU` | — |
| `PDU_SIZE` | 1,473 | 297 | `PDU` | — |
| `TOS` | 1,473 | 297 | `PDU` | — |
| `CUSTOM_TYPE` | 981 | 201 | `PDU` | — |
| `DST` | 3 | 2 | `PDU` | — |
| `SRC` | 3 | 2 | `PDU` | — |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `device` (1,478), `STRSTART` (4)

### 3.18 SOHO home-router and modem features

**50 names · 5,600 occurrences · 0.0% of all occurrences · 0 modelled**

The home-router/consumer device surface: WAN/Internet port data, PPPoE client, DMZ and single-port forwarding wrappers, parental-control `ACCESS_POLICY` lists (blocked apps/URLs/times), modem/phone connection lists and TV-image counters. Coherent block: most of these names occur in 65–80 documents each.

**Representative parent paths**

* `ENGINE` → `DMZ_SETTINGS` / `PPPOE_CLIENT` / `INTERNET_PORT_DATA`
* `ENGINE` → `ACCESS_POLICIES` → `ACCESS_POLICY` → `BLOCK_URL` / `BLOCKED_APP_LIST`
* `ENGINE` → `CONNECTIONS` / `MODEM_CONNECTION_TYPES` → `CONNECTION_TYPE` → `DSL`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `CONNECTION` | 466 | 92 | `CONNECTIONS` | — |
| `CONNECTIONS` | 274 | 105 | `ENGINE` | — |
| `MODEM_CONNECTIONS` | 274 | 105 | `ENGINE` | — |
| `MODEM_CONNECTION_TYPES` | 274 | 105 | `ENGINE` | — |
| `PHONE_CONNECTIONS` | 274 | 105 | `ENGINE` | — |
| `NO_OF_TV_IMAGES` | 256 | 97 | `ENGINE` | — |
| `STATUS` | 248 | 79 | `DMZ_SETTINGS` | — |
| `INTERNET_CONNECTION_TYPE` | 244 | 80 | `ENGINE` | — |
| `LAN_IP_ADDRESS` | 244 | 80 | `ENGINE` | — |
| `LAN_SUBNET_MASK` | 244 | 80 | `ENGINE` | — |
| `REMOTE_MANAGEMENT` | 244 | 80 | `ENGINE` | — |
| `SINGLE_PORT_FORWARDING` | 244 | 80 | `ENGINE` | — |
| `ACCESS_POLICIES` | 241 | 79 | `ENGINE` | — |
| `DESTINATION_IP_ADDR` | 241 | 79 | `DMZ_SETTINGS` | — |
| `DMZ_SETTINGS` | 241 | 79 | `ENGINE` | — |
| `INTERNET_IP_ADDRESS` | 231 | 79 | `ENGINE` | — |
| `INTERNET_SUBNET_MASK` | 231 | 79 | `ENGINE` | — |
| `PPPOE_CLIENT` | 230 | 78 | `ENGINE` | — |
| `SERVICE_NAME` | 230 | 78 | `PPPOE_CLIENT` | — |
| `CONNECTION_TYPE` | 123 | 69 | `MODEM_CONNECTION_TYPES` | — |
| `DSL` | 123 | 69 | `CONNECTION_TYPE` | — |
| `PORT1` | 107 | 47 | `CONNECTION` | — |
| *(+28 further names in this family)* | | | | |

**Attributes seen in this family** (the catalogue retains only the top 12 per element): `status` (7), `WS_COUNT` (7)

### 3.19 Cloud-managed networking (Meraki / NETCON)

**47 names · 72 occurrences · 0.0% of all occurrences · 0 modelled**

A thin, very low-frequency layer found in only a handful of documents: Meraki cloud objects (`MERAKI_SERVER` → networks/devices/users/HTTP services) and the `NETCON_SERVER` network-controller block (discovery, inventory, host lists, credentials, smart-licence tokens). 47 names but only 72 occurrences in total — treat as one-to-three documents' worth of serialised DTOs.

**Representative parent paths**

* `ENGINE` → `MERAKI_SERVER` → `MERAKI_NETWORKS` → `MERAKI_NETWORK`
* `ENGINE` → `NETCON_SERVER` → `INVENTORY` / `DISCOVERY` / `GLOBAL_CREDENTIALS`

**Key element names**

| Element | Occurrences | Documents | Dominant parent | Modelled |
| --- | ---: | ---: | --- | --- |
| `NETWORK_DEVICE` | 13 | 1 | `NETWORK_DEVICES` | — |
| `DISCOVERY_REQUEST` | 4 | 1 | `DISCOVERY_SET` | — |
| `DISCOVERY_SET` | 4 | 1 | `DISCOVERY_SETS` | — |
| `INVENTORY_REQUEST` | 4 | 1 | `DISCOVERY_SET` | — |
| `NETWORK_DEVICES` | 4 | 1 | `DISCOVERY_SET` | — |
| `SELECTED_NW_NAME` | 2 | 1 | `MERAKI_HTTP_SERVICE` | — |
| `ASSURANCE` | 1 | 1 | `NETCON_SERVER` | — |
| `CLICredentialDTO` | 1 | 1 | `CLICredentialDTOs` | — |
| `CLICredentialDTOs` | 1 | 1 | `GLOBAL_CREDENTIALS` | — |
| `COMPANY` | 1 | 1 | `MERAKI_USER` | — |
| `DASHBOARD` | 1 | 1 | `NETCON_SERVER` | — |
| `DEVICE_INFO` | 1 | 1 | `INVENTORY` | — |
| `DISCOVERY` | 1 | 1 | `NETCON_SERVER` | — |
| `DISCOVERY_SETS` | 1 | 1 | `DISCOVERY` | — |
| `FIREWALL_SETTINGS` | 1 | 1 | `MERAKI_NETWORK` | — |
| `FLOW_ANALYSIS` | 1 | 1 | `NETCON_SERVER` | — |
| `FULL_NAME` | 1 | 1 | `MERAKI_USER` | — |
| `GLOBAL_CREDENTIALS` | 1 | 1 | `NETCON_SERVER` | — |
| `HOST` | 1 | 1 | `NETCON_SERVER` | — |
| `HOST_LIST` | 1 | 1 | `HOST` | — |
| *(+27 further names in this family)* | | | | |

---

## 4. Attribute conventions

The corpus uses **81 distinct attribute
names** across all 1,285 element names (the catalogue retains at most the 12
most frequent per element). Attributes are used far less than elements — most elements are
attribute-free — but the ones that exist are load-bearing.

### 4.1 Grading attributes on `<NAME>`

The dominant attribute cluster in the corpus belongs to `<NAME>` inside the activity grading tree
(§3.9) — six attributes at **6,022,210 occurrences each**, plus three more at multi-million
scale:

```xml
<NAME checkType="…" eclass="…" incorrectFeedback="…" nodeValue="…"
      variableEnabled="…" variableName="…" headNode="…"
      obfuscateName="…" overrideDBGrading="…" translate="true">PC0</NAME>
```

| Attribute | Occurrences | On element |
| --- | ---: | --- |
| `checkType`, `eclass`, `incorrectFeedback`, `nodeValue`, `variableEnabled`, `variableName` | 6,022,210 each | `NAME` |
| `headNode` | 5,788,223 | `NAME` |
| `obfuscateName`, `overrideDBGrading` | 3,007,782 each | `NAME` |
| `translate` | 118,868 on `NAME`; 47,289 on `ID`; 761 on `PAGE`; 231,555 total | several |

Note the naming mismatch an implementer will trip over: `ScoringNode` in
[`src/pkt_core/models/schema.py`](../src/pkt_core/models/schema.py) claims a `CHECK_TYPE` field,
but **`CHECK_TYPE` does not exist as an element name in the corpus** — the corpus stores
`checkType` as an *attribute* of `NAME`.

### 4.2 Identity and type attributes

| Pattern | Attribute counts | Meaning |
| --- | --- | --- |
| `<TYPE model="2960-24TT" customModel="">` | `model` 29,968 · `customModel` 25,275 (on `TYPE`) | Device/module/port type. `model` matches the PT device-model id; `customModel` covers user-created models. `patterned` (1,547) marks pattern variants |
| `<VLAN number="1" name="default" rspan="…">` | `number` 87,340 · `name` 87,340 · `rspan` 47,181 | VLAN record; note `name` is an *attribute* here, while elsewhere `NAME` is an element |
| `<FILE class="…">` / `<FILE_CONTENT class="…">` | `class` 830,735 total (458,669 + 372,066) | File-class discriminator in the engine's virtual filesystem |
| `<NODE on="…">` | `on` 548,702 | Flag on grading/workspace `NODE` occurrences |
| `<RECTANGLE uuid="{guid}">`, `<NOTE uuid="{guid}">`, `<LINE uuid="…">`, `<ELLIPSE>`, `<POLYGON>` | `uuid` 37,963 total (NOTE 35,339 · RECTANGLE 2,092 · LINE 316 · ELLIPSE 202 · POLYGON 14) | Stable shape/note identity |
| `<PATH isanim="…">` | `isanim` 25,270 (PATH 23,911, `CLUSTER_BG_IMAGE` most of the rest) | Animated-path flag |
| `<INDEX SEED="…">` | `SEED` 794 | Variable-pool seed for reproducible randomisation |
| `<ITEM ID="…" NAME="…" LOCATIONS="…">` | 427 each | Object-location records under `OBJECT_LOCATIONS` |

### 4.3 Activity attributes (not elements)

`<ACTIVITY>` is attribute-driven; the activity-wizard state lives entirely in attributes, including
**`PASS` — the activity password is an *attribute* of `<ACTIVITY>`, not an element** (do not
confuse it with the `<PASS>` *element* under `<OPTIONS>`, which is the lab-level password,
occurrences 2,591 in 1,058 documents):

```xml
<ACTIVITY PASS="secret" ENABLED="true" COUNTDOWNMS="…" TIMERTYPE="…" …>
```

| Attribute | Count | Notes |
| --- | ---: | --- |
| `PASS`, `ENABLED`, `COUNTDOWNMS`, `TIMERTYPE` | 511 each | present on every `ACTIVITY` |
| `FORWARD_ANS_SIM_MS` | 435 | |
| `VALUE` | 349 | |
| `COUNTDOWNLEFT`, `ELAPSED` | 220 each | runtime timer residue |
| `COUNTDOWN_EXPIRED` | 152 | |

### 4.4 Presentation attributes

| Attribute | Count | On |
| --- | ---: | --- |
| `family`, `pointsize` | 20,728 each | the eight `FONT` children (`CLIFONT`, `WORKSPACEFONT`, `ACTIVITYFONT`, `BUTTONLABELS`, `FILEMENUFONT`, `HEADERFONT`, `TABSWITCH`, `TOOLTIP`) |
| `consoleBackgroundColor`, `consoleTextColor`, `iosBackgroundColor`, `iosTextColor` | 1,986 each | `COLOR` children |
| `tooltipBackgroundColor`, `tooltipTextColor` | 1,126 each | `COLOR` children |
| `OUTLINED`, `OUTLINECOLOR` | 2,265 / 2,003 | `Filled` (rectangle fill) |
| `first`, `second` | 12,184 each | `IMAGE` background images |
| `scale` | 1,130 | `APPLICATION` |
| `translate`, `tabify`, `title` | 761 / 198 / 198 | `PAGE` (instruction pages) |

`<FILTERS>` carries one boolean attribute per visible protocol — `EIGRP`, `DTP`, `STP`, `OSPF`,
`ARP`, `VTP`, `DHCP`, `RIP`, `TCP`, `TFTP`, `HTTP`, `ICMP` — at **2,082 occurrences each**.

### 4.5 `save-ref-id:` references

Devices carry `<SAVE_REF_ID>save-ref-id:NNNN</SAVE_REF_ID>` (16,928 occurrences, 607 documents,
16,926 of them directly under `ENGINE`) — a stable per-document handle. Cables reference endpoints through `<FROM>` and
`<TO>` (26,621 each, under `CABLE`), and additionally cache the runtime heap pointers
`FROM_DEVICE_MEM_ADDR`, `FROM_PORT_MEM_ADDR`, `TO_DEVICE_MEM_ADDR`, `TO_PORT_MEM_ADDR` (25,187
each; see [`SCENE_GRAPH.md`](SCENE_GRAPH.md) §3 for what survives a merge). When hand-authoring or
merging documents, fix up **both** the `save-ref-id:` values and the `*_MEM_ADDR` copies.

---

## 5. Quirks an implementer must know

These are corpus-measured, not hypothetical. Getting any of them wrong costs half the corpus.

### 5.1 Documents are not always well-formed XML

A corpus survey of the 1,058 documents
([`src/pkt_core/xml/__init__.py`](../src/pkt_core/xml/__init__.py)):

| Quirk | Files | Detail |
| --- | ---: | --- |
| Raw control bytes in text | 510 | Router/switch running-config text in `<LINE>` embeds raw control bytes — the Cisco `banner motd ^C…^C` delimiter is stored as a **literal `0x03`**; `0x01`/`0x02`/`0x11` also occur. XML 1.0 forbids these in character data |
| Numeric char refs to forbidden chars | 392 | `&#xNN;` for characters XML 1.0 forbids *by reference* too |
| Trailing NUL after the root | 64 | PT 4.1 documents end with a NUL byte after `</PACKETTRACER_ACTIVITY>` |

Measured across a 400-file modern sample, **210 files are non-well-formed** for exactly these
reasons ([`CORPUS_VERIFICATION.md`](CORPUS_VERIFICATION.md) §5).

### 5.2 Activity instructions are CDATA HTML

Instruction pages are Word-exported HTML wrapped in CDATA:

```xml
<PAGE translate="true" tabify="0" title=""><![CDATA[<html …>…</html>]]></PAGE>
<USER_NOTES isDirty="false" tabify="0"><![CDATA[]]></USER_NOTES>
```

Two traps:

* The payload is HTML with void elements (`<meta>`, `<br>`) and plenty of `>`. A naive scanner that
  handles every `<!…>` form by scanning to the first `>` **truncates the CDATA block at the first
  HTML `>`** and then mis-parses the rest of the document. Handle `<![CDATA[` *before* the generic
  `<!` declaration branch and consume up to `]]>` — exactly what
  [`tools/schema_catalogue.py`](../tools/schema_catalogue.py) does.
* The content must be preserved as raw bytes. [`PKA_GENERATION.md`](PKA_GENERATION.md) deliberately
  exposes instruction text as bytes for this reason.

### 5.3 `xml.etree` accepts only 548 of 1,058 documents

Standard-library `xml.etree.ElementTree` (and any XML-1.0-validating parser) accepts only
**548 of the 1,058 corpus documents** — roughly half — because of §5.1. Any
toolchain that round-trips through `ElementTree`, `lxml` in validating mode, or `minidom` will
silently drop or reject a large fraction of real files.

### 5.4 The correct acceptance criterion

> A Packet Tracer document is one with a **`PACKETTRACER*` root element that re-encodes
> byte-exactly** — not "well-formed XML".

In practice this means a non-validating, control-character-tolerant, **span-preserving** parser:
[`pkt_core.xml`](../src/pkt_core/xml/__init__.py) keeps each node's exact source bytes and
`XmlNode.to_bytes` returns them verbatim while the node is untouched, so
`encode(decode(f)) == f` holds byte-for-byte on **all 1,058 corpus documents**
([`CORPUS_VERIFICATION.md`](CORPUS_VERIFICATION.md)).

### 5.5 Names are not unique keys

Element names repeat across unrelated contexts (`NODE` is both the grading tree and the physical
workspace tree; `LINE` is both CLI config text and a canvas drawing; `NAME`/`ID`/`VALUE` appear
under eight different parents). Schema lookups must be **(parent, name)** pairs — see §3.1.

---

## 6. Coverage — what `pkt_core.models` types

| Layer | Element names | Share |
| --- | ---: | ---: |
| Typed by [`pkt_core.models`](../src/pkt_core/models/) | **244** | 19.0% |
| Not typed — preserved verbatim | **1041** | 81.0% |
| **Total distinct names in corpus** | **1,285** | 100% |

Unmodelled names are **never dropped**. They surface in each model's `extra_fields` catch-all
([`src/pkt_core/models/base.py`](../src/pkt_core/models/base.py)) as raw `XmlNode`s, and the
span-preserving tree ([`src/pkt_core/xml`](../src/pkt_core/xml/__init__.py)) keeps their exact
source bytes so untouched subtrees re-serialise byte-exactly.

**Typed names per family:**

| Family | Names | Modelled | Coverage |
| --- | ---: | ---: | ---: |
| Document skeleton and roots | 46 | 11 | 24% |
| Devices, engines, modules, slots and ports | 169 | 44 | 26% |
| Links and cables | 20 | 10 | 50% |
| IP, VLAN and interface configuration | 194 | 37 | 19% |
| Wireless, RF and Bluetooth | 94 | 28 | 30% |
| Canvas placement, coordinates and clusters | 49 | 19 | 39% |
| Canvas drawing and notes | 60 | 23 | 38% |
| Activity grading, instructions and variables | 28 | 15 | 54% |
| File store and filesystem | 38 | 10 | 26% |
| IoT, MCU and the simulation environment | 74 | 23 | 31% |
| Physical workspace and racks | 9 | 0 | 0% |
| Script modules, user apps and licensing | 82 | 4 | 5% |
| Device application services | 196 | 0 | 0% |
| Lab options and application UI | 79 | 19 | 24% |
| Multiuser, IPC and external connectivity | 33 | 1 | 3% |
| Simulation PDUs and scenarios | 17 | 0 | 0% |
| SOHO home-router and modem features | 50 | 0 | 0% |
| Cloud-managed networking (Meraki / NETCON) | 47 | 0 | 0% |
| **Total** | **1,285** | **244** | **19.0%** |

**The 19 model classes and the names each claims**
(`_claimed` in [`src/pkt_core/models`](../src/pkt_core/models/); a name claimed by two classes is
counted once in the totals above):
* **Lab** (lab.py) — 9 names: `CLUSTERS`, `MOVIEBANK`, `NETWORK`, `OPTIONS`, `PHYSICALWORKSPACE`, `PIXMAPBANK`, `SCENARIOSET`, `SCRIPT_MODULE`, `VERSION`
* **Network** (lab.py) — 2 names: `DEVICES`, `LINKS`
* **LabOptions** (lab.py) — 20 names: `ANIMATION`, `BACKGROUNDS`, `CONFIGPATH`, `DOCK`, `HIDEATTRIBUTES`, `HIDECLIOFROUTERANDSWITCH`, `HIDECONFIG`, `HIDECONFIGOFROUTERANDSWITCH`, `HIDEPHYSICAL`, `HIDESERVICES` … (+10)
* **Cluster** (lab.py) — 6 names: `CLUSTERID`, `CLUSTER_BG_IMAGE`, `CLUSTER_EMBEDDED_BG_IMAGE`, `CLUSTER_ICON_IMAGE`, `NAME`, `TILED_BG`
* **RunningConfig** (lab.py) — 1 name: `LINE`
* **Device** (network.py) — 2 names: `ENGINE`, `WORKSPACE`
* **Module** (network.py) — 5 names: `MODEL`, `MODULE`, `PORT`, `SLOT`, `TYPE`
* **Port** (network.py) — 18 names: `AUTONEGOTIATEBANDWIDTH`, `AUTONEGOTIATEDUPLEX`, `BANDWIDTH`, `BIA`, `CHANNEL`, `CHANNEL5GHZ`, `CLOCKRATE`, `CLOCKRATEFLAG`, `COVERAGERANGE`, `DESCRIPTION` … (+8)
* **Workspace** (network.py) — 3 names: `LOGICAL`, `PHYSICAL`, `PHYSICAL_CPUR`
* **Link** (network.py) — 2 names: `CABLE`, `TYPE`
* **Cable** (network.py) — 11 names: `FROM`, `FROM_DEVICE_MEM_ADDR`, `FROM_PORT_MEM_ADDR`, `FUNCTIONAL`, `GEO_VIEW_COLOR`, `LENGTH`, `PORT`, `TO`, `TO_DEVICE_MEM_ADDR`, `TO_PORT_MEM_ADDR` … (+1)
* **PortConfig** (schema.py) — 39 names: `DEFAULT_GATEWAY`, `DHCPV6_CLIENT`, `DHCPV6_ENABLED`, `DHCP_CLIENT`, `DHCP_ENABLED`, `DHCP_SERVER`, `DHCP_SERVERS`, `DHCP_SERVER_IP`, `DNS`, `DNS_CLIENT` … (+29)
* **WirelessConfig** (schema.py) — 23 names: `ALLOW_ACCESS`, `AUTHEN_TYPE`, `BEAMFORMING_ENABLE`, `CURRENT_PROFILE`, `ENCRYPT_TYPE`, `MAC_FILTER_ENABLED`, `NETWORK_MODE`, `NETWORK_TYPE`, `PROFILES`, `RADIO_BAND` … (+13)
* **DeviceDetails** (schema.py) — 24 names: `BIOS_VERSION`, `BUILD_IN_ADDR`, `COORD_SETTINGS`, `CUSTOM_INTERFACE`, `CUSTOM_VARS`, `DESKTOP_APPS`, `EXT_ATTRIBUTES`, `FIRMWARE_VERSION`, `Firmware_Version`, `IGNORED_VERSION` … (+14)
* **FileEntry** (schema.py) — 14 names: `CONFIGURED_FILENAME`, `DATE_TIME`, `FILE`, `FILES`, `FILE_CONTENT`, `FILE_COUNTER`, `FILE_NUMBER`, `FILE_PATH`, `FILE_SIZE`, `IS_BOOTABLE` … (+4)
* **ScoringNode** (schema.py) — 7 names: `CHECK_TYPE`, `COMPONENTS`, `ID`, `NAME`, `NODE`, `POINTS`, `VALUE`
* **EnvironmentOption** (schema.py) — 16 names: `ACTIVE`, `CATEGORY`, `CATEGORY_ID`, `ENVIRONMENT_OPTION`, `IMPERIAL_CONVERSION_FORMULA`, `IMPERIAL_UNIT`, `INTERPOLATE`, `MAX`, `MAX_RATE`, `METRIC_CONVERSION_FORMULA` … (+6)
* **CanvasShape** (schema.py) — 41 names: `BottomRightX`, `BottomRightY`, `COLOR`, `Color`, `D`, `EndX`, `EndY`, `FILL_COLOR`, `FILL_FLAG`, `Filled` … (+31)
* **ActivitySection** (schema.py) — 16 names: `CLEAN_ACTIVITY`, `COMPONENTS`, `ID`, `INSTRUCTION_DIALOG`, `IP_POOLS`, `LOAD_INIT_TREE`, `NAME`, `NODE`, `NUMBER_POOLS`, `PAGE` … (+6)

One claimed name, `CHECK_TYPE`, does not occur as an element name in the corpus (it is the
`checkType` attribute of `NAME`, §4.1); every other claimed name is present. The remaining
1,041 corpus names — from `DEVICE_TYPE` (270,393 occurrences) down
to one-off DTO serialisations — are covered by `extra_fields` only.

---

## 7. Provenance and reproduction

Every number in this document comes from one of:

1. [`docs/schema_catalogue.json`](schema_catalogue.json) — regenerable with:

   ```console
   $ python3 tools/schema_catalogue.py --index corpus/CORPUS_INDEX.tsv \
       --dir corpus/internet --out docs/schema_catalogue.json
   ```

   which reports `documents scanned : 1058  (skipped 0)`, `families : {'modern': 865, 'legacy': 193}`,
   `distinct elements : 1285`, `modelled : 244`.
2. [`src/pkt_core/xml/__init__.py`](../src/pkt_core/xml/__init__.py) — the well-formedness survey
   (510 / 392 / 64 files, `ElementTree` 548/1,058).
3. [`docs/CORPUS_VERIFICATION.md`](CORPUS_VERIFICATION.md) — byte-exact round-trip proof
   (1,058/1,058) and the 210/400 modern-sample well-formedness measurement.
4. [`docs/FORMAT_SPECIFICATION.md`](FORMAT_SPECIFICATION.md), [`docs/SCENE_GRAPH.md`](SCENE_GRAPH.md),
   [`docs/ACTIVITY.md`](ACTIVITY.md), [`docs/PKA_GENERATION.md`](PKA_GENERATION.md) — semantics
   cited where the catalogue only records structure.

Family assignment is a documented classification of catalogue data, not a Packet Tracer
construct; where the corpus itself overloads a name, §3.1 records the parent breakdown verbatim.
