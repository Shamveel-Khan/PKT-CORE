# Packet Tracer labs, rebuilt offline

> **Made by Shamveel.** Create Packet Tracer `.pkt` labs and scored `.pka` activities entirely offline, without installing Packet Tracer.

This project reverse-engineers the Packet Tracer container format and provides a byte-exact codec plus a Python generator for devices, modules, cabling, IOS config, PC IPs, instructions, activity passwords, and scoring data.

[![PyPI - Version](https://img.shields.io/pypi/v/pkt-core.svg)](https://pypi.org/project/pkt-core/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![No Packet Tracer needed](https://img.shields.io/badge/Packet_Tracer-not_required-32d74b.svg)](#quick-start)
[![Cisco Packet Tracer](https://img.shields.io/badge/Cisco_Packet_Tracer-1BA0D7?style=flat&logo=cisco&logoColor=white)](#overview)

> **`pkt-core v0.2.0` is published on PyPI**: [https://pypi.org/project/pkt-core/](https://pypi.org/project/pkt-core/)

## Overview

Packet Tracer files have no plain-text magic header and are fully encrypted containers, making offline analysis and generation challenging. `pkt-core` reverse-engineers the container formats and provides a production-ready Python SDK and byte-exact codec.

With `pkt-core`, you can **programmatically generate, modify, and inspect complete Packet Tracer `.pkt` network labs and scored `.pka` activities entirely offline**—without installing Cisco Packet Tracer and without manually constructing the underlying XML structure or cryptographic containers.

## Highlights

* **Offline Generation:** Build `.pkt` labs and scored `.pka` activities directly in Python with zero external dependencies beyond Python.
* **No XML or Crypto Boilerplate:** Bundled templates, seeds, and Twofish-EAX ciphers are managed automatically.
* **Convenient Public API:** High-level `Lab` builder with intuitive device placement, cabling, module bay management, and IOS configuration.
* **Lossless Inspection & Diffing:** Parse existing files into typed Pydantic models with `open_lab()` and semantically diff topologies with `diff_labs()`.
* **Byte-Exact Codec:** Proven 100% round-trip fidelity on 1,058 real-world Packet Tracer files.
* **CLI Included:** Inspect, unpack, pack, audit, and export labs via the `pkt` command-line utility.

## Installation

Install the published package from PyPI:

```bash
pip install pkt-core
```

> [!NOTE]
> **Package vs Import Name:**
> * Distribution name (for `pip`): **`pkt-core`** (`pip install pkt-core`)
> * Import module name (in Python): **`pkt_core`** (`from pkt_core import Lab`)

No native compilers or Packet Tracer installations are required. Pure-Python crypto fallbacks are bundled out-of-the-box. (Optional: `pip install pkt_core_native` provides an accelerated Rust backend).

## Quick Start

### 1. Create a Topology Programmatically

Generate a complete `.pkt` file with a router and switch connected via copper ethernet in just 5 lines:

```python
from pkt_core import Lab

lab = Lab()
lab.add_device("R1", "Router_2901")
lab.add_device("SW1", "Switch_2960")
lab.connect("R1", "GigabitEthernet0/0", "SW1", "FastEthernet0/1")
lab.export("my_lab.pkt")
```

### 2. Configure Hardware, Modules, and IOS Configuration

The SDK handles physical rack slots, canvas layouts, Cisco IOS CLI startup/running configs, and PC IP configurations seamlessly:

```python
from pkt_core import Lab

# Initialize a clean lab (bundled templates and seed XML load automatically)
lab = Lab()

# Place a Cisco router with an installed serial module and IOS running configuration
r1 = lab.add_device(
    model="2911",
    name="R1",
    x=200,
    y=250,
    install="HWIC-2T",
    ios_config=[
        "hostname R1",
        "interface GigabitEthernet0/0",
        " ip address 192.168.1.1 255.255.255.0",
        " no shutdown",
        "end",
    ],
)

# Place a switch and an end-user workstation
sw1 = lab.add_device("2960-24TT", "SW1", x=400, y=250)
pc1 = lab.add_device(
    model="PC-PT",
    name="PC1",
    x=600,
    y=250,
    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"),
)

# Connect interfaces using copper cables
lab.connect(r1, "GigabitEthernet0/0", sw1, "GigabitEthernet0/1")
lab.connect(sw1, "FastEthernet0/1", pc1, "FastEthernet0")

# Export directly to a .pkt container (sealed with Twofish-EAX AEAD)
lab.export("my_lab.pkt")
```

Open `my_lab.pkt` directly in Cisco Packet Tracer — all devices, physical rack placements, cables, and IOS configurations load immediately!

### 3. Open and Inspect Existing Labs

Read and inspect devices, links, IP addresses, and configs without Packet Tracer:

```python
from pkt_core import open_lab

lab = open_lab("my_lab.pkt")
print(f"Loaded lab version: {lab.version}")

for dev in lab.devices:
    print(f"Device: {dev.name} ({dev.model}) at position {dev.position}")
    for port in dev.ports:
        print(f"  Port: {port.name} [{port.type}]")

for link in lab.links:
    print(f"Link: {link.cable_type} connecting ports {link.port_names}")
```

## Public SDK API Reference

The `pkt_core` package exports a clean, type-annotated public API:

| Export | Type | Description |
|---|---|---|
| `Lab` / `LabBuilder` | Class | High-level builder to create topologies, add devices, install modules, connect cables, apply IOS config, and export `.pkt` containers. |
| `Activity` / `ActivityBuilder` | Class | Author scored `.pka` activities with instructions (HTML), time limits, wizard password, and comparison trees. |
| `Layout` | Class | Layout engine providing collision-free grid placement and semantic tier bands. |
| `open_lab(path)` | Function | Decode and parse any `.pkt` or `.pka` file into typed Pydantic models ([`LabView`](src/pkt_core/models/lab.py)). |
| `diff_labs(lab_a, lab_b)` | Function | Perform semantic difference comparison between two lab files. |
| `export(lab, format)` | Function | Render topology for external network tooling (`graphviz`, `containerlab`, `netbox`). |
| `decode(path)` / `encode(path, xml)` | Function | Container codec for direct Twofish-EAX / qCompress reading and writing. |
| `pkt_core.resources` | Module | Cached loaders for bundled data assets (`load_bundled_templates`, `load_bundled_seed_xml`, `load_bundled_device_shapes`, `load_bundled_activity_skeleton`). |

### Bundled Resources

The SDK packages **137 device templates**, **78 module templates**, a base network seed, and activity wizard skeletons directly inside the distribution wheel. When calling `Lab()`, these assets are loaded automatically from the package namespace (`pkt_core/data/`) with zero file-path configuration required.

## Working Examples

Full runnable example scripts are available in the [`examples/`](examples) directory:

* [`examples/basic_topology.py`](examples/basic_topology.py): Router, switch, and PC topology with IP configuration, copper cabling, and export.
* [`examples/serial_connection.py`](examples/serial_connection.py): Back-to-back router topology with installed `HWIC-2T` serial modules, DCE clock rates, and `/30` subnets.
* [`examples/scored_activity.py`](examples/scored_activity.py): Scored Packet Tracer activity (`.pka`) with student instructions, automated scoring tree, and wizard password.

## CLI Usage

The `pkt` CLI tool is available immediately after installation:

```console
$ pkt info my_lab.pkt
$ pkt audit my_lab.pkt
$ pkt unpack my_lab.pkt -o unpacked_lab/
$ pkt pack unpacked_lab/ -o repacked.pkt
$ pkt diff before.pkt after.pkt
$ pkt export my_lab.pkt --format graphviz
```

## Library Architecture

| Subpackage / Module | Responsibility |
| --- | --- |
| `pkt_core.builder` | `Lab`, `Activity`, and `Layout` engines for generating new labs and scored activities. |
| `pkt_core.codec` | Verifier-based container detection, Twofish-EAX sealing/opening, and Qt `qCompress` wrappers. |
| `pkt_core.crypto` | Pure-Python ciphers (`ciphers_pure.py`), primitive EAX/CMAC/CTR routines, and key schedules. |
| `pkt_core.data` | Bundled device templates (`device_templates.json`), network seed XML, and activity skeletons. |
| `pkt_core.models` | Typed Pydantic inspection models for devices, ports, links, services, and IOS running-config. |
| `pkt_core.resources` | Cached asset loaders for embedded package data. |
| `pkt_core.cli` | Command-line interface (`pkt info`, `unpack`, `pack`, `diff`, `export`, `audit`). |
| `pkt_core.xml` | Lossless XML document preservation engine. |

## Project Structure

* `src/pkt_core/` — Reusable, pip-installable Python SDK.
* `examples/` — Complete, runnable SDK usage scripts.
* `tests/` — Automated test suite (112+ unit and integration tests).
* `tools/` — Developer utilities and legacy migration shims.
* `corpus/` — Verification corpus manifest and sample files.

## Notes

* The model layer preserves untouched XML bytes when repacking.
* Format detection relies on container validation rather than a magic prefix.
* Sample containers generated by this project are committed so the tests run out of the box.

## Made by Shamveel

Rebranded by Shamveel.

## Status / scope

**Both container families are fully decoded, both directions.**
`encode(decode(f)) == f` **byte-for-byte on 1058 of 1058 real containers** — see
[`docs/CORPUS_VERIFICATION.md`](docs/CORPUS_VERIFICATION.md).

| Family | Written by | Transform | Files verified |
| --- | --- | --- | --- |
| **modern** | PT **5.3.3** → 9.0.1 | layer A → Crypto++ EAX (Twofish) → layer B → qCompress | 865 |
| **legacy** | PT **4.1** → 5.3.2 | layer B → qCompress *(no AEAD, no reversal)* | 193 |

* The AEAD authentication tag is reproduced exactly and verified on load.
* Verified against **Packet Tracer 9.0.1.0858** (Linux x86-64) and 1,058 real
  files spanning **PT 4.1 through PT 9.0.1**.
* **Neither family has a magic header.** Detection is verifier-based: the EAX tag
  for the modern family (false-positive rate 2⁻¹²⁸), a structural qCompress probe
  for the legacy one. The container switchover is exactly 5.3.2 → 5.3.3.
* Documents are **not always well-formed XML** — `<LINE>` config text carries raw
  control bytes (the Cisco `banner motd ^C…^C` delimiter is a literal `\x03`) and
  PT 4.1 documents end with a trailing NUL. Do not use a validating parser.
* Three root elements exist: `PACKETTRACER5`, `PACKETTRACER5_ACTIVITY` and
  `PACKETTRACER_ACTIVITY` (PT 4.x). Root element is **not** a container
  discriminator.
* `.pkt`/`.pka` are fully supported. The `.pta`/`.pkc` (Serpent) and internal
  `sm`/`userapp` (CAST-256) flavours are specified but need a crypto backend
  with Serpent/CAST-256 (stock `libgcrypt` has neither).

## How it was found

Static analysis of the fully-symbolized `PacketTracer` binary located
`CNetworkFile::openFile`, the `Util::encrypt*/decrypt*` family, the generic
`Util::cipher/decipher<Cipher>` templates, and Crypto++'s `EAX_Base` /
`AuthenticatedDecryptionFilter`.  Packet Tracer was then run headless under
`Xvfb` with `gdb` breakpoints to capture the exact ciphertext and plaintext,
which pinned the CTR counter and both obfuscation layers with byte-accurate
certainty.

## Generating files

Because encoding is byte-exact, the same codec **writes** `.pkt` files.  Tools in
[`tools/`](tools) and notes in [`docs/SCENE_GRAPH.md`](docs/SCENE_GRAPH.md):

* `tools/harvest_merge.py` — harvest one complete device of every model from a
  tree of existing `.pkt` files and merge them into one canvas, handling the
  physical-workspace remapping PT requires.
* `tools/build_wired_lab.py` — the same, **plus auto-wiring**: cables every
  ethernet-capable device to a backbone of core switches and chains the cores.
* `tools/build_configured_lab.py` — a full **working, configured** lab
  (`PC1－SW1－R1＝R2－SW2－PC2` with IPs, gateways, static routes, and an optional
  long running-config).  IOS config is written as `<RUNNINGCONFIG><LINE>…`
  commands and applied on load; PCs get `<IP>/<SUBNET>/<PORT_GATEWAY>`.  See
  [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).
* `tools/activity.py` + `tools/scoring.py` — author **activity files (`.pka`)** with the Activity Wizard: instructions (HTML), the **activity-wizard password**, permissions, feedback, the **initial / answer networks**, and the **scoring tree**.  See [`docs/ACTIVITY.md`](docs/ACTIVITY.md).
* `tools/make_scored_lab.py` — **one-shot offline generator**: from a topology spec (`--spec`) it builds the initial + answer networks, derives scoring, and writes a scored `.pka`.  No Packet Tracer needed.  Ships with a library of **137 device templates, 75 module templates and 14 scoring shapes** (`tools/device_templates.json`, `tools/device_shapes.json`).
* `tools/harvest_library.py` — (re)build those libraries from your own `.pkt`/`.pka` files to extend model/shape coverage.
* `tools/lab_api.py` — a small library of the **verified authoring operations**
  (place device, power on/off, install a module, cable copper, write IOS
  `RUNNINGCONFIG`, set PC IP/DHCP).  Capability matrix + details in
  [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md).
* Editing: decode → change device names/config/positions → encode → PT opens it.

Result of running the wired builder here: **147 devices, 140 distinct models,
71 cables** (routers, switches, ASAs, WLCs, APs, IP phones, PCs/laptops/tablets,
servers, and a large IoT/industrial set) in one file that Packet Tracer opens
and draws connected.

Key facts for anyone generating files (details in the scene-graph notes):

* Devices carry a *physical scene* placement that must be remapped when merging.
* A cable binds by `<FROM>`/`<TO>` ids and `<PORT>` names; the device needs an
  `<ENGINE>/<SAVE_REF_ID>` and the port must exist on that exact instance.  The
  `*_MEM_ADDR` fields are not validated — PT rebinds.

## Legal / ethical

* Interoperability research on a file format, using a locally installed copy of
  Packet Tracer and the author's own files.
* No DRM or licence protection is bypassed; there is no encryption password.
* Intended for reading *your own* files, format documentation, tooling and
  archival.
* **Do not** use this to obtain, alter, or submit assessment/competition answer
  keys.  That is cheating and is out of scope.

