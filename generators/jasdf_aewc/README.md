# JASDF AEW&C Enterprise — JADGE Network Model

A large, fully-configured Cisco Packet Tracer model of a Japan Air Self-Defense
Force (JASDF) Airborne Early Warning & Control (AEW&C / AWACS) enterprise,
generated entirely from code.

| | |
| --- | --- |
| **Deliverable** | `out/JASDF_AEWC_JADGE.pkt` — 290 devices, 326 links, 1.13 MB |
| **Profiles** | `smoke` (134) · `standard` · `enterprise` (290) |
| **Routing** | OSPF multi-area (area 0 backbone + per-site stub areas), iBGP AS65001, eBGP AS65002 |
| **Configuration** | 205 devices carry a full IOS/ASA running-config — 22,896 `<LINE>` elements, of which 22,648 are on the 143 IOS/ASA devices (selected by model, not by the presence of a `<STARTUPCONFIG>` element) |
| **Services** | 496 DNS records (248 zones × 2 servers) · 131 DHCP pools · 139 RADIUS clients · NTP · syslog · SNMPv2c · TFTP · HTTPS · PKI · NetFlow |
| **Verified** | byte-exact container round-trip, every cabled port attested, every printed count proven distinct, **opens in Packet Tracer 9.0.1 with no load errors** |
| **Reproducible** | `./run_all.sh enterprise` rebuilds `out/JASDF_AEWC_JADGE.pkt` byte-for-byte — the build contains no randomness |

![Verified in Packet Tracer 9.0.1](docs/img/packet_tracer_verified.png)

*Packet Tracer 9.0.1 with the generated lab open — green link indicators
throughout, serial datalink bearers up (drawn red by PT's serial cable style).*

---

## Architecture at a glance

![Topology](docs/img/topology_overview.png)

Thirteen operational tiers, modelled on the real JASDF air-defence system:

| Tier | Devices | What it models |
| --- | ---: | --- |
| AEW&C airborne platforms | 74 | 4× E-767 AWACS, 6× E-2D, 4× E-2C, 2× RC-2 — each a flying LAN |
| Fixed radar sites | 56 | 16 named J/FPS-3/-5/-7 sites from Wakkanai to Yonaguni |
| Air bases | 60 | 10 bases with distribution/access switching and WLAN |
| Control & Reporting Centers | 32 | Misawa, Iruma, Kasuga, Naha — dual C2 routers + HSRP |
| JADGE core data centre | 25 | 21-service server farm behind a firewall |
| Tactical datalink / SATCOM | 10 | Link-16 and X/Ku-band ground-entry serial concentrators |
| Air Defense Command HQ | 9 | Yokota AB — commander, ops, intel, liaison, COP |
| NOSC management enclave | 6 | jump host, NMS, cyber observer, packet tap |
| JADGE backbone transport | 6 | dual collapsed core + core routers + WAN edges |
| Security appliances | 4 | ASA 5505 zone firewalls |
| Regional WAN aggregation | 4 | NORTH / CENTRAL / WEST / SW hubs |
| Coalition partner | 4 | allied AS65002 boundary with IPsec |
| | **290** | |

Full detail: **[docs/DESIGN.md](docs/DESIGN.md)**.

---

## Quick start

```console
$ git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
$ cd packet-tracer-pkt-format && python3 -m venv .venv && . .venv/bin/activate
$ pip install -e . pytest pydantic

$ cd /path/to/jasdf-aewc
$ python build_jasdf_aewc.py --profile enterprise --out out/JASDF_AEWC_JADGE.pkt
$ python validate.py out/JASDF_AEWC_JADGE.pkt
$ python tools/draw_topology.py out/JASDF_AEWC_JADGE.pkt docs/img/topology.svg
$ python tools/export_plan.py out/JASDF_AEWC_JADGE.pkt
```

Then open `out/JASDF_AEWC_JADGE.pkt` in Packet Tracer 9.x.

> **First-open note.** Packet Tracer runs spanning-tree convergence after loading
> a file with many switches, so some access ports show *amber* link lights for
> the first ~30 s. This is documented Cisco behaviour, not a fault. Toggling
> between Realtime and Simulation mode 3–4 times clears it immediately.

---

## Repository layout

```
build_jasdf_aewc.py        topology generator + CLI (the model itself)
jasdf_kit.py               IOS / ASA running-config generators and
                           Server-PT service injection
validate.py                structural + evidence validation of a built .pkt
tools/
  build_port_model.py      derives allowed port names per model from evidence
  draw_topology.py         renders the tier-coloured architecture diagram
  export_plan.py           as-built address plan, subnets, VLANs, services
  mine_corpus.py           mines the reference corpus for port/config evidence
  serial_probe.py          minimal 2-router serial-link probe
  stp_probe.py             isolates STP/portfast behaviour per option
docs/
  DESIGN.md                full architecture specification
  VALIDATION.md            what was checked, how, and what it proves
  EVIDENCE.md              where every format/port/config fact came from
  INVENTORY_enterprise.csv every device with role and management address
  ADDRESS_PLAN.csv         622 addressed interfaces
  SUBNETS.csv              335 subnets
  VLANS.csv                the VLAN plan
  SERVICES.md              DNS zone, DHCP pools, AAA clients
  img/                     topology diagram + Packet Tracer screenshots
out/
  JASDF_AEWC_JADGE.pkt     the deliverable
```

---

## Scale profiles

```console
$ python build_jasdf_aewc.py --profile smoke      # 134 devices — fast iteration
$ python build_jasdf_aewc.py --profile standard   # regional subset
$ python build_jasdf_aewc.py --profile enterprise # 290 devices (default)
```

| Profile | AWACS | E-2D | E-2C | RC-2 | Radar | Air bases | Consoles |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| smoke | 1 | 1 | 1 | 0 | 4 | 3 | 1 |
| standard | 2 | 3 | 2 | 1 | 10 | 6 | 2 |
| enterprise | 4 | 6 | 4 | 2 | 16 | 10 | 3 |

---

## Credentials

Worth knowing before you open the file, because one half is readable and the
other half is not.

**Readable in the artefact** — these were never hidden:

| What | Value |
| --- | --- |
| RADIUS shared key | `r4d1us-J4DG3-k3y` |
| SNMP read-only community | `JASDF-RO-9f3c` |
| SNMP read-write community | `JASDF-RW-1a7e` |
| HSRP authentication | `JASDF-HSRP` |
| Web portal login | `jasdf-web` / `W3b-P0rt4l` |

**Not recoverable from the artefact.** Every IOS/ASA device carries:

```
enable secret 5 $1$Jz8k$QbV3nR7dTpWmYc2LxH9uK1
username jasdf-admin privilege 15 secret 5 $1$Kp2s$Rt5Yh8Nq4WzXc6BmL3vJd0
```

Those are Cisco **type-5** (MD5-crypt) hashes. The plaintext was chosen when the
generator was written and was never recorded, so it cannot be recovered from the
delivered file — and 138 of the 143 devices run `aaa new-model` with
`aaa authentication login default group radius local`, which means their CLI tab
asks for a login.

**So you cannot log into a router in this lab from the artefact alone.** If you
want CLI access, either use Packet Tracer's **Config** tab (which needs no
authentication) and set a secret you know, or rebuild with your own credentials
by editing `ENABLE_SECRET` / `ADMIN_SECRET` in `jasdf_kit.py`.

For contrast: an earlier build also shipped `$1$mERr$A0KmwwybwYdjSTcVdJ15p0` on
16 routers — the type-5 hash of `cisco`, the publicly known default. That was not
authored; it was a harvested template's factory-default startup config, and it
has been removed.

---

## Licence

GNU General Public License v3.0 or later, matching the toolchain this package
builds on — see the
[packet-tracer-pkt-format](https://github.com/aacanadaa/packet-tracer-pkt-format)
repository. The generated `.pkt` is your own artefact.

Earlier releases of this package were distributed under PolyForm Noncommercial
1.0.0. That applied to those releases only.
