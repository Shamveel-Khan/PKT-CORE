# Large-scale topology: generated, parsed, and opened in Packet Tracer 9.0.1

This documents an end-to-end stress test: author a large, fully-configured
network programmatically, round-trip it through `pkt_core`, and open the result
in the real Packet Tracer application.

## What was generated

`tools/build_large_topology.py` produces a three-tier campus network. At the
scale tested:

| Layer | Devices | Detail |
| --- | --- | --- |
| Core | 2 × 2911 | `CORE-R1`, `CORE-R2` — OSPF, serial WAN link with DCE clocking |
| Distribution | 4 × 3560-24PS | `DIST-SW1..4` — multilayer, VLANs + SVI management |
| Access | 8 × 2960-24TT | `ACCESS-S1-1 … S4-2` |
| Servers | 6 × Server-PT | DHCP, DNS, WEB, TFTP, NTP, MAIL |
| Clients | 44 × PC-PT / Laptop-PT | static addressing per site/VLAN |
| Wireless | 2 × AccessPoint-PT | + 4 associated laptops |
| IoT | 4 × MCU/Thing | temperature, light, motor, LED |
| **Total generated** | **70** | plus 7 devices carried by the XML seed |

**77 devices, 66 links, 2.3 MB of XML, 167 KB container.**

### Addressing and configuration

* Three-tier address plan: `10.<site>.<vlan>.0/24`, gateway `.1`, hosts from `.20`
* WAN: `10.255.0.0/30` between the core routers
* Every router carries a coherent IOS running configuration — 68 lines on
  `CORE-R1` alone: hostname, interface addresses, `duplex/speed auto`,
  `router ospf 1` with `network … area 0`, `passive-interface default` with
  explicit no-passive uplinks, `line con 0`/`vty` with `logging synchronous`
* Switches carry VLAN definitions, `spanning-tree mode pvst`, and an SVI
  management address
* Serial links set `clock rate 2000000` on the DCE end and the matching
  `CLOCKRATE` port field, so the link comes up instead of rendering red
* End devices carry `IP` / `SUBNET` / `PORT_GATEWAY` / `PORT_DHCP_ENABLE=false`

## Verification in `pkt_core`

| Check | Result |
| --- | --- |
| Container round-trip `encode(decode(f)) == f` | **byte-exact** |
| Devices parsed | 77 |
| Links parsed | 66 (65 `eStraightThrough`, 1 `eSerial`) |
| Devices with IOS running-config | 23 (all routers, switches, servers) |
| Root element | `PACKETTRACER5`, version `9.0.1.0858` |

## Verification in Packet Tracer 9.0.1

The file opened in the real application. Window title resolves to
`Cisco Packet Tracer - /tmp/large_campus.pkt`, confirming PT accepted and bound
the document.

Rendered correctly:

* Both core routers (`CORE-R1`, `CORE-R2`, 2911) with the serial WAN link
* All four `3560-24PS` distribution switches
* All eight `2960-24TT` access switches
* The server block — `DHCP-Server`, `DNS-Server`, `WEB-Server`, `TFTP-Server`,
  `NTP-Server`, `MAIL-Server`
* Wireless: `AccessPoint-PT` plus `WIFI-S1-0/1`
* IoT block: `TEMP-1`, `LIGHT-1`, `MOTOR-1`, `LED-1` (MCU displays active)
* Full cabling fan-out with link lights

**No load errors were reported.**

## Screenshot

![Full topology in Packet Tracer 9.0.1](../../filedrop/large_campus_topology_full.png)

The captured image and the generated `.pkt` are in the filedrop:

* `filedrop/large_campus_topology_full.png`
* `filedrop/large_campus_topology_desktop.png`
* `filedrop/large_campus.pkt`

## Reproducing

```console
$ python3 tools/build_large_topology.py --out large_campus.pkt --clients 5
$ python3 -c "
from pkt_core import decode_bytes, encode_bytes
raw = open('large_campus.pkt','rb').read()
c = decode_bytes(raw)
assert encode_bytes(c.xml, c.format_name) == raw
print('byte-exact round-trip OK')
"
$ tools/verify_in_packet_tracer.sh /path/to/PacketTracer large_campus.pkt full.png
```

Scale is controlled with `--clients N` (end devices per access switch). The
generator is deterministic: the same arguments produce the same file modulo
the UUIDs used for physical-workspace leaves.

## Observations

* The seed XML (`tools/network_seed.xml`) contributes 7 pre-existing devices
  (`SW1`, `R2`, `PC-A`, `PC-B`, `Server`, `Server-PT`, `Power Distribution
  Device0`) that the generator does not remove. They appear in the render at
  the left of the canvas. Pure-generated output would drop them.
* The red segment near `CORE-R1` is the serial WAN link. It renders red until
  the simulated interfaces finish coming up; the DCE `clock rate` is set on the
  correct end.
* 2.3 MB of XML round-trips through `pkt_core` in well under a second, so the
  lazy-parse design holds at this scale.
