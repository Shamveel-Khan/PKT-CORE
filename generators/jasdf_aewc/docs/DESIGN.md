# JASDF AEW&C Enterprise — Architecture Specification

> Generated model. Everything in this document describes what
> `build_jasdf_aewc.py --profile enterprise` actually emits into
> `out/JASDF_AEWC_JADGE.pkt`; the addressing and inventory tables are exported
> from the built file (`tools/export_plan.py`), so they cannot drift from it.

---

## 1. Design basis

The model follows the real architecture of Japanese air defence as it is
publicly described, and maps it onto Packet Tracer's device set:

| Real system | Role | Modelled as |
| --- | --- | --- |
| 航空総隊 Air Defense Command (ADC), Yokota AB | strategic air-defence HQ | `ADC-HQ-*` site |
| 警戒管制団 Air Surveillance & Control Group, Iruma AB | air-surveillance and control group | `JADGE-DC-*` + `CRC-CENTRAL` |
| JADGE (自動警戒管制システム) | the air-defence ground environment: sensor fusion, track management, weapons assignment | `JADGE-C2-SVR`, `TRACK-FUSION-SVR`, `RADAR-FUSION-SVR`, `LINK16-GW-SVR` and the OSPF/BGP transport |
| 防空管制群 Control & Reporting Centers | four regional CRCs | `CRC-NORTH` (Misawa), `CRC-CENTRAL` (Iruma), `CRC-WEST` (Kasuga), `CRC-SW` (Naha) |
| 警戒管制レーダー fixed radar sites, J/FPS-3 / -5 / -7 | 28 fixed sites | 16 named sites, `RDR-<SITE>-*` |
| 警戒航空団 Airborne Warning & Control Group, Hamamatsu AB | AEW&C force | `E767-*`, `E2D-*`, `E2C-*`, `RC2-*` |
| Link-16 / TADIL-J | tactical datalink | `TDL-GW-0x` serial concentrators |
| X/Ku-band SATCOM (Kirameki) | beyond-line-of-sight reachback | `SATCOM-GW-0x` serial concentrators |

### Assumptions and abstraction choices

* **Airborne platforms are wired to the ground.** Packet Tracer has no
  radio-propagation model suitable for a 16-airframe datalink mesh, so each
  aircraft's Link-16 and SATCOM bearers are modelled as dedicated point-to-point
  **serial** links to ground-entry concentrators. This is the standard way to
  model a bearer of last resort in PT and, crucially, it makes the bearers
  *addressable and routable*, which a wireless association would not.
* **Radar heads are not simulated.** The radar itself is represented by the
  site's signal processor (`RDR-<SITE>-RSP`), which is the network-visible
  element. Radar video distribution is modelled with PIM/multicast config.
* **`J/FPS-7` at Yonaguni** reflects the newest site in the network; the exact
  radar type at each site is illustrative where public sources are ambiguous.
* **Squadron numbers** (601st/602nd) are not modelled — the model is
  infrastructure-oriented, not an order of battle.

---

## 2. Topology

### 2.1 Tiers and naming

Device names are systematic: `<FUNCTION>-<SITE>-<ROLE><n>`.

```
                       ┌──────────────────────────────────────────┐
   AIRBORNE            │  E767-01-MR  E767-01-SW  E767-01-MC  …   │  16 airframes
   (802.1Q LAN         │  mission router → onboard switch →       │  74 devices
    per airframe)      │  mission computer / WC console / AP      │
                       └───────────────┬──────────────────────────┘
                        Link-16 serial │ X/Ku SATCOM serial
                       ┌───────────────┴──────────────────────────┐
   DATALINK            │  TDL-GW-01…04      SATCOM-GW-01…04       │  10 devices
                       │  DATALINK-AGG-01/02                      │
                       └───────────────┬──────────────────────────┘
                              FW-TDL-DMZ │ (ASA 5505)
                       ┌───────────────┴──────────────────────────┐
   BACKBONE            │  JADGE-BB-SW-01/02  ←→  CORE-RTR-01/02   │  6 devices
                       │  WAN-EDGE-01/02                          │
                       └───┬────────┬────────┬────────┬───────────┘
             ┌─────────────┘        │        │        └─────────────┐
   REGIONAL  │ REG-HUB-NORTH  REG-HUB-CENTRAL  REG-HUB-WEST  REG-HUB-SW │ 4 devices
   HUBS      └───┬──────────────┬──────────────┬──────────────┬─────┘
                 │              │              │              │
   SITES    CRC-NORTH      CRC-CENTRAL      CRC-WEST       CRC-SW       4 × 8
            RDR-* (6)       RDR-* (3)        RDR-* (3)      RDR-* (4)    16 × 3–4
            AB-*  (3)       AB-*  (4)        AB-*  (2)      AB-*  (1)    10 × 6
                 │
   CORE SVC  FW-JADGE-CORE → JADGE-DC-CORE-01/02 → JADGE-DC-ACC-01/02 → 21 servers
             ADC-HQ-*  (Yokota)
             NOSC-*    (management enclave, behind FW-MGMT)
             COALITION-GW-01 → FW-COALITION → PARTNER-RTR-01 (AS65002)
```

### 2.2 Regional composition

| Region | Hub | CRC | Radar sites | Air bases |
| --- | --- | --- | --- | --- |
| NORTH | `REG-HUB-NORTH` | CRC-NORTH (Misawa) | Wakkanai, Nemuro, Shibetsu, Okushiri, Tobetsu, Ominato | Misawa, Chitose, Hyakuri |
| CENTRAL | `REG-HUB-CENTRAL` | CRC-CENTRAL (Iruma) | Sado, Wajima, Omaezaki | Hamamatsu, Iruma, Komaki, Komatsu |
| WEST | `REG-HUB-WEST` | CRC-WEST (Kasuga) | Tsushima, Iki, Sefuri | Kasuga, Nyutabaru |
| SW | `REG-HUB-SW` | CRC-SW (Naha) | Kumejima, Miyako, Yonaguni, Okinoerabu | Naha |

Each regional hub is dual-homed to **both** backbone switches; every site
router is dual-homed to its hub. The two backbone switches are joined by a
routed /30, so the OSPF topology is loop-free with fast reconvergence.

### 2.3 Site LAN pattern

Every site — CRC, air base, or aircraft — uses the same structure:

```
site router                                site switch (3560-24PS / 2960-24TT)
┌──────────────────────┐                   ┌──────────────────────────────┐
│ Gi0/0/0  /30 → hub   │                   │ Gi0/1 ── 802.1Q trunk ── Gi0/0/1
│ Gi0/0/1  ────────────┼─── trunk ────────►│ Gi0/2 ── (second router)     │
│  .10  VLAN 10 OPS    │                   │ Fa0/1  access VLAN 60 servers│
│  .20  VLAN 20 MISSION│                   │ Fa0/2  access VLAN 10 ops    │
│  .30  VLAN 30 VOICE  │                   │ Fa0/3… access per role       │
│  .40  VLAN 40 MGMT   │                   └──────────────────────────────┘
│  .50  VLAN 50 WIFI   │
│  .60  VLAN 60 SERVERS│   HSRP group = VLAN id, virtual IP = x.x.x.1
└──────────────────────┘   (primary priority 110, standby 100, preempt,
                            interface tracking on the uplink, −20 on failure)
```

Radar sites are the exception: the **IR1101** industrial router terminates the
WAN link on `GigabitEthernet0/0/0` and serves the sensor VLAN on
`interface Vlan1` (`10.<site>.80.0/24`) through its built-in four-port switch
(`FastEthernet0/0/1`), with an **IE-9320** industrial switch aggregating the
signal processor and operator console.

---

## 3. Addressing plan

| Block | Use |
| --- | --- |
| `10.0.0.0/16` | routed point-to-point backbone and WAN links, allocated as /30s |
| `10.10.0.0/16` | Air Defense Command HQ, Yokota AB (site id 10) |
| `10.11.0.0/16` | Air Surveillance & Control Gp / JADGE data centre, Iruma AB (site id 11) |
| `10.12 / 36 / 13 / 14` | the four CRCs (NORTH / CENTRAL / WEST / SW) |
| `10.26 … 10.35` | the ten air bases |
| `10.41 … 10.56` | the sixteen fixed radar sites |
| `10.50.0.0/16` | datalink / SATCOM ground-entry transport |
| `10.61 … 10.76` | the sixteen airframes, one site id per aircraft |
| `10.200.0.0/16` | NOSC out-of-band management enclave |
| `10.254.0.0/16` | coalition / exercise partner |
| `10.255.0.0/16` | loopbacks (router-ids, SNMP, NTP, TACACS source) |

Within a site, the **third octet is always the VLAN**:

| VLAN | Name | Purpose |
| ---: | --- | --- |
| 1 | NATIVE/RADAR | IR1101 radar-site LAN and default VLAN |
| 10 | OPS-TRACK | air-surveillance and weapons-control operator positions |
| 20 | MISSION-SYS | radar processors, track servers, mission computers |
| 30 | VOICE | voice / intercom |
| 40 | MGMT | in-band management, device SVIs, loopbacks |
| 50 | WIFI | wireless clients (base and airborne tablets) |
| 60 | SERVERS | server farm (JADGE data centre, CRC display servers) |
| 70 | TDL-DATALINK | tactical datalink transport |
| 80 | RADAR-SENSOR | radar sensor VLAN |
| 99 | BLACKHOLE | reserved |

So `CRC-NORTH-ASO-PC` is `10.12.10.20` with gateway `10.12.10.1` (the HSRP
virtual IP), and `RDR-YONAGUNI-RSP` is `10.56.80.20` with gateway `10.56.80.1`.

Exported tables: **[ADDRESS_PLAN.csv](ADDRESS_PLAN.csv)** (622 addressed
interfaces), **[SUBNETS.csv](SUBNETS.csv)** (335 subnets),
**[VLANS.csv](VLANS.csv)**.

---

## 4. Routing and switching

### 4.1 OSPF

* Area 0 is the backbone: both core routers, the WAN edges, both backbone
  switches, all four regional hubs, the datalink aggregation switches and the
  firewalls' outside links.
* Every site is its own **stub area**, numbered with the site id (area 10 for
  Yokota, area 12 for CRC-NORTH, area 41…56 for radar sites, area 61…76 for the
  airframes). The site router is the ABR: the WAN /30 sits in area 0, the site
  VLANs sit in the site area.
* `passive-interface default` with explicit `no passive-interface` on real
  adjacencies, `auto-cost reference-bandwidth 10000`, and
  `log-adjacency-changes detail` throughout.
* Airborne routers originate a default route into their area
  (`default-information originate`) and carry a static default toward the
  datalink gateway, so an aircraft that loses its primary bearer still has a
  path via SATCOM.

### 4.2 BGP

* **iBGP, AS 65001** — full mesh between `CORE-RTR-01/02`, `WAN-EDGE-01/02` and
  `ADC-HQ-RTR-01`, all peering on loopbacks with `update-source Loopback0`.
* **eBGP, AS 65002** — `COALITION-GW-01` peers with the allied
  `PARTNER-RTR-01`, advertising `10.254.0.0/24`. The coalition path is
  deliberately kept out of the OSPF domain: it is a policy boundary, and the
  cross-domain firewall sits on it.

### 4.3 Switching

* `rapid-pvst`, `portfast default`, `portfast bpduguard default`,
  `loopguard default`, and `root primary` for the served VLANs on the
  distribution switch at each site.
* VTP is disabled (`vtp mode transparent`) so VLAN databases are explicit and
  never synchronised from an unintended server.
* 802.1Q trunks are `nonegotiate` with an explicit `allowed vlan` list.
* Access ports carry `port-security` with sticky MAC learning (maximum 2–3) and
  `violation restrict`.

### 4.4 QoS

A single policy, `PM-JADGE-WAN`, is applied outbound on every WAN and datalink
interface:

| Class | Match | Treatment |
| --- | --- | --- |
| `CM-VOICE` | UDP 16384–32767 | `priority 512` |
| `CM-TRACK-DATA` | UDP 4000–4010, 4200 (Link-16 / TADIL-J) | `priority 2048`, `set dscp cs5` |
| `CM-JADGE-C2` | TCP 8443, 8080; UDP 5000–5010 | `bandwidth remaining percent 40`, DSCP WRED |
| `class-default` | — | `fair-queue`, WRED |

Track data outranks voice: in this architecture the weapon-quality track is the
most perishable traffic on the bearer.

---

## 5. Security architecture

### 5.1 Zones and firewalls

Four ASA 5505 appliances, each configured in the 5505's real idiom
(`Ethernet0/x` are switchports bound to VLANs; the routed interfaces are
`Vlan1`/`Vlan2`/`Vlan3` with `nameif` and `security-level`):

| Firewall | Outside | Inside | Purpose |
| --- | --- | --- | --- |
| `FW-JADGE-CORE` | `10.99.1.2/30` → `BB-SW-01` | `10.11.60.1/24` (server VLAN gateway) | protects the 21-service JADGE farm |
| `FW-TDL-DMZ` | `10.99.3.2/30` → `BB-SW-02` | `10.99.4.2/30` → `DATALINK-AGG-01`, `10.99.5.2/30` (dmz) → `DATALINK-AGG-02` | isolates the tactical datalink tier |
| `FW-COALITION` | `10.99.6.2/30` → `COALITION-GW-01` | `10.99.7.2/30` → `PARTNER-RTR-01` | cross-domain boundary |
| `FW-MGMT` | `10.99.8.2/30` → `MGMT-GW-01` | `10.200.40.1/24` | NOSC management enclave |

Each carries explicit inbound ACLs, `deny ip any any log` at the tail,
`inspect` policy on `global_policy`, SSH-only management restricted to
`10.200.0.0/16`, and local AAA. `FW-COALITION` additionally holds the IPsec
configuration (`ACL-VPN-COALITION`, `TS-JADGE` = ESP-AES-256/ESP-SHA-HMAC,
IKEv1 policy 10, peer `10.254.0.2`).

### 5.2 Management plane

* `access-class 90` on every vty line, permitting only `10.200.0.0/16` and the
  `10.0.0.0/8` operational space, denying everything else **with logging**.
* SSHv2 only (`transport input ssh`), `exec-timeout 5 0`,
  `ip ssh authentication-retries 3`, 2048-bit RSA keys generated at boot.
* Device administration authenticates against the RADIUS server
  (`aaa new-model`, `aaa authentication login default group radius local`,
  `aaa authorization exec/commands 15`, accounting start-stop) with a local
  fallback so the network survives loss of the AAA server.
* `enable secret` and per-role usernames are stored as type-5 hashes;
  `service password-encryption` is on.
* SNMPv2c with distinct RO/RW communities, `snmp-server enable traps`,
  syslog to `10.11.60.15` at `informational`, `logging buffered 16384 debugging`.
* `archive` writes the running-config to TFTP on every `write-memory`.
* No `ip http server`; `ip source-route`, gratuitous ARPs and BOOTP are off;
  `no ip bootp server`, `ip tcp synwait-time 10`.

### 5.3 Monitoring

`NOSC-CYBER-OBS` (Cyber Observer) provides behavioural anomaly detection,
`NOSC-TAP-SNIFFER` a packet-capture tap, `NETFLOW-SVR` an IPFIX collector, and
`SYSLOG-SVR` centralises logs from all 142 network devices.

---

## 6. Network services

All service configuration is written into the Server-PT device model, so it is
live when the file is opened — not documentation.

| Server | Address | Service actually configured |
| --- | --- | --- |
| `DNS-SVR`, `DNS-SVR-02` | `10.11.60.17/.18` | authoritative forward zone (248 A-records) |
| `DHCP-SVR` | `10.11.60.19` | 131 pools across every site VLAN and airframe |
| `NTP-SVR` | `10.11.60.14` | stratum-2 NTP with MD5 key 1 |
| `SYSLOG-SVR` | `10.11.60.15` | syslog collection |
| `AAA-SVR` | `10.11.60.16` | RADIUS (auth port 1645) + TACACS+, 139 clients |
| `TFTP-SVR` | `10.11.60.28` | FTP/TFTP account for config archive |
| `MISSION-WEB-SVR` | `10.11.60.29` | HTTP + HTTPS mission portal |
| `MAIL-SVR` | `10.11.60.30` | SMTP/POP3 relay for `jasdf.mod.go.jp` |
| `PKI-CA-SVR` | `10.11.60.31` | internal certificate authority (HTTPS) |
| `NETFLOW-SVR` | `10.11.60.32` | flow collection |
| `DATA-HISTORIAN` | `10.11.60.33` | track/mission data historian |
| `BACKUP-SVR` | `10.11.60.34` | nightly configuration backup |
| `JADGE-C2-SVR` | `10.11.60.21` | JADGE air-defence C2 processor |
| `TRACK-FUSION-SVR` | `10.11.60.22` | multi-sensor track fusion |
| `RADAR-FUSION-SVR` | `10.11.60.24` | radar plot extraction/fusion |
| `LINK16-GW-SVR` | `10.11.60.23` | Link-16 / TADIL-J gateway |
| `MISSION-PLAN-SVR`, `AIR-TASKING-SVR` | `.25`, `.26` | ATO/ACO planning and distribution |
| `COP-SERVER` | `10.11.60.27` | common operational picture |

Every site also has local servers: a track server and display/HMI server at each
CRC, a radar signal processor at each radar site, and a mission computer aboard
each aircraft. All are configured as syslog clients.

---

## 7. The airborne segment

This is the part that makes the model an **AEW&C** model rather than a campus.

Each airframe is a self-contained routed domain:

```
        Serial0/0/0 ──────────────► TDL-GW-0n        (Link-16 / TADIL-J, DCE clocked)
        Serial0/0/1 ──────────────► SATCOM-GW-0n     (X/Ku-band, DCE clocked)
   ┌────────────────────┐
   │  <TAG>-MR (2911)   │  airborne mission router
   │  Loopback0         │  10.<site>.40.1
   │  Gi0/0 802.1Q trunk│
   └─────────┬──────────┘
             │  onboard mission LAN (2960-24TT)  <TAG>-SW
   ┌─────────┴──────────┬───────────────┬──────────────────┐
   │ Fa0/1 VLAN 20      │ Fa0/2 VLAN 50 │ Fa0/3 VLAN 10    │
   ▼                    ▼               ▼
 <TAG>-MC            <TAG>-WLAN-AP   <TAG>-WC-PC
 mission computer    onboard WLAN    weapons-controller console
 (AN/APY-2, APY-9,   (WPA2-PSK,      (only on AWACS and E-2D)
  APS-145 or ELINT)   per-airframe SSID)
```

* Site id per airframe: `61` for E-767-01 … `76` for the last RC-2.
* Both bearers are `/30`s from the backbone pool, registered in OSPF area 0, so
  the aircraft's onboard networks are advertised into JADGE.
* The DCE end is always the **ground** concentrator (as with real modem/radio
  equipment); the physical port fields are set per end — `CLOCKRATEFLAG=true`
  with a non-zero `CLOCKRATE` on the DCE, `false`/`0` on the DTE.
* `PM-JADGE-WAN` is applied outbound on both bearers.
* Onboard WLAN: 26 SSIDs, `JASDF-ABN-<TAG>` per airframe and
  `JASDF-<BASE>-OPS` per air base, WPA2-PSK.

---

## 8. Configuration inventory

| Metric | Value |
| --- | ---: |
| Devices | 290 |
| Links | 326 (290 copper, 36 serial bearers) |
| Devices carrying a running-config | 205 |
| `<LINE>` elements in those blocks | 22,896 |
| Configuration lines on IOS/ASA devices | 22,648 across the 143 IOS/ASA devices (selected by model) |
| Longest configuration | 250 lines (`JADGE-BB-SW-01`) |
| Distinct device models | 14 |
| Addressed interfaces | 622 |
| Subnets | 335 |
| DNS records | 496 (248 names × 2 servers) |
| DHCP pools | 131 |
| RADIUS clients | 139 |
| VLANs defined | 10 |
| WLANs | 26 |
| Serial DCE ports clocked | 66 |

Per model: `Server-PT` 64 · `PC-PT` 55 · `2960-24TT` 31 · `2911` 26 ·
`AccessPoint-PT` 26 · `IR1101` 16 · `IE-9320` 16 · `ISR4331` 15 ·
`3560-24PS` 15 · `3650-24PS` 10 · `ISR4321` 10 · `5505` 4 ·
`CyberObserver` 1 · `Sniffer` 1.

Full list with roles and management addresses:
**[INVENTORY_enterprise.csv](INVENTORY_enterprise.csv)**.

---

## 9. Extending the model

`jasdf_kit.py` separates *what a device is* from *how it is configured*, so new
sites are cheap:

```python
# add a new radar site
self.add("rdr16r", "IR1101", "RDR-NEWSITE-RTR", x, y, site="NEWSITE",
         role="J/FPS-7 radar site router", ip=host(57, V_MGMT, 2))
...
self.rlink(f"hub{region}", GE(port), "rdr16r", "GigabitEthernet0/0/0")
```

Change a profile's device counts in `PROFILES` at the top of
`build_jasdf_aewc.py`; everything downstream — addressing, DNS records, DHCP
pools, RADIUS clients, the inventory CSV and the diagram — regenerates.

---

## 10. Known limitations

* **No live radar or radio modelling** — sensors and bearers are represented by
  the network-visible endpoints (signal processor, concentrator serial port).
* **Packet Tracer's IOS is a subset.** Commands Cisco's real IOS accepts may be
  ignored by PT. Everything emitted here is either attested by the reference
  corpus or a standard CCNA/CCNP-level construct; PT renders configs in the CLI
  tab regardless.
* **No MPLS, no VRF-lite, no DMVPN** — PT's support is partial; the model uses
  OSPF + BGP + IPsec instead, which PT simulates reliably.
* **First-open STP convergence** — see the note in the README; amber link lights
  for ~30 s after load are documented Cisco behaviour.
* **The coalition AS is a stand-in.** The partner network is a single router,
  switch and liaison workstation; it exists to demonstrate the policy boundary,
  not to model an allied network.
