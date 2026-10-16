# INTERNET_SOURCES.md — Corpus provenance log

**Project:** Packet Tracer file-format reverse engineering
**Corpus dir:** `/home/saoria/PacketTracerReverse/corpus/internet/`
**Harvested by:** Corpus Harvest Agent
**Date:** 2025-10-12
**Scope:** real, public, legitimate Cisco Packet Tracer practice files (`.pkt`, `.pka`) only.
No executables, installers, or non-lab content was retained.

## Naming convention

Every staged file is named `<source-tag>__<original-name>` (spaces / slashes → `_`),
so the original filename is preserved while the source stays identifiable and
overwrites are impossible.

## Acceptance criteria applied to every file

1. Extension `.pkt` or `.pka` (plus `.zip` archives that verifiably contain them).
2. Size > 1024 bytes (0-byte and truncated downloads rejected).
3. `file(1)` must **not** report HTML / ASCII text / Unicode text / scripts / XML.
4. Content must not be mostly printable ASCII (rejects text `.pkt` impostors such
   as *packetdrill* test scripts and LaTeX packet diagrams that share the `.pkt`
   extension).
5. Byte-identical duplicates within a source are dropped; byte-identical files
   from *different* sources are kept (they are provenance-distinct).

**Result:** 0 files rejected as HTML/text after staging (a first-pass heuristic
flagged 8 binary files; manual hex inspection proved all 8 were valid encrypted
blobs and they were kept). 0-byte files found inside repos were skipped at
download time.

---

## Batch 1 — GitHub repository sweep (lab collections)

**Search method:** GitHub repository search via MCP
(`packet tracer labs pkt`, `topic:cisco-packet-tracer`, `packet tracer pka activity lab`)
plus GitHub code search (`extension:pkt`, `extension:pkt size:>30000`).
**Method:** `codeload.github.com/<owner>/<repo>/tar.gz/refs/heads/<branch>`,
extract, filter, copy.

| # | Source repo | Files kept | Notes |
|---|---|---|---|
| 1 | `vaamonde/ccna-v7-200-301` (2020) | 66 | CCNA v7 200-301 course labs, `etapa-001..056` + projects |
| 2 | `vaamonde/infra-cisco` | 15 | Portuguese CCNA infra course, Cenário A/B |
| 3 | `drespencer/CCNA-Hands-On-Labs` | 74 | Router config & troubleshooting labs |
| 4 | `Rakibul73/Cisco_Network_Routing_Switching` | 47 | `.pkt` + `.pka` incl. `ans.pka` answer keys |
| 5 | `hackthacker-sec/awesome-network-engineering-labs` | 36 | SOHO/campus/hospital/banking/VoIP designs |
| 6 | `O2sa/CCNA-Labs` | 27 | ACL/OSPF/EIGRP/VLAN/NAT labs |
| 7 | `dishavp/Network-Infrastructure-PacketTracer` | 26 | enterprise design, IPv6 dual-stack, ACLs |
| 8 | `Tanvir-Mahamood/Cisco-Packet-Tracer` | 24 | `.pkt` + `.pka`, official-looking activity numbers |
| 9 | `saikotimedabalimi/cisco-packet-tracer-pkt-files` | 22 | LAN/WAN/VLAN/RIP/OSPF/EIGRP/DHCP/DNS |
| 10 | `imsiddhant/MY-CCNA-Prep-1` + `Computer-Networking-Project-1` | 16 | CCNA prep labs + 4.9 MB campus project |
| 11 | `Ashiq3/Network-Design-in-Cisco-packet-tracer` | 14 | topologies, mail/wireless/server |
| 12 | `kaushiktarun05/packet_tracer` (2023) | 12 | "most important .pkt files", practicals 1–11 |
| 13 | `humayrakhanomrime/Cisco-Packet-Tracer` | 11 | university course models |
| 14 | `swati-gwc/Cisco-Packet-Tracer-Practicals` | 9 | DNS/DHCP/HTTP/Telnet/WLAN practicals |
| 15 | `CauaS1/packets-tracer` | 9 | **Jeremy's IT Lab** Day 01–08 + 3 official `.pka` |
| 16 | `NovneetKour/2020a1r048_..._com-512-CN-lab` | 9 | university CN lab Activity05–11 |
| 17 | `MIETDevelopers/2020a1r001_..._COM-512_...` | 9 | university CN lab Activity05–11 (independent copy) |
| 18 | `mainulBUBT/Cisco-Packet-Tracer-Networking-Lab` | 8 | university assignments |
| 19 | `soharoot/packet-tracer-labs` | 7 | VLAN/OSPF/security/DHCP/HSRP |
| 20 | `Jawadyyy/cisco-pkt-tracer-labs` | 7 | email/FTP/IoT/Web/VLAN servers |
| 21 | `blup-blup-spec/cisco-packet-tracer` | 6 | CCNA practice |
| 22 | `agsk2601/ccna-packet-tracer-labs` | 6 | CCNA 200-301 labs |
| 23 | `smsufi/CCNA-Materials` | 5 | OSPF/NAT/ACL |
| 24 | `Vagif-sys/network-lab` | 3 | `.pkt` + PowerShell + pcap |
| 25 | `kanomoo/cisco-packet-tracer` | 2 | tutoring activities |
| 26 | `Nirali4/Networking_Projects` | 2 | IPsec VPN, PAT |
| 27 | `MaksBloxX/Cisco-Packet-Tracer-Lab` | 2 | subnet tester |
| 28 | `4lban/CCENT-pkt-Labs` (2019) | 2 | CCENT/ICND1 ultimate labs |
| 29 | `katejay/College-Network` (2019) | 1 | classless subnetting + RIPv2 |
| 30 | `harismuneer/Network-Simulation-...` (2019) | 1 | three-company network |
| 31 | `greeshmamaske/University-Network-...` | 1 | campus network |
| 32 | `Mehedi-Hasan-Rabbi/Company-Business-System-...` | 1 | business network design |
| 33 | `HxnDev/CISCO-Packet-Tracer-...Routing-Protocols-And-Servers` | 1 | full routing + servers |
| — | `Amey-Thakur/COMPUTER-NETWORK-...`, `misterkrittin/CCNA-Labs`, `IamVaibhavsar/Third_Year_Lab_Assignments`, `ShubhamJagtap2000/Networking-Essentials`, `Harry5723/...` | 0 | repo empty / no `.pkt`/`.pka` / 404 branch |

**Batch 1 total kept: 463 files.**

### Code-search findings used for filtering (documented as negative results)
GitHub code search for `extension:pkt` is dominated by **non-Packet-Tracer** `.pkt`
files. These were identified and deliberately **not** harvested:

* `google/packetdrill`, `karknu/rws`, `songweijia/hdfsrs`, `Lorangeve/prping`,
  `EverCrawl/packetc`, `microsoft/WAFBench`, `JohnnyFoulds/chess`,
  `aschweiz/project-ocap`, `Phenomite/AMP-Research` — packetdrill/packet
  scripting DSLs, fuzz corpora, chess files, telemetry. All plain text.
* `obonaventure/cnp3` — `book/*/lan/pkt/*.pkt` are LaTeX/ASCII RFC-style
  protocol diagrams, not Packet Tracer.

Also observed (and rejected at download time): several repos contain `.pkt`
files that are literally `<!DOCTYPE html>` error pages committed by mistake
(`rawan468/CN_Tasks_2025`, `Squalidprasath/cisco-packet-tracer`,
`sherinjim/Cisco_packet_tracer`, `gustavoalito/BeCode`). Their individual files
were rejected by the HTML filter.

---

## Batch 2 — Cisco Networking Academy official activities (`.pka`)

**Search query:** `cisco packet tracer activity .pka ccna 1 download`,
`packet tracer 6.0 .pkt lab download` (via DuckDuckGo HTML endpoint — the
`web_search` tool was returning HTTP 401 auth errors this session and was not
usable; all web discovery was done with `curl` + `html.duckduckgo.com`).

**Source URL:** `https://cis.bbent.com/Courses/CSIS202/Resources/PacketTracer/`
(a public university course resource page, Broward College `CSIS202`).
It links 60 individual `*.pka` plus a bundle `AllPkaFiles.zip`.
The 60 individual links now return HTTP 404 (files moved/deleted), but the
bundle **`AllPkaFiles.zip` is still live** and was downloaded.

* `AllPkaFiles.zip` — 2,233,878 bytes, ZIP made by v2.0, **last modified 2011-08-16**
* Extracted **60 `.pka` files** (27–200 KB each), dated Aug 2011 inside the archive.

These are official **Cisco Networking Academy "Packet Tracer Activity" (PTA)**
curriculum files with NetAcad activity numbering, e.g.:
`1.7.1-Intro.pka`, `2.6.1-BuildingASmallNetwork.pka`, `9.8.1-ARP.pka`,
`11.2.1-ConfiguringHostnamesOnRoutersAndSwitches.pka`, …
They cover IT-Essentials / CCNA-1 style chapters 1–11.

**Batch 2 total kept: 60 files** (prefix `bbent-cis202-PTA2011__`).

### Version signal — IMPORTANT
The zip timestamp (Aug 2011) places these in the **Packet Tracer 5.x** era
(PT 5.3 was the current student version in 2011; PT 6.0 shipped 2013).

**Decoding attempt with the project's own `pt9.py info` codec:**
```
bbent-cis202-PTA2011__1.7.1-Intro.pka   -> error: PacketTracerError: EAX tag mismatch (wrong format or corrupted file)
bbent-cis202-PTA2011__11.2.1-...pka     -> error: PacketTracerError: EAX tag mismatch (wrong format or corrupted file)
```
i.e. **these 2011 files do NOT match the PT 5.7+/6/7/8/9 Twofish-EAX container.**
They are the *legacy container* the project is missing. All 60 are staged under
`bbent-cis202-PTA2011__` for exactly this reason.

---

## Batch 2b — GitHub, official NetAcad curriculum mirrors

**Search method:** DuckDuckGo HTML (`cisco packet tracer .pka lab download`,
`packet tracer 6.0 .pkt lab download`) + GitHub repo search.

| # | Source repo | Files kept | Notes |
|---|---|---|---|
| 34 | `abderaoufsec/CCNA-PacketTracerlabs` | 365 | **official CCNA v7 curriculum `.pka`** — `3.2.1.7 Configuring VLANs`, `9.3.2.12 Extended ACLs`, `11.4.2.5 Backing Up Configurations`, skills-integration challenges, etc. Many byte-identical to files found in other repos (dedup within repo applied). |
| 35 | `kristof-levai-github/CCNA-studies` | 144 | CCNA studies lab set (`.pka`) |
| 36 | `sherinjim/Cisco_packet_tracer`, `Squalidprasath/cisco-packet-tracer`, `MIETDevelopers/...`, `NovneetKour/...`, `gustavoalito/BeCode` | 18 | misc university / personal labs (HTML-contaminated members rejected) |

**Batch 2b total kept: 365 + 144 + 18 = 527 files.**

---

## Batch 3 — pre-2015 repositories (PT 5.x/6.0 era hunt)

**Search query:** GitHub repository search `packet tracer lab created:<2015`
and `packet tracer pka pkt activity created:<2017`.

| # | Source repo | Created | Files kept | Notes |
|---|---|---|---|---|
| 37 | `ptorchilov/Packet-Tracer-Labs` | 2014-11-30 | 5 | `lab02.pkt`, `lab02-static.pkt`, `lab-lra.pkt`, `lab02-branch.pkt`, `Task.pkt` — small (8–22 KB), compact older saves |
| 38 | `peeloforange/Networks_Lab` | 2014-10-03 | 0 | no `.pkt`/`.pka` committed |

**Batch 3 total kept: 5 files.**

---

## Sources checked and rejected (why)

| Source | Reason |
|---|---|
| `archive.org/download/cisco-packet-tracer-6.0.1-for-windows-with-tutorials` | only 5 files, all the PT **installer `.exe`** — executables explicitly out of scope |
| `archive.org/download/cisco-packet-tracer-6.2-for-windows-student-version` | same, installer only |
| `thiagoojack/packettracer-rpm-based`, `farhatizakaria/packet-tracer-ubuntu-deps`, `PetrusNoleto/*`, `EmotionalAmo/Cisco-Packet-Tracer-Chinese` | PT installers / dependency packages (`.deb`/`.exe`/`.rpm`) — out of scope |
| `netpilot.io/blog/cisco-packet-tracer-labs-collection` | page has no direct `.pkt`/`.pka`/`.zip` hrefs (JS-driven) |
| `ccnapracticelabs.com/labs` | no direct file hrefs (login/JS-gated) |
| `netacad.com/resources/lab-downloads` | requires Networking Academy login |

---

## Corpus verification results

* **Total staged files: 1059** = **1058 `.pkt`/`.pka` samples** + 1 `.zip`
  archive (`bbent-cis202__AllPkaFiles.zip`, kept as provenance; its 60 members
  are also staged individually)
* **Distinct by SHA-256: 1026** (33 byte-identical files appear under different
  source names — kept intentionally as provenance-distinct, e.g. the same
  official CCNA activity mirrored by two students)
* **Size range: 4,345 bytes – 5,677,870 bytes** (all > 1 KB as required)
* **HTML / text impostors in corpus: 0**
* **Executables / installers in corpus: 0**
* **Format split: 865 modern container / 193 legacy container** (plus the zip)

### Header / magic observations (first 16 bytes hex)

**No ASCII magic header exists in any of the 1059 files.** Every file begins
with high-entropy bytes. A per-offset consensus analysis over each format
generation shows the top byte at every offset 0–31 occurring in at most 3/60
files — i.e. statistically random, confirming the project's `FORMAT.md` finding
that the container has *no magic prefix*.

One file starts with printable bytes `3b 23 24 21 7c 40 3f 70` (`;#$!|@?p`);
hex inspection of the remainder proves this is a coincidental ciphertext prefix,
**not** a magic.

Representative first-16-byte hex:

| Source | Era | Header (first 16 bytes hex) | File |
|---|---|---|---|
| bbent-cis202-PTA2011 | 2011 / PT 5.x (**legacy**) | `222a059f6681f066716afa5f80fd63ec` | `bbent-cis202-PTA2011__1.7.1-Intro.pka` |
| ptorchilov (2014) | PT 6.0? | `0800bde632a7fe3c6db138e8b6f28563` | `ptorchilov__Packet-Tracer-Labs__Task.pkt` |
| vaamonde | PT 7.x | `96f173f34b56a7dcd0b4197bcae91813` | `vaamonde__ccna-v7-200-301__00-Projeto-Cisco.pkt` |
| abderaoufsec | PT 7.x / CCNA v7 | `7c27769233d30f563ecd2556b63bac85` | `abderaoufsec__CCNA-PacketTracerlabs__1.2.1.7 ...` |
| drespencer | PT 8.x | `14c12fa178acd42e5943b18cfbb02b83` | `drespencer__CCNA-Hands-On-Labs__051etherchanneltroubleshooting.pkt` |
| CauaS1 | PT 8.x | `4413f04d9d7fac6926b8f375bce3dbe9` | `CauaS1__packets-tracer__Connect Devices using ... .pka` |
| Rakibul73 | mixed | `afb0154bd33645d5fcd547ec305464db` | `Rakibul73__Cisco_Network_Routing_Switching__1.pka` |
| O2sa | PT 7.x | `3259236444a45c570f151d229e59a854` | `O2sa__CCNA-Labs__AccessControlList(Extend).pkt` |
| swati-gwc | PT 7.x | `353aecacfbfe53b4778a7b35c61e156b` | `swati-gwc__Cisco-Packet-Tracer-Practicals__DNS+DHCP+HTTP Configuration.pkt` |
| 4lban | PT 7.x (2019) | `214a079e73fcbd8ba3b81481c68bf07b` | `4lban__CCENT-pkt-Labs__Basic-complete.pkt` |
| kristof-levai-github | PT 8.x | `d629e778d468017e0b8f2d624cf63147` | `kristof-levai-github__CCNA-studies__0_WLC_ala...` |
| hackthacker-sec | PT 8.x | `a644c0631161c082fc4f766c68ef38b3` | `hackthacker-sec__awesome-network-engineering-...` |
| Tanvir-Mahamood | PT 7.x | `5a75ff74ef39eefc9ec8785adc9450b3` | `Tanvir-Mahamood__...__11.5.1.2 Packet Tracer - Skills Integration Challenge.pka` |

### FULL-CORPUS DECODE CLASSIFICATION (`pt9.py decode`, `verify_tag=True`)

Every one of the 1059 staged files was decoded with the project's own codec.

| Outcome | Count | Detail |
|---|---|---|
| **Decodes OK — modern Twofish-EAX container** | **865** | see root-tag split below |
| **FAILS `EAX tag mismatch` — LEGACY container** | **194** | the format gap |
| total | 1059 | (865 + 194) |

Root tags of the 865 that decode:

| Root tag | Count | Meaning |
|---|---|---|
| `PACKETTRACER5` | 508 | ordinary `.pkt` lab save |
| `PACKETTRACER5_ACTIVITY` | 357 | `.pka` scored/graded activity |

**`.pka` scored activities use root tag `PACKETTRACER5_ACTIVITY`; `.pkt` labs use
`PACKETTRACER5`.** Same container, different root element.

Legacy-container breakdown (all `EAX tag mismatch`):

| Source | Legacy files | What they are |
|---|---|---|
| `bbent-cis202-PTA2011__*` | 60 | Cisco NetAcad PTA activities, zip dated **Aug 2011** → PT 5.x |
| `abderaoufsec__CCNA-PacketTracerlabs__*` | 129 | older exam-sim + curriculum sets (see below) |
| `Rakibul73__...__{1,2,4,8}.pka` | 4 | numbered activities from one collection |
| `bbent-cis202__AllPkaFiles.zip` | 1 | the archive itself (not a sample) |
| **total** | **194** | |

**Legacy = 193 real sample files.**

### The legacy set is a *mixed* but well-defined group

`abderaoufsec/CCNA-PacketTracerlabs` is a **mixed-format** repo: 224 files decode
with the modern codec and 129 do not. The 129 legacy members are recognisable by
name and are all older-generation material:

* `NA-1-1-BasicConfig.pka` … `NA-4-9-DHCP.pka` — a complete numbered NetAcad
  lab series (18 files), all legacy
* `*.pka` named `NN.N.N.N 100%.pka` — 40 files, **all 40 are legacy**
  (completed/graded answer keys)
* `9tut.com_*` and `Certprepare.com *` — CCNP/CCNA **exam-sim** practice
  questions (`CCNA_Access_List_Sim.pkt`, `SWITCH Lab MLS EIGRP.pkt`,
  `New LACP - STP Lab.pkt`) — the well-known PT 6.x/7.0-era exam sim format
* `NetLab 4 x VLAN, RSTP & EIGRP/OSPF/... Conf.pkt` (9 files) — all legacy
* misc older labs: `CCNA Mega Lab*.pkt`, `VOIP.pka`, `IPSec-VPN.pka`,
  `Basic-EIGRP*.pka`, `EXT-ACL*.pka`, `AAA_*`, `CBAC_3Interface.pkt`,
  `DHCP and NAT *.pka`, `Inter Vlan*.pkt`, `Multilevel_DNS.pkt`,
  `Spanning tree protocol.pkt`, `Trunks & Vlans.pkt`, `UltimateCCNAChallenge.pkt`,
  `basic PPP configuration.pka`, `cisco_ccna_static_routing.pkt`, …

By contrast, the modern-container members of that same repo are the standard
"official-looking" CCNA activities named `X.Y.Z.W Packet Tracer - <Title>.pka`
(`1.2.1.7`, `3.2.1.7 Configuring VLANs`, `10.2.1.8 Web and Email`, …) plus the
`PT 642_832 TSHOOT Ticket 01..15.pkt` set and `9tut.com_*_Answered*` variants.

This gives a clean **same-repo, same-era-mix A/B corpus** for differential
format work: identical topic material exists in both containers.

### Representative decode results

| Sample | Result |
|---|---|
| `bbent-cis202-PTA2011__1.7.1-Intro.pka` | **FAIL** `EAX tag mismatch` → legacy |
| `bbent-cis202-PTA2011__11.2.1-...pka` | **FAIL** `EAX tag mismatch` → legacy |
| `Rakibul73__...__1.pka` | **FAIL** `EAX tag mismatch` → legacy |
| `abderaoufsec__...__NA-2-2-VTP.pka` | **FAIL** `EAX tag mismatch` → legacy |
| `abderaoufsec__...__CCNA Mega Lab.pkt` | **FAIL** `EAX tag mismatch` → legacy |
| `ptorchilov__Packet-Tracer-Labs__lab02.pkt` (2014) | OK `PACKETTRACER5`, 146,853 XML bytes |
| `vaamonde__ccna-v7-200-301__etapa-001.pkt` | OK `PACKETTRACER5`, 779,923 XML bytes |
| `4lban__CCENT-pkt-Labs__Basic-complete.pkt` (2019) | OK `PACKETTRACER5`, 719,722 XML bytes |
| `drespencer__...__051etherchanneltroubleshooting.pkt` | OK `PACKETTRACER5`, 892,351 XML bytes |
| `swati-gwc__...__SETUP WLAN.pkt` | OK `PACKETTRACER5`, 882,577 XML bytes |
| `CauaS1__...__Day 01 Lab - Packet Tracer Introduction.pkt` | OK `PACKETTRACER5`, 1,102,934 XML bytes |
| `abderaoufsec__...__3.2.1.7 Configuring VLANs.pka` | OK **`PACKETTRACER5_ACTIVITY`**, 2,100,814 XML bytes |
| `kristof-levai-github__...__WIFI_WLC_RADIUS_exercise.pka` | OK `PACKETTRACER5_ACTIVITY` |

**Key structural conclusions for the parser work:**

1. `.pka` scored activities use root tag `PACKETTRACER5_ACTIVITY`;
   `.pkt` labs use `PACKETTRACER5`. Same container, different root element.
2. The modern Twofish-EAX container (as documented in `FORMAT.md`) reads files
   from at least **PT 6.0 (2014) through PT 9** — including activity numbering
   from every CCNA/NetAcad curriculum generation and several languages
   (English, Portuguese, Hungarian).
3. **193 files are a genuinely different, older container** (EAX tag mismatch).
   This is the "legacy container" gap. Two independent populations confirm it:
   the 2011 NetAcad PTA set, and the older exam-sim / `100%`-answer-key set.
   Note: despite being legacy, these files still show **no ASCII magic** —
   their first 16 bytes are equally high-entropy.
