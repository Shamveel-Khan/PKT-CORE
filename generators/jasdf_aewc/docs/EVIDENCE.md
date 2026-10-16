# Evidence base

Every non-obvious fact this project relies on is either derived from a
verifiable artefact or was established experimentally. This file records which,
so the model's claims can be checked rather than trusted.

---

## 1. Container format and codec

Not re-derived here. The project depends on
[`packet-tracer-pkt-format`](https://github.com/aacanadaa/packet-tracer-pkt-format),
whose own verification is the basis for this one:

* two container families (legacy PT 4.1–5.3.2, modern PT 5.3.3–9.0.1), no magic
  header, detection by AEAD tag verification;
* `encode(decode(f)) == f` byte-for-byte on **1058/1058** real containers;
* the locally built toolkit's own test suite was run before any authoring:
  `python -m pytest tests/ -q` → 0 failures.

This project re-asserts the byte-exact property on its own output on every
validation run (`validate.py`, check 1).

---

## 2. Device port names

The single largest correctness risk in authoring a `.pkt` from code is writing a
port name Packet Tracer cannot resolve. Names are **not** stored in the device
template — PT derives them from the model's hardware definition at load time —
so they had to be recovered from evidence.

Three sources were mined, in order of authority:

| Source | How obtained | Files | What it yields |
| --- | --- | ---: | --- |
| **Cisco's own PT 9.0.1 sample labs** | `packettracer.AppImage --appimage-extract` → `opt/pt/saves/` | 299 | LINK evidence for 92 models, the exact PT 9.0.1 naming |
| **Community reference corpus** | `corpus/fetch_corpus.py` (952 of 1058 files fetched and SHA-256 verified against `CORPUS_INDEX.tsv`) | 952 | LINK evidence for 26 modern models, plus running-config interface names |
| **Device templates** | `pt_templates/*.ptd` decoded with the same container codec | 88 | port *inventory* per model (how many ports of each media type) — used only to extend an attested family across its range |

The 88 `.ptd` template files turned out to decode with the same codec as `.pkt`
(`pt9.decode_bytes(raw, "pkt")`), which is how the per-model port inventory was
obtained rather than guessed.

Results are recorded per port with a provenance tier in `build/port_model.json`
and are enforced by `validate.py` on every build. Representative facts:

| Model | Established port names | Evidence |
| --- | --- | --- |
| `2911` | `GigabitEthernet0/0…0/2`; `Serial0/0/0`, `0/0/1`, `0/1/0` … `0/3/1` | corpus-link (4 HWIC bays × 2 ports) |
| `ISR4331` | `GigabitEthernet0/0/0…0/0/2`; `Serial0/1/0…0/2/1` | sample-link + corpus-link |
| `ISR4321` | `GigabitEthernet0/0/0`, `0/0/1` | sample-link |
| `IR1101` | `GigabitEthernet0/0/0`; `FastEthernet0/0/1…0/0/4` | sample-link (LINK) + sample-ios (config) |
| `IE-9320` | `GigabitEthernet1/0/1…1/0/24`, `GigabitEthernet0/0/0/0`, `0/0/1` | sample-link |
| `3650-24PS` | `GigabitEthernet1/0/1…1/0/24` | corpus-link |
| `3560-24PS`, `2960-24TT` | `FastEthernet0/1…0/24`; `GigabitEthernet0/1`, `0/2` | corpus-link + template count |
| `5505` | `Ethernet0/0…0/7` (switchports); routing on `Vlan1`/`Vlan2` | corpus-ios (a real ASA running-config) |
| `AccessPoint-PT` | `Port 0` (wired) | corpus-link |
| `CyberObserver` | `GigabitEthernet0` | sample-link |
| `Sniffer` | `Ethernet1` | corpus-link |

---

## 3. Service-configuration XML

Server-PT services live in `<ENGINE>` sub-elements, not in `RUNNINGCONFIG`.
Their shapes were recovered from real files:

| Service | Element shape | Source |
| --- | --- | --- |
| DNS | `<DNS_SERVER><ENABLED>1</ENABLED><NAMESERVER-DATABASE><RESOURCE-RECORD><TYPE>A-REC</TYPE><NAME/><TTL>86400</TTL><IPADDRESS/></RESOURCE-RECORD>…` | three configured servers in the corpus (e.g. `Ashiq3__…__Mail Server.pkt`) |
| DHCP | `<DHCP_SERVERS><ASSOCIATED_PORTS><ASSOCIATED_PORT><NAME>FastEthernet0</NAME><DHCP_SERVER><ENABLED>1</ENABLED><POOLS><POOL>` with `NAME/NETWORK/MASK/DEFAULT_ROUTER/TFTP_ADDRESS/START_IP/END_IP/DNS_SERVER/MAX_USERS/DOMAIN_NAME/LEASE_TIME/WLC_ADDRESS` | `Server-PT` device template + corpus |
| AAA | `<ACS_SERVER><ENABLED>1</ENABLED><USERS><USER><NAME/><PASSWORD/><DESCRIPTION/></USER></USERS><ACS_CLIENTS><CLIENT><HOST_IP/><KEY/><DESCRIPTION/><SERVER_TYPE>RADIUS</SERVER_TYPE>…` | `Server-PT` device template |
| HTTP/HTTPS/FTP/NTP/Syslog/MAIL | `<HTTP_SERVER>`, `<HTTPS_SERVER>`, `<FTP_SERVER><USER_ACCOUNT_MNGR><ACCOUNT>`, `<NTP_SERVER>`, `<SYSLOG_SERVER>`, `<EMAIL_SERVER>` | `Server-PT` device template |

The schema catalogue shipped with the toolkit (`docs/schema_catalogue.json`,
1,285 elements with parent/child relationships across 1,058 documents) was used
to confirm `RESOURCE-RECORD` as the child of `NAMESERVER-DATABASE` before the
shape was found in a real file.

---

## 4. Facts established experimentally in this project

These were not in any document and were settled by building a probe, opening it
in Packet Tracer 9.0.1 under Xvfb, and looking at the result.

| Question | Experiment | Answer |
| --- | --- | --- |
| What does a red cable mean? | `tools/serial_probe.py` — one 2911↔2911 serial link | **PT draws serial cables in red regardless of state.** Both ends showed green (forwarding) indicators. Red is not "down". |
| What does an amber/red *indicator* mean? | PT's own help text, then confirmed with `tools/stp_probe.py` and by toggling Realtime/Simulation on the full lab | Amber = the port is not in STP forwarding state. Cisco documents this as normal for ~30 s after loading a file with switches. |
| Do `AccessPoint-PT` links come up as shipped? | Opened the toolkit's known-good lab | No — its AP port also renders non-green, because the harvested template ships `<POWER>false</POWER>` on the ports. Fixed in the generator. |
| Does the aircraft↔gateway serial bearer need addressing? | First PT open of the model | Yes — the links were dead until each bearer got its own `/30`, `no shutdown` on both ends, and `clock rate` on the DCE end. |
| Which STP/portfast option breaks forwarding? | `tools/stp_probe.py`, four variants | None: `rapid-pvst` + `portfast default` + `bpduguard default` + `loopguard default` + `root primary` all converge to green in isolation. |

---

## 5. Corpus provenance

The reference corpus is third-party material and is **not** redistributed here.
`corpus/fetch_corpus.py` rebuilds it from its upstreams and verifies every file
against `CORPUS_INDEX.tsv`. The fetch used here reported:

```
fetched 952, missing 91
verify: OK (corpus/files)
```

91 files were no longer reachable upstream; the remaining 952 were
hash-verified. Mining covered 411 decodable modern-format files and 428
decodable files in total for port evidence.

---

## 6. Reproducing the evidence base

```console
$ python tools/mine_corpus.py          # community corpus -> port + config samples
$ python tools/mine3.py               # model-aware re-mine (port evidence)
$ python tools/build_port_model.py    # -> build/port_model.json (tiers)
$ python validate.py out/JASDF_AEWC_JADGE.pkt
```
