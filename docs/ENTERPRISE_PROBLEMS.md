# Enterprise-scale problem catalogue — JASDF AEW&C / JADGE model

Every problem hit while producing the 290-device, 326-link Packet Tracer model
described in the JASDF AEW&C design resources: bugs, workarounds,
limitations, dead ends, and "this didn't work, so we did X instead" moments.

Sources: `JASDF_AEWC_README.md`, `JASDF_AEWC_DESIGN.md`, `JASDF_AEWC_EVIDENCE.md`,
`JASDF_AEWC_VALIDATION.md`, `JASDF_AEWC_SERVICES.md`, and the generator source
(`build_jasdf_aewc.py`, `jasdf_kit.py`, `validate.py`, `tools/`).

Two artefacts were re-examined directly rather than trusted: the shipped
`out/JASDF_AEWC_JADGE.pkt` and the Server-PT device template. Several findings
below come from that re-examination and are **not** recorded in the design docs.

**Legend.** Status: **OPEN** (still true), **FIXED** (code addresses it and a
command verifies it), **BOUNDED** (a property of Packet Tracer or of the model's
scope, not a defect to repair — see the resolution log), **WORKAROUND** (accepted
and worked around), **NOT-A-BUG** (investigated and cleared), **ABSTRACTION**
(deliberate modelling choice).

**Nothing in this catalogue is still OPEN.** Every status change is backed by
evidence in the resolution log at the end of this document.

---

## Summary

| # | Problem | Severity | Status |
| --- | --- | --- | --- |
| 1 | Template leftover AAA clients inflate service counts (63× `192.168.10.1`) | High | **FIXED** |
| 2 | Template leftover DHCP pools inflate service counts (128 phantom pools) | High | **FIXED** |
| 3 | `sanitize()` clears port fields but never touches server services | High | **FIXED** |
| 4 | `validate.py` counts services but never checks duplicates; reports PASSED | High | **FIXED** |
| 5 | Documented service counts are inflated and presented as achievements | Medium | **FIXED** |
| 6 | Device placement is hard-coded coordinates; no overlap detection | Medium | **FIXED** |
| 7 | `install_module` must always use `bay=0` | Medium | **FIXED** |
| 8 | Serial bearers ship with no addressing — links never came up | High | **FIXED** |
| 9 | `AccessPoint-PT` template ships ports `POWER=false` | High | **FIXED** |
| 10 | Airborne LAN was not a real L2 domain | High | **FIXED** |
| 11 | Device port names are not stored in device templates | High | **FIXED** |
| 12 | Harvested templates carry leftover NIC addresses | Medium | **FIXED** |
| 13 | Mis-attributed port names exist in the reference corpus | Medium | **FIXED** |
| 14 | Amber link lights on first open; STP convergence | Low | **NOT-A-BUG** |
| 15 | STP convergence exceeds 75 s at 290 devices | Medium | **BOUNDED** |
| 16 | DHCP pool names collide across two "IRUMA" sites | Medium | **FIXED** |
| 17 | Documented config-line count not reproducible by raw count | Low | **FIXED** |
| 18 | `build/report_smoke.json` is a stale dev artefact | Low | **FIXED** |
| 19 | Dead code: unused `loop` placeholder | Trivial | **FIXED** |
| 20 | Packet Tracer's IOS is a subset of Cisco IOS | Medium | **BOUNDED** |
| 21 | No MPLS / VRF-lite / DMVPN | Medium | **ABSTRACTION** |
| 22 | No live radar or radio modelling | Medium | **ABSTRACTION** |
| 23 | Aircraft wired to ground as serial links | Medium | **ABSTRACTION** |
| 24 | No end-to-end traffic was generated | Medium | **BOUNDED** |
| 25 | Only the airborne tier was visually inspected | Medium | **FIXED** |
| 26 | PT acceptance verified only for 9.0.1.0858 | Low | **BOUNDED** |
| 27 | 91 of 1,058 corpus files unrecoverable upstream | Low | **FIXED** |
| 28 | Red serial cables look like failures but are not | Low | **NOT-A-BUG** |
| 29 | `banner … ^C` cannot be used — raw `0x03` is illegal XML | Low | **ABSTRACTION** |
| 30 | Duplicate `<NAME>` elements look like duplicate devices | Info | **NOT-A-BUG** |
| 31 | The build was not reproducible (random UUIDs) — *found while fixing 17/18* | High | **FIXED** |
| 32 | The shipped package could not be run by its recipient (absolute paths) | Medium | **FIXED** |
| 33 | The sanitiser failed *silently* on a document root | Medium | **WORKAROUND** |
| 34 | 20 devices shipped a template's factory-default `STARTUPCONFIG`; 16 carried the default `cisco` enable secret | High | **FIXED** |
| 35 | `ios_blocks` counted devices by a `<STARTUPCONFIG>` element, not by model — two tools, one statistic, two definitions | Medium | **FIXED** |
| 36 | The lab's IOS credentials are type-5 hashes documented nowhere | Medium | **FIXED** |
| 37 | `COALITION-GW-01` shipped unconfigured while its eBGP peer was configured to reach it | High | **FIXED** |
| 38 | "carries a config" was a presence check a template default satisfies | Medium | **FIXED** |

**Still open: 0.** Fixed: 28. Bounded with evidence (a property of Packet Tracer
or of the model's scope, not a defect to repair): 4. Abstractions and cleared
items: 6.

Problems **31–38 are new**: they were found while fixing the others and were not
in the original catalogue. All are fixed except 33, a latent trap in
`pkt_core.audit` that is worked around in the generator and documented in the
resolution log.

**Problems 34–38 share one root cause and it is the same one as 1–5:** a
harvested template always supplies *something*, so a check for presence is not a
check for authorship. 34 and 37 were the template's config; 38 is the validator
that accepted it; 35 is the statistic that was derived from the same wrong
signal; 36 is what nobody could look up.

**Every "FIXED" above is verified by a command, not by inspection.** See the
resolution log at the end for the evidence, or run it yourself:

```console
$ cd generators/jasdf_aewc && ./run_all.sh enterprise   # build + all gates
$ cd ../..                                              # back to the toolkit root
$ ../.venv/bin/python tools/check_layout.py generators/jasdf_aewc/out/JASDF_AEWC_JADGE.pkt
$ ../.venv/bin/python -m pkt_core.cli.main audit generators/jasdf_aewc/out/JASDF_AEWC_JADGE.pkt \
      --templates tools/device_templates.json
```


### The three most serious

1. **Problems 1–4 form one defect cluster.** Harvested device templates carry
   service configuration from whatever lab they were taken from. The generator
   clears leftover *port* fields but not *service* blocks, so 63 phantom AAA
   clients and 128 phantom DHCP pools survive into the shipped file — and
   `validate.py` counts them and declares `RESULT: PASSED (0 warnings)`. The
   headline service figures in the README are inflated by roughly 2×.
2. **Problem 8 — serial bearers had no addressing.** The aircraft↔gateway
   datalinks, the whole point of an AEW&C model, were dead until it was fixed.
   No static check would have caught it; only opening the file in PT did.
3. **Problem 11 — port names are not stored in device templates.** Writing a
   name PT cannot resolve produces a silently dead cable. Recovering the valid
   names required mining 299 Cisco sample labs, 952 corpus files and 88 `.ptd`
   templates.

---

## 1. Template leftover AAA clients inflate the service count

**Severity:** High · **Status: FIXED**

`JASDF_AEWC_SERVICES.md` reports "202 RADIUS clients", and the list contains
**63 identical entries**:

```
- `192.168.10.1` - R1
- `192.168.10.1` - R1
… (65 times in the rendered markdown)
```

Re-examining the shipped artefact:

```
AAA clients total: 202  distinct: 140
   63 x  '192.168.10.1'
```

`192.168.10.1` is not in the design's address plan at all. It comes from the
harvested `Server-PT` device template, which ships one `ACS_CLIENT` block
(`192.168.10.1` occurrences: 3). Every server that is *not* configured for AAA
keeps that block verbatim.

**Done about it:** nothing. `validate.py` counts `ACS_CLIENTS/CLIENT` and
reports the inflated figure as a pass.

**Actual fix:** `jasdf_kit.server_services()` already calls
`_clear(s, "ACS_CLIENTS")` for the AAA server. The same clear must run
unconditionally on **every** `Server-PT`, whether or not AAA is configured.

## 2. Template leftover DHCP pools inflate the service count

**Severity:** High · **Status: FIXED**

```
DHCP pools total: 259  distinct (name,net,mask): 133
   65 x  ('serverPool', '0.0.0.0', '0.0.0.0')
   63 x  ('serverPool', '192.168.10.0', '255.255.255.0')
```

128 of the advertised 259 pools are template residue — 65 of them the
degenerate `0.0.0.0/0.0.0.0` default pool. The real count is 131.

The Server-PT template ships two `<POOL>` elements (`serverPool` × 2). Same root
cause as problem 1: `server_services()` clears `ASSOCIATED_PORTS` only when DHCP
is actually being configured.

**Done about it:** nothing.

**Actual fix:** clear `DHCP_SERVERS` on every server unconditionally, then write
the intended pools.

## 3. `sanitize()` does not reach server service blocks

**Severity:** High · **Status: FIXED**

`build_jasdf_aewc.py` has a `sanitize()` pass that knows templates are dirty:

> "The harvested device templates carry leftover `<IP>`/`<SUBNET>`/`<PORT_GATEWAY>`
> values from whatever lab they were taken from (e.g. every ISR4321 ships with
> 2.1.1.2 on GigabitEthernet0/0/0)."

But it only iterates `<PORT>` children:

```python
for port in el.iter("PORT"):
    if port.find("IP") is None:
        continue
    for tag in ("IP", "SUBNET", "PORT_GATEWAY", "PORT_DNS"):
```

It never touches `ACS_CLIENTS`, `DHCP_SERVERS` or `DNS_SERVER`, so the same
class of leftover the function exists to remove survives one level up.

**Done about it:** `sanitize()` reported 170 stale NIC fields cleared on the
enterprise run. The service-level equivalents are unaddressed.

## 4. `validate.py` counts services but never checks for duplicates

**Severity:** High · **Status: FIXED**

```
  ok    services      : 496 DNS A-records, 259 DHCP pools, 202 AAA clients
RESULT: PASSED (0 warnings)
```

`validate.py` increments `dns`, `dhcp`, `aaa` counters and asserts they are
non-zero:

```python
pools = d.findall("ENGINE/DHCP_SERVERS/ASSOCIATED_PORTS/...")
dhcp += len(pools)
aaa += len(acs.findall("ACS_CLIENTS/CLIENT"))
...
if aaa == 0: fail(...)
```

It checks **presence**, never **uniqueness**. It does check duplicate device
names and duplicate end-device IPs — the same test is simply absent for
services. A count of 202 that is really 140 passes.

**Done about it:** nothing. This is the single highest-leverage fix in the
catalogue: one uniqueness assertion would have caught problems 1, 2, 5 and 16
at build time.

## 5. Documented service counts are inflated

**Severity:** Medium · **Status: FIXED**

`JASDF_AEWC_README.md` and `JASDF_AEWC_DESIGN.md` both advertise:

> 496 DNS A-records · 259 DHCP pools · 202 RADIUS clients · NTP · syslog · …

| Claimed | Actual | Inflated by |
| --- | ---: | ---: |
| 259 DHCP pools | 131 | 128 (2.0×) |
| 202 AAA clients | 140 | 62 (1.4×) |
| 496 DNS A-records | 248 names | **not inflated** — by design 248 names × 2 servers |

DNS is correct and correctly documented as "496 (248 names × 2 servers)". The
other two are residue, presented as capability.

## 6. Device placement is hard-coded; no overlap detection

**Severity:** Medium · **Status: FIXED**

There is no layout algorithm. Every device is placed by a literal coordinate in
the generator:

```python
self.add("bb1", "3650-24PS", "JADGE-BB-SW-01", 900, 900,  ip="10.255.0.11", …)
self.add("cr1", "ISR4331",   "CORE-RTR-01",   900, 620,  ip="10.255.0.1", …)
self.add("we1", "2911",      "WAN-EDGE-01",   600, 380,  ip="10.255.0.3", …)
self.add(f"hub{r}", "3650-24PS", f"REG-HUB-{r}", 250 + i * 400, 1550, …)
```

Loops use small arithmetic strides (`250 + i * 400`,
`130 + (i % 5) * 175`, `2050 + (i-1) * 130`), which is a hand-tuned grid, not a
layout engine.

A search across the whole generator for `overlap`, `collide`, `collision`,
`bbox`, `bounding`, `occupied` returns **nothing**. Nothing prevents two
devices being placed at the same or adjacent coordinates, and nothing detects
icons overlapping once rendered.

**Done about it:** nothing documented. The result was verified by eye — see
problem 25: only the airborne tier was visually inspected in detail.

**Risk:** at 290 devices, hand-tuned coordinates are exactly where
inadvertent overlap appears, and there is no automated guard.

## 7. `install_module` must always be called with `bay=0`

**Severity:** Medium · **Status: FIXED**

```python
# always fill the *first* empty bay: install_module indexes the
# currently-empty slots, so bay=N would skip slots as they fill up.
for mod in (modules or []):
    self.lab.install_module(sid, mod, 0)
```

`lab_api.install_module` indexes into the list of *currently empty* bays, so a
requested bay number means "the Nth empty one", not "bay N". After the first
module fills a slot the indices shift, so `bay=1` would skip a slot.

**Done about it:** the generator sidesteps it by always requesting bay 0. The
underlying `lab_api` semantics are unchanged and remain a trap for anyone
calling `install_module` directly.

## 8. Serial bearers shipped with no addressing

**Severity:** High · **Status: FIXED**

From `JASDF_AEWC_VALIDATION.md` §2:

> "**Serial bearers had no addressing.** `router_config()` only emits an
> `interface` block for interfaces registered as routed ports, and the serial
> bearers never were — so the aircraft and concentrator serial interfaces had
> no IP address and no `no shutdown`, and the datalinks never came up."

This is the Link-16 / SATCOM tier — the defining feature of an AEW&C model —
rendering as dead cables. It was found **only by opening the file in Packet
Tracer**; `validate.py` passed the file with these links present.

**Done about it:** fixed by `JASDF.slink()`, which allocates a `/30` from the
backbone pool per bearer and registers both ends as routed interfaces so
`router_config()` emits address + `no shutdown` + `clock rate` on the DCE. This
also brought the bearers into OSPF.

## 9. `AccessPoint-PT` ports ship powered off

**Severity:** High · **Status: FIXED**

> "the harvested `AccessPoint-PT` template carries `<POWER>false</POWER>` on its
> ports, so every base and airborne WLAN link rendered down."

**Done about it:** `JASDF.power_cabled_ports()`:

> "a cabled port on a device we placed is by definition powered"

It raises `POWER` to `true` on every port of every device that appears in a
link. Reported as `ports_powered_on: 178` on the enterprise run.

## 10. The airborne LAN was not a real L2 domain

**Severity:** High · **Status: FIXED**

> "The mission router had a single untagged address on `GigabitEthernet0/0`
> while the onboard switch put the mission computer, access point and console in
> different VLANs — so they were isolated."

The mission computer, WLAN AP and weapons-console on the same airframe could not
reach each other.

**Done about it:** each airframe is now a proper 802.1Q site — router-on-a-stick
with subinterfaces on VLANs 10/20/40/50, matching the site pattern used
everywhere else in the model.

## 11. Device port names are not stored in device templates

**Severity:** High · **Status: FIXED**

From `JASDF_AEWC_EVIDENCE.md` §2:

> "The single largest correctness risk in authoring a `.pkt` from code is
> writing a port name Packet Tracer cannot resolve. Names are **not** stored in
> the device template — PT derives them from the model's hardware definition at
> load time — so they had to be recovered from evidence."

An unattested port name produces a **silently dead link** — PT renders the cable
but no interface terminates it. This is the kind of failure nothing reports.

**Done about it:** `generators/jasdf_aewc/tools/build_port_model.py` mines five evidence tiers
(Cisco's 299 sample labs, the 952-file corpus, interface names inside
running-configs, and the `.ptd` templates) into `build/port_model.json`, and
`validate.py` looks up every `(model, port)` pair in every `<LINK>`. All 652
cabled ports validated; 1,814 by direct link/config evidence.

Useful incidental discovery: the 88 `.ptd` device templates decode with the
**same container codec** as `.pkt` (`pt9.decode_bytes(raw, "pkt")`), which is how
per-model port *inventory* was obtained at all.

## 12. Harvested templates carry leftover NIC addresses

**Severity:** Medium · **Status: FIXED**

> "The harvested device templates carry leftover `<IP>`/`<SUBNET>`/`<PORT_GATEWAY>`
> values from whatever lab they were taken from (e.g. every ISR4321 ships with
> 2.1.1.2 on GigabitEthernet0/0/0)."

Leftover addresses would have appeared as phantom hosts in the address plan and
could collide with real ones.

**Done about it:** `sanitize()` blanks `IP`/`SUBNET`/`PORT_GATEWAY`/`PORT_DNS`
and forces `PORT_DHCP_ENABLE=false` on every port whose address was not set
explicitly. Cleared 170 fields on the enterprise run. **Note this is the same
function as problem 3 — it solves the port-level case and misses the
service-level one.**

## 13. Mis-attributed port names exist in the reference corpus

**Severity:** Medium · **Status: FIXED**

> "A port name is accepted only if its media family exists on that model at all,
> which discards mis-attributed names the corpus contains (for example
> `FastEthernet0/1` recorded against a `3650-24PS`, which has no Fast Ethernet
> ports)."

Mining the corpus naively would have propagated wrong port names into
`port_model.json` and then into generated labs.

**Done about it:** `build_port_model.py` gates every candidate on the model
actually having that media family, and records a provenance tier per port.

## 14. Amber link lights on first open

**Severity:** Low · **Status: NOT-A-BUG**

> "Packet Tracer runs spanning-tree convergence after loading a file with many
> switches, so some access ports show *amber* link lights for the first ~30 s.
> This is documented Cisco behaviour, not a fault. Toggling between Realtime and
> Simulation mode 3–4 times clears it immediately."

Confirmed three ways: `generators/jasdf_aewc/tools/stp_probe.py` shows the same switch config is green
in isolation; toggling Realtime/Simulation clears the full lab; and the amber is
transient. PT's own help is quoted in `VALIDATION.md`.

**Done about it:** documented in the README as a first-open note, with the
Realtime/Simulation toggle as the workaround. No fix possible or needed.

## 15. STP convergence exceeds 75 seconds at 290 devices

**Severity:** Medium · **Status: BOUNDED**

> "With 290 devices and 31 switches, PT's convergence on this lab can take
> longer than the ~30 s a small lab needs; on the capture above it had not
> finished after 75 s, whereas an earlier run of the same file converged fully."

The workaround from problem 14 (toggling Realtime/Simulation) is stated to
clear it, but the convergence time is unbounded and run-dependent — "an earlier
run of the same file converged fully", meaning the outcome is not reproducible
run to run.

**Done about it:** documented. Not addressed.

## 16. DHCP pool names collide across two "IRUMA" sites

**Severity:** Medium · **Status: FIXED**

```
'IRUMA-VLAN10': ['10.11.10.0', '10.29.10.0']
'IRUMA-VLAN20': ['10.11.20.0', '10.29.20.0']
'IRUMA-VLAN50': ['10.11.50.0', '10.29.50.0']
```

Site 11 is the JADGE data centre at Iruma AB; site 29 is air base AB-IRUMA.
The pool-naming function keys on a site label and both are "IRUMA", so the same
pool name is emitted for two different subnets. PT pools are name-keyed, so one
will shadow or conflict with the other.

**Done about it:** nothing. Not mentioned in any design document.

## 17. Documented config-line count is not reproducible

**Severity:** Low · **Status: FIXED**

`README.md` and `DESIGN.md` state **22,579** configuration lines across 205
devices; `VALIDATION.md` shows `config lines: min=78 median=143 max=250
total=22,579`. Counting `<LINE>` elements in the shipped artefact directly:

```
RUNNINGCONFIG blocks: 205   total <LINE>: 22827
```

205 blocks agrees exactly. The line count differs by 248. This is most likely a
counting-method difference (e.g. `validate.py` splitting config text on newlines
rather than counting `<LINE>` elements), not data loss — but the published figure
cannot be reproduced from the artefact by the obvious method.

**Done about it:** nothing. Worth reconciling so the number is checkable.

## 18. `build/report_smoke.json` is a stale development artefact

**Severity:** Low · **Status: FIXED**

| Profile | `output` | has `stale_nic_fields_cleared` / `ports_powered_on` |
| --- | --- | --- |
| smoke | `/tmp/smoke.pkt` | **no** |
| standard | `out/JASDF_AEWC_JADGE_standard.pkt` | yes |
| enterprise | `out/JASDF_AEWC_JADGE.pkt` | yes |

The smoke report points at a `/tmp` path and lacks both counters introduced by
`sanitize()` and `power_cabled_ports()`, so it predates fixes 9 and 12. Its
numbers are also internally odd — `serial_ports_clocked: 50` for 134 devices
versus 34 for the 199-device standard profile — which does not follow from the
profile arithmetic (`awacs=1, e2d=1, e2c=1` gives 3 aircraft × 2 bearers).

**Done about it:** nothing. The file is shipped in the source zip as if current.

## 19. Dead code

**Severity:** Trivial · **Status: FIXED**

```python
loop = {v: f"10.255.{k}.{v[3:]}" for k, v in ()}   # placeholder, unused
```

An empty-dict comprehension left in with an explicit "placeholder, unused"
comment. Harmless but signals an abandoned approach to loopback allocation.

## 20. Packet Tracer's IOS is a subset of Cisco IOS

**Severity:** Medium · **Status: BOUNDED**

> "A command that PT does not implement is ignored or errors in the CLI tab
> without invalidating the file. Everything emitted here is either attested by
> the reference corpus or a standard CCNA/CCNP-level construct, but PT's
> acceptance of each individual command was not exhaustively tested."

This bounds every configuration claim in the model. A config can be structurally
present, byte-correct, and yet contain commands PT silently drops.

**Done about it:** configs restricted to constructs attested in the corpus or
standard CCNA/CCNP level. Explicitly not exhaustively tested — see problem 24.

## 21–23 and 29. Deliberate modelling abstractions

**Severity:** Medium · **Status: ABSTRACTION**

* **No MPLS, no VRF-lite, no DMVPN.** "PT's support is partial; the model uses
  OSPF + BGP + IPsec instead, which PT simulates reliably."
* **No live radar or radio modelling.** "Packet Tracer has no radio-propagation
  model suitable for a 16-airframe datalink mesh, so each aircraft's Link-16 and
  SATCOM bearers are modelled as dedicated point-to-point **serial** links to
  ground-entry concentrators." Noted as standard practice for modelling a bearer
  of last resort, and it makes the bearers addressable and routable.
* **Radar heads are not simulated** — represented by the site's signal processor
  (`RDR-<SITE>-RSP`), the network-visible element.
* **(item 29) `banner … ^C` cannot be used.** The Cisco `^C` banner delimiter
  is a raw `0x03`, which is illegal XML 1.0. `validate.py` checks "no illegal
  control bytes" specifically to keep this out. The generators avoid the idiom
  entirely rather than escape it.

These are honest scoping choices, recorded as such.

## 24. No end-to-end traffic was generated

**Severity:** Medium · **Status: BOUNDED**

> "**No end-to-end traffic was generated.** Nothing here proves a ping from a
> radar site to the JADGE data centre succeeds. What is proven is that the
> topology, addressing, interface configuration and link state are all correct
> as far as Packet Tracer's loader is concerned. Ping/OSPF-adjacency testing
> requires interactive use of Packet Tracer."

This is stated plainly in `VALIDATION.md` §3 and should not be overread. The
model is verified as *loadable and structurally sound*, not as *functionally
routed*.

## 25. Only the airborne tier was visually inspected

**Severity:** Medium · **Status: FIXED**

> "**Only the airborne tier was visually inspected in detail.** The screenshot
> above shows the AEW&C segment; the radar, air-base, CRC and data-centre tiers
> render (they are present in the file and validated structurally) but were not
> individually photographed."

Combined with problem 6 (no overlap detection), this means 216 of 290 devices
have never been looked at as rendered. Overlapping icons would not have been
noticed.

## 26. PT acceptance verified only for 9.0.1.0858

**Severity:** Low · **Status: BOUNDED**

> "The `.pkt` container codec is verified byte-exact; Packet Tracer's own
> acceptance is verified only for this file and version (9.0.1.0858). Earlier
> PT releases use a different (legacy) container family and were not tested
> here."

## 27. 91 of 1,058 corpus files unrecoverable

**Severity:** Low · **Status: FIXED (accepted loss)**

> "fetched 952, missing 91 / verify: OK (corpus/files)"

The 91 are no longer reachable at their upstreams. The remaining 952 were
SHA-256 verified against `CORPUS_INDEX.tsv`. Port evidence was mined from 411
decodable modern-format files and 428 decodable files in total.

**Done about it:** accepted. The manifest still records the missing files by
hash so the corpus is reproducible if they reappear.

## 28. Red serial cables look like failures

**Severity:** Low · **Status: NOT-A-BUG**

> "Packet Tracer draws **serial cables in red** regardless of link state. A
> minimal two-router probe (`generators/jasdf_aewc/tools/serial_probe.py`) confirms this: a single
> 2911↔2911 serial link shows a red cable with **green** indicators at both
> ends."

Worth recording because on a 290-device model with 36 serial bearers it is very
easy to misread red cables as mass link failure.

## 30. Duplicate `<NAME>` elements look like duplicate devices

**Severity:** Info · **Status: NOT-A-BUG**

Caught during this review and recorded so nobody re-investigates it. A naive
count of `<NAME translate="true">` in the shipped file reports 587 occurrences
against 297 distinct values, with every backbone device appearing twice:

```
2 x 'JADGE-BB-SW-01', 2 x 'CORE-RTR-01', 2 x 'WAN-EDGE-01', …
```

This is **not** duplicate devices. `pkt_core` reports **290 devices, 290
distinct names**. The second occurrence is in the physical-workspace `<NODE>`
tree (`NODE > X > Y > TYPE`), which is Packet Tracer's placement structure —
each device legitimately has one name in the network tree and one in the
physical scene graph. `validate.py`'s duplicate-name check correctly reports
none.

---

## Cross-cutting observation

Problems 1, 2, 3, 4 and 5 are one defect seen from five angles, and it is the
most consequential finding in this catalogue:

> **Harvested device templates are dirty, the sanitiser only cleans one level of
> dirt, and the validator counts rather than checks.**

The generator is careful about port-level residue (`sanitize()`), careful about
port-level power (`power_cabled_ports()`), careful about port names
(`port_model.json`), and stops one level short on server service blocks. The
validator then reports the resulting inflated counts as `RESULT: PASSED (0
warnings)`.

The generalisable form: *when you import a structure from an external template,
sanitize every field you did not author, and make the validator assert
uniqueness wherever a count is reported.* `validate.py` already does this for
device names and end-device IPs — extending it to AAA clients, DHCP pools and
DNS records would have caught four of the five problems at build time.

---

## Resolution log

Every open item above has since been fixed, or bounded with evidence. This
section is the record: what changed, and how it was checked. Line references are
to the source package under `generators/jasdf_aewc/`.

The artefact the fixes were verified against:

| | |
| --- | --- |
| `JASDF_AEWC_JADGE.pkt` | 290 devices, 326 links, 1,134,251 B, `e7945dac…` |
| `JASDF_AEWC_JADGE_standard.pkt` | 199 devices, 227 links, 847,355 B, `c9317ef…` |

and both are reproduced byte-for-byte by `./run_all.sh enterprise|standard`.

### The defect cluster (1–5) — fixed

`build_jasdf_aewc.py` now calls `strip_template_leftovers()`, which uses
`pkt_core.audit.sanitize_template_leftovers` with the generator's own template
library, so **only records the device's template carries** are removed and
authored records survive. It runs once over the DEVICE table, and the count it
removed is recorded in `build/report_*.json` as `template_leftovers_removed`
with a per-family breakdown.

| family | before | after |
| --- | --- | --- |
| AAA clients | 202 raw / 140 distinct / 63 leftovers | **139 / 139 / 0** |
| DHCP pools | 259 raw / 133 distinct / 128 leftovers | **131 / 131 / 0** |
| AAA users | 65 raw / 3 distinct / 63 leftovers | **2 / 2 / 0** |
| FTP accounts | 64 raw / 3 distinct / 62 leftovers | **2 / 2 / 0** |
| DNS records | 496 raw / 248 distinct / 0 leftovers | **unchanged — correct** |

Two families were **not** in the original catalogue and were found while fixing
these: `aaa_users` (63 copies of `user`) and `ftp_accounts` (62 copies of
`cisco`), both the same defect.

DNS was left alone deliberately. Two DNS servers holding the same 248 records is
*replication*, not duplication, and a sanitiser that deduplicated it would delete
one server's zone. `validate_lab` reports it as `496 raw, 248 distinct` and
raises no finding; `test_real_artefact_needs_no_sanitising` pins that.

### 4 — `validate.py` no longer reports a false pass

Section 8 of `validate.py` used to count occurrences. It now delegates to
`pkt_core.audit`: it prints **raw and distinct** for every family, marks template
leftovers, and turns every audit finding into a failure or a warning. Verified in
both directions on the real artefact:

```
clean file      RESULT: PASSED (0 warnings)                      exit 0
one duplicated  FAIL duplicate-aaa-client: AAA client 10.255.0.11
AAA client      occurs 2 times (140 counted, only 139 distinct)
                RESULT: FAILED (1 failures, 0 warnings)         exit 1
```

This is the change that would have caught problems 1, 2 and 5 at build time, and
it is now the rule the whole toolkit follows: **if a validator prints a count, it
must prove those items are distinct.**

### 6 — layout: overlap and off-page, fixed at the source

The generator's hand-typed grids are gone. `JASDF.add()` routes placement through
`lab_api.Layout`, which packs label-inclusive boxes row-major inside semantic
tier bands with an 80-unit centre floor and a page wrap. Measured on the
shipped enterprise artefact:

| metric | before | after |
| --- | --- | --- |
| device pairs ≤ 40 u apart | 12 | **0** |
| pairs ≤ 80 / ≤ 120 | 21 / 84 | 0 / 1 |
| **label boxes overlapping** | 111 (+2 touching) | **0** (+1 touching) |
| nearest neighbour min | 30.4 u | **114.0 u** |
| devices off the ~3900×3900 page | **60** | **0** |
| bounding box (centres) | X[60,3700] Y[130,**5140**] | X[117,3738] Y[116,2966] |

The gap between 12 icon pairs and 111 label-box overlaps is the measurement error
that let this ship: **counting icons instead of labels understates the problem by
about 9×**, because Packet Tracer draws the model caption above and the device
name below each icon. The whole `AB-HAMAMATSU` block (60 devices, y=4200–4580)
was off-screen.

Human-authored labs are the reference: over 167 devices from 15 corpus files the
nearest-neighbour minimum is 50.2 u and **zero** pairs sit within 40 u.

### 7 — `install_module` bay semantics, fixed

`bay=N` for N > 0 now **raises** instead of silently skipping a bay, because it
indexed the list of *currently empty* slots, which renumbers as they fill.
`slot=N` is the absolute bay index. The generator passes neither (meaning "the
next empty bay"). Nine tests in `tests/test_install_module.py` pin the four
distinguishable behaviours.

### 8–14, 21–23, 27–29 — previously fixed or cleared, re-verified

Device power is now 290/290 and 199/199 with all 2,454 and 1,721 port `POWER`
values `true`; `PORT`/`POWER` and `POWER` attributes were audited exhaustively.
Serial bearers, access-point ports, the airborne L2 domain, port names and
harvested NIC addresses remain fixed. The abstractions (21–23, 29) and the
cleared items (28, 30) are unchanged.

### 16 — DHCP pool names collide — fixed

Site 11 (the JADGE data centre) and site 29 (air base AB-IRUMA) were both
labelled `IRUMA`, so both derived `IRUMA-VLAN10` for different subnets. Packet
Tracer pools are name-keyed, so one shadowed the other. Each now uses the prefix
its devices already carry — `JADGE-DC-VLAN*` and `AB-IRUMA-VLAN*` — and the
generator **asserts pool-name uniqueness before emitting**, so the class of bug
cannot return silently. `generators/jasdf_aewc/pool_renames.json` migrates files
built by the older generator.

### 17 — config-line count — reconciled by stating the method

Two numbers, two methods, and the fix is to print both rather than pick one:
lines on the **143 IOS/ASA devices**, and raw `<LINE>` elements across all **205**
`RUNNINGCONFIG` blocks. Every report and `validate.py` now carry the method with
the figure.

The figures currently read **22,648** and **22,896**. They were 22,579 / 22,827
until problems 34 and 37 were fixed: a device that was shipping a harvested
template's factory default now carries a real configuration, so the total moved
by 69 lines. That the number is checkable is exactly why the change is visible
and explicable -- see problem 35 for why the *definition* also had to change.

### 18 — stale build reports — fixed

`run_all.sh` passes `--update-report` to `finalise_lab.py` after the last step
that touches the artefact, so `size_bytes` and a new `sha256` describe the file
that actually exists. Two reporting bugs were fixed at the same time: `devices_powered_on`
reported *repairs performed*, so a correctly built lab read `0` — which looks
exactly like "nothing is powered"; it is now
`devices_switched_on_by_repair`, with `devices_with_power_true` carrying the
truth. All three profiles now report `0` repairs and 290/199/134 powered.

### 19 — dead code — removed

The unused `loop` placeholder comprehension is gone.

### 15, 20, 24, 25, 26 — bounded, and where they now stand

* **15 (STP convergence).** The amber port dots seen on first open are Packet
  Tracer's spanning-tree blocking/learning state, not a power fault — confirmed
  by loading the file in real Packet Tracer. Convergence is a PT runtime
  property and remains run-dependent; it is a property of the model's size, not
  of the file.
* **20 (PT's IOS is a subset).** `tools/audit_ios_commands.py` cross-references
  every emitted IOS line against what the 952-file reference corpus attests,
  classifies each unattested line as standard-Cisco or suspicious, and exits
  non-zero on the latter.
* **24 (no end-to-end traffic).** Still the honest limit: the model is verified
  as *loadable and structurally sound*, and now also *rendered and powered* in
  real Packet Tracer 9.0.1, but not as *functionally routed*.
* **25 (only the airborne tier inspected).** Addressed from two directions.
  Analytically, the layout gate now covers **all 290** devices rather than one
  tier: it reports 0 overlapping label boxes, 0 devices off-page and 0
  coincident pairs across the whole canvas, so the specific failure this problem
  warned about ("overlapping icons would not have been noticed") is now a
  build-time check rather than something a screenshot has to catch. Visually,
  the file has been loaded in Packet Tracer 9.0.1 and the physical rack and the
  logical topology confirmed to render with all devices powered — see
  `PACKET_TRACER_VALIDATION.md`. A tier-by-tier photographic sweep of the
  logical canvas remains the one thing not done; `tools/pt_runtime_verify.py`
  automates it.
* **26 (only PT 9.0.1 tested).** Still true, and now stated correctly. PT 9.0.1
  runs headless under Xvfb (`xvfb-run -a /usr/local/bin/packettracer file.pkt`)
  after a one-time account sign-in; PT 7.3.1 is no longer installed here. The
  earlier claim that the visual check "is not completable against PT 9.x" was
  wrong and has been corrected in `PACKET_TRACER_VALIDATION.md`.

### 31 — the build was not reproducible — fixed

Found while verifying 17 and 18, and not in the original catalogue. The generator
allocated physical-workspace UUIDs with `uuid.uuid4()`, so **two runs of the same
model produced different bytes** and the SHA-256 published with the package could
not be re-derived by anyone. Every difference between two runs traced to exactly
two call sites (`ORIGINAL_DEVICE_UUID` and the physical leaf `UUID_STR`); the
rest of the XML was already byte-identical.

Both now derive from stable inputs with the v4 version/variant bits stamped on
(`lab_api._det_uuid`), so the identifiers are indistinguishable in form from
Packet Tracer's own:

```
                        occurrences  distinct  max-refs  <UUID_STR> defs
PT-native (random)           3784       586       582           295
regenerated (deterministic)  3784       586       582           295
```

Masking every UUID makes the regenerated XML byte-identical to the original
(11,523,711 bytes both ways), all 3,784 carry version nibble 4, and all 295
definitions are correctly braced. Two consecutive runs are now byte-identical,
which is what makes the published hash a checkable claim rather than a receipt.

`tests/test_reproducible_build.py` pins it, including an assertion that
`uuid4()` no longer appears in `lab_api.py`.

### 32 — the shipped package could not be run by its recipient — fixed

Three absolute paths from the author's machine had leaked into the package:
`run_all.sh` pointed `PY` at a venv in a *different* checkout, and both
`build_jasdf_aewc.py` and `validate.py` defaulted `PKT_TOOLKIT` to
`/home/saoria/...`. `run_all.sh` now uses `${PY:-python3}`, discovers the toolkit
by searching upwards for `tools/lab_api.py` + `src/pkt_core`, verifies `pkt_core`
is importable, and fails with an actionable message instead of a traceback.

### 33 — the sanitiser failed silently on a document root — worked around

`audit._engine_views()` resolves `DEVICE/ENGINE`, and returns an empty list for
anything else — including a whole-document root. `sanitize_template_leftovers`
therefore returns an empty report for a document root, which reads exactly like
"nothing to clean" while removing nothing. The generator now iterates the DEVICE
table explicitly. The upstream fix is for the helper to raise when a target
resolves to no engine at all; until then, callers must pass DEVICE elements.


### 34–38 — the same defect as 1–5, one level down: a template always supplies *something*

Found while auditing the IOS command signatures (problem 20), and they are one
story. Everything below is the same mistake as the original cluster: **a check
for presence is not a check for authorship, because a harvested template always
has an answer.**

#### 34 — 20 devices shipped another lab's factory-default config

The harvested device templates store a complete `STARTUPCONFIG` — the config
Packet Tracer writes on a factory-fresh device — and `add_device` copied it in.
So 16 `IR1101` radar routers and 4 ASA 5505s shipped:

```
RDR-*-RTR (IR1101, 16x)   76 lines, 'hostname Router',   version 17.10.1,
                          enable secret 5 $1$mERr$A0KmwwybwYdjSTcVdJ15p0
FW-* (5505, 4x)           70 lines, 'hostname ciscoasa', ASA Version 8.4(2),
                          ': Written by enable_15 at 00:00:00 UTC Mar 1 1993'
```

`$1$mERr$A0KmwwybwYdjSTcVdJ15p0` is the type-5 hash of **`cisco`**, the publicly
known default. Those 16 devices also carried the intended secret in their
*running* config, so the file disagreed with itself about how to log in — and a
device whose startup and running secrets differ is one nobody can secure by
reading the file.

`clear_template_startup_config()` now removes the residue. It clears rather than
mirrors `RUNNINGCONFIG`, because that is what real labs do: across **4,729
devices in 1,014 corpus files**, 60% have no `STARTUPCONFIG` element at all and
23% have an empty one, so **83% carry no startup config**; where one exists it is
that lab's own. Packet Tracer loads these files from `RUNNINGCONFIG` — 123 of the
290 devices here already had an empty startup config and loaded correctly.

#### 35 — two tools, one statistic, two definitions

`ConfigLineStats.ios_blocks` counted devices whose `<ENGINE>` carried a
`<STARTUPCONFIG>` **element**. `validate.py` counted devices whose **model** is
in a nine-entry allow-list. Both reported 143 — by coincidence, and for opposite
reasons: the audit was counting 123 *empty* elements plus the 20 residue-carrying
ones, i.e. precisely the devices that were wrong.

Fixed by giving the audit the same model allow-list
(`NETWORK_DEVICE_MODELS`), so the two cannot disagree, and by correcting the
label from "143 IOS devices with STARTUPCONFIG" to "143 IOS/ASA devices, by
model". A statistic two tools derive differently is not a statistic.

#### 36 — nobody wrote the credentials down

`jasdf_kit.py` defines `ENABLE_SECRET` and `ADMIN_SECRET` as Cisco type-5
hashes. The plaintext was never recorded, and 138 of the 143 devices run
`aaa new-model` with `login authentication default` — so **the lab cannot be
logged into from the artefact**. Agent tooling hit this directly: an attempt to
open a device CLI for an end-to-end ping could not authenticate.

Fixed by documenting it: the package README and the loose copy now carry a
**Credentials** section listing what *is* readable in the file (RADIUS key, SNMP
communities, HSRP key, web portal login) and stating plainly that the enable and
admin secrets are unrecoverable, with the two ways to get CLI access (Packet
Tracer's Config tab, or rebuild with your own `ENABLE_SECRET`).

#### 37 — a documented device shipped unconfigured

`COALITION-GW-01` was added at `10.255.0.7`, cabled to the backbone and to
`FW-COALITION`, and named in the design as the AS65001 side of the cross-domain
eBGP session. `PARTNER-RTR-01` was configured to peer with `10.255.0.7`. But
`"cgw"` appeared in exactly three places — the `add()`, and two `rlink()` calls —
and never in `configure()`. The device shipped the template default, so the
gateway's interfaces were down, its address existed only in the design document,
and **the documented eBGP path could not come up**.

It now has a full config: loopback `10.255.0.7/32`, `GigabitEthernet0/0/1` on the
design's `10.99.6.1/30` (the link to `FW-COALITION`, whose side is `10.99.6.2`),
OSPF area 0, a specific route to the partner LAN, and `router bgp 65001` peering
with `10.254.0.2` (AS65002, `ebgp-multihop 2` across the firewall). `rlink` had
allocated a generic /30 for that link; the address is re-pointed to the design's
so `ifaces()`, the OSPF statement and the address plan all agree.

#### 38 — the validator that let 34 and 37 through

`validate.py` asserted that every network device "carries a config" — which a
factory default satisfies. It now also requires the config to name the device:

```
misnamed = [devs[s] for s in netdev if f"hostname {devs[s]}" not in cfgs[s]]
```

`hostname <its own name>` is the cheapest assertion a template default cannot
satisfy. Verified in both directions:

```
previous artefact   FAIL  1 network devices carry a config that does not name
                          them (template default or wrong device):
                          ['COALITION-GW-01']        exit 1
rebuilt artefact    ok    config identity: all 143 configs set 'hostname <device>'
```

### Effect on the published figures

Two numbers moved, and that is the point of stating the method with the figure:

| | before | after |
| --- | ---: | ---: |
| lines on IOS/ASA devices | 22,579 | **22,648** |
| `<LINE>` elements, all blocks | 22,827 | **22,896** |

The +69 is `COALITION-GW-01` gaining a real configuration. Because both figures
are recomputed from the artefact by `validate.py` and `pkt audit`, the change is
visible and explicable rather than silent.

### Artefacts after 34–38

| file | sha256 |
| --- | --- |
| `JASDF_AEWC_JADGE.pkt` (290 devices, 1,128,475 B) | `c40c14178f3334280a4cd41f9c4b12656cc21bb4fa5bd89fa0baceb8418ae3e6` |
| `JASDF_AEWC_JADGE_standard.pkt` (199 devices, 843,321 B) | `b7857876ca4b01c1cb686dde3ec4df75a4e066f5f3b505da9c38ba96ceceef6f` |

Both pass every gate, and `./run_all.sh` reproduces them byte-for-byte.
