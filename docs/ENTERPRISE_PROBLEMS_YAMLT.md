# Enterprise-scale problem catalogue — Y-AMLT container terminal

Every problem hit while producing the 386-device, 380-link Packet Tracer model
described in [`aacanadaa/large-scale-packet-tracer`](https://github.com/aacanadaa/large-scale-packet-tracer):
bugs, workarounds, limitations, dead ends, and "this didn't work, so we did X
instead" moments.

This is the **second** catalogue in this repository. The first,
[`ENTERPRISE_PROBLEMS.md`](ENTERPRISE_PROBLEMS.md), is the JASDF AEW&C build and
produced rules 1–6 of `SKILL.md`. This one produced **rules 7 and 8** — the two
failure modes that a lab can ship with while passing every gate the first
catalogue taught you to run.

**Legend.** Status: **FIXED** (code addresses it and a command verifies it),
**BOUNDED** (a property of Packet Tracer or of the model's scope, not a defect to
repair), **NOT-A-BUG** (investigated and cleared), **ABSTRACTION** (deliberate
modelling choice).

---

## Summary

| # | Problem | Severity | Status |
| --- | --- | --- | --- |
| 1 | One unresolvable port name makes the **entire file** unopenable | Critical | **BOUNDED** — verified by gate 5 |
| 2 | Three corpus-"attested" port names are rejected by PT 9.0.1 | Critical | **FIXED** |
| 3 | `ENGINE/TYPE` text is the device *class*, not the model | High | **FIXED** |
| 4 | The reference corpus cannot attest industrial/IoT models at all | High | **BOUNDED** |
| 5 | Packet Tracer's own `.ptd` templates carry no port names | Medium | **BOUNDED** |
| 6 | 87 cabled ports that nothing configured | Critical | **FIXED** — gate 0 |
| 7 | A blanket ASA `shutdown` also shuts the *outside* port | Critical | **FIXED** |
| 8 | Core-switch trunks covered the routed ports | Critical | **FIXED** |
| 9 | Switch downlinks declared access while the far end was a trunk | High | **FIXED** |
| 10 | Router-on-a-stick parent interface never brought up | High | **FIXED** |
| 11 | Template service *blocks* ship `<ENABLED>1</ENABLED>` | High | **FIXED** |
| 12 | `<USER>` in `<EMAIL_CLIENT>` counted as an AAA user | Medium | **FIXED** |
| 13 | DHCP/AAA identities are document-wide; DNS is per server | Medium | **BOUNDED** |
| 14 | The page, not the device count, is the binding constraint on scale | High | **BOUNDED** |
| 15 | OCR of the rejection modal reports rejected files as accepted | High | **FIXED** |
| 16 | Rapid successive PT launches raise a spurious "Incompatible File" | Medium | **BOUNDED** |
| 17 | Startup prompts make a successful load look like a timeout | Medium | **FIXED** |
| 18 | Red pixels in the render that are device artwork, not links | Medium | **NOT-A-BUG** |
| 19 | Keyboard accelerators do not work under a bare Xvfb | Medium | **FIXED** |
| 20 | `xdotool mousemove --sync` hangs without a window manager | Low | **FIXED** |
| 21 | `ctrl+s` does not save, so a save-based check cannot be built | Medium | **BOUNDED** |

---

## 1 — One unresolvable port name makes the entire file unopenable

**Severity: Critical. Status: BOUNDED** (a property of Packet Tracer).

`lab_api.link()` stores the port-name string in the `<LINK>` verbatim and Packet
Tracer resolves it at load time. When a name matches no port on its device,
Packet Tracer does **not** drop that one cable and carry on. It refuses the whole
document:

```
Unable to open file. The file ... is not compatible with this version of
Cisco Packet Tracer
```

Measured: a 37-model probe with ~40 cables failed to open because of one bad
name, while every one of those 46 models loads fine in a two-device file. On the
386-device build the same message appeared for three bad names.

There is no partial failure to inspect and no device named in the message. The
only defences are (a) never invent a port name, and (b) gate 5 before shipping.

**Why "BOUNDED" and not "FIXED":** the behaviour is Packet Tracer's. What is
fixed is our exposure to it — see #2.

## 2 — Three corpus-"attested" port names are rejected by PT 9.0.1

**Severity: Critical. Status: FIXED.**

The reference corpus is the strongest evidence available for most format facts.
For port names it is **evidence of what some older Packet Tracer wrote**, not of
what this one accepts. Measured against PT 9.0.1:

| Model | Corpus/earlier name | Rejected | Accepted instead |
| --- | --- | --- | --- |
| `7960` IP phone | `FastEthernet0` | yes | **`Switch`** (uplink), `PC` (passthrough) |
| `Cloud-PT` | `GigabitEthernet0` | yes | **`Port 0`** |
| `WLC-3504` | `GigabitEthernet0/1` | yes | **`GigabitEthernet1`** |

Also tried and rejected: `Ethernet0/1/2`, `GigabitEthernet0/0..0/5`,
`GigabitEthernet0/1/1`, `Serial0/0/0`, `Coaxial1` on those models.

**Fix.** A four-tier port-name table with the tier recorded per name, and — this
is the part that matters — the rejected names are **removed** from the table
rather than annotated. A table that still permits a name Packet Tracer rejects
will happily pass a link the artefact cannot carry.

## 3 — `ENGINE/TYPE` text is the device *class*, not the model

**Severity: High. Status: FIXED.**

```xml
<ENGINE><TYPE model="3650-24PS">MultiLayerSwitch</TYPE></ENGINE>
```

`d.findtext("ENGINE/TYPE")` returns `"MultiLayerSwitch"`. Every port table is
keyed by the **`model=` attribute**, so a reader that takes the text misses every
lookup — silently.

This was not hypothetical: a first corpus mine keyed on the text reported
"28 models of interest, all zero" and looked like it had run successfully. The
true finding was different (see #4), and the false zero nearly hid it.

```python
t = dev.find("ENGINE/TYPE")
model = (t.get("model") or (t.text or "")).strip()
```

## 4 — The reference corpus cannot attest industrial/IoT models at all

**Severity: High. Status: BOUNDED.**

A full mine of all 952 locally-held corpus files found **zero** instances of
`IE-9320`, `IE-3400`, `IE-2000`, `IR1101`, `IR8340`, `ISA-3000`, `CGR1240`,
`PLC-PT`, `HMI-PT`, `RFID Reader`, or any sensor family. The corpus is CCNA-era
lab gear — 28 device classes in total.

So for the entire industrial estate this model is built around, the corpus is
silent. Names had to be established by testing against a real Packet Tracer
instead, and labelled as inference until they were.

## 5 — Packet Tracer's own `.ptd` templates carry no port names

**Severity: Medium. Status: BOUNDED.**

The 89 `.ptd` files inside `packettracer.AppImage` decode cleanly with the
toolkit's own codec (`pt9.decode(path, "pkt")`), which raised the hope that they
were the authoritative port-name source. They are not: they describe **modules
and slots** (`PT-IOT-NM-1CFE`, `PT-IOT-NM-1CGE`), not instantiated port names.

They are still useful — the module type is what makes the convention tier
possible (`eCopperFastEthernet` x1 → `FastEthernet0`) — but the convention is
inference and must be verified.

## 6 — 87 cabled ports that nothing configured

**Severity: Critical. Status: FIXED.** → `SKILL.md` Rule 7.

The generator drew Layer-3-to-Layer-3 links with `link()` instead of `rlink()`.
`link()` is documented as drawing a cable and setting electrical properties; the
generator's "routed interfaces" registry never learned about those ports, so no
`interface` block was ever emitted. One core router shipped with **no interface
blocks at all** for either of its uplinks.

Nothing caught it. Layout passed, the audit passed, the round-trip passed — the
links simply never came up.

**Fix.** Two parts, and the second is the one that keeps it fixed:

1. derive each port's role from the peer it is cabled to, so a routed port can
   never also be written as a trunk and every cabled port is classified;
2. **gate it** — `tools/audit_links.py` reads the written artefact and asks one
   question per cable, *would this port come up?* It needs no cooperation from
   the generator, which is what makes it a real check.

Measured: 87 → 0. Sabotaging a single `no shutdown` makes the tool name the
device, port and peer.

## 7 — A blanket ASA `shutdown` also shuts the *outside* port

**Severity: Critical. Status: FIXED.**

The ASA config generator ended with the idiomatic

```
interface Ethernet0/0
 shutdown
```

intended to park unused ports. But `Ethernet0/0` was also assigned to the
**outside** zone. Five firewalls shipped with their uplink administratively down.

**Fix.** Compute the set of ports any zone claims (`{p for z in zones for p in
z["ports"]}`) and shut only the ports nothing claims:

```python
for p in (f"Ethernet0/{i}" for i in range(8)):
    if p not in zoned_ports:
        cfg += [f"interface {p}", " shutdown", "!"]
```

## 8 — Core-switch trunks covered the routed ports

**Severity: Critical. Status: FIXED.**

The collapsed-core switches were configured with

```python
trunks = [GE1(j) for j in range(1, 25)]     # every port
```

which includes the ports holding routed `/30`s to the core routers. The config
emits routed ports first and trunks second, so the **later** block applied: the
port reverted to Layer 2 and every routed neighbour died.

**Fix.** Trunks are derived as *cabled ports minus routed ports*:

```python
trunks = [p for p in cabled_ports(key) if p not in routed_ports(key)]
```

A port's mode is now emitted exactly once, and it is impossible to write both.

## 9 — Switch downlinks declared access while the far end was a trunk

**Severity: High. Status: FIXED.**

45 link endpoints had one end a trunk and the other an access port in a
different VLAN — typically a yard aggregation switch with 16 block-facing ports
declared `access vlan 70`, facing block switches whose uplink was correctly a
trunk. The link comes up and forwards nothing, which is worse than down: it
looks fine.

**Fix.** Same principle — the role follows the peer. A port whose peer is itself
a switch is a trunk; a port facing a firewall's access port is access in *that*
VLAN, so both ends agree.

## 10 — Router-on-a-stick parent interface never brought up

**Severity: High. Status: FIXED.**

Zone routers use subinterfaces (`GigabitEthernet0/0/1.10`). The generator emitted
a block for each subinterface and **nothing for the physical parent**. A
subinterface inherits the parent's state, and a router interface is
administratively down by default — so every zone router carried nothing.

**Fix.** Emit the parent alongside the subinterfaces:

```python
ifaces = [("GigabitEthernet0/0/1", "", M24)]        # parent, no address
for v in vlans:
    ifaces.append((f"GigabitEthernet0/0/1.{v}", host(site, v, 1), M24))
```

## 11 — Template service *blocks* ship `<ENABLED>1</ENABLED>`

**Severity: High. Status: FIXED.** → `SKILL.md` Rule 4.

Rule 4 says to sanitise every field you did not author, and `sanitize()` reached
service *records*. It did not reach the **blocks**: a harvested template ships
`<NTP_SERVER><ENABLED>1</ENABLED></NTP_SERVER>` on appliances that serve no time
at all. With the records correctly stripped, the empty shell still says "enabled".

Measured: **52 devices advertising themselves as NTP servers and 52 as HTTP
servers**, none of which anyone authored. The record-level audit sees nothing
wrong.

**Fix.** Two different jobs for two different cases:

```python
# on a device we DO configure: clear every block, then write only what was asked
_strip_service_blocks(eng); write(requested)

# on a device we do NOT configure: remove the blocks entirely
if key not in serviced:
    _strip_service_blocks(eng)
```

Measured effect on the published figures: `ntp/http/syslog servers` **52 → 1**,
`aaa servers` **248 → 1**, `dhcp servers` **57 → 1**.

## 12 — `<USER>` in `<EMAIL_CLIENT>` counted as an AAA user

**Severity: Medium. Status: FIXED.**

`iter("USER")` over a device matches not only `ACS_SERVER/.../USER` but also the
empty `<USER>` child of every device's inert `<EMAIL_CLIENT>` block. A
document-wide count reported **248 AAA servers** on a model that has one.

**Fix.** Scope a concept lookup to the subtree that owns it:

```python
acs = d.find(".//ACS_SERVER")
if acs is not None and (list(acs.iter("CLIENT")) or list(acs.iter("USER"))):
    ...
```

Generalisation: generic element names (`USER`, `NAME`, `TYPE`, `PORT`, `IP`)
appear in unrelated subtrees. Never count them document-wide.

## 13 — DHCP/AAA identities are document-wide; DNS is per server

**Severity: Medium. Status: BOUNDED.**

`duplicate-dhcp-pool` and `duplicate-aaa-client` are **document-wide**, because
Packet Tracer keys those records by identity across the whole file. Running a
standby DHCP server with the same pools is therefore indistinguishable from
duplication, and the gate fails either way.

DNS is the modelled exception: a zone is a *set per server*, so two DNS servers
holding the same 384 records is replication and is reported as
`768 records (384 distinct × 2 servers)`.

**Resolution.** One authoritative server per DHCP/AAA service; the standby node
is present and addressed but holds no records, and the design document says so
rather than letting a passing gate imply redundancy that is not there.

## 14 — The page, not the device count, is the binding constraint on scale

**Severity: High. Status: BOUNDED.** → `SKILL.md` Rule 2.

`check_layout.analyse()` calls `on_page(x, y)` with `allow_wrap=False`, and
`finalise_lab.py` gates on `off_page` being empty — so the packer's page-column
overflow is **not** accepted by the gates. Every device plus its label box must
be on the primary 3900×3900 page. At `ROW_PITCH = 150` that is about **26 rows**.

`lab_api.Layout` gives each semantic tier its own band and stacks bands
vertically, so **each tier costs a row before a device is placed**. A 415-device
arrangement of this terminal did not fit; the same terminal in 12 bands instead
of 18 does.

The levers, in order of effect: fewer tiers (free), shorter device names
(`column_pitch()` jumps 200 → 260 → 320 units at 17 and 25 characters), fewer
devices (last).

## 15 — OCR of the rejection modal reports rejected files as accepted

**Severity: High. Status: FIXED.**

The first detector took a screenshot and ran OCR over it looking for *"Unable to
open file ... not compatible"*. It is unreliable: the screenshot is taken at a
moment, the dialog may appear after it, and grey-on-grey OCR misses often enough
to matter. It reported **rejected files as accepted** twice, sending two
investigations down blind alleys and producing two wrong conclusions that were
each acted on.

**Fix.** Read the verdict from the **window title**:

```
Incompatible File -- Cisco Packet Tracer
```

Unambiguous, and what `pt_runtime_verify.py` uses. `tools/pt_accept.py` is the
standalone version.

## 16 — Rapid successive PT launches raise a spurious "Incompatible File"

**Severity: Medium. Status: BOUNDED.**

Launching several Packet Tracer instances in quick succession can produce the
dialog for a file that is perfectly good. Because that message is Packet
Tracer's *only* parse error, it is indistinguishable by eye from #1 — which is
how a 204-device lab was briefly believed unopenable when it was fine.

**Resolution.** Always batch a **known-good control** with a suspect file. If the
control also fails, the harness is at fault. And reproduce a rejection before
acting on it: the three genuine rejections in #2 reproduce every time, the
spurious ones do not.

## 17 — Startup prompts make a successful load look like a timeout

**Severity: Medium. Status: FIXED.**

A lab built from many device templates makes Packet Tracer raise two
informational prompts after a successful load:

- `Update Devices?` — the file references model versions PT offers to refresh
- `Network Controller External Access` — because the model contains
  `NetworkController` devices (the OT energy controller)

`pt_runtime_verify.py` waits for the *"Please wait. Opening file..."* window to
clear. A modal prompt keeps it on screen, so the load stage reports
`load-timeout` on a document that is already open. The window list
distinguishes them at a glance:

```
['Cisco Packet Tracer - /tmp/lab.pkt -', 'Please wait. Opening file...']    <- loading
['Cisco Packet Tracer - /tmp/lab.pkt -', 'Update Devices? -- Cisco P...']   <- loaded, asking
```

**Resolution.** Dismiss the prompts and screenshot what is drawn — and **do not
claim** the stages that were never reached. On this build, load and render are
verified; convergence and traffic are not.

## 18 — Red pixels in the render that are device artwork, not links

**Severity: Medium. Status: NOT-A-BUG.**

After the cabling was fixed, an automated red-pixel count still found 300 red
pixels in the rendered workspace. All 300 were **device icons**:

- the **Trip Sensor** renders as a trip wire — a red line between two posts;
- the **ASA 5505** has a red front panel.

Neither is a link. Both were confirmed by cropping at 5–6× and looking, after
two rounds of chasing them as link failures.

**Generalisation.** A pixel count is objective but not self-interpreting. Crop
and look before concluding, and compare the *same* canvas region across builds —
a layout shift moves devices out of the crop and silently changes what is being
counted.

## 19 — Keyboard accelerators do not work under a bare Xvfb

**Severity: Medium. Status: FIXED.**

With no window manager there is nothing to deliver an accelerator. `Alt+v` never
opens the View menu; `ctrl+minus` only scrolls the workspace.

**Fix.** Drive the toolbar with `xdotool` clicks, and identify the icons from a
4× crop rather than by guessing. At 1600×1000 the zoom controls are at y=38:
zoom-in (`+`) x=382, reset (`R`) x=416, **zoom-out (`−`) x=450**.

The cost of getting this wrong: clicking 384 repeatedly *zooms in* and produces a
blank white workspace that reads exactly like a render failure. It is not.

## 20 — `xdotool mousemove --sync` hangs without a window manager

**Severity: Low. Status: FIXED.**

`--sync` waits for the pointer to actually move, which never happens on a bare
X display, so the call blocks until its timeout.

**Fix.** Drop `--sync` and pass an explicit timeout:

```python
xdo("mousemove", "450", "38", timeout=10.0)
xdo("click", "1", timeout=10.0)
```

## 21 — `ctrl+s` does not save, so a save-based check cannot be built

**Severity: Medium. Status: BOUNDED.**

An early plan to learn port names by having Packet Tracer *save* the file back
and reading the canonicalised `<PORT>` strings does not work: saving is a
keyboard accelerator (#19), so it does nothing headlessly.

**Resolution.** Read the verdict from window titles and screenshots instead, and
learn port names by testing `(model, port)` pairs — one pair per file, since a
bad name takes the whole file down (#1).

---

## Cost of the two critical classes

| | before | after |
| --- | ---: | ---: |
| cabled ports with no `interface` block | **87** | 0 |
| ports administratively shut | **5** | 0 |
| links whose ends disagreed on trunk/access | **45** | 0 |
| port names Packet Tracer rejects | **3** | 0 |
| `tools/audit_links.py` findings | — | **0** of 380 links |
| red link-indicator pixels in the render | 4538 | **300** (all device artwork, #18) |

Both critical classes were invisible to every gate the first catalogue produced.
That is the whole reason rules 7 and 8, and gates 0 and 5, now exist.
