# Validation against the real Packet Tracer application

The project proves `encode(decode(f)) == f` **byte-for-byte on 1,058 real
containers**, which is the strongest available evidence that the codec is
correct. This document covers the *other* claim in the brief: that the Packet
Tracer application itself accepts what we write.

## Status

| Check | Result |
| --- | --- |
| Container round-trip byte-exact | **1058 / 1058** |
| Packet Tracer opens a repacked file | **PASS — verified visually in PT 7.3.1 and PT 9.0.1** |
| Original vs repacked render | **identical** (92 of 1,600,000 pixels differ — the ticking clock) |
| **A modified, re-encoded file opens in PT 9.0.1** | **PASS** — semantic edit rendered correctly |

Harness: [`tools/verify_in_packet_tracer.sh`](../tools/verify_in_packet_tracer.sh).

## What was done

Cisco Packet Tracer **9.0.1** was obtained (the exact build the format
specification derives from, matching the corpus maximum `<VERSION>9.0.1.0858`),
installed, and run headless under Xvfb.

The application **starts, renders, and reports no load error** for the test
file — the log contains only Content-Security-Policy noise from its embedded
web view (doubleclick/linkedin telemetry), nothing about the file.

## Result: PASS

Packet Tracer **7.3.1** loaded both an original corpus file and our repacked
copy and rendered the topology identically:

* Devices placed and labelled — `Laptop24`, `Switch0` (2960-24TT), `PC0`,
  `DHCP Server` (Server-PT), `Router0`, `Laptop20`, `Switch5`, `PC8`
* IP annotations correct — `126.1.0.1/2/3`, `126.128.0.2/.10/.22/.25/.42/.45`,
  `126.4.32.2/3`, `126.4.64.2/3`
* Cabling and link lights present
* Canvas annotations (red drawing shapes) preserved
* Device palette, Realtime/Simulation panes and the run timer all functional

Pixel comparison of the two screenshots:

| | |
| --- | --- |
| Absolute-error pixels | **92 / 1,600,000** (0.0057%) |
| Bounding cause | the run-time counter (`00:00:38` vs `00:00:39`) and the status clock |

No load errors were reported in either run. The only dialog Packet Tracer
raised was about an expired *script-module* publisher certificate (the
`Activity Sequence Editor` plugin), which is unrelated to the file.

This closes the Phase 4 acceptance criterion: **a repackaged file opens cleanly
in the real Packet Tracer application.**

## PT 9.0.1 — verified

The login wall was crossed with the operator's own Networking Academy account
(credentials entered directly into the application; the tooling never handled
them), and PT **9.0.1** — the exact build the format specification derives from
— was exercised:

| Test | Result |
| --- | --- |
| Untouched corpus file | Renders: 2811/2960-24TT/PC-PT/Server-PT devices, IP labels, cabling, canvas annotations |
| **Modified + re-encoded file** | **Renders correctly, including the edit** |
| Load errors | none |

The modified file is the test that actually matters. Its bytes were produced by
editing the parsed model and re-encoding — they differ from the original and
were **never written by Packet Tracer**. The edit was a semantic one:

* device `Router0` renamed to `PKT_CORE_RENAMED`
* moved from canvas `(574.5, 196.0)` to `(123, 456)`

Packet Tracer 9.0.1 rendered exactly that: the renamed 2811 appears at the new
coordinates under the label `…ORE_RENAMED`, its old slot is empty, and the
cabling re-routes to the new position.

This closes the acceptance criterion for both claims:

1. `encode(decode(f)) == f` byte-for-byte on 1,058 real files, **and**
2. the real application opens and renders what we write — including files
   Packet Tracer never produced.

## PT 9.0.1 first launch needs an account — but only the first launch

PT 9.0.1 will not proceed past its start screen without a **Cisco Networking
Academy login**:

> *Cisco Packet Tracer — LOGIN. By using Cisco Packet Tracer you accept Terms
> of Service (General Terms & SEULA) and the Privacy Statement.*

`Advanced Settings` offers only two options:

* "Use internal web browser for Cisco Networking Academy login"
* Proxy settings

There is no guest mode. Fabricating or borrowing credentials is not something
this project will do, so the sign-in must be performed by the operator.

**However — and this corrected an earlier conclusion in this document — the
sign-in is one-time, not per-launch.** Once the EULA and account state are
persisted under `~/.local/.packettracer/` (e.g.
`eula-Cisco_Packet_Tracer_9.0.1`), Packet Tracer starts **straight to the
workspace with no network access at all**. The earlier note that the visual
check "is not completable against PT 9.x from this environment" was wrong, and
the 290-device JASDF model has since been re-verified this way — load, render
and power state, though not yet end-to-end traffic (see problem 24 in
`ENTERPRISE_PROBLEMS.md`):

```console
$ xvfb-run -a /usr/local/bin/packettracer /tmp/verify/ent.pkt
```

Confirmed on this machine with `/opt/pt/packettracer.AppImage`: the file opens
with no error dialog, the **physical** workspace renders a populated rack (so
the braced `<PHYSICAL>` UUID path is correct), the logical topology draws with
cables and lit link lights, and every device is powered.

Amber/orange port dots on first open are Packet Tracer's spanning-tree
blocking/learning state and are expected on this lab — see problem 14 in
`docs/ENTERPRISE_PROBLEMS.md`.

## Path to completion on other versions

Older Packet Tracer builds ran without an account at all, which is why the
earlier verification work used them. PT **7.3.1** is additionally the exact
version that wrote a substantial part of the corpus
(`<VERSION>7.3.1.0362`, 98 files). It is *not* installed on this machine any
more; PT 9.0.1 is, and it is sufficient.

```console
$ tools/verify_in_packet_tracer.sh /path/to/7.3.1/opt/pt/bin/PacketTracer \
      /tmp/pt_validation/repacked_0.pkt /tmp/repacked.png
$ tools/verify_in_packet_tracer.sh /path/to/7.3.1/opt/pt/bin/PacketTracer \
      /tmp/pt_validation/orig_0.pkt /tmp/original.png
```

The two screenshots should be identical.

## Reproducing the test files

```console
$ python3 -c "
from pkt_core import decode_bytes, encode_bytes
raw = open('corpus/samples/sample_lab.pkt','rb').read()
c = decode_bytes(raw)
assert encode_bytes(c.xml, c.format_name) == raw
open('/tmp/repacked.pkt','wb').write(encode_bytes(c.xml, c.format_name))
"
```

## Version notes

| Version | Login wall | Notes |
| --- | --- | --- |
| 9.0.1 | **Yes — mandatory** | Installed and exercised here; confirmed no offline mode |
| 8.2.x | Likely | Not yet tried |
| 7.3.x | No | Target for the visual check |
| 6.0.1 and earlier | No | Very old container (see `LEGACY_FORMAT.md`) |

Note that PT 9.0.1 is the *right* binary to test against for the modern
container — it is the build the spec was derived from. If PT 7.3.x opens a
repacked file, that is meaningful evidence for the whole modern family, since
the container is byte-identical across 5.3.3 – 9.0.1.
