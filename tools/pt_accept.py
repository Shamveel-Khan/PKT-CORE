#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""pt_accept.py -- does this Packet Tracer actually accept a given .pkt?

Reads the verdict from the **window title**, which is the only reliable signal:

    Incompatible File -- Cisco Packet Tracer

Why not scrape the modal dialog
-------------------------------
An earlier probe took a screenshot and ran OCR over it to find

    "Unable to open file. The file ... is not compatible with this version of
     Cisco Packet Tracer"

and reported *rejected* files as accepted -- twice, sending two separate
investigations down blind alleys.  A screenshot is taken at a moment; the dialog
may appear after it, and OCR misses grey-on-grey text often enough to matter.
The window title is unambiguous and is what ``pt_runtime_verify.py`` uses.

What "incompatible" actually means
----------------------------------
It is Packet Tracer's only message for a file it will not parse, and it names no
device and no reason.  Measured causes include a **single port name that matches
no port on its device**: one bad name does not kill one cable, it makes the
*entire file* unopenable.  Bisect with ``pt_bisect.py`` rather than guessing.

Two cautions learned the hard way:

* A file that loads perfectly can still raise the dialog when several Packet
  Tracer instances are launched in quick succession.  **Reproduce a rejection
  before believing it**, and always keep a known-good control in the same batch.
* A *successful* load is not proof the lab is right -- see
  ``pt_render_check.py``, which dismisses the startup prompts and screenshots
  what is actually drawn.

    python3 tools/pt_accept.py lab.pkt
    python3 tools/pt_accept.py lab.pkt good-control.pkt
    python3 tools/pt_accept.py lab.pkt --wait 120 --json build/accept.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT), str(ROOT / "tools"), str(ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pt_runtime_verify as V          # noqa: E402

__all__ = ["verdict", "main"]

BAD_TITLE = ("incompatible", "unable to open", "cannot open")


def verdict(tc, path: Path, outdir: Path,
            wait: float = 90.0) -> tuple[bool, str]:
    """``(accepted, evidence)`` for one file, decided by the window title.

    Packet Tracer shows *"Please wait. Opening file..."* while it parses.  Once
    that window is gone and no rejection appeared, the file opened -- so the
    call returns as soon as it can rather than waiting out ``wait``, which keeps
    a bisect affordable.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    work = outdir / f"probe_{path.stem}.pkt"
    shutil.copy2(path, work)
    xs = V.XServer(tc, (1400, 900))
    xdo = V.Xdo(tc, xs.env_display)
    screen = V.Screen(tc, xs.env_display, outdir)
    pt = V.PacketTracer(tc, xdo, screen, xs.env_display)
    titles: list[str] = []
    try:
        xs.start()
        pt.launch(work)
        deadline = time.time() + wait
        saw_wait = False
        while time.time() < deadline:
            names = []
            for wid in xdo.windows(".", pid=pt.pid):
                nm = xdo.window_name(wid)
                if nm:
                    names.append(nm)
                    if nm not in titles:
                        titles.append(nm)
                    if any(b in nm.lower() for b in BAD_TITLE):
                        screen.capture(f"{path.stem}_rejected.png")
                        return False, nm
            if any("please wait" in n.lower() or "opening file" in n.lower()
                   for n in names):
                saw_wait = True
            elif saw_wait:
                return True, "; ".join(titles[-3:])
            time.sleep(0.4)
        return True, "; ".join(titles[-3:])
    except Exception as exc:                                   # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            if pt.pid:
                os.killpg(os.getpgid(pt.pid), signal.SIGTERM)
        except Exception:                                      # noqa: BLE001
            pass
        time.sleep(1.0)
        try:
            xs.stop()
        except Exception:                                      # noqa: BLE001
            pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("labs", nargs="+", type=Path,
                    help="one or more .pkt files; include a known-good control")
    ap.add_argument("--wait", type=float, default=75.0,
                    help="seconds to wait for a verdict (default 75)")
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "accept")
    ap.add_argument("--json", type=Path, default=None)
    a = ap.parse_args(argv)
    if shutil.which("xdotool") is None:
        print("error: xdotool is required (apt-get install -y xdotool)",
              file=sys.stderr)
        return 2
    tc = V.Toolchain.probe()
    if not tc.pt_bin:
        print("error: no Packet Tracer executable found", file=sys.stderr)
        return 2
    results: dict[str, dict] = {}
    for lab in a.labs:
        ok, ev = verdict(tc, lab, a.outdir, a.wait)
        results[lab.name] = {"accepted": ok, "evidence": ev}
        print(f"  {lab.name:36s} {'ACCEPTED' if ok else 'REJECTED'}   {ev[:60]}")
        if a.json:
            a.json.parent.mkdir(parents=True, exist_ok=True)
            a.json.write_text(json.dumps(results, indent=1, sort_keys=True))
    bad = [k for k, v in results.items() if not v["accepted"]]
    print(f"\naccepted {len(results) - len(bad)}/{len(results)}")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
