#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
harvest_library.py -- (re)build the shipped device/module/shape libraries from a
set of `.pkt`/`.pka` files (e.g. the sample labs Packet Tracer ships).

    python3 harvest_library.py --saves /opt/pt/saves --activities ./labs \
        --out-models tools/device_templates.json \
        --out-shapes tools/device_shapes.json

* models : one complete <DEVICE> block per model (gzip+base64).
* modules: one <SLOT> subtree per module model.
* shapes : complete scoring device nodes per model (from activity files).
"""
import argparse
import base64
import glob
import gzip
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import pt9       # noqa: E402
import scoring   # noqa: E402
import lab_api   # noqa: E402


def _files(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            out += glob.glob(os.path.join(p, "**", "*.pkt"), recursive=True)
            out += glob.glob(os.path.join(p, "**", "*.pka"), recursive=True)
        else:
            out.append(p)
    return sorted(set(out), key=os.path.getsize)


def _dec(path):
    return pt9.decode(path, "pkt", verify_tag=False)


def harvest_models(files):
    """Harvest one <DEVICE> block per model, plus one <SLOT> block per module.

    Device-level <ENGINE><POWER> is normalised to "true" on the way in (see
    lab_api.normalise_device_power): the donor save is just whichever save
    happened to be on disk, so its per-device power state is not part of a model
    definition -- a single off donor poisoned every 3650-24PS in the JASDF-AEWC
    model (docs/POWER_INVESTIGATION.md).  Returns (models, modules,
    power_normalised), where power_normalised lists the models whose donor block
    was off/absent ("was off in donor save") and is recorded in the output JSON
    so the artefact cannot silently recur.
    """
    models, modules, off = {}, {}, []
    for f in files:
        try:
            xml = _dec(f)
        except Exception:
            continue
        for m in re.finditer(rb"<DEVICE>.*?</DEVICE>", xml, re.S):
            blk = m.group(0)
            mm = re.search(rb'<TYPE[^>]*model="([^"]*)"', blk)
            if mm and mm.group(1).decode() not in models:
                model = mm.group(1).decode()
                blk, was_off = lab_api.normalise_device_power(blk)
                if was_off:
                    off.append(model)
                models[model] = blk
        txt = xml.decode("utf-8", "replace")
        for mm in re.finditer(r"<MODEL>([^<]+)</MODEL>", txt):
            name = mm.group(1)
            if name in modules or name in ("", "PT-IOT-CUSTOM-IO"):
                continue
            i = txt.find("<MODEL>%s</MODEL>" % name)
            a = txt.rfind("<SLOT>", 0, i)
            b = txt.find("</SLOT>", i) + len("</SLOT>")
            if a >= 0 and b > a and len(txt[a:b]) < 20000:
                modules[name] = txt[a:b].encode()
    return models, modules, off


def harvest_shapes(files):
    xmls = []
    for f in files:
        try:
            x = _dec(f).decode("utf-8", "replace")
        except Exception:
            continue
        if "<PACKETTRACER5_ACTIVITY>" in x:
            xmls.append(x)
    return scoring.harvest_shapes(xmls)


def _gz_b64(b):
    return base64.b64encode(gzip.compress(b, 9)).decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--saves", nargs="*", default=[])
    ap.add_argument("--activities", nargs="*", default=[])
    ap.add_argument("--out-models", default=os.path.join(HERE, "device_templates.json"))
    ap.add_argument("--out-shapes", default=os.path.join(HERE, "device_shapes.json"))
    a = ap.parse_args()

    files = _files(a.saves + a.activities)
    models, modules, off = harvest_models(files)
    shapes = harvest_shapes(_files(a.saves + a.activities))
    json.dump({"gz": True,
               "models": {k: _gz_b64(v) for k, v in models.items()},
               "modules": {k: _gz_b64(v) for k, v in modules.items()},
               "power_normalised": off},
              open(a.out_models, "w"))
    scoring.save_shapes(shapes, a.out_shapes)
    print(f"models={len(models)} modules={len(modules)} shapes={len(shapes['models'])} "
          f"-> {a.out_models} ({os.path.getsize(a.out_models)} B), {a.out_shapes}")
    if off:
        print("device <ENGINE><POWER> normalised to true (was off in donor save): "
              + ", ".join(off))


if __name__ == "__main__":
    main()
