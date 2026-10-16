#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
make_scored_lab.py -- build a complete, scored Packet Tracer activity (`.pka`)
entirely offline from the shipped libraries:

    tools/network_seed.xml       network seed (physical scene + reusable devices)
    tools/device_templates.json  137 device + 75 module templates (gzip+base64)
    tools/device_shapes.json     scoring device-node shapes
    tools/activity_skeleton.xml  activity wrapper skeleton

Default topology (or pass --spec JSON):

    {"devices":[{"model":"2911","name":"R9","x":250,"y":350,
                 "config":["interface GigabitEthernet0/0"," ip address ..."," no shutdown"],
                 "pc_ip":["192.168.9.10","255.255.255.0","192.168.9.1"],
                 "install":"HWIC-2T"}],
     "links":[{"a":"R9","aport":"GigabitEthernet0/0","b":"SW9","bport":"GigabitEthernet0/1"}],
     "instructions":["<h3>Page 1</h3><p>…</p>","<h3>Page 2</h3><p>…</p>"]}

"instructions" is optional and backward compatible: a single HTML string or a
list of HTML pages (one instruction page per entry).  Without it the
--instructions string is used as a single page.

Flags:
  --prune-seed   drop the devices inherited from tools/network_seed.xml from
                 both the initial and the answer network (default: keep them)
  --feedback S   overall completion message (default "Lab complete - well done!")

The initial network has the topology with no configs; the answer network has the
configs.  Scoring is derived from the answer.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import build_configured_lab as B   # noqa: E402
import activity                    # noqa: E402
import lab_api                     # noqa: E402
import scoring                     # noqa: E402
import pt9                         # noqa: E402

DEFAULT_SPEC = {
    "devices": [
        {"model": "2911", "name": "R9", "x": 250, "y": 350,
         "config": ["!", "version 15.1", "hostname R9", "!", "ip cef", "!",
                    "interface GigabitEthernet0/0", " ip address 192.168.9.1 255.255.255.0",
                    " no shutdown", "!", "end"]},
        {"model": "2960-24TT", "name": "SW9", "x": 450, "y": 350},
        {"model": "PC-PT", "name": "PC9", "x": 650, "y": 350,
         "pc_ip": ["192.168.9.10", "255.255.255.0", "192.168.9.1"]},
    ],
    "links": [
        {"a": "R9", "aport": "GigabitEthernet0/0", "b": "SW9", "bport": "GigabitEthernet0/1"},
        {"a": "SW9", "aport": "FastEthernet0/1", "b": "PC9", "bport": "FastEthernet0"},
    ],
}


def build_network(seed, models, modules, spec, path, configured, prune_seed=False):
    lab = lab_api.Lab(seed, models, modules)
    if prune_seed:
        lab.prune_seed_devices()
    ids = {}
    for d in spec["devices"]:
        ids[d["name"]] = lab.add_device(
            d["model"], d["name"], d.get("x", 100), d.get("y", 100),
            power=d.get("power", True),
            ios_config=(d.get("config") if configured else None),
            pc_ip=(d.get("pc_ip") if configured else None),
            install=d.get("install"))
    for l in spec["links"]:
        lab.link(ids[l["a"]], l["aport"], ids[l["b"]], l["bport"],
                 kind=l.get("kind", "copper"),
                 dce=(ids.get(l["dce"]) if l.get("dce") else None))
    lab.save(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="scored_lab.pka")
    ap.add_argument("--password", default="")
    ap.add_argument("--instructions",
                    default="<h3>Task</h3><p>Configure the network per the topology.</p>")
    ap.add_argument("--spec", help="JSON topology spec (default: R9-SW9-PC9)")
    ap.add_argument("--prune-seed", action="store_true",
                    help="drop the devices inherited from tools/network_seed.xml")
    ap.add_argument("--feedback", default="Lab complete - well done!",
                    help="overall completion feedback message")
    a = ap.parse_args()

    spec = json.load(open(a.spec)) if a.spec else DEFAULT_SPEC
    models, modules = lab_api.load_templates(os.path.join(HERE, "device_templates.json"))
    shapes = scoring.load_shapes(os.path.join(HERE, "device_shapes.json"))
    seed = os.path.join(HERE, "network_seed.xml")

    build_network(seed, models, modules, spec, "/tmp/_pt9_initial.pkt", False,
                  prune_seed=a.prune_seed)
    build_network(seed, models, modules, spec, "/tmp/_pt9_answer.pkt", True,
                  prune_seed=a.prune_seed)
    initial = pt9.decode("/tmp/_pt9_initial.pkt", "pkt").decode("utf-8")
    answer = pt9.decode("/tmp/_pt9_answer.pkt", "pkt").decode("utf-8")

    vals = scoring.derive_values(answer)
    score_spec = [{"name": d["name"], "model": d["model"], "overrides": vals.get(d["name"], {})}
                  for d in spec["devices"]]
    init_sc, comp_sc = scoring.from_shapes(score_spec, shapes)

    act = activity.Activity(os.path.join(HERE, "activity_skeleton.xml"))
    # instruction pages: spec["instructions"] may be a single HTML string or a
    # list of HTML pages; fall back to the --instructions string as one page
    pages = spec.get("instructions", a.instructions)
    if isinstance(pages, str):
        pages = [pages]
    act.set_instructions(list(pages))
    # The activity password is the PASS *attribute* of <ACTIVITY> (ACTIVITY/@PASS).
    # It is NOT <OPTIONS><PASS> -- a different field, left empty here -- so a naive
    # reader of pkt_core.models.LabOptions.password sees "" while
    # pkt_core.models.Lab.activity_password (which reads ACTIVITY/@PASS) gets it right.
    act.set_password(a.password)
    act.set_permissions(locked=False, noguest=False, component_list="Ip, Physical, Other")
    act.set_feedback(incomplete="Keep going.", complete=a.feedback)
    act.set_scoring_xml(init_sc, comp_sc)
    act.set_networks(initial_xml=initial, answer_xml=answer)
    act.save(a.out)
    print(f"wrote {a.out} ({len(open(a.out,'rb').read())} bytes); "
          f"{len(spec['devices'])} devices, {len(spec['links'])} links")


if __name__ == "__main__":
    main()
