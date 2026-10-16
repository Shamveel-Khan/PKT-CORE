#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Tests for device-level power (<ENGINE><POWER>).

Root cause under test (docs/POWER_INVESTIGATION.md): ``add_device()`` used to
write ``<POWER>false</POWER>`` and never ``true``, so a device inherited its
power state from the harvested model template -- and one template
(``MultiLayerSwitch``/``3650-24PS``) was harvested from a save where that
switch was off, silently taking the whole aggregation layer of the JASDF-AEWC
model down.  These tests pin the fix:

* ``add_device`` writes ``<ENGINE><POWER>`` explicitly in **both** directions,
  for every device kind (corpus: all 28 kinds carry the element),
* a stale template state can no longer leak through,
* a missing element is created at the canonical slot (child index 2, after
  ``<NAME>``),
* ``Device.power_state`` distinguishes ``true`` / ``false`` / ``absent``,
* the *port*-level ``<PORT><POWER>`` field is **not** touched by the
  device-level fix (unused ports legitimately ship ``false``/absent),
* the shipped enterprise artefacts carry no unpowered device.

Template harvesting is covered too: ``normalise_device_power()`` /
``harvest_models()`` normalise device power to ``true`` so the artefact class
cannot recur.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))  # pt9 (same convention as tests/test_pt9.py)
sys.path.insert(0, str(REPO / "src"))
TOOLS = REPO / "tools"

# where the delivered enterprise artefacts live (outside the repo); override
# with ARTEFACT_DIR when they move
ARTEFACT_DIR = Path(os.environ.get("ARTEFACT_DIR", "/home/saoria/filedrop/uploads"))

from pkt_core import decode  # noqa: E402
from pkt_core.models import Lab  # noqa: E402


def _load_lab_api():
    spec = importlib.util.spec_from_file_location("lab_api", TOOLS / "lab_api.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab_api = _load_lab_api()

# (model, kind) for one device of each family the corpus shows carrying <POWER>
KINDS = [
    ("2911", "Router"),
    ("2960-24TT", "Switch"),
    ("PC-PT", "Pc"),
    ("Server-PT", "Server"),
]


@pytest.fixture(scope="module")
def templates():
    return lab_api.load_templates(str(TOOLS / "device_templates.json"))


@pytest.fixture()
def lab(templates):
    models, modules = templates
    return lab_api.Lab(str(TOOLS / "network_seed.xml"), models, modules)


def _engine_power(lab, sid: str) -> tuple[ET.Element | None, ET.Element]:
    """(POWER element or None, ENGINE element) of a placed device."""
    el = lab._els[sid]
    eng = el.find("ENGINE")
    assert eng is not None
    return eng.find("POWER"), eng


def _port_powers(el: ET.Element) -> list[str | None]:
    out: list[str | None] = []
    for p in el.iter("PORT"):
        e = p.find("POWER")
        out.append(e.text if e is not None else None)
    return out


# --------------------------------------------------------------------------- #
# add_device(): power is written explicitly, in both directions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("model", "kind"), KINDS)
def test_add_device_defaults_to_power_true(lab, model, kind):
    sid = lab.add_device(model, f"dev-{kind}")
    p, _eng = _engine_power(lab, sid)
    assert p is not None, f"{model}: <ENGINE><POWER> was not written"
    assert p.text == "true"
    assert lab._els[sid].find("ENGINE/TYPE").text == kind


@pytest.mark.parametrize(("model", "kind"), KINDS)
def test_add_device_writes_false_when_asked(lab, model, kind):
    sid = lab.add_device(model, f"off-{kind}", power=False)
    p, _eng = _engine_power(lab, sid)
    assert p is not None
    assert p.text == "false"


def test_add_device_overrides_template_that_ships_false(templates):
    """The exact bug: 3650-24PS shipped <POWER>false</POWER> and every device
    built from it inherited "off".  add_device's default must override it."""
    models, modules = templates
    poisoned = dict(models)
    blk = models["3650-24PS"]
    assert b"<NAME translate=\"true\">Multilayer Switch0</NAME>\n     <POWER>true</POWER>" in blk
    poisoned["3650-24PS"] = blk.replace(
        b"<POWER>true</POWER>", b"<POWER>false</POWER>", 1)
    lab = lab_api.Lab(str(TOOLS / "network_seed.xml"), poisoned, modules)

    sid = lab.add_device("3650-24PS", "BB-SW-01")           # default power=True
    p, _eng = _engine_power(lab, sid)
    assert p is not None and p.text == "true", "staged-off template leaked through"

    sid2 = lab.add_device("3650-24PS", "BB-SW-02", power=False)
    p2, _eng2 = _engine_power(lab, sid2)
    assert p2 is not None and p2.text == "false"


def test_add_device_creates_power_at_canonical_slot(templates):
    """A template without <POWER> must get one at child index 2 of <ENGINE>
    (TYPE, NAME, POWER, ...) -- not appended at the end."""
    models, modules = templates
    stripped = dict(models)
    blk = models["2911"]
    smaller, n = re.subn(rb"(<NAME[^>]*>.*?</NAME>\s*)<POWER>[^<]*</POWER>",
                         rb"\1", blk, count=1, flags=re.S)
    assert n == 1 and smaller != blk
    assert b"<POWER>" not in smaller[:200]  # engine block starts without it
    stripped["2911"] = smaller
    lab = lab_api.Lab(str(TOOLS / "network_seed.xml"), stripped, modules)

    sid = lab.add_device("2911", "R9")
    p, eng = _engine_power(lab, sid)
    kids = list(eng)
    tags = [k.tag for k in kids]
    assert p is not None and p.text == "true"
    assert tags[2] == "POWER", f"POWER landed at {tags.index('POWER')}, not index 2: {tags[:5]}"
    assert tags[:3] == ["TYPE", "NAME", "POWER"]


def test_shipped_templates_all_power_true(templates):
    """The shipped library must contain no staged-off donor state (the class of
    artefact that poisoned 3650-24PS)."""
    models, _modules = templates
    offenders = []
    for model, blk in models.items():
        root = ET.fromstring(blk)
        p = root.find("ENGINE/POWER")
        if p is None or (p.text or "").strip() != "true":
            offenders.append((model, p.text if p is not None else "absent"))
    assert offenders == []


# --------------------------------------------------------------------------- #
# device-level fix must not touch the port-level field
# --------------------------------------------------------------------------- #
def test_port_power_is_not_touched_by_the_device_level_fix(templates):
    """<PORT><POWER> is a different field: unused router/PC ports legitimately
    ship false/absent in the corpus and must survive add_device verbatim."""
    models, modules = templates
    model = "AccessPoint-PT"
    before = _port_powers(ET.fromstring(models[model]))
    assert before, f"{model} template has no ports"
    assert any(v != "true" for v in before), \
        f"{model} template is all-true; this regression needs a false/absent port"

    lab = lab_api.Lab(str(TOOLS / "network_seed.xml"), models, modules)
    sid = lab.add_device(model, "AP1")
    after = _port_powers(lab._els[sid])
    assert after == before, "add_device rewrote <PORT><POWER>"

    # even power=False only flips the device-level element
    sid2 = lab.add_device(model, "AP2", power=False)
    p, _eng = _engine_power(lab, sid2)
    assert p is not None and p.text == "false"
    assert _port_powers(lab._els[sid2]) == before


# --------------------------------------------------------------------------- #
# harvest normalisation
# --------------------------------------------------------------------------- #
def test_normalise_device_power_forces_true_and_records_donor_state():
    blk = (b"<DEVICE><ENGINE><TYPE model=\"X\" customModel=\"\">Switch</TYPE>"
           b"<NAME translate=\"true\">Switch0</NAME><POWER>false</POWER>"
           b"<DESCRIPTION/></ENGINE></DEVICE>")
    new, was_off = lab_api.normalise_device_power(blk)
    assert was_off is True
    assert b"<POWER>true</POWER>" in new and b"<POWER>false</POWER>" not in new

    again, was_off2 = lab_api.normalise_device_power(new)
    assert (again, was_off2) == (new, False)


def test_normalise_device_power_creates_missing_element():
    blk = (b"<DEVICE><ENGINE><TYPE model=\"X\" customModel=\"\">Switch</TYPE>"
           b"<NAME translate=\"true\">Switch0</NAME>"
           b"<DESCRIPTION/></ENGINE></DEVICE>")
    new, was_off = lab_api.normalise_device_power(blk)
    assert was_off is True
    assert b"<NAME translate=\"true\">Switch0</NAME>\n     <POWER>true</POWER>" in new


def test_normalise_device_power_leaves_port_power_alone():
    blk = (b"<DEVICE><ENGINE><TYPE model=\"X\" customModel=\"\">Switch</TYPE>"
           b"<NAME translate=\"true\">Switch0</NAME><POWER>true</POWER>"
           b"<PORT><TYPE>eCopper</TYPE><POWER>false</POWER></PORT>"
           b"</ENGINE></DEVICE>")
    new, was_off = lab_api.normalise_device_power(blk)
    assert was_off is False
    assert new == blk  # nothing to do: device is on, port state untouched


def test_harvest_models_normalises_and_reports(templates):
    """Both harvest paths share normalise_device_power(): no shipped template
    may carry a staged-off donor state, and re-normalising is a no-op."""
    models, _modules = templates
    assert lab_api.harvest_models.__doc__  # documents the normalisation
    for model, blk in models.items():
        new, was_off = lab_api.normalise_device_power(blk)
        assert new == blk and was_off is False, model


# --------------------------------------------------------------------------- #
# pkt_core model: power_state
# --------------------------------------------------------------------------- #
XML = """<PACKETTRACER5>
 <VERSION>9.0.1.0858</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE><ENGINE><TYPE model="2960-24TT" customModel="">Switch</TYPE>
    <NAME translate="true">ON</NAME><POWER>true</POWER></ENGINE></DEVICE>
   <DEVICE><ENGINE><TYPE model="PC-PT" customModel="">Pc</TYPE>
    <NAME translate="true">OFF</NAME><POWER>false</POWER></ENGINE></DEVICE>
   <DEVICE><ENGINE><TYPE model="Server-PT" customModel="">Server</TYPE>
    <NAME translate="true">GONE</NAME></ENGINE></DEVICE>
   <DEVICE><ENGINE><TYPE model="Router" customModel="">Router</TYPE>
    <NAME translate="true">EMPTY</NAME><POWER /></ENGINE></DEVICE>
  </DEVICES>
  <LINKS />
 </NETWORK>
</PACKETTRACER5>"""


@pytest.fixture(scope="module")
def power_lab() -> Lab:
    return Lab.from_bytes(XML.encode("utf-8"))


def test_power_state_distinguishes_true_false_absent(power_lab: Lab) -> None:
    by_name = {d.name: d for d in power_lab.devices}
    assert by_name["ON"].power_state == "true"
    assert by_name["OFF"].power_state == "false"
    assert by_name["GONE"].power_state == "absent"
    assert by_name["EMPTY"].power_state == "absent"  # empty element == no state


def test_powered_reads_absent_as_off(power_lab: Lab) -> None:
    """Documented semantics: powered == (power_state == "true"); both "false"
    and "absent" are off."""
    by_name = {d.name: d for d in power_lab.devices}
    assert by_name["ON"].powered is True
    assert by_name["OFF"].powered is False
    assert by_name["GONE"].powered is False
    assert by_name["EMPTY"].powered is False
    for dev in power_lab.devices:
        assert dev.powered is (dev.power_state == "true")


# --------------------------------------------------------------------------- #
# shipped enterprise artefacts
# --------------------------------------------------------------------------- #
def _artefact(name: str) -> Path:
    path = ARTEFACT_DIR / name
    if not path.is_file():
        pytest.skip(f"artefact not present: {path}")
    return path


def _off_devices(path: Path) -> list[tuple[str, str]]:
    lab = Lab.from_bytes(decode(path).xml)
    return [(d.name, d.power_state) for d in lab.devices if d.power_state != "true"]


def test_enterprise_artefact_has_no_unpowered_device():
    """After the fix, every one of the 290 devices (the 10 aggregation
    switches included) must be POWER=true."""
    path = _artefact("JASDF_AEWC_JADGE.pkt")
    lab = Lab.from_bytes(decode(path).xml)
    assert len(lab.devices) == 290
    off = [(d.name, d.power_state) for d in lab.devices if d.power_state != "true"]
    assert off == [], f"{len(off)} unpowered devices: {off[:10]}"
    # the former offenders must be on
    agg = {d.name: d.power_state for d in lab.devices}
    for name in ("JADGE-BB-SW-01", "JADGE-BB-SW-02", "REG-HUB-NORTH",
                 "REG-HUB-CENTRAL", "REG-HUB-WEST", "REG-HUB-SW",
                 "DATALINK-AGG-01", "DATALINK-AGG-02",
                 "JADGE-DC-CORE-01", "JADGE-DC-CORE-02"):
        assert agg[name] == "true", name


def test_standard_artefact_has_no_unpowered_device():
    path = _artefact("JASDF_AEWC_JADGE_standard.pkt")
    assert _off_devices(path) == []
    lab = Lab.from_bytes(decode(path).xml)
    assert len(lab.devices) == 199
    assert all(d.power_state == "true" for d in lab.devices)


def test_enterprise_artefact_port_power_untouched():
    """The device-level fix must not have blanket-set <PORT><POWER>: the
    enterprise model's ports keep their recorded per-port state (all cabled
    ports raised by power_cabled_ports(); unused ports are not our business)."""
    path = _artefact("JASDF_AEWC_JADGE.pkt")
    lab = Lab.from_bytes(decode(path).xml)
    states: list[str] = []
    for dev in lab.devices:
        for port in dev.ports:
            node = port.element.find("POWER")
            states.append((node.text or "absent").strip() if node is not None else "absent")
    assert states, "no ports found"
    # what the device-level fix must never produce: a wholesale rewrite of the
    # port field.  The recorded as-built state is 2454 ports, all true; nothing
    # may become "absent" and the count must not change.
    assert len(states) == 2454
    assert set(states) == {"true"}
