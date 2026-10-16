"""Tests for the typed object model.

The model is a *view* over the lossless XML tree, so the load-bearing property
is: reading through it must not change a single byte.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pkt_core import decode_bytes
from pkt_core.models import (
    Cable,
    Cluster,
    Device,
    Lab,
    LabOptions,
    Link,
    Module,
    Network,
    Port,
    RunningConfig,
    Workspace,
    unknown_children,
)
from pkt_core.xml import parse_xml_bytes

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO.parent / "corpus" / "CORPUS_INDEX.tsv"
CORPUS = REPO.parent / "corpus" / "internet"

SAMPLE = """<PACKETTRACER5>
 <VERSION>7.3.1.0362</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE>
    <ENGINE>
     <TYPE model="2960-24TT" customModel="">Switch</TYPE>
     <NAME translate="true">Switch0</NAME>
     <POWER>true</POWER>
     <DESCRIPTION>core</DESCRIPTION>
     <MODULE>
      <TYPE>eNonRemovableModule</TYPE>
      <MODEL/>
      <SLOT>
       <TYPE>eNonRemovableModule</TYPE>
       <MODULE>
        <TYPE>eNonRemovableModule</TYPE>
        <MODEL/>
        <PORT>
         <TYPE>eCopperFastEthernet</TYPE>
         <BANDWIDTH>100000</BANDWIDTH>
         <FULLDUPLEX>true</FULLDUPLEX>
         <MACADDRESS>00E0.A3D0.EC01</MACADDRESS>
         <BIA>00E0.A3D0.EC01</BIA>
         <CLOCKRATE>2000000</CLOCKRATE>
         <MYSTERY_TAG>keep me</MYSTERY_TAG>
        </PORT>
       </MODULE>
      </SLOT>
     </MODULE>
    </ENGINE>
    <WORKSPACE>
     <LOGICAL>
      <X>369</X>
      <Y>202</Y>
      <DEVCLUSTERID>1-1</DEVCLUSTERID>
     </LOGICAL>
    </WORKSPACE>
   </DEVICE>
  </DEVICES>
  <LINKS>
   <LINK>
    <TYPE>eCopper</TYPE>
    <CABLE>
     <LENGTH>35.3636</LENGTH>
     <FUNCTIONAL>true</FUNCTIONAL>
     <FROM>save-ref-id:111</FROM>
     <PORT>FastEthernet0/1</PORT>
     <TO>save-ref-id:222</TO>
     <PORT>FastEthernet0</PORT>
     <GEO_VIEW_COLOR>#000000</GEO_VIEW_COLOR>
     <TYPE>eStraightThrough</TYPE>
    </CABLE>
   </LINK>
  </LINKS>
 </NETWORK>
 <OPTIONS>
  <LANGUAGE>default.ptl</LANGUAGE>
  <ANIMATION>true</ANIMATION>
  <LINKLIGHTSSHOWN>true</LINKLIGHTSSHOWN>
  <PASS>hunter2</PASS>
 </OPTIONS>
 <CLUSTERS>
  <ROOTCLUSTER>
   <NAME translate="true">Root</NAME>
   <CLUSTERID>1-1</CLUSTERID>
   <TILED_BG>false</TILED_BG>
  </ROOTCLUSTER>
 </CLUSTERS>
 <RUNNINGCONFIG>
  <LINE>hostname Switch</LINE>
  <LINE>banner motd \x03wtf\x03</LINE>
 </RUNNINGCONFIG>
</PACKETTRACER5>
"""


@pytest.fixture(scope="module")
def lab() -> Lab:
    return Lab.from_bytes(SAMPLE.encode("utf-8"))


# --------------------------------------------------------------------------
# Fidelity
# --------------------------------------------------------------------------
def test_model_access_does_not_alter_bytes(lab: Lab) -> None:
    _ = lab.summary()
    _ = lab.devices
    _ = lab.links
    _ = lab.options
    _ = lab.clusters
    assert lab.to_xml() == SAMPLE.encode("utf-8")


def test_roundtrip_is_byte_exact() -> None:
    raw = SAMPLE.encode("utf-8")
    assert Lab.from_bytes(raw).to_xml() == raw


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------
def test_device_identity(lab: Lab) -> None:
    dev = lab.devices[0]
    assert dev.name == "Switch0"
    assert dev.kind == "Switch"
    assert dev.model == "2960-24TT"
    assert dev.custom_model == ""
    assert dev.powered is True
    assert dev.description == "core"


def test_device_canvas_placement(lab: Lab) -> None:
    dev = lab.devices[0]
    assert dev.position == (369.0, 202.0)
    assert dev.cluster_id == "1-1"


def test_ports_are_flattened_through_modules_and_slots(lab: Lab) -> None:
    ports = lab.devices[0].ports
    assert len(ports) == 1
    p = ports[0]
    assert p.type == "eCopperFastEthernet"
    assert p.mac_address == "00E0.A3D0.EC01"
    assert p.burned_in_address == "00E0.A3D0.EC01"
    assert p.bandwidth == 100000
    assert p.full_duplex is True
    assert p.clock_rate == 2000000


def test_unknown_port_children_land_in_extra_fields(lab: Lab) -> None:
    p = lab.devices[0].ports[0]
    assert "MYSTERY_TAG" in p.extra_fields
    assert p.extra_fields["MYSTERY_TAG"][0].text == "keep me"


def test_device_named_lookup(lab: Lab) -> None:
    assert lab.device_named("Switch0") is not None
    assert lab.device_named("Nope") is None


# --------------------------------------------------------------------------
# Links
# --------------------------------------------------------------------------
def test_link_endpoints_and_ports(lab: Lab) -> None:
    link = lab.links[0]
    assert link.type == "eCopper"
    assert link.cable_type == "eStraightThrough"
    assert link.port_names == ["FastEthernet0/1", "FastEthernet0"]
    assert link.endpoints == ("save-ref-id:111", "save-ref-id:222")
    assert link.cable is not None
    assert link.cable.length == 35.3636
    assert link.cable.functional is True
    assert link.cable.geo_view_color == "#000000"


def test_cable_less_link_does_not_crash() -> None:
    xml = b"<PACKETTRACER5><NETWORK><LINKS><LINK><TYPE>eRadio</TYPE></LINK></LINKS></NETWORK></PACKETTRACER5>"
    lab = Lab.from_bytes(xml)
    link = lab.links[0]
    assert link.cable is None
    assert link.cable_type == ""
    assert link.port_names == []


# --------------------------------------------------------------------------
# Options, clusters, config
# --------------------------------------------------------------------------
def test_options(lab: Lab) -> None:
    assert lab.options is not None
    assert lab.options.language == "default.ptl"
    assert lab.options.animation is True
    assert lab.options.show_link_lights is True
    assert lab.options.password == "hunter2"


def test_clusters(lab: Lab) -> None:
    assert len(lab.clusters) == 1
    assert lab.clusters[0].name == "Root"
    assert lab.clusters[0].cluster_id == "1-1"


def test_running_config_keeps_control_bytes() -> None:
    """IOS banner delimiters are literal 0x03 and must not be normalised."""
    lab = Lab.from_bytes(SAMPLE.encode("utf-8"))
    node = lab.element.find("RUNNINGCONFIG")
    assert node is not None
    cfg = RunningConfig.from_element(node)
    assert cfg.lines[0] == b"hostname Switch"
    assert b"\x03wtf\x03" in cfg.lines[1], "control bytes must survive as bytes"


# --------------------------------------------------------------------------
# extra_fields contract
# --------------------------------------------------------------------------
def test_unknown_children_helper_groups_by_name() -> None:
    doc = parse_xml_bytes(b"<R><A/><A/><B/></R>")
    extra = unknown_children(doc.root, {"B"})
    assert set(extra) == {"A"}
    assert len(extra["A"]) == 2


def test_lab_extra_fields_lists_unmodelled_root_children() -> None:
    raw = b"<PACKETTRACER5><VERSION>9</VERSION><WEIRD_THING/></PACKETTRACER5>"
    lab = Lab.from_bytes(raw)
    assert "WEIRD_THING" in lab.extra_fields
    assert lab.to_xml() == raw


# --------------------------------------------------------------------------
# Real corpus
# --------------------------------------------------------------------------
def _corpus_labs() -> list[tuple[str, bytes]]:
    if not INDEX.exists() or not CORPUS.exists():
        return []
    out: list[tuple[str, bytes]] = []
    with INDEX.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    for row in rows[:120]:
        name = row["filename"]
        if name.lower().endswith(".zip"):
            continue
        path = CORPUS / name
        if not path.exists():
            continue
        try:
            out.append((name, decode_bytes(path.read_bytes()).xml))
        except Exception:  # noqa: BLE001
            continue
    return out


@pytest.mark.corpus
def test_corpus_model_access_is_lossless() -> None:
    docs = _corpus_labs()
    if not docs:
        pytest.skip("corpus not fetched (see corpus/README.md)")
    bad: list[str] = []
    for name, xml in docs:
        lab = Lab.from_bytes(xml)
        _ = lab.summary()
        for dev in lab.devices:
            _ = dev.name, dev.kind, dev.model, dev.position, dev.ports
        for link in lab.links:
            _ = link.type, link.cable_type, link.port_names
        _ = lab.options, lab.clusters
        if lab.to_xml() != xml:
            bad.append(name)
    assert not bad, f"{len(bad)} documents changed bytes:\n" + "\n".join(bad[:10])


@pytest.mark.corpus
def test_corpus_devices_and_links_are_found() -> None:
    docs = _corpus_labs()
    if not docs:
        pytest.skip("corpus not fetched (see corpus/README.md)")
    saw_device = saw_link = 0
    for _name, xml in docs:
        lab = Lab.from_bytes(xml)
        saw_device += len(lab.devices)
        saw_link += len(lab.links)
    assert saw_device > 0, "no devices found anywhere in the corpus sample"
    assert saw_link > 0, "no links found anywhere in the corpus sample"


# --------------------------------------------------------------------------
# Extended schema families
# --------------------------------------------------------------------------
ACTIVITY_DOC = """<PACKETTRACER5_ACTIVITY>
 <VERSION>9.0.1.0858</VERSION>
 <PACKETTRACER5>
  <NETWORK>
   <DEVICES>
    <DEVICE>
     <ENGINE>
      <TYPE model="PC-PT" customModel="">Pc</TYPE>
      <NAME translate="true">PC0</NAME>
      <POWER>true</POWER>
      <SYS_CONTACT>ops@example.com</SYS_CONTACT>
      <SYS_LOCATION>Lab 1</SYS_LOCATION>
      <SERIALNUMBER>FTX1234</SERIALNUMBER>
      <COORD_SETTINGS><X_COORD>10</X_COORD><Y_COORD>20</Y_COORD><Z_COORD>0</Z_COORD></COORD_SETTINGS>
      <WIRELESS_CLIENT><SSID>corp</SSID><AUTHEN_TYPE>WPA2-PSK</AUTHEN_TYPE>
        <ENCRYPT_TYPE>AES</ENCRYPT_TYPE><CURRENT_PROFILE>default</CURRENT_PROFILE>
      </WIRELESS_CLIENT>
      <PORT><TYPE>eCopperFastEthernet</TYPE>
        <IP>192.168.1.10</IP><SUBNET>255.255.255.0</SUBNET>
        <GATEWAY>192.168.1.1</GATEWAY><DNS>8.8.8.8</DNS>
        <DHCP_ENABLED>false</DHCP_ENABLED><VLAN>1</VLAN>
      </PORT>
      <FILE><FILE_PATH>flash:</FILE_PATH><FILE>config.text</FILE>
        <FILE_SIZE>128</FILE_SIZE><IS_BOOTABLE>false</IS_BOOTABLE>
      </FILE>
     </ENGINE>
     <WORKSPACE><LOGICAL><X>100</X><Y>200</Y><DEVCLUSTERID>1-1</DEVCLUSTERID>
       <DEV_ADDR>111</DEV_ADDR></LOGICAL></WORKSPACE>
    </DEVICE>
   </DEVICES>
   <LINKS/>
  </NETWORK>
 </PACKETTRACER5>
 <COMPARISONS>
  <NODE><ID>Network</ID><NAME>Network</NAME><POINTS>10</POINTS>
   <COMPONENTS><NODE><ID>PC0</ID><NAME>PC0</NAME><POINTS>5</POINTS></NODE></COMPONENTS>
  </NODE>
 </COMPARISONS>
 <LOCKINGTREE><NODE><ID>Root</ID><NAME>Root</NAME></NODE></LOCKINGTREE>
 <INSTRUCTIONS>
  <PAGE><meta charset="windows-1252"><h1>Lab</h1><br><ul><li>step</ul></PAGE>
 </INSTRUCTIONS>
 <VARIABLE_MANAGER><VARIABLES_POOLS/></VARIABLE_MANAGER>
 <ENVIRONMENT_OPTIONS>
  <ENVIRONMENT_OPTION><CATEGORY>Temperature</CATEGORY><MIN>-100</MIN>
   <MAX>100</MAX><METRIC_UNIT>C</METRIC_UNIT><IMPERIAL_UNIT>F</IMPERIAL_UNIT>
   <INTERPOLATE>true</INTERPOLATE><ACTIVE>true</ACTIVE>
  </ENVIRONMENT_OPTION>
 </ENVIRONMENT_OPTIONS>
 <LINES><LINE_LINE><StartX>1</StartX><StartY>2</StartY><EndX>3</EndX><EndY>4</EndY>
   <Color>#FF0000</Color></LINE_LINE></LINES>
</PACKETTRACER5_ACTIVITY>"""


@pytest.fixture(scope="module")
def activity() -> Lab:
    return Lab.from_bytes(ACTIVITY_DOC.encode("utf-8"))


def test_activity_network_is_found_inside_nested_document(activity: Lab) -> None:
    """Scored activities nest the real network; a child-only lookup finds none."""
    assert activity.is_activity is True
    assert len(activity.devices) == 1
    assert activity.devices[0].name == "PC0"


def test_device_details_metadata(activity: Lab) -> None:
    d = activity.devices[0].details
    assert d is not None
    assert d.sys_contact == "ops@example.com"
    assert d.sys_location == "Lab 1"
    assert d.serial_number == "FTX1234"
    assert d.coordinates == ("10", "20", "0")


def test_port_config_ip_and_dhcp(activity: Lab) -> None:
    cfgs = activity.devices[0].port_configs
    assert cfgs, "expected an IP config block on the PC port"
    cfg = cfgs[0]
    assert cfg.ip_address == "192.168.1.10"
    assert cfg.subnet_mask == "255.255.255.0"
    assert cfg.gateway == "192.168.1.1"
    assert cfg.dns == "8.8.8.8"
    assert cfg.dhcp_enabled is False
    assert cfg.vlan == "1"


def test_wireless_config(activity: Lab) -> None:
    w = activity.devices[0].wireless
    assert w is not None
    assert w.ssid == "corp"
    assert w.auth_type == "WPA2-PSK"
    assert w.encryption == "AES"
    assert w.profile == "default"


def test_device_files(activity: Lab) -> None:
    files = activity.devices[0].files
    assert files
    assert files[0].name == "config.text"
    assert files[0].path == "flash:"
    assert files[0].size == "128"
    assert files[0].is_bootable is False


def test_scoring_tree(activity: Lab) -> None:
    roots = activity.scoring_tree
    assert len(roots) == 1
    assert roots[0].node_id == "Network"
    assert roots[0].points == "10"
    kids = roots[0].children
    assert any(k.node_id == "PC0" for k in kids)


def test_activity_sections_are_typed(activity: Lab) -> None:
    tags = {s.tag for s in activity.activity_sections}
    assert {"COMPARISONS", "LOCKINGTREE", "INSTRUCTIONS", "VARIABLE_MANAGER"} <= tags


def test_instructions_html_is_raw_bytes(activity: Lab) -> None:
    """Word-exported HTML with void elements must not be decoded or tidied."""
    section = next(s for s in activity.activity_sections if s.is_instructions)
    html = section.instructions_html
    assert isinstance(html, bytes)
    assert b"<meta" in html and b"<br>" in html and b"<ul>" in html


def test_environment_options(activity: Lab) -> None:
    opts = activity.environment_options
    assert opts
    o = opts[0]
    assert o.category == "Temperature"
    assert o.minimum == -100.0
    assert o.maximum == 100.0
    assert o.metric_unit == "C"
    assert o.imperial_unit == "F"
    assert o.interpolate is True


def test_canvas_shapes(activity: Lab) -> None:
    shapes = activity.canvas_shapes
    assert shapes
    s = shapes[0]
    assert s.endpoints == ((1.0, 2.0), (3.0, 4.0))
    assert s.color == "#FF0000"


def test_extended_access_is_lossless(activity: Lab) -> None:
    for d in activity.devices:
        _ = d.details, d.port_configs, d.wireless, d.files
    _ = activity.scoring_tree, activity.activity_sections
    _ = activity.environment_options, activity.canvas_shapes
    assert activity.to_xml() == ACTIVITY_DOC.encode("utf-8")


# --------------------------------------------------------------------------
# Mutation: the setters must write to where the schema actually keeps things
# --------------------------------------------------------------------------
MUTABLE = """<PACKETTRACER5>
 <VERSION>9.0.1.0858</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE>
    <ENGINE>
     <TYPE model="2811" customModel="">Router</TYPE>
     <NAME translate="true">Router0</NAME>
     <POWER>true</POWER>
    </ENGINE>
    <WORKSPACE><LOGICAL><X>574.5</X><Y>196</Y><DEVCLUSTERID>1-1</DEVCLUSTERID></LOGICAL></WORKSPACE>
   </DEVICE>
  </DEVICES>
 </NETWORK>
</PACKETTRACER5>"""


def test_set_name_writes_into_engine_not_device() -> None:
    """The name lives at DEVICE/ENGINE/NAME, not DEVICE/NAME.

    A generic setter would append a second, ignored <NAME> and change nothing.
    """
    lab = Lab.from_bytes(MUTABLE.encode("utf-8"))
    lab.devices[0].set_name("PKT_CORE_RENAMED")

    # the edit must survive a fresh decode
    again = Lab.from_bytes(lab.to_xml())
    assert again.device_named("PKT_CORE_RENAMED") is not None
    assert again.device_named("Router0") is None

    # and must not have created a stray direct-child <NAME>
    device_el = again.devices[0].element
    stray = device_el.find("NAME")
    assert stray is None, "a stray <NAME> was written at the DEVICE level"


def test_set_position_updates_workspace_coordinates() -> None:
    lab = Lab.from_bytes(MUTABLE.encode("utf-8"))
    assert lab.devices[0].position == (574.5, 196.0)

    lab.devices[0].set_position(123, 456)
    again = Lab.from_bytes(lab.to_xml())
    assert again.devices[0].position == (123.0, 456.0)


def test_mutation_preserves_everything_else() -> None:
    """Editing one field must not disturb the rest of the document."""
    lab = Lab.from_bytes(MUTABLE.encode("utf-8"))
    lab.devices[0].set_name("RENAMED")
    lab.devices[0].set_position(1, 2)

    again = Lab.from_bytes(lab.to_xml())
    dev = again.devices[0]
    assert dev.kind == "Router"
    assert dev.model == "2811"
    assert dev.powered is True
    assert again.version == "9.0.1.0858"
    assert again.document.root_tag == "PACKETTRACER5"


def test_setters_work_on_a_device_without_workspace() -> None:
    xml = b'<PACKETTRACER5><NETWORK><DEVICES><DEVICE><ENGINE><NAME>X</NAME></ENGINE></DEVICE></DEVICES></NETWORK></PACKETTRACER5>'
    lab = Lab.from_bytes(xml)
    lab.devices[0].set_position(10, 20)
    again = Lab.from_bytes(lab.to_xml())
    assert again.devices[0].position == (10.0, 20.0)


# --------------------------------------------------------------------------
# Scored activities: password and sections live in non-obvious places
# --------------------------------------------------------------------------
ACTIVITY_FULL = """<PACKETTRACER5_ACTIVITY>
 <VERSION>9.0.1.0858</VERSION>
 <PACKETTRACER5>
  <NETWORK><DEVICES><DEVICE><ENGINE>
   <TYPE model="2911" customModel="">Router</TYPE>
   <NAME translate="true">R1</NAME><POWER>true</POWER>
  </ENGINE></DEVICE></DEVICES></NETWORK>
 </PACKETTRACER5>
 <COMPARISONS><NODE><ID>Network</ID><NAME>Network</NAME></NODE></COMPARISONS>
 <LOCKINGTREE><NODE><ID>Root</ID><NAME>Root</NAME></NODE></LOCKINGTREE>
 <ACTIVITY COUNTDOWNLEFT="0" COUNTDOWNMS="0" ELAPSED="0" ENABLED="no" PASS="hunter2" TIMERTYPE="0">
  <INSTRUCTIONS>
   <PAGE translate="true" tabify="0" title=""><![CDATA[<h3>Task</h3><br><ul><li>step</ul>]]></PAGE>
  </INSTRUCTIONS>
 </ACTIVITY>
</PACKETTRACER5_ACTIVITY>"""


def test_activity_password_is_an_attribute_not_an_element() -> None:
    """Stored as <ACTIVITY PASS="..."> - OPTIONS/PASS is a different thing."""
    lab = Lab.from_bytes(ACTIVITY_FULL.encode("utf-8"))
    assert lab.activity_password == "hunter2"
    # the OPTIONS/PASS path must not be what answers this
    assert lab.options is None or lab.options.password == ""


def test_activity_sections_include_instructions_nested_under_ACTIVITY() -> None:
    """INSTRUCTIONS lives inside <ACTIVITY>, not at the root."""
    lab = Lab.from_bytes(ACTIVITY_FULL.encode("utf-8"))
    tags = {s.tag for s in lab.activity_sections}
    assert "COMPARISONS" in tags
    assert "LOCKINGTREE" in tags
    assert "INSTRUCTIONS" in tags, f"missing INSTRUCTIONS; saw {tags}"


def test_instructions_cdata_is_preserved_verbatim() -> None:
    lab = Lab.from_bytes(ACTIVITY_FULL.encode("utf-8"))
    section = next(s for s in lab.activity_sections if s.is_instructions)
    html = section.instructions_html
    assert b"<![CDATA[" in html, "CDATA wrapper must survive"
    assert b"<h3>Task</h3>" in html
    assert b"<br>" in html and b"<ul>" in html


def test_set_activity_password_mutates_and_roundtrips() -> None:
    lab = Lab.from_bytes(ACTIVITY_FULL.encode("utf-8"))
    lab.set_activity_password("s3cret")
    again = Lab.from_bytes(lab.to_xml())
    assert again.activity_password == "s3cret"
    assert again.to_xml() == lab.to_xml()


def test_activity_password_absent_on_plain_lab() -> None:
    lab = Lab.from_bytes(b"<PACKETTRACER5><VERSION>9</VERSION></PACKETTRACER5>")
    assert lab.activity_password == ""
    assert lab.activity_sections == []
