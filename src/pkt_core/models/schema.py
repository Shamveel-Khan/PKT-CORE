"""Extended entity models for the remaining schema families.

A frequency survey of 25 corpus documents found 1,046 distinct element names.
The core entities live in :mod:`pkt_core.models.network` and
:mod:`pkt_core.models.lab`; this module types the next tier down, which
clustered cleanly into eight families:

============================================  ===============================
Family                                        Typed here as
============================================  ===============================
End-device IP / DHCP / DNS / VLAN config      :class:`PortConfig`
Wireless association settings                :class:`WirelessConfig`
Device inventory metadata (sys, coords)      :class:`DeviceDetails`
Device filesystem entries                    :class:`FileEntry`
Activity scoring tree                        :class:`ScoringNode`
IoT environment option list                  :class:`EnvironmentOption`
Canvas drawing shapes                        :class:`CanvasShape`
Activity sections (scoring, locking, wizard) :class:`ActivitySection`
============================================  ===============================

Everything else remains reachable through ``extra_fields`` and is preserved
byte-exact by the span-preserving tree; these are typed because they are the
fields a caller is most likely to want to read or edit.
"""

from __future__ import annotations

from typing import ClassVar

from pkt_core.models.base import PktNode
from pkt_core.xml.nodes import XmlElement

__all__ = [
    "PortConfig",
    "WirelessConfig",
    "DeviceDetails",
    "FileEntry",
    "ScoringNode",
    "EnvironmentOption",
    "CanvasShape",
    "ActivitySection",
]


class PortConfig(PktNode):
    """IP addressing and DHCP state for an end-device interface.

    Covers both the ``IP``/``SUBNET``/``GATEWAY`` spelling used by hosts and the
    ``IP_ADDRESS``/``SUBNET_MASK``/``DEFAULT_GATEWAY`` spelling used elsewhere
    in the schema — they mean the same thing and appear in different contexts.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "IP", "SUBNET", "GATEWAY", "DNS", "DNS_CLIENT", "DHCP_CLIENT",
            "DHCP_ENABLED", "DHCP_SERVER_IP", "DHCP_SERVER", "DHCP_SERVERS",
            "IP_ADDRESS", "SUBNET_MASK", "DEFAULT_GATEWAY", "DNS_SERVER",
            "PORT_GATEWAY", "PORT_DNS", "PORT_DHCP_ENABLE",
            "VLAN", "VLANS", "VLAN_NUMBER", "MAC_ADDRESS", "PORT_NAME",
            "IPV6_ENABLED", "IPV6_ADDRESS_AUTOCONFIG", "IPV6_PORT_GATEWAY",
            "IPV6_PORT_DNS", "IPV6_LINK_LOCAL", "IPV6_DEFAULT_LINK_LOCAL",
            "IPV6_PORT_DHCP_ENABLED", "IPV6_ADDRESSES", "IPV6_PORT_GATEWAY",
            "ND_SUPPRESSED", "ND_IPV6_DNS_ADDRESSES",
            "PC_FIREWALL", "PC_IPV6_FIREWALL", "IP_UNNUMBERED",
            "DHCPV6_ENABLED", "DHCPV6_CLIENT", "GATEWAYV6", "IAID",
        }
    )

    # -- IPv4 -------------------------------------------------------------
    @property
    def ip_address(self) -> str:
        return self._text("IP") or self._text("IP_ADDRESS")

    @property
    def subnet_mask(self) -> str:
        return self._text("SUBNET") or self._text("SUBNET_MASK")

    @property
    def gateway(self) -> str:
        return (
            self._text("GATEWAY")
            or self._text("DEFAULT_GATEWAY")
            or self._text("PORT_GATEWAY")
        )

    @property
    def dns(self) -> str:
        return self._text("DNS") or self._text("DNS_SERVER") or self._text("PORT_DNS")

    # -- DHCP -------------------------------------------------------------
    @property
    def dhcp_enabled(self) -> bool:
        return self._bool("DHCP_ENABLED") or self._bool("PORT_DHCP_ENABLE")

    @property
    def dhcp_server(self) -> str:
        return self._text("DHCP_SERVER_IP") or self._text("DHCP_SERVER")

    # -- VLAN / identity --------------------------------------------------
    @property
    def vlan(self) -> str:
        return self._text("VLAN") or self._text("VLAN_NUMBER")

    @property
    def mac_address(self) -> str:
        return self._text("MAC_ADDRESS")

    @property
    def port_name(self) -> str:
        return self._text("PORT_NAME")

    # -- IPv6 -------------------------------------------------------------
    @property
    def ipv6_enabled(self) -> bool:
        return self._bool("IPV6_ENABLED")

    @property
    def ipv6_link_local(self) -> str:
        return self._text("IPV6_LINK_LOCAL")

    @property
    def ipv6_addresses(self) -> str:
        return self._text("IPV6_ADDRESSES")

    @property
    def dhcpv6_enabled(self) -> bool:
        return self._bool("DHCPV6_ENABLED")


class WirelessConfig(PktNode):
    """Wireless association parameters (SSID, auth, encryption, radio)."""

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "SSID", "AUTHEN_TYPE", "ENCRYPT_TYPE", "WEP_KEY", "WEP_PROCESS",
            "NETWORK_TYPE", "NETWORK_MODE", "RADIO_BAND", "WIDE_CHANNEL",
            "STANDARD_CHANNEL", "STANDARD_CHANNEL5G", "WPA_EAP_USERID",
            "WPA_EAP_PASSWORD", "WIRELESS_PROFILE", "WIRELESS_COMMON",
            "WIRELESS_CLIENT", "WIRELESS_SERVER", "CURRENT_PROFILE",
            "SSID_BROADCAST_ENABLED", "MAC_FILTER_ENABLED", "ALLOW_ACCESS",
            "PROFILES", "BEAMFORMING_ENABLE",
        }
    )

    @property
    def ssid(self) -> str:
        return self._text("SSID")

    @property
    def auth_type(self) -> str:
        return self._text("AUTHEN_TYPE")

    @property
    def encryption(self) -> str:
        return self._text("ENCRYPT_TYPE")

    @property
    def wep_key(self) -> str:
        return self._text("WEP_KEY")

    @property
    def network_type(self) -> str:
        return self._text("NETWORK_TYPE")

    @property
    def network_mode(self) -> str:
        return self._text("NETWORK_MODE")

    @property
    def radio_band(self) -> str:
        return self._text("RADIO_BAND")

    @property
    def channel(self) -> str:
        return self._text("STANDARD_CHANNEL") or self._text("STANDARD_CHANNEL5G")

    @property
    def profile(self) -> str:
        return self._text("CURRENT_PROFILE") or self._text("WIRELESS_PROFILE")


class DeviceDetails(PktNode):
    """Device inventory metadata: sys contact/location, serial, 3D coords."""

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "SYS_CONTACT", "SYS_LOCATION", "SYS_NAME", "SERIALNUMBER",
            "COORD_SETTINGS", "X_COORD", "Y_COORD", "Z_COORD",
            "CUSTOM_VARS", "CUSTOM_INTERFACE", "EXT_ATTRIBUTES",
            "USB_PORT_COUNT", "TEMPLATE_CREATION_TIME",
            "IGNORE_TEMPLATE_CREATION_TIME", "IGNORED_VERSION",
            "ORIGINAL_DEVICE_UUID", "Firmware_Version", "FIRMWARE_VERSION",
            "USER_APPS", "RUNNING_APPS", "DESKTOP_APPS",
            "BUILD_IN_ADDR", "BIOS_VERSION", "SERIAL",
        }
    )

    @property
    def sys_contact(self) -> str:
        return self._text("SYS_CONTACT")

    @property
    def sys_location(self) -> str:
        return self._text("SYS_LOCATION")

    @property
    def sys_name(self) -> str:
        return self._text("SYS_NAME")

    @property
    def serial_number(self) -> str:
        return self._text("SERIALNUMBER") or self._text("SERIAL")

    @property
    def firmware_version(self) -> str:
        return self._text("Firmware_Version") or self._text("FIRMWARE_VERSION")

    @property
    def coordinates(self) -> tuple[str, str, str]:
        """Physical ``(x, y, z)`` coordinates, as written (they are not ints).

        These are nested under ``<COORD_SETTINGS>``, so a direct-child lookup
        is not enough.
        """
        box = self._el.find("COORD_SETTINGS")
        if box is None:
            return ("", "", "")

        def axis(name: str) -> str:
            node = box.find(name)
            return node.text.strip() if node is not None else ""

        return (axis("X_COORD"), axis("Y_COORD"), axis("Z_COORD"))

    @property
    def custom_vars(self) -> str:
        """Base64 blob of user-defined variables."""
        return self._text("CUSTOM_VARS")


class FileEntry(PktNode):
    """One entry in a device's simulated filesystem."""

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "FILE", "FILES", "FILE_PATH", "FILE_CONTENT", "FILE_NUMBER",
            "FILE_SIZE", "FILE_COUNTER", "DATE_TIME", "PERMISSION", "NAME",
            "IS_BOOTABLE", "METAFILE_PATH", "TMP_FILENAME", "CONFIGURED_FILENAME",
        }
    )

    @property
    def name(self) -> str:
        return self._text("FILE") or self._text("NAME")

    @property
    def path(self) -> str:
        return self._text("FILE_PATH")

    @property
    def size(self) -> str:
        return self._text("FILE_SIZE")

    @property
    def modified(self) -> str:
        return self._text("DATE_TIME")

    @property
    def permission(self) -> str:
        return self._text("PERMISSION")

    @property
    def is_bootable(self) -> bool:
        return self._bool("IS_BOOTABLE")

    @property
    def content(self) -> bytes:
        """File body as raw bytes - may be text, an image or a binary blob."""
        return self._raw_text("FILE_CONTENT")


class ScoringNode(PktNode):
    """One node of a scored activity's grading tree.

    ``.pka`` activities carry a nested tree of ``<NODE>`` elements with an
    ``<ID>``, a ``<POINTS>`` allocation and ``<COMPONENTS>`` — that is where the
    bulk of the element-name frequency in a scored document comes from.
    """

    # NB: ``CHECK_TYPE`` is deliberately absent. Scoring criteria live as the
    # *attribute* ``checkType`` on ``<NAME>`` (6.0M occurrences in the corpus),
    # not as a child element. Listing it here would invent an element that does
    # not exist and overstate element coverage.
    _claimed: ClassVar[frozenset[str]] = frozenset(
        {"NODE", "ID", "POINTS", "COMPONENTS", "NAME", "VALUE"}
    )

    @property
    def node_id(self) -> str:
        return self._text("ID")

    @property
    def name(self) -> str:
        return self._text("NAME")

    @property
    def points(self) -> str:
        return self._text("POINTS")

    @property
    def value(self) -> str:
        return self._text("VALUE")

    @property
    def children(self) -> list["ScoringNode"]:
        """Nested nodes, found under ``COMPONENTS`` and as direct ``NODE``s."""
        out: list[ScoringNode] = []
        for tag in ("COMPONENTS", "NODE"):
            node = self._el.find(tag)
            if node is not None:
                out.extend(ScoringNode.from_element(n) for n in node.find_all("NODE"))
        out.extend(ScoringNode.from_element(n) for n in self._children("NODE"))
        return out


class EnvironmentOption(PktNode):
    """One IoT/simulation environment option.

    These are extremely repetitive (17 fields per option, tens of thousands of
    occurrences in a scored document) and describe sensor min/max ranges,
    units and interpolation for analog/digital IOE devices.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "ENVIRONMENT_OPTION", "VALUE", "CATEGORY", "CATEGORY_ID",
            "TRANSFERENCE", "SHOW", "INTERPOLATE", "ACTIVE",
            "MIN", "MAX", "MIN_RATE", "MAX_RATE",
            "METRIC_UNIT", "IMPERIAL_UNIT",
            "METRIC_CONVERSION_FORMULA", "IMPERIAL_CONVERSION_FORMULA",
        }
    )

    @property
    def category(self) -> str:
        return self._text("CATEGORY")

    @property
    def category_id(self) -> str:
        return self._text("CATEGORY_ID")

    @property
    def value(self) -> str:
        return self._text("VALUE")

    @property
    def minimum(self) -> float:
        return self._float("MIN")

    @property
    def maximum(self) -> float:
        return self._float("MAX")

    @property
    def metric_unit(self) -> str:
        return self._text("METRIC_UNIT")

    @property
    def imperial_unit(self) -> str:
        return self._text("IMPERIAL_UNIT")

    @property
    def interpolate(self) -> bool:
        return self._bool("INTERPOLATE")

    @property
    def active(self) -> bool:
        return self._bool("ACTIVE")


class CanvasShape(PktNode):
    """A drawing primitive on the topology canvas (line, rect, ellipse, polygon).

    Stored under ``LINES``/``RECTANGLES``/``ELLIPSES``/``POLYGONS`` at the
    document root, and as ``GEOVIEW_GRAPHICSITEMS`` entries.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "X", "Y", "Z", "W", "H", "D", "SX", "SY",
            "StartX", "StartY", "EndX", "EndY",
            "TopLeftX", "TopLeftY", "BottomRightX", "BottomRightY",
            "X1", "Y1", "X2", "Y2",
            "Color", "COLOR", "FILL_COLOR", "FILL_FLAG", "Filled",
            "ROTATION", "OPACITY", "Z_ORDER", "WIDTH", "HEIGHT",
            "LINECLUSTERID", "RECTCLUSTERID", "NOTECLUSTERID",
            "LABELTEXT", "LABEL_POSX", "LABEL_POSY", "LABEL_COLOR", "LABEL_WIDTH",
            "SCALE", "GROUPPOINTS", "PATH",
        }
    )

    @property
    def color(self) -> str:
        return self._text("Color") or self._text("COLOR")

    @property
    def fill_color(self) -> str:
        return self._text("FILL_COLOR")

    @property
    def filled(self) -> bool:
        return self._bool("Filled") or self._bool("FILL_FLAG")

    @property
    def rotation(self) -> float:
        return self._float("ROTATION")

    @property
    def opacity(self) -> float:
        return self._float("OPACITY", 1.0)

    @property
    def z_order(self) -> int:
        return self._int("Z_ORDER")

    @property
    def endpoints(self) -> tuple[tuple[float, float], tuple[float, float]]:
        """Line endpoints; uses ``StartX/StartY`` then ``X1/Y1`` spellings."""
        if self._el.find("StartX") is not None:
            return (
                (self._float("StartX"), self._float("StartY")),
                (self._float("EndX"), self._float("EndY")),
            )
        return (
            (self._float("X1"), self._float("Y1")),
            (self._float("X2"), self._float("Y2")),
        )

    @property
    def bounds(self) -> tuple[float, float, float, float]:
        """``(x, y, w, h)`` for rectangles and ellipses."""
        return (
            self._float("TopLeftX") or self._float("X"),
            self._float("TopLeftY") or self._float("Y"),
            self._float("BottomRightX") or self._float("W") or self._float("WIDTH"),
            self._float("BottomRightY") or self._float("H") or self._float("HEIGHT"),
        )

    @property
    def label(self) -> str:
        return self._text("LABELTEXT")


class ActivitySection(PktNode):
    """A named section of a scored activity.

    ``.pka`` documents carry ``<COMPARISONS>`` (the grading tree),
    ``<INITIALSETUP>``, ``<LOCKINGTREE>``, ``<INSTRUCTIONS>`` and
    ``<VARIABLE_MANAGER>``. The instruction HTML is opaque on purpose — it
    contains a Word-exported HTML document with void elements and mis-nested
    tags, so it is exposed as raw bytes.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "NODE", "NAME", "ID", "POINTS", "COMPONENTS", "VALUE",
            "PAGE", "INSTRUCTION_DIALOG", "USER_NOTES",
            "SEED_POOLS", "NUMBER_POOLS", "STRING_POOLS", "IP_POOLS",
            "VARIABLES_POOLS", "LOAD_INIT_TREE", "CLEAN_ACTIVITY",
        }
    )

    @property
    def is_instructions(self) -> bool:
        return self.tag == "INSTRUCTIONS"

    @property
    def instructions_html(self) -> bytes:
        """Instruction markup as raw bytes - never decoded.

        This payload is a complete Word-exported HTML document containing
        ``<meta>``/``<br>`` void elements and unquoted attributes. Decoding it
        to ``str`` would either fail or normalise the bytes we preserve.
        """
        return b"".join(c.to_bytes() for c in self._el.children)

    @property
    def nodes(self) -> list[ScoringNode]:
        """Grading-tree nodes, for ``COMPARISONS``/``INITIALSETUP``/``LOCKINGTREE``."""
        return [ScoringNode.from_element(n) for n in self._children("NODE")]

    @property
    def name(self) -> str:
        return self._text("NAME")
