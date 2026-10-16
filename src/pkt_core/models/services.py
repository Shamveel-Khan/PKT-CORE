# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Typed views over the per-device *service* blocks under ``<ENGINE>``.

Server-class devices (``Server-PT``, ``Meraki-Server``, the WLC family, the
home routers, ...) carry their services as XML record lists rather than IOS
configuration:

============================================  ===============================
Record                                        Typed here as
============================================  ===============================
``ACS_SERVER/ACS_CLIENTS/CLIENT``             :class:`AaaClient`
``ACS_SERVER/USERS/USER``                     :class:`AaaUser`
``DHCP_SERVERS/.../POOLS/POOL``               :class:`DhcpPool`
``DNS_SERVER/NAMESERVER-DATABASE/...``        :class:`DnsRecord`
``FTP_SERVER/USER_ACCOUNT_MNGR/ACCOUNT``      :class:`FtpAccount`
============================================  ===============================

Each view exposes the record's *identity* — the tuple that Packet Tracer keys
the record on — because that is what a uniqueness proof has to compare.  The
identity is deliberately narrow:

* AAA clients are keyed by ``HOST_IP`` (PT shows one row per host address).
* DHCP pools are keyed by ``(name, network, mask)``; the *name* is separately
  name-keyed inside PT, so pool names must also be globally unique.
* DNS records are keyed by ``(type, name, address)`` within one server's zone.

The field lists live in :data:`IDENTITY_FIELDS` — one table, used both by these
views' ``identity`` properties and by :mod:`pkt_core.audit`'s generic scanner,
so the two can never drift.

These models are pure read/write views over the lossless tree (see
:mod:`pkt_core.models.base`); policy — what is a template leftover, what must
be unique — lives in :mod:`pkt_core.audit`.
"""

from __future__ import annotations

from typing import ClassVar, Mapping

from pkt_core.models.base import PktNode
from pkt_core.xml.nodes import XmlElement

__all__ = [
    "AaaClient",
    "AaaUser",
    "DhcpPool",
    "DnsRecord",
    "FtpAccount",
    "DeviceServices",
    "Identity",
    "IDENTITY_FIELDS",
    "IDENTITY_LABELS",
    "ZONE_KEY_FIELDS",
    "zone_identity",
]

#: A record's identity: the field tuple that must be distinct within its scope.
Identity = tuple[str, ...]

#: Family name -> the XML field tags forming the record's identity, in order.
#:
#: This *is* the identity rule.  ``pkt_core.audit`` walks raw records with it;
#: the typed views below expose ``identity`` built from the same tuples.
IDENTITY_FIELDS: Mapping[str, tuple[str, ...]] = {
    "aaa_clients": ("HOST_IP",),
    "aaa_users": ("NAME",),
    "dhcp_pools": ("NAME", "NETWORK", "MASK"),
    "dns_records": ("TYPE", "NAME", "IPADDRESS"),
    "ftp_accounts": ("USERNAME",),
}

#: Family name -> human label for finding messages.
IDENTITY_LABELS: Mapping[str, str] = {
    "aaa_clients": "AAA client",
    "aaa_users": "AAA user",
    "dhcp_pools": "DHCP pool",
    "dns_records": "DNS record",
    "ftp_accounts": "FTP account",
}

#: Fields identifying a record inside one server's zone (replication-agnostic).
ZONE_KEY_FIELDS: Mapping[str, tuple[str, ...]] = {
    "dns_records": ("TYPE", "NAME"),
}


def zone_identity(identity: Identity) -> Identity:
    """Project a DNS record identity onto its per-server zone key.

    ``(type, name, address)`` -> ``(type, name)``: two servers may each hold a
    copy of the record (replication), but one server may not hold it twice.
    """
    fields = ZONE_KEY_FIELDS["dns_records"]
    return identity[: len(fields)]


def _identity_of(family: str, el: XmlElement) -> Identity:
    parts: list[str] = []
    for tag in IDENTITY_FIELDS[family]:
        child = el.find(tag)
        parts.append(child.text.strip() if child is not None else "")
    return tuple(parts)


class AaaClient(PktNode):
    """One RADIUS/TACACS+ client entry of an AAA (``ACS``) server."""

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {"HOST_IP", "KEY", "DESCRIPTION", "SERVER_TYPE"}
    )

    @property
    def host_ip(self) -> str:
        return self._text("HOST_IP")

    @property
    def key(self) -> str:
        return self._text("KEY")

    @property
    def description(self) -> str:
        return self._text("DESCRIPTION")

    @property
    def server_type(self) -> str:
        """``RADIUS`` or ``TACACS+``."""
        return self._text("SERVER_TYPE")

    @property
    def identity(self) -> Identity:
        """AAA clients are keyed by host address."""
        return _identity_of("aaa_clients", self._el)


class AaaUser(PktNode):
    """One local account of an AAA (``ACS``) server."""

    _claimed: ClassVar[frozenset[str]] = frozenset({"NAME", "PASSWORD", "DESCRIPTION"})

    @property
    def name(self) -> str:
        return self._text("NAME")

    @property
    def password(self) -> str:
        return self._text("PASSWORD")

    @property
    def description(self) -> str:
        return self._text("DESCRIPTION")

    @property
    def identity(self) -> Identity:
        return _identity_of("aaa_users", self._el)


class DhcpPool(PktNode):
    """One DHCP pool.

    Written under ``DHCP_SERVERS/ASSOCIATED_PORTS/ASSOCIATED_PORT/DHCP_SERVER/
    POOLS/POOL`` on server devices, and under ``DHCP_SERVER/POOLS/POOL`` on the
    home-router family.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "NAME", "NETWORK", "MASK", "DEFAULT_ROUTER", "TFTP_ADDRESS",
            "START_IP", "END_IP", "DNS_SERVER", "MAX_USERS", "DOMAIN_NAME",
            "DHCP_POOL_LEASES", "LEASE_TIME", "WLC_ADDRESS",
        }
    )

    @property
    def name(self) -> str:
        return self._text("NAME")

    @property
    def network(self) -> str:
        return self._text("NETWORK")

    @property
    def mask(self) -> str:
        return self._text("MASK")

    @property
    def default_router(self) -> str:
        return self._text("DEFAULT_ROUTER")

    @property
    def start_ip(self) -> str:
        return self._text("START_IP")

    @property
    def end_ip(self) -> str:
        return self._text("END_IP")

    @property
    def dns_server(self) -> str:
        return self._text("DNS_SERVER")

    @property
    def max_users(self) -> int:
        return self._int("MAX_USERS")

    @property
    def domain_name(self) -> str:
        return self._text("DOMAIN_NAME")

    @property
    def lease_time(self) -> int:
        return self._int("LEASE_TIME")

    @property
    def identity(self) -> Identity:
        """Pools are identified by name plus the address scope they serve."""
        return _identity_of("dhcp_pools", self._el)

    @property
    def scope(self) -> Identity:
        """The served network — must itself be unique across the lab."""
        return (self.network, self.mask)

    @property
    def leases(self) -> list[XmlElement]:
        """Runtime lease records (``DHCP_POOL_LEASES``); generators never author them."""
        holder = self._el.find("DHCP_POOL_LEASES")
        return holder.find_all("DHCP_POOL_LEASE") if holder is not None else []


class DnsRecord(PktNode):
    """One record of a DNS server's ``NAMESERVER-DATABASE``."""

    _claimed: ClassVar[frozenset[str]] = frozenset({"TYPE", "NAME", "TTL", "IPADDRESS"})

    @property
    def record_type(self) -> str:
        return self._text("TYPE")

    @property
    def name(self) -> str:
        return self._text("NAME")

    @property
    def ttl(self) -> str:
        return self._text("TTL")

    @property
    def ip_address(self) -> str:
        return self._text("IPADDRESS")

    @property
    def identity(self) -> Identity:
        return _identity_of("dns_records", self._el)

    @property
    def zone_key(self) -> Identity:
        """Per-server key: one record per ``(type, name)`` inside a zone."""
        return zone_identity(self.identity)


class FtpAccount(PktNode):
    """One FTP account (``FTP_SERVER/USER_ACCOUNT_MNGR/ACCOUNT``)."""

    _claimed: ClassVar[frozenset[str]] = frozenset({"USERNAME", "PASSWORD", "PERMISSIONS"})

    @property
    def username(self) -> str:
        return self._text("USERNAME")

    @property
    def password(self) -> str:
        return self._text("PASSWORD")

    @property
    def permissions(self) -> str:
        return self._text("PERMISSIONS")

    @property
    def identity(self) -> Identity:
        return _identity_of("ftp_accounts", self._el)


class DeviceServices(PktNode):
    """The service record lists of one device's ``<ENGINE>`` block.

    A device with no service blocks reports empty lists — routers and switches
    simply have nothing here.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "ACS_SERVER", "ACS_CLIENTS", "USERS", "DHCP_SERVERS", "DHCP_SERVER",
            "DNS_SERVER", "NAMESERVER-DATABASE", "FTP_SERVER", "USER_ACCOUNT_MNGR",
            "EMAIL_SERVER", "DHCP_POOL_LEASES",
        }
    )

    # -- record lists ------------------------------------------------------
    @property
    def aaa_clients(self) -> list[AaaClient]:
        out: list[AaaClient] = []
        for container in self._find_all_deep("ACS_CLIENTS"):
            out.extend(AaaClient.from_element(c) for c in container.find_all("CLIENT"))
        return out

    @property
    def aaa_users(self) -> list[AaaUser]:
        out: list[AaaUser] = []
        for container in self._find_all_deep("USERS"):
            out.extend(AaaUser.from_element(u) for u in container.find_all("USER"))
        return out

    @property
    def dhcp_pools(self) -> list[DhcpPool]:
        out: list[DhcpPool] = []
        for container in self._find_all_deep("POOLS"):
            out.extend(DhcpPool.from_element(p) for p in container.find_all("POOL"))
        return out

    @property
    def dns_records(self) -> list[DnsRecord]:
        out: list[DnsRecord] = []
        for container in self._find_all_deep("NAMESERVER-DATABASE"):
            out.extend(
                DnsRecord.from_element(r) for r in container.find_all("RESOURCE-RECORD")
            )
        return out

    @property
    def ftp_accounts(self) -> list[FtpAccount]:
        out: list[FtpAccount] = []
        for container in self._find_all_deep("USER_ACCOUNT_MNGR"):
            out.extend(FtpAccount.from_element(a) for a in container.find_all("ACCOUNT"))
        return out

    # -- helpers ----------------------------------------------------------
    def _find_all_deep(self, tag: str) -> list[XmlElement]:
        if self._el.tag == tag:
            return [self._el]
        return [e for e in self._el.iter_elements() if e.tag == tag]
