"""Tests for pkt_core.builder (Lab and Activity public SDK API)."""

from __future__ import annotations

import contextlib
from typing import Any

try:
    import pytest
except ImportError:  # pragma: no cover
    class _PytestShim:
        @staticmethod
        def raises(exc: type[Exception]) -> Any:
            @contextlib.contextmanager
            def _mgr() -> Any:
                try:
                    yield
                except exc:
                    pass
                else:
                    raise AssertionError(f"Expected exception {exc} was not raised")

            return _mgr()

    pytest = _PytestShim()  # type: ignore[assignment]

from pkt_core import (
    Activity,
    DeviceNameConflictError,
    DeviceNotFoundError,
    InvalidCableError,
    Lab,
    decode,
)


def test_lab_clean_initial_state() -> None:
    lab = Lab()
    # By default, seed devices are pruned so the author starts with 0 devices
    assert lab.device_count == 0
    assert lab.link_count == 0
    assert lab.device_names() == []


def test_lab_add_devices_and_links(tmp_path: Any) -> None:
    lab = Lab()
    r1 = lab.add_device(
        "2911",
        "R1",
        x=200,
        y=200,
        install="HWIC-2T",
        ios_config=[
            "interface GigabitEthernet0/0",
            " ip address 192.168.1.1 255.255.255.0",
            " no shutdown",
            "end",
        ],
    )
    sw1 = lab.add_device("2960-24TT", "SW1", x=400, y=200)
    pc1 = lab.add_device(
        "PC-PT",
        "PC1",
        x=600,
        y=200,
        pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"),
    )

    assert lab.device_count == 3
    assert set(lab.device_names()) == {"R1", "SW1", "PC1"}

    lab.link(r1, "GigabitEthernet0/0", sw1, "GigabitEthernet0/1", kind="copper")
    lab.link(sw1, "FastEthernet0/1", pc1, "FastEthernet0", kind="copper")
    assert lab.link_count == 2

    # Save and verify
    out_file = tmp_path / "test_out.pkt"
    lab.save(out_file)

    container = decode(out_file)
    assert container.root_tag == "PACKETTRACER5"
    assert container.is_activity is False
    assert b"192.168.1.10" in container.xml
    assert b"GigabitEthernet0/0" in container.xml


def test_lab_serial_link(tmp_path: Any) -> None:
    lab = Lab()
    r1 = lab.add_device("2911", "R1", 100, 100, install="HWIC-2T")
    r2 = lab.add_device("2911", "R2", 300, 100, install="HWIC-2T")

    lab.link(
        r1,
        "Serial0/0/0",
        r2,
        "Serial0/0/0",
        kind="serial",
        dce=r1,
        clock=64000,
    )
    assert lab.link_count == 1

    out_file = tmp_path / "serial_lab.pkt"
    lab.save(out_file)

    container = decode(out_file)
    assert b"eSerial" in container.xml
    assert b"64000" in container.xml


def test_name_conflict_handling() -> None:
    lab = Lab()
    lab.add_device("2911", "Router1", 100, 100)

    # Collision with on_name_conflict="raise" (default) raises DeviceNameConflictError
    with pytest.raises(DeviceNameConflictError):
        lab.add_device("2911", "Router1", 200, 100)

    # Collision with on_name_conflict="suffix" auto-renames
    _renamed = lab.add_device(
        "2911", "Router1", 200, 100, on_name_conflict="suffix"
    )
    assert "Router1(1)" in lab.device_names()


def test_invalid_device_and_cable_errors() -> None:
    lab = Lab()
    r1 = lab.add_device("2911", "R1", 100, 100)

    # Unknown device in link
    with pytest.raises(DeviceNotFoundError):
        lab.link(r1, "GigabitEthernet0/0", "NonExistent", "FastEthernet0/1")

    # Invalid cable kind
    sw1 = lab.add_device("2960-24TT", "SW1", 300, 100)
    with pytest.raises(InvalidCableError):
        lab.link(
            r1,
            "GigabitEthernet0/0",
            sw1,
            "GigabitEthernet0/1",
            kind="fiber_optic",
        )


def test_activity_creation(tmp_path: Any) -> None:
    act = Activity()
    act.set_instructions("<h3>Title</h3><p>Configure everything</p>")
    act.set_password("secret123")
    act.set_timer(enabled=True, seconds=1800)
    act.set_feedback(complete="Well done!", incomplete="Keep trying!")

    out_file = tmp_path / "activity.pka"
    act.save(out_file)

    container = decode(out_file)
    assert container.root_tag == "PACKETTRACER5_ACTIVITY"
    assert container.is_activity is True
    assert b'PASS="secret123"' in container.xml
    assert b"Configure everything" in container.xml
    assert b"Well done!" in container.xml
