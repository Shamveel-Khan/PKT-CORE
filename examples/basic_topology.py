#!/usr/bin/env python3
"""Example 1: Basic Network Topology (Router - Switch - PC).

Demonstrates creating a new lab using the bundled templates and seeds,
assigning IP addresses, configuring IOS CLI commands, and saving a .pkt file.
"""

from pkt_core import Lab

# 1. Initialize a fresh, empty lab workspace
lab = Lab()

# 2. Place a Cisco 2911 router and configure its GigabitEthernet0/0 interface
r1 = lab.add_device(
    model="2911",
    name="R1",
    x=200,
    y=250,
    ios_config=[
        "interface GigabitEthernet0/0",
        " ip address 192.168.1.1 255.255.255.0",
        " no shutdown",
        "end",
    ],
)

# 3. Place a Cisco 2960-24TT layer 2 switch
sw1 = lab.add_device(
    model="2960-24TT",
    name="SW1",
    x=400,
    y=250,
)

# 4. Place a PC with static IP, subnet mask, and default gateway
pc1 = lab.add_device(
    model="PC-PT",
    name="PC1",
    x=600,
    y=250,
    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"),
)

# 5. Connect devices with copper straight-through cabling
lab.link(r1, "GigabitEthernet0/0", sw1, "GigabitEthernet0/1")
lab.link(sw1, "FastEthernet0/1", pc1, "FastEthernet0")

# 6. Save the lab file (sealed with Twofish-EAX AEAD container)
output_path = "basic_topology.pkt"
lab.save(output_path)
print(f"Generated {output_path} successfully ({lab.device_count} devices, {lab.link_count} links).")
