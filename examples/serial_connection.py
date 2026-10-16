#!/usr/bin/env python3
"""Example 2: Serial Point-to-Point Connection.

Demonstrates installing a modular HWIC-2T interface card into a router bay,
configuring DCE/DTE serial endpoints with clock rate, and cabling.
"""

from pkt_core import Lab

lab = Lab()

# Place two 2911 routers with HWIC-2T serial modules in bay 0
r1 = lab.add_device(
    model="2911",
    name="Branch-R1",
    x=250,
    y=250,
    install="HWIC-2T",
    ios_config=[
        "interface Serial0/0/0",
        " ip address 10.0.0.1 255.255.255.252",
        " no shutdown",
        "end",
    ],
)

r2 = lab.add_device(
    model="2911",
    name="HQ-R1",
    x=550,
    y=250,
    install="HWIC-2T",
    ios_config=[
        "interface Serial0/0/0",
        " ip address 10.0.0.2 255.255.255.252",
        " no shutdown",
        "end",
    ],
)

# Connect Serial0/0/0 interfaces. R1 is the DCE end with 128000 bps clock rate.
lab.link(
    a=r1,
    a_port="Serial0/0/0",
    b=r2,
    b_port="Serial0/0/0",
    kind="serial",
    dce=r1,
    clock=128000,
)

lab.save("serial_connection.pkt")
print("Generated serial_connection.pkt successfully.")
