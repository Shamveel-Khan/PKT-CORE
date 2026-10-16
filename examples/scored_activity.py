#!/usr/bin/env python3
"""Example 3: Graded Activity (.pka).

Demonstrates creating a scored, password-protected Packet Tracer activity
with student instructions and countdown timer.
"""

from pkt_core import Activity, Lab

# 1. Author the initial network (student starts with empty configuration)
initial_lab = Lab()
r1_init = initial_lab.add_device("2911", "R1", 250, 300)
pc1_init = initial_lab.add_device("PC-PT", "PC1", 550, 300)
initial_lab.link(r1_init, "GigabitEthernet0/0", pc1_init, "FastEthernet0")

# 2. Author the answer network (target configuration graded against)
answer_lab = Lab()
r1_ans = answer_lab.add_device(
    "2911",
    "R1",
    250,
    300,
    ios_config=[
        "interface GigabitEthernet0/0",
        " ip address 192.168.10.1 255.255.255.0",
        " no shutdown",
        "end",
    ],
)
pc1_ans = answer_lab.add_device(
    "PC-PT",
    "PC1",
    550,
    300,
    pc_ip=("192.168.10.50", "255.255.255.0", "192.168.10.1"),
)
answer_lab.link(r1_ans, "GigabitEthernet0/0", pc1_ans, "FastEthernet0")

# 3. Create the activity and embed networks
activity = Activity()
activity.set_instructions([
    "<h3>Lab Task 1</h3><p>Configure interface GigabitEthernet0/0 on R1 with 192.168.10.1/24.</p>",
    "<h3>Lab Task 2</h3><p>Configure PC1 with IP 192.168.10.50, subnet mask 255.255.255.0, and default gateway 192.168.10.1.</p>",
])
activity.set_password("cisco123")
activity.set_timer(enabled=True, seconds=3600)  # 60 minute timer
activity.set_feedback(
    complete="Congratulations! All objectives configured correctly.",
    incomplete="Some configurations are missing or incorrect. Check IP addressing.",
)

activity.set_networks(
    initial_xml=initial_lab.to_xml(),
    answer_xml=answer_lab.to_xml(),
)

output_file = "student_lab.pka"
activity.save(output_file)
print(f"Generated scored activity {output_file} successfully.")
