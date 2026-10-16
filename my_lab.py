import lab_api

models, modules = lab_api.load_templates("tools/device_templates.json")
lab = lab_api.Lab("tools/network_seed.xml", models, modules)
lab.prune_seed_devices()

r1 = lab.add_device(
    "2911",
    "R1",
    250,
    350,
    install="HWIC-2T",
    ios_config=[
        "interface GigabitEthernet0/0",
        " ip address 192.168.1.1 255.255.255.0",
        " no shutdown",
        "end",
    ],
)

sw1 = lab.add_device("2960-24TT", "SW1", 450, 350)

pc1 = lab.add_device(
    "PC-PT",
    "PC1",
    650,
    350,
    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"),
)

lab.link(r1, "GigabitEthernet0/0", sw1, "GigabitEthernet0/1")
lab.link(sw1, "FastEthernet0/1", pc1, "FastEthernet0")

lab.save("my_lab.pkt")
print("Generated my_lab.pkt")
