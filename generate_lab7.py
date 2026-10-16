
import lab_api

MODELS, MODULES = lab_api.load_templates("tools/device_templates.json")
SEED = "tools/network_seed.xml"


def create_lab():
    lab = lab_api.Lab(SEED, MODELS, MODULES)
    lab.prune_seed_devices()
    return lab


def add_router(lab, name, x, y, configs, install=None):
    kwargs = {"ios_config": configs}
    if install:
        kwargs["install"] = install
    return lab.add_device("2911", name, x, y, **kwargs)


def add_switch(lab, name, x, y):
    return lab.add_device("2960-24TT", name, x, y)


def add_pc(lab, name, x, y, ip, gateway, mask="255.255.255.0"):
    return lab.add_device(
        "PC-PT", name, x, y,
        pc_ip=(ip, mask, gateway)
    )


def interface_config(interface, ip, mask="255.255.255.0"):
    return [
        f"interface {interface}",
        f" ip address {ip} {mask}",
        " no shutdown",
        " exit",
    ]


def add_acl(config, number, rules, interface, direction):
    config.extend([
        f"access-list {number} " + rules[0]
    ])
    for rule in rules[1:]:
        config.append(f"access-list {number} {rule}")
    config.extend([
        f"interface {interface}",
        f" ip access-group {number} {direction}",
        " exit",
    ])


def task1(allow_one_student=False):
    lab = create_lab()

    r2_config = (
        interface_config("GigabitEthernet0/0", "192.168.1.1")
        + interface_config("GigabitEthernet0/1", "192.168.3.1")
        + [
            "ip access-list extended STUDENTS_IN",
            *(
                [
                    " permit ip host 192.168.1.10 192.168.2.0 0.0.0.255",
                    " deny ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255",
                ]
                if allow_one_student
                else [
                    " deny ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255",
                ]
            ),
            " permit ip any any",
            "interface GigabitEthernet0/0",
            " ip access-group STUDENTS_IN in",
            " exit",
        ]
    )

    r3_config = (
        interface_config("GigabitEthernet0/0", "192.168.3.2")
        + interface_config("GigabitEthernet0/1", "192.168.2.1")
        + [
            "ip route 192.168.1.0 255.255.255.0 192.168.3.1",
            "ip route 192.168.2.0 255.255.255.0 192.168.3.1",
        ]
    )

    # R2 and R3 use GigabitEthernet links in this example.
    # Change the interfaces if your chosen router template differs.
    r2 = add_router(lab, "Router2", 400, 350, r2_config)
    r3 = add_router(lab, "Router3", 650, 350, r3_config)

    sw0 = add_switch(lab, "Switch0", 200, 350)
    sw1 = add_switch(lab, "Switch1", 850, 350)

    pc2 = add_pc(lab, "PC2", 100, 280, "192.168.1.10", "192.168.1.1")
    pc3 = add_pc(lab, "PC3", 100, 420, "192.168.1.11", "192.168.1.1")
    pc4 = add_pc(lab, "PC4", 1000, 280, "192.168.2.10", "192.168.2.1")
    pc5 = add_pc(lab, "PC5", 1000, 420, "192.168.2.11", "192.168.2.1")

    lab.link(sw0, "FastEthernet0/1", pc2, "FastEthernet0")
    lab.link(sw0, "FastEthernet0/2", pc3, "FastEthernet0")
    lab.link(sw0, "GigabitEthernet0/1", r2, "GigabitEthernet0/0")

    lab.link(r2, "GigabitEthernet0/1", r3, "GigabitEthernet0/0")
    lab.link(r3, "GigabitEthernet0/1", sw1, "GigabitEthernet0/1")
    lab.link(sw1, "FastEthernet0/1", pc4, "FastEthernet0")
    lab.link(sw1, "FastEthernet0/2", pc5, "FastEthernet0")

    lab.save(
        "task1_allow_one.pkt" if allow_one_student
        else "task1_block_students.pkt"
    )


def task2():
    lab = create_lab()

    # One /24 per switch. Router0 connects to the left LANs,
    # Router1 to the central LAN, and Router2 to the right LANs.
    networks = {
        "left0": ("10.0.10.1", "10.0.10.0"),
        "left1": ("10.0.20.1", "10.0.20.0"),
        "center": ("10.0.30.1", "10.0.30.0"),
        "right3": ("10.0.40.1", "10.0.40.0"),
        "right4": ("10.0.50.1", "10.0.50.0"),
    }

    r0_config = []
    r1_config = []
    r2_config = []

    r0_config += interface_config("GigabitEthernet0/0", "10.0.10.1")
    r0_config += interface_config("GigabitEthernet0/1", "10.0.20.1")
    r0_config += interface_config("GigabitEthernet0/2", "10.0.100.1")

    r1_config += interface_config("GigabitEthernet0/0", "10.0.100.2")
    r1_config += interface_config("GigabitEthernet0/1", "10.0.30.1")
    r1_config += interface_config("GigabitEthernet0/2", "10.0.200.1")

    r2_config += interface_config("GigabitEthernet0/0", "10.0.200.2")
    r2_config += interface_config("GigabitEthernet0/1", "10.0.40.1")
    r2_config += interface_config("GigabitEthernet0/2", "10.0.50.1")

    # PC0 can be denied from routed destinations, but an ordinary
    # router ACL cannot block PC0 -> PC1 on the same switch/LAN.
    r0_config += [
        "ip access-list extended PC0_FILTER",
        " deny ip host 10.0.10.10 any",
        " permit ip any any",
        "interface GigabitEthernet0/0",
        " ip access-group PC0_FILTER in",
        " exit",
    ]

    # Block PC2-initiated ping to other LANs. Permit other IP traffic.
    r0_config += [
        "ip access-list extended PC2_FILTER",
        " deny icmp host 10.0.20.10 10.0.0.0 0.255.255.255 echo",
        " permit ip any any",
        "interface GigabitEthernet0/1",
        " ip access-group PC2_FILTER in",
        " exit",
    ]

    # PC5 HTTP block, PC7 FTP block.
    r2_config += [
        "ip access-list extended RIGHT3_FILTER",
        " deny tcp host 10.0.40.10 host 10.0.30.10 eq 80",
        " permit ip any any",
        "interface GigabitEthernet0/1",
        " ip access-group RIGHT3_FILTER in",
        " exit",
        "ip access-list extended RIGHT4_FILTER",
        " deny tcp host 10.0.50.10 host 10.0.30.10 eq 21",
        " deny tcp host 10.0.50.10 host 10.0.30.10 eq 20",
        " deny icmp any host 10.0.30.11 echo",
        " permit ip any any",
        "interface GigabitEthernet0/2",
        " ip access-group RIGHT4_FILTER in",
        " exit",
    ]

    # SMTP blocked from the Switch3 subnet.
    r2_config += [
        "ip access-list extended SMTP_FILTER",
        " deny tcp 10.0.40.0 0.0.0.255 host 10.0.30.10 eq 25",
        " permit ip any any",
        "interface GigabitEthernet0/1",
        " ip access-group SMTP_FILTER in",
        " exit",
    ]

    # POP3 blocked from the Switch4 subnet.
    r2_config += [
        "ip access-list extended POP3_FILTER",
        " deny tcp 10.0.50.0 0.0.0.255 host 10.0.30.10 eq 110",
        " permit ip any any",
        "interface GigabitEthernet0/2",
        " ip access-group POP3_FILTER in",
        " exit",
    ]

    # Static routes between routers.
    r0_config += [
        "ip route 10.0.30.0 255.255.255.0 10.0.100.2",
        "ip route 10.0.40.0 255.255.255.0 10.0.100.2",
        "ip route 10.0.50.0 255.255.255.0 10.0.100.2",
    ]
    r1_config += [
        "ip route 10.0.10.0 255.255.255.0 10.0.100.1",
        "ip route 10.0.20.0 255.255.255.0 10.0.100.1",
        "ip route 10.0.40.0 255.255.255.0 10.0.200.2",
        "ip route 10.0.50.0 255.255.255.0 10.0.200.2",
    ]
    r2_config += [
        "ip route 10.0.10.0 255.255.255.0 10.0.200.1",
        "ip route 10.0.20.0 255.255.255.0 10.0.200.1",
        "ip route 10.0.30.0 255.255.255.0 10.0.200.1",
    ]

    r0 = add_router(lab, "Router0", 300, 350, r0_config)
    r1 = add_router(lab, "Router1", 550, 250, r1_config)
    r2 = add_router(lab, "Router2", 800, 350, r2_config)

    sw0 = add_switch(lab, "Switch0", 150, 200)
    sw1 = add_switch(lab, "Switch1", 150, 500)
    sw2 = add_switch(lab, "Switch2", 550, 450)
    sw3 = add_switch(lab, "Switch3", 950, 200)
    sw4 = add_switch(lab, "Switch4", 950, 500)

    pc0 = add_pc(lab, "PC0", 50, 150, "10.0.10.10", "10.0.10.1")
    pc1 = add_pc(lab, "PC1", 50, 250, "10.0.10.11", "10.0.10.1")
    pc2 = add_pc(lab, "PC2", 50, 450, "10.0.20.10", "10.0.20.1")
    pc3 = add_pc(lab, "PC3", 50, 550, "10.0.20.11", "10.0.20.1")
    pc4 = add_pc(lab, "PC4", 500, 550, "10.0.30.11", "10.0.30.1")
    server = lab.add_device("Server-PT", "Server", 600, 550)
    pc5 = add_pc(lab, "PC5", 1050, 150, "10.0.40.10", "10.0.40.1")
    pc6 = add_pc(lab, "PC6", 1050, 250, "10.0.40.11", "10.0.40.1")
    pc7 = add_pc(lab, "PC7", 1050, 450, "10.0.50.10", "10.0.50.1")
    pc8 = add_pc(lab, "PC8", 1050, 550, "10.0.50.11", "10.0.50.1")

    lab.link(r0, "GigabitEthernet0/0", sw0, "GigabitEthernet0/1")
    lab.link(r0, "GigabitEthernet0/1", sw1, "GigabitEthernet0/1")
    lab.link(r0, "GigabitEthernet0/2", r1, "GigabitEthernet0/0")
    lab.link(r1, "GigabitEthernet0/1", sw2, "GigabitEthernet0/1")
    lab.link(r1, "GigabitEthernet0/2", r2, "GigabitEthernet0/0")
    lab.link(r2, "GigabitEthernet0/1", sw3, "GigabitEthernet0/1")
    lab.link(r2, "GigabitEthernet0/2", sw4, "GigabitEthernet0/1")

    for sw, pcs in [
        (sw0, [pc0, pc1]), (sw1, [pc2, pc3]),
        (sw3, [pc5, pc6]), (sw4, [pc7, pc8]),
    ]:
        for i, pc in enumerate(pcs, start=1):
            lab.link(sw, f"FastEthernet0/{i}", pc, "FastEthernet0")

    lab.link(sw2, "FastEthernet0/1", pc4, "FastEthernet0")
    lab.link(sw2, "FastEthernet0/2", server, "FastEthernet0")

    lab.save("task2_acl_lab.pkt")


if __name__ == "__main__":
    task1(allow_one_student=False)
    task1(allow_one_student=True)
    task2()
    print("Generated Task 1 and Task 2 Packet Tracer labs.")
