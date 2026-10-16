# Lab-making capabilities

What can be authored in a Packet Tracer 9 `.pkt` by writing XML.  All "verified"
items were tested by generating a file and loading it in Packet Tracer.

| Capability | Where in XML | Status |
| --- | --- | --- |
| Device model & name | `<ENGINE><TYPE model=…>`, `<NAME>` | ✅ verified |
| Logical position | `<WORKSPACE><LOGICAL><X>/<Y>` | ✅ verified |
| Physical scene placement | `<WORKSPACE><PHYSICAL>`, `<PHYSICAL_CPUR>` | ✅ (remap to existing node) |
| Power on/off | `<ENGINE><POWER>` | ✅ verified |
| Modules | `<ENGINE><MODULE>/<SLOT>/<MODULE><MODEL>` | ✅ verified |
| Copper cable | `<LINK><TYPE>eCopper`, `eStraightThrough` | ✅ verified |
| Serial cable | `<LINK><TYPE>eSerial` + `DCEDEV/DCEPORT` | ✅ cable loads |
| IOS running-config | `<ENGINE><RUNNINGCONFIG><LINE>` | ✅ verified |
| End-device IP / DHCP | NIC `<PORT><IP>/<SUBNET>/<PORT_GATEWAY>/<PORT_DHCP_ENABLE>` | ✅ verified |
| OS image / boot | `<OS_IMAGE>`, `<OS_FILE_NAME>`, config register | 📖 read (set untested) |
| Wireless, AP/SSID, clusters | section-specific | 📖 read |

Tooling: [`tools/lab_api.py`](../tools/lab_api.py) exposes the verified operations.

```python
import lab_api
m  = lab_api.harvest_models("/opt/pt/saves", {"2911", "2960-24TT", "PC-PT"})
mod = lab_api.harvest_modules("/opt/pt/saves", {"HWIC-2T"})
lab = lab_api.Lab("seed.pkt", m, mod)

r  = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T", bay=0,
                    ios_config=["interface GigabitEthernet0/0",
                                " ip address 192.168.9.1 255.255.255.0", " no shutdown", "end"])
sw = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350,
                    pc_ip=("192.168.9.10", "255.255.255.0", "192.168.9.1"))
lab.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet1/0/1" if False else "GigabitEthernet0/1")
lab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
lab.save("lab.pkt")
```

## 1. Devices

`<ENGINE><TYPE customModel="" model="MODEL">Label</TYPE>` picks the model; harvested
blocks give a ready-made instance (modules, ports, OS).  Position is
`<WORKSPACE><LOGICAL><X>/<Y>`; physical placement is a scene path (see
[SCENE_GRAPH.md](SCENE_GRAPH.md) §2).

## 2. Power

`<ENGINE><POWER>true|false</POWER>`.  Setting `false` powers the device off at
load (verified: the attached link drops).

## 3. Modules

An installed module is a slot subtree:

```xml
<SLOT>
  <TYPE>eInterfaceCard</TYPE>
  <MODULE>
    <TYPE>eInterfaceCard</TYPE>
    <MODEL>HWIC-2T</MODEL>
    <PORT>…</PORT><PORT>…</PORT>
  </MODULE>
</SLOT>
```

Install by replacing an **empty bay** — a `<SLOT>` whose `<TYPE>` is
`eInterfaceCard` and which has no `<MODULE>` — with the module's slot subtree
(clone it from any device that has it; refresh the port MACs).

Interface names come from the bay position: on a **2911**, an `HWIC-2T` in bay
`0/0` yields `Serial0/0/0` and `Serial0/0/1` (confirmed against configured labs).
A per-model bay catalogue (which bays exist and which module families fit) is in
`packet-tracer-mcp/src/catalog/router-slots.ts`.

## 4. Cabling

Copper links are fully synthable:

```xml
<LINK><TYPE>eCopper</TYPE><CABLE>
  <LENGTH>1</LENGTH><FUNCTIONAL>true</FUNCTIONAL>
  <FROM>save-ref-id:…</FROM><PORT>GigabitEthernet0/1</PORT>
  <TO>save-ref-id:…</TO><PORT>FastEthernet0/1</PORT>
  <FROM_DEVICE_MEM_ADDR>…</FROM_DEVICE_MEM_ADDR><TO_DEVICE_MEM_ADDR>…</TO_DEVICE_MEM_ADDR>
  <FROM_PORT_MEM_ADDR>…</FROM_PORT_MEM_ADDR><TO_PORT_MEM_ADDR>…</TO_PORT_MEM_ADDR>
  <GEO_VIEW_COLOR>#6ba72e</GEO_VIEW_COLOR>
  <IS_MANAGED_IN_RACK_VIEW>false</IS_MANAGED_IN_RACK_VIEW>
  <TYPE>eStraightThrough</TYPE>
</CABLE></LINK>
```

Requirements: `<FROM>`/`<TO>` = device `SAVE_REF_ID`s, `<PORT>` names that exist
on those devices, and a matching cable `<TYPE>`.  The `*_MEM_ADDR` values are
not validated (PT rebinds).

**Serial** uses `<TYPE>eSerial</TYPE>` with `<FROM>/<TO>` = device `SAVE_REF_ID`s
and `<DCEDEV>/<DCEPORT>` naming the DCE end.  `lab_api.link(kind="serial", dce=...)`
now also sets the DCE port's `<CLOCKRATE>`/`<CLOCKRATEFLAG>true`/`<POWER>true`
(and both ends `CLOCKRATEFLAG=true`, `POWER=true`) plus an IOS `clock rate` line.
A generated serial link is byte-for-byte structurally identical to a real one;
PT renders such links red on headless load even in the reference answer key, so
colour is initial-state behaviour, not a generation defect.

## 5. Configuration

* **IOS devices**: `<RUNNINGCONFIG>` inside `<ENGINE>`, one CLI command per
  `<LINE>`; applied on load.  Long configs work (622 lines tested).
  See [CONFIGURATION.md](CONFIGURATION.md).
* **End devices**: NIC `<PORT>` fields `<IP>`, `<SUBNET>`, `<PORT_GATEWAY>`,
  `<PORT_DNS>`, `<PORT_DHCP_ENABLE>`.

## 6. Load requirements (checklist)

1. unique `<ENGINE>/<SAVE_REF_ID>` per device;
2. unique `MACADDRESS`/`BIA` per port;
3. valid `<PHYSICAL>` scene placement;
4. every `<LINK>` endpoint resolves (id + existing port).

Violations produce *"not compatible with this version of Cisco Packet Tracer"*
or *"corrupted Physical Workspace data"*.
