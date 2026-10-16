# Configuration: making a *working* topology

Beyond placing and cabling devices, a `.pkt` can carry each device's runtime
configuration.  This is what turns a static canvas into a lab that actually
routes/pings.

## 1. Where configuration lives

### IOS devices (routers, switches, …)

Inside `<ENGINE>`:

```xml
<ENGINE>
  <TYPE model="2911">Router</TYPE>
  <NAME translate="true">R1</NAME>
  …
  <SYS_NAME>R1</SYS_NAME>
  <RUNNINGCONFIG>
    <LINE>!</LINE>
    <LINE>version 15.1</LINE>
    <LINE>hostname R1</LINE>
    <LINE>!</LINE>
    <LINE>interface GigabitEthernet0/0</LINE>
    <LINE> ip address 10.0.0.1 255.255.255.252</LINE>
    <LINE> no shutdown</LINE>
    <LINE>!</LINE>
    <LINE>ip route 192.168.2.0 255.255.255.0 10.0.0.2</LINE>
    <LINE>end</LINE>
  </RUNNINGCONFIG>
</ENGINE>
```

`<RUNNINGCONFIG>` is just the `show running-config` text, one CLI command per
`<LINE>`.  **Packet Tracer applies it when the file loads** — so you can
configure a device entirely by writing lines.

Verified: two builds differing only by

```
interface GigabitEthernet0/1 / ip address … / no shutdown      → link up (green)
interface GigabitEthernet0/1 / ip address … / shutdown         → link down (red)
```

produce images that differ in exactly 405 pixels, all in that link's indicator.
The `shutdown` line took effect on load.

**Long configs work.**  A 622-line running-config (200 extra loopback interfaces)
loads and comes up normally; there is no small per-command limit.

### End devices (PC, Server, …)

A PC's static IP lives on its NIC `<PORT>`:

```xml
<PORT>
  …
  <MACADDRESS>0005.5E25.CA71</MACADDRESS>
  <IP>192.168.1.10</IP>
  <SUBNET>255.255.255.0</SUBNET>
  <PORT_GATEWAY>192.168.1.1</PORT_GATEWAY>
  <PORT_DNS></PORT_DNS>
  <PORT_DHCP_ENABLE>false</PORT_DHCP_ENABLE>
  …
</PORT>
```

Set `PORT_DHCP_ENABLE` to `true` to use DHCP instead.

## 2. Generator

`tools/build_configured_lab.py` builds a complete working lab:

```
PC1 -- SW1 -- R1 ==== R2 -- SW2 -- PC2
192.168.1.10   .1 10.0.0.1/30 10.0.0.2/30 .1  192.168.2.10
```

with static IPs/gateways, static routes both ways, and an optional long config
(`--loopbacks N`).  It writes `<RUNNINGCONFIG>` for the routers/switch and the
`<IP>/<SUBNET>/<PORT_GATEWAY>` fields for the PCs, then cables everything.

```console
$ python3 tools/build_configured_lab.py --seed base.pkt --saves /opt/pt/saves \
      --out lab.pkt --loopbacks 200
```

## 3. Requirements checklist

For a generated file to load, every device must satisfy:

1. unique `<ENGINE>/<SAVE_REF_ID>`  (links and the file resolve devices by it);
2. unique `MACADDRESS`/`BIA` per port (cloning a template duplicates them);
3. a valid `<PHYSICAL>` scene placement (reuse the seed's node);
4. cables: `<FROM>`/`<TO>` = those ids, `<PORT>` = an interface that exists on
   that device (see [SCENE_GRAPH.md](SCENE_GRAPH.md) §3).

Missing any of these yields *"not compatible with this version of Cisco Packet
Tracer"* or *"corrupted Physical Workspace data"* at load.
