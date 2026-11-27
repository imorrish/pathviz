# Bridges demo

Linux bridges made with `ip` alone, in the arrangements you meet in practice.
It changes the network setup of the machine it runs on, so it comes with a
one-machine playground:

```sh
make playground DEMO=bridges    # on your machine, in the root of the repository
make demo-bridges               # on the dev machine of the playground, in ~/pathviz
```

Then open the `pathviz` tab. PathViz runs with `--proto arp,ip,other`, so the
IPv6 chatter of the kernel stays out of the picture. A loop sends a frame or
two every couple of seconds over one of the bridges.

| Bridge | Namespace | What it shows |
|---|---|---|
| `br-flat` | host | The bridge and both ends of every veth pair in one namespace, plus a tap device |
| `br-mixed` | host | Ports that lead to a namespace of `ip netns` (`blue`), to one made with `unshare`, and to one that a Python process made for itself. A rule of the bridge family drops TCP port 8000 to the last one |
| `docker0` | host | Docker's default bridge, without containers |
| `br1` | `bridge1` | One subnet: three end hosts, each in a namespace of its own |
| `br100`, `br200`, `br300` | `bridge100`... | Two bridges that hang off a third one |
| `br-vlan` | `bridge-vlan` | VLAN filtering: two VLANs on one bridge |

The last three rows are the topologies of the
[Computer Networking Fundamentals](https://labs.iximiuz.com/courses/computer-networking-fundamentals)
course. Their bridges live in namespaces of their own: pick one in the
**Namespace** list.

Things to try:

- **Bridge · L2**, look "Topology": an ARP request floods to every port, and the
  reply goes to one port only, because the bridge has learned where the asker is.
- The same frames in the look "Hooks": PREROUTING, the MAC table lookup, and
  FORWARD and POSTROUTING once per copy.
- `br-mixed`: the frame to port 8000 that stops in FORWARD.
- Namespace `bridge-vlan`: a broadcast reaches only the ports of its VLAN.
- **Combined** on the host: a ping from `blue` to 10.30.0.1 crosses the device
  hook of the port, the bridge hooks, and the IP hooks. With `br_netfilter`
  loaded (Docker loads it), the IP hooks run inside the bridge hooks.
- **Device · L1**: the same frame at the port, and again at the bridge device.

`make stop-bridges` stops PathViz and the traffic loop.
