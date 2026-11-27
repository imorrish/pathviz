# PathViz

PathViz is a small packet path visualizer for Linux. It shows, live in your browser, how a packet travels through the [Netfilter](https://www.netfilter.org/) hooks of the kernel: the points on a packet's way where ebtables, iptables, and nftables rules run. PathViz covers the hooks of all three layers: the ingress and egress hooks of the network devices (L1), the hooks of the Linux bridges (L2), and the hooks of the IP layer (the classic PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING).

It helps with questions like these, among others:

- Which hooks does a packet cross, and in what order?
- Where does a packet get dropped: in a firewall rule, or by a routing decision?
- What does NAT rewrite, and at which stage?
- Which ports of a bridge get a copy of a frame, and why?
- Does the IP firewall see the packets that a bridge switches (`br_netfilter`)?

No special setup is needed for a telling picture. Start PathViz on a plain Linux host, on a router, or on a Docker host, and it draws the hooks with what it finds around them: the devices, the bridges and their ports, the containers behind the ports, and the processes with listening sockets. Every packet that matches the filter then leaves a trail on this picture. The [gallery](#gallery) has a few examples.

PathViz only observes: it logs the packets and never changes or stops them. It is built for learning and demos with a few packets per second. The focus is on accurate, readable visualizations rather than handling large traffic volumes.

## Gallery

### A Linux host

A web server on a plain Linux host: requests are delivered to its process through PREROUTING and INPUT, the replies leave through OUTPUT and POSTROUTING, and a firewall rule stops the requests to a blocked port.

https://github.com/user-attachments/assets/4cbf4cd6-f86d-4f5a-adbb-9dfcc11ee280

### A router

A host that forwards packets between two networks. A DNAT rule rewrites the destination of some of them on the way, and the stage where it happens turns amber.

https://github.com/user-attachments/assets/53ba8864-d9de-4a75-bcb1-6f598f220ab6

### A Docker host

A request to a published port on its way to a container: NAT and routing in the IP layer first, then Docker's bridge. Traffic between two containers stays in the bridge, and `br_netfilter` shows it to the IP firewall anyway.

https://github.com/user-attachments/assets/c35429b0-6658-4b9f-a88e-7210c750e257

### A Linux bridge

A bridge with four ports: a broadcast floods to all of them, a frame for a known address goes to one port only, and a firewall rule of the bridge family drops a frame on its way.

https://github.com/user-attachments/assets/b9aee1ae-53e1-4def-844a-6042e429b612

The host and the router are the [routing demo](demos/routing). The [containers demo](demos/containers) and the [bridges demo](demos/bridges) have richer setups of the other two.

## The views

PathViz shows the traffic of one network namespace at a time: the host's by default, or the one of any container, pod, or `ip netns` namespace of the machine. The page has a view per layer, and one that puts them together:

| View | What it shows |
|---|---|
| **IP · L3** | The five hooks of the IP layer, optionally with the stages inside them, between the network devices and the processes behind the sockets. |
| **Bridge · L2** | A Linux bridge in two looks: the bridge with its ports and what is behind each port, or the five hooks of the bridge family. The bridge's MAC table is next to it. |
| **Device · L1** | The ingress and egress hooks of every network device: the first and the last point where Netfilter sees a frame. L1 stands for "at the device" here: the hooks see whole Ethernet frames, not the physical layer. |
| **Combined** | All of the above on one diagram: the way of a packet from a device, through a bridge if there is one, and up to a socket. It also shows the IP hooks that `br_netfilter` runs inside the bridge hooks. |


## How it works

On its way through the Linux network stack, a packet passes a series of Netfilter hooks. PathViz places probes at these hooks. A probe records that a packet passed by and lets it go on unchanged. PathViz then puts the records of one packet together and lights up the hooks the packet crossed.

The hooks, in the order a packet from the network meets them:

- **Network devices** (the `netdev` family): the ingress hook, right after a device received a frame, and the egress hook, right before a device sends one.
- **Bridges** (the `bridge` family): PREROUTING, INPUT, FORWARD, OUTPUT, and POSTROUTING of a Linux bridge. A frame that arrives on a port of a bridge crosses them before the rest of the network stack sees it, if it sees it at all.
- **The IP layer** (the `inet` family, for IPv4 and IPv6): the five hooks of the same names, each with its stages: raw, mangle, nat, and filter.

Under the hood:

1. PathViz creates one nftables table per layer, all named `pathviz`, in the network namespace you watch: `netdev pathviz`, `bridge pathviz`, and `inet pathviz`.
2. Every table has probe chains at the start and at the end of each hook. The `inet` table also has one just before each stage.
3. Each probe logs the packets that match the filter to an NFLOG group and lets them continue unchanged.
4. The first IP probe that sees a matching packet records its identity using fields such as the IP ID and TCP sequence numbers. Later IP probes use this identity to recognize the packet even if NAT changes its addresses or ports.
5. PathViz reads the NFLOG records, matches them to individual packets, and reconstructs their paths. If a packet enters a hook or a stage but never reaches the next probe, PathViz marks it as stopped there.
6. The names around the hooks come from `ip`, `bridge`, `ss`, and the container runtimes (`docker`, `podman`, `crictl`, `ctr`), once a second.

The outcome of a packet comes from the last probe that saw it.

At a network device, a frame either **passed** the hook or was **dropped** in it.

At a bridge, the outcome is the bridge's decision:

- **Forwarded to `<port>`** - the bridge's MAC table names the port of the destination.
- **Flooded** - every port got a copy: the frame is a broadcast, or the bridge hasn't learned the destination yet.
- **Delivered** - the frame went up to the network stack above the bridge.
- **Dropped** - the frame entered a hook and never left it, or left PREROUTING and went nowhere.

In the IP layer:

- **Delivered locally** - the packet reached the end of INPUT.
- **Sent / Forwarded via `<device>`** - the packet reached the end of POSTROUTING.
- **Stopped in `<stage>`** - the packet entered a stage but never came out (e.g., a firewall rule dropped or rejected it).
- **Lost after `<hook>`** - the packet left a hook but never reached the next one (e.g., because of a missing route or disabled IP forwarding).

The **Inspect** view decodes the Ethernet, IP, and TCP/UDP/ICMP headers and the payload, with the fields alongside a hex dump. ARP, DNS, HTTP, TLS handshakes, and DHCP are decoded too.

PathViz probes coexist with existing iptables, nftables, and Docker rules. Stopping PathViz removes its tables from every network namespace it watched. If the process was killed, run `pathviz cleanup` to remove them.

## Demo

The quickest way to see PathViz in action is the local demo. It needs a Linux machine with Go, root, `python3`, `curl`, and `nft`:

```sh
git clone https://github.com/iximiuz/pathviz.git
cd pathviz
make demo-local
```

It prints the address of the web UI. The other demos change the network setup of a machine, so each comes with an [iximiuz Labs](https://labs.iximiuz.com/) playground to run in:

| Demo | Shows |
|---|---|
| [`demos/local`](demos/local) | Loopback traffic on one machine |
| [`demos/routing`](demos/routing) | Local delivery, forwarding, NAT, and a drop in the IP hooks |
| [`demos/bridges`](demos/bridges) | Bridges made with `ip`: flooding, learning, VLANs, bridges in network namespaces of their own |
| [`demos/containers`](demos/containers) | The bridge networks of Docker, Podman, containerd, and CRI-O, with the names of the containers and pods |

## Usage

Download the latest release binary to the Linux machine whose traffic you want to inspect:

```sh
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -L "https://github.com/iximiuz/pathviz/releases/latest/download/pathviz_linux_${arch}.tar.gz" | tar xz pathviz
sudo install -m 0755 pathviz /usr/local/bin/pathviz
```

PathViz requires root privileges, `nft`, `ip`, `bridge`, `ss`, `nsenter`, and the `nfnetlink_log` kernel module. The egress hook of devices needs Linux 5.16 or later, built with `CONFIG_NETFILTER_EGRESS`. On a kernel without it, PathViz says so and shows only the ingress hook.

Start it with:

```sh
sudo pathviz
```

The command prints the URL of the web UI:

```text
web UI on http://127.0.0.1:7070/?token=3f0c6a...
```

Open it in a browser on that machine. By default, PathViz shows all traffic until you configure a filter. The filter is the second line of the header, and the command line takes the same values:

| Flag | Selects |
|---|---|
| `--proto arp,ip,ip6,tcp,udp,icmp,other` | Protocols. `other` is every frame that is neither ARP nor IP |
| `--iface eth0,in:eth1,out:br0` | Packets that enter or leave through these devices. The name of a bridge selects all that crosses it |
| `--mac <addr>` | Frames from or to these MAC addresses |
| `--ip <addr\|cidr>` | Packets from or to these addresses, and the ARP messages about them |
| `--port <port>` | TCP and UDP packets from or to these ports |
| `--netns <name>` | The network namespace to show first: an `ip netns` name, the name of a container or a pod, or `pid:<n>` |
| `--layers l1,l2,l3` | The layers to probe (all three by default) |

`pathviz --help` lists the rest, and `pathviz rules` prints the nftables rules without installing them.

### Accessing the web UI

PathViz generates a new access token on every start and includes it in the printed URL. The web UI requires this token for all requests.

Once you've opened the URL, the browser remembers the token, so you can use plain `http://127.0.0.1:7070` in the same browser until PathViz restarts. The token is kept in browser storage for that address and port, not in a cookie. Without a valid token, the page prompts you to enter one.

To use a persistent token, either:

- Store a token of at least 16 characters in a file readable only by its owner and pass `--token-file <path>`.
- Set the `PATHVIZ_TOKEN` environment variable.

By default, the web UI listens on `127.0.0.1:7070` and isn't accessible from other machines.

> [!CAUTION]
> **Treat the PathViz access token like a password.** Anyone with the token can:
>
> - See traced traffic, including IP addresses, ports, interfaces, and the names and PIDs of processes with listening sockets.
> - Inspect packet contents, including payloads that may contain cookies, tokens, or passwords. PathViz retains up to 2048 bytes per packet for inspection. Use `--no-packet-view` to disable packet inspection and avoid retaining packet bytes.
> - Change the capture filter and, consequently, the nftables rules installed by PathViz (which runs as root). A broad filter can capture sensitive traffic and slow down a busy machine.
>
> Keep in mind:
>
> - PathViz prints the access URL to its output. If it runs as a service, the token may also appear in its logs (e.g., `journalctl -u <unit>`).
> - The web UI uses plain HTTP, not HTTPS. If you expose it with `--listen 0.0.0.0:7070`, the token travels over the network unencrypted. Prefer SSH port forwarding or a TLS reverse proxy.
> - `--dangerously-skip-token` disables authentication entirely. Anyone who can reach the listening address can inspect traffic and change filters, including other local users and programs when listening on localhost. Use this option only in isolated, disposable environments with no sensitive traffic.

### Generating some traffic

Start a simple HTTP server on the machine running PathViz and send it a request from another machine:

```sh
python3 -m http.server 8080          # on the machine with PathViz
curl http://<machine>:8080/          # from another machine
```

More things to try:

```sh
# Loopback traffic crosses four IP hooks, and the ingress hook of lo
curl http://127.0.0.1:8080/

# Drop incoming HTTP traffic in filter/INPUT
sudo iptables -I INPUT -p tcp --dport 8080 -j DROP

# Rewrite the destination port in nat/PREROUTING
sudo iptables -t nat -I PREROUTING -p tcp --dport 8081 -j REDIRECT --to-ports 8080

# A bridge with two network namespaces: an ARP request floods, the reply does not
sudo ip link add br0 type bridge && sudo ip link set br0 up
for n in a b; do
  sudo ip netns add $n
  sudo ip link add veth-$n type veth peer name eth0 netns $n
  sudo ip link set veth-$n master br0 up
  sudo ip -n $n link set eth0 up
done
sudo ip -n a addr add 10.9.0.1/24 dev eth0 && sudo ip -n b addr add 10.9.0.2/24 dev eth0
sudo ip netns exec a ping -c 1 10.9.0.2
```

## Limits

PathViz is a learning tool, not a full-featured packet capture system. There are a few things to keep in mind:

- **One network namespace per picture.** A view shows the hooks of one network namespace. A packet that goes from a container to the host is one packet in the container's namespace and another one in the host's: switch the Namespace list to follow it.
- **NAT and capture filters.** The IP probes keep a packet in view after NAT rewrites it. The device and bridge probes cannot: they see the packet with the addresses it has at that point. So with a filter on an address or a port that NAT rewrites, the Combined view may lack the hooks before or after the rewrite. Filter by something NAT doesn't change, or name both the old and the new value.
- **Partial paths.** If a packet matches the filter only after NAT changes it, PathViz can show its IP path only from that stage onward.
- **Egress hook.** Many kernels are built without the egress hook of devices. PathViz then shows where a frame arrives, and not where it leaves.
- **Before and after netfilter.** XDP and tc run before the ingress hook and after the egress hook, so what they drop or redirect is never seen. A drop inside the bridge itself (a blocked port, VLAN filtering) shows as a frame that passed PREROUTING and went nowhere, without the reason.
- **Rule visibility.** PathViz shows which hooks and stages a packet crosses, but not which individual firewall rules matched it.
- **Web UI traffic.** PathViz never traces its own web UI port (7070 by default), in any network namespace.
- **Process identification.** PathViz uses `ss` to look up the owning process shortly after a packet is seen. Short-lived processes, such as a one-shot `curl`, may have exited by then. Kernel-generated packets, such as TCP RSTs and ICMP replies, have no owning process.
- **Output interface filtering.** The output interface isn't known yet at PREROUTING. When filtering by output interface, PathViz initially records all packets matching the other filter conditions and keeps only those that later leave through the selected interface.
- **MAC address filtering.** The IP hooks don't see MAC addresses. With a MAC filter, the IP probes log by the rest of the filter, and PathViz keeps a packet only if a device or bridge probe saw it with one of the addresses.
- **Look-alike packets.** Two packets that differ only in what NAT may rewrite, seen within a fraction of a second, can end up in one path. It happens with IPv6 multicast chatter, such as router solicitations of several hosts.
- **Packet inspection.** The packet view includes at most 2048 bytes. The IP hooks don't expose the Ethernet header, so there it starts at the IP header. Each packet is decoded independently, without TCP stream reassembly. HTTP is recognized only in the segment where a message begins, and TLS only in handshake records. Checksums of locally generated packets may appear incomplete because the network card fills them in later.
- **Web UI security.** Access is controlled by a token, without user accounts or built-in TLS. Filter values are validated, and requests from other websites are rejected. See the security warning in the Usage section.
- **Dropped probe events.** Under heavy traffic, the kernel may drop some probe events. PathViz warns about this and marks affected packets, since their reported outcomes may be incorrect.

## Embedding on an existing page

PathViz can also be embedded in another web page, such as a blog post, using an `<iframe>`.

The embedded view can be customized through URL parameters. Most of them work in the full view too, as its starting state:

| Parameter | Effect |
|---|---|
| `view=embed` | Shows a compact, read-only diagram with the packet outcome. Of the header, only the speed and the connection badge remain. The filter fields and tables are hidden, and nothing in the diagram is clickable. |
| `mode=l3`, `l2`, `l1`, or `all` | Picks the view: IP, bridge, device, or combined. |
| `sub=hooks` | Picks the look of the view: `stages` or `hooks` for `l3` (the default is `stages`) and for `all` (the default is `hooks`), `topology` or `hooks` for `l2`. `detail=hooks` still works for `l3`. |
| `layers=l2,l3` | Picks the layers of the combined view. |
| `netns=<name>` | Picks the network namespace, by the same names as `--netns`. |
| `panels=packets,details` | Shows the selected tables (`packets`, `details`, and for `l2` also `extra`, the MAC table) below the diagram. Without this parameter, the embedded view has a switch that replaces the diagram with the tables. `tables=packets,stages` still works. |
| `theme=dark` or `theme=light` | Overrides the system color scheme, and the choice made with the switch next to the help button. |
| `speed=0.5` | Controls packet animation speed, from `0.25` to `2` in steps of `0.25`. The aliases `slow`, `medium`, and `fast` correspond to `0.5`, `1`, and `1.5`. Speed can also be changed in the UI. |
| `ifaces=eth0,lo` | Shows only the selected interface cards (`l3` and `l1`). |
| `bridges=br0,docker0` | Shows only the selected bridges (`l2`). |
| `procs=nginx,:8080` | Shows only the selected processes, matched by name or listening port (`l3`). |
| `proto=tcp`, `port=8080,9000`, `ip=10.0.0.1`, `iface=in:eth0`, `mac=<addr>` | Applies a display filter to the embedded view, using the same values as the corresponding command-line flags. |

For example:

```html
<iframe src="https://<pathviz-url>/?view=embed&sub=hooks&port=8080&ifaces=eth0&procs=:8080" width="100%" height="460"></iframe>
<iframe src="https://<pathviz-url>/?view=embed&mode=l2&proto=arp" width="100%" height="460"></iframe>
```

An embedded view needs an access token, just like the regular UI. You can either:

- Add `token=<token>` to the iframe URL, using a persistent token configured with `--token-file`.
- Run PathViz with `--dangerously-skip-token`.

**Be careful:** A token included in an iframe URL is visible to anyone who can access the embedding page. Use a dedicated PathViz instance in an isolated environment, and don't expose sensitive traffic.

### Multiple embeds from one PathViz instance

PathViz has two levels of filtering:

- **Capture filter** - configured through command-line flags or the full web UI. It determines which packets PathViz actually traces in a network namespace and is shared by all views of that namespace.
- **Display filter** - configured through an embedded view's URL. It selects which of the already captured packets that particular view shows.

This lets you put several embeds on the same page, each showing a different traffic flow.

For example:

1. Start PathViz with a capture filter covering both flows: `--port 8080,9000`.
2. Give each embed its own display filter: `port=8080` for local traffic, `iface=out:veth-app` for forwarded traffic.

Embedded views never change the capture filter.

The `ip=` parameter also accepts IPv4 prefixes (e.g., `10.0.0.0/8`). IPv6 addresses must be written in full.

## Development

PathViz is a single Go module with the web UI embedded in the binary. The UI is plain JavaScript modules, with no build step and no dependencies.

PathViz changes firewall tables and reads traffic, so develop and test it on a machine you can throw away. Every demo has a playground for that, with a `dev` machine that has the Go toolchain:

```sh
make playground DEMO=bridges     # start the playground and copy the sources to dev
labctl ssh <playground-id>       # a shell on dev
cd ~/pathviz
make test                        # gofmt, go vet, go test
make demo-bridges                # build, install, and start the demo
```

After a change on your machine, `make sync PLAYGROUND=<playground-id>` copies the sources again. `make run FLAGS="--port 8080"` builds and runs PathViz on the machine you are on.
