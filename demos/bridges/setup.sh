# Bridges made with ip(8) alone. Run as root on a throwaway machine, after
# ../lib.sh ("make demo-bridges" does it on the dev machine of the playground).
#
#   br-flat   Everything in the network namespace of the host: the bridge and
#             both ends of every veth pair, and a tap device.
#   br-mixed  The bridge in the namespace of the host (10.30.0.1/24), and the
#             other ends of its ports in a namespace of "ip netns" (blue), in
#             one made with unshare(1), and in one that a Python process made
#             for itself with the unshare system call. A firewall rule of the
#             bridge family drops what goes to TCP port 8000 of the latter.
#   br1       The labs of the Computer Networking Fundamentals course: every
#   br100...  bridge in a namespace of its own (bridge1, bridge100, ...), and
#   br-vlan   every end host in one more. br100 and br200 hang off br300, and
#             br-vlan filters by VLAN (10 and 20).
#
# A loop sends a frame or two every couple of seconds over one of the bridges.

stop_units pathviz pv-traffic pv-unshared pv-cloned

NAMESPACES="blue bridge1 host1 host2 host3 bridge100 bridge200 bridge300 host100 host101 host200 host201 bridge-vlan host10 host11 host12 host20 host21 host22"
for ns in $NAMESPACES; do
	ip netns del "$ns" 2>/dev/null || true
done
for dev in br-flat br-mixed flat1 flat2 flat3 tap-vm mx-local; do
	ip link del "$dev" 2>/dev/null || true
done

# ethsend is the frame sender of the course: any text in a frame of its own.
cat > /usr/local/bin/ethsend <<'PY'
#!/usr/bin/env python3
# Usage: ethsend eth0 ff:ff:ff:ff:ff:ff 'Hello everybody!'
import fcntl, socket, struct, sys

def main():
    ifname, dstmac, payload = sys.argv[1], sys.argv[2], sys.argv[3]
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((ifname, 0))
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    frame = bytes.fromhex(dstmac.replace(':', '')) + info[18:24] + b'\x7A\x05' + payload.encode('utf-8')
    s.send(frame)

main()
PY
chmod +x /usr/local/bin/ethsend

# ---- br-flat: all in the namespace of the host ------------------------------

ip link add br-flat type bridge
ip link set br-flat up
for i in 1 2 3; do
	ip link add "flat$i" type veth peer name "flat${i}-end"
	ip link set "flat$i" master br-flat up
	ip link set "flat${i}-end" up
done
ip tuntap add dev tap-vm mode tap
ip link set tap-vm master br-flat up

# ---- br-mixed: the bridge on the host, the far ends in other namespaces -----

ip link add br-mixed type bridge
ip addr add 10.30.0.1/24 dev br-mixed
ip link set br-mixed up

ip netns add blue
ip link add mx-blue type veth peer name eth0 netns blue
ip -n blue addr add 10.30.0.11/24 dev eth0
ip -n blue link set eth0 up
ip -n blue link set lo up
ip link set mx-blue master br-mixed up

# A namespace without a name: only the process in it keeps it alive.
systemd-run --quiet --unit pv-unshared unshare --net sleep infinity
# A process that moves itself to a new namespace and then serves HTTP there.
systemd-run --quiet --unit pv-cloned python3 -c '
import http.server, os
os.unshare(os.CLONE_NEWNET)
os.chdir("/var/empty") if os.path.isdir("/var/empty") else os.chdir("/tmp")
http.server.HTTPServer(("0.0.0.0", 8000), http.server.SimpleHTTPRequestHandler).serve_forever()
'
attach_pid() {
	unit=$1 port=$2 addr=$3
	pid=$(systemctl show -p MainPID --value "$unit")
	# Wait until the process is in its own namespace.
	n=0
	while [ "$(readlink "/proc/$pid/ns/net")" = "$(readlink /proc/1/ns/net)" ]; do
		n=$((n + 1))
		[ "$n" -lt 50 ] || { echo "$unit did not leave the namespace of the host" >&2; exit 1; }
		sleep 0.1
		pid=$(systemctl show -p MainPID --value "$unit")
	done
	ip link add "$port" type veth peer name eth0 netns "$pid"
	nsenter -t "$pid" -n sh -c "ip addr add $addr dev eth0 && ip link set eth0 up && ip link set lo up"
	ip link set "$port" master br-mixed up
}
attach_pid pv-unshared mx-unshared 10.30.0.12/24
attach_pid pv-cloned mx-cloned 10.30.0.13/24

ip link add mx-local type veth peer name mx-local-end
ip link set mx-local master br-mixed up
ip link set mx-local-end up

# Docker (if the machine has it) makes the IP packets of every bridge pass the
# iptables rules, and its FORWARD chain drops what Docker does not know. Let
# the packets of br-mixed through, as Docker does for its own bridges.
if iptables -nL DOCKER-USER >/dev/null 2>&1; then
	iptables -C DOCKER-USER -i br-mixed -o br-mixed -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i br-mixed -o br-mixed -j ACCEPT
fi
# A firewall of the bridge family, to see a frame stopped: the HTTP server of
# the Python process is closed to the other ports.
nft -f - <<'NFT'
table bridge pathviz-demo-fw
delete table bridge pathviz-demo-fw
table bridge pathviz-demo-fw {
	chain forward {
		type filter hook forward priority filter; policy accept;
		oifname "mx-cloned" tcp dport 8000 drop
	}
}
NFT

# ---- The bridges of the course ----------------------------------------------

# create_bridge <namespace> <bridge> [vlan]
create_bridge() {
	ip netns add "$1"
	ip netns exec "$1" ip link set lo up
	ip netns exec "$1" ip link add "$2" type bridge
	ip netns exec "$1" ip link set "$2" up
	[ -z "${3:-}" ] || ip netns exec "$1" ip link set "$2" type bridge vlan_filtering 1
}

# create_end_host <namespace> <device> <bridge namespace> <bridge> [address] [vlan]
create_end_host() {
	ip netns add "$1"
	ip netns exec "$1" ip link set lo up
	ip link add "$2" netns "$1" type veth peer "${2}b" netns "$3"
	ip netns exec "$1" ip link set "$2" up
	ip netns exec "$3" ip link set "${2}b" up
	[ -z "${5:-}" ] || ip netns exec "$1" ip addr add "$5" dev "$2"
	ip netns exec "$3" ip link set "${2}b" master "$4"
	if [ -n "${6:-}" ]; then
		# An access port: untagged frames that come in belong to the VLAN.
		ip netns exec "$3" bridge vlan del dev "${2}b" vid 1
		ip netns exec "$3" bridge vlan add dev "${2}b" vid "$6" pvid untagged
	fi
}

# connect_bridges <namespace 1> <bridge 1> <namespace 2> <bridge 2>
connect_bridges() {
	ip link add "veth_$4" netns "$1" type veth peer "veth_$2" netns "$3"
	ip netns exec "$1" ip link set "veth_$4" up
	ip netns exec "$3" ip link set "veth_$2" up
	ip netns exec "$1" ip link set "veth_$4" master "$2"
	ip netns exec "$3" ip link set "veth_$2" master "$4"
}

# One IP subnet over one bridge.
create_bridge bridge1 br1
create_end_host host1 eth1 bridge1 br1 192.168.0.1/24
create_end_host host2 eth2 bridge1 br1 192.168.0.2/24
create_end_host host3 eth3 bridge1 br1 192.168.0.3/24

# Two bridges under a third one: a single broadcast domain.
create_bridge bridge100 br100
create_end_host host100 eth100 bridge100 br100
create_end_host host101 eth101 bridge100 br100
create_bridge bridge200 br200
create_end_host host200 eth200 bridge200 br200
create_end_host host201 eth201 bridge200 br200
create_bridge bridge300 br300
connect_bridges bridge100 br100 bridge300 br300
connect_bridges bridge200 br200 bridge300 br300

# Two VLANs on one bridge: two broadcast domains.
create_bridge bridge-vlan br-vlan vlan
create_end_host host10 eth10 bridge-vlan br-vlan "" 10
create_end_host host11 eth11 bridge-vlan br-vlan "" 10
create_end_host host12 eth12 bridge-vlan br-vlan "" 10
create_end_host host20 eth20 bridge-vlan br-vlan "" 20
create_end_host host21 eth21 bridge-vlan br-vlan "" 20
create_end_host host22 eth22 bridge-vlan br-vlan "" 20

# ---- Traffic ----------------------------------------------------------------

cat > /usr/local/bin/pathviz-demo-traffic <<'SH'
#!/bin/sh
# One step every 2 seconds, over one of the bridges.
mac() { cat "/sys/class/net/$1/address"; }
nsmac() { ip netns exec "$1" cat "/sys/class/net/$2/address"; }
unshared=$(systemctl show -p MainPID --value pv-unshared)
n=0
while true; do
	n=$((n + 1))
	case $((n % 12)) in
	1) ethsend flat1-end ff:ff:ff:ff:ff:ff 'Hello all!' ;;
	2) ip netns exec host1 ping -q -c 1 -W 1 192.168.0.2 >/dev/null ;;
	3) ip netns exec host100 ethsend eth100 ff:ff:ff:ff:ff:ff 'Hello all!' ;;
	4) ip netns exec blue ping -q -c 1 -W 1 10.30.0.12 >/dev/null ;;
	5) ip netns exec host10 ethsend eth10 ff:ff:ff:ff:ff:ff 'Hello VLAN 10!' ;;
	6) ethsend flat1-end "$(mac flat2-end)" 'Hello flat2!'; ethsend flat2-end "$(mac flat1-end)" 'Hello flat1!' ;;
	7) nsenter -t "$unshared" -n curl -s -m 2 -o /dev/null http://10.30.0.13:8000/ ;;
	8) ip netns exec host201 ethsend eth201 "$(nsmac host100 eth100)" 'Hello host100!' ;;
	9) ip netns exec host20 ethsend eth20 ff:ff:ff:ff:ff:ff 'Hello VLAN 20!' ;;
	10) ping -q -c 1 -W 1 10.30.0.11 >/dev/null ;;
	11) ip netns exec host3 ping -q -c 1 -W 1 192.168.0.1 >/dev/null ;;
	0)
		# Now and then the hosts forget their neighbors and a bridge forgets
		# its MAC table, so ARP requests and floods of unicast frames show up.
		ip -n host1 neigh flush all
		ip -n blue neigh flush all
		[ $((n % 36)) -ne 0 ] || ip -n bridge1 link set br1 type bridge fdb_flush
		;;
	esac
	sleep 2
done
SH
chmod +x /usr/local/bin/pathviz-demo-traffic

# IPv6 is left out: every new device announces itself with a burst of it.
start_pathviz --proto arp,ip,other
systemd-run --quiet --unit pv-traffic /usr/local/bin/pathviz-demo-traffic
