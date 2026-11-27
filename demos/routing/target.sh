# The target's part of the routing demo. Run it as root, after ../lib.sh (the
# Makefile next to it does that on the target machine).
#
# It starts PathViz and two web servers:
#   - on the target itself, port 8080 (traffic to it crosses PREROUTING and INPUT)
#   - in the "app" network namespace behind the target, 10.200.0.2:9000
#     (traffic to it crosses PREROUTING, FORWARD, and POSTROUTING)
# Two rules of its own make two more cases:
#   - port 8081 of the target is redirected to the server in "app" (DNAT)
#   - port 8082 of the target is dropped in INPUT

ip netns add app 2>/dev/null || true
ip link show veth-app >/dev/null 2>&1 || ip link add veth-app type veth peer name eth0 netns app
ip addr replace 10.200.0.1/24 dev veth-app
ip link set veth-app up
ip -n app addr replace 10.200.0.2/24 dev eth0
ip -n app link set eth0 up
ip -n app link set lo up
ip -n app route replace default via 10.200.0.1
sysctl -qw net.ipv4.ip_forward=1

stop_units pathviz pathviz-web pathviz-web-app
nft -f - <<'NFT'
table ip pathviz-demo
delete table ip pathviz-demo
table ip pathviz-demo {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		tcp dport 8081 dnat to 10.200.0.2:9000
	}
	chain input {
		type filter hook input priority filter;
		tcp dport 8082 drop
	}
}
NFT

mkdir -p /srv/pathviz-demo
echo "Hello from the PathViz demo!" > /srv/pathviz-demo/index.html
systemd-run --quiet --unit pathviz-web python3 -m http.server 8080 --directory /srv/pathviz-demo
systemd-run --quiet --unit pathviz-web-app ip netns exec app python3 -m http.server 9000 --directory /srv/pathviz-demo
# The filter covers all four flows.
start_pathviz --port 8080,8081,8082,9000
