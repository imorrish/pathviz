# The containerd part of the containers demo. Run as root on a throwaway
# machine with containerd and nerdctl ("make demo-containers" does it on the
# containerd machine).
#
#   shop   A CNI bridge network (10.60.0.0/24) with the containers web, db,
#          and client.

IMAGE=docker.io/library/busybox

stop_units pathviz
nerdctl rm -f web db client >/dev/null 2>&1 || true
nerdctl network rm shop >/dev/null 2>&1 || true

nerdctl network create --subnet 10.60.0.0/24 shop >/dev/null 2>&1
nerdctl run -d --name web --network shop --ip 10.60.0.10 "$IMAGE" sh -c 'mkdir /www && echo hello > /www/index.html && httpd -f -p 80 -h /www' >/dev/null 2>&1
nerdctl run -d --name db --network shop --ip 10.60.0.20 "$IMAGE" sleep infinity >/dev/null 2>&1
nerdctl run -d --name client --network shop --ip 10.60.0.30 "$IMAGE" sh -c '
	while true; do
		wget -q -T 2 -O /dev/null http://10.60.0.10/; sleep 5
		ping -q -c 1 -W 1 10.60.0.20 >/dev/null; sleep 5
		ip neigh flush all 2>/dev/null 2>&1
	done' >/dev/null 2>&1

start_pathviz --proto arp,ip
