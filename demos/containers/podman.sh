# The Podman part of the containers demo. Run as root on a throwaway
# machine with Podman ("make demo-containers" does it on the podman machine).
#
#   shop   A bridge network (10.50.0.0/24, the bridge br-shop) with the
#          containers web and client, and the pod cart (two containers in one
#          network namespace).

IMAGE=docker.io/library/busybox

stop_units pathviz
podman rm -f web client cart-app cart-ping >/dev/null 2>&1 || true
podman pod rm -f cart >/dev/null 2>&1 || true
podman network rm -f shop >/dev/null 2>&1 || true

podman network create --subnet 10.50.0.0/24 --interface-name br-shop shop >/dev/null
podman run -d --name web --network shop --ip 10.50.0.10 "$IMAGE" sh -c 'mkdir /www && echo hello > /www/index.html && httpd -f -p 80 -h /www' >/dev/null
podman run -d --name client --network shop --ip 10.50.0.30 "$IMAGE" sh -c '
	while true; do
		wget -q -T 2 -O /dev/null http://10.50.0.10/; sleep 5
		ping -q -c 1 -W 1 10.50.0.40 >/dev/null; sleep 5
		ip neigh flush all 2>/dev/null
	done' >/dev/null
podman pod create --name cart --network shop --ip 10.50.0.40 >/dev/null
podman run -d --pod cart --name cart-app "$IMAGE" sleep infinity >/dev/null
podman run -d --pod cart --name cart-ping "$IMAGE" sh -c 'while true; do ping -q -c 1 -W 1 10.50.0.1 >/dev/null; sleep 9; done' >/dev/null

start_pathviz --proto arp,ip
