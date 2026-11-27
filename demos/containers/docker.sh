# The Docker part of the containers demo. Run as root on a throwaway
# machine with Docker ("make demo-containers" does it on the docker machine).
#
#   shop     A user-defined bridge network (10.40.0.0/24, the bridge br-shop)
#            with the containers web, db, and client. Port 8080 of the
#            machine is published to port 80 of web.
#   bridge   The default network (docker0) with the container pinger.

stop_units pathviz pv-published
docker rm -f web db client pinger >/dev/null 2>&1 || true
docker network rm shop >/dev/null 2>&1 || true

docker network create --subnet 10.40.0.0/24 -o com.docker.network.bridge.name=br-shop shop >/dev/null
docker run -d --name web --network shop --ip 10.40.0.10 -p 8080:80 busybox sh -c 'mkdir /www && echo hello > /www/index.html && httpd -f -p 80 -h /www' >/dev/null
docker run -d --name db --network shop --ip 10.40.0.20 busybox sleep infinity >/dev/null
docker run -d --name client --network shop --ip 10.40.0.30 busybox sh -c '
	while true; do
		wget -q -T 2 -O /dev/null http://10.40.0.10/; sleep 5
		ping -q -c 1 -W 1 10.40.0.20 >/dev/null; sleep 5
		ip neigh flush all 2>/dev/null
	done' >/dev/null
docker run -d --name pinger busybox sh -c 'while true; do ping -q -c 1 -W 1 172.17.0.1 >/dev/null; sleep 9; done' >/dev/null

start_pathviz --proto arp,ip
# A request to the published port of web: Docker's DNAT rule rewrites its
# destination in the nat stage of OUTPUT.
addr=$(hostname -I | cut -d' ' -f1)
systemd-run --quiet --unit pv-published sh -c "while true; do curl -s -m 2 -o /dev/null http://$addr:8080/; sleep 7; done"
