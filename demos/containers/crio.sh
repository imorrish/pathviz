# The CRI-O part of the containers demo. Run as root on a throwaway
# machine ("make demo-containers" does it on the crio machine, a Kubernetes node
# image that is not a part of any cluster). It installs CRI-O if it is
# missing, and starts three pods with crictl, the way a kubelet would:
#
#   cni0   The bridge of the CNI bridge plugin (10.70.0.0/24) with the pods
#          web, db, and client.

IMAGE=docker.io/library/busybox:latest
WORK=/var/lib/pathviz-demo

stop_units pathviz
# A kubelet without a cluster only restarts in a loop.
systemctl disable --now kubelet >/dev/null 2>&1 || true

if ! command -v crio >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	# The image of the playground keeps the package next to its repository.
	cp -r /opt/iximiuz-labs/apt-cache/* /var/cache/apt/archives/ 2>/dev/null || true
	apt-get install -y cri-o >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; apt-get install -y cri-o >/dev/null; }
fi
mkdir -p /etc/cni/net.d "$WORK"
cat > /etc/cni/net.d/10-pathviz-demo.conflist <<'JSON'
{
  "cniVersion": "1.0.0",
  "name": "shop",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "ipMasq": true,
      "ipam": {
        "type": "host-local",
        "ranges": [[{ "subnet": "10.70.0.0/24" }]],
        "routes": [{ "dst": "0.0.0.0/0" }]
      }
    }
  ]
}
JSON
systemctl enable --now crio >/dev/null 2>&1
cat > /etc/crictl.yaml <<'YAML'
runtime-endpoint: "unix:///var/run/crio/crio.sock"
YAML
n=0
until crictl info >/dev/null 2>&1; do
	n=$((n + 1))
	[ "$n" -lt 30 ] || { echo "CRI-O did not start" >&2; exit 1; }
	sleep 1
done

# The pods of an earlier run.
old=$(crictl pods -q --label demo=pathviz)
[ -z "$old" ] || crictl rmp -f $old >/dev/null
crictl pull "$IMAGE" >/dev/null

# run_pod <name> <shell command of its container>: prints the ID of the pod.
run_pod() {
	cat > "$WORK/$1-pod.json" <<JSON
{
  "metadata": { "name": "$1", "namespace": "default", "uid": "pathviz-demo-$1", "attempt": 0 },
  "labels": { "demo": "pathviz" },
  "log_directory": "$WORK/logs-$1",
  "linux": {}
}
JSON
	cat > "$WORK/$1-container.json" <<JSON
{
  "metadata": { "name": "app" },
  "image": { "image": "$IMAGE" },
  "command": ["sh", "-c", "$2"],
  "log_path": "app.log",
  "linux": {}
}
JSON
	pod=$(crictl runp "$WORK/$1-pod.json" 2>/dev/null)
	ctr=$(crictl create "$pod" "$WORK/$1-container.json" "$WORK/$1-pod.json" 2>/dev/null)
	crictl start "$ctr" >/dev/null
	echo "$pod"
}
pod_ip() {
	crictl inspectp --output go-template --template '{{.status.network.ip}}' "$1"
}

web=$(run_pod web 'mkdir /www && echo hello > /www/index.html && httpd -f -p 80 -h /www')
db=$(run_pod db 'sleep infinity')
web_ip=$(pod_ip "$web")
db_ip=$(pod_ip "$db")
run_pod client "while true; do wget -q -T 2 -O /dev/null http://$web_ip/; sleep 5; ping -q -c 1 -W 1 $db_ip >/dev/null; sleep 5; ip neigh flush all 2>/dev/null; done" >/dev/null

start_pathviz --proto arp,ip
