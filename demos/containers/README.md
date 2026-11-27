# Containers demo

The bridge networks of four container runtimes, with the names of the
containers and the pods on the ports. Every runtime has a machine of its own,
so the demo comes with a five-machine playground:

```sh
make playground DEMO=containers    # on your machine, in the root of the repository
make demo-containers               # on the dev machine of the playground, in ~/pathviz
```

Every machine but `dev` then runs PathViz with `--proto arp,ip` on port 7070,
and the playground has a tab for each.

| Machine | Runtime | Network | Workloads |
|---|---|---|---|
| `docker` | Docker | `br-shop` (10.40.0.0/24) and `docker0` | containers `web`, `db`, `client`, and `pinger` |
| `podman` | Podman | `br-shop` (10.50.0.0/24) | containers `web` and `client`, and the pod `cart` |
| `containerd` | containerd with nerdctl | a CNI bridge (10.60.0.0/24) | containers `web`, `db`, and `client` |
| `crio` | CRI-O, driven with `crictl` | `cni0` (10.70.0.0/24) | pods `web`, `db`, and `client` |

Things to try:

- **Bridge · L2**: the ports are named after the containers and pods behind
  them. The names come from the runtime, so nothing has to be configured.
- **Namespace** list: pick a container to see its side of the same traffic
  (the IP hooks of the container, its `eth0`).
- **Combined** on the host: a request from one container to another crosses the
  port, the bridge, and, with `br_netfilter`, the IP hooks.
- On `docker`: a request to a published port, with the DNAT in PREROUTING.

To run only some of the machines:

```sh
make demo-containers HOSTS="docker podman"
```

The `crio` machine is a Kubernetes node image that is not a part of a cluster.
The demo installs CRI-O on it at the first run and stops the idle kubelet.
