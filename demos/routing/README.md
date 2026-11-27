# Routing demo

What the IP hooks do with a packet: local delivery, forwarding, NAT, and a
drop. It needs two machines, so it comes with a playground:

```sh
make playground DEMO=routing    # on your machine, in the root of the repository
make demo-routing               # on the dev machine of the playground, in ~/pathviz
```

| Machine | Address | Role |
|---|---|---|
| `dev` | 172.16.0.10 | builds PathViz and sends the requests |
| `target` | 172.16.0.20 | runs PathViz (the `pathviz` tab), a web server on port 8080, and one more in the `app` namespace (10.200.0.2:9000) |

Four loops on `dev` fetch a page every three seconds:

| Request | Path on the target | What to notice |
|---|---|---|
| `172.16.0.20:8080` | PREROUTING → INPUT | delivered to `python3` |
| `10.200.0.2:9000` | PREROUTING → FORWARD → POSTROUTING | routed to `veth-app` |
| `172.16.0.20:8081` | PREROUTING → FORWARD → POSTROUTING | the nat stage of PREROUTING rewrites the destination (amber) |
| `172.16.0.20:8082` | PREROUTING → INPUT | stopped in the filter stage of INPUT (red) |

Things to try:

- **IP · L3**, look "Stages" and "Hooks only".
- **Inspect** on a row of port 8081: the bytes of the packet before and after
  the rewrite.
- **Combined**: the device hook of `eth0` in front of the IP hooks.
- Namespace `app`: the same requests as the server sees them.

`make stop-routing` stops the loops on `dev`.
