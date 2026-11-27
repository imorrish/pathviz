# Local demo

The smallest demo: everything runs on one Linux machine, over the loopback
interface. It needs root, `python3`, `curl`, and `nft`.

```sh
make demo-local     # in the root of the repository
make stop-local
```

It starts a web server on port 8080, a client that fetches a page from it every
two seconds, and PathViz with `--port 8080`. The command prints the address of
the web UI.

What to look at:

- **IP · L3**: every packet crosses OUTPUT and POSTROUTING on its way out, comes
  back in over the loopback line, and crosses PREROUTING and INPUT. The process
  that sent it and the one that got it light up.
- **Device · L1**: the same packet at the ingress hook of `lo`.
- **Combined**: both in one picture.

To open the UI from another machine (for example in a tab of a playground),
serve it on all addresses. Without the token, anyone who can reach the port can
see the traffic, so do it only on a machine that nobody else can reach:

```sh
make demo-local LISTEN=0.0.0.0:7070 PATHVIZ_FLAGS=--dangerously-skip-token
```

`playground.yaml` is a one-machine playground for it:
`make playground DEMO=local`.
