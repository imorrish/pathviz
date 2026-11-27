// Command pathviz shows the path of a packet through the Linux network stack.
//
// It installs nftables tables of its own with probe chains at the hooks a
// packet crosses: the ingress and egress hooks of the devices (L1), the hooks
// of the bridges (L2), and the IP hooks with their classic iptables stages
// (L3). The probes log the selected traffic to an NFLOG group, pathviz groups
// the log events by packet, and a web page draws the path of every packet.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// version is set by the release build (see .goreleaser.yaml).
var version = "dev"

const usage = `pathviz - see the path of a packet through the Linux network stack

Usage:
  pathviz [run] [flags]      Install the probes and serve the web UI (needs root)
  pathviz rules [flags]      Print the nftables probe rules and exit
  pathviz cleanup            Remove the probes left behind by a killed pathviz
  pathviz version            Print the version and exit

What to trace ("run" and "rules"). The page can change it later:
  --proto <name>[,...]       Protocols: arp, ip, ip6, tcp, udp, icmp, other
                             (default: all of them)
  --ip <addr|cidr>[,...]     Packets from or to these addresses
  --mac <addr>[,...]         Frames from or to these MAC addresses
  --iface <name>[,...]       Packets that enter or leave through these devices
                             (in:<name> only entering, out:<name> only leaving).
                             The name of a bridge selects all that crosses it
  --port <port>[,...]        TCP and UDP packets from or to these ports

Where to trace:
  --netns <name>             The network namespace to show first: a name of
                             "ip netns", the name of a container or a pod, or
                             pid:<n> for the namespace of a process (default:
                             the namespace pathviz runs in). The page can
                             switch to any other namespace of the machine
  --layers <l1,l2,l3>        The layers to probe: l1 is the devices, l2 the
                             bridges, l3 the IP hooks (default: all three)

Other flags:
  --listen <addr>            Address of the web UI (default 127.0.0.1:7070)
  --group <n>                NFLOG group to use (default 77)
  --token-file <path>        Take the access token of the web UI from this file
                             (or from PATHVIZ_TOKEN) instead of a new random one.
                             At least 16 characters, in a file only you can read
  --no-packet-view           Do not keep or show the contents of the packets
  --dangerously-skip-token   Serve the web UI without the access token: everyone
                             who can reach it can read the traced packets and
                             change the filter

"run" prints the address of the web UI with the access token in it.

Examples:
  sudo pathviz
  sudo pathviz --proto tcp --port 8080
  sudo pathviz --ip 172.16.0.10 --proto icmp
  sudo pathviz --iface docker0 --proto arp,ip
  sudo pathviz --netns web
`

func main() {
	log.SetFlags(log.Ltime)
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = cmdRun(args, false)
	case "rules":
		err = cmdRun(args, true)
	case "cleanup":
		err = cmdCleanup()
	case "version":
		fmt.Println(version)
	case "help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q, see pathviz --help", cmd)
	}
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "pathviz:", err)
		os.Exit(1)
	}
}

// cmdCleanup removes the probes from every network namespace of the machine.
func cmdCleanup() error {
	var firstErr error
	for _, ns := range discoverNetns() {
		if err := RemoveProbes(ns); err != nil && ns.Home && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	return fs
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, p)
	}
	return out
}

// parseLayers validates the --layers flag and puts the layers in order.
func parseLayers(s string) ([]string, error) {
	want := map[string]bool{}
	for _, l := range splitList(strings.ToLower(s)) {
		if _, ok := layerFamily[l]; !ok {
			return nil, fmt.Errorf("unknown layer %q (use l1, l2, or l3)", l)
		}
		want[l] = true
	}
	var out []string
	for _, l := range allLayers {
		if want[l] {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no layer to probe")
	}
	return out, nil
}

func cmdRun(args []string, rulesOnly bool) error {
	fs := newFlagSet("run")
	protos := fs.String("proto", "", "")
	ips := fs.String("ip", "", "")
	macs := fs.String("mac", "", "")
	ports := fs.String("port", "", "")
	ifaces := fs.String("iface", "", "")
	netns := fs.String("netns", "", "")
	layerList := fs.String("layers", "l1,l2,l3", "")
	listen := fs.String("listen", "127.0.0.1:7070", "")
	group := fs.Int("group", 77, "")
	noPacketView := fs.Bool("no-packet-view", false, "")
	tokenFile := fs.String("token-file", "", "")
	skipToken := fs.Bool("dangerously-skip-token", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *group < 1 || *group > 65535 {
		return fmt.Errorf("bad NFLOG group %d", *group)
	}
	layers, err := parseLayers(*layerList)
	if err != nil {
		return err
	}

	f := Filter{Protos: splitList(*protos), IPs: splitList(*ips), MACs: splitList(*macs), Ifaces: splitList(*ifaces)}
	for _, p := range splitList(*ports) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("bad port %q", p)
		}
		f.Ports = append(f.Ports, n)
	}
	if err := f.Normalize(); err != nil {
		return err
	}

	_, uiPortStr, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("bad --listen address: %v", err)
	}
	uiPort, err := strconv.Atoi(uiPortStr)
	if err != nil || uiPort < 1 || uiPort > 65535 {
		return fmt.Errorf("bad --listen port %q", uiPortStr)
	}
	opts := Options{Group: *group, PacketView: !*noPacketView, SkipPorts: []int{uiPort}, Layers: layers}

	if rulesOnly {
		// The rules are printed for the devices of this namespace, as for a
		// kernel that has the egress hook.
		ro := RuleOptions{Group: opts.Group, SkipPorts: opts.SkipPorts, Layers: layers, Egress: true}
		ifs, _ := net.Interfaces()
		for _, ifc := range ifs {
			ro.Devices = append(ro.Devices, ifc.Name)
		}
		fmt.Print(BuildRules(f, ro).Text())
		return nil
	}
	fileToken := ""
	if *tokenFile != "" {
		if fileToken, err = readTokenFile(*tokenFile); err != nil {
			return err
		}
	}
	token, ownToken, err := pickToken(fileToken, os.Getenv("PATHVIZ_TOKEN"), *skipToken)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("installing the probes needs root, run it with sudo")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	inv := NewInventory()
	if err := inv.Refresh(); err != nil {
		return err
	}
	home, _ := inv.Find("")
	if opts.has(L1) {
		opts.Egress = egressSupported(home)
		if !opts.Egress {
			log.Printf("this kernel has no egress hook for devices (it needs Linux 5.16 or later with CONFIG_NETFILTER_EGRESS), so only their ingress hook is probed")
		}
	}
	hub := NewHub(ctx, opts, inv, f)
	hub.Tick()
	// The observers are closed with the probes removed, whatever ends the run.
	defer func() {
		stop()
		hub.Close()
		log.Printf("probes removed")
	}()
	first, err := hub.Observe(*netns, true)
	if err != nil {
		return err
	}
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				hub.Tick()
			}
		}
	}()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	server := &Server{token: token, hub: hub, opts: opts, netns: first.id}
	srv := &http.Server{Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Printf("probes installed in the namespace %s (nft list tables | grep %s)", first.id, tableName)
	switch {
	case ownToken:
		// A token that outlives this run is kept out of the log.
		log.Printf("web UI on http://%s/?token=<your token>", ln.Addr())
	case token != "":
		log.Printf("web UI on http://%s/?token=%s", ln.Addr(), token)
	default:
		log.Printf("web UI on http://%s", ln.Addr())
		log.Printf("WARNING: the access token is off (--dangerously-skip-token). Everyone who can reach %s can read the traced packets and change the filter.", *listen)
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// minTokenLen is the shortest access token pathviz accepts from the user.
const minTokenLen = 16

// readTokenFile reads an access token from a file. The token is not a flag of
// its own, because the other users of the machine can see the command line of
// a running program. For the same reason the file must be private.
func readTokenFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot read the token file: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("the token file %s is open to other users (mode %04o): run chmod 600 on it", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read the token file: %v", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("the token file %s is empty", path)
	}
	return token, nil
}

// pickToken returns the access token of the web UI: the one of the token file,
// else the one of the PATHVIZ_TOKEN variable, else a new random one.
// The token is empty when the check is off. own tells that the user chose it.
func pickToken(fileValue, envValue string, skip bool) (token string, own bool, err error) {
	token = fileValue
	if token == "" {
		token = envValue
	}
	switch {
	case skip && token != "":
		return "", false, errors.New("--dangerously-skip-token turns the access token off, so it cannot be combined with --token-file or PATHVIZ_TOKEN")
	case skip:
		return "", false, nil
	case token == "":
		token, err = newToken()
		if err != nil {
			return "", false, fmt.Errorf("cannot make the access token: %v", err)
		}
		return token, false, nil
	case len(token) < minTokenLen:
		return "", false, fmt.Errorf("the access token is too short: it needs at least %d characters", minTokenLen)
	}
	for _, c := range token {
		if c <= ' ' || c > '~' {
			return "", false, errors.New("the access token can hold only visible ASCII characters, without spaces")
		}
	}
	return token, true, nil
}

// newToken returns a random access token for the web UI.
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
