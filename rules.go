package main

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PathViz keeps its probes in tables of this name, one per nftables family.
const tableName = "pathviz"

// The layers PathViz can watch, and the nftables family of each.
const (
	L1 = "l1" // the ingress and egress hooks of a device (netdev)
	L2 = "l2" // the hooks of a bridge (bridge)
	L3 = "l3" // the hooks of the IP layer (inet)
)

var layerFamily = map[string]string{L1: "netdev", L2: "bridge", L3: "inet"}

// allLayers lists the layers from the wire up.
var allLayers = []string{L1, L2, L3}

const (
	// enterStage is the probe at the start of a link or a bridge hook.
	enterStage = "enter"
	// exitStage is the probe at the end of a hook. A packet that reaches it
	// has survived the whole hook.
	exitStage = "exit"
	// exitPriority is higher than every classic iptables/nftables priority
	// (srcnat is 100, SELinux last is 225, conntrack helpers are 300).
	exitPriority = 500
	// The probes of a bridge hook sit around the classic priorities of
	// ebtables and nftables (dstnat is -300, filter is -200, srcnat is 300).
	bridgeEnterPriority = -350
	bridgeExitPriority  = 350
	// The probes of a device hook sit around everything a user would put there.
	linkEnterPriority = -500
	linkExitPriority  = 500
)

// rememberFor is how long the kernel remembers a matched packet. A packet crosses
// all hooks within microseconds, and a short time keeps look-alikes out.
const rememberFor = "500ms"

// tcpFlagsByte is the byte with the TCP flags (offset 13 of the TCP header),
// taken as a raw payload. It is the same field as "tcp flags", but a set keyed
// on "tcp flags" makes "nft list" abort when it prints the elements
// (nftables 1.0.9: Assertion `ilen > 0' failed in concat_expr_msort_value).
const tcpFlagsByte = "@th,104,8"

// packetKeys are the NAT-invariant identities of a packet, one set per protocol.
// The guard is needed where the key alone does not pin the packet kind down.
var packetKeys = []struct{ set, guard, key string }{
	{"tcp4", "", "ip id . tcp sequence . tcp ackseq . " + tcpFlagsByte},
	// A UDP payload shorter than 8 bytes cannot be loaded by the first key.
	{"udp4", "udp length >= 16 ", "ip id . udp length . @th,64,64"},
	{"udp4short", "udp length < 16 ", "ip id . udp length"},
	{"icmp4", "", "ip id . icmp type . icmp sequence"},
	{"tcp6", "", "ip6 flowlabel . tcp sequence . tcp ackseq . " + tcpFlagsByte},
	{"udp6", "udp length >= 16 ", "ip6 flowlabel . udp length . @th,64,64"},
	{"udp6short", "udp length < 16 ", "ip6 flowlabel . udp length"},
	{"icmp6", "", "ip6 flowlabel . icmpv6 type . icmpv6 sequence"},
}

// Stage is one classic table position inside a hook (e.g. "mangle" in PREROUTING).
type Stage struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

// Hook is one netfilter hook with its stages in traversal order.
type Hook struct {
	Name   string  `json:"name"`
	Stages []Stage `json:"stages"`
}

// Hooks lists the IP hooks and the stages iptables users know, in traversal
// order. The priorities are the ones the kernel uses for the iptables tables.
var Hooks = []Hook{
	{"PREROUTING", []Stage{{"raw", -300}, {"mangle", -150}, {"nat", -100}}},
	{"INPUT", []Stage{{"mangle", -150}, {"filter", 0}, {"nat", 100}}},
	{"FORWARD", []Stage{{"mangle", -150}, {"filter", 0}}},
	{"OUTPUT", []Stage{{"raw", -300}, {"mangle", -150}, {"nat", -100}, {"filter", 0}}},
	{"POSTROUTING", []Stage{{"mangle", -150}, {"nat", 100}}},
}

// bridgeHooks are the hooks of the bridge family, in the order a frame may
// cross them.
var bridgeHooks = []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}

// RuleOptions is what the probes depend on besides the filter.
type RuleOptions struct {
	Group int
	// SkipPorts are the TCP ports that are never traced: the web UI's own.
	SkipPorts []int
	// Layers are the layers to probe.
	Layers []string
	// Devices are the devices of the namespace. The link probes are bound to them.
	Devices []string
	// Egress tells that the kernel has the egress hook (Linux 5.16 and later,
	// with CONFIG_NETFILTER_EGRESS).
	Egress bool
}

func (o RuleOptions) has(layer string) bool {
	for _, l := range o.Layers {
		if l == layer {
			return true
		}
	}
	return false
}

// Rules are the nft scripts of the probes, one per layer. Each script replaces
// its table in a single transaction. An empty script means that the layer has
// no table.
type Rules map[string]string

// Text is what the help dialog and "pathviz rules" show: all scripts, from
// the wire up.
func (r Rules) Text() string {
	var parts []string
	for _, layer := range allLayers {
		if r[layer] != "" {
			parts = append(parts, r[layer])
		}
	}
	return strings.Join(parts, "\n")
}

// BuildRules renders the probes for a filter.
//
// Every probe is a base chain that never issues a verdict of its own: it logs
// the selected packets to the NFLOG group and lets them go on. The comments
// in the scripts are for the reader of the help dialog. [static] marks what is
// the same for every filter, and [filter] marks what comes from the filter.
func BuildRules(f Filter, o RuleOptions) Rules {
	r := Rules{}
	if o.has(L1) && len(o.Devices) > 0 {
		r[L1] = linkRules(f, o)
	}
	if o.has(L2) {
		r[L2] = bridgeRules(f, o)
	}
	if o.has(L3) {
		r[L3] = ipRules(f, o)
	}
	return r
}

func tableHead(b *bytes.Buffer, family string) {
	b.WriteString("# [static] Replace the table in one transaction: make sure it exists,\n")
	b.WriteString("#          delete it, and define it anew.\n")
	fmt.Fprintf(b, "table %s %s\n", family, tableName)
	fmt.Fprintf(b, "delete table %s %s\n\n", family, tableName)
	fmt.Fprintf(b, "table %s %s {\n", family, tableName)
}

func skipUI(b *bytes.Buffer, ports []int) {
	if len(ports) > 0 {
		b.WriteString("\t\t# [static] Never trace the web UI's own traffic.\n")
	}
	for _, p := range ports {
		// Every traced packet makes more UI traffic, so tracing it would never end.
		fmt.Fprintf(b, "\t\ttcp sport %d accept\n", p)
		fmt.Fprintf(b, "\t\ttcp dport %d accept\n", p)
	}
}

// frameSelect writes the chain that decides for the probes of frames whether
// to log one: a return goes back to the probe, and an accept ends it.
func frameSelect(b *bytes.Buffer, name string, matches []string, skipPorts []int) {
	fmt.Fprintf(b, "\tchain %s {\n", name)
	skipUI(b, skipPorts)
	switch {
	case len(matches) == 0:
		b.WriteString("\t\t# [filter] The filter selects nothing that this hook can see.\n")
	case matches[0] == "":
		b.WriteString("\t\t# [filter] No filter is set, so every frame is logged.\n")
		b.WriteString("\t\treturn\n")
	default:
		b.WriteString("\t\t# [filter] The frames that match the filter are logged.\n")
		for _, m := range matches {
			fmt.Fprintf(b, "\t\t%s return\n", m)
		}
	}
	b.WriteString("\t\t# [static] Every other frame passes without a record.\n")
	b.WriteString("\t\taccept\n\t}\n\n")
}

func probeChain(b *bytes.Buffer, name, hook, device string, prio int, selectChain string, group int, prefix string) {
	fmt.Fprintf(b, "\tchain %s {\n", name)
	fmt.Fprintf(b, "\t\ttype filter hook %s %spriority %d; policy accept;\n", hook, device, prio)
	fmt.Fprintf(b, "\t\tjump %s\n", selectChain)
	fmt.Fprintf(b, "\t\tlog group %d prefix \"%s\"\n", group, prefix)
	b.WriteString("\t}\n")
}

// linkRules renders the probes of the devices: one at the start and one at
// the end of the ingress hook of every device, and the same for egress.
func linkRules(f Filter, o RuleOptions) string {
	var b bytes.Buffer
	tableHead(&b, "netdev")
	b.WriteString("\t# [static] Decide for a probe whether to log a frame: a return goes back to the\n")
	b.WriteString("\t#          probe, which logs it, and an accept ends the probe without a record.\n")
	frameSelect(&b, "select_ingress", f.frameMatches(false, "iifname"), o.SkipPorts)
	if o.Egress {
		frameSelect(&b, "select_egress", f.frameMatches(false, "oifname"), o.SkipPorts)
	}
	devices := append([]string(nil), o.Devices...)
	sort.Strings(devices)
	bound := "devices = " + nftSet(quoted(devices)) + " "
	fmt.Fprintf(&b, "\t# [static] The probes. They are bound to the devices of the namespace: a frame\n")
	fmt.Fprintf(&b, "\t#          crosses the ingress hook of a device right after the device received it,\n")
	fmt.Fprintf(&b, "\t#          and the egress hook right before the device sends it.\n")
	probeChain(&b, "ingress_enter", "ingress", bound, linkEnterPriority, "select_ingress", o.Group, L1+":"+enterStage+"/INGRESS")
	probeChain(&b, "ingress_exit", "ingress", bound, linkExitPriority, "select_ingress", o.Group, L1+":"+exitStage+"/INGRESS")
	if o.Egress {
		probeChain(&b, "egress_enter", "egress", bound, linkEnterPriority, "select_egress", o.Group, L1+":"+enterStage+"/EGRESS")
		probeChain(&b, "egress_exit", "egress", bound, linkExitPriority, "select_egress", o.Group, L1+":"+exitStage+"/EGRESS")
	}
	b.WriteString("}\n")
	return b.String()
}

// bridgeRules renders the probes of the bridges: one at the start and one at
// the end of every hook of the bridge family.
func bridgeRules(f Filter, o RuleOptions) string {
	var b bytes.Buffer
	tableHead(&b, "bridge")
	b.WriteString("\t# [static] Decide for a probe whether to log a frame: a return goes back to the\n")
	b.WriteString("\t#          probe, which logs it, and an accept ends the probe without a record.\n")
	frameSelect(&b, "select", f.frameMatches(true, ""), o.SkipPorts)
	fmt.Fprintf(&b, "\t# [static] The probes. Every hook has one before the rules of the firewall\n")
	fmt.Fprintf(&b, "\t#          (priority %d) and one after them (priority %d). A frame that the\n", bridgeEnterPriority, bridgeExitPriority)
	b.WriteString("\t#          first one saw and the second one did not was dropped in the hook.\n")
	for _, hook := range bridgeHooks {
		low := strings.ToLower(hook)
		probeChain(&b, low+"_enter", low, "", bridgeEnterPriority, "select", o.Group, L2+":"+enterStage+"/"+hook)
		probeChain(&b, low+"_exit", low, "", bridgeExitPriority, "select", o.Group, L2+":"+exitStage+"/"+hook)
	}
	b.WriteString("}\n")
	return b.String()
}

// ipRules renders the probes of the IP hooks: one right before every classic
// stage of a hook (its priority minus 1), and one at the end of the hook.
//
// The first probe that matches a packet remembers the packet's identity in a
// set for a moment, and every later probe also logs the remembered packets.
// The identity is made of header fields that NAT does not rewrite, so a packet
// stays in view after DNAT or SNAT changes the addresses or ports the filter
// looks at. Nothing in the packet itself is touched.
func ipRules(f Filter, o RuleOptions) string {
	var b bytes.Buffer
	tableHead(&b, "inet")

	fmt.Fprintf(&b, "\t# [static] Sets that hold the identity of a traced packet for %s. One set\n", rememberFor)
	b.WriteString("\t#          per kind of packet, keyed on fields that NAT does not rewrite.\n")
	for _, s := range packetKeys {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttypeof %s\n\t\tflags dynamic,timeout\n\t\ttimeout %s\n\t}\n\n", s.set, s.key, rememberFor)
	}

	// "remember" is entered with goto, so its end returns to the probe chain.
	b.WriteString("\t# [static] Stores the identity of a packet that matched the filter. Its end\n")
	b.WriteString("\t#          returns to the probe chain, which logs the packet.\n")
	b.WriteString("\tchain remember {\n")
	for _, s := range packetKeys {
		fmt.Fprintf(&b, "\t\t%supdate @%s { %s }\n", s.guard, s.set, s.key)
	}
	b.WriteString("\t}\n\n")

	// "select" returns to the probe chain for the packets to trace and accepts
	// (ends the probe chain for) everything else.
	selectChain := func(name string, matches, candidates []string) {
		if candidates == nil {
			b.WriteString("\t# [static] Decides for a probe whether to log a packet: a return goes back to the\n")
			b.WriteString("\t#          probe, which logs it, and an accept ends the probe without a record.\n")
			b.WriteString("\t#          Only the rules marked [filter] in it depend on the filter.\n")
		} else {
			b.WriteString("\t# [filter] The select chain of the PREROUTING probes. It exists because the\n")
			b.WriteString("\t#          filter names an output interface, which is not known in PREROUTING yet.\n")
		}
		fmt.Fprintf(&b, "\tchain %s {\n", name)
		skipUI(&b, o.SkipPorts)
		switch {
		case len(matches) == 0:
			b.WriteString("\t\t# [filter] The filter selects no IP packet.\n")
		case matches[0] == "":
			b.WriteString("\t\t# [filter] No filter is set, so every packet is remembered and logged.\n")
		default:
			b.WriteString("\t\t# [filter] The packets that match the filter are remembered and logged.\n")
		}
		for _, m := range matches {
			if m != "" {
				m += " "
			}
			fmt.Fprintf(&b, "\t\t%sgoto remember\n", m)
		}
		if len(matches) > 0 {
			b.WriteString("\t\t# [static] A packet that an earlier probe remembered is logged too, even\n")
			b.WriteString("\t\t#          if NAT rewrote the fields the filter looks at.\n")
			for _, s := range packetKeys {
				fmt.Fprintf(&b, "\t\t%s%s @%s return\n", s.guard, s.key, s.set)
			}
		}
		if len(candidates) > 0 {
			b.WriteString("\t\t# [filter] Log every packet that matches the rest of the filter. PathViz\n")
			b.WriteString("\t\t#          keeps it only if it leaves through the right interface later.\n")
		}
		for _, m := range candidates {
			if m != "" {
				m += " "
			}
			fmt.Fprintf(&b, "\t\t%sreturn\n", m)
		}
		b.WriteString("\t\t# [static] Every other packet passes without a record.\n")
		b.WriteString("\t\taccept\n\t}\n\n")
	}
	matches := f.ipMatches()
	selectChain("select", matches, nil)
	// The output device is unknown in PREROUTING. When the filter asks for one,
	// the PREROUTING probes log every packet that satisfies the rest of the
	// filter, and pathviz keeps the packet only if it leaves through the right
	// device later (see Filter.Keeps).
	early := f.needsCandidates() && len(matches) > 0
	if early {
		rest := f
		rest.Ifaces = nil
		selectChain("select_early", matches, rest.ipMatches())
	}

	fmt.Fprintf(&b, "\t# [static] The probes. Every hook has one right before each of its stages\n")
	fmt.Fprintf(&b, "\t#          (the stage's priority minus 1) and one at its end (priority %d). A probe\n", exitPriority)
	fmt.Fprintf(&b, "\t#          asks the select chain and logs the chosen packets to NFLOG group %d.\n", o.Group)
	for i, h := range Hooks {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "\t# [static] The probes of %s.", h.Name)
		sel := "select"
		if early && h.Name == "PREROUTING" {
			b.WriteString(" [filter] They ask select_early.")
			sel = "select_early"
		}
		b.WriteString("\n")
		low := strings.ToLower(h.Name)
		for _, s := range h.Stages {
			probeChain(&b, low+"_"+s.Name, low, "", s.Priority-1, sel, o.Group, L3+":"+s.Name+"/"+h.Name)
		}
		probeChain(&b, low+"_"+exitStage, low, "", exitPriority, sel, o.Group, L3+":"+exitStage+"/"+h.Name)
	}
	b.WriteString("}\n")
	return b.String()
}

// nft runs the nft command in a network namespace.
func nft(ns Netns, stdin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := ns.command(ctx, "nft", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// InstallProbes loads a script of rules into a namespace. It replaces the
// tables of PathViz that are there.
func InstallProbes(ns Netns, script string) error {
	return explainNft(nft(ns, script, "-f", "-"))
}

// explainNft adds what to do to the error of a kernel that cannot log to an
// NFLOG group: its "log group" rules fail with "No such file or directory".
func explainNft(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if !strings.Contains(msg, "log group") || !strings.Contains(msg, "No such file or directory") {
		return err
	}
	return fmt.Errorf("%w\n\nThe kernel rejected the NFLOG rules (\"log group ...\"). PathViz needs them to trace packets.\n\nTry:\n  sudo modprobe nft_log\n  sudo modprobe nfnetlink_log\n\nIf the modules are not available (common on some WSL kernels), run PathViz on a Linux machine or VM that has them", err)
}

// removeScript deletes the table of a family. A missing table is not an error.
func removeScript(family string) string {
	return fmt.Sprintf("table %s %s\ndelete table %s %s\n", family, tableName, family, tableName)
}

// RemoveProbes deletes all the tables of PathViz from a namespace.
func RemoveProbes(ns Netns) error {
	var script strings.Builder
	for _, layer := range allLayers {
		script.WriteString(removeScript(layerFamily[layer]))
	}
	return nft(ns, script.String(), "-f", "-")
}
