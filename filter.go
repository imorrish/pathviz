package main

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// ifaceName is what a Linux interface name may look like (at most 15 characters).
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)

// The protocols a filter can name. The first three are kinds of frames, the
// next three are what an IP packet carries, and "other" is every frame that is
// neither ARP nor IP.
var knownProtos = map[string]bool{"arp": true, "ip": true, "ip6": true, "tcp": true, "udp": true, "icmp": true, "other": true}

// Filter selects the traffic to trace, on all layers. Every field matches in
// either direction: an address matches the source or the destination, an
// interface matches the input or the output device.
type Filter struct {
	// Protos are the protocols to trace: arp, ip, ip6, tcp, udp, icmp, other.
	// A frame or a packet is traced when it is one of them. Empty means all.
	Protos []string `json:"protos"`
	// Ifaces are device names. A bare name matches the input or the output
	// device, "in:eth0" only the input device, and "out:eth0" only the output
	// device. The name of a bridge selects all that crosses the bridge.
	// Mind that the IP hooks do not know the input device in OUTPUT, nor the
	// output device in PREROUTING and INPUT.
	Ifaces []string `json:"ifaces"`
	// MACs are Ethernet addresses. The IP hooks cannot match them, so a packet
	// is kept only if a link or a bridge hook saw it with one of them.
	MACs  []string `json:"macs"`
	IPs   []string `json:"ips"` // addresses or CIDR prefixes
	Ports []int    `json:"ports"`
}

// splitIface splits a filter entry such as "in:eth0" into the direction
// ("in", "out", or "" for both) and the device name.
func splitIface(entry string) (dir, name string) {
	for _, d := range []string{"in", "out"} {
		if rest, ok := strings.CutPrefix(entry, d+":"); ok {
			return d, rest
		}
	}
	return "", entry
}

// cleanList trims, validates, and deduplicates the items of a list.
func cleanList(items []string, canon func(string) (string, error)) ([]string, error) {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, raw := range items {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		v, err := canon(raw)
		if err != nil {
			return nil, err
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

// Normalize validates the filter and brings it to a canonical form.
// Only validated values ever reach the nft script.
func (f *Filter) Normalize() error {
	var err error
	if f.Protos, err = cleanList(f.Protos, func(s string) (string, error) {
		s = strings.ToLower(s)
		switch s {
		case "ipv4":
			s = "ip"
		case "ipv6":
			s = "ip6"
		case "icmpv6":
			s = "icmp"
		}
		if !knownProtos[s] && s != "any" {
			return "", fmt.Errorf("unknown protocol %q (use arp, ip, ip6, tcp, udp, icmp, or other)", s)
		}
		return s, nil
	}); err != nil {
		return err
	}
	for _, p := range f.Protos {
		if p == "any" {
			f.Protos = []string{}
		}
	}
	sort.Strings(f.Protos)

	if f.Ifaces, err = cleanList(f.Ifaces, func(s string) (string, error) {
		if _, name := splitIface(s); !ifaceName.MatchString(name) {
			return "", fmt.Errorf("bad interface %q (use eth0, in:eth0, or out:eth0)", s)
		}
		return s, nil
	}); err != nil {
		return err
	}
	sort.Strings(f.Ifaces)

	if f.MACs, err = cleanList(f.MACs, func(s string) (string, error) {
		mac, err := net.ParseMAC(s)
		if err != nil || len(mac) != 6 {
			return "", fmt.Errorf("bad MAC address %q", s)
		}
		return mac.String(), nil
	}); err != nil {
		return err
	}
	sort.Strings(f.MACs)

	if f.IPs, err = cleanList(f.IPs, func(s string) (string, error) {
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return "", fmt.Errorf("bad prefix %q", s)
			}
			return p.Masked().String(), nil
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf("bad IP address %q", s)
		}
		return a.Unmap().String(), nil
	}); err != nil {
		return err
	}

	ports := make([]int, 0, len(f.Ports))
	seenPort := map[int]bool{}
	for _, p := range f.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("bad port %d", p)
		}
		if !seenPort[p] {
			seenPort[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	f.Ports = ports
	if len(f.Ports) > 0 && len(f.Protos) > 0 && !f.wants("tcp") && !f.wants("udp") {
		return fmt.Errorf("only TCP and UDP have ports")
	}
	return nil
}

// wants tells whether the filter names the protocol.
func (f Filter) wants(proto string) bool {
	for _, p := range f.Protos {
		if p == proto {
			return true
		}
	}
	return false
}

// needsCandidates tells whether the filter names an output device.
func (f Filter) needsCandidates() bool {
	for _, entry := range f.Ifaces {
		if dir, _ := splitIface(entry); dir != "in" {
			return true
		}
	}
	return false
}

// Keeps tells whether a finished journey satisfies the parts of the filter
// that the probes cannot check alone. The IP probes of PREROUTING log packets
// whose output device is not known yet, and the IP probes cannot see MAC
// addresses at all.
func (f Filter) Keeps(j *Journey) bool {
	if f.needsCandidates() {
		ok := false
		for _, entry := range f.Ifaces {
			dir, name := splitIface(entry)
			for _, h := range j.Hops {
				if (dir != "out" && (h.In == name || h.PhysIn == name)) || (dir != "in" && (h.Out == name || h.PhysOut == name)) || h.Bridge == name {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	if len(f.MACs) > 0 {
		ok := false
		for _, h := range j.Hops {
			for _, mac := range f.MACs {
				ok = ok || (h.SMAC != "" && (h.SMAC == mac || h.DMAC == mac))
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func nftSet(items []string) string { return "{ " + strings.Join(items, ", ") + " }" }

func quoted(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = `"` + s + `"`
	}
	return out
}

// product joins one alternative of every group into a match expression, for
// every combination. An empty alternative adds nothing.
func product(groups ...[]string) []string {
	out := []string{""}
	for _, alts := range groups {
		if len(alts) == 0 {
			continue
		}
		var next []string
		for _, head := range out {
			for _, alt := range alts {
				next = append(next, strings.TrimSpace(head+" "+alt))
			}
		}
		out = next
	}
	return out
}

func (f Filter) splitIPs() (v4, v6 []string) {
	for _, ip := range f.IPs {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	return v4, v6
}

func (f Filter) portAlts() []string {
	if len(f.Ports) == 0 {
		return nil
	}
	ps := make([]string, len(f.Ports))
	for i, p := range f.Ports {
		ps[i] = fmt.Sprint(p)
	}
	return []string{"th sport " + nftSet(ps), "th dport " + nftSet(ps)}
}

// l4Match is the match of the transport protocols the filter names. Ports
// narrow "any protocol" down to TCP and UDP.
func (f Filter) l4Match() string {
	var l4 []string
	for _, p := range f.Protos {
		switch p {
		case "tcp", "udp":
			l4 = append(l4, p)
		case "icmp":
			l4 = append(l4, "icmp", "ipv6-icmp")
		}
	}
	if len(f.Ports) > 0 {
		l4 = nil
		for _, p := range []string{"tcp", "udp"} {
			if len(f.Protos) == 0 || f.wants(p) {
				l4 = append(l4, p)
			}
		}
	}
	if len(l4) == 0 {
		return ""
	}
	return "meta l4proto " + nftSet(l4)
}

// ifaceAlts returns the device matches of the filter. With bridges, the name
// of a bridge matches as well as the name of a port.
func (f Filter) ifaceAlts(bridges bool) []string {
	if len(f.Ifaces) == 0 {
		return nil
	}
	var in, out []string
	for _, entry := range f.Ifaces {
		dir, name := splitIface(entry)
		if dir != "out" {
			in = append(in, name)
		}
		if dir != "in" {
			out = append(out, name)
		}
	}
	var alts []string
	if len(in) > 0 {
		alts = append(alts, "meta iifname "+nftSet(quoted(in)))
		if bridges {
			alts = append(alts, "meta ibrname "+nftSet(quoted(in)))
		}
	}
	if len(out) > 0 {
		alts = append(alts, "meta oifname "+nftSet(quoted(out)))
		if bridges {
			alts = append(alts, "meta obrname "+nftSet(quoted(out)))
		}
	}
	return alts
}

// ipMatches returns the nft match expressions of the filter for the IP hooks
// (the inet family). A packet is traced when it satisfies at least one of
// them. No expression at all means that the filter selects no IP packet, and
// an empty expression matches every packet.
func (f Filter) ipMatches() []string {
	var protoAlts []string
	if len(f.Protos) > 0 {
		if l4 := f.l4Match(); l4 != "" {
			protoAlts = append(protoAlts, l4)
		}
		// With ports, "ip" and "ip6" are narrowed down by the ports alone.
		if len(f.Ports) == 0 {
			if f.wants("ip") {
				protoAlts = append(protoAlts, "meta nfproto ipv4")
			}
			if f.wants("ip6") {
				protoAlts = append(protoAlts, "meta nfproto ipv6")
			}
		}
		if len(protoAlts) == 0 {
			return nil // only ARP or other frames are asked for
		}
	} else if l4 := f.l4Match(); l4 != "" {
		protoAlts = []string{l4}
	}
	var ipAlts []string
	v4, v6 := f.splitIPs()
	if len(v4) > 0 {
		ipAlts = append(ipAlts, "ip saddr "+nftSet(v4), "ip daddr "+nftSet(v4))
	}
	if len(v6) > 0 {
		ipAlts = append(ipAlts, "ip6 saddr "+nftSet(v6), "ip6 daddr "+nftSet(v6))
	}
	return product(f.ifaceAlts(false), ipAlts, protoAlts, f.portAlts())
}

// frameMatches returns the nft match expressions of the filter for the hooks
// that see frames: the bridge family (with bridges) and the netdev family.
// dir limits the device matches to one direction: the ingress hook of a
// device knows no output device, and the egress hook no input device.
func (f Filter) frameMatches(bridges bool, dir string) []string {
	var ifaces []string
	for _, alt := range f.ifaceAlts(bridges) {
		if dir == "" || strings.HasPrefix(alt, "meta "+dir) {
			ifaces = append(ifaces, alt)
		}
	}
	if len(f.Ifaces) > 0 && len(ifaces) == 0 {
		return nil
	}
	var macAlts []string
	if len(f.MACs) > 0 {
		macAlts = []string{"ether saddr " + nftSet(f.MACs), "ether daddr " + nftSet(f.MACs)}
	}

	any := len(f.Protos) == 0
	v4, v6 := f.splitIPs()
	ipProtos := f.wants("ip") || f.wants("ip6") || f.wants("tcp") || f.wants("udp") || f.wants("icmp")
	// What the frame carries: every alternative is a match of its own.
	var payload []string
	switch {
	case len(f.IPs) > 0 || len(f.Ports) > 0:
		// Addresses and ports select IP packets, and ARP messages by address.
		var ipAlts []string
		if len(v4) > 0 {
			ipAlts = append(ipAlts, "ip saddr "+nftSet(v4), "ip daddr "+nftSet(v4))
		}
		if len(v6) > 0 {
			ipAlts = append(ipAlts, "ip6 saddr "+nftSet(v6), "ip6 daddr "+nftSet(v6))
		}
		if any || ipProtos {
			var l4 []string
			if m := f.l4Match(); m != "" {
				l4 = []string{m}
			}
			payload = append(payload, product(ipAlts, l4, f.portAlts())...)
		}
		if len(v4) > 0 && len(f.Ports) == 0 && (any || f.wants("arp")) {
			payload = append(payload, "arp saddr ip "+nftSet(v4), "arp daddr ip "+nftSet(v4))
		}
	case !any:
		var types []string
		for _, p := range []string{"arp", "ip", "ip6"} {
			if f.wants(p) {
				types = append(types, p)
			}
		}
		if len(types) > 0 {
			payload = append(payload, "ether type "+nftSet(types))
		}
		if m := f.l4Match(); m != "" {
			payload = append(payload, m)
		}
		if f.wants("other") {
			payload = append(payload, "ether type != { arp, ip, ip6 }")
		}
	}
	if !any || len(f.IPs) > 0 || len(f.Ports) > 0 {
		if len(payload) == 0 {
			return nil
		}
	}
	return product(ifaces, macAlts, payload)
}
