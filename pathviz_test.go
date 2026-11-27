package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

// tcpPacket builds an IPv4 TCP packet with the given addresses, ports, and IP ID.
func tcpPacket(src, dst [4]byte, sport, dport, id uint16, ttl uint8) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 40)
	binary.BigEndian.PutUint16(b[4:], id)
	b[6] = 0x40 // DF
	b[8] = ttl
	b[9] = 6
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint32(b[24:], 1000)
	b[32] = 0x50
	b[33] = 0x02 // SYN
	binary.BigEndian.PutUint16(b[34:], 64240)
	return b
}

func mustParse(t *testing.T, b []byte) Packet {
	t.Helper()
	p, err := ParsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseTCP(t *testing.T) {
	p := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 7, 64))
	if p.Proto != "tcp" || p.SrcString() != "10.0.0.1:40000" || p.DstString() != "10.0.0.2:8080" {
		t.Fatalf("unexpected packet: %+v", p)
	}
	if p.Info != "SYN" || p.Detail != "seq=1000" {
		t.Fatalf("unexpected info: %q", p.Info)
	}
}

func TestFingerprintSurvivesNATAndForwarding(t *testing.T) {
	orig := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 7, 64))
	natted := mustParse(t, tcpPacket([4]byte{192, 168, 0, 9}, [4]byte{172, 17, 0, 2}, 1024, 80, 7, 63))
	if orig.fingerprint != natted.fingerprint {
		t.Fatal("NAT and a TTL decrement must not change the fingerprint")
	}
	other := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 8, 64))
	if orig.fingerprint == other.fingerprint {
		t.Fatal("packets with different IP IDs must have different fingerprints")
	}
}

func TestParseTruncated(t *testing.T) {
	if _, err := ParsePacket([]byte{0x45, 0}); err == nil {
		t.Fatal("expected an error for a truncated header")
	}
	// A packet cut in the middle of the TCP header still yields the addresses.
	p := mustParse(t, tcpPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2, 7, 64)[:30])
	if p.Src.String() != "10.0.0.1" {
		t.Fatalf("unexpected packet: %+v", p)
	}
}

// ---- Frames ------------------------------------------------------------------

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The frames below were captured from a bridge with three veth ports.
const (
	arpRequestL2  = "ffffffffffff5a83d6db6b710806"
	arpRequestPay = "00010800060400015a83d6db6b710a0a000b0000000000000a0a000c"
	pingL2        = "d2101e98541e5a83d6db6b710800"
	pingPay       = "450000543ea540004001e7d90a0a000b0a0a000c0800a1b2000100016162636465666768"
)

func seen(t *testing.T, l2, payload string) Seen {
	t.Helper()
	var hdr []byte
	if l2 != "" {
		hdr = mustHex(t, l2)
	}
	s, err := ParseSeen(hdr, mustHex(t, payload), 0x0800)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseSeen(t *testing.T) {
	arp := seen(t, arpRequestL2, arpRequestPay)
	if arp.Packet != nil || arp.Frame.Type != "ARP" || arp.Frame.DstKind != KindBroadcast || arp.Frame.Info != "Who has 10.10.0.12? Tell 10.10.0.11" {
		t.Fatalf("ARP request: %+v", arp.Frame)
	}
	ping := seen(t, pingL2, pingPay)
	if ping.Frame.Type != "IPv4" || ping.Frame.SrcIP != "10.10.0.11" || ping.Packet.Proto != "icmp" || !strings.HasPrefix(ping.Frame.Info, "ICMP echo request") {
		t.Fatalf("ping: %+v %+v", ping.Frame, ping.Packet)
	}
	// The same packet without its Ethernet header (as an IP hook sees it), or
	// with another one (after a router), is still the same packet.
	bare := seen(t, "", pingPay)
	routed := seen(t, "0200000000010200000000020800", pingPay)
	if bare.Frame != nil || bare.key != ping.key || routed.key != ping.key {
		t.Fatal("the key of an IP packet must not depend on the Ethernet header")
	}
	if arp.key == ping.key {
		t.Fatal("different frames must have different keys")
	}
	if _, err := ParseSeen(nil, mustHex(t, arpRequestPay), 0x0806); err == nil {
		t.Fatal("an ARP message without its Ethernet header cannot be told apart")
	}
	if got := textOf([]byte("Hello all!\x00\x00")); got != `"Hello all!"` {
		t.Fatalf("text payload: %s", got)
	}
}

func TestLogRecord(t *testing.T) {
	be := binary.BigEndian
	vlan, _ := netlink.MarshalAttributes([]netlink.Attribute{{Type: nfulaVLANTCI, Data: be.AppendUint16(nil, 0x2000|20)}})
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfulaPacketHdr, Data: []byte{0x08, 0x06, 0, 0}},
		{Type: nfulaPrefix, Data: []byte("l1:enter/INGRESS\x00")},
		{Type: nfulaInDev, Data: be.AppendUint32(nil, 4)},
		{Type: nfulaPhysOutDev, Data: be.AppendUint32(nil, 9)},
		{Type: nfulaHwType, Data: be.AppendUint16(nil, 1)},
		{Type: nfulaHwHeader, Data: mustHex(t, arpRequestL2)},
		{Type: nfulaPayload, Data: mustHex(t, arpRequestPay)},
		{Type: nfulaSeq, Data: be.AppendUint32(nil, 77)},
		{Type: nfulaVLAN | 0x8000, Data: vlan},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The netdev family (5) is the one that other readers of NFLOG skip.
	rec, ok := parseLogRecord(append([]byte{5, 0, 0, 77}, attrs...))
	if !ok || rec.Prefix != "l1:enter/INGRESS" || rec.InDev != 4 || rec.PhysOutDev != 9 || rec.EtherType != 0x0806 || rec.HwType != 1 || !rec.HasSeq || rec.Seq != 77 || rec.VLAN != 20 {
		t.Fatalf("record: %+v", rec)
	}
	if len(rec.HwHeader) != 14 || len(rec.Payload) != 28 {
		t.Fatalf("header and payload: %d, %d bytes", len(rec.HwHeader), len(rec.Payload))
	}
	if _, ok := parseLogRecord([]byte{5, 0}); ok {
		t.Fatal("a message without a header must be refused")
	}
}

func TestDissectFrame(t *testing.T) {
	raw := append(mustHex(t, pingL2), mustHex(t, pingPay)...)
	d := DissectFrame(raw, 14)
	if len(d.Layers) < 3 || d.Layers[0].Kind != LayerLink || d.Layers[1].Name != "IPv4" || d.Layers[1].Off != 14 {
		t.Fatalf("layers: %+v", d.Layers)
	}
	if d.Total != 14+84 {
		t.Fatalf("total: %d", d.Total)
	}
	arp := DissectFrame(append(mustHex(t, arpRequestL2), mustHex(t, arpRequestPay)...), 14)
	if len(arp.Layers) != 2 || arp.Layers[1].Name != "ARP" || arp.Layers[1].Summary != "request" {
		t.Fatalf("ARP layers: %+v", arp.Layers)
	}
	// Without a header it is a plain IP packet, as before.
	if ip := DissectFrame(mustHex(t, pingPay), 0); ip.Layers[0].Name != "IPv4" {
		t.Fatalf("IP layers: %+v", ip.Layers)
	}
}

// ---- Tracker -----------------------------------------------------------------

// hops builds the events of one packet from a compact script. Every item is
// "<layer>:<stage>/<HOOK>" followed by fields: in=, out=, pin=, pout=, br=.
func hops(t *testing.T, start time.Time, s Seen, script ...string) []Event {
	t.Helper()
	var out []Event
	for i, line := range script {
		fields := strings.Fields(line)
		layer, rest, _ := strings.Cut(fields[0], ":")
		stage, hook, _ := strings.Cut(rest, "/")
		ev := Event{Time: start.Add(time.Duration(i) * time.Microsecond), Layer: layer, Hook: hook, Stage: stage, Seen: s}
		for _, f := range fields[1:] {
			k, v, _ := strings.Cut(f, "=")
			switch k {
			case "in":
				ev.In = v
			case "out":
				ev.Out = v
			case "pin":
				ev.PhysIn = v
			case "pout":
				ev.PhysOut = v
			case "br":
				ev.Bridge = v
			default:
				t.Fatalf("unknown field %q", f)
			}
		}
		out = append(out, ev)
	}
	return out
}

func track(peer func(string) string, events ...[]Event) []*Journey {
	var out []*Journey
	tr := NewTracker(func(j *Journey) { out = append(out, j) }, peer)
	var last time.Time
	for _, list := range events {
		for _, ev := range list {
			tr.Add(ev)
			last = ev.Time
		}
	}
	tr.Flush(last.Add(time.Second))
	return out
}

func ipSeen(t *testing.T, src, dst [4]byte, sport, dport, id uint16) Seen {
	t.Helper()
	p := mustParse(t, tcpPacket(src, dst, sport, dport, id, 64))
	return Seen{Packet: &p, key: "ip\x00" + p.fingerprint}
}

var inputPath = []string{
	"l3:raw/PREROUTING in=eth0", "l3:mangle/PREROUTING in=eth0", "l3:nat/PREROUTING in=eth0", "l3:exit/PREROUTING in=eth0",
	"l3:mangle/INPUT in=eth0", "l3:filter/INPUT in=eth0", "l3:nat/INPUT in=eth0", "l3:exit/INPUT in=eth0",
}

func TestIPStory(t *testing.T) {
	now := time.Now()
	pkt := ipSeen(t, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 8080, 7)

	js := track(nil, hops(t, now, pkt, inputPath...))
	if len(js) != 1 || js[0].IP.Verdict != VerdictDelivered || js[0].IP.Partial || strings.Join(js[0].IP.Path, " ") != "PREROUTING INPUT" {
		t.Fatalf("delivered: %+v", js[0].IP)
	}
	if js[0].Links != nil || js[0].Bridges != nil || len(js[0].Copies) != 0 {
		t.Fatal("a packet that only the IP hooks saw has no other story")
	}
	// Dropped by the filter stage of INPUT.
	js = track(nil, hops(t, now, pkt, inputPath[:6]...))
	if s := js[0].IP; s.Verdict != VerdictStopped || s.StoppedHook != "INPUT" || s.StoppedStage != "filter" {
		t.Fatalf("dropped: %+v", s)
	}
	// Left PREROUTING and was never seen again.
	js = track(nil, hops(t, now, pkt, inputPath[:4]...))
	if s := js[0].IP; s.Verdict != VerdictStopped || s.StoppedStage != "routing" {
		t.Fatalf("lost: %+v", s)
	}
	// First seen in the middle of a hook.
	js = track(nil, hops(t, now, pkt, inputPath[3:]...))
	if s := js[0].IP; s.Verdict != VerdictDelivered || !s.Partial {
		t.Fatalf("partial: %+v", s)
	}

	// DNAT in PREROUTING: the next probe sees another destination.
	natted := ipSeen(t, [4]byte{10, 0, 0, 1}, [4]byte{172, 17, 0, 2}, 40000, 80, 7)
	before := hops(t, now, pkt, inputPath[:3]...)
	after := hops(t, now.Add(time.Millisecond), natted, inputPath[3:]...)
	js = track(nil, before, after)
	if len(js) != 1 || js[0].Hops[2].Rewrote != "destination 10.0.0.2:8080 to 172.17.0.2:80" || js[0].Dst != "10.0.0.2:8080" {
		t.Fatalf("rewrite: %d journeys, %q", len(js), js[0].Hops[2].Rewrote)
	}
	// The same packet at the same stage again is another packet (a retransmit).
	js = track(nil, hops(t, now, pkt, inputPath...), hops(t, now.Add(time.Millisecond), pkt, inputPath...))
	if len(js) != 2 || js[0].ID == js[1].ID {
		t.Fatalf("repeat: %d journeys", len(js))
	}
}

func TestBridgeStory(t *testing.T) {
	now := time.Now()
	arp := seen(t, arpRequestL2, arpRequestPay)
	js := track(nil, hops(t, now, arp,
		"l2:enter/PREROUTING in=v1 br=br0", "l2:exit/PREROUTING in=v1 br=br0",
		"l2:enter/FORWARD in=v1 out=v2 br=br0", "l2:exit/FORWARD in=v1 out=v2 br=br0", "l2:enter/POSTROUTING out=v2 br=br0", "l2:exit/POSTROUTING out=v2 br=br0",
		"l2:enter/FORWARD in=v1 out=v3 br=br0",
		"l2:enter/INPUT in=v1 br=br0", "l2:exit/INPUT in=v1 br=br0",
	))
	if len(js) != 1 || len(js[0].Bridges) != 1 || js[0].IP != nil {
		t.Fatalf("flood: %+v", js)
	}
	s := js[0].Bridges[0]
	if s.Bridge != "br0" || s.In != "v1" || s.Ingress != OutcomePassed || s.Decision != DecisionFlood || len(s.Legs) != 3 || len(js[0].Copies) != 3 {
		t.Fatalf("flood story: %+v", s)
	}
	if l := s.Legs[0]; l.To != "v2" || l.Outcome != OutcomeSent || strings.Join(l.Hooks, " ") != "FORWARD POSTROUTING" {
		t.Fatalf("sent leg: %+v", l)
	}
	if l := s.Legs[1]; l.To != "v3" || l.Outcome != OutcomeDropped || l.StoppedHook != "FORWARD" {
		t.Fatalf("dropped leg: %+v", l)
	}
	if l := s.Legs[2]; !l.Host || l.Outcome != OutcomeDelivered || js[0].Hops[7].Copy != l.Copy {
		t.Fatalf("host leg: %+v", l)
	}

	ping := seen(t, pingL2, pingPay)
	// Known destination: one copy. And a frame that PREROUTING dropped.
	js = track(nil,
		hops(t, now, ping, "l2:enter/PREROUTING in=v1 br=br0", "l2:exit/PREROUTING in=v1 br=br0", "l2:enter/FORWARD in=v1 out=v2 br=br0", "l2:exit/FORWARD in=v1 out=v2 br=br0", "l2:enter/POSTROUTING out=v2 br=br0", "l2:exit/POSTROUTING out=v2 br=br0"),
		hops(t, now.Add(time.Second), ping, "l2:enter/PREROUTING in=v1 br=br0"),
		hops(t, now.Add(2*time.Second), ping, "l2:enter/PREROUTING in=v1 br=br0", "l2:exit/PREROUTING in=v1 br=br0"),
		// Sent by the network stack through the bridge device.
		hops(t, now.Add(3*time.Second), ping, "l2:enter/OUTPUT out=v2 br=br0", "l2:exit/OUTPUT out=v2 br=br0", "l2:enter/POSTROUTING out=v2 br=br0", "l2:exit/POSTROUTING out=v2 br=br0"),
	)
	if len(js) != 4 {
		t.Fatalf("%d journeys", len(js))
	}
	if s := js[0].Bridges[0]; s.Decision != DecisionForward || s.Legs[0].Outcome != OutcomeSent {
		t.Fatalf("forward: %+v", s)
	}
	if s := js[1].Bridges[0]; s.Ingress != OutcomeDropped || s.Decision != DecisionDrop {
		t.Fatalf("dropped in PREROUTING: %+v", s)
	}
	if s := js[2].Bridges[0]; s.Ingress != OutcomePassed || s.Decision != DecisionDrop || len(s.Legs) != 0 {
		t.Fatalf("dropped by the bridge: %+v", s)
	}
	if s := js[3].Bridges[0]; s.In != "" || s.Decision != DecisionForward || strings.Join(s.Legs[0].Hooks, " ") != "OUTPUT POSTROUTING" {
		t.Fatalf("sent by the stack: %+v", s)
	}
}

// A packet that arrives on a bridge port and is routed on: the device hooks,
// the bridge hooks with the IP hooks inside them (br_netfilter), and the IP
// hooks again after the bridge passed the packet up.
func TestAllLayers(t *testing.T) {
	now := time.Now()
	ping := seen(t, pingL2, pingPay)
	js := track(nil, hops(t, now, ping,
		"l1:enter/INGRESS in=v1", "l1:exit/INGRESS in=v1",
		"l2:enter/PREROUTING in=v1 br=br0",
		"l3:raw/PREROUTING in=br0 pin=v1", "l3:mangle/PREROUTING in=br0 pin=v1", "l3:nat/PREROUTING in=br0 pin=v1", "l3:exit/PREROUTING in=br0 pin=v1",
		"l2:exit/PREROUTING in=v1 br=br0",
		"l2:enter/INPUT in=v1 br=br0", "l2:exit/INPUT in=v1 br=br0",
		"l1:enter/INGRESS in=br0", "l1:exit/INGRESS in=br0",
		"l3:mangle/FORWARD in=br0 out=eth0 pin=v1", "l3:filter/FORWARD in=br0 out=eth0 pin=v1", "l3:exit/FORWARD in=br0 out=eth0 pin=v1",
		"l3:mangle/POSTROUTING out=eth0", "l3:nat/POSTROUTING out=eth0", "l3:exit/POSTROUTING out=eth0",
		"l1:enter/EGRESS out=eth0",
	))
	if len(js) != 1 {
		t.Fatalf("%d journeys", len(js))
	}
	j := js[0]
	if j.Frame == nil || j.Proto != "icmp" || len(j.Copies) != 1 || !j.Copies[0].Host {
		t.Fatalf("journey: %+v", j)
	}
	var copies []string
	for _, h := range j.Hops {
		copies = append(copies, fmt.Sprint(h.Copy))
	}
	if got := strings.Join(copies, ""); got != "0000000011111111111" {
		t.Fatalf("copies of the hops: %s", got)
	}
	if s := j.IP; s.Verdict != VerdictSent || s.Partial || strings.Join(s.Path, " ") != "PREROUTING FORWARD POSTROUTING" || len(s.Hops) != 10 {
		t.Fatalf("IP story: %+v", s)
	}
	if s := j.Bridges[0]; s.Decision != DecisionLocal || s.Legs[0].Outcome != OutcomeDelivered {
		t.Fatalf("bridge story: %+v", s)
	}
	want := []LinkCrossing{{Dev: "v1", Hook: "INGRESS", Outcome: OutcomePassed}, {Dev: "br0", Hook: "INGRESS", Outcome: OutcomePassed, Copy: 1}, {Dev: "eth0", Hook: "EGRESS", Outcome: OutcomeDropped, Copy: 1}}
	if fmt.Sprint(j.Links) != fmt.Sprint(want) {
		t.Fatalf("link story: %+v", j.Links)
	}

	// A flooded packet under br_netfilter crosses the IP FORWARD stages once
	// per port, and it is still one packet. The far end of a veth pair in the
	// same namespace sees its copy later, after the other copies.
	peer := func(dev string) string { return map[string]string{"v2": "v2-end"}[dev] }
	js = track(peer, hops(t, now, ping,
		"l2:enter/PREROUTING in=v1 br=br0", "l2:exit/PREROUTING in=v1 br=br0",
		"l2:enter/FORWARD in=v1 out=v2 br=br0", "l3:filter/FORWARD in=br0 out=br0 pin=v1 pout=v2", "l3:exit/FORWARD in=br0 out=br0 pin=v1 pout=v2", "l2:exit/FORWARD in=v1 out=v2 br=br0",
		"l2:enter/POSTROUTING out=v2 br=br0", "l2:exit/POSTROUTING out=v2 br=br0",
		"l2:enter/FORWARD in=v1 out=v3 br=br0", "l3:filter/FORWARD in=br0 out=br0 pin=v1 pout=v3", "l3:exit/FORWARD in=br0 out=br0 pin=v1 pout=v3", "l2:exit/FORWARD in=v1 out=v3 br=br0",
		"l2:enter/POSTROUTING out=v3 br=br0", "l2:exit/POSTROUTING out=v3 br=br0",
		"l1:enter/INGRESS in=v2-end", "l1:exit/INGRESS in=v2-end",
	))
	if len(js) != 1 || len(js[0].Copies) != 2 || len(js[0].Bridges[0].Legs) != 2 {
		t.Fatalf("flood under br_netfilter: %d journeys, %+v", len(js), js[0].Copies)
	}
	if last := js[0].Hops[len(js[0].Hops)-1]; last.Copy != 1 {
		t.Fatalf("the far end of v2 belongs to the copy for v2, got copy %d", last.Copy)
	}
	// The IP story follows one copy.
	if s := js[0].IP; len(s.Hops) != 2 || js[0].Hops[s.Hops[0]].PhysOut != "v2" {
		t.Fatalf("IP story of a flooded packet: %+v", s)
	}
}

// ---- Filter and rules ----------------------------------------------------------

func TestFilter(t *testing.T) {
	f := Filter{Protos: []string{"TCP", "tcp", "ipv6"}, IPs: []string{"10.0.0.1", "10.1.2.3/8", " ", "::ffff:10.0.0.1"}, Ports: []int{80, 80, 22}, Ifaces: []string{"out:eth0", "lo"}, MACs: []string{"AA:BB:CC:00:11:22"}}
	if err := f.Normalize(); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(f); got != "{[ip6 tcp] [lo out:eth0] [aa:bb:cc:00:11:22] [10.0.0.1 10.0.0.0/8] [22 80]}" {
		t.Fatalf("normalized: %s", got)
	}
	for _, bad := range []Filter{
		{Protos: []string{"sctp"}}, {IPs: []string{"10.0.0.300"}}, {IPs: []string{"fe80::1%eth0"}}, {Ports: []int{0}},
		{Ifaces: []string{`eth0"; drop`}}, {Ifaces: []string{"in:"}}, {MACs: []string{"aa:bb"}}, {Protos: []string{"icmp"}, Ports: []int{80}},
	} {
		if err := bad.Normalize(); err == nil {
			t.Errorf("filter %+v must be refused", bad)
		}
	}
	any := Filter{Protos: []string{"any"}}
	if any.Normalize() != nil || len(any.Protos) != 0 {
		t.Fatalf("any: %+v", any)
	}

	norm := func(f Filter) Filter {
		t.Helper()
		if err := f.Normalize(); err != nil {
			t.Fatal(err)
		}
		return f
	}
	join := func(m []string) string { return strings.Join(m, " | ") }
	for _, c := range []struct {
		f           Filter
		ip, frame   string
		frameBridge bool
	}{
		{f: Filter{}, ip: "", frame: ""},
		{f: Filter{Protos: []string{"tcp"}, Ports: []int{8080}}, ip: "meta l4proto { tcp } th sport { 8080 } | meta l4proto { tcp } th dport { 8080 }", frame: "meta l4proto { tcp } th sport { 8080 } | meta l4proto { tcp } th dport { 8080 }"},
		{f: Filter{Ports: []int{53}}, ip: "meta l4proto { tcp, udp } th sport { 53 } | meta l4proto { tcp, udp } th dport { 53 }", frame: "meta l4proto { tcp, udp } th sport { 53 } | meta l4proto { tcp, udp } th dport { 53 }"},
		{f: Filter{Protos: []string{"arp", "ip"}}, ip: "meta nfproto ipv4", frame: "ether type { arp, ip }"},
		// Only frames the IP hooks never see: they have nothing to match.
		{f: Filter{Protos: []string{"arp", "other"}}, ip: "NONE", frame: "ether type { arp } | ether type != { arp, ip, ip6 }"},
		{f: Filter{Protos: []string{"icmp"}}, ip: "meta l4proto { icmp, ipv6-icmp }", frame: "meta l4proto { icmp, ipv6-icmp }"},
		// An address selects IP packets and the ARP messages about it.
		{f: Filter{IPs: []string{"10.0.0.1"}}, ip: "ip saddr { 10.0.0.1 } | ip daddr { 10.0.0.1 }", frame: "ip saddr { 10.0.0.1 } | ip daddr { 10.0.0.1 } | arp saddr ip { 10.0.0.1 } | arp daddr ip { 10.0.0.1 }"},
		// The IP hooks cannot match a MAC address.
		{f: Filter{MACs: []string{"aa:bb:cc:00:11:22"}}, ip: "", frame: "ether saddr { aa:bb:cc:00:11:22 } | ether daddr { aa:bb:cc:00:11:22 }"},
		// The name of a bridge matches as well as the name of a port.
		{f: Filter{Ifaces: []string{"in:br0"}}, ip: `meta iifname { "br0" }`, frame: `meta iifname { "br0" } | meta ibrname { "br0" }`, frameBridge: true},
	} {
		f := norm(c.f)
		ip := join(f.ipMatches())
		if f.ipMatches() == nil {
			ip = "NONE"
		}
		if ip != c.ip {
			t.Errorf("%+v: IP matches %q, want %q", c.f, ip, c.ip)
		}
		if got := join(f.frameMatches(c.frameBridge, "")); got != c.frame {
			t.Errorf("%+v: frame matches %q, want %q", c.f, got, c.frame)
		}
	}
	// The ingress hook of a device knows no output device.
	out := norm(Filter{Ifaces: []string{"out:eth0"}})
	if out.frameMatches(false, "iifname") != nil || join(out.frameMatches(false, "oifname")) != `meta oifname { "eth0" }` {
		t.Fatal("a filter on the output device selects nothing at ingress")
	}

	// What the probes cannot check is checked on the finished journey.
	j := &Journey{Hops: []Hop{{Layer: L3, Hook: "PREROUTING", In: "eth0"}, {Layer: L3, Hook: "POSTROUTING", Out: "eth1"}, {Layer: L1, Hook: "INGRESS", In: "eth0", SMAC: "aa:bb:cc:00:11:22", DMAC: "ff:ff:ff:ff:ff:ff"}}}
	for _, c := range []struct {
		f    Filter
		want bool
	}{
		{Filter{}, true}, {Filter{Ifaces: []string{"out:eth1"}}, true}, {Filter{Ifaces: []string{"out:eth0"}}, false}, {Filter{Ifaces: []string{"in:eth1"}}, true},
		{Filter{MACs: []string{"aa:bb:cc:00:11:22"}}, true}, {Filter{MACs: []string{"aa:bb:cc:00:11:23"}}, false},
	} {
		if got := c.f.Keeps(j); got != c.want {
			t.Errorf("%+v keeps the journey: %v, want %v", c.f, got, c.want)
		}
	}
}

func TestRules(t *testing.T) {
	f := Filter{Protos: []string{"tcp"}, Ports: []int{8080}, Ifaces: []string{"out:eth1"}}
	if err := f.Normalize(); err != nil {
		t.Fatal(err)
	}
	o := RuleOptions{Group: 77, SkipPorts: []int{7070}, Layers: allLayers, Devices: []string{"lo", "eth0"}, Egress: true}
	r := BuildRules(f, o)
	for layer, wants := range map[string][]string{
		L1: {"table netdev pathviz {", `hook ingress devices = { "eth0", "lo" } priority -500`, `hook egress devices = { "eth0", "lo" } priority 500`, `log group 77 prefix "l1:enter/INGRESS"`, "tcp dport 7070 accept", `meta oifname { "eth1" } meta l4proto { tcp } th dport { 8080 } return`},
		L2: {"table bridge pathviz {", "hook forward priority -350", `log group 77 prefix "l2:exit/POSTROUTING"`, `meta obrname { "eth1" }`},
		L3: {"table inet pathviz {", "hook prerouting priority -301", `log group 77 prefix "l3:raw/PREROUTING"`, "chain select_early", "goto remember", "jump select_early"},
	} {
		for _, want := range wants {
			if !strings.Contains(r[layer], want) {
				t.Errorf("the %s rules lack %q", layer, want)
			}
		}
		if !strings.HasPrefix(r[layer], "# [static]") || !strings.Contains(r[layer], "delete table") {
			t.Errorf("the %s rules must replace their table", layer)
		}
	}
	// The ingress probes have nothing to select with a filter on the output device.
	if strings.Contains(r[L1], "chain select_ingress {\n\t\ttcp sport 7070 accept\n\t\ttcp dport 7070 accept\n\t\t# [filter] The frames") {
		t.Error("select_ingress must select nothing")
	}
	if text := r.Text(); strings.Index(text, "table netdev") > strings.Index(text, "table bridge") || strings.Index(text, "table bridge") > strings.Index(text, "table inet") {
		t.Error("the rules are shown from the wire up")
	}

	// No egress hook, no devices, fewer layers.
	o.Egress = false
	if r := BuildRules(f, o); strings.Contains(r[L1], "hook egress") {
		t.Error("no egress probes without the egress hook")
	}
	o.Devices = nil
	o.Layers = []string{L1, L3}
	if r := BuildRules(f, o); r[L1] != "" || r[L2] != "" || r[L3] == "" {
		t.Errorf("layers: %v", len(r))
	}
	if l, err := parseLayers("L3, l1"); err != nil || strings.Join(l, ",") != "l1,l3" {
		t.Errorf("parseLayers: %v %v", l, err)
	}
	if _, err := parseLayers("l4"); err == nil {
		t.Error("an unknown layer must be refused")
	}
}

// ---- Namespaces and devices ----------------------------------------------------

// labSpaces is a small machine: a bridge in the home namespace with a veth
// port to a container and one to a named namespace, a veth pair with both
// ends at home, and a second bridge.
func labSpaces() []nsData {
	id := func(n int) *int { return &n }
	link := func(index int, name, mac string) ipLink {
		return ipLink{Ifindex: index, Name: name, Address: mac, Flags: []string{"UP", "LOWER_UP"}, LinkType: "ether"}
	}
	port := func(l ipLink, bridge string) ipLink {
		l.Master = bridge
		l.LinkInfo.Kind = "veth"
		l.LinkInfo.SlaveKind = "bridge"
		l.LinkInfo.SlaveData.State = "forwarding"
		return l
	}
	addr := func(l ipLink, ip string) ipLink {
		l.AddrInfo = append(l.AddrInfo, struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Scope  string `json:"scope"`
		}{"inet", ip, "global"})
		return l
	}
	br0 := addr(link(3, "br0", "02:00:00:00:00:01"), "10.0.0.1")
	br0.LinkInfo.Kind = "bridge"
	br1 := link(8, "br1", "02:00:00:00:00:08")
	br1.LinkInfo.Kind = "bridge"
	web := port(link(4, "veth-web", "02:00:00:00:00:04"), "br0")
	web.LinkIndex, web.NetnsID = 2, id(0)
	blue := port(link(5, "veth-blue", "02:00:00:00:00:05"), "br0")
	blue.LinkIndex, blue.NetnsID = 2, id(1)
	// A pair with both ends at home: one is a port of br0, the other of br1.
	a := port(link(6, "pair-a", "02:00:00:00:00:06"), "br0")
	a.Link = "pair-b"
	b := port(link(7, "pair-b", "02:00:00:00:00:07"), "br1")
	b.Link = "pair-a"
	lo := ipLink{Ifindex: 1, Name: "lo", Flags: []string{"UP"}, LinkType: "loopback", Address: "00:00:00:00:00:00"}

	far := func(name, mac, ip string, peerIndex int) []ipLink {
		l := addr(link(2, name, mac), ip)
		l.LinkInfo.Kind = "veth"
		l.LinkIndex, l.NetnsID = peerIndex, id(0)
		return []ipLink{l}
	}
	return []nsData{
		{
			ns: Netns{Ino: 1, Home: true}, label: nsLabel{Kind: "host", Name: "box"},
			links: []ipLink{lo, br0, web, blue, a, b, br1},
			fdb: []fdbEntry{
				{MAC: "0a:00:00:00:00:02", Port: "veth-web", Master: "br0"},
				{MAC: "02:00:00:00:00:04", Port: "veth-web", Master: "br0", State: "permanent"},
			},
			neigh: []neighEntry{{IP: "10.0.0.2", MAC: "0a:00:00:00:00:02"}},
			nsids: map[int]uint64{0: 12, 1: 11},
		},
		{ns: Netns{Ino: 11, Names: []string{"blue"}}, label: nsLabel{Kind: "netns", Name: "blue"}, links: far("eth0", "0a:00:00:00:00:03", "10.0.0.3", 5)},
		// The same indexes as blue has: only the namespace ID tells them apart.
		{ns: Netns{Ino: 12, Pids: []int{700}}, label: nsLabel{Kind: "container", Name: "web", Runtime: "docker"}, links: far("eth0", "0a:00:00:00:00:02", "10.0.0.2", 4)},
	}
}

func TestBuildState(t *testing.T) {
	spaces := labSpaces()
	st := buildState(&spaces[0], spaces, map[string]string{})
	if len(st.Ifaces) != 7 || len(st.Bridges) != 2 || st.Bridges[0].Name != "br0" || len(st.Bridges[0].Ports) != 3 {
		t.Fatalf("state: %d devices, %+v", len(st.Ifaces), st.Bridges)
	}
	if lo := st.Ifaces[0]; lo.Kind != "loopback" || lo.MAC != "" {
		t.Fatalf("loopback: %+v", lo)
	}
	ports := map[string]Port{}
	for _, p := range st.Bridges[0].Ports {
		ports[p.Name] = p
	}
	if p := ports["veth-web"].Peer; p == nil || p.Kind != "container" || p.Name != "web" || p.Runtime != "docker" || p.Ifname != "eth0" || p.Addrs[0] != "10.0.0.2" {
		t.Fatalf("container peer: %+v", p)
	}
	if p := ports["veth-blue"].Peer; p == nil || p.Kind != "netns" || p.Name != "blue" || p.MAC != "0a:00:00:00:00:03" {
		t.Fatalf("namespace peer: %+v", p)
	}
	if p := ports["pair-a"].Peer; p == nil || p.Kind != "local" || p.Ifname != "pair-b" || p.Bridge != "br1" {
		t.Fatalf("local peer: %+v", p)
	}
	if m := ports["veth-web"].MACs; len(m) != 1 || m[0].MAC != "0a:00:00:00:00:02" || m[0].IP != "10.0.0.2" {
		t.Fatalf("learned addresses: %+v", m)
	}
	// Seen from the container, the far end is the host, and it is a bridge port.
	web := buildState(&spaces[2], spaces, nil)
	if len(web.Bridges) != 0 || len(web.Ifaces) != 1 {
		t.Fatalf("container state: %+v", web)
	}
	// The container does not know the ID of the host's namespace here.
	if web.Ifaces[0].Peer != nil {
		t.Fatalf("a peer in an unknown namespace: %+v", web.Ifaces[0].Peer)
	}
	spaces[2].nsids = map[int]uint64{0: 1}
	web = buildState(&spaces[2], spaces, nil)
	if p := web.Ifaces[0].Peer; p == nil || p.Kind != "host" || p.Name != "box" || p.Ifname != "veth-web" || p.Bridge != "br0" {
		t.Fatalf("the peer of the container: %+v", p)
	}
}

func TestInventory(t *testing.T) {
	inv := NewInventory()
	inv.data = labSpaces()
	inv.ids = spaceIDs(inv.data)
	// A container goes by its name: the ID then survives its restart.
	if got := fmt.Sprint(inv.Spaces()); got != "[{host host box  2} {blue netns blue  0} {web container web docker 0}]" {
		t.Fatalf("spaces: %s", got)
	}
	for name, ino := range map[string]uint64{"": 1, "host": 1, "blue": 11, "web": 12, "net:12": 12} {
		if ns, ok := inv.Find(name); !ok || ns.Ino != ino {
			t.Errorf("Find(%q) = %d, %v, want %d", name, ns.Ino, ok, ino)
		}
	}
	if _, ok := inv.Find("green"); ok {
		t.Error("an unknown namespace must not be found")
	}

	mounts := netnsMounts(`57 52 0:4 net:[4026532174] /run/netns/c1 rw shared:174 - nsfs nsfs rw
58 52 0:4 net:[4026532174] /run/netns/c1 rw shared:174 - nsfs nsfs rw
60 52 0:4 net:[4026532300] /run/docker/netns/a\0401 rw - nsfs nsfs rw
61 52 0:4 mnt:[4026532301] /run/x rw - nsfs nsfs rw`)
	if len(mounts) != 2 || mounts[4026532174][0] != "/run/netns/c1" || len(mounts[4026532174]) != 1 || mounts[4026532300][0] != "/run/docker/netns/a 1" {
		t.Fatalf("mounts: %v", mounts)
	}
	id := strings.Repeat("ab", 32)
	if got := containerOfCgroup("0::/system.slice/docker-" + id + ".scope\n"); got != id {
		t.Fatalf("container ID: %q", got)
	}
	if got := containerOfCgroup("0::/machine.slice/libpod-conmon-" + id + ".scope\n"); got != "" {
		t.Fatalf("conmon is not the container: %q", got)
	}
	l := labelOf(Netns{Ino: 5, Pids: []int{9}}, "box", []string{id}, map[string]containerInfo{id: {Name: "app", Pod: "shop/cart", Runtime: "cri"}}, "pause")
	if l.Kind != "pod" || l.Name != "shop/cart" {
		t.Fatalf("pod label: %+v", l)
	}
	if l := labelOf(Netns{Ino: 5, Pids: []int{9}}, "box", nil, nil, "sleep"); l.Kind != "process" || l.Name != "sleep (pid 9)" {
		t.Fatalf("process label: %+v", l)
	}
}

func TestBridgeMemory(t *testing.T) {
	m := NewBridgeMemory()
	now := time.Now()
	vlanBridge := Bridge{Name: "br0", VLANFiltering: true, PVID: 1, Ports: []Port{{Name: "v1", PVID: 10}, {Name: "v2", PVID: 10}}}
	m.Update([]fdbEntry{{MAC: "0a:00:00:00:00:02", Port: "v2", Master: "br0"}}, []Bridge{vlanBridge})
	story := func(src, dst string) *Journey {
		return &Journey{Time: now.Add(time.Second), Bridges: []BridgeStory{{Bridge: "br0", In: "v1", Src: src, Dst: dst, DstKind: KindUnicast, Ingress: OutcomePassed, Legs: []Leg{{To: "v2"}, {Host: true}}}}}
	}
	j := story("0a:00:00:00:00:01", "0a:00:00:00:00:02")
	m.Annotate(j)
	if s := j.Bridges[0]; !s.Learned || !s.Legs[0].Known || s.Legs[1].Known || s.VLAN != 10 {
		t.Fatalf("first frame: %+v", s)
	}
	// The bridge has learned the source by now.
	j = story("0a:00:00:00:00:01", "0a:00:00:00:00:09")
	j.Time = now.Add(2 * time.Second)
	m.Annotate(j)
	if s := j.Bridges[0]; s.Learned || s.Legs[0].Known {
		t.Fatalf("second frame: %+v", s)
	}
	arp := &Journey{Time: now, arp: &ARPInfo{SenderMAC: "0a:00:00:00:00:01", SenderIP: "10.0.0.1"}}
	m.Annotate(arp)
	if m.ARP()["0a:00:00:00:00:01"] != "10.0.0.1" {
		t.Fatal("an ARP message tells the address of its sender")
	}
}

func TestSockets(t *testing.T) {
	out := `udp   UNCONN 0      0         127.0.0.53%lo:53         0.0.0.0:*     users:(("systemd-resolve",pid=335,fd=13))
udp   UNCONN 0      0                     *:8080              *:*     users:(("pathviz",pid=900,fd=4))
tcp   LISTEN 0      4096                  *:8080              *:*     users:(("pathviz",pid=900,fd=3))
tcp   LISTEN 0      128                [::]:22             [::]:*     users:(("sshd",pid=771,fd=4))
tcp   LISTEN 0      128             0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=771,fd=3))
tcp   ESTAB  0      0           172.16.0.20:8080    172.16.0.10:57308 users:(("pathviz",pid=900,fd=7))
tcp   ESTAB  0      0           172.16.0.20:40000   172.16.0.10:9000  users:(("curl",pid=1200,fd=5))
tcp   LISTEN 0      4096                  *:7070              *:*     users:(("pathviz",pid=800,fd=6))
tcp   LISTEN 0      5             127.0.0.1:631         0.0.0.0:*
`
	tbl := NewSocketTable(Netns{Home: true}, []int{7070})
	tbl.socks = parseSS(out)
	tbl.last = time.Now()
	if len(tbl.socks) != 8 {
		t.Fatalf("expected 8 sockets with a process, got %d", len(tbl.socks))
	}
	ap := netip.MustParseAddrPort
	if o := tbl.Owner("tcp", ap("172.16.0.20:8080"), ap("172.16.0.10:1")); o == nil || o.PID != 900 {
		t.Fatalf("listening socket owner: %+v", o)
	}
	if o := tbl.Owner("tcp", ap("172.16.0.20:40000"), ap("172.16.0.10:9000")); o == nil || o.Name != "curl" {
		t.Fatalf("connected socket owner: %+v", o)
	}
	if o := tbl.Owner("udp", ap("127.0.0.53:53"), ap("127.0.0.1:5000")); o == nil || o.PID != 335 {
		t.Fatalf("bound address owner: %+v", o)
	}
	if o := tbl.Owner("udp", ap("172.16.0.20:53"), ap("127.0.0.1:5000")); o != nil {
		t.Fatalf("a socket bound to another address must not match: %+v", o)
	}
	var names []string
	for _, p := range tbl.Procs() {
		names = append(names, fmt.Sprintf("%s/%d/%d", p.Name, p.PID, len(p.Sockets)))
	}
	if got := strings.Join(names, " "); got != "sshd/771/1 systemd-resolve/335/1 pathviz/900/2" {
		t.Fatalf("processes: %q", got)
	}
}

func TestInstallProbesExplainsMissingLogSupport(t *testing.T) {
	plain := errors.New("nft -f -: exit status 1: Error: syntax error")
	if got := explainNft(plain); got != plain {
		t.Fatalf("an unrelated error must stay as it is: %v", got)
	}
	missing := errors.New("nft -f -: exit status 1: Error: Could not process rule: No such file or directory\nlog group 77 prefix \"l3:raw/PREROUTING\"")
	msg := explainNft(missing).Error()
	if !strings.Contains(msg, "modprobe nft_log") || !strings.Contains(msg, "modprobe nfnetlink_log") {
		t.Fatalf("missing remediation in error: %s", msg)
	}
	if !errors.Is(explainNft(missing), missing) {
		t.Fatal("the explained error must wrap the original one")
	}
}

func TestToken(t *testing.T) {
	opts := Options{PacketView: true, Layers: allLayers}
	app := &Server{token: "secret", opts: opts, hub: NewHub(context.Background(), opts, NewInventory(), Filter{})}
	h := app.Handler()
	get := func(path, bearer string) int {
		r := httptest.NewRequest("GET", path, nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		path, bearer string
		want         int
	}{
		{"/", "", 200},
		{"/app.js", "", 200},
		{"/api/session", "", 401},
		{"/api/session", "wrong", 401},
		{"/api/session?token=wrong", "", 401},
		{"/api/session", "secret", 204},
		{"/api/session?token=secret", "", 204},
		{"/api/ruleset", "", 401},
		{"/api/packet?id=1", "", 401},
		{"/api/packet?id=1", "secret", 404},
		{"/api/events", "", 401},
		{"/api/nothing", "", 401},
	} {
		if got := get(c.path, c.bearer); got != c.want {
			t.Errorf("GET %s (bearer %q) = %d, want %d", c.path, c.bearer, got, c.want)
		}
	}
	r := httptest.NewRequest("POST", "/api/clear", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("POST /api/clear without the token = %d, want 401", w.Code)
	}

	// No cookies: a browser would send them to every port of the host.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/?token=secret", nil))
	if c := w.Result().Cookies(); len(c) != 0 {
		t.Errorf("the page must not set cookies: %v", c)
	}
	r = httptest.NewRequest("GET", "/api/session", nil)
	r.AddCookie(&http.Cookie{Name: "pathviz_token_7070", Value: "secret"})
	r.AddCookie(&http.Cookie{Name: "token", Value: "secret"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("GET /api/session with the token in a cookie = %d, want 401", w.Code)
	}

	// --dangerously-skip-token: no token, no check.
	app.token = ""
	if got := get("/api/session", ""); got != 204 {
		t.Errorf("GET /api/session without a token check = %d, want 204", got)
	}

	a, _ := newToken()
	b, _ := newToken()
	if len(a) != 32 || a == b {
		t.Errorf("bad tokens: %q, %q", a, b)
	}

	const own, other = "0123456789abcdef", "fedcba9876543210"
	for _, c := range []struct {
		flag, env string
		skip      bool
		want      string // "random", "error", or the token
	}{
		{"", "", false, "random"},
		{"", "", true, ""},
		{own, "", false, own},
		{"", own, false, own},
		{own, other, false, own},
		{"short", "", false, "error"},
		{"0123456789 abcdef", "", false, "error"},
		{own, "", true, "error"},
		{"", own, true, "error"},
	} {
		got, isOwn, err := pickToken(c.flag, c.env, c.skip)
		switch c.want {
		case "error":
			if err == nil {
				t.Errorf("pickToken(%q, %q, %v) must fail", c.flag, c.env, c.skip)
			}
		case "random":
			if err != nil || len(got) != 32 || isOwn {
				t.Errorf("pickToken(%q, %q, %v) = %q, %v, %v", c.flag, c.env, c.skip, got, isOwn, err)
			}
		default:
			if err != nil || got != c.want || isOwn != (c.want != "") {
				t.Errorf("pickToken(%q, %q, %v) = %q, %v, %v", c.flag, c.env, c.skip, got, isOwn, err)
			}
		}
	}
}

func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := dir + "/" + name
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got, err := readTokenFile(write("ok", "  0123456789abcdef\n", 0o600)); err != nil || got != "0123456789abcdef" {
		t.Errorf("readTokenFile = %q, %v", got, err)
	}
	if _, err := readTokenFile(write("open", "0123456789abcdef", 0o644)); err == nil {
		t.Error("a token file that others can read must be refused")
	}
	if _, err := readTokenFile(write("empty", "\n", 0o600)); err == nil {
		t.Error("an empty token file must be refused")
	}
	if _, err := readTokenFile(dir + "/missing"); err == nil {
		t.Error("a missing token file must be refused")
	}
}
