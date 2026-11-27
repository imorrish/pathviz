package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Field is one decoded field of a packet: a name, a value, and the bytes it
// was read from. Fields smaller than a byte share their bytes with a neighbor.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Off   int    `json:"off"`
	Len   int    `json:"len"`
}

// Layer kinds. The page colors the bytes of a layer by its kind.
const (
	LayerLink = "link"
	LayerIP   = "ip"
	LayerL4   = "l4"
	LayerApp  = "app"
	LayerData = "data"
)

// Layer is a run of bytes that belongs to one protocol.
type Layer struct {
	Kind    string  `json:"kind"`
	Name    string  `json:"name"`
	Summary string  `json:"summary,omitempty"`
	Off     int     `json:"off"`
	Len     int     `json:"len"`
	Fields  []Field `json:"fields"`
}

// Dissection is a packet split into layers and fields.
type Dissection struct {
	// Bytes is the captured part of the packet: from the Ethernet header on
	// when the probe saw one, else from the IP header on.
	Bytes []byte `json:"bytes"`
	// Total is the real length of the packet. It is larger than the number of
	// captured bytes when the capture cut the packet short.
	Total  int     `json:"total"`
	Layers []Layer `json:"layers"`
}

// Dissect decodes the captured bytes of an IP packet. It never fails: the
// bytes it cannot decode end up in a data layer.
func Dissect(b []byte) Dissection { return DissectFrame(b, 0) }

// DissectFrame decodes captured bytes that start with an Ethernet header of
// l2len bytes, or with the IP header when l2len is 0.
func DissectFrame(b []byte, l2len int) Dissection {
	d := &dissector{b: b}
	ip := true
	if l2len >= 14 && len(b) >= l2len {
		l := d.begin(LayerLink, "Ethernet", 0)
		etherType := d.u16(l2len - 2)
		d.add(l, "Destination", 0, 6, net.HardwareAddr(b[0:6]).String())
		d.add(l, "Source", 6, 6, net.HardwareAddr(b[6:12]).String())
		d.add(l, "EtherType", l2len-2, 2, fmt.Sprintf("%s (%s)", hex16(etherType), etherTypeName(etherType)))
		l.Summary = fmt.Sprintf("%s → %s", net.HardwareAddr(b[6:12]), net.HardwareAddr(b[0:6]))
		d.end(l, l2len)
		switch etherType {
		case 0x0800, 0x86dd:
		case 0x0806:
			ip = false
			d.arp(l2len)
		default:
			ip = false
			d.data("Payload", l2len, len(b))
		}
	} else {
		l2len = 0
	}
	total := len(b)
	if ip {
		d.ip(l2len, false)
		if len(b) > l2len {
			switch b[l2len] >> 4 {
			case 4:
				if len(b) >= l2len+4 {
					total = max(total, l2len+int(d.u16(l2len+2)))
				}
			case 6:
				if len(b) >= l2len+6 {
					total = max(total, l2len+40+int(d.u16(l2len+4)))
				}
			}
		}
	}
	// Bytes past the end the headers declare (e.g. padding) are still shown.
	covered := 0
	if n := len(d.layers); n > 0 {
		covered = d.layers[n-1].Off + d.layers[n-1].Len
	}
	if covered < len(b) {
		d.data("Trailing data", covered, len(b))
	}
	if d.layers == nil {
		d.layers = []Layer{}
	}
	return Dissection{Bytes: b, Total: total, Layers: d.layers}
}

// arp decodes an ARP message for Ethernet and IPv4.
func (d *dissector) arp(off int) {
	l := d.begin(LayerIP, "ARP", off)
	op := d.u16(off + 6)
	name := map[uint16]string{1: "request", 2: "reply"}[op]
	if name == "" {
		name = "unknown"
	}
	d.add(l, "Hardware type", off, 2, fmt.Sprint(d.u16(off)))
	d.add(l, "Protocol type", off+2, 2, hex16(d.u16(off+2)))
	d.add(l, "Hardware size", off+4, 1, fmt.Sprint(d.u8(off+4)))
	d.add(l, "Protocol size", off+5, 1, fmt.Sprint(d.u8(off+5)))
	d.add(l, "Operation", off+6, 2, fmt.Sprintf("%d (%s)", op, name))
	if d.u8(off+4) == 6 && d.u8(off+5) == 4 && d.has(off, 28) {
		d.add(l, "Sender MAC", off+8, 6, net.HardwareAddr(d.b[off+8:off+14]).String())
		d.add(l, "Sender IP", off+14, 4, d.addr(off+14, 4))
		d.add(l, "Target MAC", off+18, 6, net.HardwareAddr(d.b[off+18:off+24]).String())
		d.add(l, "Target IP", off+24, 4, d.addr(off+24, 4))
		l.Summary = name
	}
	d.end(l, off+28)
}

// dissector walks the packet. Its readers return zero past the end of the
// captured bytes, and add drops the fields that were not captured in full, so
// a truncated or malformed packet cannot make it fail.
type dissector struct {
	b      []byte
	layers []Layer
}

func (d *dissector) has(off, n int) bool { return off >= 0 && n >= 0 && off+n <= len(d.b) }

func (d *dissector) u8(off int) uint8 {
	if !d.has(off, 1) {
		return 0
	}
	return d.b[off]
}

func (d *dissector) u16(off int) uint16 {
	if !d.has(off, 2) {
		return 0
	}
	return binary.BigEndian.Uint16(d.b[off:])
}

func (d *dissector) u32(off int) uint32 {
	if !d.has(off, 4) {
		return 0
	}
	return binary.BigEndian.Uint32(d.b[off:])
}

// slice returns up to n bytes at off, as many as were captured.
func (d *dissector) slice(off, n int) []byte {
	if off < 0 || off >= len(d.b) || n <= 0 {
		return nil
	}
	return d.b[off:min(len(d.b), off+n)]
}

// begin opens a layer at off. Its length is set by end.
func (d *dissector) begin(kind, name string, off int) *Layer {
	d.layers = append(d.layers, Layer{Kind: kind, Name: name, Off: off, Fields: []Field{}})
	return &d.layers[len(d.layers)-1]
}

// end closes the layer at the offset to (or at the end of the captured bytes)
// and returns where it ended. An empty layer is removed.
func (d *dissector) end(l *Layer, to int) int {
	to = max(l.Off, min(to, len(d.b)))
	l.Len = to - l.Off
	// A damaged length field can end the layer before its last fields.
	kept := l.Fields[:0]
	for _, f := range l.Fields {
		if f.Off >= l.Off && f.Off+f.Len <= to {
			kept = append(kept, f)
		}
	}
	l.Fields = kept
	if l.Len == 0 && len(d.layers) > 0 && &d.layers[len(d.layers)-1] == l {
		d.layers = d.layers[:len(d.layers)-1]
	}
	return to
}

// add appends a field, unless its bytes were not captured in full.
func (d *dissector) add(l *Layer, name string, off, n int, value string) {
	if n <= 0 || !d.has(off, n) {
		return
	}
	l.Fields = append(l.Fields, Field{Name: name, Value: value, Off: off, Len: n})
}

// data puts the bytes from off to the end (or to the limit) into a data layer.
func (d *dissector) data(name string, off, limit int) {
	l := d.begin(LayerData, name, off)
	to := d.end(l, limit)
	if to > off {
		l.Summary = plural(to-off, "byte")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func hex16(v uint16) string { return fmt.Sprintf("0x%04x", v) }

var ipProtoNames = map[uint8]string{
	0: "IPv6 Hop-by-Hop Options", 1: "ICMP", 2: "IGMP", 4: "IPv4 in IP", 6: "TCP", 17: "UDP",
	41: "IPv6 in IP", 43: "IPv6 Routing", 44: "IPv6 Fragment", 47: "GRE", 50: "ESP", 51: "AH",
	58: "ICMPv6", 59: "No Next Header", 60: "IPv6 Destination Options", 89: "OSPF", 132: "SCTP",
}

func ipProto(n uint8) string {
	if name, ok := ipProtoNames[n]; ok {
		return fmt.Sprintf("%d (%s)", n, name)
	}
	return fmt.Sprint(n)
}

// ip decodes the IP header at off and everything after it. A quoted packet is
// the start of another packet inside an ICMP error.
func (d *dissector) ip(off int, quoted bool) {
	if !d.has(off, 1) {
		return
	}
	suffix := ""
	if quoted {
		suffix = " (quoted)"
	}
	switch d.b[off] >> 4 {
	case 4:
		d.ipv4(off, suffix, quoted)
	case 6:
		d.ipv6(off, suffix, quoted)
	default:
		d.data("Data", off, len(d.b))
	}
}

func (d *dissector) ipv4(off int, suffix string, quoted bool) {
	l := d.begin(LayerIP, "IPv4"+suffix, off)
	ihl := int(d.u8(off)&0x0f) * 4
	total := int(d.u16(off + 2))
	frag := d.u16(off + 6)
	proto := d.u8(off + 9)
	d.add(l, "Version", off, 1, "4")
	d.add(l, "Header Length", off, 1, fmt.Sprintf("%d (%d bytes)", ihl/4, ihl))
	tos := d.u8(off + 1)
	d.add(l, "DSCP / ECN", off+1, 1, fmt.Sprintf("DSCP %d, ECN %d", tos>>2, tos&3))
	d.add(l, "Total Length", off+2, 2, fmt.Sprint(total))
	d.add(l, "Identification", off+4, 2, fmt.Sprintf("%s (%d)", hex16(d.u16(off+4)), d.u16(off+4)))
	var flags []string
	if frag&0x4000 != 0 {
		flags = append(flags, "DF (don't fragment)")
	}
	if frag&0x2000 != 0 {
		flags = append(flags, "MF (more fragments)")
	}
	if len(flags) == 0 {
		flags = []string{"none"}
	}
	d.add(l, "Flags", off+6, 1, strings.Join(flags, ", "))
	fragOff := int(frag&0x1fff) * 8
	d.add(l, "Fragment Offset", off+6, 2, fmt.Sprint(fragOff))
	d.add(l, "Time to Live", off+8, 1, fmt.Sprint(d.u8(off+8)))
	d.add(l, "Protocol", off+9, 1, ipProto(proto))
	d.add(l, "Header Checksum", off+10, 2, hex16(d.u16(off+10)))
	src, dst := d.addr(off+12, 4), d.addr(off+16, 4)
	d.add(l, "Source Address", off+12, 4, src)
	d.add(l, "Destination Address", off+16, 4, dst)
	if !d.has(off, 20) || ihl < 20 {
		d.end(l, len(d.b))
		return
	}
	if ihl > 20 {
		d.add(l, "Options", off+20, ihl-20, plural(ihl-20, "byte"))
	}
	l.Summary = fmt.Sprintf("%s → %s", src, dst)
	next := d.end(l, off+ihl)

	// The packet ends where the IP header says, even when more was captured.
	limit := len(d.b)
	if total >= ihl && !quoted {
		limit = min(limit, off+total)
	}
	if fragOff != 0 {
		d.data("Fragment data", next, limit)
		return
	}
	d.transport(proto, next, limit, total-ihl, quoted)
}

func (d *dissector) ipv6(off int, suffix string, quoted bool) {
	l := d.begin(LayerIP, "IPv6"+suffix, off)
	payloadLen := int(d.u16(off + 4))
	next := d.u8(off + 6)
	d.add(l, "Version", off, 1, "6")
	d.add(l, "Traffic Class", off, 2, fmt.Sprintf("0x%02x", uint8(d.u16(off)>>4)))
	d.add(l, "Flow Label", off+1, 3, fmt.Sprintf("0x%05x", d.u32(off)&0xfffff))
	d.add(l, "Payload Length", off+4, 2, fmt.Sprint(payloadLen))
	d.add(l, "Next Header", off+6, 1, ipProto(next))
	d.add(l, "Hop Limit", off+7, 1, fmt.Sprint(d.u8(off+7)))
	src, dst := d.addr(off+8, 16), d.addr(off+24, 16)
	d.add(l, "Source Address", off+8, 16, src)
	d.add(l, "Destination Address", off+24, 16, dst)
	if !d.has(off, 40) {
		d.end(l, len(d.b))
		return
	}
	l.Summary = fmt.Sprintf("%s → %s", src, dst)
	at := d.end(l, off+40)
	limit := len(d.b)
	if !quoted {
		limit = min(limit, off+40+payloadLen)
	}

	// The extension headers that can precede the L4 header.
	for {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if !d.has(at, 8) {
				d.data("Data", at, limit)
				return
			}
			n := (int(d.u8(at+1)) + 1) * 8
			e := d.begin(LayerIP, ipProtoNames[next], at)
			d.add(e, "Next Header", at, 1, ipProto(d.u8(at)))
			d.add(e, "Length", at+1, 1, plural(n, "byte"))
			d.add(e, "Data", at+2, n-2, plural(n-2, "byte"))
			next = d.u8(at)
			at = d.end(e, at+n)
			continue
		case 44: // fragment
			if !d.has(at, 8) {
				d.data("Data", at, limit)
				return
			}
			e := d.begin(LayerIP, ipProtoNames[next], at)
			field := d.u16(at + 2)
			fragOff := int(field>>3) * 8
			d.add(e, "Next Header", at, 1, ipProto(d.u8(at)))
			d.add(e, "Fragment Offset", at+2, 2, fmt.Sprint(fragOff))
			more := "no"
			if field&1 != 0 {
				more = "yes"
			}
			d.add(e, "More Fragments", at+3, 1, more)
			d.add(e, "Identification", at+4, 4, fmt.Sprintf("0x%08x", d.u32(at+4)))
			e.Summary = fmt.Sprintf("offset %d", fragOff)
			next = d.u8(at)
			at = d.end(e, at+8)
			if fragOff != 0 {
				d.data("Fragment data", at, limit)
				return
			}
			continue
		}
		break
	}
	d.transport(next, at, limit, off+40+payloadLen-at, quoted)
}

func (d *dissector) addr(off, n int) string {
	if !d.has(off, n) {
		return ""
	}
	a, _ := netip.AddrFromSlice(d.b[off : off+n])
	return a.String()
}

// transport decodes the L4 header at off. The limit is where the packet's
// bytes end, and l4len is the real length of the L4 header plus its payload.
func (d *dissector) transport(proto uint8, off, limit, l4len int, quoted bool) {
	if off >= limit {
		return
	}
	switch proto {
	case 6:
		d.tcp(off, limit, l4len, quoted)
	case 17:
		d.udp(off, limit, quoted)
	case 1, 58:
		d.icmp(proto, off, limit, quoted)
	default:
		d.data("Data", off, limit)
	}
}

var tcpFlagNames = []struct {
	bit  uint16
	name string
}{{0x002, "SYN"}, {0x001, "FIN"}, {0x004, "RST"}, {0x008, "PSH"}, {0x010, "ACK"}, {0x020, "URG"}, {0x040, "ECE"}, {0x080, "CWR"}}

func (d *dissector) tcp(off, limit, l4len int, quoted bool) {
	l := d.begin(LayerL4, "TCP", off)
	sport, dport := d.u16(off), d.u16(off+2)
	d.add(l, "Source Port", off, 2, fmt.Sprint(sport))
	d.add(l, "Destination Port", off+2, 2, fmt.Sprint(dport))
	d.add(l, "Sequence Number", off+4, 4, fmt.Sprint(d.u32(off+4)))
	if d.has(off, 4) {
		l.Summary = fmt.Sprintf("%d → %d", sport, dport)
	}
	if !d.has(off, 20) {
		// An ICMP error may quote only the first 8 bytes.
		d.end(l, limit)
		return
	}
	flags := d.u16(off+12) & 0x0fff
	hdr := int(d.u8(off+12)>>4) * 4
	d.add(l, "Acknowledgment Number", off+8, 4, fmt.Sprint(d.u32(off+8)))
	d.add(l, "Header Length", off+12, 1, fmt.Sprintf("%d (%d bytes)", hdr/4, hdr))
	var names []string
	for _, f := range tcpFlagNames {
		if flags&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	if len(names) == 0 {
		names = []string{"none"}
	}
	d.add(l, "Flags", off+12, 2, strings.Join(names, " "))
	d.add(l, "Window", off+14, 2, fmt.Sprint(d.u16(off+14)))
	d.add(l, "Checksum", off+16, 2, hex16(d.u16(off+16)))
	d.add(l, "Urgent Pointer", off+18, 2, fmt.Sprint(d.u16(off+18)))
	l.Summary += " [" + strings.Join(names, " ") + "]"
	if hdr < 20 {
		d.end(l, limit)
		return
	}
	d.tcpOptions(l, off+20, min(off+hdr, limit))
	at := d.end(l, min(off+hdr, limit))
	if at >= limit || quoted {
		if at < limit {
			d.data("Data", at, limit)
		}
		return
	}
	d.tcpPayload(at, limit, sport, dport)
}

func (d *dissector) tcpOptions(l *Layer, off, end int) {
	for off < end && d.has(off, 1) {
		kind := d.u8(off)
		if kind == 0 {
			d.add(l, "Option: End of List", off, end-off, "")
			return
		}
		if kind == 1 {
			d.add(l, "Option: No-Operation", off, 1, "")
			off++
			continue
		}
		n := int(d.u8(off + 1))
		if n < 2 || off+n > end || !d.has(off, n) {
			return
		}
		switch {
		case kind == 2 && n == 4:
			d.add(l, "Option: Maximum Segment Size", off, n, fmt.Sprint(d.u16(off+2)))
		case kind == 3 && n == 3:
			d.add(l, "Option: Window Scale", off, n, fmt.Sprintf("%d (multiply by %d)", d.u8(off+2), 1<<min(d.u8(off+2), 14)))
		case kind == 4:
			d.add(l, "Option: SACK Permitted", off, n, "")
		case kind == 5:
			var blocks []string
			for i := off + 2; i+8 <= off+n; i += 8 {
				blocks = append(blocks, fmt.Sprintf("%d-%d", d.u32(i), d.u32(i+4)))
			}
			d.add(l, "Option: SACK", off, n, strings.Join(blocks, ", "))
		case kind == 8 && n == 10:
			d.add(l, "Option: Timestamps", off, n, fmt.Sprintf("value %d, echo reply %d", d.u32(off+2), d.u32(off+6)))
		default:
			d.add(l, fmt.Sprintf("Option: kind %d", kind), off, n, plural(n-2, "byte"))
		}
		off += n
	}
}

func (d *dissector) tcpPayload(off, limit int, sport, dport uint16) {
	p := d.slice(off, limit-off)
	switch {
	case looksLikeHTTP(p):
		d.http(off, limit)
	case looksLikeTLS(p):
		d.tls(off, limit)
	case (sport == 53 || dport == 53) && len(p) > 14 && int(d.u16(off)) >= 12:
		// DNS over TCP puts the length of the message in front of it.
		d.dns(off, limit, true)
	default:
		d.data("Data", off, limit)
	}
}

func (d *dissector) udp(off, limit int, quoted bool) {
	l := d.begin(LayerL4, "UDP", off)
	sport, dport := d.u16(off), d.u16(off+2)
	d.add(l, "Source Port", off, 2, fmt.Sprint(sport))
	d.add(l, "Destination Port", off+2, 2, fmt.Sprint(dport))
	d.add(l, "Length", off+4, 2, fmt.Sprint(d.u16(off+4)))
	d.add(l, "Checksum", off+6, 2, hex16(d.u16(off+6)))
	if d.has(off, 4) {
		l.Summary = fmt.Sprintf("%d → %d", sport, dport)
	}
	at := d.end(l, min(off+8, limit))
	if at >= limit {
		return
	}
	is := func(port uint16) bool { return sport == port || dport == port }
	switch {
	case quoted:
		d.data("Data", at, limit)
	case is(53) || is(5353) || is(5355):
		d.dns(at, limit, false)
	case is(67) || is(68):
		d.dhcp(at, limit)
	default:
		d.data("Data", at, limit)
	}
}

var icmpTypes = map[uint8]string{
	0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench", 5: "Redirect", 8: "Echo Request",
	9: "Router Advertisement", 10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
	13: "Timestamp Request", 14: "Timestamp Reply",
}

var icmp6Types = map[uint8]string{
	1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded", 4: "Parameter Problem",
	128: "Echo Request", 129: "Echo Reply", 130: "Multicast Listener Query", 131: "Multicast Listener Report",
	133: "Router Solicitation", 134: "Router Advertisement", 135: "Neighbor Solicitation",
	136: "Neighbor Advertisement", 137: "Redirect", 143: "Multicast Listener Report v2",
}

func (d *dissector) icmp(proto uint8, off, limit int, quoted bool) {
	name, types := "ICMP", icmpTypes
	if proto == 58 {
		name, types = "ICMPv6", icmp6Types
	}
	l := d.begin(LayerL4, name, off)
	typ, code := d.u8(off), d.u8(off+1)
	typeName := types[typ]
	if typeName == "" {
		typeName = "unknown"
	}
	d.add(l, "Type", off, 1, fmt.Sprintf("%d (%s)", typ, typeName))
	codeText := fmt.Sprint(code)
	if proto == 1 && typ == 3 {
		if info := icmpName(proto, typ, code); !strings.Contains(info, "(code") {
			codeText = fmt.Sprintf("%d (%s)", code, info)
		}
	}
	d.add(l, "Code", off+1, 1, codeText)
	d.add(l, "Checksum", off+2, 2, hex16(d.u16(off+2)))
	if d.has(off, 1) {
		l.Summary = typeName
	}
	echo := (proto == 1 && (typ == 8 || typ == 0)) || (proto == 58 && (typ == 128 || typ == 129))
	isError := (proto == 1 && (typ == 3 || typ == 4 || typ == 5 || typ == 11 || typ == 12)) || (proto == 58 && typ >= 1 && typ <= 4)
	switch {
	case echo:
		d.add(l, "Identifier", off+4, 2, fmt.Sprint(d.u16(off+4)))
		d.add(l, "Sequence Number", off+6, 2, fmt.Sprint(d.u16(off+6)))
		if d.has(off, 8) {
			l.Summary += fmt.Sprintf(", seq %d", d.u16(off+6))
		}
	case proto == 1 && typ == 3 && code == 4:
		d.add(l, "Unused", off+4, 2, "")
		d.add(l, "Next-Hop MTU", off+6, 2, fmt.Sprint(d.u16(off+6)))
	case proto == 58 && typ == 2:
		d.add(l, "MTU", off+4, 4, fmt.Sprint(d.u32(off+4)))
	case proto == 1 && typ == 5:
		d.add(l, "Gateway Address", off+4, 4, d.addr(off+4, 4))
	case proto == 58 && (typ == 135 || typ == 136):
		d.add(l, "Flags", off+4, 4, fmt.Sprintf("0x%08x", d.u32(off+4)))
		d.add(l, "Target Address", off+8, 16, d.addr(off+8, 16))
	default:
		d.add(l, "Rest of Header", off+4, 4, fmt.Sprintf("0x%08x", d.u32(off+4)))
	}
	hdr := 8
	if proto == 58 && (typ == 135 || typ == 136) {
		hdr = 24
	}
	at := d.end(l, min(off+hdr, limit))
	if at >= limit {
		return
	}
	switch {
	case isError && !quoted:
		// An error carries the start of the packet that caused it.
		d.ip(at, true)
	case echo:
		d.data("Echo data", at, limit)
	default:
		d.data("Data", at, limit)
	}
}

// DNS

var dnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
	41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

var dnsRcodes = map[uint16]string{0: "no error", 1: "format error", 2: "server failure", 3: "no such name", 4: "not implemented", 5: "refused"}

func dnsType(t uint16) string {
	if name, ok := dnsTypes[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

// dnsName reads a domain name at off. The base is where the DNS message
// starts: compression pointers count from it. It returns the name and the
// offset after it, or ok false when the name is cut or malformed.
func (d *dissector) dnsName(base, off int) (name string, next int, ok bool) {
	var labels []string
	next = -1
	for jumps := 0; jumps < 16; {
		if !d.has(off, 1) {
			return "", 0, false
		}
		n := int(d.b[off])
		switch {
		case n == 0:
			if next < 0 {
				next = off + 1
			}
			if len(labels) == 0 {
				return ".", next, true
			}
			return strings.Join(labels, "."), next, true
		case n&0xc0 == 0xc0:
			if !d.has(off, 2) {
				return "", 0, false
			}
			if next < 0 {
				next = off + 2
			}
			off = base + int(d.u16(off)&0x3fff)
			jumps++
		case n&0xc0 != 0:
			return "", 0, false
		default:
			if !d.has(off+1, n) || len(labels) > 127 {
				return "", 0, false
			}
			labels = append(labels, printable(d.b[off+1:off+1+n]))
			off += 1 + n
		}
	}
	return "", 0, false
}

// printable replaces the bytes that are not visible ASCII with dots.
func printable(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			c = '.'
		}
		out[i] = c
	}
	return string(out)
}

func (d *dissector) dns(off, limit int, overTCP bool) {
	l := d.begin(LayerApp, "DNS", off)
	if overTCP {
		d.add(l, "Message Length", off, 2, fmt.Sprint(d.u16(off)))
		off += 2
	}
	if !d.has(off, 12) {
		l.Kind, l.Name = LayerData, "Data"
		l.Fields = []Field{}
		d.end(l, limit)
		return
	}
	flags := d.u16(off + 2)
	kind := "query"
	if flags&0x8000 != 0 {
		kind = "response"
	}
	parts := []string{kind}
	if op := flags >> 11 & 0xf; op != 0 {
		parts = append(parts, fmt.Sprintf("opcode %d", op))
	}
	for _, f := range []struct {
		bit  uint16
		name string
	}{{0x0400, "authoritative"}, {0x0200, "truncated"}, {0x0100, "recursion desired"}, {0x0080, "recursion available"}} {
		if flags&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	if flags&0x8000 != 0 {
		rcode := flags & 0xf
		text, ok := dnsRcodes[rcode]
		if !ok {
			text = fmt.Sprintf("rcode %d", rcode)
		}
		parts = append(parts, text)
	}
	counts := [4]int{int(d.u16(off + 4)), int(d.u16(off + 6)), int(d.u16(off + 8)), int(d.u16(off + 10))}
	d.add(l, "Transaction ID", off, 2, hex16(d.u16(off)))
	d.add(l, "Flags", off+2, 2, fmt.Sprintf("%s (%s)", hex16(flags), strings.Join(parts, ", ")))
	d.add(l, "Questions", off+4, 2, fmt.Sprint(counts[0]))
	d.add(l, "Answer Records", off+6, 2, fmt.Sprint(counts[1]))
	d.add(l, "Authority Records", off+8, 2, fmt.Sprint(counts[2]))
	d.add(l, "Additional Records", off+10, 2, fmt.Sprint(counts[3]))
	l.Summary = kind

	at := off + 12
	done := func() {
		if rest := d.end(l, at); rest < limit {
			d.data("Data", rest, limit)
		}
	}
	for i := 0; i < counts[0] && i < 32; i++ {
		name, next, ok := d.dnsName(off, at)
		if !ok || !d.has(next, 4) {
			done()
			return
		}
		value := fmt.Sprintf("%s, type %s", name, dnsType(d.u16(next)))
		d.add(l, "Question", at, next+4-at, value)
		if i == 0 {
			l.Summary = fmt.Sprintf("%s: %s %s", kind, dnsType(d.u16(next)), name)
		}
		at = next + 4
	}
	sections := []string{"Answer", "Authority", "Additional"}
	for s, section := range sections {
		for i := 0; i < counts[s+1] && i < 64; i++ {
			name, next, ok := d.dnsName(off, at)
			if !ok || !d.has(next, 10) {
				done()
				return
			}
			typ, ttl, rdlen := d.u16(next), d.u32(next+4), int(d.u16(next+8))
			rdata := next + 10
			if !d.has(rdata, rdlen) {
				done()
				return
			}
			var value string
			if typ == 41 {
				// EDNS: the class field holds the UDP payload size.
				value = fmt.Sprintf("OPT (EDNS), UDP payload size %d", d.u16(next+2))
			} else {
				value = fmt.Sprintf("%s, type %s, TTL %d s", name, dnsType(typ), ttl)
				if text := d.dnsRdata(off, typ, rdata, rdlen); text != "" {
					value += ": " + text
				}
			}
			d.add(l, section, at, rdata+rdlen-at, value)
			at = rdata + rdlen
		}
	}
	done()
}

func (d *dissector) dnsRdata(base int, typ uint16, off, n int) string {
	switch {
	case typ == 1 && n == 4, typ == 28 && n == 16:
		return d.addr(off, n)
	case typ == 2 || typ == 5 || typ == 12:
		if name, _, ok := d.dnsName(base, off); ok {
			return name
		}
	case typ == 15 && n > 2:
		if name, _, ok := d.dnsName(base, off+2); ok {
			return fmt.Sprintf("%d %s", d.u16(off), name)
		}
	case typ == 16:
		var texts []string
		for i := off; i < off+n; {
			size := int(d.u8(i))
			if i+1+size > off+n {
				break
			}
			texts = append(texts, printable(d.b[i+1:i+1+size]))
			i += 1 + size
		}
		return fmt.Sprintf("%q", strings.Join(texts, ""))
	}
	return plural(n, "byte")
}

// HTTP

var httpMethods = []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func looksLikeHTTP(p []byte) bool {
	if bytes.HasPrefix(p, []byte("HTTP/1.")) {
		return true
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(p, []byte(m)) {
			// A request line ends with the protocol version.
			line, _, _ := bytes.Cut(p, []byte("\r\n"))
			return len(line) == len(p) || bytes.Contains(line, []byte(" HTTP/"))
		}
	}
	return false
}

func (d *dissector) http(off, limit int) {
	l := d.begin(LayerApp, "HTTP", off)
	at := off
	first := true
	for at < limit {
		rest := d.b[at:min(limit, len(d.b))]
		eol := bytes.Index(rest, []byte("\r\n"))
		if eol < 0 {
			// The capture cut the header short.
			if first {
				l.Summary = printable(rest)
			}
			d.add(l, "Header (cut short)", at, len(rest), printable(rest))
			at += len(rest)
			break
		}
		line := printable(rest[:eol])
		switch {
		case first:
			name := "Request Line"
			if strings.HasPrefix(line, "HTTP/") {
				name = "Status Line"
			}
			d.add(l, name, at, eol+2, line)
			l.Summary = line
		case eol == 0:
			d.add(l, "End of Headers", at, 2, "")
		default:
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				name, value = "Header", line
			}
			d.add(l, name, at, eol+2, strings.TrimSpace(value))
		}
		at += eol + 2
		if eol == 0 {
			break
		}
		first = false
	}
	if at = d.end(l, at); at < limit {
		d.data("HTTP body", at, limit)
	}
}

// TLS

var tlsContentTypes = map[uint8]string{20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data"}

var tlsHandshakeTypes = map[uint8]string{
	1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 8: "Encrypted Extensions", 11: "Certificate",
	12: "Server Key Exchange", 13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
	16: "Client Key Exchange", 20: "Finished",
}

func tlsVersion(v uint16) string {
	names := map[uint16]string{0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
	if name, ok := names[v]; ok {
		return fmt.Sprintf("%s (%s)", name, hex16(v))
	}
	return hex16(v)
}

func looksLikeTLS(p []byte) bool {
	return len(p) >= 5 && p[0] >= 20 && p[0] <= 23 && p[1] == 3 && p[2] <= 4 && binary.BigEndian.Uint16(p[3:]) <= 1<<14+256
}

func (d *dissector) tls(off, limit int) {
	at := off
	for records := 0; records < 16 && at < limit && looksLikeTLS(d.slice(at, limit-at)); records++ {
		typ, n := d.u8(at), int(d.u16(at+3))
		l := d.begin(LayerApp, "TLS "+tlsContentTypes[typ], at)
		l.Summary = plural(n, "byte")
		d.add(l, "Content Type", at, 1, fmt.Sprintf("%d (%s)", typ, tlsContentTypes[typ]))
		d.add(l, "Version", at+1, 2, tlsVersion(d.u16(at+1)))
		d.add(l, "Length", at+3, 2, fmt.Sprint(n))
		end := at + 5 + n
		switch typ {
		case 22:
			d.tlsHandshake(l, at+5, min(end, limit))
		case 21:
			if n == 2 {
				level := map[uint8]string{1: "warning", 2: "fatal"}[d.u8(at+5)]
				d.add(l, "Alert", at+5, 2, fmt.Sprintf("%s, description %d", level, d.u8(at+6)))
			} else {
				d.add(l, "Encrypted Alert", at+5, min(end, len(d.b))-at-5, "")
			}
		case 23:
			d.add(l, "Encrypted Data", at+5, min(end, len(d.b), limit)-at-5, "")
		}
		at = d.end(l, min(end, limit))
	}
	if at < limit {
		d.data("Data", at, limit)
	}
}

func (d *dissector) tlsHandshake(l *Layer, off, end int) {
	typ := d.u8(off)
	name, known := tlsHandshakeTypes[typ]
	n := int(d.u32(off) & 0xffffff)
	if !known || !d.has(off, 4) || off+4+n > end+1<<14 {
		// A handshake message after the key exchange is encrypted.
		d.add(l, "Encrypted Handshake Message", off, min(end, len(d.b))-off, "")
		return
	}
	d.add(l, "Handshake Type", off, 1, fmt.Sprintf("%d (%s)", typ, name))
	d.add(l, "Handshake Length", off+1, 3, fmt.Sprint(n))
	l.Name = "TLS " + name
	if typ != 1 && typ != 2 {
		return
	}
	at := off + 4
	d.add(l, "Version", at, 2, tlsVersion(d.u16(at)))
	d.add(l, "Random", at+2, 32, "32 bytes")
	at += 34
	sid := int(d.u8(at))
	d.add(l, "Session ID", at, 1+sid, plural(sid, "byte"))
	at += 1 + sid
	if typ == 1 {
		suites := int(d.u16(at))
		d.add(l, "Cipher Suites", at, 2+suites, plural(suites/2, "suite"))
		at += 2 + suites
		comp := int(d.u8(at))
		d.add(l, "Compression Methods", at, 1+comp, plural(comp, "method"))
		at += 1 + comp
	} else {
		d.add(l, "Cipher Suite", at, 2, hex16(d.u16(at)))
		d.add(l, "Compression Method", at+2, 1, fmt.Sprint(d.u8(at+2)))
		at += 3
	}
	if !d.has(at, 2) {
		return
	}
	extEnd := at + 2 + int(d.u16(at))
	d.add(l, "Extensions Length", at, 2, fmt.Sprint(d.u16(at)))
	at += 2
	for at+4 <= extEnd && d.has(at, 4) {
		ext, size := d.u16(at), int(d.u16(at+2))
		body := at + 4
		switch {
		case ext == 0 && size >= 5 && d.has(body, size):
			host := printable(d.slice(body+5, int(d.u16(body+3))))
			d.add(l, "Extension: Server Name", at, 4+size, host)
			l.Summary = host
		case ext == 16 && size >= 2 && d.has(body, size):
			var protos []string
			for i := body + 2; i < body+size; {
				k := int(d.u8(i))
				if k == 0 || i+1+k > body+size {
					break
				}
				protos = append(protos, printable(d.b[i+1:i+1+k]))
				i += 1 + k
			}
			d.add(l, "Extension: ALPN", at, 4+size, strings.Join(protos, ", "))
		case ext == 43 && d.has(body, size):
			var versions []string
			if typ == 2 && size == 2 {
				versions = append(versions, tlsVersion(d.u16(body)))
			} else {
				for i := body + 1; i+2 <= body+size; i += 2 {
					if v := d.u16(i); v&0x0f0f != 0x0a0a { // skip the GREASE values
						versions = append(versions, tlsVersion(v))
					}
				}
			}
			d.add(l, "Extension: Supported Versions", at, 4+size, strings.Join(versions, ", "))
		default:
			d.add(l, fmt.Sprintf("Extension: type %d", ext), at, 4+size, plural(size, "byte"))
		}
		at = body + size
	}
}

// DHCP

var dhcpMessageTypes = map[uint8]string{1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}

func (d *dissector) dhcp(off, limit int) {
	if !d.has(off, 44) || (d.u8(off) != 1 && d.u8(off) != 2) {
		d.data("Data", off, limit)
		return
	}
	l := d.begin(LayerApp, "DHCP", off)
	op := map[uint8]string{1: "request", 2: "reply"}[d.u8(off)]
	hlen := int(d.u8(off + 2))
	d.add(l, "Operation", off, 1, fmt.Sprintf("%d (%s)", d.u8(off), op))
	d.add(l, "Hardware Type", off+1, 1, fmt.Sprint(d.u8(off+1)))
	d.add(l, "Hardware Address Length", off+2, 1, fmt.Sprint(hlen))
	d.add(l, "Hops", off+3, 1, fmt.Sprint(d.u8(off+3)))
	d.add(l, "Transaction ID", off+4, 4, fmt.Sprintf("0x%08x", d.u32(off+4)))
	d.add(l, "Seconds Elapsed", off+8, 2, fmt.Sprint(d.u16(off+8)))
	flags := "none"
	if d.u16(off+10)&0x8000 != 0 {
		flags = "broadcast"
	}
	d.add(l, "Flags", off+10, 2, flags)
	d.add(l, "Client Address", off+12, 4, d.addr(off+12, 4))
	d.add(l, "Your Address", off+16, 4, d.addr(off+16, 4))
	d.add(l, "Server Address", off+20, 4, d.addr(off+20, 4))
	d.add(l, "Relay Address", off+24, 4, d.addr(off+24, 4))
	if hlen == 6 {
		d.add(l, "Client Hardware Address", off+28, 16, net.HardwareAddr(d.b[off+28:off+34]).String())
	} else {
		d.add(l, "Client Hardware Address", off+28, 16, "")
	}
	d.add(l, "Server Name", off+44, 64, cString(d.slice(off+44, 64)))
	d.add(l, "Boot File", off+108, 128, cString(d.slice(off+108, 128)))
	l.Summary = op
	if d.u32(off+236) != 0x63825363 {
		d.end(l, limit)
		return
	}
	d.add(l, "Magic Cookie", off+236, 4, "DHCP")
	at := off + 240
	for at < limit && d.has(at, 1) {
		code := d.u8(at)
		if code == 0 {
			at++
			continue
		}
		if code == 255 {
			d.add(l, "Option: End", at, 1, "")
			at++
			break
		}
		n := int(d.u8(at + 1))
		if !d.has(at, 2+n) {
			break
		}
		body := at + 2
		addrs := func() string {
			var list []string
			for i := body; i+4 <= body+n; i += 4 {
				list = append(list, d.addr(i, 4))
			}
			return strings.Join(list, ", ")
		}
		switch {
		case code == 53 && n == 1:
			name := dhcpMessageTypes[d.u8(body)]
			d.add(l, "Option: Message Type", at, 2+n, fmt.Sprintf("%d (%s)", d.u8(body), name))
			l.Summary = name
		case code == 1:
			d.add(l, "Option: Subnet Mask", at, 2+n, addrs())
		case code == 3:
			d.add(l, "Option: Router", at, 2+n, addrs())
		case code == 6:
			d.add(l, "Option: DNS Servers", at, 2+n, addrs())
		case code == 12:
			d.add(l, "Option: Host Name", at, 2+n, printable(d.b[body:body+n]))
		case code == 15:
			d.add(l, "Option: Domain Name", at, 2+n, printable(d.b[body:body+n]))
		case code == 50:
			d.add(l, "Option: Requested Address", at, 2+n, addrs())
		case code == 51 && n == 4:
			d.add(l, "Option: Lease Time", at, 2+n, fmt.Sprintf("%d s", d.u32(body)))
		case code == 54:
			d.add(l, "Option: Server Identifier", at, 2+n, addrs())
		case code == 55:
			d.add(l, "Option: Parameter Request List", at, 2+n, plural(n, "parameter"))
		default:
			d.add(l, fmt.Sprintf("Option: code %d", code), at, 2+n, plural(n, "byte"))
		}
		at = body + n
	}
	if at = d.end(l, at); at < limit {
		d.data("Padding", at, limit)
	}
}

// cString returns the text before the first zero byte.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return printable(b)
}
