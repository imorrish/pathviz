package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Destination kinds of a frame.
const (
	KindUnicast   = "unicast"
	KindBroadcast = "broadcast"
	KindMulticast = "multicast"
)

// ARPInfo is the decoded body of an ARP message.
type ARPInfo struct {
	Op        string `json:"op"` // request, reply, or the number
	SenderMAC string `json:"senderMac"`
	SenderIP  string `json:"senderIp"`
	TargetMAC string `json:"targetMac"`
	TargetIP  string `json:"targetIp"`
}

// FrameInfo is the decoded part of an Ethernet frame.
type FrameInfo struct {
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	DstKind string `json:"dstKind"`
	// Type names the EtherType: ARP, IPv4, IPv6, or the number.
	Type string `json:"type"`
	// Info is a short summary of what the frame carries.
	Info string `json:"info"`
	// SrcIP and DstIP are the endpoints of an IP packet (with ports, if any),
	// or the sender and the target of an ARP message.
	SrcIP string   `json:"srcIp,omitempty"`
	DstIP string   `json:"dstIp,omitempty"`
	ARP   *ARPInfo `json:"arp,omitempty"`
}

// Seen is what a probe saw: a frame, an IP packet, or an IP packet in a frame.
type Seen struct {
	Frame  *FrameInfo
	Packet *Packet
	// key identifies the packet at all the hooks of all the layers. For an IP
	// packet it is made of what neither NAT nor routing rewrites, so it does
	// not depend on the Ethernet header.
	key string
}

// maxFramePayload caps how many payload bytes of a frame that is not an IP
// packet take part in its key.
const maxFramePayload = 64

func macKind(mac []byte) string {
	switch {
	case mac[0]&mac[1]&mac[2]&mac[3]&mac[4]&mac[5] == 0xff:
		return KindBroadcast
	case mac[0]&1 == 1:
		return KindMulticast
	}
	return KindUnicast
}

// ParseSeen decodes what a probe logged: the Ethernet header (nil when the
// probe has none, as the IP hooks and the loopback device) and what follows
// it. etherType tells what follows when there is no header. The payload may
// be truncated (NFLOG copies only a prefix).
func ParseSeen(l2, payload []byte, etherType uint16) (Seen, error) {
	var s Seen
	if len(l2) >= 14 {
		etherType = binary.BigEndian.Uint16(l2[len(l2)-2:])
		s.Frame = &FrameInfo{
			Dst:     net.HardwareAddr(l2[0:6]).String(),
			Src:     net.HardwareAddr(l2[6:12]).String(),
			DstKind: macKind(l2[0:6]),
			Type:    etherTypeName(etherType),
		}
	} else {
		l2 = nil
	}
	rawKey := func() string {
		return "eth\x00" + string(l2) + string(payload[:min(len(payload), maxFramePayload)])
	}
	switch etherType {
	case 0x0800, 0x86dd:
		p, err := ParsePacket(payload)
		if err != nil {
			if s.Frame == nil {
				return s, err
			}
			s.Frame.Info = "malformed packet"
			s.key = rawKey()
			return s, nil
		}
		s.Packet = &p
		s.key = "ip\x00" + p.fingerprint
		if s.Frame != nil {
			s.Frame.SrcIP, s.Frame.DstIP = p.SrcString(), p.DstString()
			s.Frame.Info = strings.TrimSpace(ipProtoName(p.Proto) + " " + p.Info)
		}
	default:
		if s.Frame == nil {
			return s, fmt.Errorf("neither a frame nor an IP packet (type 0x%04x)", etherType)
		}
		if etherType == 0x0806 {
			parseARP(s.Frame, payload)
		} else {
			s.Frame.Info = textOf(payload)
		}
		s.key = rawKey()
	}
	return s, nil
}

func parseARP(f *FrameInfo, b []byte) {
	// Ethernet and IPv4 only: hardware type 1, protocol 0x0800, sizes 6 and 4.
	if len(b) < 28 || b[0] != 0 || b[1] != 1 || b[2] != 0x08 || b[3] != 0 || b[4] != 6 || b[5] != 4 {
		f.Info = "ARP message"
		return
	}
	a := &ARPInfo{
		SenderMAC: net.HardwareAddr(b[8:14]).String(),
		SenderIP:  netip.AddrFrom4([4]byte(b[14:18])).String(),
		TargetMAC: net.HardwareAddr(b[18:24]).String(),
		TargetIP:  netip.AddrFrom4([4]byte(b[24:28])).String(),
	}
	f.ARP = a
	f.SrcIP, f.DstIP = a.SenderIP, a.TargetIP
	switch op := binary.BigEndian.Uint16(b[6:8]); op {
	case 1:
		a.Op = "request"
		if a.SenderIP == a.TargetIP {
			f.Info = fmt.Sprintf("Announcement: %s is at %s", a.SenderIP, a.SenderMAC)
		} else {
			f.Info = fmt.Sprintf("Who has %s? Tell %s", a.TargetIP, a.SenderIP)
		}
	case 2:
		a.Op = "reply"
		f.Info = fmt.Sprintf("%s is at %s", a.SenderIP, a.SenderMAC)
	default:
		a.Op = fmt.Sprint(op)
		f.Info = fmt.Sprintf("ARP operation %d", op)
	}
}

func etherTypeName(t uint16) string {
	switch t {
	case 0x0806:
		return "ARP"
	case 0x0800:
		return "IPv4"
	case 0x86dd:
		return "IPv6"
	case 0x8100:
		return "802.1Q"
	case 0x88cc:
		return "LLDP"
	case 0x8035:
		return "RARP"
	}
	if t < 0x0600 {
		// An 802.3 length field: STP and other LLC frames.
		return "802.3"
	}
	return fmt.Sprintf("0x%04x", t)
}

// ipProtoName names the protocol of an IP packet for the summary of a frame.
func ipProtoName(proto string) string {
	switch proto {
	case "2":
		return "IGMP"
	case "tcp", "udp", "icmp":
		return strings.ToUpper(proto)
	case "icmpv6":
		return "ICMPv6"
	}
	return "IP protocol " + proto
}

// textOf shows a payload that is plain text (as a hand-made test frame often
// is) in quotes. Any other payload gives an empty string.
func textOf(payload []byte) string {
	// A short frame is padded with zeros up to the minimum size.
	text := strings.TrimRight(string(payload[:min(len(payload), maxFramePayload)]), "\x00")
	if text == "" {
		return ""
	}
	for _, r := range text {
		if r < ' ' || r > '~' {
			return ""
		}
	}
	return strconv.Quote(text)
}
