package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// A small reader of NFLOG groups (the nfnetlink_log subsystem of the kernel).
// PathViz has its own, because the probes of devices log in the netdev family,
// and the common libraries read only the IP and the bridge families.

const (
	nfnlSubsysULOG = 4
	nfulMsgPacket  = 0
	nfulMsgConfig  = 1

	// Attributes of a config message.
	nfulaCfgCmd     = 1
	nfulaCfgMode    = 2
	nfulaCfgQThresh = 5
	nfulaCfgFlags   = 6

	nfulCmdBind   = 1
	nfulCopyBytes = 2 // NFULNL_COPY_PACKET
	nfulFlagSeq   = 1

	// Attributes of a logged packet.
	nfulaPacketHdr  = 1
	nfulaMark       = 2
	nfulaInDev      = 4
	nfulaOutDev     = 5
	nfulaPhysInDev  = 6
	nfulaPhysOutDev = 7
	nfulaPayload    = 9
	nfulaPrefix     = 10
	nfulaSeq        = 12
	nfulaHwType     = 15
	nfulaHwHeader   = 16
	nfulaVLAN       = 20
	nfulaL2Hdr      = 21

	nfulaVLANTCI = 2
)

// LogRecord is one packet as a probe logged it.
type LogRecord struct {
	Prefix string
	// The devices are interface indexes, 0 when unknown. Under a bridge, the
	// "physical" ones are the ports and the others are the bridge.
	InDev, OutDev         uint32
	PhysInDev, PhysOutDev uint32
	Mark                  uint32
	// EtherType is the protocol of the packet as the kernel sees it.
	EtherType uint16
	// HwType is the ARPHRD type of the input device: 1 is Ethernet.
	HwType uint16
	// HwHeader is the link-layer header, when the kernel hands it over apart
	// from the payload.
	HwHeader []byte
	Payload  []byte
	VLAN     uint16
	Seq      uint32
	HasSeq   bool
}

// LogReader reads one NFLOG group of a network namespace.
type LogReader struct {
	conn *netlink.Conn
}

// OpenLog binds to an NFLOG group in a namespace. The kernel copies up to
// copyRange bytes of every packet.
func OpenLog(ns Netns, group int, copyRange int) (*LogReader, error) {
	cfg := &netlink.Config{}
	if !ns.Home {
		f, err := os.Open(ns.Path)
		if err != nil {
			return nil, fmt.Errorf("open the network namespace: %w", err)
		}
		// The socket stays in the namespace after the file is closed.
		defer f.Close()
		cfg.NetNS = int(f.Fd())
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, cfg)
	if err != nil {
		return nil, err
	}
	r := &LogReader{conn: conn}
	mode := binary.BigEndian.AppendUint32(nil, uint32(copyRange))
	mode = append(mode, nfulCopyBytes, 0)
	steps := [][2]any{
		{nfulaCfgCmd, []byte{nfulCmdBind}},
		{nfulaCfgMode, mode},
		// Deliver every packet right away instead of batching.
		{nfulaCfgQThresh, binary.BigEndian.AppendUint32(nil, 1)},
		// Per-group sequence numbers reveal lost records.
		{nfulaCfgFlags, binary.BigEndian.AppendUint16(nil, nfulFlagSeq)},
	}
	for _, s := range steps {
		if err := r.config(group, uint16(s[0].(int)), s[1].([]byte)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("set up NFLOG group %d: %w", group, err)
		}
	}
	return r, nil
}

func (r *LogReader) config(group int, attr uint16, value []byte) error {
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: attr, Data: value}})
	if err != nil {
		return err
	}
	// struct nfgenmsg: the family, the version, and the group in network order.
	head := []byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, byte(group >> 8), byte(group)}
	_, err = r.conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(nfnlSubsysULOG<<8 | nfulMsgConfig),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(head, attrs...),
	})
	return err
}

// SetReadBuffer sets the size of the socket's receive buffer.
func (r *LogReader) SetReadBuffer(bytes int) error { return r.conn.SetReadBuffer(bytes) }

// Close releases the socket. A blocked Receive returns with an error.
func (r *LogReader) Close() error { return r.conn.Close() }

// Receive waits for the next records. An error of the ENOBUFS kind means that
// the kernel dropped records for this socket, and reading can go on.
func (r *LogReader) Receive() ([]LogRecord, error) {
	msgs, err := r.conn.Receive()
	if err != nil {
		return nil, err
	}
	var out []LogRecord
	for _, m := range msgs {
		if m.Header.Type != netlink.HeaderType(nfnlSubsysULOG<<8|nfulMsgPacket) {
			continue
		}
		if rec, ok := parseLogRecord(m.Data); ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

// parseLogRecord decodes the body of a packet message: a struct nfgenmsg and
// the attributes.
func parseLogRecord(data []byte) (LogRecord, bool) {
	var rec LogRecord
	if len(data) < 4 {
		return rec, false
	}
	ad, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return rec, false
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case nfulaPacketHdr:
			if b := ad.Bytes(); len(b) >= 2 {
				rec.EtherType = binary.BigEndian.Uint16(b)
			}
		case nfulaMark:
			rec.Mark = ad.Uint32()
		case nfulaInDev:
			rec.InDev = ad.Uint32()
		case nfulaOutDev:
			rec.OutDev = ad.Uint32()
		case nfulaPhysInDev:
			rec.PhysInDev = ad.Uint32()
		case nfulaPhysOutDev:
			rec.PhysOutDev = ad.Uint32()
		case nfulaPayload:
			rec.Payload = ad.Bytes()
		case nfulaPrefix:
			rec.Prefix = ad.String()
		case nfulaSeq:
			rec.Seq, rec.HasSeq = ad.Uint32(), true
		case nfulaHwType:
			rec.HwType = ad.Uint16()
		case nfulaHwHeader, nfulaL2Hdr:
			// The bridge hooks hand the header over as the "layer 2 header",
			// and the others as the "hardware header". It is the same thing.
			if rec.HwHeader == nil || ad.Type() == nfulaL2Hdr {
				rec.HwHeader = ad.Bytes()
			}
		case nfulaVLAN:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				nad.ByteOrder = binary.BigEndian
				for nad.Next() {
					if nad.Type() == nfulaVLANTCI {
						rec.VLAN = nad.Uint16() & 0x0fff
					}
				}
				return nil
			})
		}
	}
	return rec, ad.Err() == nil
}
