package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// How many bytes of every packet the kernel copies to pathviz.
const (
	// headerRange holds the headers and the fingerprinted payload prefix with
	// a wide margin. It is used when the packet view is disabled.
	headerRange = 256
	// packetRange holds a whole packet of a usual 1500-byte MTU, so the packet
	// view can show its payload (e.g. the options of a DHCP message or a TLS
	// Client Hello).
	packetRange = 2048
)

// Event is one probe hit: a packet seen at one point of a hook.
type Event struct {
	Time time.Time
	// Layer is l1, l2, or l3. Hook is INGRESS or EGRESS for l1, and a netfilter
	// hook for the others. Stage is a classic stage of an IP hook (raw, mangle,
	// ...), "enter" for the start of a link or a bridge hook, or "exit".
	Layer string
	Hook  string
	Stage string
	// In and Out are the devices as the hook knows them. For a bridge hook they
	// are the ports, and Bridge is the bridge. An IP hook that runs for a bridged
	// packet (br_netfilter) names the bridge, and has the ports in PhysIn and
	// PhysOut.
	In, Out         string
	PhysIn, PhysOut string
	Bridge          string
	VLAN            uint16
	Mark            uint32
	Seen
	// Raw is the captured part of the packet, with its first L2Len bytes being
	// the Ethernet header. It is nil when the packet view is disabled.
	Raw   []byte
	L2Len int
}

// device is what a capture knows about a device of its namespace.
type device struct {
	name   string
	master string
	ether  bool
}

// Capture reads the probe events of one network namespace.
type Capture struct {
	ctx    context.Context
	stop   context.CancelFunc
	log    *LogReader
	onSeen func(Event)
	onLost func(time.Time)
	// keepBytes makes the events carry the captured bytes for the packet view.
	keepBytes bool

	mu sync.Mutex
	// ns is the namespace, with a path that opens it now.
	ns       Netns
	devs     map[uint32]device
	devsRead time.Time
	lastSeq  uint32
	haveSeq  bool
	lost     uint64
}

// StartCapture binds to the NFLOG group of a namespace and reports the events
// until ctx is done or the capture is closed. With keepBytes it captures whole
// packets. Without it only the headers are captured, and they are dropped once
// parsed.
func StartCapture(ctx context.Context, ns Netns, group int, keepBytes bool, onSeen func(Event), onLost func(time.Time)) (*Capture, error) {
	copyRange := headerRange
	if keepBytes {
		copyRange = packetRange
	}
	lr, err := OpenLog(ns, group, copyRange)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			// The kernel gives a group to one reader at a time.
			return nil, fmt.Errorf("NFLOG group %d is taken: is another pathviz watching this namespace? (--group picks another group)", group)
		}
		return nil, fmt.Errorf("open NFLOG group %d: %w", group, err)
	}
	if err := lr.SetReadBuffer(8 << 20); err != nil {
		log.Printf("warning: cannot enlarge the netlink buffer: %v", err)
	}
	c := &Capture{log: lr, onSeen: onSeen, onLost: onLost, keepBytes: keepBytes, ns: ns, devs: map[uint32]device{}}
	c.ctx, c.stop = context.WithCancel(ctx)
	go func() {
		<-c.ctx.Done()
		lr.Close()
	}()
	go c.read()
	return c, nil
}

// SetNetns updates the way into the namespace: the process whose /proc entry
// opened it may be gone, while another one still lives there.
func (c *Capture) SetNetns(ns Netns) {
	c.mu.Lock()
	c.ns = ns
	c.mu.Unlock()
}

// Close stops the capture and releases its socket.
func (c *Capture) Close() { c.stop() }

// LostEvents returns how many probe events were lost so far.
func (c *Capture) LostEvents() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lost
}

func (c *Capture) read() {
	for {
		recs, err := c.log.Receive()
		now := time.Now()
		if err != nil {
			if c.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return // shutting down
			}
			// ENOBUFS and friends mean the kernel dropped events for this socket.
			c.mu.Lock()
			c.lost++
			c.mu.Unlock()
			c.onLost(now)
			log.Printf("capture error: %v", err)
			// Anything else than a full buffer would repeat forever.
			if !strings.Contains(err.Error(), "no buffer space") {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		for _, rec := range recs {
			c.onRecord(now, rec)
		}
	}
}

func (c *Capture) onRecord(now time.Time, rec LogRecord) {
	if rec.HasSeq {
		c.mu.Lock()
		gap := c.haveSeq && rec.Seq != c.lastSeq+1
		if gap {
			c.lost += uint64(rec.Seq - c.lastSeq - 1)
		}
		c.lastSeq, c.haveSeq = rec.Seq, true
		c.mu.Unlock()
		if gap {
			c.onLost(now)
		}
	}
	// The prefix is "<layer>:<stage>/<HOOK>".
	layer, rest, ok := strings.Cut(rec.Prefix, ":")
	stage, hook, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 {
		return
	}
	ev := Event{Time: now, Layer: layer, Hook: hook, Stage: stage, VLAN: rec.VLAN, Mark: rec.Mark}
	l2, payload, etherType := rec.HwHeader, rec.Payload, rec.EtherType
	switch layer {
	case L3:
		// The IP hooks log the packet from the IP header on.
		l2 = nil
		ev.In, ev.Out = c.device(rec.InDev).name, c.device(rec.OutDev).name
		ev.PhysIn, ev.PhysOut = c.device(rec.PhysInDev).name, c.device(rec.PhysOutDev).name
		if len(payload) > 0 && payload[0]>>4 == 6 {
			etherType = 0x86dd
		} else {
			etherType = 0x0800
		}
	case L2:
		// The kernel reports the port as the "physical" device and the bridge as
		// the device. Without br_netfilter support in the kernel there is only the
		// device, and it is the port.
		ev.In, ev.Bridge = c.portAndBridge(rec.PhysInDev, rec.InDev, "")
		ev.Out, ev.Bridge = c.portAndBridge(rec.PhysOutDev, rec.OutDev, ev.Bridge)
		if ev.Bridge == "" || len(l2) < 14 {
			return
		}
	case L1:
		if hook == "EGRESS" {
			dev := c.device(rec.OutDev)
			if rec.OutDev == 0 {
				dev = c.device(rec.InDev)
			}
			ev.Out = dev.name
			// On its way out the frame is complete: the header leads the payload.
			if l2 == nil && dev.ether && len(payload) >= 14 {
				l2, payload = payload[:14], payload[14:]
			}
		} else {
			ev.In = c.device(rec.InDev).name
		}
		// Only an Ethernet header has MAC addresses (the loopback device has
		// an empty one).
		if rec.HwType != 0 && rec.HwType != 1 {
			l2 = nil
		}
	default:
		return
	}
	seen, err := ParseSeen(l2, payload, etherType)
	if err != nil {
		return
	}
	ev.Seen = seen
	if c.keepBytes {
		// The bytes are copied: the journey keeps them after this call returns.
		if seen.Frame != nil {
			ev.Raw = append(bytes.Clone(l2), payload...)
			ev.L2Len = len(l2)
		} else {
			ev.Raw = bytes.Clone(payload)
		}
	}
	c.onSeen(ev)
}

func (c *Capture) portAndBridge(phys, dev uint32, bridge string) (string, string) {
	switch {
	case phys != 0 && dev != 0:
		return c.device(phys).name, c.device(dev).name
	case dev != 0:
		port := c.device(dev)
		if port.master != "" {
			return port.name, port.master
		}
		return port.name, bridge
	}
	return "", bridge
}

// device names a device of the namespace by its index. The devices are read
// anew when an unknown index shows up.
func (c *Capture) device(idx uint32) device {
	if idx == 0 {
		return device{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.devs[idx]; ok {
		return d
	}
	if time.Since(c.devsRead) > 200*time.Millisecond {
		c.devsRead = time.Now()
		var links []ipLink
		if out, err := c.ns.output(2*time.Second, "ip", "-j", "link", "show"); err == nil && json.Unmarshal(out, &links) == nil {
			c.devs = map[uint32]device{}
			for _, l := range links {
				c.devs[uint32(l.Ifindex)] = device{name: l.Name, master: l.Master, ether: l.LinkType == "ether"}
			}
		}
	}
	if d, ok := c.devs[idx]; ok {
		return d
	}
	return device{name: fmt.Sprintf("if%d", idx)}
}
