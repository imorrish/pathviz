package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Hop is a probe hit as it is shown to the user.
type Hop struct {
	Layer string `json:"layer"` // l1, l2, l3
	Hook  string `json:"hook"`
	Stage string `json:"stage"`
	Exit  bool   `json:"exit,omitempty"`
	In    string `json:"in,omitempty"`
	Out   string `json:"out,omitempty"`
	// PhysIn and PhysOut are the bridge ports of a bridged packet in an IP hook.
	PhysIn  string `json:"pin,omitempty"`
	PhysOut string `json:"pout,omitempty"`
	// Bridge is the bridge of a bridge hook.
	Bridge string `json:"bridge,omitempty"`
	// Src and Dst are the IP endpoints at this point, if it is an IP packet.
	Src  string `json:"src,omitempty"`
	Dst  string `json:"dst,omitempty"`
	TTL  uint8  `json:"ttl,omitempty"`
	Mark uint32 `json:"mark,omitempty"`
	// SMAC and DMAC are the Ethernet addresses at this point, if the hook sees them.
	SMAC string `json:"smac,omitempty"`
	DMAC string `json:"dmac,omitempty"`
	// Micros is the time since the first hop of the journey.
	Micros int64 `json:"us"`
	// Rewrote describes what this stage changed in the packet, if anything.
	// It is known because the next probe saw different addresses.
	Rewrote string `json:"rewrote,omitempty"`
	// Copy tells which copy of the packet this is: 0 before a bridge copied
	// it, else the ID of a Copy.
	Copy int `json:"copy,omitempty"`
}

// Copy is one copy of a frame that a bridge made: for one of its ports, or
// for the network stack above it. A flooded frame has a copy per port.
type Copy struct {
	ID int `json:"id"`
	// Parent is the copy that arrived at the bridge, 0 for the original.
	Parent int    `json:"parent,omitempty"`
	Bridge string `json:"bridge"`
	// To is the port. It is empty for the copy that goes up to the stack.
	To   string `json:"to,omitempty"`
	Host bool   `json:"host,omitempty"`
}

// Verdicts of the IP hooks about a packet.
const (
	VerdictDelivered = "delivered" // passed INPUT, handed to the local transport layer
	VerdictSent      = "sent"      // passed POSTROUTING, handed to the output device
	VerdictStopped   = "stopped"   // entered a stage or a routing step and was never seen again
)

// IPStory is what the IP hooks did with a packet.
type IPStory struct {
	// Hops are the indexes of the journey's hops that belong to this story.
	// When a bridge copied the packet, they follow one copy.
	Hops    []int  `json:"hops"`
	Verdict string `json:"verdict"`
	// StoppedHook and StoppedStage tell where a stopped packet was last seen.
	// StoppedStage is "routing" when the packet left the hook and got lost before the next one.
	StoppedHook  string `json:"stoppedHook,omitempty"`
	StoppedStage string `json:"stoppedStage,omitempty"`
	// Path is the sequence of hooks, e.g. "PREROUTING INPUT".
	Path []string `json:"path"`
	// From is the local process that sent the packet, and To is the local
	// process that received it. They are nil when unknown or not applicable.
	From *Owner `json:"from,omitempty"`
	To   *Owner `json:"to,omitempty"`
	// Partial is set when the first hop is not the first stage of PREROUTING or
	// OUTPUT. The packet started to match the filter only at that stage (e.g.
	// after NAT rewrote it), so the earlier part of its path is unknown.
	Partial bool `json:"partial,omitempty"`
}

// Outcomes of a copy of a frame, and of its way into a bridge or through a
// device hook.
const (
	OutcomeSent      = "sent"      // passed POSTROUTING, handed to the port
	OutcomeDelivered = "delivered" // passed INPUT, handed to the network stack
	OutcomeDropped   = "dropped"   // entered a hook and never left it
	OutcomeLost      = "lost"      // left a hook and never reached the next one
	OutcomePassed    = "passed"    // passed the hook
)

// Leg is one copy of a frame on its way out of a bridge: to a port, or up to
// the network stack.
type Leg struct {
	Copy int `json:"copy"`
	// To is the port. It is empty for the copy that goes up.
	To    string   `json:"to"`
	Host  bool     `json:"host,omitempty"`
	Hooks []string `json:"hooks"` // the hooks the copy entered, in order
	// Outcome is sent, delivered, dropped, or lost.
	Outcome string `json:"outcome"`
	// StoppedHook is the hook that dropped the copy, or the one it was last seen leaving.
	StoppedHook string `json:"stoppedHook,omitempty"`
	// Known tells that the bridge's MAC table had the destination behind this port.
	Known bool `json:"known,omitempty"`
}

// Decisions of a bridge about a frame.
const (
	DecisionForward = "forward" // one copy, to one port
	DecisionFlood   = "flood"   // a copy to every port
	DecisionLocal   = "local"   // up to the network stack only
	DecisionDrop    = "drop"    // nowhere
)

// BridgeStory is what one bridge did with a frame.
type BridgeStory struct {
	Bridge string `json:"bridge"`
	// Parent is the copy that arrived at this bridge: 0, unless another bridge
	// of the same namespace sent it here.
	Parent int `json:"parent,omitempty"`
	// In is the port the frame came in through. It is empty for a frame that
	// the network stack sent through the bridge device.
	In      string `json:"in"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	DstKind string `json:"dstKind"`
	VLAN    uint16 `json:"vlan,omitempty"`
	// Ingress tells how PREROUTING went: passed or dropped. It is empty when
	// the frame was not seen there.
	Ingress  string `json:"ingress,omitempty"`
	Legs     []Leg  `json:"legs"`
	Decision string `json:"decision"`
	// Learned tells that this frame taught the bridge where its source lives.
	Learned bool `json:"learned,omitempty"`
}

// LinkCrossing is one pass of a frame through a hook of a device.
type LinkCrossing struct {
	Dev  string `json:"dev"`
	Hook string `json:"hook"` // INGRESS or EGRESS
	// Outcome is passed or dropped.
	Outcome string `json:"outcome"`
	Copy    int    `json:"copy,omitempty"`
}

// Journey is the path of one packet through the hooks of a namespace, on all
// the layers that saw it.
type Journey struct {
	ID   uint64    `json:"id"`
	Time time.Time `json:"time"`
	// Frame is the Ethernet frame as it was first seen. It is nil when only
	// the IP hooks saw the packet.
	Frame *FrameInfo `json:"frame,omitempty"`
	// The fields below describe an IP packet as it was first seen. Proto is
	// empty for a frame that carries something else.
	Proto string `json:"proto,omitempty"`
	Src   string `json:"src,omitempty"`
	Dst   string `json:"dst,omitempty"`
	Len   int    `json:"len,omitempty"`
	Info  string `json:"info,omitempty"`
	// Detail holds the longer L4 facts, e.g. the TCP sequence numbers.
	Detail string `json:"detail,omitempty"`
	Hops   []Hop  `json:"hops"`
	Copies []Copy `json:"copies,omitempty"`

	// What every layer made of the hops. A layer that saw nothing has no story.
	Links   []LinkCrossing `json:"l1,omitempty"`
	Bridges []BridgeStory  `json:"l2,omitempty"`
	IP      *IPStory       `json:"l3,omitempty"`

	// Unreliable is set when probe events were lost around this journey, so a
	// drop may be reported wrongly.
	Unreliable bool `json:"unreliable,omitempty"`

	lastSeen time.Time
	seen     map[[6]string]bool
	arp      *ARPInfo
	// vlans are the VLAN tags that the hooks of the bridges reported.
	vlans map[string]uint16
	// raw holds the captured bytes of the packet at every hop, in the order of
	// Hops, and l2len how many of them are the Ethernet header.
	raw   [][]byte
	l2len []int
}

const (
	// idleTimeout is how long a journey waits for more hops. All hooks of one
	// packet fire within microseconds, so this is generous.
	idleTimeout = 200 * time.Millisecond
	// lossWindow marks journeys around a lost probe event as unreliable.
	lossWindow = time.Second
)

// Tracker groups events into journeys.
type Tracker struct {
	mu       sync.Mutex
	open     map[string]*Journey
	nextID   uint64
	lastLoss time.Time
	emit     func(*Journey)
	// peer names the other end of a veth device when it lives in the same
	// namespace. It may be nil.
	peer func(dev string) string
}

// NewTracker creates a tracker that calls emit for every finished journey.
// The emit function is called with the tracker locked and must not block.
func NewTracker(emit func(*Journey), peer func(dev string) string) *Tracker {
	return &Tracker{open: map[string]*Journey{}, emit: emit, peer: peer}
}

// Add records one event.
func (t *Tracker) Add(ev Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// An IP stage is crossed once, or once per bridge port by a bridged packet
	// (br_netfilter). A device or a bridge hook is crossed once per device: a
	// flooded frame enters FORWARD once per port.
	at := [6]string{ev.Layer, ev.Hook, ev.Stage, ev.PhysIn, ev.PhysOut}
	if ev.Layer != L3 {
		at[3], at[4], at[5] = ev.In, ev.Out, ev.Bridge
	}
	j := t.open[ev.key]
	if j != nil && (j.seen[at] || ev.Time.Sub(j.lastSeen) > idleTimeout) {
		// The same packet cannot be at one place twice, so this is another
		// packet that looks the same (e.g. a duplicate ACK, a repeated ARP request).
		t.finish(ev.key, j)
		j = nil
	}
	if j == nil {
		t.nextID++
		j = &Journey{ID: t.nextID, Time: ev.Time, seen: map[[6]string]bool{}}
		t.open[ev.key] = j
	}
	if j.Frame == nil && ev.Frame != nil {
		j.Frame = ev.Frame
		j.arp = ev.Frame.ARP
	}
	if j.Proto == "" && ev.Packet != nil {
		p := ev.Packet
		j.Proto, j.Src, j.Dst, j.Len, j.Info, j.Detail = p.Proto, p.SrcString(), p.DstString(), p.Len, p.Info, p.Detail
	}
	j.seen[at] = true
	j.lastSeen = ev.Time
	j.raw = append(j.raw, ev.Raw)
	j.l2len = append(j.l2len, ev.L2Len)
	h := Hop{
		Layer: ev.Layer, Hook: ev.Hook, Stage: ev.Stage, Exit: ev.Stage == exitStage,
		In: ev.In, Out: ev.Out, PhysIn: ev.PhysIn, PhysOut: ev.PhysOut, Bridge: ev.Bridge,
		Mark: ev.Mark, Micros: ev.Time.Sub(j.Time).Microseconds(),
	}
	if ev.Packet != nil {
		h.Src, h.Dst, h.TTL = ev.Packet.SrcString(), ev.Packet.DstString(), ev.Packet.TTL
	}
	if ev.Frame != nil {
		h.SMAC, h.DMAC = ev.Frame.Src, ev.Frame.Dst
	}
	if ev.VLAN != 0 && ev.Bridge != "" {
		if j.vlans == nil {
			j.vlans = map[string]uint16{}
		}
		j.vlans[ev.Bridge] = ev.VLAN
	}
	j.Hops = append(j.Hops, h)
}

// Lost records that probe events were lost at the given time.
func (t *Tracker) Lost(at time.Time) {
	t.mu.Lock()
	t.lastLoss = at
	t.mu.Unlock()
}

// Flush finishes the journeys that have been idle for long enough.
func (t *Tracker) Flush(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var done []string
	for key, j := range t.open {
		if now.Sub(j.lastSeen) > idleTimeout {
			done = append(done, key)
		}
	}
	// Emit in the order the packets were first seen.
	sort.Slice(done, func(a, b int) bool { return t.open[done[a]].ID < t.open[done[b]].ID })
	for _, key := range done {
		t.finish(key, t.open[key])
	}
}

func (t *Tracker) finish(key string, j *Journey) {
	delete(t.open, key)
	finalize(j, t.peer)
	if !t.lastLoss.IsZero() && j.Time.Sub(t.lastLoss) < lossWindow && t.lastLoss.Sub(j.lastSeen) < lossWindow {
		j.Unreliable = true
	}
	t.emit(j)
}

// finalize derives the copies and the story of every layer from the hops.
func finalize(j *Journey, peer func(string) string) {
	assignCopies(j, peer)
	j.Links = linkStory(j)
	j.Bridges = bridgeStories(j)
	j.IP = ipStory(j)
}

// assignCopies tells the hops of the copies that the bridges made apart.
//
// The kernel handles one copy at a time, from the hook that made it down to
// the device, so most hops belong to the copy of the hop before them. The
// exceptions are told by the devices: a hop on a device that an earlier copy
// left through belongs to that copy. This matters when both ends of a veth
// pair live in the namespace, because the far end sees the frame only later.
func assignCopies(j *Journey, peer func(string) string) {
	owner := map[string]int{}    // device to the copy that goes through it
	trunk := map[string]bool{}   // devices of the packet before any copy
	crossing := map[string]int{} // bridge to the copy that arrived at it
	index := map[[3]string]int{} // parent, bridge, and port to the copy
	cur := 0
	own := func(id int, devs ...string) {
		for _, d := range devs {
			if d == "" || trunk[d] || owner[d] != 0 {
				continue
			}
			owner[d] = id
			if peer != nil {
				if p := peer(d); p != "" && !trunk[p] && owner[p] == 0 {
					owner[p] = id
				}
			}
		}
	}
	copyOf := func(bridge, to string, host bool) int {
		parent, ok := crossing[bridge]
		if !ok {
			// The frame did not come in through a port of this bridge: the
			// network stack sent it.
			parent = cur
			crossing[bridge] = parent
		}
		key := [3]string{fmt.Sprint(parent), bridge, to}
		if host {
			key[2] = "\x00up"
		}
		if id, ok := index[key]; ok {
			return id
		}
		c := Copy{ID: len(j.Copies) + 1, Parent: parent, Bridge: bridge, To: to, Host: host}
		j.Copies = append(j.Copies, c)
		index[key] = c.ID
		return c.ID
	}
	for i := range j.Hops {
		h := &j.Hops[i]
		switch {
		case h.Layer == L2 && h.Hook == "PREROUTING":
			h.Copy = owner[h.In]
			crossing[h.Bridge] = h.Copy
			if h.Copy == 0 {
				trunk[h.In] = true
			}
		case h.Layer == L2 && h.Hook == "INPUT":
			h.Copy = copyOf(h.Bridge, "", true)
			own(h.Copy, h.Bridge)
		case h.Layer == L2:
			h.Copy = copyOf(h.Bridge, h.Out, false)
			own(h.Copy, h.Out)
		default:
			for _, d := range []string{h.PhysOut, h.Out, h.PhysIn, h.In} {
				if d != "" && owner[d] != 0 {
					h.Copy = owner[d]
					break
				}
			}
			if h.Copy == 0 {
				h.Copy = cur
			}
			if h.Copy == 0 {
				trunk[h.In], trunk[h.Out] = true, true
			} else {
				own(h.Copy, h.Out)
				if h.Layer == L1 {
					own(h.Copy, h.In)
				}
			}
		}
		cur = h.Copy
	}
}

// lineage returns the copy and all the copies it descends from.
func (j *Journey) lineage(id int) map[int]bool {
	line := map[int]bool{0: true}
	for id != 0 && !line[id] {
		line[id] = true
		id = j.Copies[id-1].Parent
	}
	return line
}

// linkStory lists the device hooks the frame crossed.
func linkStory(j *Journey) []LinkCrossing {
	var out []LinkCrossing
	at := map[[2]string]int{}
	left := map[int]bool{}
	for _, h := range j.Hops {
		if h.Layer != L1 {
			continue
		}
		dev := h.In
		if h.Hook == "EGRESS" {
			dev = h.Out
		}
		key := [2]string{h.Hook, dev}
		i, ok := at[key]
		if !ok {
			i = len(out)
			at[key] = i
			out = append(out, LinkCrossing{Dev: dev, Hook: h.Hook, Outcome: OutcomeDropped, Copy: h.Copy})
		}
		if h.Exit {
			left[i] = true
		}
	}
	for i := range out {
		if left[i] {
			out[i].Outcome = OutcomePassed
		}
	}
	return out
}

func macKindOf(mac string) string {
	if hw, err := net.ParseMAC(mac); err == nil && len(hw) == 6 {
		return macKind(hw)
	}
	return KindUnicast
}

// bridgeStories tells what every bridge did with the frame: how the frame got
// in, which copies the bridge made, and what became of each.
func bridgeStories(j *Journey) []BridgeStory {
	type progress struct {
		leg     *Leg
		entered map[string]bool
		left    map[string]bool
	}
	type crossing struct {
		story               *BridgeStory
		legs                []*progress
		byCopy              map[int]*progress
		preEntered, preLeft bool
	}
	var order []*crossing
	byKey := map[[2]string]*crossing{}
	for _, h := range j.Hops {
		if h.Layer != L2 {
			continue
		}
		parent := h.Copy
		if h.Hook != "PREROUTING" {
			parent = j.Copies[h.Copy-1].Parent
		}
		key := [2]string{h.Bridge, fmt.Sprint(parent)}
		c := byKey[key]
		if c == nil {
			c = &crossing{story: &BridgeStory{Bridge: h.Bridge, Parent: parent, Src: h.SMAC, Dst: h.DMAC, DstKind: macKindOf(h.DMAC), VLAN: j.vlans[h.Bridge]}, byCopy: map[int]*progress{}}
			byKey[key] = c
			order = append(order, c)
		}
		if c.story.In == "" && h.In != "" {
			c.story.In = h.In
		}
		if h.Hook == "PREROUTING" {
			if h.Exit {
				c.preLeft = true
			} else {
				c.preEntered = true
			}
			continue
		}
		p := c.byCopy[h.Copy]
		if p == nil {
			cp := j.Copies[h.Copy-1]
			p = &progress{leg: &Leg{Copy: cp.ID, To: cp.To, Host: cp.Host, Hooks: []string{}}, entered: map[string]bool{}, left: map[string]bool{}}
			c.byCopy[h.Copy] = p
			c.legs = append(c.legs, p)
		}
		if h.Exit {
			p.left[h.Hook] = true
		}
		// A copy that is seen leaving a hook has entered it, even when the
		// record of that was lost.
		if !p.entered[h.Hook] {
			p.entered[h.Hook] = true
			p.leg.Hooks = append(p.leg.Hooks, h.Hook)
		}
	}

	var out []BridgeStory
	for _, c := range order {
		s := c.story
		switch {
		case c.preLeft:
			s.Ingress = OutcomePassed
		case c.preEntered:
			s.Ingress = OutcomeDropped
		}
		ports := 0
		s.Legs = []Leg{}
		for _, p := range c.legs {
			leg := p.leg
			last := leg.Hooks[len(leg.Hooks)-1]
			switch {
			case leg.Host && p.left["INPUT"]:
				leg.Outcome = OutcomeDelivered
			case !leg.Host && p.left["POSTROUTING"]:
				leg.Outcome = OutcomeSent
			case p.left[last]:
				leg.Outcome, leg.StoppedHook = OutcomeLost, last
			default:
				leg.Outcome, leg.StoppedHook = OutcomeDropped, last
			}
			if !leg.Host {
				ports++
			}
			s.Legs = append(s.Legs, *leg)
		}
		switch {
		case len(s.Legs) == 0:
			s.Decision = DecisionDrop
		case s.DstKind != KindUnicast || ports > 1:
			// More than one copy of a unicast frame: the bridge did not know the port.
			s.Decision = DecisionFlood
		case ports == 1:
			s.Decision = DecisionForward
		default:
			s.Decision = DecisionLocal
		}
		out = append(out, *s)
	}
	return out
}

// ipStory derives the path, the rewrites, and the verdict of the IP hooks.
// When a bridge copied the packet and the IP hooks saw more than one copy
// (a flooded packet under br_netfilter), it follows the copy that went up to
// the network stack, or else the first one.
func ipStory(j *Journey) *IPStory {
	follow, host := 0, false
	for _, h := range j.Hops {
		if h.Layer != L3 || h.Copy == 0 {
			continue
		}
		if c := j.Copies[h.Copy-1]; follow == 0 || (c.Host && !host) {
			follow, host = c.ID, c.Host
		}
	}
	line := j.lineage(follow)
	s := &IPStory{}
	for i, h := range j.Hops {
		if h.Layer == L3 && line[h.Copy] {
			s.Hops = append(s.Hops, i)
		}
	}
	if len(s.Hops) == 0 {
		return nil
	}
	for n, i := range s.Hops {
		h := &j.Hops[i]
		if len(s.Path) == 0 || s.Path[len(s.Path)-1] != h.Hook {
			s.Path = append(s.Path, h.Hook)
		}
		// A stage rewrote the packet when the next probe of the same hook saw
		// different addresses.
		if n+1 < len(s.Hops) && !h.Exit && j.Hops[s.Hops[n+1]].Hook == h.Hook {
			next := j.Hops[s.Hops[n+1]]
			if next.Dst != h.Dst {
				h.Rewrote = fmt.Sprintf("destination %s to %s", h.Dst, next.Dst)
			}
			if next.Src != h.Src {
				if h.Rewrote != "" {
					h.Rewrote += ", "
				}
				h.Rewrote += fmt.Sprintf("source %s to %s", h.Src, next.Src)
			}
		}
	}

	first := j.Hops[s.Hops[0]]
	s.Partial = !((first.Hook == "PREROUTING" || first.Hook == "OUTPUT") && first.Stage == "raw")

	last := j.Hops[s.Hops[len(s.Hops)-1]]
	switch {
	case last.Exit && last.Hook == "INPUT":
		s.Verdict = VerdictDelivered
	case last.Exit && last.Hook == "POSTROUTING":
		s.Verdict = VerdictSent
	case last.Exit:
		// The packet survived the hook but never showed up in the next one.
		s.Verdict = VerdictStopped
		s.StoppedHook = last.Hook
		s.StoppedStage = "routing"
	default:
		s.Verdict = VerdictStopped
		s.StoppedHook = last.Hook
		s.StoppedStage = last.Stage
	}
	return s
}
