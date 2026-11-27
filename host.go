package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// MACEntry is a line of a bridge's MAC table (the forwarding database): an
// address the bridge learned behind a port.
type MACEntry struct {
	MAC string `json:"mac"`
	// IP is the address that this MAC answers for, when it is known.
	IP string `json:"ip,omitempty"`
}

// Peer is what a port leads to: the other end of a veth pair, and whose it is.
type Peer struct {
	// Kind tells what Name is: a container, a pod, a netns (a named network
	// namespace), a process (a namespace known only by a process in it),
	// the host (the namespace pathviz runs in), or local (a device in the
	// same namespace).
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Runtime string `json:"runtime,omitempty"`
	// Ifname, MAC, and Addrs describe the device at the other end.
	Ifname string   `json:"ifname,omitempty"`
	MAC    string   `json:"mac,omitempty"`
	Addrs  []string `json:"addrs,omitempty"`
	// Bridge is the bridge that the other end is a port of, when the pair
	// connects two bridges.
	Bridge string `json:"bridge,omitempty"`
}

// Port is a device attached to a bridge.
type Port struct {
	Name  string `json:"name"`
	Up    bool   `json:"up"`
	State string `json:"state"` // forwarding, blocking, disabled, ...
	// Kind is the kind of the device: veth, tap, dummy, vxlan, ... It is empty
	// for a physical one.
	Kind string `json:"kind,omitempty"`
	Peer *Peer  `json:"peer,omitempty"`
	// PVID is the VLAN that untagged frames of this port belong to, and VLANs
	// are all the VLANs of the port. Both are set only when the bridge filters
	// by VLAN.
	PVID  int        `json:"pvid,omitempty"`
	VLANs []int      `json:"vlans,omitempty"`
	MACs  []MACEntry `json:"macs"`
}

// Bridge is a bridge device with its ports.
type Bridge struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs"`
	// VLANFiltering tells that the bridge keeps its VLANs apart.
	VLANFiltering bool   `json:"vlanFiltering,omitempty"`
	PVID          int    `json:"pvid,omitempty"`
	Ports         []Port `json:"ports"`
}

// Iface is a network device of the namespace.
type Iface struct {
	Name  string   `json:"name"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs"`
	MAC   string   `json:"mac,omitempty"`
	// Kind is the kind of the device: veth, bridge, tap, loopback, ... It is
	// empty for a physical one.
	Kind string `json:"kind,omitempty"`
	// Master is the bridge (or the bond) that the device is a port of.
	Master string `json:"master,omitempty"`
	Peer   *Peer  `json:"peer,omitempty"`
}

// HostState is what the page draws around the hooks: the devices, the
// bridges, and the listening processes of the watched namespace.
type HostState struct {
	Ifaces  []Iface   `json:"ifaces"`
	Procs   []Process `json:"procs"`
	Bridges []Bridge  `json:"bridges"`
}

// buildState describes one namespace. All the namespaces are needed to tell
// what the far ends of its veth devices belong to. arp is what the traced ARP
// messages said: MAC to IP.
func buildState(d *nsData, all []nsData, arp map[string]string) HostState {
	byIno := map[uint64]*nsData{}
	byIndex := map[uint64]map[int]*ipLink{}
	// A device tells the address of its MAC, wherever it lives.
	ipOf := map[string]string{}
	for _, n := range d.neigh {
		if n.MAC != "" && !strings.Contains(n.IP, ":") {
			ipOf[n.MAC] = n.IP
		}
	}
	for i := range all {
		o := &all[i]
		byIno[o.ns.Ino] = o
		idx := map[int]*ipLink{}
		for j := range o.links {
			l := &o.links[j]
			idx[l.Ifindex] = l
			if a := l.addrs(); len(a) > 0 && l.Address != "" && !strings.Contains(a[0], ":") {
				ipOf[l.Address] = a[0]
			}
		}
		byIndex[o.ns.Ino] = idx
	}
	// What the ARP messages said is the newest.
	for mac, ip := range arp {
		ipOf[mac] = ip
	}

	st := HostState{Ifaces: []Iface{}, Procs: []Process{}, Bridges: []Bridge{}}
	peers := map[string]*Peer{}
	for _, l := range d.links {
		ifc := Iface{Name: l.Name, Up: hasFlag(l.Flags, "UP"), Addrs: l.addrs(), MAC: l.Address, Kind: l.kind(), Master: l.Master, Peer: peerOf(d, l, byIno, byIndex)}
		if l.LinkType == "loopback" {
			ifc.Kind, ifc.MAC = "loopback", ""
		}
		peers[l.Name] = ifc.Peer
		st.Ifaces = append(st.Ifaces, ifc)
	}

	pvid := map[string]int{}
	vlans := map[string][]int{}
	for _, v := range d.vlans {
		for _, e := range v.VLANs {
			vlans[v.Port] = append(vlans[v.Port], e.VLAN)
			if hasFlag(e.Flags, "PVID") {
				pvid[v.Port] = e.VLAN
			}
		}
	}
	index := map[string]int{}
	for _, l := range d.links {
		if l.LinkInfo.Kind != "bridge" {
			continue
		}
		b := Bridge{Name: l.Name, MAC: l.Address, Up: hasFlag(l.Flags, "UP"), Addrs: l.addrs(), Ports: []Port{}}
		if l.LinkInfo.Data.VLANFiltering == 1 {
			b.VLANFiltering, b.PVID = true, pvid[l.Name]
		}
		index[b.Name] = len(st.Bridges)
		st.Bridges = append(st.Bridges, b)
	}
	learned := map[[2]string][]MACEntry{}
	seen := map[[3]string]bool{}
	for _, e := range d.fdb {
		// Permanent entries are the addresses of the ports themselves.
		if e.Master == "" || e.State == "permanent" || seen[[3]string{e.Master, e.Port, e.MAC}] {
			continue
		}
		seen[[3]string{e.Master, e.Port, e.MAC}] = true
		key := [2]string{e.Master, e.Port}
		learned[key] = append(learned[key], MACEntry{MAC: e.MAC, IP: ipOf[e.MAC]})
	}
	for _, l := range d.links {
		bi, ok := index[l.Master]
		if !ok || l.LinkInfo.SlaveKind != "bridge" {
			continue
		}
		p := Port{Name: l.Name, Up: hasFlag(l.Flags, "LOWER_UP"), State: l.LinkInfo.SlaveData.State, Kind: l.kind(), MACs: learned[[2]string{l.Master, l.Name}], Peer: peers[l.Name]}
		if p.MACs == nil {
			p.MACs = []MACEntry{}
		}
		sort.Slice(p.MACs, func(a, b int) bool { return p.MACs[a].MAC < p.MACs[b].MAC })
		if st.Bridges[bi].VLANFiltering {
			p.PVID, p.VLANs = pvid[l.Name], vlans[l.Name]
		}
		st.Bridges[bi].Ports = append(st.Bridges[bi].Ports, p)
	}
	sort.Slice(st.Bridges, func(a, b int) bool { return st.Bridges[a].Name < st.Bridges[b].Name })
	return st
}

// peerOf finds the other end of a veth device and tells whose it is.
func peerOf(d *nsData, l ipLink, byIno map[uint64]*nsData, byIndex map[uint64]map[int]*ipLink) *Peer {
	if l.LinkInfo.Kind != "veth" {
		return nil
	}
	target := d
	var pl *ipLink
	switch {
	case l.Link != "":
		for i := range d.links {
			if d.links[i].Name == l.Link && d.links[i].Link == l.Name {
				pl = &d.links[i]
			}
		}
	case l.LinkIndex != 0:
		if l.NetnsID != nil {
			target = byIno[d.nsids[*l.NetnsID]]
		}
		if target == nil {
			return nil
		}
		// The two ends of a pair point at each other.
		if pl = byIndex[target.ns.Ino][l.LinkIndex]; pl != nil && pl.LinkIndex != l.Ifindex {
			pl = nil
		}
	}
	if pl == nil {
		return nil
	}
	p := &Peer{Kind: target.label.Kind, Name: target.label.Name, Runtime: target.label.Runtime, Ifname: pl.Name, MAC: pl.Address, Addrs: pl.addrs()}
	if target == d {
		p.Kind, p.Name, p.Runtime = "local", pl.Name, ""
	}
	if pl.Master != "" && pl.LinkInfo.SlaveKind == "bridge" {
		p.Bridge = pl.Master
	}
	return p
}

// fdbSnapshot is where the bridges thought every MAC address was at some moment.
type fdbSnapshot struct {
	at     time.Time
	portOf map[[2]string]string // bridge and MAC to port
}

// macAge is how long a bridge remembers a MAC address by default.
const macAge = 300 * time.Second

type sourceSeen struct {
	port string
	at   time.Time
}

// BridgeMemory remembers what the bridges of a namespace knew a moment ago.
// The MAC tables are read on a timer, so the table as it was right before a
// frame tells what the frame taught the bridge.
type BridgeMemory struct {
	mu sync.Mutex
	// snaps are the last few MAC tables, the newest last.
	snaps []fdbSnapshot
	// arp is what the traced ARP messages said: MAC to IP.
	arp map[string]string
	// sources is where the traced frames came from: bridge and MAC to port.
	sources map[[2]string]sourceSeen
	bridges []Bridge
}

// NewBridgeMemory creates an empty memory.
func NewBridgeMemory() *BridgeMemory {
	return &BridgeMemory{arp: map[string]string{}, sources: map[[2]string]sourceSeen{}}
}

// ARP returns what the traced ARP messages said: MAC to IP.
func (m *BridgeMemory) ARP() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.arp))
	for k, v := range m.arp {
		out[k] = v
	}
	return out
}

// Update takes the MAC tables and the bridges as they are now.
func (m *BridgeMemory) Update(fdb []fdbEntry, bridges []Bridge) {
	snap := fdbSnapshot{at: time.Now(), portOf: map[[2]string]string{}}
	for _, e := range fdb {
		if e.Master != "" && e.State != "permanent" {
			snap.portOf[[2]string{e.Master, e.MAC}] = e.Port
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bridges = bridges
	m.snaps = append(m.snaps, snap)
	if len(m.snaps) > 8 {
		m.snaps = m.snaps[len(m.snaps)-8:]
	}
}

// portBefore tells behind which port the bridge had a MAC address right before
// the given moment, as far as it is known. The caller holds m.mu.
func (m *BridgeMemory) portBefore(bridge, mac string, at time.Time) string {
	key := [2]string{bridge, mac}
	port := ""
	for _, s := range m.snaps {
		if s.at.Before(at) {
			port = s.portOf[key]
		}
	}
	// A frame traced since that snapshot taught the bridge as well.
	if src, ok := m.sources[key]; ok && src.at.Before(at) && at.Sub(src.at) < macAge {
		port = src.port
	}
	return port
}

// Annotate adds to a finished journey what the MAC tables explain: whether
// the frame taught a bridge where its source is, and whether the bridge knew
// where its destination is. The journeys must come in the order they were seen.
func (m *BridgeMemory) Annotate(j *Journey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j.arp != nil && j.arp.SenderIP != "0.0.0.0" {
		m.arp[j.arp.SenderMAC] = j.arp.SenderIP
	}
	for i := range j.Bridges {
		s := &j.Bridges[i]
		if s.VLAN == 0 {
			// An untagged frame belongs to the VLAN of the port it came in through.
			for _, b := range m.bridges {
				if b.Name != s.Bridge || !b.VLANFiltering {
					continue
				}
				s.VLAN = uint16(b.PVID)
				for _, p := range b.Ports {
					if p.Name == s.In {
						s.VLAN = uint16(p.PVID)
					}
				}
			}
		}
		if s.In != "" && s.Ingress == OutcomePassed {
			s.Learned = m.portBefore(s.Bridge, s.Src, j.Time) != s.In
			m.sources[[2]string{s.Bridge, s.Src}] = sourceSeen{port: s.In, at: j.Time}
		}
		if s.DstKind == KindUnicast {
			known := m.portBefore(s.Bridge, s.Dst, j.Time)
			for k := range s.Legs {
				s.Legs[k].Known = !s.Legs[k].Host && known != "" && known == s.Legs[k].To
			}
		}
	}
}
