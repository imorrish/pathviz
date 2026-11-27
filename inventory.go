package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type ipLink struct {
	Ifindex   int `json:"ifindex"`
	LinkIndex int `json:"link_index"`
	// Link is the name of the other end of a veth pair, when it lives in the
	// same namespace. Else there is LinkIndex, and NetnsID for the namespace.
	Link    string   `json:"link"`
	Name    string   `json:"ifname"`
	Flags   []string `json:"flags"`
	Master  string   `json:"master"`
	Address string   `json:"address"`
	// LinkType is ether, loopback, none, ...
	LinkType string `json:"link_type"`
	NetnsID  *int   `json:"link_netnsid"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
		Data struct {
			VLANFiltering int    `json:"vlan_filtering"`
			Type          string `json:"type"` // tun or tap, for a tun device
		} `json:"info_data"`
		SlaveKind string `json:"info_slave_kind"`
		SlaveData struct {
			State string `json:"state"`
		} `json:"info_slave_data"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
		Scope  string `json:"scope"`
	} `json:"addr_info"`
}

// addrs returns the addresses of the device that are not link-local, IPv4 first.
func (l ipLink) addrs() []string {
	out := []string{}
	for _, family := range []string{"inet", "inet6"} {
		for _, a := range l.AddrInfo {
			if a.Family == family && a.Scope != "link" {
				out = append(out, a.Local)
			}
		}
	}
	return out
}

// kind names the kind of the device.
func (l ipLink) kind() string {
	if l.LinkInfo.Kind == "tun" && l.LinkInfo.Data.Type != "" {
		return l.LinkInfo.Data.Type
	}
	return l.LinkInfo.Kind
}

type fdbEntry struct {
	MAC    string `json:"mac"`
	Port   string `json:"ifname"`
	Master string `json:"master"`
	State  string `json:"state"`
}

type neighEntry struct {
	IP  string `json:"dst"`
	MAC string `json:"lladdr"`
}

type vlanEntry struct {
	Port  string `json:"ifname"`
	VLANs []struct {
		VLAN  int      `json:"vlan"`
		Flags []string `json:"flags"`
	} `json:"vlans"`
}

// nsLabel names a network namespace for the user.
type nsLabel struct {
	Kind    string
	Name    string
	Runtime string
}

// nsData is what one network namespace holds.
type nsData struct {
	ns    Netns
	label nsLabel
	links []ipLink
	fdb   []fdbEntry
	neigh []neighEntry
	vlans []vlanEntry
	// nsids maps the IDs that this namespace knows other namespaces by (the
	// link_netnsid of a veth device) to their inodes.
	nsids map[int]uint64
}

func (d *nsData) hasBridge() bool {
	for _, l := range d.links {
		if l.LinkInfo.Kind == "bridge" {
			return true
		}
	}
	return false
}

// labelOf names a namespace: by its container or pod, else by its "ip netns"
// name, else by a process that lives in it.
func labelOf(ns Netns, hostname string, cids []string, infos map[string]containerInfo, comm string) nsLabel {
	if ns.Home {
		return nsLabel{Kind: "host", Name: hostname}
	}
	if len(cids) > 0 {
		var names []string
		pod, runtime := "", ""
		for _, id := range cids {
			info, ok := infos[id]
			if !ok {
				continue
			}
			runtime = info.Runtime
			if info.Pod != "" {
				pod = info.Pod
			}
			names = append(names, info.Name)
		}
		switch {
		case pod != "":
			return nsLabel{Kind: "pod", Name: pod, Runtime: runtime}
		case len(names) == 1:
			return nsLabel{Kind: "container", Name: names[0], Runtime: runtime}
		case len(names) > 1:
			return nsLabel{Kind: "container", Name: fmt.Sprintf("%s +%d", names[0], len(names)-1), Runtime: runtime}
		}
		// No runtime knows the container (yet).
		return nsLabel{Kind: "container", Name: cids[0][:12]}
	}
	switch {
	case len(ns.Names) > 0:
		return nsLabel{Kind: "netns", Name: ns.Names[0]}
	case len(ns.Pids) > 0 && comm != "":
		return nsLabel{Kind: "process", Name: fmt.Sprintf("%s (pid %d)", comm, ns.Pids[0])}
	}
	return nsLabel{Kind: "netns", Name: fmt.Sprintf("net:[%d]", ns.Ino)}
}

func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

// collectScript prints all that pathviz needs to know about a namespace.
const collectScript = `ip -j -d addr show; echo; echo ---; bridge -j fdb show; echo; echo ---; ip -j neigh show; echo; echo ---; bridge -j vlan show; echo`

// collect reads the devices, the MAC tables, the neighbors, and the VLANs of
// a namespace.
func collect(ns Netns) (nsData, error) {
	d := nsData{ns: ns}
	out, err := ns.output(4*time.Second, "sh", "-c", collectScript)
	if len(out) == 0 && err != nil {
		return d, err
	}
	parts := strings.Split(string(out), "\n---\n")
	parse := func(i int, into any) {
		if i < len(parts) {
			if text := strings.TrimSpace(parts[i]); text != "" {
				json.Unmarshal([]byte(text), into)
			}
		}
	}
	parse(0, &d.links)
	// The MAC table, the neighbors, and the VLANs are optional: the page
	// works without them.
	parse(1, &d.fdb)
	parse(2, &d.neigh)
	parse(3, &d.vlans)
	if d.links == nil {
		return d, fmt.Errorf("cannot list the devices of %s", ns.Path)
	}
	return d, nil
}

// Space is a network namespace as the page lists it.
type Space struct {
	// ID is what selects the namespace: in the --netns flag, in the URL of
	// the page, and in the API.
	ID string `json:"id"`
	// Kind and Name tell what the namespace belongs to, in the terms of Peer.
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Runtime string `json:"runtime,omitempty"`
	// Bridges is how many bridges the namespace has.
	Bridges int `json:"bridges,omitempty"`
}

// homeID is the ID of the namespace that pathviz itself runs in.
const homeID = "host"

// spaceID is the ID of a namespace that needs no inventory: the name that
// "ip netns" knows it by, else its inode.
func spaceID(ns Netns) string {
	if ns.Home {
		return homeID
	}
	return ns.Key()
}

// spaceIDs gives every namespace its ID. A namespace without an "ip netns"
// name goes by the name of its container or pod, when no other namespace
// answers to that name. Such an ID survives a restart of the container.
func spaceIDs(data []nsData) map[uint64]string {
	taken := map[string]int{homeID: 1}
	for _, d := range data {
		for _, n := range d.ns.Names {
			taken[n]++
		}
		if !d.ns.Home && len(d.ns.Names) == 0 && (d.label.Kind == "container" || d.label.Kind == "pod") {
			taken[d.label.Name]++
		}
	}
	ids := map[uint64]string{}
	for _, d := range data {
		id := spaceID(d.ns)
		if !d.ns.Home && len(d.ns.Names) == 0 && (d.label.Kind == "container" || d.label.Kind == "pod") && taken[d.label.Name] == 1 && !strings.ContainsAny(d.label.Name, " ,") {
			id = d.label.Name
		}
		ids[d.ns.Ino] = id
	}
	return ids
}

// Inventory knows the network namespaces of the machine and the devices in
// them. It is a snapshot of the ip and bridge commands' output that is
// refreshed on a timer.
type Inventory struct {
	containers *containerResolver
	hostname   string

	mu   sync.Mutex
	data []nsData
	ids  map[uint64]string
	// busy are the namespaces that are read on every refresh: the watched ones.
	busy map[uint64]bool

	// The fields below belong to Refresh alone.
	round  int
	cached map[uint64]nsData
	nsids  map[uint64]map[int]uint64
}

// NewInventory creates an empty inventory.
func NewInventory() *Inventory {
	hostname, _ := os.Hostname()
	return &Inventory{containers: newContainerResolver(), hostname: hostname, busy: map[uint64]bool{}, cached: map[uint64]nsData{}, nsids: map[uint64]map[int]uint64{}}
}

// quietEvery is how often a namespace that nobody watches is read: it only
// names the far ends of the devices, and those change seldom.
const quietEvery = 3

// Watch tells the inventory to keep a namespace fresh, or to stop doing so.
func (inv *Inventory) Watch(ino uint64, on bool) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if on {
		inv.busy[ino] = true
	} else {
		delete(inv.busy, ino)
	}
}

// Refresh reloads the inventory. It must not be called from two goroutines at once.
func (inv *Inventory) Refresh() error {
	spaces := discoverNetns()
	inv.round++
	inv.mu.Lock()
	busy := make(map[uint64]bool, len(inv.busy))
	for ino := range inv.busy {
		busy[ino] = true
	}
	inv.mu.Unlock()

	data := make([]nsData, len(spaces))
	errs := make([]error, len(spaces))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, ns := range spaces {
		old, ok := inv.cached[ns.Ino]
		if ok && !ns.Home && !busy[ns.Ino] && inv.round%quietEvery != 0 {
			old.ns = ns
			data[i] = old
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			data[i], errs[i] = collect(ns)
		}()
	}
	wg.Wait()
	if len(spaces) == 0 || errs[0] != nil {
		return fmt.Errorf("cannot read the network devices: %v", errs[0])
	}

	alive := map[uint64]bool{}
	inv.cached = map[uint64]nsData{}
	for i := range data {
		alive[spaces[i].Ino] = true
		inv.cached[spaces[i].Ino] = data[i]
	}

	// Name the namespaces.
	cidsOf := make([][]string, len(data))
	var allCids []string
	for i, d := range data {
		if d.ns.Home {
			continue
		}
		seen := map[string]bool{}
		for _, pid := range d.ns.Pids {
			if id := containerOfPid(pid); id != "" && !seen[id] {
				seen[id] = true
				cidsOf[i] = append(cidsOf[i], id)
			}
		}
		allCids = append(allCids, cidsOf[i]...)
	}
	var infos map[string]containerInfo
	if len(allCids) > 0 {
		infos = inv.containers.Resolve(allCids)
	}
	for i := range data {
		comm := ""
		if len(data[i].ns.Pids) > 0 {
			comm = processName(data[i].ns.Pids[0])
		}
		data[i].label = labelOf(data[i].ns, inv.hostname, cidsOf[i], infos, comm)
	}

	// Find out which namespaces the veth devices of the watched ones lead to.
	for ino := range inv.nsids {
		if !alive[ino] {
			delete(inv.nsids, ino)
		}
	}
	for i := range data {
		d := &data[i]
		if !busy[d.ns.Ino] && !d.ns.Home {
			continue
		}
		known := inv.nsids[d.ns.Ino]
		ask := false
		for _, l := range d.links {
			if l.NetnsID != nil && l.LinkInfo.Kind == "veth" && !alive[known[*l.NetnsID]] {
				ask = true
			}
		}
		if ask {
			if ids, err := peerNsids(d.ns, spaces); err == nil {
				known = ids
				inv.nsids[d.ns.Ino] = ids
			}
		}
		d.nsids = known
	}

	inv.mu.Lock()
	inv.data, inv.ids = data, spaceIDs(data)
	inv.mu.Unlock()
	return nil
}

// idOf returns the ID of a namespace. The caller holds inv.mu.
func (inv *Inventory) idOf(d nsData) string {
	if id, ok := inv.ids[d.ns.Ino]; ok {
		return id
	}
	return spaceID(d.ns)
}

// ID returns the ID of a namespace by its inode.
func (inv *Inventory) ID(ns Netns) string {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if id, ok := inv.ids[ns.Ino]; ok {
		return id
	}
	return spaceID(ns)
}

// Spaces lists the namespaces: the home one first, then by name.
func (inv *Inventory) Spaces() []Space {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := make([]Space, 0, len(inv.data))
	for _, d := range inv.data {
		s := Space{ID: inv.idOf(d), Kind: d.label.Kind, Name: d.label.Name, Runtime: d.label.Runtime}
		for _, l := range d.links {
			if l.LinkInfo.Kind == "bridge" {
				s.Bridges++
			}
		}
		out = append(out, s)
	}
	return out
}

// Find resolves what a user calls a namespace: its ID, any of its "ip netns"
// names, the name of its container or pod, "pid:<n>" for the namespace of a
// process, or an empty string for the home namespace.
func (inv *Inventory) Find(name string) (Netns, bool) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if name == "" {
		name = homeID
	}
	var pid int
	fmt.Sscanf(name, "pid:%d", &pid)
	var byLabel *Netns
	for i := range inv.data {
		d := &inv.data[i]
		if spaceID(d.ns) == name || inv.idOf(*d) == name {
			return d.ns, true
		}
		for _, n := range d.ns.Names {
			if n == name {
				return d.ns, true
			}
		}
		if pid != 0 {
			if ino, ok := inodeOf(fmt.Sprintf("/proc/%d/ns/net", pid)); ok && ino == d.ns.Ino {
				return d.ns, true
			}
		}
		if !d.ns.Home && d.label.Name == name && byLabel == nil {
			byLabel = &d.ns
		}
	}
	if byLabel != nil {
		return *byLabel, true
	}
	return Netns{}, false
}

// View returns what is known about a namespace, and about all of them.
func (inv *Inventory) View(ino uint64) (*nsData, []nsData) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for i := range inv.data {
		if inv.data[i].ns.Ino == ino {
			return &inv.data[i], inv.data
		}
	}
	return nil, inv.data
}
