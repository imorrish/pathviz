package main

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SocketInfo is a socket a process waits for traffic on.
type SocketInfo struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// Process is a process with the sockets it listens on.
type Process struct {
	PID     int          `json:"pid"`
	Name    string       `json:"name"`
	Sockets []SocketInfo `json:"sockets"`
}

// Owner is the process that owns the local socket of a packet.
type Owner struct {
	PID   int    `json:"pid"`
	Name  string `json:"name"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// sock is one line of the ss output.
type sock struct {
	proto     string
	listening bool       // TCP LISTEN or an unconnected UDP socket
	local     netip.Addr // invalid means any address
	port      int
	peer      netip.AddrPort // valid for connected sockets
	pid       int
	name      string
}

var ssUser = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)

// parseHostPort splits an ss address such as "*:8080", "[::]:22", or "127.0.0.53%lo:53".
// The address is invalid for a wildcard, and the port is 0 for "*".
func parseHostPort(s string) (netip.Addr, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return netip.Addr{}, 0
	}
	host, portStr := s[:i], s[i+1:]
	port, _ := strconv.Atoi(portStr)
	// Drop the brackets and the "%eth0" zone, wherever ss puts it.
	host = strings.Trim(host, "[]")
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsUnspecified() {
		return netip.Addr{}, port
	}
	return addr.Unmap(), port
}

// parseSS parses the output of "ss -H -n -a -t -u -p".
func parseSS(out string) []sock {
	var socks []sock
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		s := sock{proto: f[0]}
		s.local, s.port = parseHostPort(f[4])
		if s.port == 0 {
			continue
		}
		peerAddr, peerPort := parseHostPort(f[5])
		if peerPort != 0 && peerAddr.IsValid() {
			s.peer = netip.AddrPortFrom(peerAddr, uint16(peerPort))
		}
		s.listening = f[1] == "LISTEN" || (f[0] == "udp" && !s.peer.IsValid())
		if f[0] == "tcp" && !s.listening && !s.peer.IsValid() {
			continue
		}
		if m := ssUser.FindStringSubmatch(strings.Join(f[6:], " ")); m != nil {
			s.name = m[1]
			s.pid, _ = strconv.Atoi(m[2])
		}
		if s.pid == 0 {
			continue // a kernel socket, or the process is gone
		}
		socks = append(socks, s)
	}
	return socks
}

// SocketTable knows which process owns which socket of a network namespace.
// It is a snapshot of the ss output that is refreshed on a timer and on a
// failed lookup.
type SocketTable struct {
	hidePorts map[int]bool

	mu    sync.Mutex
	ns    Netns
	socks []sock
	last  time.Time
}

// NewSocketTable creates a table. Sockets on the hidden ports are never reported.
func NewSocketTable(ns Netns, hidePorts []int) *SocketTable {
	t := &SocketTable{ns: ns, hidePorts: map[int]bool{}}
	for _, p := range hidePorts {
		t.hidePorts[p] = true
	}
	return t
}

// Refresh reloads the table.
func (t *SocketTable) Refresh() error {
	t.mu.Lock()
	ns := t.ns
	t.mu.Unlock()
	out, err := ns.output(4*time.Second, "ss", "-H", "-n", "-a", "-t", "-u", "-p")
	if err != nil {
		return err
	}
	socks := parseSS(string(out))
	t.mu.Lock()
	t.socks, t.last = socks, time.Now()
	t.mu.Unlock()
	return nil
}

func (t *SocketTable) lookup(proto string, local, peer netip.AddrPort) *Owner {
	t.mu.Lock()
	defer t.mu.Unlock()
	var best *sock
	bestScore := 0
	for i := range t.socks {
		s := &t.socks[i]
		if s.proto != proto || s.port != int(local.Port()) {
			continue
		}
		score := 0
		switch {
		case s.peer.IsValid():
			if s.peer == peer && (!s.local.IsValid() || s.local == local.Addr()) {
				score = 3
			}
		case s.listening && s.local.IsValid():
			if s.local == local.Addr() {
				score = 2
			}
		case s.listening:
			score = 1
		}
		if score > bestScore {
			best, bestScore = s, score
		}
	}
	if best == nil {
		return nil
	}
	return &Owner{PID: best.pid, Name: best.name, Proto: proto, Port: best.port}
}

// Owner finds the process that owns the socket with the given local and peer
// endpoints. A connected socket wins over a listening one.
func (t *SocketTable) Owner(proto string, local, peer netip.AddrPort) *Owner {
	if proto != "tcp" && proto != "udp" {
		return nil
	}
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if o := t.lookup(proto, local, peer); o != nil {
		return o
	}
	// The socket may be newer than the snapshot.
	t.mu.Lock()
	stale := time.Since(t.last) > 300*time.Millisecond
	t.mu.Unlock()
	if !stale || t.Refresh() != nil {
		return nil
	}
	return t.lookup(proto, local, peer)
}

// SetNetns updates the way into the namespace.
func (t *SocketTable) SetNetns(ns Netns) {
	t.mu.Lock()
	t.ns = ns
	t.mu.Unlock()
}

// Procs lists the processes with listening sockets.
func (t *SocketTable) Procs() []Process {
	procs := []Process{}
	t.mu.Lock()
	defer t.mu.Unlock()
	byPID := map[int]*Process{}
	for _, s := range t.socks {
		if !s.listening || t.hidePorts[s.port] {
			continue
		}
		p := byPID[s.pid]
		if p == nil {
			p = &Process{PID: s.pid, Name: s.name}
			byPID[s.pid] = p
		}
		info := SocketInfo{Proto: s.proto, Port: s.port}
		dup := false
		for _, have := range p.Sockets {
			dup = dup || have == info
		}
		if !dup {
			p.Sockets = append(p.Sockets, info)
		}
	}
	for _, p := range byPID {
		sort.Slice(p.Sockets, func(a, b int) bool {
			if p.Sockets[a].Port != p.Sockets[b].Port {
				return p.Sockets[a].Port < p.Sockets[b].Port
			}
			return p.Sockets[a].Proto < p.Sockets[b].Proto
		})
		procs = append(procs, *p)
	}
	sort.Slice(procs, func(a, b int) bool {
		pa, pb := procs[a], procs[b]
		if pa.Sockets[0].Port != pb.Sockets[0].Port {
			return pa.Sockets[0].Port < pb.Sockets[0].Port
		}
		return pa.PID < pb.PID
	})
	return procs
}

// ResolveOwners finds the local processes at the ends of a journey.
func (t *SocketTable) ResolveOwners(j *Journey) {
	s := j.IP
	if s == nil {
		return
	}
	first, last := j.Hops[s.Hops[0]], j.Hops[s.Hops[len(s.Hops)-1]]
	if first.Hook == "OUTPUT" && !s.Partial {
		// A locally generated packet: the source socket is ours.
		local, err1 := netip.ParseAddrPort(first.Src)
		peer, err2 := netip.ParseAddrPort(first.Dst)
		if err1 == nil && err2 == nil {
			s.From = t.Owner(j.Proto, local, peer)
		}
	}
	if s.Verdict == VerdictDelivered {
		// The addresses after all rewrites tell which socket gets the packet.
		local, err1 := netip.ParseAddrPort(last.Dst)
		peer, err2 := netip.ParseAddrPort(last.Src)
		if err1 == nil && err2 == nil {
			s.To = t.Owner(j.Proto, local, peer)
		}
	}
}
