package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Netns is a network namespace of the machine.
type Netns struct {
	// Ino is the inode of the namespace: its identity.
	Ino uint64
	// Path opens the namespace: a /proc/<pid>/ns/net link or a bind mount.
	Path string
	// Home tells that bridgeviz itself runs in this namespace.
	Home bool
	// Names are the names that "ip netns" knows the namespace by.
	Names []string
	// Pids are some of the processes that live in it, the oldest first.
	Pids []int
}

// maxPidsPerNetns caps how many processes of a namespace are remembered.
const maxPidsPerNetns = 16

// Key is a short and stable name of the namespace. It is empty for the home
// namespace.
func (n Netns) Key() string {
	switch {
	case n.Home:
		return ""
	case len(n.Names) > 0:
		return n.Names[0]
	}
	return fmt.Sprintf("net:%d", n.Ino)
}

// command prepares a command that runs in the namespace.
func (n Netns) command(ctx context.Context, name string, args ...string) *exec.Cmd {
	if n.Home {
		return exec.CommandContext(ctx, name, args...)
	}
	return exec.CommandContext(ctx, "nsenter", append([]string{"--net=" + n.Path, "--", name}, args...)...)
}

// output runs a command in the namespace and returns what it printed.
func (n Netns) output(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return n.command(ctx, name, args...).Output()
}

func inodeOf(path string) (uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, false
	}
	return st.Ino, true
}

// unescapeMount decodes the octal escapes of a mountinfo field.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// netnsMounts finds the network namespaces that are kept alive by a bind mount
// ("ip netns add", Docker, CNI plugins): inode to the mount points.
func netnsMounts(mountinfo string) map[uint64][]string {
	out := map[uint64][]string{}
	sc := bufio.NewScanner(strings.NewReader(mountinfo))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// 57 52 0:4 net:[4026532174] /run/netns/c1 rw shared:174 - nsfs nsfs rw
		if len(fields) < 5 || !strings.HasPrefix(fields[3], "net:[") || !strings.HasSuffix(fields[3], "]") {
			continue
		}
		ino, err := strconv.ParseUint(fields[3][5:len(fields[3])-1], 10, 64)
		if err != nil {
			continue
		}
		path := unescapeMount(fields[4])
		dup := false
		for _, p := range out[ino] {
			dup = dup || p == path
		}
		if !dup {
			out[ino] = append(out[ino], path)
		}
	}
	return out
}

// isNetnsDir tells whether a directory is where "ip netns" keeps its names.
func isNetnsDir(dir string) bool {
	return dir == "/run/netns" || dir == "/var/run/netns"
}

// discoverNetns lists the network namespaces of the machine: the ones that
// have a process, and the ones that a bind mount keeps alive. The home
// namespace comes first.
func discoverNetns() []Netns {
	byIno := map[uint64]*Netns{}
	get := func(ino uint64) *Netns {
		n := byIno[ino]
		if n == nil {
			n = &Netns{Ino: ino}
			byIno[ino] = n
		}
		return n
	}
	homeIno, _ := inodeOf("/proc/self/ns/net")
	home := get(homeIno)
	home.Home, home.Path = true, "/proc/self/ns/net"

	if entries, err := os.ReadDir("/proc"); err == nil {
		var pids []int
		for _, e := range entries {
			if pid, err := strconv.Atoi(e.Name()); err == nil {
				pids = append(pids, pid)
			}
		}
		sort.Ints(pids)
		for _, pid := range pids {
			path := fmt.Sprintf("/proc/%d/ns/net", pid)
			ino, ok := inodeOf(path)
			if !ok {
				continue
			}
			n := get(ino)
			if len(n.Pids) < maxPidsPerNetns {
				n.Pids = append(n.Pids, pid)
			}
			if n.Path == "" {
				n.Path = path
			}
		}
	}
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		for ino, paths := range netnsMounts(string(b)) {
			n := get(ino)
			for _, p := range paths {
				// A mount is a steadier way in than a process that may exit.
				if !n.Home && (n.Path == "" || strings.HasPrefix(n.Path, "/proc/")) {
					n.Path = p
				}
				if isNetnsDir(filepath.Dir(p)) {
					n.Names = append(n.Names, filepath.Base(p))
				}
			}
			sort.Strings(n.Names)
		}
	}

	out := make([]Netns, 0, len(byIno))
	for _, n := range byIno {
		out = append(out, *n)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Home != out[b].Home {
			return out[a].Home
		}
		return out[a].Ino < out[b].Ino
	})
	return out
}

// peerNsids asks the kernel for the IDs that the namespace "from" knows the
// other namespaces by. A veth device names the namespace of its peer with such
// an ID (link_netnsid). Namespaces without an ID are not in the result.
func peerNsids(from Netns, others []Netns) (map[int]uint64, error) {
	cfg := &netlink.Config{}
	if !from.Home {
		f, err := os.Open(from.Path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		cfg.NetNS = int(f.Fd())
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	out := map[int]uint64{}
	for _, other := range others {
		f, err := os.Open(other.Path)
		if err != nil {
			continue
		}
		ae := netlink.NewAttributeEncoder()
		ae.Uint32(unix.NETNSA_FD, uint32(f.Fd()))
		attrs, err := ae.Encode()
		if err != nil {
			f.Close()
			continue
		}
		// The request is a struct rtgenmsg (a family byte, padded) and the
		// attribute that names the namespace by an open file.
		req := netlink.Message{
			Header: netlink.Header{Type: unix.RTM_GETNSID, Flags: netlink.Request},
			Data:   append(make([]byte, 4), attrs...),
		}
		msgs, err := conn.Execute(req)
		f.Close()
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if len(m.Data) < 4 {
				continue
			}
			ad, err := netlink.NewAttributeDecoder(m.Data[4:])
			if err != nil {
				continue
			}
			for ad.Next() {
				if ad.Type() == unix.NETNSA_NSID && len(ad.Bytes()) == 4 {
					if id := int32(binary.NativeEndian.Uint32(ad.Bytes())); id >= 0 {
						out[int(id)] = other.Ino
					}
				}
			}
		}
	}
	return out, nil
}

// processName returns the name of a process, as "ps" shows it.
func processName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
