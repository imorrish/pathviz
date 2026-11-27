package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// backlogSize is how many finished journeys a newly opened page receives.
const backlogSize = 300

// idleFor is how long a namespace stays watched after its last page closed.
const idleFor = 30 * time.Second

// Options are what all the observers of a pathviz share.
type Options struct {
	Group int
	// PacketView tells whether the bytes of the traced packets are kept and served.
	PacketView bool
	// SkipPorts are the TCP ports of the web UI: its traffic is never traced.
	SkipPorts []int
	// Layers are the layers to probe.
	Layers []string
	// Egress tells that the kernel has the egress hook of devices.
	Egress bool
}

func (o Options) has(layer string) bool {
	for _, l := range o.Layers {
		if l == layer {
			return true
		}
	}
	return false
}

type message struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func encode(typ string, data any) []byte {
	b, _ := json.Marshal(message{typ, data})
	return b
}

// Observer watches one network namespace: it keeps the probes there, reads
// their events, and holds what the pages of this namespace show.
type Observer struct {
	opts Options
	inv  *Inventory
	// id is how the pages call the namespace, and label is how they show it.
	id string

	ctx     context.Context
	cancel  context.CancelFunc
	capture *Capture
	tracker *Tracker
	sockets *SocketTable
	memory  *BridgeMemory

	mu     sync.Mutex
	ns     Netns
	filter Filter
	rules  Rules
	// devices are the devices that the link probes are bound to.
	devices []string
	backlog []*Journey
	host    HostState
	hostKey string
	// peers maps a veth device to its other end, when both are in this namespace.
	peers     map[string]string
	subs      map[chan []byte]bool
	idleSince time.Time
	// pinned keeps the observer when no page is open: the namespace that
	// pathviz was started for.
	pinned bool
}

func startObserver(ctx context.Context, ns Netns, opts Options, inv *Inventory, filter Filter) (*Observer, error) {
	o := &Observer{opts: opts, inv: inv, id: inv.ID(ns), ns: ns, subs: map[chan []byte]bool{}, idleSince: time.Now(), memory: NewBridgeMemory()}
	o.ctx, o.cancel = context.WithCancel(ctx)
	o.sockets = NewSocketTable(ns, opts.SkipPorts)

	// The tracker must not wait for the socket lookups of a finished journey,
	// so the journeys go through a queue.
	finished := make(chan *Journey, 4096)
	o.tracker = NewTracker(func(j *Journey) {
		select {
		case finished <- j:
		default: // the page cannot keep up anyway
		}
	}, o.peer)
	go func() {
		for {
			select {
			case <-o.ctx.Done():
				return
			case j := <-finished:
				o.onJourney(j)
			}
		}
	}()
	go func() {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-o.ctx.Done():
				return
			case now := <-tick.C:
				o.tracker.Flush(now)
			}
		}
	}()

	// Bind to the NFLOG group before the probes exist, so no event is missed.
	c, err := StartCapture(o.ctx, ns, opts.Group, opts.PacketView, o.tracker.Add, o.tracker.Lost)
	if err != nil {
		o.cancel()
		return nil, err
	}
	o.capture = c
	inv.Watch(ns.Ino, true)
	o.refresh()
	if err := o.SetFilter(filter); err != nil {
		o.close()
		return nil, err
	}
	return o, nil
}

func (o *Observer) peer(dev string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.peers[dev]
}

// refresh takes the current state of the namespace from the inventory. It
// returns false when the namespace is gone.
func (o *Observer) refresh() bool {
	d, all := o.inv.View(o.ns.Ino)
	if d == nil {
		return false
	}
	o.capture.SetNetns(d.ns)
	o.sockets.SetNetns(d.ns)
	o.sockets.Refresh()

	st := buildState(d, all, o.memory.ARP())
	st.Procs = o.sockets.Procs()
	o.memory.Update(d.fdb, st.Bridges)
	peers := map[string]string{}
	var devices []string
	for _, l := range d.links {
		if l.Link != "" {
			peers[l.Name] = l.Link
		}
		if ifaceName.MatchString(l.Name) {
			devices = append(devices, l.Name)
		}
	}
	sort.Strings(devices)
	key, _ := json.Marshal(st)

	o.mu.Lock()
	o.ns, o.peers = d.ns, peers
	rebind := o.rules != nil && strings.Join(devices, " ") != strings.Join(o.devices, " ")
	o.devices = devices
	if string(key) != o.hostKey {
		o.host, o.hostKey = st, string(key)
		o.broadcast(encode("host", st))
	}
	o.mu.Unlock()
	if rebind {
		// The devices changed: the link probes are bound to the new set. The
		// other probes stay as they are, and so do the traced packets.
		o.mu.Lock()
		f := o.filter
		o.mu.Unlock()
		if err := o.install(f, []string{L1}); err != nil {
			log.Printf("%s: cannot bind the link probes to the devices: %v", o.id, err)
		}
	}
	return true
}

// install builds the probes for a filter and loads the ones of the given layers.
func (o *Observer) install(f Filter, layers []string) error {
	o.mu.Lock()
	ns := o.ns
	ro := RuleOptions{Group: o.opts.Group, SkipPorts: o.opts.SkipPorts, Layers: o.opts.Layers, Devices: o.devices, Egress: o.opts.Egress}
	o.mu.Unlock()
	rules := BuildRules(f, ro)
	for _, layer := range layers {
		script := rules[layer]
		if script == "" {
			// The layer is off, or the namespace has no device: no table.
			script = removeScript(layerFamily[layer])
		}
		if err := InstallProbes(ns, script); err != nil {
			return err
		}
	}
	o.mu.Lock()
	if o.rules == nil {
		o.rules = Rules{}
	}
	for _, layer := range layers {
		o.rules[layer] = rules[layer]
	}
	o.mu.Unlock()
	return nil
}

// SetFilter validates the filter and reinstalls the probes for it.
func (o *Observer) SetFilter(f Filter) error {
	if err := f.Normalize(); err != nil {
		return err
	}
	o.mu.Lock()
	before := o.rules.Text()
	o.mu.Unlock()
	// The IP probes go first: a filter they refuse changes nothing.
	if err := o.install(f, []string{L3, L2, L1}); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if before != "" && before != o.rules.Text() {
		// The packets traced so far belong to the previous filter.
		o.backlog = nil
		o.broadcast(encode("clear", nil))
	}
	o.filter = f
	o.broadcast(encode("filter", f))
	return nil
}

// broadcast sends a message to all open pages. A page that cannot keep up is
// disconnected and reloads the backlog when it reconnects. The caller holds o.mu.
func (o *Observer) broadcast(msg []byte) {
	for ch := range o.subs {
		select {
		case ch <- msg:
		default:
			delete(o.subs, ch)
			close(ch)
		}
	}
}

// onJourney stores a finished journey and pushes it to the open pages.
func (o *Observer) onJourney(j *Journey) {
	o.mu.Lock()
	keep := o.filter.Keeps(j)
	o.mu.Unlock()
	if !keep {
		return
	}
	o.sockets.ResolveOwners(j)
	o.memory.Annotate(j)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.backlog = append(o.backlog, j)
	if len(o.backlog) > backlogSize {
		o.backlog = o.backlog[len(o.backlog)-backlogSize:]
	}
	o.broadcast(encode("journey", j))
}

// Clear forgets the traced packets.
func (o *Observer) Clear() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.backlog = nil
	o.broadcast(encode("clear", nil))
}

// Journey returns a traced packet that is still kept.
func (o *Observer) Journey(id uint64) *Journey {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, j := range o.backlog {
		if j.ID == id {
			return j
		}
	}
	return nil
}

// Rules returns the installed probes as text.
func (o *Observer) Rules() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.rules.Text()
}

// snapshot is what a newly opened page gets about the namespace.
type snapshot struct {
	Netns    string     `json:"netns"`
	State    HostState  `json:"state"`
	Filter   Filter     `json:"filter"`
	Journeys []*Journey `json:"journeys"`
}

// subscribe registers a page. It returns the channel of its messages and the
// state to start from.
func (o *Observer) subscribe() (chan []byte, snapshot) {
	ch := make(chan []byte, 1024)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.subs[ch] = true
	return ch, snapshot{Netns: o.id, State: o.host, Filter: o.filter, Journeys: append([]*Journey{}, o.backlog...)}
}

func (o *Observer) unsubscribe(ch chan []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.subs[ch] {
		delete(o.subs, ch)
	}
	if len(o.subs) == 0 {
		o.idleSince = time.Now()
	}
}

// idle tells whether nobody has needed the observer for a while.
func (o *Observer) idle() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.pinned && len(o.subs) == 0 && time.Since(o.idleSince) > idleFor
}

// touch keeps an observer without pages for a while longer.
func (o *Observer) touch() {
	o.mu.Lock()
	o.idleSince = time.Now()
	o.mu.Unlock()
}

// close stops the capture, tells the pages, and removes the probes if the
// namespace is still there.
func (o *Observer) close() {
	o.cancel()
	o.inv.Watch(o.ns.Ino, false)
	o.mu.Lock()
	ns, installed := o.ns, o.rules != nil
	o.broadcast(encode("gone", nil))
	for ch := range o.subs {
		delete(o.subs, ch)
		close(ch)
	}
	o.mu.Unlock()
	if !installed {
		return
	}
	if ino, ok := inodeOf(ns.Path); !ok || ino != ns.Ino {
		return // the namespace is gone, and its tables with it
	}
	if err := RemoveProbes(ns); err != nil {
		log.Printf("%s: cannot remove the probes: %v", o.id, err)
	}
}

// Hub holds the observers: one per watched namespace. A namespace is watched
// while a page shows it, and the one pathviz was started for is watched always.
type Hub struct {
	ctx  context.Context
	opts Options
	inv  *Inventory
	// first is the filter that a newly watched namespace starts with.
	first Filter

	mu        sync.Mutex
	observers map[uint64]*Observer
	spaces    []Space
	spacesKey string
}

// NewHub creates a hub that watches nothing yet.
func NewHub(ctx context.Context, opts Options, inv *Inventory, first Filter) *Hub {
	return &Hub{ctx: ctx, opts: opts, inv: inv, first: first, observers: map[uint64]*Observer{}}
}

// Observe returns the observer of a namespace, and starts it if needed.
// An empty name stands for the home namespace.
func (h *Hub) Observe(name string, pin bool) (*Observer, error) {
	ns, ok := h.inv.Find(name)
	if !ok {
		return nil, fmt.Errorf("no network namespace %q", name)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if o := h.observers[ns.Ino]; o != nil {
		o.touch()
		return o, nil
	}
	o, err := startObserver(h.ctx, ns, h.opts, h.inv, h.first)
	if err != nil {
		return nil, err
	}
	o.pinned = pin
	h.observers[ns.Ino] = o
	if !pin {
		log.Printf("watching the namespace %s", o.id)
	}
	return o, nil
}

// Spaces lists the namespaces of the machine.
func (h *Hub) Spaces() []Space {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.spaces
}

// Tick reloads the inventory and brings the observers up to date. It runs on
// a timer.
func (h *Hub) Tick() {
	if err := h.inv.Refresh(); err != nil {
		log.Printf("%v", err)
		return
	}
	spaces := h.inv.Spaces()
	key, _ := json.Marshal(spaces)

	h.mu.Lock()
	changed := string(key) != h.spacesKey
	h.spaces, h.spacesKey = spaces, string(key)
	list := make([]*Observer, 0, len(h.observers))
	for _, o := range h.observers {
		list = append(list, o)
	}
	h.mu.Unlock()

	for _, o := range list {
		alive := o.refresh()
		if alive && !o.idle() {
			if changed {
				o.mu.Lock()
				o.broadcast(encode("spaces", spaces))
				o.mu.Unlock()
			}
			continue
		}
		h.mu.Lock()
		delete(h.observers, o.ns.Ino)
		h.mu.Unlock()
		o.close()
		log.Printf("stopped watching the namespace %s", o.id)
	}
}

// Lost returns how many probe events an observer has lost so far.
func (o *Observer) Lost() uint64 { return o.capture.LostEvents() }

// Close stops all the observers and removes their probes.
func (h *Hub) Close() {
	h.mu.Lock()
	list := make([]*Observer, 0, len(h.observers))
	for ino, o := range h.observers {
		list = append(list, o)
		delete(h.observers, ino)
	}
	h.mu.Unlock()
	for _, o := range list {
		o.close()
	}
}

// egressSupported tells whether the kernel has the egress hook of devices.
// The check creates a chain on that hook and deletes it in one transaction,
// so nothing of it is ever visible.
func egressSupported(ns Netns) bool {
	const script = "table netdev pathviz_check { chain c { type filter hook egress device lo priority 0; } }\ndelete table netdev pathviz_check\n"
	return nft(ns, script, "-f", "-") == nil
}
