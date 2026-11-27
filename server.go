package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

// Server is the HTTP side of pathviz: the page and its API.
type Server struct {
	// token is the secret every API request must carry. It is empty when the
	// check is off (--dangerously-skip-token).
	token string
	hub   *Hub
	opts  Options
	// netns is the namespace that a page shows unless it asks for another.
	netns string
}

// hello is the first message of an event stream: all that a page needs to
// draw itself.
type hello struct {
	Host string `json:"host"`
	// Spaces are the namespaces the page can switch to.
	Spaces []Space `json:"spaces"`
	// Layers are the layers that pathviz probes, and Egress tells whether the
	// kernel has the egress hook of devices.
	Layers []string `json:"layers"`
	Egress bool     `json:"egress"`
	Hooks  []Hook   `json:"hooks"`
	// PacketView tells the page whether it can ask for the bytes of a packet.
	PacketView bool `json:"packetView"`
	snapshot
}

// observer returns the observer of the namespace a request asks for.
func (s *Server) observer(w http.ResponseWriter, r *http.Request) *Observer {
	name := r.URL.Query().Get("netns")
	if name == "" {
		name = s.netns
	}
	o, err := s.hub.Observe(name, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return nil
	}
	return o
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported", http.StatusInternalServerError)
		return
	}
	o := s.observer(w, r)
	if o == nil {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	host, _ := os.Hostname()
	ch, snap := o.subscribe()
	defer o.unsubscribe(ch)

	send := func(msg []byte) {
		fmt.Fprintf(w, "data: %s\n\n", msg)
		fl.Flush()
	}
	send(encode("hello", hello{Host: host, Spaces: s.hub.Spaces(), Layers: s.opts.Layers, Egress: s.opts.Egress, Hooks: Hooks, PacketView: s.opts.PacketView, snapshot: snap}))
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			send(msg)
		case <-tick.C:
			send(encode("stats", map[string]uint64{"lost": o.Lost()}))
		}
	}
}

// allowChange guards the endpoints that change something. It rejects requests
// that another website could make a visitor's browser send (CSRF): such requests
// cannot carry a JSON content type without a CORS preflight, which pathviz never
// approves, and browsers label them as cross-site.
func allowChange(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "use Content-Type: application/json", http.StatusUnsupportedMediaType)
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site requests are not allowed", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) handleFilter(w http.ResponseWriter, r *http.Request) {
	if !allowChange(w, r) {
		return
	}
	var f Filter
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&f); err != nil {
		http.Error(w, "bad filter: "+err.Error(), http.StatusBadRequest)
		return
	}
	o := s.observer(w, r)
	if o == nil {
		return
	}
	if err := o.SetFilter(f); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if !allowChange(w, r) {
		return
	}
	if o := s.observer(w, r); o != nil {
		o.Clear()
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleRuleset(w http.ResponseWriter, r *http.Request) {
	if o := s.observer(w, r); o != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, o.Rules())
	}
}

// packetHop is a packet as one probe saw it, split into layers and fields.
type packetHop struct {
	// Index is the place of the hop among the hops of the journey.
	Index int    `json:"index"`
	Layer string `json:"layer"`
	Hook  string `json:"hook"`
	Stage string `json:"stage"`
	Exit  bool   `json:"exit,omitempty"`
	Dissection
}

// handlePacket returns the bytes of a traced packet at every hop.
func (s *Server) handlePacket(w http.ResponseWriter, r *http.Request) {
	if !s.opts.PacketView {
		http.Error(w, "the packet view is disabled (--no-packet-view)", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad packet id", http.StatusBadRequest)
		return
	}
	o := s.observer(w, r)
	if o == nil {
		return
	}
	j := o.Journey(id)
	if j == nil {
		http.Error(w, "the packet is not kept anymore", http.StatusNotFound)
		return
	}
	// A finished journey does not change, so it is read without a lock.
	hops := make([]packetHop, 0, len(j.Hops))
	for i, hop := range j.Hops {
		if i >= len(j.raw) || j.raw[i] == nil {
			continue
		}
		hops = append(hops, packetHop{Index: i, Layer: hop.Layer, Hook: hop.Hook, Stage: hop.Stage, Exit: hop.Exit, Dissection: DissectFrame(j.raw[i], j.l2len[i])})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"id": j.ID, "hops": hops})
}

// tokenMatches compares a value with the access token in constant time.
func (s *Server) tokenMatches(got string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// authorized tells whether the request carries the access token: in the
// Authorization header, or in the URL for an EventSource, which cannot set
// headers. A cookie is not accepted, and PathViz never sets one: a browser
// sends the cookies of a host to every port of it, so any other web server of
// the machine that the browser visits would get the token.
func (s *Server) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && s.tokenMatches(bearer) {
		return true
	}
	return s.tokenMatches(r.URL.Query().Get("token"))
}

// Handler returns the HTTP handler of the UI and its API. The files of the
// page hold no secrets and are open to everyone. The API is not: without the
// token the page can neither see a packet nor change anything.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("/api/events", s.handleEvents)
	api.HandleFunc("/api/filter", s.handleFilter)
	api.HandleFunc("/api/clear", s.handleClear)
	api.HandleFunc("/api/ruleset", s.handleRuleset)
	api.HandleFunc("/api/packet", s.handlePacket)
	// The page asks this one whether its token is right.
	api.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	static, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(static))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// The address of the page can hold the token: it must not leak to other sites.
		w.Header().Set("Referrer-Policy", "no-referrer")
		// The page is small and changes with every release of pathviz.
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			http.Error(w, "the access token is missing or wrong", http.StatusUnauthorized)
			return
		}
		api.ServeHTTP(w, r)
	})
	return mux
}
