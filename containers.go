package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// containerInfo is what a container runtime knows about a container.
type containerInfo struct {
	Name    string
	Pod     string // the pod of the container, if it has one
	Runtime string // docker, podman, containerd, cri-o
}

// containerID is how every popular runtime names the cgroup of a container:
// docker-<id>.scope, libpod-<id>.scope, cri-containerd-<id>.scope,
// crio-<id>.scope, /docker/<id>, /default/<id>.
var containerID = regexp.MustCompile(`[0-9a-f]{64}`)

// containerOfPid returns the ID of the container that a process runs in, or
// an empty string.
func containerOfPid(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return containerOfCgroup(string(b))
}

func containerOfCgroup(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		// The conmon of Podman and CRI-O lives next to its container, in a
		// cgroup with the same ID, and in the network namespace of the host.
		if strings.Contains(line, "conmon") {
			continue
		}
		if ids := containerID.FindAllString(line, -1); len(ids) > 0 {
			return ids[len(ids)-1]
		}
	}
	return ""
}

// containerResolver turns container IDs into names by asking the container
// runtimes of the machine. It keeps what it has learned.
type containerResolver struct {
	mu      sync.Mutex
	known   map[string]containerInfo
	lastTry time.Time
}

func newContainerResolver() *containerResolver {
	return &containerResolver{known: map[string]containerInfo{}}
}

// retryEvery is how often the runtimes are asked about the IDs that none of
// them knew.
const retryEvery = 3 * time.Second

// Resolve returns what is known about the containers. It asks the runtimes
// when it sees an ID for the first time.
func (r *containerResolver) Resolve(ids []string) map[string]containerInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	var unknown []string
	for _, id := range ids {
		if _, ok := r.known[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 && time.Since(r.lastTry) > retryEvery {
		r.lastTry = time.Now()
		for id, info := range listContainers(unknown) {
			r.known[id] = info
		}
	}
	out := map[string]containerInfo{}
	for _, id := range ids {
		if info, ok := r.known[id]; ok {
			out[id] = info
		}
	}
	return out
}

func toolOutput(name string, args ...string) ([]byte, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return out, err == nil
}

// listContainers asks every runtime it can find for its containers.
func listContainers(wanted []string) map[string]containerInfo {
	found := map[string]containerInfo{}
	missing := func() []string {
		var out []string
		for _, id := range wanted {
			if _, ok := found[id]; !ok {
				out = append(out, id)
			}
		}
		return out
	}
	add := func(id string, info containerInfo) {
		if _, ok := found[id]; !ok && id != "" && info.Name != "" {
			found[id] = info
		}
	}

	if out, ok := toolOutput("docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"); ok {
		for id, info := range parsePsTable(string(out), "docker") {
			add(id, info)
		}
	}
	if len(missing()) > 0 {
		out, ok := toolOutput("podman", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.PodName}}")
		if !ok {
			out, ok = toolOutput("podman", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}")
		}
		if ok {
			for id, info := range parsePsTable(string(out), "podman") {
				add(id, info)
			}
		}
	}
	if len(missing()) > 0 {
		// crictl speaks to containerd and to CRI-O alike.
		pods, okPods := toolOutput("crictl", "pods", "-o", "json")
		ctrs, okCtrs := toolOutput("crictl", "ps", "-o", "json")
		if okPods || okCtrs {
			for id, info := range parseCrictl(pods, ctrs) {
				add(id, info)
			}
		}
	}
	if ids := missing(); len(ids) > 0 {
		// containerd without the CRI: nerdctl and ctr keep the name in a label.
		if out, ok := toolOutput("ctr", "namespaces", "ls", "-q"); ok {
			for _, ns := range strings.Fields(string(out)) {
				for _, id := range ids {
					if _, done := found[id]; done {
						continue
					}
					if info, ok := toolOutput("ctr", "-n", ns, "containers", "info", id); ok {
						add(id, parseCtrInfo(info, id))
					}
				}
			}
		}
	}
	return found
}

// parsePsTable reads the lines of "docker ps" or "podman ps": the ID, the
// names, and for Podman the pod, separated by tabs.
func parsePsTable(out, runtime string) map[string]containerInfo {
	found := map[string]containerInfo{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		info := containerInfo{Name: strings.Split(fields[1], ",")[0], Runtime: runtime}
		if len(fields) > 2 {
			info.Pod = fields[2]
		}
		found[fields[0]] = info
	}
	return found
}

type criMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// parseCrictl reads the JSON of "crictl pods" and "crictl ps".
func parseCrictl(podsJSON, containersJSON []byte) map[string]containerInfo {
	found := map[string]containerInfo{}
	var pods struct {
		Items []struct {
			ID             string  `json:"id"`
			Metadata       criMeta `json:"metadata"`
			RuntimeHandler string  `json:"runtimeHandler"`
		} `json:"items"`
	}
	json.Unmarshal(podsJSON, &pods)
	podName := func(m criMeta) string {
		if m.Namespace == "" || m.Namespace == "default" {
			return m.Name
		}
		return m.Namespace + "/" + m.Name
	}
	for _, p := range pods.Items {
		// The sandbox (the "pause" container) holds the network namespace.
		found[p.ID] = containerInfo{Name: podName(p.Metadata), Pod: podName(p.Metadata), Runtime: "cri"}
	}
	var ctrs struct {
		Containers []struct {
			ID       string            `json:"id"`
			Metadata criMeta           `json:"metadata"`
			Labels   map[string]string `json:"labels"`
		} `json:"containers"`
	}
	json.Unmarshal(containersJSON, &ctrs)
	for _, c := range ctrs.Containers {
		pod := podName(criMeta{Name: c.Labels["io.kubernetes.pod.name"], Namespace: c.Labels["io.kubernetes.pod.namespace"]})
		found[c.ID] = containerInfo{Name: c.Metadata.Name, Pod: pod, Runtime: "cri"}
	}
	return found
}

// parseCtrInfo reads the JSON of "ctr containers info".
func parseCtrInfo(out []byte, id string) containerInfo {
	var info struct {
		Labels map[string]string `json:"Labels"`
	}
	if json.Unmarshal(out, &info) != nil {
		return containerInfo{}
	}
	pod := info.Labels["io.kubernetes.pod.name"]
	if ns := info.Labels["io.kubernetes.pod.namespace"]; pod != "" && ns != "" && ns != "default" {
		pod = ns + "/" + pod
	}
	name := info.Labels["nerdctl/name"]
	if name == "" {
		name = info.Labels["io.kubernetes.container.name"]
	}
	if name == "" {
		name = pod
	}
	if name == "" {
		// A container that was started with plain ctr has only its ID, and
		// the ID is the name the user gave it.
		name = id
	}
	return containerInfo{Name: name, Pod: pod, Runtime: "containerd"}
}
