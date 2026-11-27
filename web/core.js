// What all the views share: the page's parameters, the API, the state that
// comes from pathviz, and the helpers that draw.

export const SVG = 'http://www.w3.org/2000/svg';
export const $ = (sel) => document.querySelector(sel);

// What a page shows comes from its URL, so that a view can be embedded:
//   ?mode=l3|l2|l1|all  the layer: IP hooks, bridge hooks, device hooks, or all
//   ?sub=<name>         the look of the layer: stages or hooks for l3 and all,
//                       topology or hooks for l2 (?detail=hooks still means
//                       l3 hooks)
//   ?layers=l2,l3       the layers of the combined view
//   ?netns=<name>       the network namespace to watch
//   ?bridges=br0,br1    only these bridges (l2)
//   ?view=embed         a small read-only view: the diagram and little else
//   ?panels=packets,details  which tables to show. In an embedded view they go
//                       below the diagram, and without it the view has a switch
//                       between the path and the tables. An empty list hides all
//                       (?tables=packets,stages is the old name of it)
//   ?ifaces=eth0,lo     only these interface cards (l3, l1)
//   ?procs=nginx,:8080  only these processes (l3)
//   ?theme=dark|light   force the colors (index.html applies it)
//   ?speed=0.5          how fast a packet travels through the diagram: 0.25 to 2
// An embedded view also has its own display filter, so several embeds of one
// pathviz can show different traffic: ?proto=tcp&port=8080&ip=10.0.0.1&iface=in:eth0&mac=...
export const params = new URLSearchParams(location.search);
export const listParam = (name) => (params.has(name) ? params.get(name).split(',').map((v) => v.trim()).filter(Boolean) : null);

export const embed = params.get('view') === 'embed';

// ---- Access token and API ----------------------------------------------------

// PathViz prints the address of the page with the token in it. The page takes
// the token out of the address bar, keeps it for the next visits, and sends it
// with every call of the API. It is kept in the storage of this origin (host
// and port) and not in a cookie: a browser sends the cookies of a host to every
// port of it, so another web server of the same machine would get the token.
const TOKEN_KEY = 'pathviz.token';
let token = params.get('token') || '';

export function keepToken(value) {
  token = value;
  try { localStorage.setItem(TOKEN_KEY, value); } catch { /* the token then lives as long as the page */ }
}
export const getToken = () => token;

// setParam writes a parameter of the page to the address bar, without a reload.
export function setParam(name, value) {
  if (value === null || value === undefined || value === '') params.delete(name);
  else params.set(name, value);
  const rest = params.toString();
  history.replaceState(null, '', location.pathname + (rest ? `?${rest}` : '') + location.hash);
}

if (token) {
  keepToken(token);
  setParam('token', null);
} else {
  try { token = localStorage.getItem(TOKEN_KEY) || ''; } catch { /* no storage, no kept token */ }
}

// store is what pathviz told the page.
export const store = {
  hostName: '',
  netns: '',           // the ID of the watched namespace
  spaces: [],          // the namespaces of the machine
  layers: [],          // the layers that are probed
  egress: false,       // whether devices have the egress hook
  hooks: [],           // the IP hooks and their stages
  packetView: false,
  host: { ifaces: [], procs: [], bridges: [] },
  capture: emptyFilter(), // what pathviz traces
};

export function emptyFilter() { return { protos: [], ifaces: [], macs: [], ips: [], ports: [] }; }

// apiPath adds the watched namespace to a path of the API.
export function apiPath(path, netns = store.netns) {
  if (!netns) return path;
  return `${path}${path.includes('?') ? '&' : '?'}netns=${encodeURIComponent(netns)}`;
}

// api calls the API of pathviz with the token.
export function api(path, opts = {}) {
  const headers = { ...opts.headers };
  if (token) headers.Authorization = `Bearer ${token}`;
  return fetch(apiPath(path), { ...opts, headers });
}

export const post = (path, body) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// ---- Speed -------------------------------------------------------------------

// The speed is a playback rate, like in a video player: x1 is normal.
export const SPEED_STEPS = [0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.75, 2];
const SPEED_NAMES = { slow: 0.5, medium: 1, normal: 1, fast: 1.5 };

function speedParam() {
  const raw = (params.get('speed') || '1').trim().toLowerCase();
  if (raw in SPEED_NAMES) return SPEED_NAMES[raw];
  const rate = Number(raw.replace(/^x|x$/, ''));
  if (!Number.isFinite(rate) || rate <= 0) return 1;
  // Snap to the nearest step of the range.
  return Math.min(2, Math.max(0.25, Math.round(rate * 4) / 4));
}

export const playback = { speed: speedParam() };
export const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

// ---- Elements ----------------------------------------------------------------

// el makes an SVG element.
export function el(name, attrs = {}, text) {
  const e = document.createElementNS(SVG, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

// html makes an HTML element.
export function html(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined && c !== '') node.append(c);
  return node;
}

// svgButton makes an SVG group behave like a button. An embedded view is
// read-only, so its groups stay as they are. The label goes to the tooltip,
// after what the group already says there.
export function svgButton(g, label, onPick) {
  if (embed) return;
  g.setAttribute('role', 'button');
  g.setAttribute('tabindex', '0');
  g.setAttribute('aria-label', label);
  const title = g.querySelector(':scope > title');
  if (title) title.textContent = title.textContent ? `${title.textContent}\n${label}` : label;
  else g.append(el('title', {}, label));
  // With Ctrl or Cmd held, a pick adds to what is picked already.
  const more = (e) => e.ctrlKey || e.metaKey;
  g.addEventListener('click', (e) => { e.stopPropagation(); onPick(more(e)); });
  g.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); onPick(more(e)); }
  });
}

// tracedTag marks a picked box: the box is a part of what the filter traces.
// It differs from the highlight of a passing packet. The tag ends at x.
export function tracedTag(x, y) {
  const g = el('g', { class: 'tag' });
  g.append(el('rect', { x: x - 44, y: y - 8, width: 44, height: 15, rx: 7.5 }), el('text', { x: x - 22, y: y + 3, 'text-anchor': 'middle' }, 'traced'));
  return g;
}

// pickable makes a part of a diagram a button that traces only what the part
// stands for. A click on the only traced part goes back to tracing everything,
// and a click with Ctrl or Cmd adds the part to the traced ones or takes it
// out. ctx is what the page gave the view, filter is the fields the part
// stands for, and what names the traffic in the tooltip.
export function pickable(g, ctx, filter, what) {
  if (embed) return;
  const full = { ...emptyFilter(), ...filter };
  const picked = filterHas(ctx.filter(), full);
  svgButton(g, `${picked ? `Stop tracing only ${what}` : `Trace only ${what}`}\nWith Ctrl or Cmd: ${picked ? 'take it out of' : 'add it to'} what is traced`, (more) => ctx.pick(full, more));
  g.classList.add('pick');
  if (!picked) return;
  g.classList.add('picked');
  const box = g.querySelector(':scope > rect');
  if (!box) return;
  const x = Number(box.getAttribute('x')), w = Number(box.getAttribute('width'));
  const y = Number(box.getAttribute('y'));
  // On a box the tag sits on the top edge, in the corner. A pill is low, so
  // its tag is in the middle of the edge and a touch higher, clear of the text.
  g.append(g.classList.contains('port') ? tracedTag(x + w / 2 + 22, y - 1) : tracedTag(x + w - 4, y));
}

// ---- Words -------------------------------------------------------------------

export function clock(iso) {
  const d = new Date(iso);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export const short = (text, n = 22) => (text.length > n ? `${text.slice(0, n - 1)}…` : text);
export const list = (items) => (items.length <= 2 ? items.join(' and ') : `${items.slice(0, -1).join(', ')}, and ${items[items.length - 1]}`);
export const micros = (us) => `${us} µs`;

// space returns the watched namespace as the page lists it.
export const space = () => store.spaces.find((s) => s.id === store.netns) || { id: store.netns, kind: 'host', name: store.hostName };

// spaceLabel names a namespace in a list: "web (docker container)".
export function spaceLabel(s) {
  switch (s.kind) {
    case 'host': return `${s.name} (host)`;
    case 'container': return `${s.name} (${s.runtime && s.runtime !== 'cri' ? `${s.runtime} ` : ''}container)`;
    case 'pod': return `${s.name} (pod)`;
    case 'process': return s.name;
    default: return `${s.name} (netns)`;
  }
}

// stackName names the network stack of the watched namespace in a sentence.
export function stackName() {
  const s = space();
  switch (s.kind) {
    case 'host': return 'the host';
    case 'container': return `the container ${s.name}`;
    case 'pod': return `the pod ${s.name}`;
    case 'process': return `the namespace of ${s.name}`;
    default: return `the ${s.name} namespace`;
  }
}

// peerKind tells what kind of a thing is behind a device.
export function peerKind(dev) {
  const peer = dev.peer;
  if (!peer) return dev.kind ? `${dev.kind} device` : 'physical device';
  if (peer.bridge && peer.kind === 'local') return 'another bridge';
  switch (peer.kind) {
    case 'container': return peer.runtime && peer.runtime !== 'cri' ? `${peer.runtime} container` : 'container';
    case 'pod': return 'pod';
    case 'netns': return 'network namespace';
    case 'process': return 'namespace of a process';
    case 'host': return 'host';
    default: return 'same namespace';
  }
}

// peerName names what a device leads to, when that is known.
export function peerName(dev) {
  if (!dev || !dev.peer) return '';
  if (dev.peer.bridge && dev.peer.kind === 'local') return `bridge ${dev.peer.bridge}`;
  return dev.peer.name;
}

// procKey names a process in the list of the blocks to show. A pid changes
// with every restart, so the name and the ports stand for the process.
export const procKey = (proc) => `${proc.name} ${proc.sockets.map((s) => `:${s.port}`).join(' ')}`;

export const ifaceByName = (name) => store.host.ifaces.find((i) => i.name === name) || null;

// ---- Drawing -----------------------------------------------------------------

export const CARD_W = 176, CARD_H = 76;

// drawCard draws what is at the end of a device: the kind of the thing, its
// name, and two lines about it. Long texts are cut, and the whole of them is
// in the tooltip.
export function drawCard(parent, x, top, kind, name, lines, cls) {
  const g = el('g', { class: `card ${cls || ''}` });
  g.append(el('title', {}, [`${name} (${kind})`, ...lines].join('\n')));
  g.append(el('rect', { x: x - CARD_W / 2, y: top, width: CARD_W, height: CARD_H, rx: 8 }));
  g.append(el('text', { x, y: top + 15, 'text-anchor': 'middle', class: 'kind' }, kind));
  g.append(el('text', { x, y: top + 33, 'text-anchor': 'middle', class: 'name' }, short(name, 24)));
  lines.forEach((line, i) => g.append(el('text', { x, y: top + 50 + i * 14, 'text-anchor': 'middle', class: 'addr' }, short(line, 26))));
  parent.append(g);
  return g;
}

// peerCard draws the card of what a device leads to.
export function peerCard(parent, x, top, dev, macs = []) {
  const peer = dev.peer;
  const learned = macs.map((m) => m.ip).filter(Boolean);
  let name, lines, empty = false;
  if (peer && peer.bridge) {
    // The device leads to another bridge, with all that is behind it.
    name = peer.kind === 'local' ? peer.bridge : `${peer.name} · ${peer.bridge}`;
    lines = [`its port ${peer.ifname}`, macs.length ? `${macs.length} MAC ${macs.length > 1 ? 'addresses' : 'address'} behind it` : peer.mac];
  } else if (peer) {
    name = peer.name;
    const ips = peer.addrs && peer.addrs.length ? peer.addrs : learned;
    const others = macs.filter((m) => m.mac !== peer.mac).length;
    lines = [[peer.kind === 'local' ? '' : peer.ifname, ips.join(', ') || 'no IP address'].filter(Boolean).join(' · '), others ? `${peer.mac} +${others}` : peer.mac];
  } else if (macs.length) {
    name = `behind ${dev.name}`;
    lines = [learned.join(', ') || 'IP not seen yet', macs.length > 1 ? `${macs[0].mac} +${macs.length - 1}` : macs[0].mac];
  } else if (dev.kind === 'loopback') {
    name = 'this namespace';
    lines = ['Loopback: what is sent', 'comes right back'];
  } else if (dev.kind === 'bridge') {
    name = `ports of ${dev.name}`;
    lines = ['The frames come from', 'the ports of the bridge'];
  } else {
    name = dev.kind ? dev.name : 'the network';
    lines = dev.kind ? ['Nothing is known', 'about the other end'] : ['Whatever the device', 'is plugged into'];
    empty = !!dev.kind;
  }
  return drawCard(parent, x, top, peerKind(dev), name, lines, empty ? 'empty' : '');
}

// drawPill draws a rounded label: a port, a hook of a device.
export function drawPill(parent, x, y, text, cls) {
  const w = Math.max(64, text.length * 7.6 + 22);
  const g = el('g', { class: `port ${cls || ''}` });
  g.append(el('rect', { x: x - w / 2, y: y - 12, width: w, height: 24, rx: 12 }));
  g.append(el('text', { x, y: y + 4, 'text-anchor': 'middle' }, text));
  parent.append(g);
  return g;
}

// drawHook draws the box of a hook, with an optional second line.
export function drawHook(parent, x, y, name, sub, w = 150, h = 44) {
  const g = el('g', { class: 'hook' });
  g.append(el('rect', { x: x - w / 2, y: y - h / 2, width: w, height: h, rx: 10 }));
  g.append(el('text', { class: 'hookname', x, y: sub ? y - 2 : y + 4, 'text-anchor': 'middle' }, name));
  if (sub) g.append(el('text', { class: 'hooksub', x, y: y + 13, 'text-anchor': 'middle' }, sub));
  g.append(el('title'));
  parent.append(g);
  return g;
}

// setWidth gives a diagram its natural width: a box that is too narrow for it
// scrolls sideways. With min, the diagram first shrinks with its box, down to
// that width. An embedded view scales the diagram to its box instead.
export function setWidth(svg, width, min) {
  if (embed) { svg.style.width = ''; return; }
  svg.style.width = min ? '100%' : `${width}px`;
  svg.style.maxWidth = min ? `${width}px` : '';
  svg.style.minWidth = min ? `${min}px` : '';
}

export const linePath = (pts) => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0]} ${p[1]}`).join(' ');

// tracer draws the way of a packet as trails that grow along their paths, and
// lights up what they reach. Several trails can run at once: the copies of a
// flooded frame.
export function tracer(svg, trails, marks) {
  let timers = [];
  let running = [];
  const t = {
    animate: false,
    // reset removes the trails and the marks of the previous packet.
    reset(animate) {
      timers.forEach(clearTimeout);
      timers = [];
      running.forEach((a) => a.cancel());
      running = [];
      trails.replaceChildren();
      marks.replaceChildren();
      for (const node of svg.querySelectorAll('.lit, .stopped, .rewrote')) node.classList.remove('lit', 'stopped', 'rewrote');
      t.animate = !!animate && !reducedMotion();
    },
    // later runs fn when the animation has got that far.
    later(ms, fn) {
      if (t.animate && ms > 0) timers.push(setTimeout(fn, ms));
      else fn();
    },
    // trail draws a path that starts to grow after the delay. It returns where
    // and when it ends.
    trail(points, cls, delay) {
      const pts = [];
      for (const p of points) {
        const last = pts[pts.length - 1];
        if (!last || last[0] !== p[0] || last[1] !== p[1]) pts.push(p);
      }
      let len = 0;
      for (let i = 1; i < pts.length; i++) len += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
      const node = el('path', { class: `trail ${cls || ''}`, d: linePath(pts) });
      trails.append(node);
      const duration = t.animate ? (len / (420 * playback.speed)) * 1000 : 0;
      if (duration > 0) {
        node.style.strokeDasharray = len;
        running.push(node.animate([{ strokeDashoffset: len }, { strokeDashoffset: 0 }], { duration, delay, fill: 'both', easing: 'linear' }));
      }
      return { end: pts[pts.length - 1], done: (t.animate ? delay : 0) + duration, length: len };
    },
    // timeAt tells when a trail that started at the delay has covered a distance.
    timeAt(delay, distance) {
      return t.animate ? delay + (distance / (420 * playback.speed)) * 1000 : 0;
    },
    light(node, at, cls = 'lit') {
      if (node) t.later(at, () => node.classList.add(...cls.split(' ')));
    },
    stop(point, at) {
      t.later(at, () => {
        const g = el('g', { class: 'stopmark', transform: `translate(${point[0]} ${point[1]})` });
        g.append(el('circle', { r: 9 }));
        g.append(el('path', { d: 'M-3.5 -3.5 L3.5 3.5 M3.5 -3.5 L-3.5 3.5' }));
        marks.append(g);
      });
    },
  };
  return t;
}

// ---- Display filter (embedded view) -------------------------------------------

function parseEndpoint(text) {
  let m = text.match(/^\[(.+)\]:(\d+)$/);
  if (m) return { ip: m[1], port: Number(m[2]) };
  m = text.match(/^([\d.]+):(\d+)$/);
  if (m) return { ip: m[1], port: Number(m[2]) };
  return { ip: text, port: null };
}

function ipv4Number(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d+$/.test(p) || Number(p) > 255)) return null;
  return parts.reduce((n, p) => n * 256 + Number(p), 0);
}

// An item is an address or an IPv4 prefix such as 10.0.0.0/8.
function ipMatches(ip, item) {
  if (!item.includes('/')) return ip === item;
  const [net, bitsText] = item.split('/');
  const a = ipv4Number(ip), n = ipv4Number(net), bits = Number(bitsText);
  if (a === null || n === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const size = 2 ** (32 - bits);
  return Math.floor(a / size) === Math.floor(n / size);
}

// An IPv6 endpoint is "[addr]:port" or an address with several colons.
const isV6 = (endpoint) => !!endpoint && (endpoint.startsWith('[') || endpoint.split(':').length > 2);

function protoMatches(j, protos) {
  if (!protos.length) return true;
  const type = j.frame ? j.frame.type : '';
  return protos.some((p) => {
    switch (p) {
      case 'arp': return type === 'ARP';
      case 'ip': return j.proto ? !isV6(j.src) : type === 'IPv4';
      case 'ip6': return j.proto ? isV6(j.src) : type === 'IPv6';
      case 'icmp': return j.proto === 'icmp' || j.proto === 'icmpv6';
      case 'other': return !j.proto && type !== 'ARP';
      default: return j.proto === p;
    }
  });
}

// journeyMatches tells whether one of the hops of a journey satisfies a whole
// filter. It is the rule the probes follow: a packet that matched once stays
// in view.
export function journeyMatches(j, f) {
  if (!protoMatches(j, f.protos)) return false;
  return j.hops.some((hop) => {
    if (f.ports.length || f.ips.length) {
      if (!hop.src) return false;
      const src = parseEndpoint(hop.src), dst = parseEndpoint(hop.dst);
      if (f.ports.length && !f.ports.includes(src.port) && !f.ports.includes(dst.port)) return false;
      if (f.ips.length && !f.ips.some((item) => ipMatches(src.ip, item) || ipMatches(dst.ip, item))) return false;
    }
    if (f.macs.length && !f.macs.includes(hop.smac) && !f.macs.includes(hop.dmac)) return false;
    if (f.ifaces.length) {
      const ok = f.ifaces.some((entry) => {
        const dir = entry.startsWith('in:') ? 'in' : entry.startsWith('out:') ? 'out' : '';
        const name = dir ? entry.slice(dir.length + 1) : entry;
        return (dir !== 'out' && (hop.in === name || hop.pin === name)) || (dir !== 'in' && (hop.out === name || hop.pout === name)) || hop.bridge === name;
      });
      if (!ok) return false;
    }
    return true;
  });
}

// The filter as a set of picks: a part is a filter with a few values, such as
// one interface or the ports of a process.
const FIELDS = ['protos', 'ifaces', 'macs', 'ips', 'ports'];
const sorted = (k, values) => [...new Set(values)].sort(k === 'ports' ? (a, b) => a - b : undefined);

// filterHas tells whether a filter traces a part: it has every value of it.
export function filterHas(f, part) {
  return FIELDS.some((k) => part[k].length) && FIELDS.every((k) => part[k].every((v) => f[k].includes(v)));
}

// filterWith adds the values of a part to a filter.
export function filterWith(f, part) {
  return Object.fromEntries(FIELDS.map((k) => [k, sorted(k, [...f[k], ...part[k]])]));
}

// filterWithout takes the values of a part out of a filter. The protocols of
// a part with ports go only with the last port: other ports may need them.
export function filterWithout(f, part) {
  const out = Object.fromEntries(FIELDS.map((k) => [k, k === 'protos' ? f[k] : f[k].filter((v) => !part[k].includes(v))]));
  if (!part.ports.length || !out.ports.length) out.protos = f.protos.filter((v) => !part.protos.includes(v));
  return out;
}

export const sameList = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
export const sameFilter = (a, b) => ['protos', 'ifaces', 'macs', 'ips', 'ports'].every((k) => sameList(a[k] || [], b[k] || []));

// describeFilter says in words what is traced.
export function describeFilter(f) {
  const names = { arp: 'ARP', ip: 'IPv4', ip6: 'IPv6', tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', other: 'other' };
  const subject = f.protos.length ? `${list(f.protos.map((p) => names[p] || p))} traffic` : 'all traffic';
  const parts = [];
  if (f.ports.length) parts.push(`on ${f.ports.length > 1 ? 'ports' : 'port'} ${f.ports.join(', ')}`);
  if (f.ips.length) parts.push(`from or to ${f.ips.join(', ')}`);
  if (f.macs.length) parts.push(`of ${f.macs.join(', ')}`);
  // Several interfaces are alternatives: "arriving on eth0 or lo".
  const either = (items) => (items.length <= 2 ? items.join(' or ') : `${items.slice(0, -1).join(', ')}, or ${items[items.length - 1]}`);
  const dirs = [['in:', 'arriving on'], ['out:', 'leaving through'], ['', 'crossing']].map(([prefix, words]) => {
    const names = f.ifaces.filter((e) => (prefix ? e.startsWith(prefix) : !/^(in|out):/.test(e))).map((e) => e.slice(prefix.length));
    return names.length ? `${words} ${either(names)}` : '';
  }).filter(Boolean);
  if (dirs.length) parts.push(dirs.join(' or '));
  return `Tracing ${subject}${parts.length ? ` ${parts.join(', ')}` : ''}.`;
}
