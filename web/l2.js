// The bridge hooks (L2): what a Linux bridge does with a frame. It has two
// looks: the topology (the bridge, its ports, and what is behind them) and the
// hooks (the five netfilter hooks of the bridge family).

import { el, setWidth, store, listParam, clock, list, short, stackName, peerName, peerCard, drawCard, drawPill, drawHook, linePath, tracer, pickable, CARD_W, space } from './core.js';

let ctx = null;
let drawn = new Map(); // the drawn bridges: name -> { G, T }
let G = null;          // the geometry of the bridge that is being drawn or shown
let T = null;          // its tracer

// ?bridges= limits the bridges an embedded view draws.
const only = listParam('bridges');
const GAP_Y = 28;      // between two bridges

const bridgeByName = (name) => store.host.bridges.find((b) => b.name === name) || null;

// shownBridges are the bridges to draw, one under another: all of the
// namespace, without the ones that are switched off (Show, Devices).
const listed = (b) => !only || only.includes(b.name);
const shownBridges = () => store.host.bridges.filter((b) => listed(b) && ctx.blockOn('devices', b.name));
// shownPorts are the ports of a bridge that are not switched off (Show, Devices).
const shownPorts = (bridge) => bridge.ports.filter((p) => ctx.blockOn('devices', p.name));

// What a click traces: the port a card hangs on, or the machine behind it when
// its MAC address is known.
function behind(port) {
  const peer = port.peer;
  if (peer && peer.mac && !peer.bridge) return [{ macs: [peer.mac] }, `the frames from and to ${peer.mac} (${peerName(port)})`];
  return [{ ifaces: [port.name] }, `the frames that cross the port ${port.name}`];
}
const portOf = (bridge, name) => (bridge ? bridge.ports.find((p) => p.name === name) : null);
const failed = (leg) => leg.outcome === 'dropped' || leg.outcome === 'lost';
const legName = (leg) => (leg.host ? stackName() : leg.to);

// who names the owner of a MAC address in words, when the bridge knows it.
function who(mac, bridge) {
  if (mac === 'ff:ff:ff:ff:ff:ff') return 'everyone';
  if (parseInt(mac.slice(0, 2), 16) & 1) return 'a group';
  if (!bridge) return '';
  if (mac === bridge.mac) return `${bridge.name}, ${stackName()}`;
  for (const port of bridge.ports) {
    if (port.peer && port.peer.mac === mac) return peerName(port);
  }
  for (const port of bridge.ports) {
    if (port.macs.some((m) => m.mac === mac)) return peerName(port) || `behind ${port.name}`;
  }
  return '';
}

// ---- What happened to a frame, in words ------------------------------------

// outcome is the short text of the list: what the bridge did with the frame.
function outcome(f) {
  const bad = f.legs.filter(failed);
  const suffix = bad.length && bad.length < f.legs.length ? ` (${bad.length} dropped)` : '';
  if (f.ingress === 'dropped') return ['Dropped in PREROUTING', 'stopped'];
  if (f.decision === 'drop') return ['Dropped by the bridge', 'stopped'];
  if (bad.length === f.legs.length) return [`Dropped in ${bad[0].stoppedHook}`, 'stopped'];
  if (f.decision === 'flood') return [`Flooded to ${list(f.legs.map(legName))}${suffix}`, 'flood'];
  if (f.decision === 'forward') return [`${f.in ? 'Forwarded' : 'Sent'} to ${f.legs.find((l) => !l.host).to}${suffix}`, 'done'];
  return [`Delivered to ${stackName()}`, 'done'];
}

// verdict is the sentence under the diagram: why the bridge did it.
function verdict(f) {
  if (!f) return { text: store.host.bridges.length ? 'Waiting for a frame that matches the filter.' : '' };
  const bridge = bridgeByName(f.bridge);
  const up = stackName();
  const from = f.in ? `port ${f.in}` : `${up} (${f.bridge})`;
  const vlan = bridge && bridge.vlanFiltering && f.vlan ? f.vlan : 0;
  const bad = f.legs.filter(failed);
  const firewall = 'A firewall rule stopped it: nftables of the bridge family, ebtables, or iptables through br_netfilter.';
  let text;
  if (f.ingress === 'dropped') {
    text = `The frame arrived on ${from} and did not leave PREROUTING, so the bridge never looked at it. ${firewall}`;
  } else if (f.decision === 'drop') {
    text = `The frame arrived on ${from}, passed PREROUTING, and went nowhere. The bridge had no port to send it to: the destination may be behind the port the frame came from, the port may not be in the forwarding state, or VLAN filtering refused the frame.`;
  } else if (f.decision === 'flood') {
    const why = f.dstKind === 'broadcast'
      ? `The destination ${f.dst} is the broadcast address: the frame is for everyone`
      : f.dstKind === 'multicast'
        ? `The destination ${f.dst} is a multicast address: the frame is for a group of receivers`
        : `The bridge did not know which port ${f.dst} is behind`;
    text = `${why}, so the bridge made a copy for every ${vlan ? `port of VLAN ${vlan}` : 'port'} except the one the frame came from${f.in ? '' : ` (it came from ${up})`}.`;
    if (vlan) text += ` The frame came in untagged through a port of VLAN ${vlan}, and the ports of the other VLANs never see it.`;
  } else if (f.decision === 'forward') {
    const leg = f.legs.find((l) => !l.host);
    text = leg.known
      ? `The bridge's MAC table says that ${f.dst} is behind ${leg.to}, so only this port got the frame.`
      : `Only ${leg.to} got the frame: the bridge looked ${f.dst} up in its MAC table.`;
  } else {
    text = bridge && f.dst === bridge.mac
      ? `The destination ${f.dst} is the address of ${f.bridge} itself, so the frame went up to the network stack of ${up}. No other port saw it.`
      : `The frame went up to the network stack of ${up}. No other port saw it.`;
  }
  if (bad.length && f.decision !== 'drop' && f.ingress !== 'dropped') {
    const where = bad.map((l) => `the copy for ${legName(l)} ${l.outcome === 'lost' ? `got lost after ${l.stoppedHook}` : `was dropped in ${l.stoppedHook}`}`);
    text += ` But ${list(where)}. ${firewall}`;
  }
  if (f.learned) text += ` The bridge also learned from this frame that ${f.src} is behind ${f.in}.`;
  if (f.unreliable) text += ' Some probe events were lost around this frame, so a drop may be reported wrongly.';
  const [head, kind] = outcome(f);
  return { head: `${head}.`, text, kind: kind === 'stopped' ? 'stopped' : 'done' };
}

// ---- The topology look -----------------------------------------------------

const GAP = 22;
const Y = { cardTop: 6, cardBottom: 82, boxTop: 128, bus: 186, boxBottom: 244, hostTop: 290, height: 372 };

function stackCard(svg, x, top, bridge) {
  const s = space();
  const kind = { host: 'host', netns: 'network namespace', container: 'container', pod: 'pod', process: 'namespace of a process' }[s.kind] || 'network namespace';
  return drawCard(svg, x, top, kind, s.name, [bridge.addrs.join(', ') || 'no IP address', bridge.mac]);
}

function noBridge(svg) {
  svg.setAttribute('viewBox', '0 0 900 120');
  setWidth(svg, 900);
  const text = store.host.bridges.some(listed)
    ? 'All the bridges are switched off (Show, Devices).'
    : `No bridge in ${stackName()} yet. The page updates when one appears, and the Namespace list tells where the bridges are.`;
  svg.append(el('text', { x: 450, y: 64, 'text-anchor': 'middle', class: 'label' }, text));
}

function layers(svg) {
  const trails = el('g'), marks = el('g');
  return { trails, marks, start() { T = tracer(svg, trails, marks); } };
}

function buildTopology(svg, bridge) {
  const ports = shownPorts(bridge);
  const n = ports.length;
  const inner = Math.max(n * CARD_W + (n - 1) * GAP, 300);
  const W = Math.max(inner + 140, 620);
  const left = (W - (n * CARD_W + (n - 1) * GAP)) / 2;
  const cx = W / 2;
  G = { look: 'topology', bridge: bridge.name, W, height: Y.height, cx, ports: {}, cards: {}, portEls: {} };

  const boxL = (W - inner) / 2 - 24, boxR = (W + inner) / 2 + 24;
  svg.append(el('rect', { class: 'bridgebox', x: boxL, y: Y.boxTop, width: boxR - boxL, height: Y.boxBottom - Y.boxTop, rx: 12 }));
  svg.append(el('text', { class: 'bridgename', x: boxL + 14, y: Y.boxBottom - 14 }, bridge.name));
  svg.append(el('text', { class: 'label', x: boxR - 14, y: Y.boxBottom - 14, 'text-anchor': 'end' }, bridge.vlanFiltering ? 'Linux bridge with VLAN filtering' : 'Linux bridge'));

  const xs = ports.map((_, i) => left + i * (CARD_W + GAP) + CARD_W / 2);
  if (n > 0) svg.append(el('path', { class: 'track', d: `M${Math.min(xs[0], cx)} ${Y.bus} H${Math.max(xs[n - 1], cx)}` }));
  svg.append(el('path', { class: 'track', d: `M${cx} ${Y.bus} V${Y.hostTop}` }));
  xs.forEach((x) => svg.append(el('path', { class: 'track', d: `M${x} ${Y.cardBottom} V${Y.bus}` })));

  const L = layers(svg);
  svg.append(L.trails);
  G.junction = el('circle', { class: 'junction', r: 6, cx, cy: Y.bus });
  svg.append(G.junction);

  ports.forEach((port, i) => {
    const x = xs[i];
    G.ports[port.name] = x;
    G.cards[port.name] = peerCard(svg, x, Y.cardTop, port, port.macs);
    pickable(G.cards[port.name], ctx, ...behind(port));
    const vlanTag = bridge.vlanFiltering && port.pvid ? ` · vlan ${port.pvid}` : '';
    G.portEls[port.name] = drawPill(svg, x, Y.boxTop, port.name + vlanTag, port.up && port.state === 'forwarding' ? '' : 'down');
    pickable(G.portEls[port.name], ctx, { ifaces: [port.name] }, `the frames that cross the port ${port.name}`);
    if (port.state && port.state !== 'forwarding') {
      svg.append(el('text', { class: 'label', x: x + 8, y: Y.boxTop + 30 }, port.state));
    }
  });
  G.hostPort = drawPill(svg, cx, Y.boxBottom, bridge.name, bridge.up ? '' : 'down');
  pickable(G.hostPort, ctx, { ifaces: [bridge.name] }, `the frames that cross the bridge ${bridge.name}`);
  G.hostCard = stackCard(svg, cx, Y.hostTop, bridge);
  pickable(G.hostCard, ctx, { macs: [bridge.mac] }, `the frames from and to ${bridge.mac} (${bridge.name}, ${stackName()})`);
  svg.append(L.marks);
  L.start();
}

function showTopology(f) {
  const fromHost = !f.in;
  const sx = fromHost ? G.cx : G.ports[f.in];
  if (sx === undefined) return 0;

  // The way in: from the sender down to the bus of the bridge.
  T.light(fromHost ? G.hostCard : G.cards[f.in], 0);
  T.light(fromHost ? G.hostPort : G.portEls[f.in], 0);
  const start = fromHost ? [G.cx, Y.hostTop] : [sx, Y.cardBottom];
  const junction = [sx, Y.bus];
  if (f.ingress === 'dropped') {
    const t = T.trail([start, [sx, Y.boxTop + 28]], '', 0);
    T.stop(t.end, t.done);
    return t.done;
  }
  const t = T.trail([start, junction], '', 0);
  let total = t.done;
  if (f.legs.length === 0) T.stop(junction, t.done);
  G.junction.setAttribute('cx', sx);
  T.light(G.junction, t.done);
  const cls = f.decision === 'flood' ? 'flood' : '';
  for (const leg of f.legs) {
    const bad = failed(leg);
    const tx = leg.host ? G.cx : G.ports[leg.to];
    if (tx === undefined) continue;
    let end;
    if (leg.host) end = bad ? [tx, Y.bus + 30] : [tx, Y.hostTop];
    else if (!bad) end = [tx, Y.cardBottom];
    else end = leg.stoppedHook === 'POSTROUTING' ? [tx, Y.boxTop + 24] : [tx, Y.bus - 24];
    // A copy that the OUTPUT hook dropped never reached the bus.
    const points = bad && leg.stoppedHook === 'OUTPUT' ? [junction, [sx, Y.bus]] : [junction, [tx, Y.bus], end];
    const out = T.trail(points, cls, t.done);
    if (bad) {
      T.stop(leg.stoppedHook === 'OUTPUT' ? [sx, Y.bus + 30] : out.end, out.done);
    } else {
      T.light(leg.host ? G.hostPort : G.portEls[leg.to], out.done - 60);
      T.light(leg.host ? G.hostCard : G.cards[leg.to], out.done);
    }
    total = Math.max(total, out.done);
  }
  return total;
}

// ---- The hooks look --------------------------------------------------------

// The frame goes from left to right, like a packet in the IP view: the ports it
// may arrive on, PREROUTING, the bridge's decision, FORWARD, POSTROUTING, and
// the ports it may leave through. INPUT leads up to the network stack, and
// OUTPUT comes from it.
const H = {
  W: 1264, lineY: 76, hookY: 76, sideY: 172, stackY: 250, stackH: 26,
  // A card, the bus that collects the wires of the cards, and the node where
  // the bus meets the line of the hooks.
  cardX: [86, 1178], busX: [196, 1068], inX: 232, preX: 360, decideX: 494, fwdX: 642, mergeX: 784, postX: 904, outX: 1032,
  nic: { w: 148, h: 34, step: 42, max: 7 },
};

function buildHooks(svg, bridge) {
  const all = shownPorts(bridge);
  const ports = all.slice(0, H.nic.max);
  const rows = Math.max(ports.length, 1);
  const height = Math.max(H.stackY + H.stackH + 4, H.lineY + (rows - 1) * H.nic.step + (all.length > ports.length ? 52 : 30));
  G = { look: 'hooks', bridge: bridge.name, W: H.W, height, nics: { in: {}, out: {} }, hooks: {} };

  const y = H.lineY;
  svg.append(
    el('path', { class: 'track', d: linePath([[H.inX, y], [H.outX, y]]) }),
    el('path', { class: 'track', d: linePath([[H.decideX, y], [H.decideX, H.stackY]]) }),
    el('path', { class: 'track', d: linePath([[H.mergeX, H.stackY], [H.mergeX, y]]) }),
  );
  for (const [x, ay, rot] of [[(H.inX + H.preX - 75) / 2, y, 0], [(H.decideX + H.fwdX - 75) / 2 + 4, y, 0], [(H.postX + 75 + H.outX) / 2, y, 0], [H.decideX, 122, 90], [H.decideX, 222, 90], [H.mergeX, 124, -90], [H.mergeX, 224, -90]]) {
    svg.append(el('path', { class: 'arrow', d: 'M-6 -5 L5 0 L-6 5 Z', transform: `translate(${x} ${ay}) rotate(${rot})` }));
  }

  const L = layers(svg);
  svg.append(L.trails);

  // The ports: the same cards on both ends.
  const side = (name, x, bus, node, heading) => {
    svg.append(el('text', { class: 'label', x, y: y - 34, 'text-anchor': 'middle' }, heading));
    ports.forEach((port, i) => {
      const cy = y + i * H.nic.step;
      const edge = name === 'in' ? x + H.nic.w / 2 : x - H.nic.w / 2;
      const wire = [[edge, cy], [bus, cy], [bus, y]];
      svg.append(el('path', { class: 'track', d: linePath([...wire, [node, y]]) }));
      const g = el('g', { class: `nic ${port.up && port.state === 'forwarding' ? '' : 'down'}` });
      const vlan = bridge.vlanFiltering && port.pvid ? ` · vlan ${port.pvid}` : '';
      g.append(
        el('title', {}, `${port.name}${vlan}: ${peerName(port) || 'nothing known about the other end'}`),
        el('rect', { x: x - H.nic.w / 2, y: cy - H.nic.h / 2, width: H.nic.w, height: H.nic.h, rx: 6 }),
        el('text', { class: 'nic-name', x: x - H.nic.w / 2 + 10, y: cy - 2 }, short(port.name + vlan, 19)),
        el('text', { class: 'nic-addr', x: x - H.nic.w / 2 + 10, y: cy + 11 }, short(peerName(port) || (port.macs[0] ? port.macs[0].mac : 'no frame seen yet'), 21)),
      );
      pickable(g, ctx, { ifaces: [`${name}:${port.name}`] }, name === 'in' ? `the frames that arrive on ${port.name}` : `the frames that leave through ${port.name}`);
      svg.append(g);
      G.nics[name][port.name] = { el: g, wire };
    });
    if (all.length > ports.length) {
      svg.append(el('text', { class: 'label', x, y: y + ports.length * H.nic.step - 4, 'text-anchor': 'middle' }, `and ${all.length - ports.length} more`));
    }
  };
  side('in', H.cardX[0], H.busX[0], H.inX, 'Frames arrive on');
  side('out', H.cardX[1], H.busX[1], H.outX, 'Frames leave through');

  // The network stack above the bridge: the bridge device is its interface.
  const stack = el('rect', { class: 'proc', x: 290, y: H.stackY, width: H.W - 580, height: H.stackH, rx: 6 });
  const stackBox = el('g', { class: 'stackbox' });
  stackBox.append(stack, el('text', { class: 'proc-label', x: H.W / 2, y: H.stackY + 17, 'text-anchor': 'middle' },
    short(`Network stack of ${stackName()} · ${bridge.name} ${bridge.addrs.join(', ')}`, 78)));
  pickable(stackBox, ctx, { ifaces: [bridge.name] }, `the frames that cross the bridge ${bridge.name}`);
  svg.append(stackBox);
  G.stack = stack;

  // The second line is the nftables family: the same hooks exist for IP.
  const hook = (name, x, hy) => { G.hooks[name] = { el: drawHook(svg, x, hy, name, 'bridge'), pos: [x, hy] }; };
  hook('PREROUTING', H.preX, y);
  hook('FORWARD', H.fwdX, y);
  hook('POSTROUTING', H.postX, y);
  hook('INPUT', H.decideX, H.sideY);
  hook('OUTPUT', H.mergeX, H.sideY);

  G.nodes = {};
  for (const [name, x] of [['in', H.inX], ['out', H.outX]]) {
    G.nodes[name] = el('circle', { class: 'node', cx: x, cy: y, r: 8 });
    svg.append(G.nodes[name]);
  }
  G.nodes.decide = el('path', { class: 'diamond', d: `M${H.decideX} ${y - 11} L${H.decideX + 11} ${y} L${H.decideX} ${y + 11} L${H.decideX - 11} ${y} Z` });
  G.nodes.merge = el('circle', { class: 'diamond', cx: H.mergeX, cy: y, r: 5 });
  svg.append(G.nodes.decide, G.nodes.merge, el('text', { class: 'label', x: H.decideX, y: y - 20, 'text-anchor': 'middle' }, 'MAC table lookup'));
  svg.append(L.marks);
  L.start();
}

// along walks a trail through the hooks of one copy. Every stop is a point, and
// may name the hook whose box lights up there.
function along(stops, cls, delay, stoppedHook) {
  const points = [];
  const reach = [];
  let dist = 0;
  let ended = null;
  for (const s of stops) {
    if (points.length) dist += Math.hypot(s.at[0] - points[points.length - 1][0], s.at[1] - points[points.length - 1][1]);
    points.push(s.at);
    reach.push({ ...s, dist });
    if (s.hook && s.hook === stoppedHook) { ended = s; break; }
  }
  const t = T.trail(points, cls, delay);
  for (const r of reach) {
    const at = T.timeAt(delay, r.dist);
    if (r.hook && G.hooks[r.hook]) T.light(G.hooks[r.hook].el, at, ended === r || (ended && r.hook === stoppedHook) ? 'lit stopped' : 'lit');
    if (r.node) T.light(r.node, at);
  }
  if (ended) T.stop([ended.at[0] + 72, ended.at[1] - 19], t.done);
  return t.done;
}

function showHooks(f) {
  const y = H.lineY;
  const at = (hook) => G.hooks[hook].pos;
  let start = 0;
  let origin;
  if (f.in) {
    const nic = G.nics.in[f.in];
    const stops = [];
    if (nic) {
      T.light(nic.el, 0);
      nic.wire.forEach((p) => stops.push({ at: p }));
    }
    stops.push({ at: [H.inX, y], node: G.nodes.in }, { at: at('PREROUTING'), hook: 'PREROUTING' }, { at: [H.decideX, y], node: G.nodes.decide });
    start = along(stops, '', 0, f.ingress === 'dropped' ? 'PREROUTING' : '');
    if (f.ingress === 'dropped') return start;
    origin = [H.decideX, y];
    if (f.legs.length === 0) { T.stop([H.decideX + 18, y - 18], start); T.light(G.nodes.decide, start, 'stopped'); }
  } else {
    T.light(G.stack, 0);
    origin = [H.mergeX, H.stackY];
  }
  let total = start;
  const cls = f.decision === 'flood' ? 'flood' : '';
  for (const leg of f.legs) {
    const stopped = failed(leg) && leg.outcome === 'dropped' ? leg.stoppedHook : '';
    let stops;
    if (leg.host) {
      stops = [{ at: origin }, { at: at('INPUT'), hook: 'INPUT' }, { at: [H.decideX, H.stackY], node: G.stack }];
    } else {
      const nic = G.nics.out[leg.to];
      stops = f.in
        ? [{ at: origin }, { at: at('FORWARD'), hook: 'FORWARD' }, { at: [H.mergeX, y], node: G.nodes.merge }]
        : [{ at: origin }, { at: at('OUTPUT'), hook: 'OUTPUT' }, { at: [H.mergeX, y], node: G.nodes.merge }];
      stops.push({ at: at('POSTROUTING'), hook: 'POSTROUTING' }, { at: [H.outX, y], node: G.nodes.out });
      if (nic) [...nic.wire].reverse().forEach((p, i, all) => stops.push({ at: p, node: i === all.length - 1 ? nic.el : null }));
    }
    // A lost copy left its last hook and was not seen again: the trail ends there.
    if (leg.outcome === 'lost') {
      const cut = stops.findIndex((s) => s.hook === leg.stoppedHook);
      stops = stops.slice(0, cut + 2);
    }
    const done = along(stops, cls, start, stopped);
    if (leg.outcome === 'lost') T.stop(stops[stops.length - 1].at, done);
    total = Math.max(total, done);
  }
  return total;
}

// ---- The view --------------------------------------------------------------

// build draws every shown bridge in a group of its own, one under another.
// Each has its own tracer, so a frame lights up only its bridge.
function build() {
  const svg = ctx.svg;
  drawn = new Map();
  G = null;
  T = null;
  const bridges = shownBridges();
  if (!bridges.length) { noBridge(svg); return; }
  const groups = bridges.map((bridge) => {
    const g = el('g');
    if (ctx.sub() === 'hooks') buildHooks(g, bridge);
    else buildTopology(g, bridge);
    drawn.set(bridge.name, { G, T });
    return [g, G];
  });
  const W = Math.max(...groups.map(([, geo]) => geo.W));
  let y = 0;
  for (const [g, geo] of groups) {
    g.setAttribute('transform', `translate(${(W - geo.W) / 2} ${y})`);
    svg.append(g);
    y += geo.height + GAP_Y;
  }
  svg.setAttribute('viewBox', `0 0 ${W} ${y - GAP_Y}`);
  setWidth(svg, W);
  // Several bridges are taller than the page gives a diagram: the page scrolls then.
  svg.classList.toggle('tall', groups.length > 1);
}

function show(f, animate) {
  for (const d of drawn.values()) d.T.reset(animate);
  const d = f ? drawn.get(f.bridge) : null;
  if (!d) return 0;
  ({ G, T } = d);
  return G.look === 'hooks' ? showHooks(f) : showTopology(f);
}

function macCell(mac, bridge) {
  return [mac, 'mono', who(mac, bridge)];
}

function cells(f) {
  const bridge = bridgeByName(f.bridge);
  const [text, kind] = outcome(f);
  const details = f.type === 'ARP' ? f.info : [f.info, f.srcIp && `${f.srcIp} → ${f.dstIp}`].filter(Boolean).join(', ');
  const from = f.in ? [f.in, 'mono', store.host.bridges.length > 1 ? f.bridge : ''] : [f.bridge, 'mono', stackName().replace(/^the /, '')];
  return [
    [clock(f.time), 'mono'], from, macCell(f.src, bridge), macCell(f.dst, bridge),
    [f.type + (f.vlan ? ` · vlan ${f.vlan}` : '')], [details, 'details'], [text + (f.unreliable ? ' ?' : ''), `outcome-${kind}`],
  ];
}

// detail lists the copies of the frame: where each went and through which hooks.
function detail(f) {
  const d = { title: 'Copies of the selected frame', columns: ['To', 'Hooks', 'Outcome'], empty: 'Select a frame to see where its copies went.', summary: '', rows: [] };
  if (!f) return d;
  const bridge = bridgeByName(f.bridge);
  d.summary = [f.type, f.info].filter(Boolean).join(', ');
  if (f.in) {
    d.rows.push({ cells: [[`In through ${f.in}`, '', peerName(portOf(bridge, f.in))], [f.ingress ? 'PREROUTING' : '', 'mono'], [f.ingress === 'dropped' ? 'Dropped in PREROUTING' : 'Passed']], cls: f.ingress === 'dropped' ? 'stopped' : '' });
  } else {
    d.rows.push({ cells: [[`Sent by ${stackName()} through ${f.bridge}`], [''], ['']], cls: '' });
  }
  for (const leg of f.legs) {
    const text = leg.outcome === 'sent' ? 'Sent' : leg.outcome === 'delivered' ? 'Delivered'
      : leg.outcome === 'lost' ? `Lost after ${leg.stoppedHook}` : `Dropped in ${leg.stoppedHook}`;
    const to = leg.host ? [`Up to ${stackName()}`] : [`Out to ${leg.to}`, '', peerName(portOf(bridge, leg.to))];
    d.rows.push({ cells: [to, [leg.hooks.join(' → '), 'mono'], [text]], cls: failed(leg) ? 'stopped' : '' });
  }
  if (f.in && f.ingress !== 'dropped' && f.legs.length === 0) {
    d.rows.push({ cells: [['No copy left the bridge'], [''], ['Dropped by the bridge']], cls: 'stopped' });
  }
  return d;
}

// extra is the MAC table of the bridge of the selected frame (of the first
// drawn bridge without one), with the addresses of the frame marked.
function extra(f) {
  const bridge = (f && bridgeByName(f.bridge)) || shownBridges()[0] || null;
  const x = { title: 'MAC table', summary: bridge ? bridge.name : '', columns: ['MAC address', 'Port', 'IP', ''], empty: 'The bridge has not learned any address yet.', rows: [] };
  if (!bridge) return x;
  const sel = f && f.bridge === bridge.name ? f : null;
  const role = (mac) => {
    if (!sel) return ['', ''];
    if (mac === sel.src) return ['src', sel.learned ? 'source, just learned' : 'source'];
    if (mac === sel.dst) return ['dst', 'destination'];
    return ['', ''];
  };
  for (const port of bridge.ports) {
    for (const m of port.macs) {
      const [cls, text] = role(m.mac);
      x.rows.push({ cells: [[m.mac, 'mono'], [port.name, 'mono', peerName(port)], [m.ip || '', 'mono'], [text, 'role']], cls });
    }
  }
  const [cls, text] = role(bridge.mac);
  x.rows.push({ cells: [[bridge.mac, 'mono'], [bridge.name, 'mono', stackName()], [bridge.addrs.join(', '), 'mono'], [text || 'own address', 'role']], cls });
  return x;
}

// items turns a journey into what this view lists: one entry per bridge the
// frame crossed.
function items(j) {
  return (j.l2 || []).map((s, k) => ({
    id: `${j.id}.${k}`, j, time: j.time, unreliable: j.unreliable, ...s,
    type: j.frame ? j.frame.type : '', info: j.frame ? j.frame.info : '', srcIp: j.frame && j.frame.srcIp, dstIp: j.frame && j.frame.dstIp,
  }));
}

// blocks are the bridges and their ports: each can be taken out of the diagram.
function blocks() {
  const bridges = store.host.bridges.filter(listed);
  return [{
    id: 'devices', label: 'Devices',
    items: [
      ...bridges.map((b) => ({ key: b.name, label: b.name, note: `bridge, ${b.ports.length} ${b.ports.length === 1 ? 'port' : 'ports'}` })),
      ...bridges.flatMap((b) => b.ports.map((p) => ({ key: p.name, label: p.name, note: `port of ${b.name}${peerName(p) ? `, ${peerName(p)}` : ''}` }))),
    ],
  }];
}

export default {
  id: 'l2',
  label: 'Bridge · L2',
  title: 'Frames',
  noun: 'frame',
  layer: 'l2',
  about: 'A Linux bridge: its ports, its MAC table, and the netfilter hooks of the bridge family.',
  subs: [{ id: 'topology', label: 'Topology' }, { id: 'hooks', label: 'Hooks' }],
  panels: [{ id: 'packets', label: 'Frames' }, { id: 'details', label: 'Copies' }, { id: 'extra', label: 'MAC table' }],
  aria: 'The bridges, their ports, and the way of the selected frame',
  init(context) { ctx = context; },
  items,
  columns: ['Time', 'In port', 'Source', 'Destination', 'Type', 'Details', 'Outcome'],
  cells,
  resize: () => false,
  build,
  show,
  verdict,
  detail,
  extra,
  blocks,
  packetHops: (f) => f.j.hops.map((h, i) => (h.layer === 'l2' && h.bridge === f.bridge ? i : -1)).filter((i) => i >= 0),
};
