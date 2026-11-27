// The combined view: one packet across all the layers that saw it, on a
// diagram that stays the same from packet to packet.
//
// The diagram has two lanes with the same hooks, one above the other. The upper
// one is the IP layer, between the devices it receives on and sends through.
// The lower one is the bridge, between its ports. Every lane starts with the
// ingress hook of its device and ends with the egress hook of it. Two things
// join the lanes:
//   - the bridge device (br0): a frame that the bridge passes up (INPUT) goes
//     around the left side and enters the IP lane like a packet from any other
//     device, and what the IP layer sends to the bridge device goes around the
//     right side to the bridge's OUTPUT;
//   - br_netfilter: a bridge hook calls the IP hook of the same name while the
//     frame is in it. The dashed links between the lanes are these calls.
// The way of a packet is found on this diagram as on a map: from every hook
// that saw it to the next one, along the lines.

import { el, setWidth, store, clock, micros, short, stackName, peerName, ifaceByName, procKey, linePath, drawHook, tracer, pickable } from './core.js';

let ctx = null;
let T = null;
let S = null;      // the drawn diagram: its lanes, cards, and the map of its lines
let shown = null;  // the journey on view
let leaf = 0;      // the copy of it that the diagram follows

const LANES = [
  { layer: 'l3', label: 'IP hooks', short: 'L3' },
  { layer: 'l2', label: 'Bridge hooks', short: 'L2' },
  { layer: 'l1', label: 'Device hooks', short: 'L1' },
];

// leaves are the copies that no bridge copied further: the ends of the paths.
function leaves(j) {
  const copies = j.copies || [];
  const parents = new Set(copies.map((c) => c.parent || 0));
  return copies.filter((c) => !parents.has(c.id));
}

// defaultLeaf follows the copy that went up to the network stack, else the first one.
function defaultLeaf(j) {
  const all = leaves(j);
  if (!all.length) return 0;
  return (all.find((c) => c.host) || all[0]).id;
}

// lineage is a copy with all the copies it descends from, and the original.
function lineage(j, id) {
  const line = new Set([0]);
  while (id && !line.has(id)) {
    line.add(id);
    id = j.copies[id - 1].parent || 0;
  }
  return line;
}

const copyName = (c) => (c.host ? `up to the stack (${c.bridge})` : `to ${c.to}`);

// plan turns the hops of one path into boxes. A box is one pass through a hook.
// It spans several columns when hooks of another layer ran in between.
function plan(j, leafId, on) {
  const line = lineage(j, leafId);
  const boxes = [];
  const open = new Map();
  const seq = []; // the path: a box and the column where the path touches it
  let col = -1;
  j.hops.forEach((h, index) => {
    if (!line.has(h.copy || 0) || !on.has(h.layer)) return;
    const key = h.layer === 'l3' ? `l3|${h.hook}|${h.pin || ''}|${h.pout || ''}`
      : h.layer === 'l2' ? `l2|${h.hook}|${h.bridge}|${h.hook === 'PREROUTING' || h.hook === 'INPUT' ? '' : h.out || ''}`
        : `l1|${h.hook}|${h.in || h.out}`;
    let box = open.get(key);
    const last = seq.length ? seq[seq.length - 1].box : null;
    if (!box) {
      col++;
      box = { layer: h.layer, hook: h.hook, c0: col, c1: col, hops: [], exited: false, first: h };
      open.set(key, box);
      boxes.push(box);
      seq.push({ box, col });
    } else if (box !== last) {
      col++;
      box.c1 = col;
      seq.push({ box, col });
    }
    box.hops.push({ h, index });
    if (h.exit) box.exited = true;
  });
  return { boxes, seq, cols: col + 1 };
}

// ending tells how the path ended.
function ending(j, p) {
  if (!p.seq.length) return { kind: 'done', head: 'Nothing to show', text: 'None of the layers that are on saw this packet.' };
  const box = p.seq[p.seq.length - 1].box;
  const h = box.hops[box.hops.length - 1].h;
  const name = box.layer === 'l1' ? `the ${box.hook.toLowerCase()} hook of ${h.in || h.out}` : box.layer === 'l2' ? `${box.hook} of the bridge ${h.bridge}` : box.hook;
  if (!box.exited) {
    return { kind: 'stopped', head: `Dropped in ${name}`, text: `The packet entered ${name} and did not leave it: a rule there dropped, rejected, or queued it.`, box };
  }
  const l3 = j.l3;
  switch (`${box.layer}/${box.hook}`) {
    case 'l3/INPUT':
      return l3 && l3.to
        ? { kind: 'done', head: `Delivered to ${l3.to.name}`, text: `The packet passed INPUT and reached the ${l3.to.proto.toUpperCase()} socket on port ${l3.to.port} of ${l3.to.name} (pid ${l3.to.pid}).`, end: l3.to.name }
        : { kind: 'done', head: 'Delivered locally', text: `The packet passed INPUT and went up to the transport layer of ${stackName()}.`, end: 'local socket' };
    case 'l3/POSTROUTING': {
      const dev = h.pout || h.out;
      return { kind: 'done', head: `Sent via ${dev}`, text: `The packet passed POSTROUTING and was handed to ${dev}.${store.egress ? '' : ' This kernel has no egress hook for devices, so the path ends here.'}`, end: dev };
    }
    case 'l1/EGRESS':
      return { kind: 'done', head: `Sent through ${h.out}`, text: `The frame passed the egress hook of ${h.out} and was handed to the device.`, end: peerName(ifaceByName(h.out)) || 'the network' };
    case 'l2/POSTROUTING':
      return { kind: 'done', head: `Sent to port ${h.out}`, text: `The frame passed POSTROUTING of the bridge ${h.bridge} and was handed to its port ${h.out}.`, end: peerName(ifaceByName(h.out)) || h.out };
    case 'l2/INPUT':
      return { kind: 'done', head: `Delivered to ${stackName()}`, text: `The bridge ${h.bridge} passed the frame up to the network stack, and no hook above saw it. That is normal for a frame that is not an IP packet, like an ARP message.`, end: 'network stack' };
    case 'l1/INGRESS': {
      const dev = ifaceByName(h.in);
      return { kind: 'done', head: `Received on ${h.in}`, text: `The frame passed the ingress hook of ${h.in}, and no hook above saw it.${dev && dev.master ? ` ${h.in} is a port of ${dev.master}: the bridge may have dropped the frame before its own hooks.` : ' That is normal for a frame that is not an IP packet, like an ARP message.'}`, end: dev && dev.master ? dev.master : 'network stack' };
    }
    case 'l2/PREROUTING':
      return { kind: 'stopped', head: 'Dropped by the bridge', text: `The frame passed PREROUTING of ${h.bridge} and went nowhere: the bridge had no port to send it to.`, lost: true };
    default:
      return { kind: 'stopped', head: `Lost after ${name}`, text: `The packet left ${name} and was not seen again.${box.layer === 'l3' && box.hook === 'PREROUTING' ? ' The routing decision discarded it: no route, forwarding disabled, or a reverse path check.' : ''}`, lost: true };
  }
}

// ---- Diagram ---------------------------------------------------------------

function onLayers() {
  const on = ctx.layers();
  return new Set(LANES.map((l) => l.layer).filter((l) => on.includes(l)));
}

// The columns of the diagram. Both lanes use them, so that a hook of the
// bridge sits right under the IP hook of the same name.
const X = {
  loopL: 20, cardL: 124, busL: 230, in: 262, ING: 350, PRE: 520, DEC: 646, FWD: 776, MRG: 906, POST: 1026,
  EGR: 1186, out: 1278, busR: 1310, cardR: 1416, loopR: 1520, W: 1540,
};
const NIC = { w: 148, h: 34, step: 42, max: 8 };
const PROC = { w: 180, h: 40, gap: 12, max: 5 };
const BOX = { w: 150, h: 44, small: 110 };
const LANE_GAP = 156, SOCK_H = 22, BAR_H = 26;
// Every lane is on a band with its name in the top left corner. TOP is the
// room for the name above what the band holds, and BAND_X is where a band
// starts: between the line that goes around the side and the cards.
const TOP = 34, BAND_X = 36;
// The chips of the stages inside an IP hook, in the look "Stages".
const CHIP = { w: 52, h: 24, dx: 58, dy: 38 };
const withStages = () => ctx.sub() === 'stages';
const stagesOf = (name) => ((store.hooks.find((h) => h.name === name) || {}).stages || []).map((x) => x.name);
const HOOK_KEY = { INGRESS: 'ING', EGRESS: 'EGR', PREROUTING: 'PRE', FORWARD: 'FWD', POSTROUTING: 'POST', INPUT: 'INPUT', OUTPUT: 'OUTPUT' };

const isPort = (dev) => !!dev.master;
const shownDevices = () => store.host.ifaces.filter((d) => ctx.blockOn('devices', d.name));
const shownProcs = () => store.host.procs.filter((p) => ctx.blockOn('procs', procKey(p)));

function socketsFilter(sockets) {
  return {
    protos: [...new Set(sockets.map((s) => s.proto))].sort(),
    ports: [...new Set(sockets.map((s) => s.port))].sort((a, b) => a - b),
  };
}

function note(svg, text) {
  svg.setAttribute('viewBox', '0 0 900 120');
  setWidth(svg, 900);
  svg.append(el('text', { x: 450, y: 64, 'text-anchor': 'middle', class: 'label' }, text));
}

// build draws the diagram for the layers that are on and the devices of the
// namespace. It does not depend on the packet.
function build() {
  const svg = ctx.svg;
  S = null;
  T = null;
  const on = onLayers();
  const devices = shownDevices();
  const ports = devices.filter(isPort), others = devices.filter((d) => !isPort(d));
  // The IP lane also carries the device hooks of the devices that are no ports.
  const has3 = on.has('l3') || on.has('l1');
  // The bridge lane is drawn while a bridge or a port of one is on view.
  const has2 = (on.has('l2') || on.has('l1')) && devices.some((d) => isPort(d) || d.kind === 'bridge');
  if (!has3 && !has2) {
    note(svg, `No bridge in ${stackName()}, so there are no bridge hooks to show. Switch another layer on.`);
    return;
  }
  const cards3 = has3 ? others.slice(0, NIC.max) : [], cards2 = has2 ? ports.slice(0, NIC.max) : [];
  const more3 = has3 ? others.length - cards3.length : 0, more2 = has2 ? ports.length - cards2.length : 0;
  const procs = on.has('l3') ? shownProcs().slice(0, PROC.max) : [];
  const moreProcs = on.has('l3') ? shownProcs().length - procs.length : 0;

  // The rows, from the top: the processes, the sockets, the IP lane (its cards
  // stack upwards), the bridge lane (its cards stack downwards), and the bar
  // of the bridge device.
  const sockY = TOP + PROC.h + 18;
  const cardsUp = (Math.max(cards3.length, 1) - 1) * NIC.step + NIC.h / 2 + 26 + (more3 ? 18 : 0);
  let y3 = 0, y2 = 0, barY = 0, height = 0;
  if (has3) {
    // With the stages, INPUT and OUTPUT are columns of chips and need more height.
    y3 = Math.max(on.has('l3') ? sockY + SOCK_H + (withStages() ? 246 : 150) : 44, cardsUp + TOP);
    // Room for the name of the lane under its line.
    height = y3 + 54;
  }
  if (has2) {
    y2 = has3 ? y3 + LANE_GAP : 84;
    const cardsDown = (Math.max(cards2.length, 1) - 1) * NIC.step + NIC.h / 2 + (more2 ? 20 : 0);
    barY = y2 + Math.max(150, cardsDown + 26);
    height = barY + BAR_H + 26;
  }
  svg.setAttribute('viewBox', `0 0 ${X.W} ${height}`);
  setWidth(svg, X.W, 1240);
  // The diagram keeps its size, and the page scrolls when it is taller than the window.
  svg.classList.add('tall');

  S = { on, y3, y2, barY, sockY, nodes: new Map(), edges: new Map(), cards: { 2: { in: {}, out: {} }, 3: { in: {}, out: {} } }, procs: {}, subs: [], has2, has3 };
  const tracks = el('g'), trails = el('g'), parts = el('g'), marks = el('g');
  // The bands of the lanes: what belongs to the IP layer and what to the bridge.
  const band = (top, bottom, name) => svg.append(
    el('rect', { class: 'lane', x: BAND_X, y: top, width: X.W - 2 * BAND_X, height: bottom - top, rx: 10 }),
    el('text', { class: 'lane-name', x: BAND_X + 12, y: top + 17 }, name),
  );
  if (has3) band(2, y3 + 50, on.has('l3') ? 'IP · L3' : 'Devices');
  if (has2) band(y2 - 78, barY + BAR_H + 22, 'Bridge · L2');
  svg.append(tracks, trails, parts, marks);
  const track = (pts, cls = '') => tracks.append(el('path', { class: `track ${cls}`, d: linePath(pts) }));
  const arrow = (x, y, rot) => tracks.append(el('path', { class: 'arrow', d: 'M-6 -5 L5 0 L-6 5 Z', transform: `translate(${x} ${y}) rotate(${rot})` }));
  const label = (x, y, text, anchor = 'middle') => parts.append(el('text', { class: 'label', x, y, 'text-anchor': anchor }, text));

  // The map: the named points of the diagram and the lines between them. A
  // point is a box of a hook, a node on a line, or a place on a bar.
  const point = (key, x, y, node, box) => { S.nodes.set(key, { at: [x, y], el: node || null, box: !!box }); S.edges.set(key, []); };
  const line = (a, b, cls) => {
    S.edges.get(a).push(b);
    track([S.nodes.get(a).at, S.nodes.get(b).at], cls);
  };
  // stageHook draws an IP hook as a box with a chip per stage. The chips are
  // on the line of the hook, in the order a packet passes them: along the x
  // axis (dx) or the y axis (dy, negative for a packet that travels upwards).
  const stageHook = (key, x, y, name, dx, dy) => {
    const names = stagesOf(name);
    const n = names.length;
    const at = (i) => [x + dx * (i - (n - 1) / 2), y + dy * (i - (n - 1) / 2)];
    const halfW = Math.abs(dx) * (n - 1) / 2 + CHIP.w / 2 + 10, halfH = Math.abs(dy) * (n - 1) / 2 + CHIP.h / 2 + 12;
    parts.append(el('rect', { class: 'hookbox', x: x - halfW, y: y - halfH, width: 2 * halfW, height: 2 * halfH, rx: 10 }));
    // The name of the hook with its nftables family under it, as in the other
    // boxes: above a row of chips, and next to a column of them.
    const [tx, ty, anchor] = dx ? [x, y - halfH - 23, 'middle'] : name === 'INPUT' ? [x - halfW - 10, y - 3, 'end'] : [x + halfW + 10, y - 3, 'start'];
    const title = el('text', { class: 'hookname', x: tx, y: ty, 'text-anchor': anchor }, name);
    parts.append(title);
    // The family is centered under the name, wherever the name is anchored,
    // as far below it as the second line of a hook box (see drawHook).
    const half = title.getComputedTextLength() / 2;
    const mid = anchor === 'end' ? tx - half : anchor === 'start' ? tx + half : tx;
    parts.append(el('text', { class: 'family', x: mid, y: ty + 15, 'text-anchor': 'middle' }, 'inet'));
    const chips = {};
    names.forEach((stage, i) => {
      const [cx, cy] = at(i);
      const g = el('g', { class: 'chip' });
      g.append(el('rect', { x: cx - CHIP.w / 2, y: cy - CHIP.h / 2, width: CHIP.w, height: CHIP.h, rx: CHIP.h / 2 }), el('text', { x: cx, y: cy + 4, 'text-anchor': 'middle' }, stage));
      parts.append(g);
      chips[stage] = { el: g, at: [cx, cy] };
    });
    point(key, x, y, null, true);
    Object.assign(S.nodes.get(key), { chips, across: !!dx });
    return halfH;
  };
  const hook = (key, x, y, name, layer, small) => {
    if (layer === 'l3' && on.has('l3') && withStages()) { stageHook(key, x, y, name, CHIP.dx, 0); return; }
    if (!on.has(layer)) { point(key, x, y); return; }
    // The second line of a box is the nftables family of its hook. Under a
    // device hook is the name of the device of the packet on view.
    const g = drawHook(parts, x, y, name, small ? 'netdev' : layer === 'l2' ? 'bridge' : 'inet', small ? BOX.small : BOX.w, BOX.h);
    if (small) {
      const dev = el('text', { class: 'devname', x, y: y + BOX.h / 2 + 19, 'text-anchor': 'middle' });
      parts.append(dev);
      S.subs.push(dev);
      g.dev = dev;
    }
    point(key, x, y, g, true);
  };
  const circle = (x, y) => { const c = el('circle', { class: 'node', cx: x, cy: y, r: 8 }); parts.append(c); return c; };
  const diamond = (x, y) => { const d = el('path', { class: 'diamond', d: `M${x} ${y - 11} L${x + 11} ${y} L${x} ${y + 11} L${x - 11} ${y} Z` }); parts.append(d); return d; };
  const dot = (x, y) => { const c = el('circle', { class: 'diamond', cx: x, cy: y, r: 5 }); parts.append(c); return c; };

  // lane draws the line of one lane: the hooks of its layer between the device
  // hooks of its ends.
  const lane = (k, y, layer) => {
    const keys = ['in', 'ING', 'PRE', 'DEC', 'FWD', 'MRG', 'POST', 'EGR', 'out'].map((n) => n + k);
    point(keys[0], X.in, y, circle(X.in, y));
    hook(keys[1], X.ING, y, 'ingress', 'l1', true);
    hook(keys[2], X.PRE, y, 'PREROUTING', layer);
    point(keys[3], X.DEC, y, on.has(layer) ? diamond(X.DEC, y) : null);
    hook(keys[4], X.FWD, y, 'FORWARD', layer);
    point(keys[5], X.MRG, y, on.has(layer) ? dot(X.MRG, y) : null);
    hook(keys[6], X.POST, y, 'POSTROUTING', layer);
    hook(keys[7], X.EGR, y, 'egress', 'l1', true);
    point(keys[8], X.out, y, circle(X.out, y));
    for (let i = 1; i < keys.length; i++) line(keys[i - 1], keys[i]);
    arrow((X.in + X.ING - BOX.small / 2) / 2 + 2, y, 0);
    arrow((X.EGR + BOX.small / 2 + X.out) / 2, y, 0);
  };

  // cards draws the devices at both ends of a lane. dir is -1 for the cards
  // that stack upwards and 1 for the ones that stack downwards.
  const cards = (k, y, devs, more, dir, headings) => {
    for (const [side, cx, bus, nodeX] of [['in', X.cardL, X.busL, X.in], ['out', X.cardR, X.busR, X.out]]) {
      const rows = devs.length;
      devs.forEach((dev, i) => {
        // The first device of the list is the topmost card.
        const cy = dir < 0 ? y - (rows - 1 - i) * NIC.step : y + i * NIC.step;
        const edge = side === 'in' ? cx + NIC.w / 2 : cx - NIC.w / 2;
        const wire = [[edge, cy], [bus, cy], [bus, y]];
        track([...wire, [nodeX, y]]);
        const g = el('g', { class: `nic ${dev.up ? '' : 'down'}` });
        const second = isPort(dev) ? peerName(dev) || `port of ${dev.master}` : dev.addrs[0] || (dev.up ? 'no address' : 'down');
        g.append(
          el('title', {}, `${dev.name}${isPort(dev) ? `, port of ${dev.master}` : ''}${peerName(dev) ? `: ${peerName(dev)}` : ''}`),
          el('rect', { x: cx - NIC.w / 2, y: cy - NIC.h / 2, width: NIC.w, height: NIC.h, rx: 6 }),
          el('text', { class: 'nic-name', x: cx - NIC.w / 2 + 10, y: cy - 2 }, short(dev.name, 19)),
          el('text', { class: 'nic-addr', x: cx - NIC.w / 2 + 10, y: cy + 11 }, short(second, 21)),
        );
        pickable(g, ctx, { ifaces: [`${side}:${dev.name}`] }, side === 'in' ? `what arrives on ${dev.name}` : `what leaves through ${dev.name}`);
        parts.append(g);
        S.cards[k][side][dev.name] = { el: g, wire, cx, cy, bridge: dev.kind === 'bridge' };
      });
      const end = dir < 0 ? y - (Math.max(rows, 1) - 1) * NIC.step - NIC.h / 2 : y + (Math.max(rows, 1) - 1) * NIC.step + NIC.h / 2;
      if (dir < 0) {
        label(cx, end - 8 - (more ? 18 : 0), headings[side]);
        if (more) label(cx, end - 8, `and ${more} more`);
      } else {
        label(cx, y - NIC.h / 2 - 8, headings[side]);
        if (more) label(cx, end + 16, `and ${more} more`);
      }
    }
  };

  if (has3) {
    lane(3, y3, 'l3');
    if (on.has('l3')) {
      // The sockets and the processes behind them, above the IP lane.
      const mid = (sockY + SOCK_H + y3) / 2;
      const bar = el('rect', { class: 'proc', x: X.in, y: sockY, width: X.out - X.in, height: SOCK_H, rx: 6 });
      parts.append(bar, el('text', { class: 'proc-label', x: (X.in + X.out) / 2, y: sockY + 15, 'text-anchor': 'middle' }, 'Sockets'));
      point('SOCKin', X.DEC, sockY + SOCK_H, bar);
      point('SOCKout', X.MRG, sockY + SOCK_H, bar);
      // A packet goes up through INPUT and down through OUTPUT.
      let inHalf = BOX.h / 2, outHalf = BOX.h / 2;
      if (withStages()) {
        inHalf = stageHook('INPUT3', X.DEC, mid, 'INPUT', 0, -CHIP.dy);
        outHalf = stageHook('OUTPUT3', X.MRG, mid, 'OUTPUT', 0, CHIP.dy);
      } else {
        hook('INPUT3', X.DEC, mid, 'INPUT', 'l3');
        hook('OUTPUT3', X.MRG, mid, 'OUTPUT', 'l3');
      }
      line('DEC3', 'INPUT3'); line('INPUT3', 'SOCKin'); line('SOCKout', 'OUTPUT3'); line('OUTPUT3', 'MRG3');
      arrow(X.DEC, (mid + inHalf + y3) / 2 - 4, -90);
      arrow(X.MRG, (mid + outHalf + y3) / 2 + 6, 90);
      label(X.DEC + 14, y3 - 30, 'routing', 'start');
      const rowW = procs.length * (PROC.w + PROC.gap) - PROC.gap;
      procs.forEach((proc, i) => {
        const x = (X.in + X.out - rowW) / 2 + i * (PROC.w + PROC.gap), y = TOP;
        tracks.append(el('path', { class: 'track thin', d: `M${x + PROC.w / 2} ${y + PROC.h} V${sockY}` }));
        const g = el('g', { class: 'nic' });
        const portsText = proc.sockets.map((s) => `${s.proto} :${s.port}`).join('  ');
        g.append(
          el('title', {}, `${proc.name} (pid ${proc.pid}): ${portsText}`),
          el('rect', { x, y, width: PROC.w, height: PROC.h, rx: 8 }),
          el('text', { class: 'nic-name', x: x + 10, y: y + 16 }, short(proc.name, 22)),
          el('text', { class: 'nic-addr', x: x + 10, y: y + 30 }, short(portsText, 26)),
        );
        pickable(g, ctx, socketsFilter(proc.sockets), `the ports of ${proc.name} (pid ${proc.pid})`);
        parts.append(g);
        S.procs[proc.pid] = { el: g, cx: x + PROC.w / 2, bottom: y + PROC.h };
      });
      if (moreProcs) label((X.in + X.out + rowW) / 2 + 14, TOP + PROC.h / 2 + 4, `and ${moreProcs} more`, 'start');
      if (!procs.length) label((X.in + X.out) / 2, sockY - 10, store.host.procs.length ? 'The processes are switched off (Show, Processes).' : 'No process listens on a TCP or UDP port.');
    }
    cards(3, y3, cards3, more3, -1, { in: 'Devices: arriving on', out: 'Devices: leaving through' });
  }

  if (has2) {
    lane(2, y2, 'l2');
    const mid = (y2 + barY) / 2 + 4;
    const bar = el('rect', { class: 'proc', x: X.in, y: barY, width: X.out - X.in, height: BAR_H, rx: 6 });
    parts.append(bar, el('text', { class: 'proc-label', x: (X.in + X.out) / 2, y: barY + 17, 'text-anchor': 'middle' }, 'Bridge device: the bridge as a device of the network stack'));
    point('BARin', X.DEC, barY, bar);
    point('BARout', X.MRG, barY, bar);
    hook('INPUT2', X.DEC, mid, 'INPUT', 'l2');
    hook('OUTPUT2', X.MRG, mid, 'OUTPUT', 'l2');
    line('DEC2', 'INPUT2'); line('INPUT2', 'BARin'); line('BARout', 'OUTPUT2'); line('OUTPUT2', 'MRG2');
    if (on.has('l2')) {
      arrow(X.DEC, (y2 + mid - BOX.h / 2) / 2 + 4, 90);
      arrow(X.MRG, (y2 + mid - BOX.h / 2) / 2 - 4, -90);
    }
    cards(2, y2, cards2, more2, 1, { in: 'Ports: arriving on', out: 'Ports: leaving through' });
  }

  if (has2 && has3) {
    // br_netfilter: a bridge hook calls the IP hook above it, and the packet
    // comes back.
    for (const n of ['PRE', 'FWD', 'POST']) {
      S.edges.get(`${n}2`).push(`${n}3`);
      S.edges.get(`${n}3`).push(`${n}2`);
      if (on.has('l2') && on.has('l3')) track([[X[n], y2 - BOX.h / 2], [X[n], y3 + (withStages() ? CHIP.h / 2 + 12 : BOX.h / 2)]], 'loop');
    }
    if (on.has('l2') && on.has('l3')) label(X.FWD + 10, y3 + 68, 'br_netfilter', 'start');
    // The bridge devices are among the devices of the IP lane. The bar of the
    // bridge lane is joined to their cards around both sides.
    const loopY = barY + BAR_H / 2;
    for (const [side, loopX, edgeDx, barX] of [['in', X.loopL, -NIC.w / 2, X.in], ['out', X.loopR, NIC.w / 2, X.out]]) {
      const bridges = Object.values(S.cards[3][side]).filter((c) => c.bridge);
      if (!bridges.length) continue;
      const top = Math.min(...bridges.map((c) => c.cy));
      track([[barX, loopY], [loopX, loopY], [loopX, top]]);
      for (const c of bridges) track([[loopX, c.cy], [c.cx + edgeDx, c.cy]]);
      arrow(loopX, (loopY + y3) / 2, side === 'in' ? -90 : 90);
    }
  }
  T = tracer(svg, trails, marks);
}

// way finds the way from one point of the map to another, along the lines.
function way(from, to) {
  if (from === to) return [from];
  const prev = new Map([[from, null]]);
  const queue = [from];
  while (queue.length) {
    const at = queue.shift();
    for (const next of S.edges.get(at) || []) {
      if (prev.has(next)) continue;
      prev.set(next, at);
      if (next === to) {
        const path = [to];
        while (prev.get(path[0]) !== null) path.unshift(prev.get(path[0]));
        return path;
      }
      queue.push(next);
    }
  }
  return null;
}

// laneOf tells the lane of a box of the plan: a device hook is in the lane of
// the bridge when its device is a port.
function laneOf(box) {
  if (box.layer === 'l3') return 3;
  if (box.layer === 'l2') return 2;
  const dev = ifaceByName(box.first.in || box.first.out);
  return dev && isPort(dev) && S.has2 ? 2 : 3;
}

// trace puts the path of a packet on the diagram. It returns how long the
// animation takes.
function trace(j, p) {
  const end = ending(j, p);
  // The stops of the trail. A stop may light up a part, and a stop with a
  // gap starts a new trail: the packet left the namespace's hooks on one side
  // and came back in on the other.
  const stops = [];
  let cur = null, gap = false;
  // inBox is the box of stages the trail is in, when it stopped at a chip
  // that is not in the middle of the box.
  let inBox = null;
  const push = (at, node, cls) => { stops.push({ at, node, cls: cls || 'lit', gap }); gap = false; };
  const walk = (to) => {
    const path = cur === null ? [to] : way(cur, to);
    if (!path) return false;
    for (const key of cur === null ? path : path.slice(1)) {
      const n = S.nodes.get(key);
      // The line of a box of stages is left sideways from its middle only.
      if (inBox && (inBox.across ? n.at[1] !== inBox.at[1] : n.at[0] !== inBox.at[0])) push(inBox.at);
      inBox = null;
      // A box on the way lights up only when one of its probes saw the packet.
      push(n.at, n.box ? null : n.el);
    }
    cur = to;
    return true;
  };
  const enter = (k, dev) => {
    if (stops.length) gap = true;
    const card = S.cards[k].in[dev];
    if (card) card.wire.forEach((pt, i) => push(pt, i === 0 ? card.el : null));
    cur = null;
    walk(`in${k}`);
  };
  const leave = (k, dev) => {
    if (!walk(`out${k}`)) return;
    const card = S.cards[k].out[dev];
    if (card) [...card.wire].reverse().forEach((pt, i, all) => push(pt, i === all.length - 1 ? card.el : null));
    cur = null;
  };
  const loopY = S.barY + BAR_H / 2;
  // up takes a frame from the bridge lane to the IP lane, through the bridge device.
  const up = (dev) => {
    const card = S.cards[3].in[dev];
    if (!walk('BARin') || !card) { enter(3, dev); return; }
    push([X.DEC, loopY]); push([X.loopL, loopY]); push([X.loopL, card.cy]); push([card.cx - NIC.w / 2, card.cy], card.el);
    card.wire.forEach((pt) => push(pt));
    cur = null;
    walk('in3');
  };
  // down takes a packet from the IP lane to the bridge lane the same way.
  const down = (dev) => {
    const card = S.cards[3].out[dev];
    if (!card || !walk('out3')) { gap = true; cur = null; walk('BARout'); return; }
    [...card.wire].reverse().forEach((pt) => push(pt));
    push([card.cx + NIC.w / 2, card.cy], card.el); push([X.loopR, card.cy]); push([X.loopR, loopY]); push([X.MRG, loopY]);
    cur = null;
    walk('BARout');
  };

  let prev = null;
  let last = null;
  p.seq.forEach((s, i) => {
    const box = s.box, k = laneOf(box), key = HOOK_KEY[box.hook] + k;
    const n = S.nodes.get(key);
    if (!n) return;
    const h = box.first;
    const lastHop = box.hops[box.hops.length - 1].h;
    if (cur === null && !stops.length) {
      // Where the path starts: at a device, at a process, or right at the hook
      // when the packet started to match the filter in the middle of its way.
      if (box.hook === 'INGRESS' || box.hook === 'PREROUTING') enter(k, h.in);
      else if (key === 'OUTPUT3') {
        const proc = j.l3 && j.l3.from && S.procs[j.l3.from.pid];
        const mid = S.sockY + SOCK_H / 2;
        if (proc) { push([proc.cx, proc.bottom], proc.el); push([proc.cx, mid]); push([X.MRG, mid]); }
        walk('SOCKout');
      } else if (key === 'OUTPUT2') walk('BARout');
    } else if (cur === null || !way(cur, key)) {
      // No line leads there. Between the lanes, the way is around the side,
      // through the bridge device. Within a lane, the packet left through a
      // device and came back in through another one (loopback, a veth pair).
      const from = prev ? laneOf(prev.box) : k;
      const out = prev ? prev.box.hops[prev.box.hops.length - 1].h : null;
      const viaBridge = k === 3 && S.has2 && S.cards[3].in[h.in] && S.cards[3].in[h.in].bridge;
      const atEnd = prev && ['EGRESS', 'POSTROUTING'].includes(prev.box.hook) && prev.box.exited;
      if (cur !== null && (from === 2 || viaBridge) && k === 3 && way(cur, 'BARin')) up(h.in || (out && out.bridge) || '');
      else if (cur !== null && from === 3 && k === 2) down((out && out.out) || h.bridge || '');
      else {
        if (cur !== null && atEnd) leave(from, out ? out.out || '' : '');
        enter(k, h.in || '');
      }
    }
    if (!walk(key)) { gap = true; cur = null; walk(key); }
    let stop = stops[stops.length - 1];
    const stopped = end.box === box && i === p.seq.length - 1;
    if (n.chips) {
      // A box of stages: the trail goes from chip to chip, and lights up the
      // ones whose probes saw the packet. It came in along the line of the
      // chips, or from the side (br_netfilter) into the middle of the box.
      const before = stops[stops.length - 2];
      if (before && !stop.gap && (n.across ? before.at[1] === n.at[1] : before.at[0] === n.at[0])) stops.pop();
      const seen = box.hops.filter((x) => !x.h.exit && n.chips[x.h.stage]);
      seen.forEach((x, at) => {
        const chip = n.chips[x.h.stage];
        const dead = stopped && at === seen.length - 1;
        push(chip.at, chip.el, `lit${x.h.rewrote ? ' rewrote' : ''}${dead ? ' stopped' : ''}`);
        if (dead) stops[stops.length - 1].mark = [chip.at[0] + CHIP.w / 2 + 2, chip.at[1] - CHIP.h / 2 + 2];
      });
      inBox = n;
      stop = stops[stops.length - 1];
    } else {
      stop.node = n.el;
      stop.cls = `lit${box.hops.some((x) => x.h.rewrote) ? ' rewrote' : ''}${stopped ? ' stopped' : ''}`;
      if (stopped) stop.mark = [n.at[0] + (box.layer === 'l1' ? BOX.small : BOX.w) / 2 - 4, n.at[1] - BOX.h / 2 + 4];
    }
    // The device hook tells which device it is of this time.
    if (n.el && n.el.dev) stop.sub = [n.el.dev, h.in || h.out];
    prev = s;
    last = { box, key, k, hop: lastHop };
  });
  if (!last) return 0;

  // Where the path ends.
  if (last.box.exited) {
    const name = HOOK_KEY[last.box.hook];
    // br_netfilter runs the IP POSTROUTING after the bridge's own: the last
    // probe is in the IP lane, but the frame leaves through the port.
    if (last.key === 'POST3' && last.hop.pout && S.has2 && walk('POST2')) leave(2, last.hop.pout);
    else if (name === 'EGR' || name === 'POST') leave(last.k, last.hop.out || '');
    else if (last.key === 'INPUT3') {
      walk('SOCKin');
      const proc = j.l3 && j.l3.to && S.procs[j.l3.to.pid];
      const mid = S.sockY + SOCK_H / 2;
      if (proc) { push([X.DEC, mid]); push([proc.cx, mid]); push([proc.cx, proc.bottom], proc.el); }
    } else if (last.key === 'INPUT2') walk('BARin');
    else if (end.lost) {
      // The packet left the hook and was not seen again: the trail ends at the
      // next point of the line.
      const next = { PRE: 'DEC', FWD: 'MRG', OUTPUT: 'MRG' }[name];
      if (next && walk(next + last.k)) {
        const stop = stops[stops.length - 1];
        stop.cls = 'stopped';
        stop.mark = [stop.at[0] + 16, stop.at[1] - 16];
        if (!stop.node) stop.mark = [stop.at[0], stop.at[1]];
      }
    }
  }

  // Draw the trails one after another, and light up the parts as they are reached.
  let at = 0;
  let from = 0;
  while (from < stops.length) {
    let to = from + 1;
    while (to < stops.length && !stops[to].gap) to++;
    const part = stops.slice(from, to);
    const t = T.trail(part.map((x) => x.at), '', at);
    let dist = 0;
    part.forEach((x, i) => {
      if (i) dist += Math.hypot(x.at[0] - part[i - 1].at[0], x.at[1] - part[i - 1].at[1]);
      const when = T.timeAt(at, dist);
      if (x.node) T.light(x.node, when, x.cls);
      if (x.mark) T.stop(x.mark, when);
      if (x.sub) T.later(when, () => { x.sub[0].textContent = x.sub[1]; });
    });
    at = t.done;
    from = to;
  }
  return at;
}

function show(item, animate) {
  const j = item ? item.j : null;
  if (j !== shown) {
    shown = j;
    leaf = j ? defaultLeaf(j) : 0;
  }
  if (!S || !T) return 0;
  T.reset(animate);
  for (const sub of S.subs) sub.textContent = '';
  if (!j) return 0;
  const p = plan(j, leaf, S.on);
  return p.seq.length ? trace(j, p) : 0;
}

// ---- Text ------------------------------------------------------------------

function verdict(item) {
  if (!item) return { text: 'Waiting for a packet that matches the filter.' };
  const j = item.j;
  const on = onLayers();
  const p = plan(j, shown === j ? leaf : defaultLeaf(j), on);
  const end = ending(j, p);
  let text = end.text;
  const hops = p.boxes.flatMap((b) => b.hops.map((x) => x.h));
  if (hops.some((h) => h.layer === 'l3' && (h.pin || h.pout)) && on.has('l2')) {
    text += ' The IP hooks ran inside the bridge hooks: br_netfilter is loaded, so iptables and nftables rules of the IP families see the bridged packets.';
  }
  const all = leaves(j);
  if (all.length > 1) {
    const mine = all.find((c) => c.id === leaf);
    text += ` A bridge made ${all.length} copies of this frame. This is the one that went ${mine ? copyName(mine) : 'on'}: pick another one above the diagram.`;
  }
  if (j.unreliable) text += ' Some probe events were lost around this packet, so the path may be incomplete.';
  return { head: `${end.head}.`, text, kind: end.kind };
}

const layersOf = (j) => LANES.map((l) => l.layer).filter((l) => j.hops.some((h) => h.layer === l)).reverse().map((l) => l.toUpperCase()).join(' ');

function cells(item) {
  const j = item.j;
  const f = j.frame;
  const end = ending(j, plan(j, defaultLeaf(j), new Set(['l1', 'l2', 'l3'])));
  const copies = leaves(j).length;
  return [
    [clock(j.time), 'mono'], [layersOf(j), 'mono'],
    [j.proto ? j.src : f ? f.src : '', 'mono'], [j.proto ? j.dst : f ? f.dst : '', 'mono'],
    [j.proto ? [j.proto.toUpperCase(), j.info].filter(Boolean).join(' ') : f ? [f.type, f.info].filter(Boolean).join(' ') : '', 'details'],
    [end.head + (copies > 1 ? ` (1 of ${copies} copies)` : ''), end.kind === 'stopped' ? 'outcome-stopped' : 'outcome-done'],
  ];
}

// detail lists every probe that saw the packet on the path on view.
function detail(item) {
  const d = { title: 'Path of the selected packet', columns: ['Layer', 'Hook', 'In', 'Out', 'Source', 'Destination', 'Elapsed'], empty: 'Select a packet to see every probe that saw it.', summary: '', rows: [] };
  if (!item) return d;
  const j = item.j;
  d.summary = j.proto ? [j.proto.toUpperCase(), j.info, `${j.len} bytes`].filter(Boolean).join(', ') : j.frame ? [j.frame.type, j.frame.info].filter(Boolean).join(', ') : '';
  const on = onLayers();
  const line = lineage(j, shown === j ? leaf : defaultLeaf(j));
  const hops = j.hops.filter((h) => line.has(h.copy || 0) && on.has(h.layer));
  const end = ending(j, plan(j, shown === j ? leaf : defaultLeaf(j), on));
  // Without the stages, the probes of one pass through an IP hook are one row.
  const rows = [];
  for (const h of hops) {
    const prev = rows[rows.length - 1];
    if (!withStages() && h.layer === 'l3' && prev && prev.first.layer === 'l3' && prev.first.hook === h.hook && !prev.last.exit) {
      prev.hops.push(h);
      prev.last = h;
    } else rows.push({ first: h, last: h, hops: [h] });
  }
  rows.forEach((r, i) => {
    const h = r.first;
    const whole = !withStages() && h.layer === 'l3';
    const name = whole ? h.hook
      : h.layer === 'l3' ? (h.exit ? `left ${h.hook}` : `${h.stage}/${h.hook}`)
        : `${h.exit ? 'left' : 'entered'} ${h.hook}${h.layer === 'l2' ? ` of ${h.bridge}` : ''}`;
    const ip = h.layer === 'l3' || !h.smac;
    const out = [...r.hops].reverse().find((x) => x.pout || x.out);
    const row = {
      cells: [[h.layer.toUpperCase(), 'mono'], [name, 'mono wrap'], [h.pin || h.in || '', 'mono'], [out ? out.pout || out.out : '', 'mono'], [(ip ? h.src : h.smac) || '', 'mono'], [(ip ? h.dst : h.dmac) || '', 'mono'], [micros(h.us), 'mono']],
      cls: !whole && h.exit ? 'exit' : '', notes: [],
    };
    const rewrites = r.hops.filter((x) => x.rewrote).map((x) => x.rewrote);
    if (rewrites.length) { row.cls += ' rewrote'; row.notes.push(`This ${whole ? 'hook' : 'stage'} rewrote the ${rewrites.join(', ')}.`); }
    if (i === rows.length - 1 && end.kind === 'stopped') {
      row.cls += ' stopped';
      row.notes.push(end.lost ? 'The packet was not seen after this point.' : 'The packet did not leave this hook.');
    }
    d.rows.push(row);
  });
  return d;
}

export default {
  id: 'all',
  label: 'Combined',
  title: 'Packets',
  noun: 'packet',
  layer: '',
  about: 'One packet across the device, bridge, and IP hooks, on one diagram.',
  // The IP hooks as one box each, or with the stages inside them (see level).
  subs: [{ id: 'hooks', label: 'Hooks only' }, { id: 'stages', label: 'Stages' }],
  // The layers of this view can be switched on and off one by one.
  layered: true,
  level: { label: 'Stages', on: 'stages', off: 'hooks', about: 'The raw, mangle, nat, and filter stages inside the IP hooks, in the diagram and in the table' },
  panels: [{ id: 'packets', label: 'Packets' }, { id: 'details', label: 'Path' }],
  aria: 'The hooks of all the layers, the devices around them, and the path of the selected packet',
  init(context) { ctx = context; },
  items: (j) => [{ id: `${j.id}`, j, time: j.time }],
  columns: ['Time', 'Layers', 'Source', 'Destination', 'Details', 'Outcome'],
  cells,
  resize: () => false,
  build,
  show,
  verdict,
  detail,
  // blocks are the cards of the diagram: each can be taken out of it.
  blocks: () => [
    { id: 'devices', label: 'Devices', items: store.host.ifaces.map((d) => ({ key: d.name, label: d.name, note: isPort(d) ? `port of ${d.master}` : d.kind === 'bridge' ? 'bridge' : d.addrs[0] || '' })) },
    { id: 'procs', label: 'Processes', items: store.host.procs.map((x) => ({ key: procKey(x), label: x.name, note: x.sockets.map((k) => `:${k.port}`).join(' ') })) },
  ],
  // tabs are the copies of the selected frame, when a bridge made several.
  tabs() {
    if (!shown) return [];
    const all = leaves(shown);
    return all.length < 2 ? [] : all.map((c) => ({ id: String(c.id), label: copyName(c), on: c.id === leaf }));
  },
  pickTab(id) { leaf = Number(id); },
  onTab: () => true,
  packetHops(item) {
    const on = onLayers();
    const line = lineage(item.j, shown === item.j ? leaf : defaultLeaf(item.j));
    return item.j.hops.map((h, i) => (line.has(h.copy || 0) && on.has(h.layer) ? i : -1)).filter((i) => i >= 0);
  },
};
