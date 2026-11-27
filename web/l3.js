// The IP hooks (L3): the five netfilter hooks with their classic stages, the
// interfaces around them, and the processes behind the sockets.

import { $, el, embed, listParam, playback, reducedMotion, store, svgButton, tracedTag, procKey, clock, micros, emptyFilter, filterHas } from './core.js';

// The page calls ctx to learn the look that is on and to change the filter.
let ctx = null;
const hooksOnly = () => ctx.sub() === 'hooks';

// Which cards to draw (?ifaces= and ?procs=). Null means all of them.
const cards = { ifaces: listParam('ifaces'), procs: listParam('procs') };

// S is what the drawn diagram consists of.
const S = {
  hookEls: {},           // hooks-only look: hook name -> { el, pos }
  chips: {},             // "HOOK/stage" -> { el, pos }
  nodeEls: {},           // node name -> element
  nics: { in: {}, out: {} },  // interface name -> { el, wire }
  procs: {},             // pid -> { el, cx, cy }
  extras: [],            // processes of the selected packet that listen on nothing
  timers: [],
  trailAnim: null,
};

// Geometry of the diagram. There are two arrangements of the same parts:
//   wide     interface cards in columns left and right of the hooks (wideLayout)
//   compact  interface cards in a row above the hooks, everything closer
// The compact one keeps the text readable when the page gets half a screen.
// In both, the chips of a hook are laid out along one axis.
// wideLayout builds the wide arrangement for the width the diagram gets. Between
// WIDE_MIN and WIDE_FULL px, the cards, the boxes, and the text keep their size
// and only the connecting lines get shorter. Above WIDE_FULL, everything grows
// together.
const WIDE_MIN = 1100, WIDE_FULL = 1540;
// The widths that never change: two interface cards, three hook boxes, the side
// margins. The rest of the width is the connecting lines.
const WIDE_FIXED = 846, WIDE_LINES = 694;

// nicCount is how many interface cards a column has, and nicMore tells whether
// a note about the ones that do not fit follows them: the socket bar must stay
// below both.
function wideLayout(avail, hooksOnly, nicCount, nicMore) {
  const W = Math.round(Math.max(WIDE_MIN, Math.min(WIDE_FULL, avail)));
  const g = (W - WIDE_FIXED) / WIDE_LINES; // 1 at full width
  let x = 10;
  const step = (px) => { x = Math.round(x + px); return x; };
  const cardL = x + 65; step(130);
  const busL = step(35 * g);
  const inX = step(35 * g);
  const preL = step(99 * g); step(242);
  const route1 = step(89 * g);
  const fwdL = step(109 * g); step(162);
  const merge = step(109 * g);
  const postL = step(59 * g); step(162);
  const out = step(89 * g);
  const busR = step(35 * g);
  step(35 * g); const cardR = x + 65;
  const mid = (a, b) => Math.round((a + b) / 2);
  // An arrowhead needs a line that is long enough to carry it.
  // Without the stage chips, the INPUT and OUTPUT boxes need much less height.
  const boxY = hooksOnly ? 160 : 205;
  const nicBottom = 70 + (Math.max(nicCount, 1) - 1) * 42 + 17 + (nicMore ? 22 : 0);
  const sockY = Math.max(hooksOnly ? 246 : 345, nicBottom + 16);
  // The second routing decision sits in the middle of the line from the
  // sockets up to OUTPUT, however far down the cards push the sockets.
  const route2Y = Math.round(((hooksOnly ? 182 : 294) + sockY) / 2);
  const arrows = [[route1, 112, 90], [route1, hooksOnly ? mid(182, sockY) : 306, 90], [merge, 106, -90], [mid(busL, busR), 8, 180]];
  for (const [from, to] of [[inX, preL], [route1, fwdL], [fwdL + 162, merge], [postL + 162, out]]) {
    if (to - from >= 44) arrows.push([mid(from, to), 70, 0]);
  }
  const roomAtRoute1 = fwdL - (preL + 242);
  return {
    compact: false, key: `wide${W}`,
    viewX: 0, viewY: -18, viewW: W, lineY: 70, centerX: W / 2,
    headings: { in: 'Packets arrive on', out: 'Packets leave through' },
    nodes: {
      in: [inX, 70], out: [out, 70],
      route1: [route1, 70], merge: [merge, 70], route2: [merge, route2Y],
      procIn: [route1, sockY], procOut: [merge, sockY],
    },
    hooks: {
      PREROUTING: { x: preL + 41, y: 70, dx: 80, dy: 0, entry: 'in', exit: 'route1' },
      FORWARD: { x: fwdL + 41, y: 70, dx: 80, dy: 0, entry: 'route1', exit: 'merge' },
      POSTROUTING: { x: postL + 41, y: 70, dx: 80, dy: 0, entry: 'merge', exit: 'out' },
      INPUT: { x: route1, y: 160, dx: 0, dy: 40, entry: 'route1', exit: 'procIn' },
      OUTPUT: { x: merge, y: 270, dx: 0, dy: -38, entry: 'route2', exit: 'merge' },
    },
    chip: { w: 62, h: 24 },
    // In the hooks-only view, every hook is one box.
    hookBox: { w: 150, h: 44 },
    hookCenter: { PREROUTING: [preL + 121, 70], FORWARD: [fwdL + 81, 70], POSTROUTING: [postL + 81, 70], INPUT: [route1, boxY], OUTPUT: [merge, boxY] },
    nic: { w: 130, h: 34, max: 7 },
    // The loopback line leaves the "out" side and re-enters on the "in" side.
    loop: [[busR, 70], [busR, 8], [busL, 8], [busL, 70]],
    loopLabel: { x: mid(busL, busR), y: -2, text: 'loopback traffic re-enters here' },
    arrows,
    routeLabels: {
      route1: [0, -20, 'middle', roomAtRoute1 >= 130 ? 'routing decision' : 'routing'],
      route2: [18, 4, 'start', 'routing decision'],
    },
    sock: { x: 10, w: W - 20, y: sockY, h: 22, mid: sockY + 11 },
    proc: { x0: 10, y0: sockY + 40, w: 180, h: 46, gap: 10, rowStep: 56, perRow: Math.floor((W - 10) / 190), max: 2 * Math.floor((W - 10) / 190) },
    // nicCards places the cards of one side and says how each one is wired to its node.
    nicCards(side, count) {
      const cx = side === 'in' ? cardL : cardR, bus = side === 'in' ? busL : busR;
      const edge = side === 'in' ? cx + 65 : cx - 65;
      const cards = [];
      for (let i = 0; i < count; i++) {
        const y = 70 + i * 42;
        cards.push({ cx, cy: y, wire: [[edge, y], [bus, y], [bus, 70]] });
      }
      return { cards, heading: { x: cx, y: 40, anchor: 'middle' }, more: { x: cx, y: 70 + count * 42 - 4, anchor: 'middle' } };
    },
  };
}

// compactLayout builds the compact arrangement. Its hooks-only variant has no
// stage chips to make room for, so it is narrower and shorter: the same boxes
// and text then come out larger in a narrow place.
//
// width is the width to lay the diagram out for, in its own units. Anything
// above the natural width goes into the connecting lines. This is how the
// diagram fills a place that is wider than its natural shape (an iframe of a
// fixed height) instead of leaving blank space on its sides.
function compactLayout(hooksOnly, width) {
  const X = hooksOnly
    ? { in: 28, route1: 232, merge: 436, out: 640 }
    : { in: 30, route1: 284, merge: 495, out: 710 };
  const naturalWidth = X.out - X.in + 112;
  const extra = Math.max(0, Math.round((width || 0) - naturalWidth));
  if (extra) {
    const f = (X.out - X.in + extra) / (X.out - X.in);
    X.route1 = Math.round(X.in + (X.route1 - X.in) * f);
    X.merge = Math.round(X.in + (X.merge - X.in) * f);
    X.out += extra;
  }
  const center = (a, b) => Math.round((a + b) / 2);
  const Y = hooksOnly
    ? { box: 236, route2: 286, sock: 316 }
    : { box: 286, route2: 402, sock: 428 };
  const nic = { w: 104, h: 34, max: 3 };
  // The outermost cards sit right above the "in" and "out" nodes.
  const left = X.in - nic.w / 2 - 4, right = X.out + nic.w / 2 + 4;
  const mid = Math.round((X.in + X.out) / 2);
  const sockW = right - left - 8;
  return {
    compact: true, key: `compact${extra}`, naturalWidth,
    viewX: left, viewY: 0, viewW: right - left, lineY: 160, centerX: mid,
    // The headings are as narrow as a card, so they need no extra margins.
    headings: { in: 'Arriving on', out: 'Leaving through' },
    nodes: {
      in: [X.in, 160], out: [X.out, 160],
      route1: [X.route1, 160], merge: [X.merge, 160], route2: [X.merge, Y.route2],
      procIn: [X.route1, Y.sock], procOut: [X.merge, Y.sock],
    },
    hooks: {
      // The chips of a hook are centered between the nodes around it.
      PREROUTING: { x: center(X.in, X.route1) - 58, y: 160, dx: 58, dy: 0, entry: 'in', exit: 'route1' },
      FORWARD: { x: center(X.route1, X.merge) - 29, y: 160, dx: 58, dy: 0, entry: 'route1', exit: 'merge' },
      POSTROUTING: { x: center(X.merge, X.out) - 29, y: 160, dx: 58, dy: 0, entry: 'merge', exit: 'out' },
      INPUT: { x: X.route1, y: 246, dx: 0, dy: 38, entry: 'route1', exit: 'procIn' },
      OUTPUT: { x: X.merge, y: 354, dx: 0, dy: -36, entry: 'route2', exit: 'merge' },
    },
    chip: { w: 52, h: 24 },
    hookBox: { w: 124, h: 40 },
    hookCenter: {
      PREROUTING: [center(X.in, X.route1), 160],
      FORWARD: [center(X.route1, X.merge), 160],
      POSTROUTING: [center(X.merge, X.out), 160],
      INPUT: [X.route1, Y.box], OUTPUT: [X.merge, Y.box],
    },
    nic,
    // The loopback line runs between the cards and the hooks.
    loop: [[X.out, 106], [X.in, 106]],
    loopLabel: { x: mid, y: 99, text: 'loopback' },
    arrows: hooksOnly
      ? [[X.route1, 198, 90], [X.route1, 290, 90], [X.merge, 196, -90], [mid + 60, 106, 180]]
      : [[X.route1, 202, 90], [X.route1, 394, 90], [X.merge, 200, -90], [mid + 60, 106, 180]],
    routeLabels: { route1: [0, -19, 'middle', 'routing'], route2: [17, 4, 'start', 'routing'] },
    sock: { x: left + 4, w: sockW, y: Y.sock, h: 22, mid: Y.sock + 11 },
    proc: { x0: left + 4, y0: Y.sock + 40, w: Math.floor((sockW - 30) / 4), h: 46, gap: 10, rowStep: 56, perRow: 4, max: 8 },
    nicCards(side, count) {
      const nodeX = side === 'in' ? X.in : X.out;
      const cards = [];
      for (let i = 0; i < count; i++) {
        // The outermost card sits right above its node, so its wire is straight.
        const cx = side === 'in' ? nodeX + i * 110 : nodeX - i * 110;
        cards.push({ cx, cy: 44, wire: i === 0 ? [[cx, 61]] : [[cx, 61], [cx, 82], [nodeX, 82]] });
      }
      // The heading is centered above the row of cards.
      const rowCenter = count ? (cards[0].cx + cards[count - 1].cx) / 2 : nodeX;
      return {
        cards,
        heading: { x: rowCenter, y: 13, anchor: 'middle' },
        // Both rows end in the middle, so one note there stands for both.
        more: side === 'in' ? { x: mid, y: 48, anchor: 'middle' } : null,
      };
    },
  };
}

// G is the arrangement in use. buildDiagram picks it for the box the diagram
// gets, the view, and the number of interface cards and processes.
// diagramHeight is Infinity when the page is free to grow (the full view).
let diagramWidth = WIDE_FULL, diagramHeight = Infinity;
let G = wideLayout(WIDE_FULL, false, 1, false);

function pickLayout(hooksOnly, nicCount, procCount, nicMore) {
  if (diagramWidth >= WIDE_MIN) return wideLayout(diagramWidth, hooksOnly, nicCount, nicMore);
  const base = compactLayout(hooksOnly, 0);
  if (!Number.isFinite(diagramHeight) || diagramHeight <= 0) return base;
  // The box has a fixed height. When the diagram at its natural shape would
  // be limited by that height, lay it out wider, so that it fills the width too.
  const height = diagramBottom(base, Math.min(procCount, base.proc.max), procCount > base.proc.max);
  const fit = (diagramWidth * height) / diagramHeight;
  if (fit < base.viewW * 1.03) return base;
  // Steps of 8 units keep a slow resize from rebuilding the diagram all the time.
  const width = Math.min(Math.round(fit / 8) * 8, Math.round(base.viewW * 1.6));
  return compactLayout(hooksOnly, base.naturalWidth + (width - base.viewW));
}

// diagramBottom is the y coordinate where a diagram that draws that many
// processes ends: right under its last row of them (and the note about the ones
// that do not fit, if there is one).
function diagramBottom(layout, procCount, withNote) {
  // The view asked for no processes at all (?procs=): the socket bar is the end.
  if (!procCount && cards.procs) return layout.sock.y + layout.sock.h + 2;
  const { proc } = layout;
  const rows = Math.max(1, Math.ceil(procCount / proc.perRow));
  return proc.y0 + (rows - 1) * proc.rowStep + proc.h + (withNote ? 20 : 2);
}

// layoutCounts tells how many interface cards and processes the diagram draws,
// and whether some interfaces do not fit.
function layoutCounts() {
  const ifaces = store.host.ifaces.filter(ifaceShown).length;
  return [Math.min(ifaces, 7), store.host.procs.filter(procShown).length + S.extras.length, ifaces > 7];
}

// The URL can limit the cards (?ifaces=, ?procs=), and the Show menus of the
// header switch single ones off.
const ifaceListed = (ifc) => !cards.ifaces || cards.ifaces.includes(ifc.name);
const procListed = (proc) => !cards.procs || cards.procs.some((item) => {
  const port = /^:?\d+$/.test(item) ? Number(item.replace(':', '')) : null;
  return port === null ? proc.name === item : proc.sockets.some((s) => s.port === port);
});
const ifaceShown = (ifc) => ifaceListed(ifc) && ctx.blockOn('devices', ifc.name);
const procShown = (proc) => procListed(proc) && (proc.extra || ctx.blockOn('procs', procKey(proc)));

function blocks() {
  return [
    { id: 'devices', label: 'Devices', items: store.host.ifaces.filter(ifaceListed).map((i) => ({ key: i.name, label: i.name, note: i.addrs[0] || '' })) },
    { id: 'procs', label: 'Processes', items: store.host.procs.filter(procListed).map((p) => ({ key: procKey(p), label: p.name, note: p.sockets.map((x) => `:${x.port}`).join(' ') })) },
  ];
}

// ---- Filter picks ----------------------------------------------------------

// side is "in" for the cards packets arrive on and "out" for the cards they leave through.
function pickIface(side, name, more) {
  ctx.pick({ ...emptyFilter(), ifaces: [`${side}:${name}`] }, more);
}

function ifacePicked(side, name) {
  const f = ctx.filter();
  return !embed && (f.ifaces.includes(`${side}:${name}`) || f.ifaces.includes(name));
}

function socketsFilter(sockets) {
  return {
    ...emptyFilter(),
    protos: [...new Set(sockets.map((s) => s.proto))].sort(),
    ports: [...new Set(sockets.map((s) => s.port))].sort((a, b) => a - b),
  };
}

function pickSockets(sockets, more) {
  ctx.pick(socketsFilter(sockets), more);
}

// A socket or a process counts as picked when the filter has all its ports.
function socketsPicked(sockets) {
  return !embed && filterHas(ctx.filter(), socketsFilter(sockets));
}

// stageLabel names a stage the way the current look draws it.
const stageLabel = (hook, stage) => (hooksOnly() ? hook : `${stage}/${hook}`);

// ---- Diagram ---------------------------------------------------------------

function buildDiagram() {
  const svg = $('#diagram');
  svg.replaceChildren();
  G = pickLayout(hooksOnly(), ...layoutCounts());
  svg.classList.toggle('compact', G.compact);
  S.chips = {};
  S.nodeEls = {};
  S.nics = { in: {}, out: {} };
  S.procs = {};
  S.hookEls = {};

  const { nodes, lineY } = G;
  const allIfaces = store.host.ifaces.filter(ifaceShown);
  const ifaces = allIfaces.slice(0, G.nic.max);
  const P = G.proc;
  const allProcs = store.host.procs.filter(procShown);
  const procs = [...allProcs.slice(0, P.max - S.extras.length), ...S.extras];
  // The rows of processes sit in the middle of the socket bar.
  const rowWidth = Math.min(Math.max(procs.length, 1), P.perRow) * (P.w + P.gap) - P.gap;
  const procShift = Math.max(0, (G.sock.w - rowWidth) / 2);
  const hidden = allProcs.length + S.extras.length - procs.length;
  const height = diagramBottom(G, procs.length, hidden > 0);
  svg.setAttribute('viewBox', `${G.viewX} ${G.viewY} ${G.viewW} ${height - G.viewY}`);
  const line = (pts) => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0]} ${p[1]}`).join(' ');

  // Tracks
  svg.append(
    el('path', { class: 'track loop', d: line([nodes.out, ...G.loop, nodes.in]) }),
    el('path', { class: 'track', d: line([nodes.in, nodes.out]) }),
    el('path', { class: 'track', d: line([nodes.route1, nodes.procIn]) }),
    el('path', { class: 'track', d: line([nodes.procOut, nodes.merge]) }),
  );
  for (const [x, y, rot] of G.arrows) {
    svg.append(el('path', { class: 'arrow', d: 'M-6 -5 L5 0 L-6 5 Z', transform: `translate(${x} ${y}) rotate(${rot})` }));
  }
  svg.append(el('text', { class: 'label', x: G.loopLabel.x, y: G.loopLabel.y, 'text-anchor': 'middle' }, G.loopLabel.text));

  // Trail of the selected packet: above the tracks, below everything else
  svg.append(el('path', { id: 'trail', d: '' }));

  // Network interfaces: the same cards on both ends
  const nicSide = (side, heading) => {
    const placed = G.nicCards(side, ifaces.length);
    const h = placed.heading;
    svg.append(el('text', { class: 'label', x: h.x, y: h.y, 'text-anchor': h.anchor }, heading));
    ifaces.forEach((ifc, i) => {
      const card = placed.cards[i];
      const left = card.cx - G.nic.w / 2, top = card.cy - G.nic.h / 2;
      svg.append(el('path', { class: 'track', d: line([...card.wire, nodes[side]]) }));
      // In the compact arrangement a card sits above its wire, so its text is centered.
      const centered = G.compact;
      const textX = centered ? card.cx : left + 10, anchor = centered ? 'middle' : 'start';
      const g = el('g', { class: 'nic' });
      if (!ifc.up) g.classList.add('down');
      const picked = ifacePicked(side, ifc.name);
      if (picked) g.classList.add('picked');
      g.append(
        el('rect', { x: left, y: top, width: G.nic.w, height: G.nic.h, rx: 6 }),
        el('text', { class: 'nic-name', x: textX, y: card.cy - 2, 'text-anchor': anchor }, ifc.name),
        el('text', { class: 'nic-addr', x: textX, y: card.cy + 11, 'text-anchor': anchor }, ifc.up ? (ifc.addrs[0] || 'no address') : 'down'),
      );
      const what = side === 'in' ? `packets arriving on ${ifc.name}` : `packets leaving through ${ifc.name}`;
      svgButton(g, picked ? `Stop tracing only ${what}` : `Trace only ${what}`, (more) => pickIface(side, ifc.name, more));
      if (picked) g.append(tracedTag(left + G.nic.w - 4, top));
      svg.append(g);
      S.nics[side][ifc.name] = { el: g, wire: card.wire };
    });
    if (allIfaces.length > ifaces.length && placed.more) {
      const m = placed.more;
      svg.append(el('text', { class: 'label', x: m.x, y: m.y, 'text-anchor': m.anchor }, `and ${allIfaces.length - ifaces.length} more`));
    }
  };
  nicSide('in', G.headings.in);
  nicSide('out', G.headings.out);

  // Sockets and the processes that own them
  const bar = el('rect', { class: 'proc', x: G.sock.x, y: G.sock.y, width: G.sock.w, height: G.sock.h, rx: 6 });
  svg.append(bar, el('text', { class: 'proc-label', x: G.centerX, y: G.sock.y + 15, 'text-anchor': 'middle' }, 'Sockets'));
  S.nodeEls.procIn = bar;
  S.nodeEls.procOut = bar;
  if (!procs.length && !cards.procs) {
    svg.append(el('text', { class: 'label', x: G.centerX, y: P.y0 + 26, 'text-anchor': 'middle' }, store.host.procs.length ? 'All the processes are switched off (Show, Processes).' : 'No process listens on a TCP or UDP port.'));
  }
  const procPos = (i) => [P.x0 + procShift + (i % P.perRow) * (P.w + P.gap), P.y0 + Math.floor(i / P.perRow) * P.rowStep];
  // The connectors from the socket bar are drawn first: the boxes of an upper
  // row then cover the connectors of the rows below them.
  procs.forEach((proc, i) => {
    const [x, y] = procPos(i);
    svg.append(el('path', { class: 'track thin', d: `M${x + P.w / 2} ${G.sock.y + G.sock.h} V${y}` }));
  });
  procs.forEach((proc, i) => {
    const [x, y] = procPos(i);
    const g = el('g', { class: 'procchip' });
    if (proc.extra) g.classList.add('extra');
    const body = el('g', { class: 'procbody' });
    // The name gets the room the pid leaves.
    const pidText = `pid ${proc.pid}`;
    const fit = Math.max(4, Math.floor((P.w - 24 - pidText.length * 6.4) / 7));
    const name = proc.name.length > fit ? `${proc.name.slice(0, fit - 1)}…` : proc.name;
    body.append(
      el('rect', { x, y, width: P.w, height: P.h, rx: 8 }),
      el('text', { class: 'proc-name', x: x + 10, y: y + 17 }, name),
      el('text', { class: 'proc-pid', x: x + P.w - 10, y: y + 17, 'text-anchor': 'end' }, pidText),
    );
    const procPicked = socketsPicked(proc.sockets);
    svgButton(body, procPicked ? `Stop tracing only ${proc.name}` : `Trace only the ports of ${proc.name} (pid ${proc.pid})`, (more) => pickSockets(proc.sockets, more));
    g.append(body);
    if (procPicked) g.classList.add('picked');
    // One pill per socket, as many as fit
    let px = x + 8;
    let shown = 0;
    for (const sock of proc.sockets) {
      const label = `${sock.proto} :${sock.port}`;
      const w = label.length * 6.4 + 14;
      const room = shown < proc.sockets.length - 1 ? 30 : 0;
      if (px + w > x + P.w - 8 - room) break;
      const pill = el('g', { class: 'sock' });
      const sockPicked = !procPicked && socketsPicked([sock]);
      if (sockPicked) pill.classList.add('picked');
      pill.append(
        el('rect', { x: px, y: y + 24, width: w, height: 16, rx: 8 }),
        el('text', { x: px + w / 2, y: y + 35.5, 'text-anchor': 'middle' }, label),
      );
      svgButton(pill, sockPicked ? `Stop tracing only ${sock.proto.toUpperCase()} port ${sock.port}` : `Trace only ${sock.proto.toUpperCase()} port ${sock.port}`, (more) => pickSockets([sock], more));
      g.append(pill);
      px += w + 5;
      shown++;
    }
    if (shown < proc.sockets.length) {
      g.append(el('text', { class: 'proc-pid', x: px + 2, y: y + 35.5 }, `+${proc.sockets.length - shown}`));
    }
    if (procPicked) g.append(tracedTag(x + P.w - 4, y));
    svg.append(g);
    S.procs[proc.pid] = { el: g, cx: x + P.w / 2, cy: y };
  });
  if (hidden > 0) {
    svg.append(el('text', { class: 'label', x: G.sock.x + G.sock.w, y: height - 2, 'text-anchor': 'end' }, `and ${hidden} more processes`));
  }

  // Hooks with their stage chips
  const { w: chipW, h: chipH } = G.chip;
  for (const hook of store.hooks) {
    const lay = G.hooks[hook.name];
    if (!lay) continue;
    if (hooksOnly()) {
      const [cx, cy] = G.hookCenter[hook.name];
      const g = el('g', { class: 'hook' });
      g.append(
        el('rect', { x: cx - G.hookBox.w / 2, y: cy - G.hookBox.h / 2, width: G.hookBox.w, height: G.hookBox.h, rx: 10 }),
        el('text', { class: 'hookname', x: cx, y: cy + 4, 'text-anchor': 'middle' }, hook.name),
        el('title'),
      );
      svg.append(g);
      S.hookEls[hook.name] = { el: g, pos: [cx, cy] };
      continue;
    }
    const n = hook.stages.length;
    const x1 = lay.x + lay.dx * (n - 1), y1 = lay.y + lay.dy * (n - 1);
    const left = Math.min(lay.x, x1) - chipW / 2 - 10, right = Math.max(lay.x, x1) + chipW / 2 + 10;
    const top = Math.min(lay.y, y1) - chipH / 2 - 12, bottom = Math.max(lay.y, y1) + chipH / 2 + 12;
    svg.append(el('rect', { class: 'hookbox', x: left, y: top, width: right - left, height: bottom - top, rx: 10 }));
    if (lay.dx) {
      svg.append(el('text', { class: 'hookname', x: (left + right) / 2, y: bottom + 17, 'text-anchor': 'middle' }, hook.name));
    } else if (hook.name === 'INPUT') {
      svg.append(el('text', { class: 'hookname', x: left - 10, y: (top + bottom) / 2 + 4, 'text-anchor': 'end' }, hook.name));
    } else {
      svg.append(el('text', { class: 'hookname', x: right + 10, y: (top + bottom) / 2 + 4 }, hook.name));
    }
    hook.stages.forEach((stage, i) => {
      const cx = lay.x + lay.dx * i, cy = lay.y + lay.dy * i;
      const g = el('g', { class: 'chip' });
      g.append(
        el('rect', { x: cx - chipW / 2, y: cy - chipH / 2, width: chipW, height: chipH, rx: chipH / 2 }),
        el('text', { x: cx, y: cy + 4, 'text-anchor': 'middle' }, stage.name),
        el('title'),
      );
      svg.append(g);
      S.chips[`${hook.name}/${stage.name}`] = { el: g, pos: [cx, cy] };
    });
  }

  // Network ends and routing decisions
  for (const name of ['in', 'out']) {
    const c = el('circle', { class: 'node', cx: nodes[name][0], cy: nodes[name][1], r: 8 });
    svg.append(c);
    S.nodeEls[name] = c;
  }
  for (const name of ['route1', 'route2']) {
    const [x, y] = nodes[name];
    const [lx, ly, anchor, label] = G.routeLabels[name];
    const d = el('path', { class: 'diamond', d: `M${x} ${y - 11} L${x + 11} ${y} L${x} ${y + 11} L${x - 11} ${y} Z` });
    svg.append(d, el('text', { class: 'label', x: x + lx, y: y + ly, 'text-anchor': anchor }, label));
    S.nodeEls[name] = d;
  }
  const merge = el('circle', { class: 'diamond', cx: nodes.merge[0], cy: nodes.merge[1], r: 5 });
  svg.append(merge);
  S.nodeEls.merge = merge;

  // Marker of the place where the selected packet stopped
  const stop = el('g', { id: 'stopmark', visibility: 'hidden' });
  stop.append(el('circle', { r: 8 }), el('path', { d: 'M-3 -3 L3 3 M3 -3 L-3 3' }));
  svg.append(stop);
}

// waypoints turns a journey into the points its trail goes through. Every point
// may light up a chip, a node, an interface, or a process when the trail reaches it.
function waypoints(j) {
  const pts = [];
  const push = (xy, target, cls) => pts.push({ x: xy[0], y: xy[1], target, cls });
  const node = (name) => push(G.nodes[name], S.nodeEls[name], 'lit');
  let prevHook = null;
  let prevHop = null;
  let boxPoint = null;   // hooks-only view: the point of the current hook's box
  const box = (hop) => {
    const b = S.hookEls[hop.hook];
    if (boxPoint || !b) return;
    push(b.pos, b.el, 'lit');
    boxPoint = pts[pts.length - 1];
    boxPoint.mark = [b.pos[0] + G.hookBox.w / 2 - 3, b.pos[1] - G.hookBox.h / 2 + 3];
    b.el.querySelector('title').textContent = `${hop.src} to ${hop.dst}`;
  };

  j.hops.forEach((hop, i) => {
    const lay = G.hooks[hop.hook];
    if (!lay) return;
    if (hop.hook !== prevHook) {
      // A partial journey starts in the middle of a hook: how the packet got
      // there is unknown, so the trail starts at the first stage that saw it.
      const unknownStart = prevHook === null && j.partial;
      if (prevHook === 'POSTROUTING' && hop.hook === 'PREROUTING') {
        // Loopback: the packet that left comes back in.
        const out = S.nics.out[prevHop.out], back = S.nics.in[hop.in];
        G.loop.forEach((p, k) => {
          if (k === 0) push(p, out && out.el, 'lit');
          else if (k === G.loop.length - 1) push(p, back && back.el, 'lit');
          else push(p);
        });
      } else if (hop.hook === 'PREROUTING' && prevHook === null && !unknownStart) {
        const nic = S.nics.in[hop.in];
        if (nic) nic.wire.forEach((p, k) => (k === 0 ? push(p, nic.el, 'lit') : push(p)));
      } else if (hop.hook === 'OUTPUT' && prevHook === null && !unknownStart) {
        const proc = j.from && S.procs[j.from.pid];
        if (proc) {
          push([proc.cx, proc.cy], proc.el, 'lit');
          push([proc.cx, G.sock.mid]);
          push([G.nodes.procOut[0], G.sock.mid]);
        }
        node('procOut');
      }
      if (!unknownStart) node(lay.entry);
      prevHook = hop.hook;
      boxPoint = null;
    }
    prevHop = hop;
    if (hooksOnly()) {
      box(hop);
      // A hook whose stage rewrote the packet (NAT) is marked like that stage.
      if (hop.rewrote && boxPoint && !boxPoint.cls.includes('rewrote')) boxPoint.cls += ' rewrote';
      if (hop.exit) node(lay.exit);
      else if (i === j.hops.length - 1 && j.verdict === 'stopped' && boxPoint) boxPoint.cls += ' stopped';
      return;
    }
    if (hop.exit) {
      node(lay.exit);
      return;
    }
    const chip = S.chips[`${hop.hook}/${hop.stage}`];
    if (!chip) return;
    const last = i === j.hops.length - 1;
    let cls = 'lit';
    if (hop.rewrote) cls += ' rewrote';
    if (last && j.verdict === 'stopped') cls += ' stopped';
    push(chip.pos, chip.el, cls);
    pts[pts.length - 1].chip = true;
    chip.el.querySelector('title').textContent = `${hop.src} to ${hop.dst}`;
  });

  if (j.verdict === 'sent' && prevHop) {
    const nic = S.nics.out[prevHop.out];
    if (nic) {
      const wire = [...nic.wire].reverse();
      wire.forEach((p, k) => (k === wire.length - 1 ? push(p, nic.el, 'lit') : push(p)));
    }
  }
  if (j.verdict === 'delivered') {
    const proc = j.to && S.procs[j.to.pid];
    if (proc) {
      push([G.nodes.procIn[0], G.sock.mid]);
      push([proc.cx, G.sock.mid]);
      push([proc.cx, proc.cy], proc.el, 'lit');
    }
  }
  if (j.verdict === 'stopped' && pts.length) {
    const last = pts[pts.length - 1];
    last.stop = true;
    if (j.stoppedStage === 'routing') last.cls = 'stopped';
  }
  return pts;
}

function resetDiagram() {
  S.timers.forEach(clearTimeout);
  S.timers = [];
  if (S.trailAnim) { S.trailAnim.cancel(); S.trailAnim = null; }
  document.querySelectorAll('#diagram .lit, #diagram .stopped').forEach((e) => e.classList.remove('lit', 'rewrote', 'stopped'));
  $('#trail').setAttribute('d', '');
  $('#stopmark').setAttribute('visibility', 'hidden');
}

// extraProcs lists the processes at the ends of a journey that have no box in
// the diagram because they listen on nothing (e.g. a client).
function extraProcs(j) {
  if (!j) return [];
  const out = [];
  for (const o of [j.from, j.to]) {
    if (!o || store.host.procs.some((p) => p.pid === o.pid) || out.some((p) => p.pid === o.pid)) continue;
    const proc = { pid: o.pid, name: o.name, sockets: [{ proto: o.proto, port: o.port }], extra: true };
    if (procShown(proc)) out.push(proc);
  }
  return out;
}

// show draws the path of a packet and returns how long the animation takes.
function show(j, animate) {
  const extras = extraProcs(j);
  if (JSON.stringify(extras) !== JSON.stringify(S.extras)) {
    S.extras = extras;
    buildDiagram();
  }
  resetDiagram();
  if (!j) return 0;

  const pts = waypoints(j);
  if (!pts.length) return 0;
  let d = '', total = 0;
  const at = [];
  pts.forEach((p, i) => {
    if (i) total += Math.hypot(p.x - pts[i - 1].x, p.y - pts[i - 1].y);
    at.push(total);
    d += `${i ? 'L' : 'M'}${p.x} ${p.y} `;
  });
  const trail = $('#trail');
  trail.setAttribute('d', d);

  const duration = animate && !reducedMotion() && total > 0 ? Math.min(1100, Math.max(350, total * 0.7)) / playback.speed : 0;
  const reach = (p) => {
    if (p.target && p.cls) p.target.classList.add(...p.cls.split(' '));
    if (p.stop) {
      const mark = $('#stopmark');
      // On a chip, the mark sits at the end the packet did not get past.
      const [mx, my] = p.mark || (p.chip ? [p.x + G.chip.w / 2 + 2, p.y - G.chip.h / 2 + 2] : [p.x + 18, p.y - 18]);
      mark.setAttribute('transform', `translate(${mx} ${my})`);
      mark.setAttribute('visibility', 'visible');
    }
  };
  if (!duration) {
    trail.style.strokeDasharray = 'none';
    pts.forEach(reach);
    return 0;
  }
  trail.style.strokeDasharray = `${total} ${total}`;
  S.trailAnim = trail.animate(
    [{ strokeDashoffset: total }, { strokeDashoffset: 0 }],
    { duration, easing: 'linear', fill: 'forwards' },
  );
  pts.forEach((p, i) => S.timers.push(setTimeout(() => reach(p), (at[i] / total) * duration)));
  return duration;
}

// ---- Text ------------------------------------------------------------------

function outcomeText(j) {
  if (j.verdict === 'delivered') return j.to ? `Delivered to ${j.to.name}` : 'Delivered locally';
  if (j.verdict === 'sent') {
    const last = j.hops[j.hops.length - 1];
    const verb = j.path.includes('FORWARD') ? 'Forwarded' : 'Sent';
    return last.out ? `${verb} via ${last.pout || last.out}` : verb;
  }
  if (j.stoppedStage === 'routing') return `Lost after ${j.stoppedHook}`;
  return `Stopped in ${stageLabel(j.stoppedHook, j.stoppedStage)}`;
}

function verdictSentence(j) {
  if (j.verdict === 'delivered') {
    if (j.to) {
      return [`Delivered to ${j.to.name} (pid ${j.to.pid}).`, `The packet passed INPUT and reached the ${j.to.proto.toUpperCase()} socket on port ${j.to.port}.`];
    }
    return ['Delivered locally.', 'The packet passed INPUT and went up to the transport layer of this namespace.'];
  }
  if (j.verdict === 'sent') {
    return [`${outcomeText(j)}.`, 'The packet passed POSTROUTING and was handed to the network device.'];
  }
  if (j.stoppedStage === 'routing') {
    if (j.stoppedHook === 'PREROUTING') {
      return ['Lost after PREROUTING.', 'The packet reached neither INPUT nor FORWARD. The routing decision discarded it: no route, forwarding disabled, or a reverse path check.'];
    }
    return [`Lost after ${j.stoppedHook}.`, 'The packet left this hook and never reached POSTROUTING.'];
  }
  if (hooksOnly()) {
    return [`Stopped in ${j.stoppedHook}.`, 'The packet entered this hook and was not seen after it. A rule in it dropped, rejected, or queued the packet.'];
  }
  return [`Stopped in ${j.stoppedStage}/${j.stoppedHook}.`, 'The packet entered this stage and was not seen after it. A rule at this point dropped, rejected, or queued it.'];
}

function verdict(j) {
  if (!j) return { text: 'Waiting for a matching packet.' };
  const [head, rest] = verdictSentence(j);
  let text = rest;
  if (j.from) text += ` It was sent by ${j.from.name} (pid ${j.from.pid}).`;
  if (j.hops.some((h) => h.pin || h.pout)) text += ' The packet was crossing a bridge: br_netfilter ran the IP hooks for it.';
  if (j.partial) {
    const h = j.hops[0];
    const where = h.exit ? `the end of ${h.hook}` : stageLabel(h.hook, h.stage);
    text += ` The packet started to match the filter at ${where}, so the earlier stages are not shown.`;
  }
  if (j.unreliable) text += ' Some probe events were lost around this packet, so the path may be incomplete.';
  return { head, text, kind: j.verdict === 'stopped' ? 'stopped' : 'done' };
}

const DETAIL_COLUMNS = ['In', 'Out', 'Source', 'Destination', 'TTL', 'Elapsed'];

function hopCells(hop, prev, out) {
  return [
    [hop.pin || hop.in || '', 'mono'], [out || '', 'mono'],
    [hop.src, prev && prev.src !== hop.src ? 'mono changed' : 'mono'],
    [hop.dst, prev && prev.dst !== hop.dst ? 'mono changed' : 'mono'],
    [String(hop.ttl || ''), 'mono'], [micros(hop.us), 'mono'],
  ];
}

// detail lists what every stage (or every hook) saw of the packet.
function detail(j) {
  const byHook = hooksOnly();
  const d = {
    title: 'Path of the selected packet',
    columns: [byHook ? 'Hook' : 'Stage', ...DETAIL_COLUMNS],
    empty: byHook ? 'Select a packet to see what every hook saw.' : 'Select a packet to see what every stage saw.',
    summary: '', rows: [],
  };
  if (!j) return d;
  d.summary = [j.proto.toUpperCase(), j.info, j.detail, `${j.len} bytes`].filter(Boolean).join(', ');
  const stopped = j.verdict === 'stopped';
  if (!byHook) {
    let prev = null;
    j.hops.forEach((hop, i) => {
      const row = { cells: [[hop.exit ? `left ${hop.hook}` : `${hop.stage}/${hop.hook}`, 'mono wrap'], ...hopCells(hop, prev, hop.pout || hop.out)], cls: '', notes: [] };
      if (hop.exit) row.cls += ' exit';
      if (hop.rewrote) { row.cls += ' rewrote'; row.notes.push(`This stage rewrote the ${hop.rewrote}.`); }
      if (i === j.hops.length - 1 && stopped) {
        row.cls += ' stopped';
        row.notes.push(j.stoppedStage === 'routing' ? 'The packet was not seen after this point.' : 'The packet did not leave this stage.');
      }
      d.rows.push(row);
      prev = hop;
    });
    return d;
  }
  // One row per hook the packet crossed.
  const groups = [];
  j.hops.forEach((hop, i) => {
    let g = groups[groups.length - 1];
    if (!g || g.hook !== hop.hook) {
      g = { hook: hop.hook, first: hop, hops: [] };
      groups.push(g);
    }
    g.hops.push(hop);
    g.last = i === j.hops.length - 1;
  });
  let prev = null;
  for (const g of groups) {
    const out = [...g.hops].reverse().find((h) => h.out);
    const row = { cells: [[g.hook, 'mono wrap'], ...hopCells(g.first, prev, out ? out.pout || out.out : '')], cls: '', notes: [] };
    const rewrites = g.hops.filter((h) => h.rewrote).map((h) => h.rewrote);
    if (rewrites.length) { row.cls += ' rewrote'; row.notes.push(`This hook rewrote the ${rewrites.join(', ')}.`); }
    if (g.last && stopped) {
      row.cls += ' stopped';
      row.notes.push(j.stoppedStage === 'routing' ? 'The packet was not seen after this hook.' : 'The packet did not leave this hook.');
    }
    d.rows.push(row);
    prev = g.first;
  }
  return d;
}

// items turns a journey into what this view lists: the packet as the IP hooks
// saw it, or nothing when they did not see it.
function items(j) {
  const s = j.l3;
  if (!s) return [];
  return [{
    id: `${j.id}`, j, time: j.time, proto: j.proto, src: j.src, dst: j.dst, len: j.len, info: j.info, detail: j.detail, unreliable: j.unreliable,
    hops: s.hops.map((i) => j.hops[i]), hopIndexes: s.hops,
    verdict: s.verdict, stoppedHook: s.stoppedHook, stoppedStage: s.stoppedStage, path: s.path, from: s.from, to: s.to, partial: s.partial,
  }];
}

export default {
  id: 'l3',
  label: 'IP · L3',
  title: 'Packets',
  noun: 'packet',
  layer: 'l3',
  about: 'The netfilter hooks of the IP layer, with the raw, mangle, nat, and filter stages inside them.',
  subs: [{ id: 'stages', label: 'Stages' }, { id: 'hooks', label: 'Hooks only' }],
  // The stages inside the hooks are a detail that can be switched off.
  level: { label: 'Stages', on: 'stages', off: 'hooks', about: 'The raw, mangle, nat, and filter stages inside the hooks, in the diagram and in the table' },
  panels: [{ id: 'packets', label: 'Packets' }, { id: 'details', label: 'Path' }],
  aria: 'Netfilter hooks and the path of the selected packet',
  init(context) { ctx = context; },
  items,
  columns: ['Time', 'Proto', 'Source', 'Destination', 'Details', 'Outcome'],
  cells: (j) => [[clock(j.time), 'mono'], [j.proto.toUpperCase()], [j.src, 'mono'], [j.dst, 'mono'], [j.info, 'mono'], [outcomeText(j), j.verdict === 'stopped' ? 'outcome-stopped' : 'outcome-done']],
  // resize tells whether the diagram needs another arrangement for the box it gets.
  resize(width, height) {
    diagramWidth = width;
    diagramHeight = height;
    return store.hooks.length > 0 && pickLayout(hooksOnly(), ...layoutCounts()).key !== G.key;
  },
  build: buildDiagram,
  show,
  verdict,
  detail,
  blocks,
  packetHops: (j) => j.hopIndexes,
};
