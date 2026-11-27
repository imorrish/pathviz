// The device hooks (L1): the ingress and the egress hook of every network
// device. A frame crosses the ingress hook right after the device received it,
// and the egress hook right before the device sends it.

import { el, setWidth, store, listParam, clock, micros, stackName, peerName, peerKind, peerCard, drawPill, tracer, pickable, ifaceByName, CARD_W } from './core.js';

let ctx = null;
let G = null;
let T = null;

const only = listParam('ifaces');
const MAX_DEVICES = 12;
const GAP = 22, HOOK_DX = 42;
const Y = { cardTop: 6, cardBottom: 82, devTop: 118, hook: 148, devBottom: 208, stack: 246, stackH: 26 };

const hookName = (c) => (c.hook === 'INGRESS' ? 'ingress' : 'egress');
const dropped = (c) => c.outcome !== 'passed';

// above tells where a frame goes after the ingress hook of a device.
function above(dev) {
  if (dev && dev.master) return `the bridge ${dev.master}`;
  return `the network stack of ${stackName()}`;
}

// ---- Diagram ---------------------------------------------------------------

// shownDevices picks the devices to draw: the ones the URL asks for, else all
// of them, with the ones of the selected frame first when they are too many.
const listed = (d) => !only || only.includes(d.name);
const wanted = (d) => listed(d) && ctx.blockOn('devices', d.name);

function shownDevices(item) {
  let devs = store.host.ifaces.filter(wanted);
  if (devs.length > MAX_DEVICES) {
    const used = new Set(item ? item.crossings.map((c) => c.dev) : []);
    devs = [...devs.filter((d) => used.has(d.name)), ...devs.filter((d) => !used.has(d.name))].slice(0, MAX_DEVICES);
  }
  return devs;
}

function build(item) {
  const svg = ctx.svg;
  const devs = shownDevices(item);
  const n = Math.max(devs.length, 1);
  const inner = n * CARD_W + (n - 1) * GAP;
  const W = Math.max(inner + 80, 620);
  const left = (W - inner) / 2;
  svg.setAttribute('viewBox', `0 0 ${W} ${Y.stack + Y.stackH + 24}`);
  setWidth(svg, W);
  G = { devs: {}, key: devs.map((d) => d.name).join(' ') };

  const trails = el('g'), marks = el('g');
  const xs = devs.map((_, i) => left + i * (CARD_W + GAP) + CARD_W / 2);
  devs.forEach((dev, i) => {
    const x = xs[i];
    svg.append(
      el('path', { class: 'track', d: `M${x - HOOK_DX} ${Y.cardBottom} V${Y.stack}` }),
      el('path', { class: `track ${store.egress ? '' : 'off'}`, d: `M${x + HOOK_DX} ${Y.cardBottom} V${Y.stack}` }),
      el('path', { class: 'arrow', d: 'M-6 -5 L5 0 L-6 5 Z', transform: `translate(${x - HOOK_DX} ${Y.cardBottom + 18}) rotate(90)` }),
      el('path', { class: `arrow ${store.egress ? '' : 'off'}`, d: 'M-6 -5 L5 0 L-6 5 Z', transform: `translate(${x + HOOK_DX} ${Y.cardBottom + 20}) rotate(-90)` }),
    );
  });
  svg.append(trails);
  devs.forEach((dev, i) => {
    const x = xs[i];
    const card = peerCard(svg, x, Y.cardTop, dev);
    if (dev.peer && dev.peer.mac && !dev.peer.bridge) pickable(card, ctx, { macs: [dev.peer.mac] }, `the frames from and to ${dev.peer.mac} (${peerName(dev)})`);
    const second = dev.master ? `port of ${dev.master}` : (dev.addrs[0] || (dev.up ? 'no IP address' : 'down'));
    const box = el('g', { class: `devbox ${dev.up ? '' : 'down'}` });
    box.append(
      el('rect', { x: x - CARD_W / 2, y: Y.devTop, width: CARD_W, height: Y.devBottom - Y.devTop, rx: 10 }),
      el('text', { class: 'bridgename', x, y: Y.devBottom - 22, 'text-anchor': 'middle' }, dev.name),
      el('text', { class: 'label', x, y: Y.devBottom - 8, 'text-anchor': 'middle' }, second),
    );
    pickable(box, ctx, { ifaces: [dev.name] }, `the frames that ${dev.name} receives or sends`);
    svg.append(box);
    const ingress = drawPill(svg, x - HOOK_DX, Y.hook, 'ingress');
    pickable(ingress, ctx, { ifaces: [`in:${dev.name}`] }, `the frames that ${dev.name} receives`);
    const egress = drawPill(svg, x + HOOK_DX, Y.hook, 'egress', store.egress ? '' : 'off');
    if (store.egress) pickable(egress, ctx, { ifaces: [`out:${dev.name}`] }, `the frames that ${dev.name} sends`);
    else egress.append(el('title', {}, 'This kernel has no egress hook for devices. It needs Linux 5.16 or later, built with CONFIG_NETFILTER_EGRESS.'));
    G.devs[dev.name] = { x, card, ingress, egress };
  });
  const hidden = store.host.ifaces.filter(wanted).length - devs.length;
  const stack = el('rect', { class: 'proc', x: left, y: Y.stack, width: inner, height: Y.stackH, rx: 6 });
  svg.append(stack, el('text', { class: 'proc-label', x: W / 2, y: Y.stack + 17, 'text-anchor': 'middle' }, `Bridges and the network stack of ${stackName()}`));
  if (!devs.length) svg.append(el('text', { class: 'label', x: W / 2, y: Y.hook, 'text-anchor': 'middle' }, 'All the devices are switched off (Show, Devices).'));
  if (hidden > 0) svg.append(el('text', { class: 'label', x: left + inner, y: Y.stack + Y.stackH + 18, 'text-anchor': 'end' }, `and ${hidden} more devices`));
  G.stack = stack;
  svg.append(marks);
  T = tracer(svg, trails, marks);
}

function show(item, animate) {
  // With many devices, the ones of the selected frame must be among the drawn.
  if (item && item.crossings.some((c) => !G.devs[c.dev]) && shownDevices(item).map((d) => d.name).join(' ') !== G.key) {
    ctx.svg.replaceChildren();
    build(item);
  }
  T.reset(animate);
  if (!item) return 0;
  let at = 0;
  for (const c of item.crossings) {
    const d = G.devs[c.dev];
    if (!d) continue;
    const ingress = c.hook === 'INGRESS';
    const x = ingress ? d.x - HOOK_DX : d.x + HOOK_DX;
    const pill = ingress ? d.ingress : d.egress;
    const ends = ingress ? [[x, Y.cardBottom], [x, Y.stack]] : [[x, Y.stack], [x, Y.cardBottom]];
    T.light(ingress ? d.card : G.stack, at);
    const first = T.trail([ends[0], [x, Y.hook]], '', at);
    if (dropped(c)) {
      T.light(pill, first.done, 'lit stopped');
      T.stop([x + 30, Y.hook - 14], first.done);
      at = first.done;
      continue;
    }
    T.light(pill, first.done);
    const second = T.trail([[x, Y.hook], ends[1]], '', first.done);
    T.light(ingress ? G.stack : d.card, second.done);
    at = second.done;
  }
  return at;
}

// ---- Text ------------------------------------------------------------------

function crossingText(c) {
  if (dropped(c)) return `Dropped in the ${hookName(c)} hook of ${c.dev}`;
  return c.hook === 'INGRESS' ? `Received on ${c.dev}` : `Sent through ${c.dev}`;
}

function outcome(item) {
  const bad = item.crossings.find(dropped);
  if (bad) return [crossingText(bad), 'stopped'];
  const parts = item.crossings.map(crossingText);
  return [parts.length > 2 ? `${parts[0]}, and ${parts.length - 1} more hooks` : parts.join(', then '), 'done'];
}

function verdict(item) {
  if (!item) return { text: 'Waiting for a frame that matches the filter.' };
  const [head, kind] = outcome(item);
  const sentences = item.crossings.map((c) => {
    const dev = ifaceByName(c.dev);
    const peer = dev && peerName(dev) ? ` (${peerName(dev)} is at its other end)` : '';
    if (dropped(c)) {
      return `The frame entered the ${hookName(c)} hook of ${c.dev} and did not leave it: a rule of the netdev family dropped it.`;
    }
    if (c.hook === 'INGRESS') {
      return `The frame arrived on ${c.dev}${peer}, passed its ingress hook, and went on to ${above(dev)}.`;
    }
    return `The frame passed the egress hook of ${c.dev}${peer} and was handed to the device.`;
  });
  let text = sentences.join(' ');
  if (!store.egress) text += ' This kernel has no egress hook, so the frames that leave are not shown here.';
  if (item.unreliable) text += ' Some probe events were lost around this frame, so a drop may be reported wrongly.';
  return { head: `${head}.`, text, kind: kind === 'stopped' ? 'stopped' : 'done' };
}

function cells(item) {
  const f = item.frame;
  const [text, kind] = outcome(item);
  const devs = [...new Set(item.crossings.map((c) => c.dev))];
  const hooks = [...new Set(item.crossings.map(hookName))];
  const details = !f ? item.j.info : f.type === 'ARP' ? f.info : [f.info, f.srcIp && `${f.srcIp} → ${f.dstIp}`].filter(Boolean).join(', ');
  return [
    [clock(item.time), 'mono'], [devs.join(', '), 'mono'], [hooks.join(', ')],
    [f ? f.src : '', 'mono'], [f ? f.dst : '', 'mono'], [f ? f.type : (item.j.proto || '').toUpperCase()],
    [details || '', 'details'], [text + (item.unreliable ? ' ?' : ''), `outcome-${kind}`],
  ];
}

// detail lists the device hooks the frame crossed.
function detail(item) {
  const d = { title: 'Path of the selected frame', columns: ['Device', 'Hook', 'Other end', 'Outcome', 'Elapsed'], empty: 'Select a frame to see which device hooks it crossed.', summary: '', rows: [] };
  if (!item) return d;
  const f = item.frame;
  d.summary = f ? [f.type, f.info].filter(Boolean).join(', ') : '';
  for (const c of item.crossings) {
    const dev = ifaceByName(c.dev);
    const hop = item.j.hops.find((h) => h.layer === 'l1' && h.hook === c.hook && (h.in === c.dev || h.out === c.dev));
    d.rows.push({
      cells: [[c.dev, 'mono', dev && dev.master ? `port of ${dev.master}` : ''], [hookName(c)], [dev ? peerName(dev) || peerKind(dev) : ''], [dropped(c) ? 'Dropped' : 'Passed'], [hop ? micros(hop.us) : '', 'mono']],
      cls: dropped(c) ? 'stopped' : '',
    });
  }
  return d;
}

function items(j) {
  if (!j.l1 || !j.l1.length) return [];
  return [{ id: `${j.id}`, j, time: j.time, unreliable: j.unreliable, crossings: j.l1, frame: j.frame }];
}

export default {
  id: 'l1',
  label: 'Device · L1',
  title: 'Frames',
  noun: 'frame',
  layer: 'l1',
  about: 'The ingress and egress hooks of the network devices: the first and the last point where a frame can be seen.',
  subs: [],
  panels: [{ id: 'packets', label: 'Frames' }, { id: 'details', label: 'Path' }],
  aria: 'The network devices, their hooks, and the way of the selected frame',
  init(context) { ctx = context; },
  items,
  columns: ['Time', 'Device', 'Hook', 'Source', 'Destination', 'Type', 'Details', 'Outcome'],
  cells,
  resize: () => false,
  build: () => build(null),
  show,
  verdict,
  detail,
  blocks: () => [{ id: 'devices', label: 'Devices', items: store.host.ifaces.filter(listed).map((d) => ({ key: d.name, label: d.name, note: peerName(d) || d.addrs[0] || '' })) }],
  packetHops: (item) => item.j.hops.map((h, i) => (h.layer === 'l1' ? i : -1)).filter((i) => i >= 0),
};
