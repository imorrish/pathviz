// The packet view: the headers and the bytes of one packet, as every probe saw them.

import { $, api } from './core.js';

const packetView = { item: null, j: null, entries: [], at: 0, cells: [], byHook: false, note: '' };

function base64Bytes(text) {
  const raw = atob(text || '');
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function packetMessage(text) {
  $('#pd-hops').replaceChildren();
  $('#pd-note').textContent = text;
  $('#pd-body').hidden = true;
}

// place names the hook of a hop: the group it belongs to in the switcher, and
// the label of that group.
function place(hop) {
  if (hop.layer === 'l1') return [`l1|${hop.hook}|${hop.in || hop.out}`, `${hop.hook.toLowerCase()} · ${hop.in || hop.out}`];
  if (hop.layer === 'l2') return [`l2|${hop.hook}|${hop.bridge}|${hop.out || ''}`, `${hop.hook} · ${hop.bridge}`];
  return [`l3|${hop.hook}|${hop.pout || ''}`, hop.hook];
}

// openPacket shows the packet of a listed item. indexes are the hops of its
// journey that the current view shows, and byHook asks for one entry per hook
// (plus the probes that saw the packet changed).
export async function openPacket(item, indexes, byHook) {
  const j = item.j;
  packetView.item = item;
  packetView.j = j;
  packetView.byHook = byHook;
  packetView.entries = [];
  $('#pd-title').textContent = j.proto ? `${j.proto.toUpperCase()} packet ${j.src} → ${j.dst}` : `${j.frame.type} frame ${j.frame.src} → ${j.frame.dst}`;
  packetMessage('Loading the packet…');
  const dialog = $('#packet-dialog');
  if (!dialog.open) dialog.showModal();
  let data;
  try {
    const res = await api(`api/packet?id=${j.id}`);
    if (res.status === 404) throw new Error('PathViz does not keep this packet anymore, so its bytes cannot be shown.');
    if (!res.ok) throw new Error(`Cannot load the packet: ${(await res.text()).trim()}`);
    data = await res.json();
  } catch (err) {
    if (packetView.item === item) packetMessage(err.message);
    return;
  }
  // Another packet may have been opened while this one was loading.
  if (packetView.item !== item) return;
  const wanted = new Set(indexes);
  const hops = data.hops.filter((h) => wanted.has(h.index)).map((h) => {
    const [group, label] = place(j.hops[h.index]);
    return { ...h, group, label, bytes: base64Bytes(h.bytes) };
  });
  hops.forEach((h, i) => {
    // A probe of another layer may see the packet with or without its Ethernet
    // header: that is not a change of the packet.
    const before = i > 0 && hops[i - 1].layers[0].kind === h.layers[0].kind ? hops[i - 1].bytes : h.bytes;
    h.changed = before.length !== h.bytes.length || before.some((v, k) => v !== h.bytes[k]);
  });
  packetView.entries = hops.filter((h, i) => !byHook || i === 0 || h.group !== hops[i - 1].group || h.changed);
  if (!packetView.entries.length) { packetMessage('No bytes of this packet were captured.'); return; }
  $('#pd-body').hidden = false;
  showPacketHop(0);
}

// seenAt tells where a probe saw the packet: "entered raw/PREROUTING".
function seenAt(h) {
  if (h.exit) return `left ${h.label}`;
  return h.layer === 'l3' ? `entered ${h.stage}/${h.hook}` : `entered ${h.label}`;
}
const hopName = (h) => (h.exit ? `the end of ${h.label}` : h.layer === 'l3' ? `${h.stage}/${h.hook}` : `the start of ${h.label}`);

// packetStart tells where a packet came from before its first probe, and
// whether that is known.
function packetStart() {
  const j = packetView.j;
  const first = packetView.entries[0] && j.hops[packetView.entries[0].index];
  if (!first) return ['The packet was first seen here.', false];
  if (first.layer === 'l1' && first.hook === 'INGRESS') return [`The frame arrived on the ${first.in} device.`, true];
  if (first.layer === 'l2' && first.hook === 'PREROUTING') return [`The frame arrived on the port ${first.in} of ${first.bridge}.`, true];
  if (first.layer === 'l3' && j.l3 && !j.l3.partial && first.stage === 'raw') {
    if (first.hook === 'PREROUTING') return [first.in ? `The packet arrived on the ${first.in} interface.` : 'The packet arrived on a network interface.', true];
    if (first.hook === 'OUTPUT') return [j.l3.from ? `The packet was sent by ${j.l3.from.name} (pid ${j.l3.from.pid}).` : 'The packet was sent by a local process.', true];
  }
  if (first.hook === 'OUTPUT' || first.hook === 'EGRESS') return ['The packet came from the network stack of this namespace.', true];
  return ['The packet was first seen here, so the earlier part of its path is not shown.', false];
}

// fieldKeys names the fields of a hop so that the same field of another hop
// gets the same key: the layer, the field, and its number among its namesakes.
function fieldKeys(hop) {
  const keys = new Map(), seen = new Map();
  hop.layers.forEach((layer, li) => {
    for (const f of layer.fields) {
      const base = `${li}|${layer.name}|${f.name}`;
      const n = seen.get(base) || 0;
      seen.set(base, n + 1);
      keys.set(f, `${base}|${n}`);
    }
  });
  return keys;
}

// linkPacketHooks finds the hooks of the switcher that wrapped to a new row,
// and sizes the line that links each of them to the last hook of the row above.
function linkPacketHooks() {
  const bar = $('#pd-hops');
  const groups = [...bar.querySelectorAll('.pd-hook')];
  // A hook that starts a row is wider (it has the turn of the line before its
  // box), so the rows are found in order, each with the earlier ones marked.
  for (const g of groups) g.classList.remove('wrap-in', 'wrap-out');
  for (const run of bar.querySelectorAll('.pd-run')) run.remove();
  let wrapped = false;
  groups.forEach((g, i) => {
    const prev = groups[i - 1];
    if (!prev || g.offsetTop <= prev.offsetTop) return;
    wrapped = true;
    g.classList.add('wrap-in');
    prev.classList.add('wrap-out');
    // The part of the line between the rows: from the turn after the previous
    // hook back to the turn before this one.
    const run = document.createElement('span');
    run.className = 'pd-run';
    run.style.width = `${prev.offsetLeft + prev.offsetWidth - (g.offsetLeft + 26)}px`;
    g.append(run);
  });
  bar.classList.toggle('wrapped', wrapped);
}
new ResizeObserver(linkPacketHooks).observe($('#pd-hops'));

function showPacketHop(at) {
  const entries = packetView.entries;
  packetView.at = at;
  const hop = entries[at], prev = at > 0 ? entries[at - 1] : null;
  // A probe of another layer shows the packet with or without its Ethernet
  // header, so the two cannot be compared field by field.
  const cmp = prev && prev.layers[0].kind === hop.layers[0].kind ? prev : null;

  // The switcher draws the hooks like the diagram does, in the order the
  // packet crossed them, on one line: a node where the line starts, then for
  // every hook a box with the hook's name below and a chip for every stage
  // that saw the packet, and after the box a node for the probe at the end of
  // the hook. The line ends where the packet was seen last.
  const bar = $('#pd-hops');
  bar.replaceChildren();
  const part = (cls) => { const e = document.createElement('span'); e.className = cls; return e; };
  let group = null, box = null;
  entries.forEach((h, i) => {
    const first = !group || group.dataset.hook !== h.group || i === 0;
    if (first) {
      group = part('pd-hook');
      group.dataset.hook = h.group;
      box = part('pd-box');
      const name = part('lbl');
      name.textContent = h.label;
      if (i === 0) {
        // The node where the line starts tells where the packet came from:
        // pointing at it shows that in place of the note about the shown probe.
        const [text, known] = packetStart();
        const start = part('pd-in'), node = part(known ? 'node' : 'node unknown');
        node.addEventListener('mouseenter', () => { $('#pd-note').textContent = text; });
        node.addEventListener('mouseleave', () => { $('#pd-note').textContent = packetView.note; });
        node.setAttribute('role', 'img');
        node.setAttribute('aria-label', text);
        start.append(node);
        group.append(start);
      }
      group.append(box, name);
      bar.append(group);
    }
    const b = document.createElement('button');
    b.type = 'button';
    let to = box;
    // The end of a hook is not a stage: it is a node after the box, like the
    // nodes between the hooks of the diagram.
    if (h.exit) {
      b.className = 'exit';
      b.setAttribute('aria-label', `The end of ${h.label}`);
      to = part('pd-out');
      group.append(to);
    } else {
      b.textContent = h.layer !== 'l3' || (packetView.byHook && first) ? 'entry' : h.stage;
    }
    b.title = `The packet as it ${seenAt(h)}`;
    if (h.changed) { b.classList.add('changed'); b.title += ' (it differs from what the previous probe saw)'; }
    if (i === at) b.setAttribute('aria-current', 'true');
    b.addEventListener('click', () => { showPacketHop(i); $('#pd-hops [aria-current]').focus(); });
    to.append(b);
  });
  const groups = [...bar.children];
  groups.forEach((g, i) => {
    const last = i === groups.length - 1;
    let out = g.querySelector('.pd-out');
    // A hook without a probe at its end still has the line to the next hook.
    if (!out && !last) { out = part('pd-out'); g.append(out); }
    if (out) g.querySelector('.pd-box').classList.add('leaves');
    if (out && last) out.classList.add('end');
  });

  linkPacketHooks();

  // The fields that the previous probe saw with another value.
  const before = new Map();
  if (cmp) for (const [f, key] of fieldKeys(cmp)) before.set(key, f.value);
  const keys = fieldKeys(hop);
  let changedFields = 0;

  const fields = $('#pd-fields'), hex = $('#pd-hex');
  const scroll = [fields.scrollTop, hex.scrollTop];
  fields.replaceChildren();
  for (const layer of hop.layers) {
    const section = document.createElement('section');
    section.className = `pd-layer k-${layer.kind}`;
    const head = document.createElement('h3');
    head.dataset.off = layer.off;
    head.dataset.len = layer.len;
    head.textContent = layer.name;
    if (layer.summary) {
      const s = document.createElement('span');
      s.className = 'muted mono';
      s.textContent = layer.summary;
      head.append(s);
    }
    section.append(head);
    for (const f of layer.fields) {
      const row = document.createElement('div');
      row.className = 'pd-field';
      row.tabIndex = 0;
      row.dataset.off = f.off;
      row.dataset.len = f.len;
      const name = document.createElement('span');
      name.className = 'n';
      name.textContent = f.name;
      const value = document.createElement('span');
      value.className = 'v mono';
      value.textContent = f.value;
      const was = before.get(keys.get(f));
      if (was !== undefined && was !== f.value) {
        changedFields++;
        row.classList.add('changed');
        const old = document.createElement('span');
        old.className = 'was';
        old.textContent = `was ${was || 'empty'}`;
        value.append(old);
      }
      row.append(name, value);
      section.append(row);
    }
    fields.append(section);
  }

  // The bytes: 16 in a row, colored by their layer, with their text on the right.
  const kinds = [];
  for (const layer of hop.layers) for (let i = layer.off; i < layer.off + layer.len; i++) kinds[i] = layer.kind;
  hex.replaceChildren();
  packetView.cells = [];
  const bytes = hop.bytes;
  for (let start = 0; start < bytes.length; start += 16) {
    const line = document.createElement('div');
    const off = document.createElement('span');
    off.className = 'off';
    off.textContent = start.toString(16).padStart(4, '0');
    const hexPart = document.createElement('span');
    hexPart.className = 'bytes';
    const textPart = document.createElement('span');
    textPart.className = 'text';
    for (let i = start; i < Math.min(start + 16, bytes.length); i++) {
      const v = bytes[i];
      const cls = `k-${kinds[i] || 'data'}${cmp && cmp.bytes[i] !== v ? ' changed' : ''}`;
      const b = document.createElement('span');
      b.className = `b ${cls}${i % 16 === 8 ? ' mid' : ''}`;
      b.dataset.i = i;
      b.textContent = v.toString(16).padStart(2, '0');
      const c = document.createElement('span');
      c.className = `c ${cls}`;
      c.dataset.i = i;
      c.textContent = v >= 0x20 && v <= 0x7e ? String.fromCharCode(v) : '·';
      hexPart.append(b);
      textPart.append(c);
      packetView.cells.push([b, c]);
    }
    line.append(off, hexPart, textPart);
    hex.append(line);
  }
  fields.scrollTop = scroll[0];
  hex.scrollTop = scroll[1];

  const notes = [`The packet as it ${seenAt(hop)}.`];
  notes.push(hop.total > bytes.length
    ? `The first ${bytes.length} of its ${hop.total} bytes were captured.`
    : `${bytes.length} bytes, from the ${hop.layers[0] && hop.layers[0].kind === 'link' ? 'Ethernet' : 'IP'} header on.`);
  if (prev && hop.changed) {
    notes.push(`The highlighted ${changedFields === 1 ? 'field differs' : 'fields differ'} from what the probe at ${hopName(prev)} saw.`);
  } else if (prev) {
    notes.push(`Nothing changed since the probe at ${hopName(prev)}.`);
  }
  packetView.note = notes.join(' ');
  $('#pd-note').textContent = packetView.note;
}

// Pointing at a field marks its bytes, and pointing at a byte marks its field.
function markPacketRange(off, len, rows) {
  for (const el of document.querySelectorAll('#packet-dialog .on')) el.classList.remove('on');
  for (let i = off; i < off + len; i++) for (const el of packetView.cells[i] || []) el.classList.add('on');
  for (const row of rows) row.classList.add('on');
}

function markPacketField(e) {
  const row = e.target.closest('[data-off]');
  if (!row) return;
  const off = Number(row.dataset.off), len = Number(row.dataset.len);
  markPacketRange(off, len, [row]);
  const cell = packetView.cells[off];
  if (cell) cell[0].scrollIntoView({ block: 'nearest', inline: 'nearest' });
}

function markPacketByte(e) {
  if (!e.target.dataset || e.target.dataset.i === undefined) return;
  const i = Number(e.target.dataset.i);
  // The smallest field that holds the byte, and every field of the same bytes.
  let best = null;
  const rows = [...document.querySelectorAll('#pd-fields .pd-field')].filter((row) => {
    const off = Number(row.dataset.off), len = Number(row.dataset.len);
    if (i < off || i >= off + len) return false;
    if (!best || len < best.len) best = { off, len };
    return true;
  });
  if (!best) { markPacketRange(i, 1, []); return; }
  const same = rows.filter((row) => Number(row.dataset.off) === best.off && Number(row.dataset.len) === best.len);
  markPacketRange(best.off, best.len, same);
  same[0].scrollIntoView({ block: 'nearest' });
}

$('#pd-fields').addEventListener('mouseover', markPacketField);
$('#pd-fields').addEventListener('focusin', markPacketField);
$('#pd-hex').addEventListener('mouseover', markPacketByte);
for (const id of ['#pd-fields', '#pd-hex']) $(id).addEventListener('mouseleave', () => markPacketRange(0, 0, []));

// The left and right arrows step through the probes.
$('#packet-dialog').addEventListener('keydown', (e) => {
  const step = { ArrowLeft: -1, ArrowRight: 1 }[e.key];
  const next = packetView.at + (step || 0);
  if (!step || next < 0 || next >= packetView.entries.length) return;
  e.preventDefault();
  showPacketHop(next);
  $('#pd-hops [aria-current]').focus();
});
$('#packet-dialog').addEventListener('close', () => { packetView.item = null; });