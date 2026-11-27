// The page: the header, the tables, and the flow of the traced packets. What
// is drawn and listed comes from the view of the layer that is on (l3.js,
// l2.js, l1.js, all.js). A view turns a traced packet into the items it lists,
// draws its diagram, and puts the path of an item on it.

import {
  $, html, params, listParam, setParam, embed, store, emptyFilter, api, apiPath, post, getToken, keepToken,
  playback, SPEED_STEPS, spaceLabel, procKey, journeyMatches, sameFilter, filterHas, filterWith, filterWithout, describeFilter,
} from './core.js';
import l3 from './l3.js';
import l2 from './l2.js';
import l1 from './l1.js';
import all from './all.js';
import { openPacket } from './packet.js';
import { PRESETS } from './presets.js';

const VIEWS = [l3, l2, l1, all];
const MAX_ROWS = 300;
const ALL_LAYERS = ['l1', 'l2', 'l3'];

// ---- What the page shows -----------------------------------------------------

// The full view remembers the looks and the tables that were picked. An
// embedded view starts the way its URL says.
const SAVED_KEY = 'pathviz.ui';
const saved = (() => {
  if (!embed) {
    try { return JSON.parse(localStorage.getItem(SAVED_KEY)) || {}; } catch { /* no storage, or nothing sensible in it */ }
  }
  return {};
})();

// The tables to show can come from the URL: ?panels=, or ?tables= with the
// names of the first version of the page.
const urlPanels = (() => {
  const names = listParam('panels') || listParam('tables');
  return names ? names.map((n) => ({ stages: 'details', hops: 'details', copies: 'details', fdb: 'extra', frames: 'packets' }[n] || n)) : null;
})();

const state = {
  view: VIEWS.find((v) => v.id === params.get('mode')) || l3,
  // subs is the look of every layer that has several.
  subs: { l3: 'stages', l2: 'topology', all: 'hooks', ...saved.subs },
  // layers are the layers of the combined view.
  layers: saved.layers || ALL_LAYERS,
  // hidden are the tables that are switched off, per layer.
  hidden: saved.hidden || {},
  // folded are the tables that are folded down to their header.
  folded: saved.folded || {},
  // off are the blocks that are taken out of a diagram (devices, processes):
  // namespace -> view -> kind -> keys. Every view has its own, so that what is
  // hidden in one diagram does not empty another.
  off: saved.off || {},
  journeys: [],     // the traced packets, newest last
  items: [],        // what the view lists of them
  selected: null,   // the item the diagram shows
  live: true,       // new items are played as they come
  queue: [],        // items that wait to be played
  paused: false,    // the page is frozen: nothing new is listed or played
  held: [],         // the packets that arrived during the pause, oldest first
  missed: 0,        // the packets that found no room in it and were not kept
  playing: false,
  animEnd: 0,       // when the running animation ends
  redrawTimer: null,
  // filter is what pathviz traces in the full view (the clicks in the diagram
  // change it), and the display filter of an embedded view.
  filter: emptyFilter(),
};

// An earlier version kept one list of blocks for all the views: that is dropped.
for (const ns of Object.values(state.off)) { delete ns.devices; delete ns.procs; }
if (params.get('detail') === 'hooks') state.subs.l3 = 'hooks';
if (params.get('sub') && state.view.subs.some((s) => s.id === params.get('sub'))) state.subs[state.view.id] = params.get('sub');
if (listParam('layers')) state.layers = ALL_LAYERS.filter((l) => listParam('layers').includes(l));
if (!state.layers.length) state.layers = ALL_LAYERS;

function save() {
  if (embed) return;
  try { localStorage.setItem(SAVED_KEY, JSON.stringify({ subs: state.subs, layers: state.layers, hidden: state.hidden, folded: state.folded, off: state.off })); } catch { /* not saved, still applied */ }
}

// The display filter of an embedded view, with the names of the command-line flags.
const urlFilter = {
  protos: (listParam('proto') || []).filter((p) => p !== 'any').sort(),
  ifaces: (listParam('iface') || []).sort(),
  macs: (listParam('mac') || []).map((m) => m.toLowerCase()).sort(),
  ips: listParam('ip') || [],
  ports: (listParam('port') || []).map(Number).filter(Number.isInteger).sort((a, b) => a - b),
};
if (embed) state.filter = urlFilter;

// An embedded view with ?panels= shows them below the diagram. Without it,
// the view switches between the diagram and the tables.
const panelsBelow = embed && urlPanels !== null && urlPanels.length > 0;
const hasSwitch = embed && urlPanels === null;
document.body.classList.toggle('embed', embed);
document.body.classList.toggle('below', panelsBelow);

// offKeys are the blocks of one kind that are switched off in the diagram on
// view, in the watched namespace.
const offKeys = (kind) => ((state.off[store.netns] || {})[state.view.id] || {})[kind] || [];

// setOff replaces the switched-off blocks of the diagram on view: kind -> keys.
function setOff(kinds) {
  const ns = state.off[store.netns] || (state.off[store.netns] = {});
  const kept = Object.fromEntries(Object.entries(kinds).filter(([, keys]) => keys.length));
  if (Object.keys(kept).length) ns[state.view.id] = kept;
  else delete ns[state.view.id];
  if (!Object.keys(ns).length) delete state.off[store.netns];
}

const svg = $('#diagram');
const view = () => state.view;
const sub = () => state.subs[view().id] || '';

// The views call back through this.
const ctx = {
  svg,
  sub,
  layers: () => state.layers.filter((l) => store.layers.includes(l)),
  filter: () => state.filter,
  // pick traces exactly the clicked thing: it replaces the whole filter.
  // Picking the only thing that is traced goes back to tracing everything.
  // With Ctrl or Cmd held (more), the thing is added to what is traced, or
  // taken out of it.
  pick(part, more) {
    const now = state.filter;
    if (!more) applyFilter(sameFilter(part, now) ? emptyFilter() : part);
    else applyFilter(filterHas(now, part) ? filterWithout(now, part) : filterWith(now, part));
  },
  // blockOn tells whether a block of a diagram (a device, a process) is shown.
  blockOn: (kind, key) => !offKeys(kind).includes(key),
};
for (const v of VIEWS) v.init(ctx);

const panelShown = (id) => {
  if (!view().panels.some((p) => p.id === id)) return false;
  if (embed) return urlPanels === null || urlPanels.includes(id);
  if (urlPanels !== null && !state.hidden[view().id]) return urlPanels.includes(id);
  return !(state.hidden[view().id] || []).includes(id);
};

// ---- The header --------------------------------------------------------------

function switchButton(label, pressed, onClick, title) {
  const b = html('button', { type: 'button', 'aria-pressed': String(pressed) }, label);
  if (title) b.title = title;
  b.addEventListener('click', onClick);
  return b;
}

// chrome draws all that depends on the layer that is on: the switches of the
// header, the titles, and the head of the list.
function chrome() {
  const v = view();
  const probed = (x) => (x.layer ? store.layers.includes(x.layer) : true);
  $('#mode-switch').replaceChildren(...VIEWS.map((x) => {
    const b = switchButton(x.label, x === v, () => setMode(x.id), x.about);
    if (!probed(x) && store.layers.length) { b.disabled = true; b.title = 'PathViz was started without the probes of this layer (--layers).'; }
    return b;
  }));

  // The looks of a view are a switch of their own (two diagrams of the bridge),
  // or a level of detail: then they are a button among the things to show.
  const pickSub = (id) => {
    state.subs[v.id] = id;
    setParam('sub', id === v.subs[0].id ? null : id);
    save();
    chrome();
    relist();
  };
  $('#sub-group').hidden = v.subs.length === 0 || !!v.level || embed;
  $('#sub-switch').replaceChildren(...(v.level ? [] : v.subs).map((s) => switchButton(s.label, s.id === sub(), () => pickSub(s.id))));
  $('#detail-switch').replaceChildren(...(v.level ? [switchButton(v.level.label, sub() === v.level.on, () => pickSub(sub() === v.level.on ? v.level.off : v.level.on), v.level.about)] : []));

  $('#layer-group').hidden = !v.layered || embed;
  $('#layer-switch').replaceChildren(...ALL_LAYERS.filter((l) => store.layers.includes(l) || !store.layers.length).reverse().map((l) => switchButton(l.toUpperCase(), state.layers.includes(l), () => {
    const next = state.layers.includes(l) ? state.layers.filter((x) => x !== l) : ALL_LAYERS.filter((x) => x === l || state.layers.includes(x));
    if (!next.length) return; // one layer stays on
    dropPreset();
    state.layers = next;
    setParam('layers', next.length === ALL_LAYERS.length ? null : next.join(','));
    save();
    chrome();
    rebuild(false);
  })));

  $('#panel-group').hidden = embed;
  $('#panel-switch').replaceChildren(...v.panels.map((p) => switchButton(p.label, panelShown(p.id), () => {
    const hidden = new Set(v.panels.filter((x) => !panelShown(x.id)).map((x) => x.id));
    if (hidden.has(p.id)) hidden.delete(p.id); else hidden.add(p.id);
    state.hidden[v.id] = [...hidden];
    save();
    chrome();
  })));
  let any = false;
  for (const panel of document.querySelectorAll('.lower .panel')) {
    const on = panelShown(panel.dataset.panel);
    panel.hidden = !on;
    any = any || on;
  }
  document.body.classList.toggle('no-panels', !any);
  showFolded();
  showBlocks();
  showPreset();

  $('#list-title').textContent = v.title;
  $('#embed-tables').textContent = v.title;
  svg.setAttribute('aria-label', v.aria);
  $('#packets thead').replaceChildren(html('tr', {}, ...v.columns.map((c) => html('th', {}, c)), html('th', { 'aria-label': 'Packet contents' })));
  setLive(state.live);
  showPause();
  document.title = `PathViz on ${store.hostName || '…'}`;
}

function setMode(id) {
  state.view = VIEWS.find((v) => v.id === id) || l3;
  setParam('mode', state.view === l3 ? null : state.view.id);
  setParam('sub', null);
  chrome();
  relist();
}

// ---- Folded tables -------------------------------------------------------------

// A click on the head of a table folds it down to that head, and back. A folded
// table gets a row of its own, and the others share the rest.
function showFolded() {
  const shown = [...document.querySelectorAll('.lower .panel')].filter((p) => !p.hidden);
  for (const panel of shown) {
    const folded = !!state.folded[panel.dataset.panel];
    panel.classList.toggle('collapsed', folded);
    panel.querySelector('.section-head').setAttribute('aria-expanded', String(!folded));
  }
  const folded = shown.filter((p) => state.folded[p.dataset.panel]).length;
  $('.lower').classList.toggle('has-collapsed', folded > 0);
  $('.lower').classList.toggle('all-collapsed', folded > 0 && folded === shown.length);
}

for (const head of document.querySelectorAll('.lower .section-head')) {
  const toggle = () => {
    const id = head.parentElement.dataset.panel;
    state.folded[id] = !state.folded[id];
    save();
    showFolded();
  };
  head.addEventListener('click', (e) => { if (!e.target.closest('button')) toggle(); });
  head.addEventListener('keydown', (e) => {
    if (e.target !== head || (e.key !== 'Enter' && e.key !== ' ')) return;
    e.preventDefault();
    toggle();
  });
}

// ---- The blocks of a diagram ---------------------------------------------------

// fillSelect sets the options of a list, and leaves a list alone that has them
// already: an open list must not close under the pointer.
function fillSelect(sel, options, value) {
  const key = JSON.stringify(options);
  if (sel.dataset.key !== key) {
    sel.dataset.key = key;
    sel.replaceChildren(...options.map((o) => html('option', { value: o.id }, o.label)));
  }
  sel.value = value;
}

// showBlocks draws the menus of the blocks that can be taken out of the diagram:
// a list of checkboxes per kind. It changes what is drawn and not what is traced.
function showBlocks() {
  const box = $('#block-switch');
  const blocks = view().blocks && !embed ? view().blocks() : [];
  for (const menu of [...box.children]) {
    if (!blocks.some((b) => b.id === menu.dataset.kind)) menu.remove();
  }
  for (const b of blocks) {
    let menu = box.querySelector(`[data-kind="${b.id}"]`);
    if (!menu) {
      menu = html('details', { class: 'menu', 'data-kind': b.id }, html('summary', {}), html('div', { class: 'menu-list' }));
      box.append(menu);
    }
    const off = offKeys(b.id);
    const on = b.items.filter((i) => !off.includes(i.key)).length;
    const summary = menu.querySelector('summary');
    summary.textContent = on === b.items.length ? b.label : `${b.label} ${on}/${b.items.length}`;
    summary.classList.toggle('partly', on < b.items.length);
    const key = JSON.stringify([b.items, off]);
    if (menu.dataset.key === key) continue;
    menu.dataset.key = key;
    const set = (keys) => {
      setOff({ ...(state.off[store.netns] || {})[state.view.id], [b.id]: keys });
      dropPreset();
      save();
      showBlocks();
      rebuild(false);
    };
    const all = html('button', { type: 'button' }, 'All');
    all.addEventListener('click', () => set([]));
    const none = html('button', { type: 'button' }, 'None');
    none.addEventListener('click', () => set(b.items.map((i) => i.key)));
    const rows = b.items.map((i) => {
      const check = html('input', { type: 'checkbox' });
      check.checked = !off.includes(i.key);
      // The keys of the things that are gone stay off: they may come back.
      check.addEventListener('change', () => set(check.checked ? offKeys(b.id).filter((k) => k !== i.key) : [...offKeys(b.id), i.key]));
      return html('label', {}, check, html('span', { class: 'mono' }, i.label), i.note ? html('span', { class: 'muted' }, i.note) : null);
    });
    menu.querySelector('.menu-list').replaceChildren(
      html('div', { class: 'menu-all' }, all, none),
      ...(rows.length ? rows : [html('p', { class: 'muted' }, 'Nothing here yet.')]),
    );
  }
}

// An open menu closes on a click outside of it and on Escape.
document.addEventListener('click', (e) => {
  for (const menu of document.querySelectorAll('details.menu[open]')) {
    if (!menu.contains(e.target)) menu.open = false;
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  for (const menu of document.querySelectorAll('details.menu[open]')) menu.open = false;
});

// In a narrow window, a row of the header is folded down to its name, and a
// tap on the name unfolds its controls.
for (const btn of document.querySelectorAll('.rowname')) {
  btn.addEventListener('click', () => {
    const open = btn.closest('.row').classList.toggle('open');
    btn.setAttribute('aria-expanded', String(open));
  });
}

// spaces fills the list of the namespaces.
function showSpaces() {
  const sel = $('#f-netns');
  const options = store.spaces.map((s) => ({ id: s.id, label: spaceLabel(s) + (s.bridges ? ` · ${s.bridges} ${s.bridges > 1 ? 'bridges' : 'bridge'}` : '') }));
  if (!store.spaces.some((s) => s.id === store.netns) && store.netns) options.push({ id: store.netns, label: store.netns });
  fillSelect(sel, options, store.netns);
}

$('#f-netns').addEventListener('change', (e) => {
  setParam('netns', e.target.value);
  store.netns = e.target.value;
  connect();
});

// ---- Tables ------------------------------------------------------------------

// cell makes a table cell from [text, class, note].
function cell([text, cls, note]) {
  const td = html('td', cls ? { class: cls } : {}, text === undefined || text === null ? '' : String(text));
  if (cls && cls.includes('details')) td.title = text;
  if (note) td.append(html('span', { class: 'who' }, note));
  return td;
}

function row(item) {
  const tr = html('tr', { id: `i${item.id}`, tabindex: '0' }, ...view().cells(item).map(cell));
  // The button opens the packet view. It must not select the row as well.
  const act = html('td', { class: 'act' });
  const inspect = html('button', { type: 'button', class: 'inspect', title: 'Show the headers and the bytes of this packet' }, 'Inspect');
  inspect.addEventListener('click', (e) => {
    e.stopPropagation();
    openPacket(item, view().packetHops(item), view() === l3 && sub() === 'hooks');
  });
  inspect.addEventListener('keydown', (e) => e.stopPropagation());
  act.append(inspect);
  tr.append(act);
  const pick = () => { setLive(false); select(item, true); };
  tr.addEventListener('click', pick);
  tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') pick(); });
  return tr;
}

function addRow(item) {
  const body = $('#packets tbody');
  body.prepend(row(item));
  while (body.rows.length > MAX_ROWS) body.deleteRow(-1);
}

function counts() {
  const n = state.items.length;
  $('#count').textContent = n ? `${n} shown` : '';
  $('#empty').hidden = n > 0;
  $('#empty p').textContent = `No ${view().noun} has matched the filter yet.`;
}

// fill shows a table that a view describes: its title, columns, and rows.
function fill(name, t) {
  const titles = { hops: ['#detail-title', '#detail-summary'], extra: ['#extra-title', '#extra-summary'] }[name];
  const body = $(`#${name} tbody`);
  body.replaceChildren();
  if (!t) return;
  $(titles[0]).textContent = t.title;
  $(titles[1]).textContent = t.summary || '';
  $(`#${name} thead`).replaceChildren(html('tr', {}, ...t.columns.map((c) => html('th', {}, c))));
  $(`#${name}-empty`).hidden = t.rows.length > 0;
  $(`#${name}-empty p`).textContent = t.empty;
  for (const r of t.rows) {
    const tr = html('tr', r.cls ? { class: r.cls.trim() } : {}, ...r.cells.map(cell));
    for (const note of r.notes || []) tr.cells[0].append(html('span', { class: 'note' }, note));
    body.append(tr);
  }
}

function describe() {
  const v = view(), item = state.selected;
  const box = $('#verdict');
  const d = v.verdict(item);
  box.className = `verdict ${d.kind || ''}`;
  box.title = [d.head, d.text].filter(Boolean).join(' ');
  // The sentence is one element, so that the box can center it as a whole.
  const p = html('span', {});
  if (d.head) p.append(html('strong', {}, d.head), ' ');
  p.append(d.text || '');
  box.replaceChildren(p);
  fill('hops', v.detail(item));
  fill('extra', v.extra ? v.extra(item) : null);
}

function tabs() {
  const v = view();
  const list = v.tabs ? v.tabs() : [];
  const box = $('#tabs');
  box.hidden = list.length === 0;
  box.replaceChildren(...list.map((t) => switchButton(t.label, t.on, () => {
    v.pickTab(t.id);
    if (state.selected && !v.onTab(state.selected)) { setLive(false); state.selected = null; markSelected(); }
    rebuild(false);
  })));
}

// A click unfolds an outcome that was cut to fit its lines, and folds it back.
$('#verdict').addEventListener('click', () => $('#verdict').classList.toggle('open'));

// ---- Diagram, selection, and playback ----------------------------------------

// rebuild draws the diagram anew and puts the selected item back on it.
function rebuild(animate) {
  svg.replaceChildren();
  svg.style.width = '';
  svg.style.maxWidth = '';
  svg.style.minWidth = '';
  svg.classList.remove('compact', 'tall');
  view().build();
  const ms = view().show(state.selected, animate);
  tabs();
  describe();
  return ms;
}

function markSelected() {
  for (const tr of document.querySelectorAll('#packets tr.selected')) tr.classList.remove('selected');
  const r = state.selected && document.getElementById(`i${state.selected.id}`);
  if (r) r.classList.add('selected');
}

// select shows an item in the diagram and returns how long its animation takes.
function select(item, animate) {
  state.selected = item;
  markSelected();
  const ms = view().show(item, animate) || 0;
  state.animEnd = performance.now() + ms;
  tabs();
  describe();
  return ms;
}

// play shows the waiting items one after another.
function play() {
  if (state.playing || !state.live || state.paused) return;
  // When packets arrive faster than they can be drawn, skip to the recent ones.
  if (state.queue.length > 4) state.queue = state.queue.slice(-2);
  const item = state.queue.shift();
  if (!item) return;
  state.playing = true;
  const ms = select(item, true);
  setTimeout(() => { state.playing = false; play(); }, ms + 300 / playback.speed);
}

function setLive(on) {
  state.live = on;
  const b = $('#live-btn');
  b.setAttribute('aria-pressed', String(on));
  b.textContent = on ? `Following new ${view().noun}s` : `Follow new ${view().noun}s`;
  if (!on) state.queue = [];
}

const shown = (j) => !embed || journeyMatches(j, state.filter);

// ingest lists a traced packet and returns the items the view made of it.
function ingest(j) {
  state.journeys.push(j);
  if (state.journeys.length > MAX_ROWS) state.journeys.shift();
  if (!shown(j)) return [];
  const added = view().items(j);
  for (const item of added) {
    state.items.push(item);
    if (state.items.length > MAX_ROWS) state.items.shift();
    addRow(item);
  }
  counts();
  return added;
}

function onJourney(j) {
  // During a pause the packets wait. When as many wait as the list holds,
  // the later ones are not kept: Step then still shows what came right after
  // the pause, with no gap in it.
  if (state.paused) {
    if (state.held.length < MAX_ROWS) state.held.push(j);
    else state.missed++;
    showPause();
    return;
  }
  const added = ingest(j);
  if (state.live) state.queue.push(...added);
  play();
}

// ---- Pause -------------------------------------------------------------------

// A pause freezes the diagram and the lists of packets. What arrives meanwhile
// waits, and is listed on Resume, or one by one with Step. It is not the same
// as not following: without following the list still grows.
function showPause() {
  const waiting = state.held.length + state.queue.length;
  const pause = $('#pause-btn');
  pause.setAttribute('aria-pressed', String(state.paused));
  pause.textContent = state.paused ? 'Resume' : 'Pause';
  pause.title = state.paused ? `List and play the ${view().noun}s that arrived meanwhile` : `Freeze the diagram and the tables. New ${view().noun}s wait until Resume or Step`;
  const step = $('#step-btn');
  step.disabled = !state.paused || waiting === 0;
  step.title = state.paused ? `Show the next ${view().noun} that waits` : 'Pause first, then step through what arrives';
  // The count has a place of its own after the controls, so that they stay put
  // while it changes.
  const note = $('#held-note');
  note.classList.toggle('full', state.missed > 0);
  note.textContent = !state.paused ? '' : !waiting ? 'Paused' : state.missed
    ? `Full · ${state.missed} dropped`
    : `${waiting} waiting`;
  note.title = state.missed
    ? `${MAX_ROWS} ${view().noun}s wait, and that is the limit: the ${state.missed} that arrived after them were dropped. Resume or Step to make room.`
    : `Up to ${MAX_ROWS} ${view().noun}s wait during a pause. The ones that arrive after that are dropped.`;
}

function setPaused(on) {
  state.paused = on;
  if (on) {
    // The running animation ends right away: the path is drawn in full.
    if (state.selected) select(state.selected, false);
  } else {
    const held = state.held;
    state.held = [];
    state.missed = 0;
    for (const j of held) {
      const added = ingest(j);
      if (state.live) state.queue.push(...added);
    }
    play();
  }
  showPause();
}

// step shows the next waiting packet. A packet that the view lists nothing of
// (an ARP frame in the IP view) is taken in and skipped.
function step() {
  if (!state.paused) return;
  let item = state.queue.shift();
  while (!item && state.held.length) {
    const added = ingest(state.held.shift());
    item = added.shift();
    state.queue.push(...added);
  }
  if (item) select(item, true);
  showPause();
}

// relist lists the traced packets anew, the way the current view shows them,
// and selects the newest one.
function relist() {
  state.queue = [];
  state.items = state.journeys.filter(shown).flatMap((j) => view().items(j)).slice(-MAX_ROWS);
  $('#packets tbody').replaceChildren(...state.items.map(row).reverse());
  state.selected = state.items.length ? state.items[state.items.length - 1] : null;
  counts();
  rebuild(false);
  markSelected();
}

function clearAll() {
  state.journeys = [];
  state.held = [];
  state.missed = 0;
  relist();
}

// onHost takes a new state of the namespace. The diagram is drawn anew, but
// not in the middle of an animation.
function onHost(host) {
  store.host = host;
  showBlocks();
  clearTimeout(state.redrawTimer);
  const wait = state.animEnd - performance.now();
  if (wait > 0) state.redrawTimer = setTimeout(() => rebuild(false), wait + 50);
  else rebuild(false);
}

// ---- Filter ------------------------------------------------------------------

function showFilter(f) {
  store.capture = { ...emptyFilter(), ...f };
  for (const k of Object.keys(store.capture)) store.capture[k] = store.capture[k] || [];
  if (!embed) state.filter = store.capture;
  const c = store.capture;
  const protos = c.protos.join(',');
  const sel = $('#f-proto');
  if (![...sel.options].some((o) => o.value === protos)) sel.append(html('option', { value: protos }, protos));
  sel.value = protos;
  $('#f-ifaces').value = c.ifaces.join(', ');
  $('#f-macs').value = c.macs.join(', ');
  $('#f-ips').value = c.ips.join(', ');
  $('#f-ports').value = c.ports.join(', ');
  // The line is cut short when it does not fit: the tooltip has all of it.
  $('#tracing').textContent = describeFilter(state.filter);
  $('#tracing').title = describeFilter(state.filter);
  // The filter is shared by all the views: a changed one drops their presets.
  for (const [id, x] of Object.entries(presets)) {
    if (x && !sameFilter({ ...emptyFilter(), ...x.filter }, store.capture)) presets[id] = null;
  }
  showPreset();
  markDirty();
}

// applyFilter asks pathviz to trace other traffic. The page updates when the
// server announces the new filter.
async function applyFilter(filter) {
  const msg = $('#filter-msg');
  try {
    const res = await post('api/filter', filter);
    if (!res.ok) throw new Error((await res.text()).trim());
    msg.className = 'ok';
    msg.textContent = 'Probes updated.';
    setTimeout(() => { if (msg.textContent === 'Probes updated.') msg.textContent = ''; }, 2500);
  } catch (err) {
    msg.className = '';
    msg.textContent = `Filter not applied: ${err.message}`;
  }
}

// formFilter reads the filter the user typed. It returns null for bad ports.
function formFilter() {
  const split = (v) => v.split(/[\s,]+/).filter(Boolean);
  const ports = split($('#f-ports').value).map(Number);
  if (ports.some((p) => !Number.isInteger(p))) return null;
  return {
    protos: split($('#f-proto').value).sort(),
    ifaces: split($('#f-ifaces').value).sort(),
    macs: split($('#f-macs').value).map((m) => m.toLowerCase()).sort(),
    ips: split($('#f-ips').value),
    ports: ports.sort((a, b) => a - b),
  };
}

// The button applies a typed filter, so it is active only while the fields
// differ from what is traced. Picks in the diagram apply right away.
function markDirty() {
  const f = formFilter();
  $('#apply-btn').disabled = !!f && sameFilter(f, store.capture);
}

$('#filter').addEventListener('input', (e) => { if (e.target.id !== 'f-netns') markDirty(); });
$('#filter').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = formFilter();
  if (!f) {
    $('#filter-msg').className = '';
    $('#filter-msg').textContent = 'Ports must be numbers.';
    return;
  }
  applyFilter(f);
});

// ---- Connection --------------------------------------------------------------

// askToken shows the dialog that asks for the access token. It stays until
// the right token is entered.
function askToken() {
  const conn = $('#conn');
  conn.className = 'conn down';
  conn.textContent = 'Token needed';
  const dialog = $('#token-dialog');
  if (!dialog.open) dialog.showModal();
}

$('#token-dialog').addEventListener('cancel', (e) => e.preventDefault());
$('#token-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = $('#token-msg');
  // The whole address that PathViz printed can be pasted as well.
  const text = $('#token-input').value.trim();
  const fromUrl = /[?&]token=([^&#\s]+)/.exec(text);
  const candidate = fromUrl ? decodeURIComponent(fromUrl[1]) : text;
  if (!candidate) return;
  try {
    const res = await fetch('api/session', { headers: { Authorization: `Bearer ${candidate}` } });
    if (res.status === 401) { msg.textContent = 'This is not the token of this PathViz.'; return; }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
  } catch (err) {
    msg.textContent = `Cannot reach PathViz: ${err.message}`;
    return;
  }
  msg.textContent = '';
  $('#token-input').value = '';
  keepToken(candidate);
  $('#token-dialog').close();
  connect();
});

let source = null;   // the open stream of events
let attempt = 0;     // tells a stale connect() that a newer one took over
store.netns = params.get('netns') || '';

// leaveNetns goes back to the namespace pathviz was started for.
function leaveNetns(why) {
  $('#filter-msg').className = '';
  $('#filter-msg').textContent = why;
  setParam('netns', null);
  store.netns = '';
  connect();
}

async function connect() {
  const mine = ++attempt;
  if (source) { source.close(); source = null; }
  const conn = $('#conn');
  const retry = () => { conn.className = 'conn down'; conn.textContent = 'Reconnecting'; setTimeout(() => { if (mine === attempt) connect(); }, 2000); };
  // An EventSource does not tell why it failed, so the token and the
  // namespace are checked first.
  try {
    const res = await api('api/ruleset');
    if (mine !== attempt) return;
    if (res.status === 401) { askToken(); return; }
    if (res.status === 404 && store.netns) { leaveNetns(`There is no namespace "${store.netns}" (anymore).`); return; }
    if (!res.ok) { retry(); return; }
  } catch {
    if (mine === attempt) retry();
    return;
  }
  const token = getToken();
  const es = new EventSource(apiPath('api/events') + (token ? `${store.netns ? '&' : '?'}token=${encodeURIComponent(token)}` : ''));
  source = es;
  es.onopen = () => { conn.className = 'conn up'; conn.textContent = 'Connected'; };
  es.onerror = () => {
    if (mine !== attempt) return;
    conn.className = 'conn down';
    conn.textContent = 'Reconnecting';
    // A refused EventSource gives up for good. A restarted PathViz has a new
    // token, so the token is checked again.
    if (es.readyState === EventSource.CLOSED) retry();
  };
  es.onmessage = (e) => {
    if (mine !== attempt) return;
    const msg = JSON.parse(e.data);
    switch (msg.type) {
      case 'hello': {
        const d = msg.data;
        Object.assign(store, { hostName: d.host, netns: d.netns, spaces: d.spaces || [], layers: d.layers || [], egress: d.egress, hooks: d.hooks, packetView: d.packetView });
        store.host = d.state && d.state.ifaces ? d.state : { ifaces: [], procs: [], bridges: [] };
        // Without the packet view (--no-packet-view) the rows have no Inspect button.
        document.body.classList.toggle('no-packet-view', !d.packetView);
        // A layer that is not probed cannot be shown.
        if (state.view.layer && !store.layers.includes(state.view.layer)) state.view = VIEWS.find((v) => !v.layer || store.layers.includes(v.layer));
        showSpaces();
        showFilter(d.filter);
        chrome();
        state.journeys = d.journeys || [];
        state.held = [];
        state.missed = 0;
        relist();
        break;
      }
      case 'journey': onJourney(msg.data); break;
      case 'filter': showFilter(msg.data); rebuild(false); break;
      case 'host': onHost(msg.data); break;
      case 'spaces': store.spaces = msg.data; showSpaces(); break;
      case 'clear': clearAll(); setLive(true); break;
      case 'gone': leaveNetns('The namespace is gone.'); break;
      case 'stats':
        if (msg.data.lost > 0) {
          conn.className = 'conn up warn';
          conn.textContent = `Connected, ${msg.data.lost} probe events lost`;
        }
        break;
    }
  };
}

// ---- Controls ----------------------------------------------------------------

$('#live-btn').addEventListener('click', () => {
  setLive(!state.live);
  if (state.live && state.items.length && !state.paused) select(state.items[state.items.length - 1], true);
});
$('#pause-btn').addEventListener('click', () => setPaused(!state.paused));
$('#step-btn').addEventListener('click', step);

$('#clear-btn').addEventListener('click', () => post('api/clear', {}));

$('#help-btn').addEventListener('click', async () => {
  const pre = $('#rules-text');
  pre.textContent = 'Loading';
  $('#rules-dialog').showModal();
  let text;
  try {
    const res = await api('api/ruleset');
    text = res.ok ? await res.text() : `HTTP ${res.status}`;
  } catch (err) {
    text = `Cannot reach PathViz: ${err.message}`;
  }
  // The comments are dimmed, and their [static] and [filter] labels stand out.
  pre.textContent = '';
  for (const line of text.split('\n')) {
    const at = line.indexOf('#');
    if (at < 0 || line.slice(0, at).trim() !== '') {
      pre.append(`${line}\n`);
      continue;
    }
    const span = html('span', { class: 'comment' });
    for (const part of line.split(/(\[static\]|\[filter\])/)) {
      if (part === '[static]' || part === '[filter]') span.append(html('span', { class: part === '[filter]' ? 'tag dynamic' : 'tag' }, part));
      else span.append(part);
    }
    pre.append(span, '\n');
  }
});

// The switch of the colors. A choice that differs from the system's is kept,
// and one that agrees with it is not: the page then follows the system again.
// ?theme= wins over both (see index.html).
const THEME_KEY = 'pathviz.theme';
const systemDark = matchMedia('(prefers-color-scheme: dark)');
const isDark = () => (document.documentElement.dataset.theme || (systemDark.matches ? 'dark' : 'light')) === 'dark';

function showTheme() {
  const btn = $('#theme-btn');
  btn.classList.toggle('dark', isDark());
  btn.title = isDark() ? 'Switch to the light colors' : 'Switch to the dark colors';
}

$('#theme-btn').addEventListener('click', () => {
  const next = isDark() ? 'light' : 'dark';
  const same = next === (systemDark.matches ? 'dark' : 'light');
  if (same) delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = next;
  setParam('theme', null);
  try {
    if (same) localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, next);
  } catch { /* not kept, still applied */ }
  showTheme();
});
systemDark.addEventListener('change', showTheme);
showTheme();

// ---- Presets -------------------------------------------------------------------

// A preset sets the filter, the layers of the combined view, and the devices
// and processes of the diagram on view (see presets.js). Every view offers the
// presets that fit it and remembers its own. The list shows the preset while
// nothing of it was changed by hand.
const presetSelect = $('#preset-select');
const presets = {}; // view -> the preset that is on
const fitting = () => PRESETS.filter((x) => x.views.includes(state.view.id));

function showPreset() {
  const options = [{ id: '', label: 'Custom' }, ...fitting().map((x) => ({ id: x.id, label: x.label }))];
  const on = presets[state.view.id] || null;
  fillSelect(presetSelect, options, on ? on.id : '');
  presetSelect.title = on ? on.about : 'A filter and a look for a common setup';
}

// dropPreset tells the list that a thing the preset had set was changed.
function dropPreset() {
  presets[state.view.id] = null;
  showPreset();
}

presetSelect.addEventListener('change', () => {
  const preset = fitting().find((x) => x.id === presetSelect.value) || null;
  presets[state.view.id] = preset;
  showPreset();
  if (!preset) return;
  if (state.view.layered) {
    const layers = preset.layers.filter((l) => store.layers.includes(l));
    if (layers.length) state.layers = layers;
    setParam('layers', state.layers.length === ALL_LAYERS.length ? null : state.layers.join(','));
  }
  setOff({
    devices: store.host.ifaces.filter((d) => !preset.device(d)).map((d) => d.name),
    procs: preset.procs ? [] : store.host.procs.map(procKey),
  });
  save();
  chrome();
  rebuild(false);
  applyFilter({ ...emptyFilter(), ...preset.filter });
});

const speedSelect = $('#speed-select');
for (const rate of SPEED_STEPS) speedSelect.append(new Option(`x${rate}`, String(rate)));
speedSelect.value = String(playback.speed);
speedSelect.addEventListener('change', () => { playback.speed = Number(speedSelect.value); });

// An embedded view without tables below: a switch between the path and the tables.
if (hasSwitch) {
  $('#embed-group').hidden = false;
  for (const btn of document.querySelectorAll('#embed-switch button')) {
    btn.addEventListener('click', () => {
      document.body.classList.toggle('tabular', btn.dataset.show === 'tables');
      for (const b of document.querySelectorAll('#embed-switch button')) b.setAttribute('aria-pressed', String(b === btn));
    });
  }
}

// The diagram of a view may have several arrangements, picked by the box it
// gets. An embedded view without tables fits the diagram into its height.
const fitsHeight = embed && !panelsBelow;
if (fitsHeight) svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
const EMBED_MIN_WIDTH = 540;
let layoutFrame = 0;
new ResizeObserver(([entry]) => {
  const { width, height } = entry.contentRect;
  // The diagram is hidden while an embedded view shows its tables.
  if (!width) return;
  cancelAnimationFrame(layoutFrame);
  layoutFrame = requestAnimationFrame(() => {
    // An embedded diagram does not shrink below EMBED_MIN_WIDTH (see style.css):
    // its box scrolls sideways then, and the layout is made for that width.
    if (view().resize(embed ? Math.max(width, EMBED_MIN_WIDTH) : width, fitsHeight ? height : Infinity)) rebuild(false);
  });
}).observe($('#diagram-box'));

chrome();
connect();
