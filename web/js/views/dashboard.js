import { api } from "../api.js";
import { h, clear, toast, modal, confirmDialog, isWide, setWide, chartStyle, setChartStyle, loadJSON, saveJSON, icons } from "../ui.js";
import { buildChartCard } from "../chart.js";

const TREE_KEY = "driftband-tree-collapsed";
function toLocalInput(unix) { const d = new Date(unix * 1000), p = (n) => String(n).padStart(2, "0"); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; }
function fromLocalInput(v) { if (!v) return null; const t = new Date(v).getTime(); return isNaN(t) ? null : Math.floor(t / 1000); }

const RANGES = [
  { w: 3600, label: "1h" }, { w: 21600, label: "6h" }, { w: 86400, label: "24h" },
  { w: 604800, label: "7d" }, { w: 0, label: "max" },
];

export function renderDashboard(mount, ctx) {
  clear(mount);
  let tree = [], profiles = [], selectedId = null;
  let windowSec = 86400, live = false, liveTimer = null;
  let charts = [];
  let statusMap = {}, dotEls = [];
  let customRange = null; // {from, to} unix, or null for the rolling window
  let dragId = null;      // node id being dragged in the tree
  const collapsed = new Set(loadJSON(TREE_KEY, []));

  const treeHost = h("ul.tree");
  const quota = h("span.badge.muted", { hidden: true, style: "margin-left:8px;font-weight:500" });
  const treePanel = h("div.tree-panel.card",
    h("div.tree-head",
      h("h2", "Hosts", quota),
      h("button.btn.sm.primary", { onclick: () => openNodeModal({ parentId: null }) }, h("span.ico", { html: icons.plus }), "Add"),
    ),
    treeHost,
  );

  // ---- toolbar ----
  const rangeSeg = h("div.seg", ...RANGES.map((r) =>
    h("button", { class: r.w === windowSec ? "active" : "", onclick: () => setRange(r.w) }, r.label)));

  const pill = (label, active, onClick, dot) =>
    h("button.pill" + (active ? ".on" : ""), { onclick: onClick }, dot ? h("span.pdot") : null, label);

  const liveToggle = pill("Live", live, () => setLiveOn(!live), true);
  const wideToggle = pill("Wide", isWide(), () => { const on = !isWide(); setWide(on); wideToggle.classList.toggle("on", on); });
  const styleToggle = pill("Old style", chartStyle() === "classic", () => { const on = chartStyle() !== "classic"; setChartStyle(on ? "classic" : "modern"); styleToggle.classList.toggle("on", on); });

  // custom from-to range
  const fromIn = h("input", { type: "datetime-local" });
  const toIn = h("input", { type: "datetime-local" });
  const pop = h("div.range-pop",
    h("label.field", h("span.lbl", "From"), fromIn),
    h("label.field", h("span.lbl", "To"), toIn),
    h("div", { style: "display:flex;gap:8px;justify-content:flex-end" },
      h("button.btn.sm.ghost", { onclick: clearCustom }, "Clear"),
      h("button.btn.sm.primary", { onclick: applyCustom }, "Apply")));
  pop.style.display = "none";
  const customBtn = pill("Custom", false, () => {
    const open = pop.style.display === "none";
    if (open) {
      const now = Math.floor(Date.now() / 1000);
      fromIn.value = toLocalInput(customRange ? customRange.from : now - (windowSec > 0 ? windowSec : 86400));
      toIn.value = toLocalInput(customRange ? customRange.to : now);
    }
    pop.style.display = open ? "" : "none";
  });
  const customWrap = h("div.range-wrap", customBtn, pop);

  const chartsHost = h("div.charts", h("div.placeholder", h("div.big", "Select a host or folder"), "Pick a node from the tree to see its smoke graph."));
  const chartsCol = h("div",
    h("div.toolbar",
      h("div.tb-group", rangeSeg, customWrap),
      h("div.tb-spacer"),
      h("div.tb-group", liveToggle, wideToggle, styleToggle)),
    h("div.tb-hint", "drag to zoom · double-click resets · click a host title to open it"),
    chartsHost,
  );

  mount.append(h("div.dash", treePanel, chartsCol));
  load();

  function applyCustom() {
    const f = fromLocalInput(fromIn.value), t = fromLocalInput(toIn.value);
    if (f == null || t == null || f >= t) { toast("Pick a valid From / To range", "err"); return; }
    customRange = { from: f, to: t };
    [...rangeSeg.children].forEach((b) => b.classList.remove("active"));
    customBtn.classList.add("on");
    pop.style.display = "none";
    loadSeries();
  }
  function clearCustom() {
    customRange = null;
    customBtn.classList.remove("on");
    [...rangeSeg.children].forEach((b, i) => b.classList.toggle("active", RANGES[i].w === windowSec));
    pop.style.display = "none";
    loadSeries();
  }

  async function load() {
    try {
      const [t, p] = await Promise.all([api.tree(), api.profiles()]);
      tree = t; profiles = p;
    } catch (e) { toast(e.message, "err"); return; }
    // Draw the tree immediately; health dots fill in when /api/status lands.
    drawTree();
    if (selectedId && !findNode(tree, selectedId)) selectedId = null;
    showSelection();
    refreshStatus();
  }

  // ---- tree ----
  function drawTree() {
    clear(treeHost);
    dotEls = [];
    // host count against the organization's limit (if any)
    const limit = ctx.me.limits ? ctx.me.limits.host_limit : 0;
    let n = 0; const count = (ns) => ns.forEach((x) => { if (x.kind === "host") n++; if (x.children) count(x.children); });
    count(tree);
    quota.hidden = !limit;
    if (limit) { quota.textContent = `${n} / ${limit}`; quota.title = `Your organization can have up to ${limit} hosts`; quota.className = "badge" + (n >= limit ? ".bad" : ".muted").replace(".", " "); }
    if (!tree.length) {
      treeHost.append(h("li", h("div.tree-empty", "No hosts yet. Click Add to create a folder or host.")));
      return;
    }
    for (const n of tree) treeHost.append(nodeLi(n, 0));
  }

  // ---- drag-and-drop helpers ----
  function dropMode(e, row, isFolder) {
    const r = row.getBoundingClientRect();
    const frac = (e.clientY - r.top) / r.height;
    if (isFolder) { if (frac < 0.30) return "before"; if (frac > 0.70) return "after"; return "into"; }
    return frac < 0.5 ? "before" : "after";
  }
  function clearMark(row) { row.classList.remove("drop-into", "drop-before", "drop-after"); }
  function clearDropMarks() { treeHost.querySelectorAll(".tree-row").forEach(clearMark); }
  function setDropMark(row, mode) {
    clearDropMarks();
    row.classList.add(mode === "into" ? "drop-into" : mode === "before" ? "drop-before" : "drop-after");
  }
  async function doDrop(movedId, refNode, mode) {
    let parentId, position;
    if (mode === "into") {
      parentId = refNode.id;
      position = (refNode.children || []).filter((c) => c.id !== movedId).length;
    } else {
      parentId = refNode.parent_id != null ? refNode.parent_id : null;
      const parentNode = parentId == null ? null : findNode(tree, parentId);
      const sibs = (parentId == null ? tree : (parentNode ? parentNode.children || [] : [])).filter((c) => c.id !== movedId);
      let idx = sibs.findIndex((c) => c.id === refNode.id);
      if (idx < 0) idx = sibs.length;
      position = mode === "after" ? idx + 1 : idx;
    }
    try { await api.moveNode(movedId, parentId, position); await load(); }
    catch (e) { toast(e.message, "err"); }
  }

  function nodeLi(n, depth) {
    const isFolder = n.kind === "folder";
    const hasChildren = isFolder && n.children && n.children.length;
    const isCollapsed = collapsed.has(n.id);
    const chevron = hasChildren
      ? h("span.tchev.ico", { html: icons.chevron, title: isCollapsed ? "Expand" : "Collapse",
          style: `transition:transform .15s;transform:rotate(${isCollapsed ? 0 : 90}deg)`,
          onclick: (e) => { e.stopPropagation(); collapsed.has(n.id) ? collapsed.delete(n.id) : collapsed.add(n.id); saveJSON(TREE_KEY, [...collapsed]); drawTree(); } })
      : h("span", { style: "width:14px" });

    const canNest = isFolder && depth < 2; // max 3 levels
    const actions = h("div.trow-actions",
      canNest ? iconBtn(icons.folder, "Add folder", (e) => { e.stopPropagation(); openNodeModal({ parentId: n.id, kind: "folder" }); }) : null,
      canNest ? iconBtn(icons.host, "Add host", (e) => { e.stopPropagation(); openNodeModal({ parentId: n.id, kind: "host" }); }) : null,
      iconBtn(icons.edit, "Edit", (e) => { e.stopPropagation(); openNodeModal({ node: n, parentId: n.parent_id }); }),
      iconBtn(icons.trash, "Delete", (e) => { e.stopPropagation(); delNode(n); }),
    );

    let dot = null;
    if (!isFolder) { dot = h("span.hdot", { style: `background:${colorFor(n)}` }); dotEls.push({ node: n, el: dot }); }
    const row = h("div.tree-row" + (n.id === selectedId ? ".selected" : ""),
      { draggable: true, onclick: () => { selectedId = n.id; drawTree(); showSelection(); } },
      chevron,
      h("span.ticon", { html: isFolder ? icons.folder : icons.host }),
      dot,
      h("span.tname", n.name),
      actions,
    );
    // drag-and-drop reordering / moving
    row.addEventListener("dragstart", (e) => { dragId = n.id; e.dataTransfer.effectAllowed = "move"; try { e.dataTransfer.setData("text/plain", String(n.id)); } catch (_) {} row.classList.add("dragging"); });
    row.addEventListener("dragend", () => { dragId = null; row.classList.remove("dragging"); clearDropMarks(); });
    row.addEventListener("dragover", (e) => {
      if (dragId == null || dragId === n.id) return;
      e.preventDefault(); e.dataTransfer.dropEffect = "move";
      setDropMark(row, dropMode(e, row, isFolder));
    });
    row.addEventListener("dragleave", (e) => { if (!row.contains(e.relatedTarget)) clearMark(row); });
    row.addEventListener("drop", (e) => {
      if (dragId == null || dragId === n.id) return;
      e.preventDefault();
      const mode = dropMode(e, row, isFolder);
      const moved = dragId; dragId = null; clearDropMarks();
      doDrop(moved, n, mode);
    });

    const li = h("li.tnode", row);
    if (hasChildren && !isCollapsed) {
      li.append(h("ul.tree-children", ...n.children.map((c) => nodeLi(c, depth + 1))));
    }
    return li;
  }
  function iconBtn(svg, title, onclick) {
    return h("button.btn.sm.icon.ghost", { title, onclick }, h("span.ico", { html: svg }));
  }

  // ---- selection -> charts ----
  function collectHosts(node) {
    if (node.kind === "host") return [node];
    let out = [];
    for (const c of node.children || []) out = out.concat(collectHosts(c));
    return out;
  }
  const FIXED = [[3600, "Last 1 hour"], [21600, "Last 6 hours"], [86400, "Last 24 hours"]];

  function samplingFor(hn) {
    const prof = profiles.find((p) => p.id === hn.profile_id);
    return `${prof ? prof.ping_count : "?"} pings / ${prof ? prof.interval_s : "?"}s · ICMP`;
  }
  function intervalFor(hn) { const p = profiles.find((p) => p.id === hn.profile_id); return p ? p.interval_s : 60; }
  function probeFor(hn) { const p = profiles.find((x) => x.id === hn.profile_id); return { interval: p ? p.interval_s : 60, pings: p ? p.ping_count : 20, packet: p ? p.packet_size : 56 }; }

  function addChart(meta, hostId, win, rangeControlled) {
    const c = buildChartCard({ ...meta, fetch: (from, to, opts) => api.series(hostId, from, to, opts) });
    c._hostId = hostId; c._window = win; c._range = rangeControlled;
    charts.push(c); chartsHost.append(c.el);
  }

  function showSelection() {
    destroyCharts();
    clear(chartsHost);
    const node = selectedId ? findNode(tree, selectedId) : null;
    if (!node) {
      chartsHost.append(h("div.placeholder", h("div.big", "Select a host or folder"), "Pick a node from the tree to see its smoke graph."));
      return;
    }
    if (node.kind === "host") {
      // Main chart follows the range selector; below it a fixed 1h/6h/24h stack.
      addChart({ title: node.name, ip: node.host, sampling: samplingFor(node), description: node.description, ...probeFor(node), height: 300 }, node.id, windowSec, true);
      for (const [w, label] of FIXED) {
        addChart({ title: label, ...probeFor(node), height: 300 }, node.id, w, false);
      }
    } else {
      const hosts = collectHosts(node);
      if (!hosts.length) {
        chartsHost.append(h("div.placeholder", h("div.big", "No hosts here"), "This folder has no hosts yet. Add one with the host button."));
        return;
      }
      for (const hn of hosts) {
        addChart({ title: hn.name, ip: hn.host, sampling: samplingFor(hn), description: hn.description, ...probeFor(hn), height: 220, onTitle: () => selectHost(hn.id) }, hn.id, windowSec, true);
      }
    }
    loadSeries();
  }
  function selectHost(id) {
    selectedId = id; drawTree(); showSelection();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  // incremental (Live ticks): charts fetch only their newest columns.
  async function loadSeries(incremental = false) {
    const now = Math.floor(Date.now() / 1000);
    await Promise.all(charts.map(async (c) => {
      let from, to;
      if (c._range && customRange) { from = customRange.from; to = customRange.to; }
      else { to = now; from = c._window > 0 ? now - c._window : 0; }
      try { await c.load(from, to, incremental); } catch (e) {}
    }));
    refreshStatus();
  }
  function destroyCharts() { charts.forEach((c) => c.destroy()); charts = []; }

  // ---- tree health dots ----
  function colorFor(node) {
    const s = statusMap[node.id];
    if (!s) return "var(--text-mute)";
    const prof = profiles.find((p) => p.id === node.profile_id);
    const iv = prof ? prof.interval_s : 60;
    if (Date.now() / 1000 - s.ts > iv * 3) return "var(--text-mute)";
    return lossDot(s.sent ? s.loss / s.sent : 0);
  }
  function applyStatus() {
    for (const d of dotEls) {
      const c = colorFor(d.node);
      d.el.style.background = c;
      d.el.style.boxShadow = c === "var(--text-mute)" ? "none" : `0 0 5px 0 ${c}`;
    }
  }
  async function refreshStatus() {
    try { const st = await api.status(); statusMap = {}; for (const s of st) statusMap[s.host_id] = s; applyStatus(); }
    catch (e) {}
  }

  function setRange(w) {
    windowSec = w;
    customRange = null;
    customBtn.classList.remove("on");
    [...rangeSeg.children].forEach((b, i) => b.className = RANGES[i].w === w ? "active" : "");
    for (const c of charts) if (c._range) c._window = w;
    loadSeries();
  }
  function setLiveOn(on) {
    live = on;
    liveToggle.classList.toggle("on", on);
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    if (on) { liveTimer = setInterval(() => loadSeries(true), 15000); loadSeries(true); }
  }

  // ---- node create/edit modal ----
  function openNodeModal({ parentId = null, node = null, kind = null }) {
    const editing = !!node;
    let curKind = node ? node.kind : (kind || "host");

    const kindSeg = h("div.seg",
      h("button", { class: curKind === "folder" ? "active" : "", onclick: () => setKind("folder") }, "Folder"),
      h("button", { class: curKind === "host" ? "active" : "", onclick: () => setKind("host") }, "Host"),
    );
    const name = h("input", { type: "text", placeholder: curKind === "folder" ? "Group name" : "My server", value: node ? node.name : "" });
    const host = h("input", { type: "text", placeholder: "IP or hostname", value: node && node.host ? node.host : "" });
    const desc = h("input", { type: "text", placeholder: "Optional description", value: node && node.description ? node.description : "" });
    const profSel = h("select", ...profiles.map((p) =>
      h("option", { value: p.id, selected: node ? node.profile_id === p.id : p.is_default }, profileLabel(p))));
    const err = h("p.error-text");

    const hostFields = h("div",
      h("label.field", h("span.lbl", "Address (IP or hostname)"), host),
      h("label.field", h("span.lbl", "Description"), desc),
      h("label.field", h("span.lbl", "Probe profile"), profSel),
    );

    function setKind(k) {
      curKind = k;
      kindSeg.children[0].className = k === "folder" ? "active" : "";
      kindSeg.children[1].className = k === "host" ? "active" : "";
      hostFields.style.display = k === "host" ? "" : "none";
    }
    setKind(curKind);

    const body = [
      editing ? null : h("label.field", h("span.lbl", "Type"), kindSeg),
      h("label.field", h("span.lbl", "Name"), name),
      hostFields,
      err,
    ];
    const m = modal(editing ? "Edit " + curKind : "Add node",
      editing ? null : "New node will be added " + (parentId ? "inside the selected folder." : "at the top level."),
      body,
      [
        h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"),
        h("button.btn.primary", { onclick: save }, editing ? "Save" : "Create"),
      ]);

    async function save() {
      err.textContent = "";
      const payload = {
        parent_id: editing ? node.parent_id : parentId,
        kind: curKind, name: name.value,
        host: curKind === "host" ? host.value : "",
        description: curKind === "host" ? desc.value : "",
        profile_id: curKind === "host" ? Number(profSel.value) : null,
      };
      try {
        if (editing) await api.updateNode(node.id, payload);
        else await api.createNode(payload);
        m.close();
        toast(editing ? "Saved" : "Created", "ok");
        await load();
      } catch (e) { err.textContent = e.message; }
    }
  }

  function delNode(n) {
    const extra = n.kind === "folder" ? " All nested hosts and their history will be removed." : " Its history will be removed.";
    confirmDialog("Delete " + n.kind + "?", `"${n.name}" will be deleted.` + extra, async () => {
      try { await api.deleteNode(n.id); if (selectedId === n.id) selectedId = null; toast("Deleted", "ok"); await load(); }
      catch (e) { toast(e.message, "err"); }
    });
  }
}

function lossDot(frac) {
  const stops = [[0, [74, 222, 128]], [0.05, [163, 230, 53]], [0.2, [250, 204, 21]], [0.5, [251, 146, 60]], [1, [248, 113, 113]]];
  if (frac <= 0) return "rgb(74,222,128)";
  for (let i = 1; i < stops.length; i++) {
    const [q1, c1] = stops[i - 1], [q2, c2] = stops[i];
    if (frac <= q2) { const t = (frac - q1) / (q2 - q1); return `rgb(${[0, 1, 2].map((k) => Math.round(c1[k] + (c2[k] - c1[k]) * t)).join(",")})`; }
  }
  return "rgb(248,113,113)";
}
function profileLabel(p) {
  return `${p.name} (${p.interval_s}s · ${p.ping_count}p · ${p.packet_size}B)${p.is_default ? " · default" : ""}`;
}
function findNode(nodes, id) {
  for (const n of nodes) {
    if (n.id === id) return n;
    if (n.children) { const f = findNode(n.children, id); if (f) return f; }
  }
  return null;
}
