// Small DOM + UI helpers (no framework).

// h("div.cls#id", {attr:val, onclick:fn}, ...children)
export function h(tag, attrs, ...kids) {
  let el;
  const m = tag.match(/^([a-z0-9]+)?/i);
  const name = (m && m[1]) || "div";
  el = document.createElement(name);
  const idm = tag.match(/#([\w-]+)/);
  if (idm) el.id = idm[1];
  const cls = [...tag.matchAll(/\.([\w-]+)/g)].map((x) => x[1]);
  if (cls.length) el.className = cls.join(" ");
  if (attrs && (attrs.nodeType || typeof attrs !== "object" || Array.isArray(attrs))) {
    kids.unshift(attrs); attrs = null;
  }
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = (el.className ? el.className + " " : "") + v;
      else if (k === "html") el.innerHTML = v;
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (k in el && k !== "list") { try { el[k] = v; } catch (e) { el.setAttribute(k, v); } }
      else el.setAttribute(k, v);
    }
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }

// ----- theme -----
export function currentTheme() {
  try { return localStorage.getItem("driftband-theme") || "dark"; } catch (e) { return "dark"; }
}
export function applyTheme(name) {
  document.documentElement.setAttribute("data-theme", name);
  try { localStorage.setItem("driftband-theme", name); } catch (e) {}
  window.dispatchEvent(new CustomEvent("themechange", { detail: name }));
}
export function toggleTheme() {
  applyTheme(currentTheme() === "dark" ? "light" : "dark");
}

// ----- wide layout -----
export function isWide() {
  try { return localStorage.getItem("driftband-wide") === "1"; } catch (e) { return false; }
}
export function setWide(on) {
  try { localStorage.setItem("driftband-wide", on ? "1" : "0"); } catch (e) {}
  const app = document.querySelector(".app");
  if (app) app.classList.toggle("wide", on);
}

// ----- chart style (modern | classic SmokePing look) -----
export function chartStyle() {
  try { return localStorage.getItem("driftband-chartstyle") || "modern"; } catch (e) { return "modern"; }
}
export function setChartStyle(s) {
  try { localStorage.setItem("driftband-chartstyle", s); } catch (e) {}
  window.dispatchEvent(new CustomEvent("chartstylechange", { detail: s }));
}

// ----- small localStorage JSON helpers (e.g. tree state) -----
export function loadJSON(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; }
}
export function saveJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) {}
}

// ----- paging -----
export const PAGE_SIZES = [10, 20, 50, 100, 200];

// pager(key, load): rows-per-page select, "11-20 of 137" and Previous/Next
// for a server-paged list. load() is called whenever the page or its size
// changes and reads .limit / .offset; it reports the total with .set(total).
// The chosen size is remembered per list (key).
export function pager(key, load) {
  let size = Number(loadJSON("driftband-page-" + key, PAGE_SIZES[0]));
  if (!PAGE_SIZES.includes(size)) size = PAGE_SIZES[0];
  let offset = 0, total = 0;
  const sel = h("select", { "aria-label": "Rows per page" }, ...PAGE_SIZES.map((n) => h("option", { value: n }, String(n))));
  sel.value = String(size);
  const info = h("span.pager-info");
  const prev = h("button.btn.sm.ghost", { onclick: () => go(offset - size) }, "Previous");
  const next = h("button.btn.sm.ghost", { onclick: () => go(offset + size) }, "Next");
  const el = h("div.pager", h("label.pager-size", h("span", "Rows per page"), sel), info, h("div.pager-nav", prev, next));
  sel.addEventListener("change", () => { size = Number(sel.value); saveJSON("driftband-page-" + key, size); offset = 0; load(); });
  function go(o) { offset = Math.max(0, o); load(); }
  function draw() {
    info.textContent = total ? `${offset + 1}-${Math.min(offset + size, total)} of ${total}` : "0 of 0";
    prev.disabled = offset <= 0;
    next.disabled = offset + size >= total;
  }
  draw();
  return {
    el,
    get limit() { return size; },
    get offset() { return offset; },
    reset() { offset = 0; },
    // Returns false when the page fell off the end (rows were removed):
    // the pager moved to the last page and called load() again.
    set(t) {
      total = t;
      if (total > 0 && offset >= total) { offset = Math.floor((total - 1) / size) * size; load(); return false; }
      draw();
      return true;
    },
  };
}

// ----- avatar -----
// A user's picture (u.avatar is its version tag) or their initials on a
// colour derived from the email, so the same person always looks the same.
export function avatar(u, size = 28) {
  const name = [u.first_name, u.last_name].filter(Boolean).join(" ").trim();
  const el = h("span.avatar", { title: name || u.email || "" });
  el.style.width = el.style.height = size + "px";
  el.style.fontSize = Math.max(10, Math.round(size * 0.4)) + "px";
  if (u.avatar) {
    el.append(h("img", { src: `/api/users/${u.id}/avatar?v=${encodeURIComponent(u.avatar)}`, alt: "", width: size, height: size }));
    return el;
  }
  const words = (name || (u.email || "?").split("@")[0].replace(/[._-]+/g, " ")).split(/\s+/).filter(Boolean);
  el.textContent = ((words[0] || "?")[0] + (words.length > 1 ? words[words.length - 1][0] : "")).toUpperCase();
  let hash = 0;
  for (const c of u.email || name) hash = (hash * 31 + c.charCodeAt(0)) >>> 0;
  el.style.background = `hsl(${hash % 360} 42% 40%)`;
  return el;
}

// ----- toast -----
export function toast(msg, kind = "") {
  const box = document.getElementById("toasts");
  const t = h("div.toast" + (kind ? "." + kind : ""), msg);
  box.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .25s"; setTimeout(() => t.remove(), 250); }, 3200);
}

// ----- modal -----
export function modal(title, sub, bodyNodes, actions) {
  const back = h("div.modal-back", { onclick: (e) => { if (e.target === back) close(); } });
  function close() { back.remove(); document.removeEventListener("keydown", onKey); }
  function onKey(e) { if (e.key === "Escape") close(); }
  document.addEventListener("keydown", onKey);
  const box = h("div.modal",
    h("h3", title),
    sub ? h("p.sub", sub) : null,
    ...(Array.isArray(bodyNodes) ? bodyNodes : [bodyNodes]),
    h("div.modal-actions", ...(actions || []).map((a) => a)),
  );
  back.appendChild(box);
  document.body.appendChild(back);
  return { close, back };
}

export function confirmDialog(title, sub, onYes, yesLabel = "Delete", danger = true) {
  const m = modal(title, sub, [], [
    h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"),
    h("button.btn" + (danger ? ".danger" : ".primary"), { onclick: async () => { m.close(); await onYes(); } }, yesLabel),
  ]);
}

// ----- time formatting -----
export function fmtDateTime(unix) {
  const d = new Date(unix * 1000), p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
export function fmtUntil(unix) {
  const s = Math.floor(unix - Date.now() / 1000);
  if (s <= 0) return "expired";
  if (s < 3600) return Math.floor(s / 60) + "m left";
  if (s < 86400) return Math.floor(s / 3600) + "h left";
  return Math.floor(s / 86400) + "d left";
}
export function fmtRelative(unix) {
  const s = Math.floor(Date.now() / 1000 - unix);
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

// ----- icons (inline svg strings) -----
const svg = (p) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="100%" height="100%">${p}</svg>`;
export const icons = {
  sun:    svg(`<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/>`),
  moon:   svg(`<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>`),
  folder: svg(`<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>`),
  host:   svg(`<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>`),
  plus:   svg(`<path d="M12 5v14M5 12h14"/>`),
  edit:   svg(`<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>`),
  trash:  svg(`<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>`),
  chevron:svg(`<path d="M9 18l6-6-6-6"/>`),
};
