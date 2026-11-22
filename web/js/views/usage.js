// Settings > Usage: how much monitoring data the organization stores, which
// hosts it comes from, how fast it grows and where it levels off for each
// retention the organization could choose.
//
// Colour is used for identity only: a host has the same colour in the
// per-day chart and in the list beside it, and the chosen retention is the
// one coloured line of the forecast. The palette (--viz-1..6, style.css) is
// checked for colour-vision deficiencies in both themes; every chart also
// has a table view.
import { api } from "../api.js";
import { h, clear, toast } from "../ui.js";

const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const fmtInt = (n) => Math.round(n).toLocaleString("en-US");
export function fmtSize(b) {
  if (!isFinite(b)) return "-";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(b < 10 ? 2 : 1) : Math.round(b)) + " " + u[i];
}
const fmtShort = (n) => n >= 1e9 ? (n / 1e9).toFixed(2) + " B" : n >= 1e6 ? (n / 1e6).toFixed(2) + " M" : n >= 1e4 ? (n / 1e3).toFixed(1) + " k" : fmtInt(n);
const ease = (t) => 1 - Math.pow(1 - t, 3);
const dateStr = (unix) => new Date(unix * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short" });
const dateLong = (unix) => new Date(unix * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
const FONT = "11px Inter, ui-sans-serif, system-ui, sans-serif";
const SERIES = 6; // hosts with a colour of their own; the rest are "Other"

function animate(ms, step) {
  if (reduced) { step(1); return; }
  const t0 = performance.now();
  const f = (now) => { const t = Math.min(1, (now - t0) / ms); step(ease(t)); if (t < 1) requestAnimationFrame(f); };
  requestAnimationFrame(f);
}
function countUp(el, to, fmt) { animate(900, (k) => (el.textContent = fmt(to * k))); }

// Colours are read when painting, so a theme switch repaints correctly.
function palette() {
  return {
    text: css("--text"), dim: css("--text-dim"), mute: css("--text-mute"), grid: css("--viz-grid"), surface: css("--surface"),
    series: Array.from({ length: SERIES }, (_, i) => css("--viz-" + (i + 1))), other: css("--viz-other"),
  };
}

// A canvas that tracks its box and repaints through draw(ctx, w, h, k, hover, P):
// k is the 0..1 entrance progress, hover the pointer position or null. draw
// returns { x, y, nodes } to show a tooltip.
function chart(height, label, draw) {
  const box = h("div.uchart", { role: "img", "aria-label": label });
  box.style.height = height + "px";
  const cv = h("canvas"); const tip = h("div.utip");
  box.append(cv, tip);
  let k = 0, hover = null;
  const paint = () => {
    const r = box.getBoundingClientRect(), dpr = Math.min(devicePixelRatio || 1, 2);
    if (!r.width) return;
    cv.width = r.width * dpr; cv.height = r.height * dpr;
    const ctx = cv.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const t = draw(ctx, r.width, r.height, k, hover, palette());
    if (t && hover) {
      clear(tip).append(...t.nodes);
      tip.style.left = Math.max(70, Math.min(r.width - 70, t.x)) + "px";
      tip.style.top = Math.max(t.y, 56) + "px";
      tip.style.opacity = 1;
    } else tip.style.opacity = 0;
  };
  new ResizeObserver(paint).observe(box);
  box.addEventListener("pointermove", (e) => { const r = box.getBoundingClientRect(); hover = { x: e.clientX - r.left, y: e.clientY - r.top }; paint(); });
  box.addEventListener("pointerleave", () => { hover = null; paint(); });
  const onTheme = () => { if (box.isConnected) paint(); else window.removeEventListener("themechange", onTheme); };
  window.addEventListener("themechange", onTheme);
  const io = new IntersectionObserver(([en]) => { if (en.isIntersecting) { io.disconnect(); animate(900, (v) => { k = v; paint(); }); } });
  io.observe(box);
  return box;
}

// Axis ticks on round numbers: 4 or 5 steps of 1, 2 or 5 x 10^n.
function niceTicks(max, unit = 1) {
  const raw = Math.max(max, unit) / 4 / unit, p = Math.pow(10, Math.floor(Math.log10(raw))), m = raw / p;
  const step = (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p * unit;
  const out = [];
  for (let v = 0; v < max + step; v += step) out.push(v);
  return out;
}
// Sizes get ticks that are round in their own unit (MB, GB).
function sizeTicks(max) {
  let unit = 1;
  while (max / unit >= 1024 && unit < 1024 ** 4) unit *= 1024;
  return niceTicks(max, unit);
}
function grid(ctx, L, T, pw, ph, ticks, P, fmt) {
  const top = ticks[ticks.length - 1];
  ctx.font = FONT; ctx.textAlign = "right"; ctx.textBaseline = "middle";
  for (const v of ticks) {
    const y = Math.round(T + ph - (v / top) * ph) + 0.5;
    ctx.strokeStyle = P.grid; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(L + pw, y); ctx.stroke();
    ctx.fillStyle = P.mute; ctx.fillText(fmt(v), L - 8, y);
  }
  ctx.textBaseline = "alphabetic";
}

const swatch = (color, cls = "") => { const s = h("span.usw" + cls); s.style.background = color; return s; };
const tipRow = (color, name, value) => h("div.utip-row", swatch(color), h("span.utip-name", name), h("b", value));

// A card whose chart can be swapped for the same numbers as a table.
function chartCard(title, sub, legend, chartEl, table) {
  const tbl = h("div.utable", { hidden: true }, table);
  const btn = h("button.btn.sm.ghost", { type: "button", "aria-pressed": "false", onclick: () => {
    const on = tbl.hidden;
    tbl.hidden = !on; chartEl.hidden = on; if (legend) legend.hidden = on;
    btn.textContent = on ? "Chart" : "Table"; btn.setAttribute("aria-pressed", String(on));
  } }, "Table");
  return h("div.card", h("div.spread.ucard-head", h("div", h("h2", title), h("p.sub", sub)), btn), legend, chartEl, tbl);
}

// ----- stat tiles -----
function tile(label, sub, ...extra) {
  const v = h("div.ukpi-val", "0");
  return { el: h("div.ukpi", h("div.ukpi-lbl", label), v, sub ? h("div.ukpi-sub", sub) : null, ...extra), v };
}
function meter(fraction, color) {
  const fill = h("span");
  fill.style.background = color;
  requestAnimationFrame(() => animate(900, (k) => (fill.style.width = Math.max(0, Math.min(1, fraction)) * 100 * k + "%")));
  return h("div.umeter", fill);
}
// The last 30 days as a line: the tile's number is the total, this is its shape.
function sparkline(values) {
  const cv = h("canvas.uspark", { "aria-hidden": "true" });
  const paint = () => {
    const r = cv.getBoundingClientRect(), dpr = Math.min(devicePixelRatio || 1, 2);
    if (!r.width) return;
    cv.width = r.width * dpr; cv.height = r.height * dpr;
    const ctx = cv.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const P = palette(), max = Math.max(1, ...values), w = r.width - 6, hh = r.height - 6;
    const X = (i) => 3 + (i / (values.length - 1)) * w, Y = (v) => 3 + hh - (v / max) * hh;
    ctx.beginPath(); values.forEach((v, i) => (i ? ctx.lineTo(X(i), Y(v)) : ctx.moveTo(X(i), Y(v))));
    ctx.strokeStyle = P.series[0]; ctx.lineWidth = 2; ctx.lineJoin = ctx.lineCap = "round"; ctx.stroke();
    ctx.lineTo(X(values.length - 1), 3 + hh); ctx.lineTo(X(0), 3 + hh); ctx.closePath();
    ctx.globalAlpha = 0.1; ctx.fillStyle = P.series[0]; ctx.fill(); ctx.globalAlpha = 1;
  };
  new ResizeObserver(paint).observe(cv);
  window.addEventListener("themechange", function onTheme() { if (cv.isConnected) paint(); else window.removeEventListener("themechange", onTheme); });
  return cv;
}

export async function usageTab(body) {
  const wrap = h("div.stack", h("div.card", "Loading..."));
  body.append(wrap);
  let u;
  try { u = await api.usage(); } catch (e) { toast(e.message, "err"); return; }
  const years = (n) => `${n} year${n > 1 ? "s" : ""}`;

  // ----- hosts: the six that store the most keep a colour everywhere -----
  const hosts = u.top_hosts.filter((x) => x.records > 0);
  const top = hosts.slice(0, SERIES);
  const colorVar = (i) => (i < SERIES ? `var(--viz-${i + 1})` : "var(--viz-other)");

  // ----- stat tiles -----
  const days = fill30(u.daily);
  const t1 = tile("Measurements stored", "probe cycles, each with every ping", sparkline(days.map((d) => d.records)),
    h("div.ukpi-note", "per day, last 30 days"));
  const split = u.bytes > 0 ? [["Every ping, full resolution", u.raw_bytes, "var(--viz-1)"], ["Summaries for long ranges", u.summary_bytes, "var(--viz-3)"]] : [];
  const seg = h("div.useg", ...split.map(([, b, c]) => { const s = h("span"); s.style.background = c; s.style.flexGrow = String(Math.max(b, u.bytes * 0.02)); return s; }));
  const t2 = tile("Data stored", null, split.length ? seg : null,
    ...split.map(([name, b, c]) => h("div.ukpi-key", swatch(c), h("span", name), h("b", fmtSize(b)))));
  const t3 = tile("Growth", `${fmtInt(u.records_per_day)} measurements a day`,
    h("div.ukpi-key", h("span", "in 30 days"), h("b", fmtSize(u.in_30_days))),
    h("div.ukpi-key", h("span", "in a year"), h("b", fmtSize(u.in_365_days))));
  const filled = u.steady_bytes > 0 ? u.bytes / u.steady_bytes : 1;
  const t4 = tile(`Full ${years(u.retention_years)} of history`, null, meter(filled, "var(--viz-1)"),
    h("div.ukpi-note", u.steady_in_days > 0 ? `${Math.round(filled * 100)}% there, reached in ${fmtInt(u.steady_in_days)} days` : "reached: old data now leaves as new arrives"));
  const tiles = h("div.ukpis", t1.el, t2.el, t3.el, t4.el);
  if (u.host_limit) {
    const full = u.host_count >= u.host_limit;
    const t5 = tile("Hosts", null, meter(u.host_count / u.host_limit, full ? "var(--bad)" : "var(--viz-1)"),
      h("div.ukpi-note", full ? "limit reached" : `${u.host_limit - u.host_count} more allowed`));
    t5.v.textContent = `${u.host_count} / ${u.host_limit}`;
    tiles.append(t5.el);
  }

  // ----- measurements per day, stacked by host -----
  const byDay = new Map();
  for (const d of u.daily_by_host || []) { if (!byDay.has(d.day)) byDay.set(d.day, new Map()); byDay.get(d.day).set(d.id, d.records); }
  const stacks = days.map((d) => {
    const m = byDay.get(d.day) || new Map();
    const parts = top.map((x, i) => ({ name: x.name, i, v: m.get(x.id) || 0 }));
    const other = Math.max(0, d.records - parts.reduce((a, p) => a + p.v, 0));
    if (hosts.length > SERIES || other > 0) parts.push({ name: "Other hosts", i: SERIES, v: other });
    return { day: d.day, total: d.records, parts };
  });
  const hasOther = stacks.some((s) => s.parts.length > top.length);
  const bars = chart(250, "Measurements stored per day over the last 30 days, by host", (ctx, w, hgt, k, hover, P) => {
    const L = 46, R = 8, T = 12, B = 26, pw = w - L - R, ph = hgt - T - B;
    const ticks = niceTicks(Math.max(1, ...stacks.map((s) => s.total)));
    const topV = ticks[ticks.length - 1];
    grid(ctx, L, T, pw, ph, ticks, P, fmtShort);
    const slot = pw / stacks.length, bw = Math.min(24, Math.max(3, slot - 4)), base = T + ph;
    let tip = null;
    stacks.forEach((s, i) => {
      const x = L + i * slot + (slot - bw) / 2;
      const on = hover && hover.x >= L + i * slot && hover.x < L + (i + 1) * slot;
      ctx.globalAlpha = hover && !on ? 0.4 : 1;
      let y = base;
      const live = s.parts.filter((p) => p.v > 0);
      live.forEach((p, n) => {
        const hh = (p.v * k / topV) * ph, last = n === live.length - 1;
        // a 2px gap in the surface colour separates the segments
        const gap = last || hh < 4 ? 0 : 2;
        ctx.fillStyle = p.i < SERIES ? P.series[p.i] : P.other;
        ctx.beginPath();
        if (last) ctx.roundRect(x, y - hh, bw, hh, [Math.min(4, hh), Math.min(4, hh), 0, 0]); else ctx.rect(x, y - hh + gap, bw, hh - gap);
        ctx.fill();
        y -= hh;
      });
      ctx.globalAlpha = 1;
      if (on) tip = { x: x + bw / 2, y: Math.min(y, base - 30) - 8, nodes: [
        h("div.utip-head", dateStr(s.day), h("b", fmtInt(s.total))),
        ...[...live].reverse().map((p) => tipRow(p.i < SERIES ? P.series[p.i] : P.other, p.name, fmtInt(p.v)))] };
      if (i % 5 === 0 || i === stacks.length - 1) { ctx.fillStyle = P.mute; ctx.font = FONT; ctx.textAlign = "center"; ctx.fillText(dateStr(s.day), L + i * slot + slot / 2, hgt - 8); }
    });
    return tip;
  });
  const cols = [...top.map((x) => x.name), ...(hasOther ? ["Other hosts"] : [])];
  const dayTable = h("table.tbl",
    h("thead", h("tr", h("th", "Day"), h("th", "All hosts"), ...cols.map((c) => h("th", c)))),
    h("tbody", ...[...stacks].reverse().map((s) => h("tr", h("td", dateLong(s.day)), h("td", fmtInt(s.total)),
      ...cols.map((_, i) => h("td", fmtInt((s.parts[i] || { v: 0 }).v)))))));

  // ----- per host: the list is also the legend of the chart -----
  const maxR = Math.max(1, ...hosts.map((x) => x.records));
  const hostList = h("div.uhosts", ...hosts.map((x, i) => {
    const bar = h("span.ubar-fill"); bar.style.background = colorVar(i);
    requestAnimationFrame(() => animate(900, (k) => (bar.style.width = (x.records / maxR) * 100 * k + "%")));
    return h("div.uhost", swatch(colorVar(i)), h("span.uhost-name", { title: x.name }, x.name), h("span.ubar", bar),
      h("span.uhost-val", fmtShort(x.records)), h("span.uhost-pct", u.records ? Math.round((x.records / u.records) * 100) + "%" : ""));
  }));

  // ----- forecast for each retention option -----
  const opts = u.retention_options || [];
  const now = Math.floor(Date.now() / 1000);
  const mine = opts.find((o) => o.years === u.retention_years) || opts[0];
  const forecast = chart(300, "Projected stored data over three years for 1, 2 and 3 years of retention", (ctx, w, hgt, k, hover, P) => {
    const L = 64, R = 126, T = 18, B = 28, pw = w - L - R, ph = hgt - T - B;
    const maxD = 3 * 365;
    const ticks = sizeTicks(Math.max(1, ...opts.map((o) => o.steady_bytes), u.bytes) * 1.05);
    const topV = ticks[ticks.length - 1];
    const X = (d) => L + (d / maxD) * pw, Y = (b) => T + ph - (b / topV) * ph;
    grid(ctx, L, T, pw, ph, ticks, P, fmtSize);
    ctx.fillStyle = P.mute; ctx.font = FONT; ctx.textAlign = "center";
    for (let m = 0; m <= 36; m += 6) ctx.fillText(m === 0 ? "today" : m % 12 === 0 ? `+${m / 12} y` : `+${m} mo`, X(m * 30.4), hgt - 8);

    const path = (o) => { ctx.beginPath(); o.points.forEach((p, i) => (i ? ctx.lineTo(X(p.day), Y(p.bytes)) : ctx.moveTo(X(p.day), Y(p.bytes)))); };
    ctx.save(); ctx.beginPath(); ctx.rect(L - 2, 0, (pw + 4) * k, hgt); ctx.clip(); // revealed left to right
    ctx.lineJoin = ctx.lineCap = "round";
    for (const o of opts) if (o !== mine) { path(o); ctx.strokeStyle = P.other; ctx.lineWidth = 1.5; ctx.stroke(); }
    if (mine) {
      path(mine); ctx.lineTo(X(maxD), Y(0)); ctx.lineTo(X(0), Y(0)); ctx.closePath();
      ctx.globalAlpha = 0.1; ctx.fillStyle = P.series[0]; ctx.fill(); ctx.globalAlpha = 1;
      path(mine); ctx.strokeStyle = P.series[0]; ctx.lineWidth = 2; ctx.stroke();
    }
    ctx.restore();
    const dot = (x, y, color, r = 4) => { ctx.beginPath(); ctx.arc(x, y, r + 2, 0, 7); ctx.fillStyle = P.surface; ctx.fill(); ctx.beginPath(); ctx.arc(x, y, r, 0, 7); ctx.fillStyle = color; ctx.fill(); };
    if (k > 0.98) {
      // where each option stops growing
      for (const o of opts) if (o.steady_in_days > 0 && o.steady_in_days <= maxD) dot(X(o.steady_in_days), Y(o.steady_bytes), o === mine ? P.series[0] : P.other, 3);
      dot(X(0), Y(u.bytes), P.text);
      // direct labels at the line ends; options that end together share one
      const ends = opts.map((o) => ({ o, y: Y(o.points[o.points.length - 1].bytes) })).sort((a, b) => a.y - b.y);
      const groups = [];
      for (const e of ends) { const g = groups[groups.length - 1]; if (g && e.y - g.y < 15) g.list.push(e.o); else groups.push({ y: e.y, list: [e.o] }); }
      ctx.textAlign = "left"; ctx.textBaseline = "middle";
      for (const g of groups) {
        const ys = g.list.map((o) => o.years).sort();
        const name = ys.length === 1 ? years(ys[0]) : ys.length === 3 ? "1 to 3 years" : `${ys[0]} and ${ys[1]} years`;
        const own = g.list.includes(mine);
        ctx.font = (own ? "600 " : "") + FONT; ctx.fillStyle = own ? P.text : P.dim;
        ctx.fillText(name, X(maxD) + 8, g.y - 7);
        ctx.font = FONT; ctx.fillStyle = P.mute;
        ctx.fillText(fmtSize(g.list[0].points[g.list[0].points.length - 1].bytes), X(maxD) + 8, g.y + 7);
      }
      ctx.textBaseline = "alphabetic";
    }
    if (!hover || hover.x < L || hover.x > L + pw || !opts.length) return null;
    const d = Math.max(0, Math.min(maxD, ((hover.x - L) / pw) * maxD));
    const idx = mine.points.reduce((best, p, i) => (Math.abs(p.day - d) < Math.abs(mine.points[best].day - d) ? i : best), 0);
    const day = mine.points[idx].day, x = Math.round(X(day)) + 0.5;
    ctx.strokeStyle = P.mute; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(x, T); ctx.lineTo(x, T + ph); ctx.stroke();
    for (const o of opts) dot(X(day), Y(o.points[idx].bytes), o === mine ? P.series[0] : P.other, 3.5);
    return { x: X(day), y: Y(Math.max(...opts.map((o) => o.points[idx].bytes))) - 12, nodes: [
      h("div.utip-head", day === 0 ? "today" : dateLong(now + day * 86400)),
      ...[...opts].reverse().map((o) => tipRow(o === mine ? P.series[0] : P.other, years(o.years) + (o === mine ? " (yours)" : ""), fmtSize(o.points[idx].bytes)))] };
  });
  const lineKey = (color, text) => h("span.ulegend-item", swatch(color, ".line"), text);
  const fcLegend = h("div.ulegend", lineKey("var(--viz-1)", `Your retention: ${years(u.retention_years)}`), lineKey("var(--viz-other)", "The other options"));
  const marks = [0, 90, 180, 365, 730, 1095];
  const at = (o, d) => o.points.reduce((a, p) => (Math.abs(p.day - d) < Math.abs(a.day - d) ? p : a)).bytes;
  const fcTable = h("table.tbl",
    h("thead", h("tr", h("th", "When"), ...opts.map((o) => h("th", years(o.years) + (o === mine ? " (yours)" : ""))))),
    h("tbody",
      ...marks.map((d) => h("tr", h("td", d === 0 ? "today" : d < 365 ? `in ${d / 30} months` : `in ${years(d / 365)}`), ...opts.map((o) => h("td", fmtSize(at(o, d)))))),
      h("tr", h("td", "stops growing"), ...opts.map((o) => h("td", o.steady_in_days > 0 ? `in ${fmtInt(o.steady_in_days)} days` : "already")))));

  clear(wrap).append(
    h("div.card", h("h2", "Usage"), h("p.sub", "How much monitoring data your organization keeps, which hosts it comes from, how fast it grows, and where it levels off once data older than the retention window is removed."), tiles),
    h("div.ugrid",
      chartCard("Measurements per day", "Probe cycles stored over the last 30 days. Each colour is a host from the list.", null, bars, dayTable),
      h("div.card", h("h2", "Where your data lives"), h("p.sub", hasOther ? "Hosts with the most stored measurements. Hosts in grey are \"Other hosts\" in the chart." : "Hosts with the most stored measurements."),
        hosts.length ? hostList : h("p.muted", "No data yet."))),
    chartCard("Storage forecast", `Projected from your hosts' probe intervals. Growth stops once the oldest data reaches the retention age, so a longer retention levels off later and higher. Yours is ${years(u.retention_years)}.`,
      fcLegend, forecast, fcTable),
  );
  countUp(t1.v, u.records, fmtInt);
  countUp(t2.v, u.bytes, fmtSize);
  countUp(t3.v, u.bytes_per_day, (v) => "+" + fmtSize(v) + " a day");
  countUp(t4.v, u.steady_bytes, fmtSize);
}

function fill30(daily) {
  const map = new Map(daily.map((d) => [d.day, d.records]));
  const today = new Date(); today.setUTCHours(0, 0, 0, 0);
  const out = [];
  for (let i = 29; i >= 0; i--) { const day = today.getTime() / 1000 - i * 86400; out.push({ day, records: map.get(day) || 0 }); }
  return out;
}
