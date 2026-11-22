// Smoke-graph chart: shaded percentile bands, loss-coloured median, loss strip,
// drag-to-zoom, tooltip, and a SmokePing-style legend. Built on uPlot.
import { h, chartStyle } from "./ui.js";

const BANDS = [
  ["p0",   "p100",  0.07, "min-max"],
  ["p2_5", "p97_5", 0.11, "p2.5-97.5"],
  ["p10",  "p90",   0.18, "p10-90"],
  ["p25",  "p75",   0.30, "p25-75"],
];
const LOSS_STOPS = [
  [0.00, [74, 222, 128]],
  [0.05, [163, 230, 53]],
  [0.20, [250, 204, 21]],
  [0.50, [251, 146, 60]],
  [1.00, [248, 113, 113]],
];
// Classic SmokePing discrete loss palette + binning, matching SmokePing's
// "loss colour" legend (0 green, then cyan/blue/purple/magenta/orange/red/darkred).
const SP_PALETTE = ["#00e000", "#00d0ff", "#0000ff", "#8a2be2", "#ff00ff", "#ff8c00", "#ff0000", "#a00000"];
const SP_THR = [0.10, 0.20, 0.30, 0.40, 0.50, 0.95, 1.0];
const CLASSIC_SMOKE = [74, 78, 88]; // grey smoke

const rgb = (c) => `rgb(${c[0]},${c[1]},${c[2]})`;
const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

function ramp(stops, frac) {
  if (frac <= 0) return rgb(stops[0][1]);
  for (let i = 1; i < stops.length; i++) {
    const [q1, c1] = stops[i - 1];
    const [q2, c2] = stops[i];
    if (frac <= q2) {
      const t = (frac - q1) / (q2 - q1);
      return rgb([0, 1, 2].map((k) => Math.round(c1[k] + (c2[k] - c1[k]) * t)));
    }
  }
  return rgb(stops.at(-1)[1]);
}
const lossColor = (frac) => ramp(LOSS_STOPS, frac);

function spLossColor(lost, sent) {
  if (!sent || lost <= 0) return SP_PALETTE[0];
  const f = lost / sent;
  for (let i = 0; i < SP_THR.length; i++) if (f <= SP_THR[i]) return SP_PALETTE[i + 1];
  return SP_PALETTE[7];
}
function spLossBins(sent) {
  const bins = [{ c: SP_PALETTE[0], label: "0" }];
  let prev = 0;
  for (let i = 0; i < SP_THR.length; i++) {
    const hi = Math.floor(SP_THR[i] * sent);
    const lo = prev + 1;
    bins.push({ c: SP_PALETTE[i + 1], label: i === SP_THR.length - 1 ? `${sent}/${sent}` : (hi <= lo ? `${Math.max(lo, hi)}` : `${lo}-${hi}`) });
    prev = hi;
  }
  return bins;
}
const getCss = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const themeVars = () => ({
  accent: getCss("--smoke-rgb").split(",").map(Number),
  aMul: parseFloat(getCss("--smoke-alpha-mul")) || 1,
  glow: parseFloat(getCss("--smoke-glow")) || 8,
});

// Stroke the median as one path per run of equal colour: a stroke() per
// colour change instead of per segment. Returns the number of strokes.
function strokeMedian(ctx, runs, X, Y, colorOf) {
  let n = 0;
  for (const run of runs) {
    let col = null;
    for (let i = 1; i < run.length; i++) {
      const a = run[i - 1], b = run[i], c = colorOf(b);
      if (c !== col) {
        if (col) ctx.stroke();
        ctx.strokeStyle = ctx.shadowColor = col = c; n++;
        ctx.beginPath(); ctx.moveTo(X(a.ts), Y(a.p50));
      }
      ctx.lineTo(X(b.ts), Y(b.p50));
    }
    if (col) ctx.stroke();
  }
  return n;
}
// Distinct median colours, counted without drawing (glow budget check).
function colourRuns(runs, colorOf) {
  let n = 0;
  for (const run of runs) { let col = null; for (let i = 1; i < run.length; i++) { const c = colorOf(run[i]); if (c !== col) { col = c; n++; } } }
  return n;
}
// Shadow blur is costly per stroke (and runs in Chrome's shared GPU process),
// so the glow is dropped when the median changes colour this often.
const GLOW_MAX_STROKES = 300;
// Median colour quantised to 5 % loss steps so runs stay long.
const medColor = (p) => lossColor(p.sent ? Math.round((p.loss / p.sent) * 20) / 20 : 0);

function smokePlugin(getData, getStep) {
  return { hooks: { draw(u) {
    const data = getData();
    if (!data || !data.length) return;
    const ctx = u.ctx, { left, top, width, height } = u.bbox, tv = themeVars(), dpr = devicePixelRatio;
    const classic = chartStyle() === "classic";
    const X = (t) => u.valToPos(t, "x", true), Y = (v) => u.valToPos(v, "y", true);
    ctx.save(); ctx.beginPath(); ctx.rect(left, top, width, height); ctx.clip();

    // column half-width: the bucket width, or the smallest spacing between raw cycles
    let step = getStep() || null;
    if (!step) { let prev = null; for (const p of data) { if (prev != null) { const d = p.ts - prev; if (step == null || d < step) step = d; } prev = p.ts; } }
    const colHalf = step ? Math.max(1, (X(step) - X(0)) / 2) : 3 * dpr;

    if (classic) {
      // ----- classic SmokePing: stepped grey columns + RRDtool-style median -----
      for (const [lo, hi, alpha] of BANDS) {
        ctx.fillStyle = rgba(CLASSIC_SMOKE, Math.min(0.55, alpha * 1.6));
        for (const p of data) {
          if (p[lo] == null) continue;
          const x = X(p.ts), yT = Y(p[hi]), yB = Y(p[lo]);
          ctx.fillRect(x - colHalf, yT, colHalf * 2, Math.max(1, yB - yT));
        }
      }
      // Median as a continuous LINE1 like RRDtool, coloured per sample by the
      // SmokePing loss palette. Per-sample dashes fall apart into dots once
      // columns shrink below ~1px (dense windows like 24h/7d).
      const spRuns = []; let spCur = null;
      for (const p of data) { if (p.p50 == null) { spCur = null; continue; } if (!spCur) { spCur = []; spRuns.push(spCur); } spCur.push(p); }
      ctx.lineWidth = 1.6 * dpr; ctx.lineJoin = "round"; ctx.lineCap = "butt";
      const dashH = 3 * dpr;
      strokeMedian(ctx, spRuns, X, Y, (p) => spLossColor(p.loss, p.sent));
      for (const run of spRuns) {
        if (run.length === 1) {
          const p = run[0];
          ctx.fillStyle = spLossColor(p.loss, p.sent);
          ctx.fillRect(X(p.ts) - colHalf, Y(p.p50) - dashH / 2, colHalf * 2, dashH);
        }
      }
      ctx.restore();
      // black axis frame + red RRDtool-style arrowheads (drawn outside the clip)
      ctx.save();
      ctx.strokeStyle = "#000"; ctx.lineWidth = 1 * dpr;
      ctx.strokeRect(left + 0.5, top + 0.5, width - 1, height - 1);
      ctx.fillStyle = "#cc0000";
      const a = 4 * dpr;
      ctx.beginPath(); ctx.moveTo(left, top - a * 1.7); ctx.lineTo(left - a, top); ctx.lineTo(left + a, top); ctx.closePath(); ctx.fill();
      ctx.beginPath(); ctx.moveTo(left + width + a * 1.7, top + height); ctx.lineTo(left + width, top + height - a); ctx.lineTo(left + width, top + height + a); ctx.closePath(); ctx.fill();
      ctx.restore();
      return;
    }

    // ----- modern: smooth bands + glowing loss-coloured median + loss strip -----
    const runs = []; let cur = null;
    for (const p of data) { if (p.p50 == null) { cur = null; continue; } if (!cur) { cur = []; runs.push(cur); } cur.push(p); }

    for (const [lo, hi, alpha] of BANDS) {
      ctx.fillStyle = rgba(tv.accent, Math.min(0.6, alpha * tv.aMul));
      for (const run of runs) {
        if (run.length < 2) continue;
        ctx.beginPath(); ctx.moveTo(X(run[0].ts), Y(run[0][hi]));
        for (let i = 1; i < run.length; i++) ctx.lineTo(X(run[i].ts), Y(run[i][hi]));
        for (let i = run.length - 1; i >= 0; i--) ctx.lineTo(X(run[i].ts), Y(run[i][lo]));
        ctx.closePath(); ctx.fill();
      }
    }
    ctx.lineWidth = 2 * dpr; ctx.lineJoin = "round"; ctx.lineCap = "round";
    ctx.shadowBlur = colourRuns(runs, medColor) <= GLOW_MAX_STROKES ? tv.glow * dpr : 0;
    strokeMedian(ctx, runs, X, Y, medColor);
    for (const run of runs) {
      if (run.length === 1) {
        const p = run[0]; ctx.fillStyle = lossColor(p.sent ? p.loss / p.sent : 0);
        ctx.beginPath(); ctx.arc(X(p.ts), Y(p.p50), 2.2 * dpr, 0, 7); ctx.fill();
      }
    }
    ctx.shadowBlur = 0;
    const stripH = 4 * dpr, stripY = top + height - stripH;
    for (const p of data) {
      const frac = p.sent ? p.loss / p.sent : 0; if (frac <= 0) continue;
      ctx.fillStyle = rgba([248, 113, 113], 0.35 + 0.6 * frac); ctx.fillRect(X(p.ts) - colHalf * 0.84, stripY, colHalf * 1.68, stripH);
    }
    ctx.restore();
  } } };
}

// uPlot data tuple: x, plus hidden min (p0) and max (p100) series so uPlot
// auto-ranges Y to the visible band extent (correct on zoom and reset).
const uData = (d) => [d.map((p) => p.ts), d.map((p) => p.p0), d.map((p) => p.p100)];

const fmtTime = (ts) => { const d = new Date(ts * 1000), p = (n) => String(n).padStart(2, "0"); return `${p(d.getDate())}.${p(d.getMonth() + 1)} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; };
const fmtDur = (s) => { s = Math.round(s); if (s < 60) return s + " s"; if (s < 3600) return Math.round(s / 60) + " min"; if (s < 86400) return (s / 3600).toFixed(1) + " h"; return (s / 86400).toFixed(1) + " d"; };

// buildChartCard(meta) -> { el, load(from, to, incremental), destroy() }
// meta.fetch(from, to, opts) returns a /api/series response {step, since, points, stats}.
export function buildChartCard(meta) {
  const chartEl = h("div.chart", { style: `height:${meta.height || 220}px` }, h("div.placeholder", { style: "min-height:0;border:0" }, "loading..."));
  const status = h("span.status");
  const lgRtt = h("div.lg-line.lg-rtt"), lgLoss = h("div.lg-line.lg-loss-stats"), lgCursor = h("div.lg-cursor");
  const lgBands = h("div.lg-bands"), lgBar = h("div.bar");
  const titleEl = meta.onTitle
    ? h("a.label.chart-link", { href: "#", title: "Open host", onclick: (e) => { e.preventDefault(); meta.onTitle(); } }, meta.title || meta.label)
    : h("span.label", meta.title || meta.label);
  const headParts = [titleEl];
  const sep = () => document.createTextNode("-");
  if (meta.ip) headParts.push(sep(), h("span.label", meta.ip));
  if (meta.sampling) headParts.push(sep(), h("span.desc-inline", meta.sampling));
  if (meta.description) headParts.push(sep(), h("span.desc-inline", meta.description));
  // classic (SmokePing/RRDtool) legend lines
  const spRtt = h("div.sp-line"), spLoss = h("div.sp-line"), spColors = h("div.sp-line"), spProbe = h("div.sp-line");
  const mark = h("span.rrd-mark", "Driftband");
  const el = h("div.chart-card",
    h("div.chart-head",
      status,
      h("div.label-line", { style: "min-width:0" }, ...headParts),
    ),
    chartEl,
    mark,
    h("div.legend.lg-modern",
      h("div.lg-stats", lgRtt, lgLoss, lgCursor),
      h("div.lg-keys", lgBands, h("div.lg-loss", h("span.lab", "loss"),
        h("div.lg-loss-wrap", lgBar,
          h("div.ticks", h("span", "0%"), h("span", "20%"), h("span", "50%"), h("span", "100%"))))),
    ),
    h("div.legend.sp-legend", spRtt, spLoss, spColors, spProbe),
  );

  let u = null, ro = null, tip = null;
  let base = null;     // last full-window response {step, points, stats}
  let detail = false;  // showing a finer re-fetch of a drag-zoomed range
  let data = [], step = 0; // what is drawn
  let zoomSeq = 0;
  const getData = () => data;
  const columns = () => Math.max(50, Math.round(chartEl.clientWidth || 1000));

  function buildKeys() {
    const tv = themeVars();
    const classic = chartStyle() === "classic";
    lgBands.innerHTML = "";
    for (const [lo, hi, a, lab] of [...BANDS].reverse()) {
      const bg = classic ? rgba(CLASSIC_SMOKE, Math.min(0.85, a * 2.4)) : rgba(tv.accent, Math.min(0.85, a * tv.aMul * 1.6));
      lgBands.append(h("span.b", h("span.sw", { style: `background:${bg}` }), lab));
    }
    lgBar.style.background = `linear-gradient(90deg,${LOSS_STOPS.map(([q, c]) => `${rgb(c)} ${q * 100}%`).join(",")})`;
  }

  // uPlot passes the visible data extent (computed after the x scale settles),
  // so this is correct on zoom and on double-click reset.
  function yRange(uu, dataMin, dataMax) {
    if (dataMin == null || !isFinite(dataMin)) return [0, 10];
    const pad = (dataMax - dataMin) * 0.14 || 1;
    return [Math.max(0, dataMin - pad), dataMax + pad];
  }

  function makePlot() {
    chartEl.innerHTML = "";
    const classic = chartStyle() === "classic";
    chartEl.classList.toggle("classic", classic);
    el.classList.toggle("classic", classic);
    const axStroke = classic ? "#000000" : getCss("--axis");
    const gridStroke = classic ? "rgba(210,0,0,0.40)" : getCss("--grid");
    const gridDash = classic ? [1, 3] : [];
    const yFont = classic ? "11px ui-monospace, monospace" : "11px Inter, sans-serif";
    const yVals = classic
      ? (uu, vals) => vals.map((v) => (v === 0 ? "0.0" : `${(+v).toFixed(1)} m`))
      : (uu, vals) => vals.map((v) => v + " ms");
    tip = h("div.smoke-tip"); chartEl.appendChild(tip);
    const opts = {
      width: chartEl.clientWidth || 600, height: chartEl.clientHeight || 220, padding: [10, 12, 0, 6],
      // sync only the cursor position across charts; keep drag-zoom (mousedown/
      // mouseup) and double-click reset local to the chart they happen on
      cursor: {
        sync: { key: "driftband", filters: { pub: (type) => type !== "mousedown" && type !== "mouseup" && type !== "dblclick" } },
        drag: { x: true, y: false }, points: { show: false }, y: false,
        // double-click after a detail zoom goes back to the full-window data
        bind: { dblclick: (self, targ, handler) => (e) => {
          if (e.button !== 0) return null;
          if (detail) { zoomSeq++; detail = false; show(base.points, base.step, false); return null; }
          return handler(e);
        } },
      },
      scales: { x: { time: true }, y: { range: yRange } },
      legend: { show: false },
      series: [{}, { scale: "y", stroke: "transparent", points: { show: false } }, { scale: "y", stroke: "transparent", points: { show: false } }],
      axes: [
        { stroke: axStroke, grid: { stroke: gridStroke, width: 1, dash: gridDash }, ticks: { stroke: gridStroke, width: 1, size: 4 }, font: yFont, space: 70 },
        { stroke: axStroke, grid: { stroke: gridStroke, width: 1, dash: gridDash }, ticks: { stroke: gridStroke, width: 1, size: 4 }, font: yFont, size: classic ? 60 : 48, label: classic ? "Seconds" : undefined, labelFont: "12px ui-monospace, monospace", values: yVals },
      ],
      hooks: { setCursor: [updateCursor], setSelect: [updateSelect] },
      plugins: [smokePlugin(getData, () => step)],
    };
    u = new uPlot(opts, uData(data), chartEl);
    ro = new ResizeObserver(() => u && u.setSize({ width: chartEl.clientWidth, height: chartEl.clientHeight }));
    ro.observe(chartEl);
  }

  function updateCursor(uu) {
    const idx = uu.cursor.idx;
    if (idx == null || !data[idx] || data[idx].p50 == null) {
      tip.style.opacity = 0;
      if (!uu.select || uu.select.width === 0) lgCursor.innerHTML = "";
      return;
    }
    const p = data[idx], frac = p.sent ? p.loss / p.sent : 0, f = (v) => (v == null ? "-" : v.toFixed(2));
    // built with h(): colours go through the CSSOM, which the CSP allows
    // (inline style attributes are not)
    tip.replaceChildren(
      h("div.t-time", `${fmtTime(p.ts)}${step ? ` · ${fmtDur(step)} avg` : ""}`),
      h("div.t-row", h("span.lab", h("span.t-dot", { style: `background:${lossColor(frac)}` }), "median"), h("span.t-med", `${f(p.p50)} ms`)),
      h("div.t-row", h("span.lab", "min - max"), h("span", `${f(p.p0)} - ${f(p.p100)}`)),
      h("div.t-row", h("span.lab", "p25 - p75"), h("span", `${f(p.p25)} - ${f(p.p75)}`)),
      h("div.t-row", h("span.lab", "loss"), h("span", { style: `color:${frac > 0 ? lossColor(frac) : "var(--text-dim)"}` }, `${(frac * 100).toFixed(0)}% · ${p.loss}/${p.sent}`)),
    );
    tip.style.left = uu.valToPos(p.ts, "x") + "px";
    tip.style.top = uu.valToPos(p.p50, "y") + "px";
    tip.style.opacity = 1;
    if (!uu.select || uu.select.width === 0) {
      lgCursor.innerHTML = `cursor: <span class="hl">${fmtTime(p.ts)}</span> · median <span class="hl">${f(p.p50)} ms</span> · loss <span class="hl">${(frac * 100).toFixed(0)}%</span>`;
    }
  }

  function updateSelect(uu) {
    const sel = uu.select; if (!sel || sel.width <= 2) return;
    const min = uu.posToVal(sel.left, "x"), max = uu.posToVal(sel.left + sel.width, "x");
    const pts = data.filter((p) => p.ts >= min && p.ts <= max && p.p50 != null); if (!pts.length) return;
    let sMin = Infinity, sMax = -Infinity, sum = 0, sent = 0, loss = 0;
    for (const p of pts) { if (p.p0 < sMin) sMin = p.p0; if (p.p100 > sMax) sMax = p.p100; sum += p.p50; sent += p.sent; loss += p.loss; }
    if (step > 0) zoomDetail(min, max);
    lgCursor.innerHTML = `selection: <span class="hl">${fmtDur(max - min)}</span> · median avg <span class="hl">${(sum / pts.length).toFixed(2)} ms</span> · range <span class="hl">${sMin.toFixed(1)}-${sMax.toFixed(1)} ms</span> · loss <span class="hl">${sent ? ((loss / sent) * 100).toFixed(1) : 0}%</span>`;
  }

  // Re-fetch a drag-zoomed range at full resolution for the zoomed width.
  async function zoomDetail(min, max) {
    const seq = ++zoomSeq;
    let r;
    try { r = await meta.fetch(Math.floor(min), Math.ceil(max), { points: columns() }); } catch (e) { return; }
    if (seq !== zoomSeq || !u) return;
    detail = true;
    data = r.points; step = r.step;
    u.setData(uData(data), false);
    u.setScale("x", { min, max });
  }

  // Draw points; keepZoom preserves a drag-zoom across data refreshes.
  function show(points, st, keepZoom) {
    const prev = data;
    data = points; step = st;
    if (!u) makePlot();
    else {
      const zoomed = keepZoom && prev.length && (u.scales.x.min > prev[0].ts + 1 || u.scales.x.max < prev.at(-1).ts - 1);
      const keep = zoomed ? { min: u.scales.x.min, max: u.scales.x.max } : null;
      u.setData(uData(data));
      if (keep) u.setScale("x", keep);
    }
    if (data.some((p) => p.p50 != null)) chartEl.querySelectorAll(".placeholder").forEach((n) => n.remove());
  }

  // Legend values come from the server, computed over every probe cycle in
  // the window (not over the downsampled columns).
  function updateLegend() {
    const s = (base && base.stats) || {};
    const avg = s.med_avg ?? null, mx = s.rtt_max ?? null, mn = s.rtt_min ?? null, sd = s.med_sd ?? null, now = s.now ?? null;
    const f = (v) => (v == null || !isFinite(v) ? "-" : v.toFixed(1));
    lgRtt.innerHTML = `<span class="lab">Median RTT</span> avg <b>${f(avg)}</b> · max <b>${f(mx)}</b> · min <b>${f(mn)}</b> · now <b>${f(now)}</b> ms · sd <b>${f(sd)}</b>`;
    const lp = s.sent ? ((s.sent - s.recv) / s.sent) * 100 : 0, maxL = s.loss_max || 0;
    lgLoss.replaceChildren(
      h("span.lab", "Packet loss"), " avg ",
      h("b", { style: `color:${lp > 0 ? lossColor(lp / 100) : "inherit"}` }, `${lp.toFixed(2)}%`), " · max ",
      h("b", { style: `color:${maxL > 0 ? lossColor(maxL) : "inherit"}` }, `${(maxL * 100).toFixed(0)}%`),
      " · cycles with loss ", h("b", String(s.loss_cycles || 0)), `/${s.cycles || 0}`,
    );
    const nowFrac = s.now_sent ? s.now_loss / s.now_sent : 0;
    const fresh = s.last && (Date.now() / 1000 - s.last) < (meta.interval || 60) * 3;
    let col = "var(--text-mute)";
    if (fresh && now != null) col = lossColor(nowFrac);
    status.style.background = col; status.style.boxShadow = fresh ? `0 0 9px 1px ${col}` : "none";

    // classic SmokePing legend block (monospace)
    const lossMax = s.loss_max || 0, lossMin = s.loss_min || 0, nowLoss = nowFrac * 100;
    const sent2 = meta.pings || s.now_sent || 20;
    spRtt.innerHTML = `<span class="spk">median rtt:</span> ${f(avg)} ms avg   ${f(mx)} ms max   ${f(mn)} ms min   ${f(now)} ms now   ${f(sd)} ms sd`;
    spLoss.innerHTML = `<span class="spk">packet loss:</span> ${lp.toFixed(2)} % avg   ${(lossMax * 100).toFixed(2)} % max   ${(lossMin * 100).toFixed(2)} % min   ${nowLoss.toFixed(2)} % now`;
    spColors.replaceChildren(h("span.spk", "loss color:"), " ",
      ...spLossBins(sent2).flatMap((b) => [h("span.sp-sq", { style: `background:${b.c}` }), b.label + "  "]));
    spProbe.innerHTML = `<span class="spk">probe:</span> ${sent2} ICMP Echo Pings (${meta.packet || 56} Bytes) every ${meta.interval || 60}s`;
  }

  buildKeys();
  const onTheme = () => { buildKeys(); if (u) { u.destroy(); makePlot(); } updateLegend(); };
  window.addEventListener("themechange", onTheme);
  window.addEventListener("chartstylechange", onTheme);

  return {
    el,
    // Load the window [from, to]. incremental: fetch only columns from the
    // last one on (same bucket width) and splice them in, trimming columns
    // that slid out of the window; stats are always for the whole window.
    async load(from, to, incremental) {
      const last = base && base.points.length ? base.points.at(-1) : null;
      if (incremental && last) {
        const r = await meta.fetch(from, to, { step: base.step, since: last.ts });
        const keepFrom = base.step ? Math.floor(from / base.step) * base.step : from;
        const kept = base.points.filter((p) => p.ts >= keepFrom && p.ts < r.since);
        base = { step: r.step, stats: r.stats, points: kept.concat(r.points) };
      } else {
        base = await meta.fetch(from, to, { points: columns() });
        if (detail) { zoomSeq++; detail = false; show(base.points, base.step, false); updateLegend(); return; }
      }
      if (!detail) show(base.points, base.step, true);
      updateLegend();
    },
    destroy() { window.removeEventListener("themechange", onTheme); window.removeEventListener("chartstylechange", onTheme); if (ro) ro.disconnect(); if (u) u.destroy(); },
  };
}
