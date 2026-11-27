// Platform administration (superadmins only): organizations and their users,
// database usage with a forecast, the global audit log and instance settings.
import { api } from "../api.js";
import { h, clear, toast, modal, confirmDialog, fmtDateTime, fmtRelative, pager } from "../ui.js";

const TABS = [
  { id: "orgs", label: "Organizations" },
  { id: "usage", label: "Usage & forecast" },
  { id: "audit", label: "Global audit log" },
  { id: "settings", label: "Settings" },
];

export function renderAdmin(mount, ctx) {
  clear(mount);
  let tab = ctx.tab || "orgs";
  const tabsEl = h("div.tabs", ...TABS.map((t) =>
    h("button", { class: t.id === tab ? "active" : "", onclick: () => { tab = t.id; draw(); } }, t.label)));
  const body = h("div");
  mount.append(h("div.section-title", h("h2", "Platform admin")), tabsEl, body);

  function draw() {
    [...tabsEl.children].forEach((b, i) => b.className = TABS[i].id === tab ? "active" : "");
    clear(body);
    if (tab === "orgs") orgsTab(body, ctx);
    else if (tab === "usage") usageTab(body);
    else if (tab === "settings") settingsTab(body);
    else auditTab(body);
  }
  draw();
}

export function fmtBytes(n) {
  if (n == null || !isFinite(n)) return "-";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0; while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 2 : 1) : String(Math.round(n))) + " " + u[i];
}
const fmtNum = (n) => (n ?? 0).toLocaleString("en-US");
const scroll = (el) => h("div", { style: "overflow-x:auto" }, el);
const when = (ts) => ts ? h("span", { title: fmtDateTime(ts) }, fmtRelative(ts)) : h("span.muted", "never");

// ---------- Organizations ----------
async function orgsTab(body, ctx) {
  const orgsCard = h("div.card", h("h2", "Organizations"), h("div", "Loading..."));
  const usersCard = h("div.card", { hidden: true });
  const hostsCard = h("div.card", { hidden: true });
  body.append(h("div.stack", orgsCard, usersCard, hostsCard));
  let selected = null;

  async function refreshOrgs() {
    let orgs;
    try { orgs = await api.adminOrgs(); } catch (e) { toast(e.message, "err"); return; }
    clear(orgsCard).append(h("h2", "Organizations"),
      h("p.sub", `${orgs.length} organizations. Blocking signs everyone out, refuses sign-in and pauses probing.`));
    orgsCard.append(scroll(h("table.tbl",
      h("thead", h("tr", ...["Organization", "Status", "Users", "Hosts", "Stored cycles", "Est. size", "Retention", "Last sign-in", "Created", ""].map((t) => h("th", t)))),
      h("tbody", ...orgs.map((o) => {
        const own = o.id === ctx.me.org.id;
        return h("tr", { style: o.id === selected ? "background:var(--surface-2)" : "" },
          h("td", h("a", { href: "#", onclick: (e) => { e.preventDefault(); selected = o.id; showUsers(o); refreshOrgs(); } }, o.name),
            own ? h("span.badge.muted", { style: "margin-left:8px" }, "yours") : null),
          h("td", o.disabled ? h("span.badge.bad", "blocked") : h("span.badge.ok", "active")),
          h("td", fmtNum(o.users)),
          h("td", { title: o.host_limit == null ? "instance default" : "set for this organization" },
            fmtNum(o.hosts), " / ", o.effective_host_limit ? fmtNum(o.effective_host_limit) : "∞",
            o.exempt_limits ? h("span.badge.accent", { style: "margin-left:6px", title: "Exempt from test-instance limits" }, "exempt") : null,
            h("button.btn.sm.ghost", { style: "margin-left:4px;padding:3px 7px", onclick: () => editLimit(o) }, "edit")),
          h("td", fmtNum(o.samples)),
          h("td", fmtBytes(o.est_bytes)), h("td", o.retention_years + " y"),
          h("td", when(o.last_login)), h("td", fmtDateTime(o.created_at)),
          h("td", { style: "text-align:right;white-space:nowrap" },
            h("button.btn.sm.ghost", { onclick: () => { selected = o.id; showUsers(o); refreshOrgs(); } }, "Users"),
            h("button.btn.sm.ghost", { onclick: () => { selected = o.id; showHosts(o); refreshOrgs(); } }, "Hosts"),
            own ? null : h("button.btn.sm.ghost", { onclick: () => confirmDialog(
              o.disabled ? `Unblock ${o.name}?` : `Block ${o.name}?`,
              o.disabled ? "Members can sign in again and probing resumes."
                         : "All members are signed out and cannot sign in; its hosts stop being probed. Data is kept.",
              async () => { try { await api.adminBlockOrg(o.id, !o.disabled); toast(o.disabled ? "Organization unblocked" : "Organization blocked", "ok"); await refreshOrgs(); if (selected === o.id) showUsers({ ...o, disabled: !o.disabled }); } catch (e) { toast(e.message, "err"); } },
              o.disabled ? "Unblock" : "Block", !o.disabled) }, o.disabled ? "Unblock" : "Block"),
            own ? null : h("button.btn.sm.ghost", { onclick: () => deleteOrg(o) }, "Delete")),
        );
      })))));
  }

  // The hosts an organization monitors, with the parameters the prober uses.
  async function showHosts(o) {
    hostsCard.hidden = false;
    clear(hostsCard).append(h("h2", `Hosts of ${o.name}`), h("div", "Loading..."));
    let hosts;
    try { hosts = await api.adminOrgHosts(o.id); } catch (e) { toast(e.message, "err"); return; }
    clear(hostsCard).append(h("h2", `Hosts of ${o.name}`),
      h("p.sub", `${hosts.length} monitored host${hosts.length === 1 ? "" : "s"}, with the probe parameters in effect` +
        (o.disabled ? ". The organization is blocked: nothing is probed." : ".")));
    if (!hosts.length) { hostsCard.append(h("p.muted", "This organization monitors no hosts.")); return; }
    const last = (x) => {
      if (!x.last_ts) return h("span.muted", "never");
      const lost = x.last_sent - x.last_recv;
      return h("span", { title: fmtDateTime(x.last_ts) }, fmtRelative(x.last_ts),
        lost > 0 ? h("span.badge.bad", { style: "margin-left:6px" }, `${lost}/${x.last_sent} lost`) : null);
    };
    hostsCard.append(scroll(h("table.tbl",
      h("thead", h("tr", ...["Folder", "Name", "Address", "Profile", "Interval", "Pings", "Packet", "Last cycle", "Added", "Description"].map((t) => h("th", t)))),
      h("tbody", ...hosts.map((x) => h("tr",
        h("td", x.path || h("span.muted", "-")),
        h("td", x.name),
        h("td.mono", x.host),
        h("td", x.profile || "-", x.default_profile ? h("span.badge.muted", { style: "margin-left:6px" }, "default") : null),
        h("td", x.interval_s + " s"), h("td", String(x.ping_count)), h("td", x.packet_size + " B"),
        h("td", last(x)), h("td", fmtDateTime(x.created_at)),
        h("td", x.description || ""),
      ))))));
  }

  // Deleting an organization removes everything it owns. The administrator
  // types its name and their own password; the server checks both.
  function deleteOrg(o) {
    const name = h("input", { type: "text", autocomplete: "off", placeholder: o.name });
    const pw = h("input", { type: "password", autocomplete: "current-password", placeholder: "Your password" });
    const err = h("p.error-text");
    const go = h("button.btn.danger", { disabled: true, onclick: submit }, "Delete organization");
    name.addEventListener("input", () => { go.disabled = name.value.trim() !== o.name; });
    const m = modal(`Delete ${o.name}?`,
      `This permanently removes the organization with its ${fmtNum(o.users)} user${o.users === 1 ? "" : "s"}, ${fmtNum(o.hosts)} host${o.hosts === 1 ? "" : "s"} ` +
      "and all their measurements, probe profiles, notification settings, invites and audit log. It cannot be undone.",
      [h("label.field", h("span.lbl", "Type the organization's name to confirm"), name),
       h("label.field", h("span.lbl", "Your password"), pw), err],
      [h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"), go]);
    async function submit() {
      err.textContent = "";
      go.disabled = true; go.textContent = "Deleting...";
      try {
        await api.adminDeleteOrg(o.id, pw.value, name.value.trim());
        m.close();
        toast(`${o.name} deleted`, "ok");
        if (selected === o.id) { selected = null; usersCard.hidden = true; hostsCard.hidden = true; }
        await refreshOrgs();
      } catch (e) {
        err.textContent = e.message;
        go.textContent = "Delete organization"; go.disabled = name.value.trim() !== o.name;
      }
    }
  }

  function editLimit(o) {
    const input = h("input", { type: "number", min: 0, max: 100000, placeholder: "default", value: o.host_limit ?? "" });
    const exempt = h("input", { type: "checkbox" }); exempt.checked = !!o.exempt_limits;
    const err = h("p.error-text");
    const m = modal(`Limits for ${o.name}`,
      "Empty = instance default (10 on a test instance, otherwise unlimited). 0 = unlimited. Existing hosts are kept; only adding more is refused.",
      [h("label.field", h("span.lbl", "Maximum hosts"), input),
       h("label.field", { style: "display:flex;gap:8px;align-items:center;flex-direction:row" }, exempt,
         h("span.lbl", { style: "margin:0" }, "Exempt from test-instance limits (host default, 60 s interval, 56 B packets)")), err],
      [h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"),
       h("button.btn.primary", { onclick: async () => {
         const v = input.value.trim() === "" ? null : Number(input.value);
         try { await api.adminSetLimits(o.id, v, exempt.checked); m.close(); toast("Limits saved", "ok"); refreshOrgs(); }
         catch (e) { err.textContent = e.message; }
       } }, "Save")]);
  }

  async function showUsers(o) {
    usersCard.hidden = false;
    clear(usersCard).append(h("h2", `Users of ${o.name}`), h("div", "Loading..."));
    let users;
    try { users = await api.adminOrgUsers(o.id); } catch (e) { toast(e.message, "err"); return; }
    clear(usersCard).append(h("h2", `Users of ${o.name}`),
      h("p.sub", o.disabled ? "This organization is blocked: nobody in it can sign in." : "Block, reset the password of, or delete individual users."));
    const act = (u) => {
      if (u.id === ctx.me.id) return h("span.muted", "you");
      if (u.is_superadmin) return h("span.muted", "platform admin");
      return h("span", { style: "white-space:nowrap" },
        h("button.btn.sm.ghost", { onclick: () => confirmDialog(u.disabled ? `Unblock ${u.email}?` : `Block ${u.email}?`,
          u.disabled ? "The user can sign in again." : "The user is signed out everywhere and cannot sign in until unblocked.",
          async () => { try { await api.adminBlockUser(u.id, !u.disabled); toast(u.disabled ? "User unblocked" : "User blocked", "ok"); showUsers(o); } catch (e) { toast(e.message, "err"); } },
          u.disabled ? "Unblock" : "Block", !u.disabled) }, u.disabled ? "Unblock" : "Block"),
        h("button.btn.sm.ghost", { onclick: () => resetPassword(u) }, "Reset password"),
        u.role === "owner" ? null : h("button.btn.sm.ghost", { onclick: () => confirmDialog(`Delete ${u.email}?`,
          "The account and its sessions are deleted permanently. Monitoring data of the organization is not affected.",
          async () => { try { await api.adminDeleteUser(u.id); toast("User deleted", "ok"); showUsers(o); refreshOrgs(); } catch (e) { toast(e.message, "err"); } },
          "Delete") }, "Delete"));
    };
    usersCard.append(scroll(h("table.tbl",
      h("thead", h("tr", ...["Name", "Email", "Role", "Status", "2FA", "Sessions", "Last sign-in", "Joined", ""].map((t) => h("th", t)))),
      h("tbody", ...users.map((u) => h("tr",
        h("td", [u.first_name, u.last_name].filter(Boolean).join(" ") || h("span.muted", "-")),
        h("td.mono", u.email),
        h("td", h("span.badge" + (u.role !== "member" ? ".accent" : ""), u.role), u.is_superadmin ? h("span.badge.accent", { style: "margin-left:6px" }, "platform admin") : null),
        h("td", u.disabled ? h("span.badge.bad", "blocked") : h("span.badge.ok", "active")),
        h("td", (u.two_factor || []).length ? u.two_factor.map((f) => ({ totp: "TOTP", key: "key", passkey: "passkey" }[f] || f)).join(", ") : h("span.muted", "off")),
        h("td", fmtNum(u.sessions)),
        h("td", when(u.last_login)), h("td", fmtDateTime(u.created_at)),
        h("td", { style: "text-align:right" }, act(u)),
      ))))));
  }

  function resetPassword(u) {
    const reset2fa = h("input", { type: "checkbox" });
    const m = modal(`Reset password for ${u.email}?`,
      "A random temporary password is generated and shown once. The user is signed out everywhere.",
      [(u.two_factor || []).length ? h("label", { style: "display:flex;gap:8px;align-items:center" }, reset2fa, "Also turn off two-factor: authenticator app, security keys and passkeys (lost device)") : null].filter(Boolean),
      [h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"),
       h("button.btn.danger", { onclick: async () => {
         m.close();
         try { const r = await api.adminResetPassword(u.id, reset2fa.checked); showTempPassword(u, r.password); }
         catch (e) { toast(e.message, "err"); }
       } }, "Reset password")]);
  }

  function showTempPassword(u, pw) {
    const box = h("input", { type: "text", value: pw, readonly: true, class: "mono" });
    const m = modal("Temporary password", `Give this to ${u.email} over a secure channel. It is not stored anywhere and will not be shown again.`,
      [box],
      [h("button.btn.ghost", { onclick: async () => { try { await navigator.clipboard.writeText(pw); toast("Copied", "ok"); } catch (e) { box.select(); } } }, "Copy"),
       h("button.btn.primary", { onclick: () => m.close() }, "Done")]);
    box.select();
  }

  await refreshOrgs();
}

// ---------- Usage & forecast ----------
async function usageTab(body) {
  const wrap = h("div.stack", h("div.card", "Loading..."));
  body.append(wrap);
  let s;
  try { s = await api.adminStats(); } catch (e) { toast(e.message, "err"); return; }
  const f = s.forecast, c = s.counts;
  const kpi = (label, value, hint) => h("div.kpi", h("div.kpi-lbl", label), h("div.kpi-val", value), hint ? h("div.kpi-hint", hint) : null);

  const kpis = h("div.card", h("h2", "Database"), h("p.sub", "Projection from each active organization's probe rate and retention; data older than the retention is removed daily."),
    h("div.kpis",
      kpi("Size now", fmtBytes(s.db_bytes)),
      kpi("Growth", fmtBytes(f.bytes_per_day) + " / day", fmtNum(Math.round(f.cycles_per_day)) + " probe cycles / day"),
      kpi("In 30 days", fmtBytes(f.in_30_days)),
      kpi("In 90 days", fmtBytes(f.in_90_days)),
      kpi("In 1 year", fmtBytes(f.in_365_days)),
      kpi("Steady state", fmtBytes(f.steady_state), "when every org reaches its retention"),
    ));

  const chartEl = h("div", { style: "height:280px" });
  const chartCard = h("div.card", h("h2", "Size: history and forecast"),
    h("p.sub", "Solid: daily snapshots. Dashed: forecast for the next 3 years."), chartEl);

  const counts = h("div.card", h("h2", "Platform"), h("div.kpis",
    kpi("Organizations", fmtNum(c.orgs), c.orgs_blocked ? `${c.orgs_blocked} blocked` : null),
    kpi("Users", fmtNum(c.users), `${c.users_blocked} blocked · ${c.users_2fa} with 2FA`),
    kpi("Hosts", fmtNum(c.hosts)),
    kpi("Active sessions", fmtNum(c.sessions)),
    kpi("Failed sign-ins (24h)", fmtNum(c.failed_logins_24h)),
    kpi("Audit entries", fmtNum(c.audit_entries)),
  ));

  const maxB = Math.max(1, ...s.tables.map((t) => t.bytes));
  const tables = h("div.card", h("h2", "Tables"), scroll(h("table.tbl",
    h("thead", h("tr", h("th", "Table"), h("th", "Rows (est.)"), h("th", "Size"), h("th", { style: "width:40%" }, ""))),
    h("tbody", ...s.tables.map((t) => h("tr",
      h("td.mono", t.name), h("td", fmtNum(t.rows)), h("td", fmtBytes(t.bytes)),
      h("td", h("div.size-bar", h("span", { style: `width:${(t.bytes / maxB * 100).toFixed(1)}%` })))))))));

  const daily = h("div.card", h("h2", "Ingestion (last 30 days)"), h("p.sub", "Probe cycles stored per day, all organizations."),
    s.daily_cycles.length ? h("div.day-bars", ...(() => {
      const mx = Math.max(1, ...s.daily_cycles.map((d) => d.cycles));
      return s.daily_cycles.map((d) => h("span", { title: `${fmtDateTime(d.day).slice(0, 10)}: ${fmtNum(d.cycles)} cycles`, style: `height:${(d.cycles / mx * 100).toFixed(1)}%` }));
    })()) : h("p.muted", "No data yet."));

  clear(wrap).append(kpis, chartCard, counts, daily, tables);
  drawForecast(chartEl, s);
}

function drawForecast(el, s) {
  const now = Math.floor(Date.now() / 1000);
  const hist = s.history.map((p) => [p.day, p.bytes]);
  hist.push([now, s.db_bytes]);
  const fc = s.forecast.points.map((p) => [now + p.day * 86400, p.bytes]);
  const xs = [...new Set([...hist.map((p) => p[0]), ...fc.map((p) => p[0])])].sort((a, b) => a - b);
  const hm = new Map(hist), fm = new Map(fc);
  const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#3b82f6";
  const axis = getComputedStyle(document.documentElement).getPropertyValue("--axis").trim() || "#888";
  const grid = getComputedStyle(document.documentElement).getPropertyValue("--grid").trim() || "rgba(128,128,128,.2)";
  const ax = { stroke: axis, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid, width: 1 } };
  const u = new uPlot({
    width: el.clientWidth || 800, height: 280, padding: [10, 12, 0, 6],
    scales: { x: { time: true }, y: { range: (u, mn, mx) => [0, (mx || 1) * 1.1] } },
    legend: { show: false },
    axes: [ax, { ...ax, size: 70, values: (u, vals) => vals.map(fmtBytes) }],
    series: [{}, { stroke: accent, width: 2, spanGaps: true }, { stroke: accent, width: 2, dash: [6, 5], spanGaps: true }],
  }, [xs, xs.map((x) => hm.get(x) ?? null), xs.map((x) => fm.get(x) ?? null)], el);
  new ResizeObserver(() => u.setSize({ width: el.clientWidth, height: 280 })).observe(el);
}

// ---------- Global audit ----------
async function auditTab(body) {
  const orgSel = h("select", h("option", { value: "" }, "All organizations"), h("option", { value: "system" }, "System only"));
  const q = h("input", { type: "text", placeholder: "Search email, action, detail, IP" });
  const act = h("input", { type: "text", placeholder: "Action prefix, e.g. auth. or denied." });
  const tbody = h("tbody");
  const pg = pager("admin-audit", load);
  const card = h("div.card", h("h2", "Global audit log"),
    h("p.sub", "Every organization's actions plus system events (no organization). Failures are highlighted."),
    h("div.row", { style: "margin-bottom:16px" }, orgSel, q, act),
    scroll(h("table.tbl", h("thead", h("tr", ...["When", "Organization", "User", "Action", "Detail", "IP"].map((t) => h("th", t)))), tbody)),
    pg.el);
  body.append(card);

  try { for (const o of await api.adminOrgs()) orgSel.append(h("option", { value: o.id }, o.name)); } catch (e) {}

  let timer = null;
  async function load() {
    let page;
    try { page = await api.adminAudit({ org: orgSel.value, q: q.value.trim(), action: act.value.trim(), limit: pg.limit, offset: pg.offset }); }
    catch (e) { toast(e.message, "err"); return; }
    if (!pg.set(page.total)) return;
    clear(tbody);
    for (const r of page.items) {
      const bad = /^(denied\.|auth\.login_(failed|blocked|disabled)|system\..*error)/.test(r.action);
      tbody.append(h("tr",
        h("td", { title: fmtDateTime(r.created_at) }, fmtRelative(r.created_at)),
        h("td", r.org_id == null ? h("span.badge.muted", "system") : r.org),
        h("td.mono", r.email || "-"),
        h("td", h(bad ? "span.badge.bad" : r.action.startsWith("admin.") ? "span.badge.accent" : "span.badge", r.action)),
        h("td", r.detail || ""),
        h("td.mono", r.ip || ""),
      ));
    }
    if (!page.items.length) tbody.append(h("tr", h("td", { colspan: 6, class: "muted" }, "No entries match.")));
  }
  // a changed filter starts again at the first page
  const reload = () => { clearTimeout(timer); timer = setTimeout(() => { pg.reset(); load(); }, 250); };
  orgSel.addEventListener("change", reload); q.addEventListener("input", reload); act.addEventListener("input", reload);
  await load();
}

// ---------- Settings ----------
async function settingsTab(body) {
  const wrap = h("div.stack", h("div.card", "Loading..."));
  body.append(wrap);
  let s;
  try { s = await api.adminSettings(); } catch (e) { toast(e.message, "err"); return; }

  const open = h("input", { type: "checkbox", id: "reg-open" }); open.checked = !!s.registration_open;
  const state = h("p.hint");
  const describe = () => {
    state.textContent = open.checked
      ? "Anyone who can reach the sign-in page can create an organization and becomes its owner."
      : "The sign-in page has no \"Create organization\" form. New people join only through an invitation link from an owner or admin.";
  };
  describe();
  open.addEventListener("change", async () => {
    open.disabled = true;
    try {
      await api.adminSetSettings({ registration_open: open.checked });
      toast(open.checked ? "Creating organizations is on" : "Creating organizations is off", "ok");
    } catch (e) { open.checked = !open.checked; toast(e.message, "err"); }
    open.disabled = false;
    describe();
  });

  clear(wrap);
  wrap.append(
    h("div.card",
      h("h2", "Registration"),
      h("p.sub", "Who can start using this instance."),
      h("label.field.check-row", open, h("span.lbl", "Allow creating organizations")),
      state),
    h("div.card",
      h("h2", "Sign-in protection"),
      h("p.sub", "Set in the server's environment (TURNSTILE_ENABLE), shown here for information."),
      h("p", "Cloudflare Turnstile on the sign-in, organization and invitation forms: ",
        h("b", s.turnstile_enabled ? "on" : "off"), ".")),
    h("div.card",
      h("h2", "Single sign-on"),
      h("p.sub", "Set in the server's environment (SSO_GOOGLE_..., SSO_ENTRA_...), shown here for information."),
      h("p", "Providers on the sign-in page: ",
        h("b", (s.sso || []).length ? s.sso.map((p) => p.name).join(", ") : "none"), ".")),
  );
}
