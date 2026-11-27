// Settings > Notifications: channels (where), alert rules (when), active
// alerts and delivery history. Members can look; owners and admins edit.
import { api } from "../api.js";
import { h, clear, toast, modal, confirmDialog, fmtDateTime, fmtRelative, icons, pager } from "../ui.js";

const KINDS = {
  telegram: { label: "Telegram", hint: "A bot posts to a chat, group or channel." },
  slack: { label: "Slack", hint: "Incoming webhook to a channel." },
  teams: { label: "Microsoft Teams", hint: "Workflows webhook (Post to a channel when a webhook request is received)." },
  email: { label: "Email", hint: "SMTP with password or OAuth 2.0 (Microsoft 365)." },
  zabbix: { label: "Zabbix", hint: "Alerts open and close problems in Zabbix 7.0 or later, through its API. Import the Driftband template into Zabbix first (see the FAQ)." },
};

function field(label, input, hint) {
  return h("label.field", h("span.lbl", label), input, hint ? h("p.hint", hint) : null);
}
function check(label, checked) {
  const i = h("input", { type: "checkbox" }); i.checked = !!checked;
  return [h("label.field", { style: "display:flex;gap:8px;align-items:center;flex-direction:row" }, i, h("span.lbl", { style: "margin:0" }, label)), i];
}
function wideModal(...args) {
  const m = modal(...args);
  m.back.querySelector(".modal").classList.add("wide");
  return m;
}

// eventsCards(): the "Active alerts" and "Recent notifications" cards, shared
// by Settings > Notifications and the Active Alerts page. The history is
// paged on the server; refresh() reloads both cards.
export function eventsCards() {
  const activeCard = h("div.card", h("h2", "Active alerts"), h("p.muted", "Loading..."));
  const tbody = h("tbody");
  const pg = pager("notify-log", refresh);
  const logCard = h("div.card", h("h2", "Recent notifications"), h("p.sub", "Deliveries of the last 90 days, newest first."),
    h("div", { style: "overflow-x:auto" }, h("table.tbl",
      h("thead", h("tr", h("th", "When"), h("th", "Event"), h("th", "Message"), h("th", "Channel"), h("th", "Result"))), tbody)),
    pg.el);

  async function refresh() {
    let ev;
    try { ev = await api.notifyEvents({ limit: pg.limit, offset: pg.offset }); } catch (e) { toast(e.message, "err"); return null; }
    if (!pg.set(ev.log_total)) return ev;
    clear(activeCard).append(h("h2", "Active alerts"));
    if (!ev.active.length) activeCard.append(h("p.muted", "Nothing is alerting right now."));
    else activeCard.append(h("table.tbl",
      h("thead", h("tr", h("th", "Host"), h("th", "Rule"), h("th", "State"), h("th", "Value"), h("th", "Since"))),
      h("tbody", ...ev.active.map((a) => h("tr",
        h("td", a.host), h("td", a.rule),
        h("td", a.flapping ? h("span.badge", { style: "color:var(--warn, #f59e0b)" }, "flapping") : h("span.badge.bad", "alerting")),
        h("td.mono", a.value == null ? "-" : a.value.toFixed(1) + (a.metric === "loss" ? "%" : " ms")),
        h("td", { title: fmtDateTime(a.since) }, fmtRelative(a.since)))))));
    clear(tbody);
    if (!ev.log.length) tbody.append(h("tr", h("td", { colspan: 5, class: "muted" }, "No notifications sent yet.")));
    for (const l of ev.log) {
      tbody.append(h("tr",
        h("td", { title: fmtDateTime(l.at) }, fmtRelative(l.at)),
        h("td", h(l.event === "firing" || l.event === "reminder" ? "span.badge.bad" : l.event === "resolved" ? "span.badge.ok" : "span.badge", l.event)),
        h("td", l.message),
        h("td", l.channel || "-"),
        h("td", l.ok ? h("span.badge.ok", "sent") : h("span.badge.bad", { title: l.error || "" }, "failed")),
      ));
    }
    return ev;
  }
  return { activeCard, logCard, refresh };
}

export async function notificationsTab(body, ctx, canManage) {
  const events = eventsCards();
  const activeCard = events.activeCard, logCard = events.logCard;
  const chCard = h("div.card");
  const ruleCard = h("div.card");
  body.append(h("div.stack", activeCard, chCard, ruleCard, logCard));
  let channels = [], rules = [], tree = [];
  const drawEvents = () => events.refresh();

  async function refresh() {
    try {
      [channels, rules, tree] = await Promise.all([api.notifyChannels(), api.notifyRules(), api.tree()]);
    } catch (e) { toast(e.message, "err"); return; }
    drawChannels(); drawRules(); await drawEvents();
  }

  // ----- channels -----
  function drawChannels() {
    clear(chCard).append(h("div.spread",
      h("div", h("h2", "Channels"), h("p.sub", "Where alerts are delivered. Secrets (tokens, webhook URLs, passwords) are stored encrypted and never shown again.")),
      canManage ? h("button.btn.primary", { onclick: () => openChannelModal(null) }, h("span.ico", { html: icons.plus }), "Add channel") : null));
    if (!channels.length) { chCard.append(h("p.muted", canManage ? "No channels yet. Add one, then create an alert rule." : "No channels yet.")); return; }
    chCard.append(h("table.tbl",
      h("thead", h("tr", h("th", "Name"), h("th", "Type"), h("th", "Target"), h("th", "Status"), canManage ? h("th", "") : null)),
      h("tbody", ...channels.map((c) => h("tr",
        h("td", c.name),
        h("td", h("span.badge", KINDS[c.kind]?.label || c.kind)),
        h("td.mono", { style: "font-size:12px" }, target(c)),
        h("td", c.enabled ? h("span.badge.ok", "enabled") : h("span.badge.muted", "disabled")),
        canManage ? h("td", { style: "text-align:right;white-space:nowrap" },
          h("button.btn.sm.ghost", { onclick: () => testChannel(c) }, "Send test"),
          h("button.btn.sm.ghost", { onclick: () => openChannelModal(c) }, "Edit"),
          h("button.btn.sm.ghost", { onclick: () => confirmDialog("Delete channel?", `"${c.name}" is removed from every alert rule.`,
            async () => { try { await api.deleteChannel(c.id); toast("Channel deleted", "ok"); refresh(); } catch (e) { toast(e.message, "err"); } }) }, "Delete")) : null,
      )))));
  }
  function target(c) {
    const cfg = c.config || {};
    if (c.kind === "telegram") return "chat " + cfg.chat_id;
    if (c.kind === "email") return (cfg.to || []).join(", ") + " via " + cfg.host + (cfg.auth === "oauth2" ? " (OAuth 2.0)" : "");
    if (c.kind === "zabbix") return "host " + cfg.zabbix_host + " at " + (cfg.zabbix_url || "").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    return c.secrets_set?.webhook_url ? "webhook set" : "-";
  }
  async function testChannel(c) {
    try { await api.testChannel(c.id); toast(`Test sent to ${c.name}`, "ok"); }
    catch (e) { toast(e.message, "err"); }
    drawEvents();
  }

  function openChannelModal(c) {
    const editing = !!c, cfg = (c && c.config) || {}, set = (c && c.secrets_set) || {};
    const kind = h("select", ...Object.entries(KINDS).map(([k, v]) => h("option", { value: k }, v.label)));
    kind.value = c ? c.kind : "telegram"; kind.disabled = editing;
    const name = h("input", { type: "text", value: c ? c.name : "", placeholder: "e.g. NOC on-call" });
    const [enabledRow, enabled] = check("Enabled", c ? c.enabled : true);
    const secretInput = (has, ph) => h("input", { type: "password", autocomplete: "off", placeholder: has ? "stored - leave empty to keep" : ph });
    // telegram
    const botToken = secretInput(set.bot_token, "123456789:AA...");
    const chatId = h("input", { type: "text", value: cfg.chat_id || "", placeholder: "-1001234567890 or @channel" });
    // slack / teams
    const webhook = secretInput(set.webhook_url, "https://...");
    // email
    const host = h("input", { type: "text", value: cfg.host || "", placeholder: "smtp.office365.com" });
    const port = h("input", { type: "number", value: cfg.port || 587, min: 1, max: 65535 });
    const security = h("select", h("option", { value: "starttls" }, "STARTTLS"), h("option", { value: "tls" }, "TLS (implicit)"), h("option", { value: "none" }, "None"));
    security.value = cfg.security || "starttls";
    const from = h("input", { type: "text", value: cfg.from || "", placeholder: "Driftband <alerts@example.com>" });
    const to = h("input", { type: "text", value: (cfg.to || []).join(", "), placeholder: "noc@example.com, oncall@example.com" });
    const auth = h("select", h("option", { value: "none" }, "No authentication"), h("option", { value: "password" }, "Username and password"), h("option", { value: "oauth2" }, "OAuth 2.0 (client credentials)"));
    auth.value = cfg.auth || "password";
    const username = h("input", { type: "text", value: cfg.username || "", autocomplete: "off" });
    const password = secretInput(set.password, "password");
    const provider = h("select", h("option", { value: "microsoft" }, "Microsoft 365"), h("option", { value: "custom" }, "Other provider"));
    provider.value = cfg.oauth_provider || "microsoft";
    const tenant = h("input", { type: "text", value: cfg.tenant_id || "", placeholder: "contoso.onmicrosoft.com or tenant GUID" });
    const clientId = h("input", { type: "text", value: cfg.client_id || "" });
    const clientSecret = secretInput(set.client_secret, "client secret");
    const tokenURL = h("input", { type: "text", value: cfg.oauth_provider === "custom" ? cfg.token_url || "" : "", placeholder: "https://provider/oauth2/token" });
    const scope = h("input", { type: "text", value: cfg.oauth_provider === "custom" ? cfg.scope || "" : "", placeholder: "scope" });

    // zabbix
    const zbxUrl = h("input", { type: "text", value: cfg.zabbix_url || "", placeholder: "https://zabbix.example.com" });
    const zbxHost = h("input", { type: "text", value: cfg.zabbix_host || "", placeholder: "Driftband" });
    const zbxToken = secretInput(set.api_token, "API token");
    const zbxBox = h("div",
      field("Zabbix URL", zbxUrl, "Address of the Zabbix frontend. HTTPS only."),
      h("div.row", field("Host in Zabbix", zbxHost, "Technical name of the host linked to the Driftband template."),
        field("API token", zbxToken, "Created in Zabbix under Users, API tokens.")));

    const tgBox = h("div", h("div.row", field("Bot token", botToken, "From @BotFather."), field("Chat id", chatId, "Add the bot to the chat first.")));
    const hookBox = h("div", field("Webhook URL", webhook, "HTTPS only. Treated as a secret."));
    const pwBox = h("div.row", field("Username", username), field("Password", password));
    const oauthBox = h("div",
      h("div.row", field("Provider", provider), field("Mailbox (username)", username.cloneNode())),
      h("div.ms", h("div.row", field("Tenant", tenant), field("Client id", clientId))),
      h("div.custom", h("div.row", field("Token URL", tokenURL), field("Scope", scope))),
      field("Client secret", clientSecret, "Microsoft 365: an Entra app with the SMTP.SendAsApp permission, allowed to send as the mailbox."));
    // one username field shared by both auth modes
    const oauthUser = oauthBox.querySelector("input"); oauthUser.value = username.value;
    oauthUser.addEventListener("input", () => (username.value = oauthUser.value));
    username.addEventListener("input", () => (oauthUser.value = username.value));
    const mailBox = h("div",
      h("div.row", field("SMTP host", host), field("Port", port), field("Security", security)),
      h("div.row", field("From", from), field("To", to, "Comma-separated, up to 20.")),
      field("Authentication", auth), pwBox, oauthBox);
    const hint = h("p.hint");
    const err = h("p.error-text");
    function sync() {
      const k = kind.value;
      hint.textContent = KINDS[k].hint;
      tgBox.hidden = k !== "telegram"; hookBox.hidden = k !== "slack" && k !== "teams"; mailBox.hidden = k !== "email";
      zbxBox.hidden = k !== "zabbix";
      pwBox.hidden = auth.value !== "password"; oauthBox.hidden = auth.value !== "oauth2";
      oauthBox.querySelector(".ms").hidden = provider.value !== "microsoft";
      oauthBox.querySelector(".custom").hidden = provider.value !== "custom";
    }
    [kind, auth, provider].forEach((s) => s.addEventListener("change", sync));
    sync();
    const m = wideModal(editing ? "Edit channel" : "Add channel", null,
      [h("div.row", field("Type", kind), field("Name", name)), hint, tgBox, hookBox, mailBox, zbxBox, enabledRow, err],
      [h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"), h("button.btn.primary", { onclick: save }, editing ? "Save" : "Add channel")]);
    async function save() {
      err.textContent = "";
      const k = kind.value;
      const payload = { name: name.value, kind: k, enabled: enabled.checked, config: {}, secrets: {} };
      if (k === "telegram") { payload.config.chat_id = chatId.value; payload.secrets.bot_token = botToken.value; }
      else if (k === "slack" || k === "teams") payload.secrets.webhook_url = webhook.value;
      else if (k === "zabbix") { payload.config.zabbix_url = zbxUrl.value; payload.config.zabbix_host = zbxHost.value; payload.secrets.api_token = zbxToken.value; }
      else {
        Object.assign(payload.config, { host: host.value, port: Number(port.value), security: security.value, from: from.value,
          to: to.value.split(",").map((s) => s.trim()).filter(Boolean), auth: auth.value, username: username.value });
        if (auth.value === "password") payload.secrets.password = password.value;
        if (auth.value === "oauth2") {
          Object.assign(payload.config, { oauth_provider: provider.value, tenant_id: tenant.value, client_id: clientId.value, token_url: tokenURL.value, scope: scope.value });
          payload.secrets.client_secret = clientSecret.value;
        }
      }
      try {
        if (editing) await api.updateChannel(c.id, payload); else await api.createChannel(payload);
        m.close(); toast("Channel saved", "ok"); refresh();
      } catch (e) { err.textContent = e.message; }
    }
  }

  // ----- rules -----
  const flatNodes = () => {
    const out = [];
    const walk = (ns, d) => { for (const n of ns) { out.push({ n, d }); if (n.children) walk(n.children, d + 1); } };
    walk(tree, 0); return out;
  };
  const nodeName = (id) => { const f = flatNodes().find((x) => x.n.id === id); return f ? f.n.name : "?"; };
  const unit = (r) => (r.metric === "loss" ? "%" : " ms");
  function describe(r) {
    const what = r.metric === "loss" ? "Packet loss" : "Median latency";
    const bits = [`${what} ≥ ${r.threshold}${unit(r)} for ${r.for_minutes} min`, `recovers below ${r.recover_threshold}${unit(r)} for ${r.recover_minutes} min`];
    if (r.repeat_minutes) bits.push(`reminder every ${r.repeat_minutes} min`);
    bits.push(r.flap_transitions ? `flap guard ${r.flap_transitions} changes / ${r.flap_window_minutes} min` : "no flap guard");
    if (!r.notify_recovery) bits.push("no recovery notice");
    return bits.join(" · ");
  }
  function drawRules() {
    clear(ruleCard).append(h("div.spread",
      h("div", h("h2", "Alert rules"), h("p.sub", "When to notify. A rule fires only after its condition holds for the whole duration, resolves with a lower recovery threshold, and goes quiet while a link flaps.")),
      canManage ? h("button.btn.primary", { disabled: !channels.length, title: channels.length ? "" : "Add a channel first", onclick: () => openRuleModal(null) }, h("span.ico", { html: icons.plus }), "New rule") : null));
    if (!rules.length) { ruleCard.append(h("p.muted", "No alert rules yet.")); return; }
    const chName = (id) => channels.find((c) => c.id === id)?.name || "?";
    ruleCard.append(h("table.tbl",
      h("thead", h("tr", h("th", "Rule"), h("th", "Scope"), h("th", "Condition"), h("th", "Channels"), canManage ? h("th", "") : null)),
      h("tbody", ...rules.map((r) => h("tr",
        h("td", r.name, r.enabled ? null : h("span.badge.muted", { style: "margin-left:8px" }, "off")),
        h("td", r.node_id ? nodeName(r.node_id) : h("span.muted", "all hosts")),
        h("td", { style: "font-size:12.5px" }, describe(r)),
        h("td", r.channel_ids.map(chName).join(", ")),
        canManage ? h("td", { style: "text-align:right;white-space:nowrap" },
          h("button.btn.sm.ghost", { onclick: () => openRuleModal(r) }, "Edit"),
          h("button.btn.sm.ghost", { onclick: () => confirmDialog("Delete rule?", `"${r.name}" stops alerting immediately.`,
            async () => { try { await api.deleteRule(r.id); toast("Rule deleted", "ok"); refresh(); } catch (e) { toast(e.message, "err"); } }) }, "Delete")) : null,
      )))));
  }

  function openRuleModal(r) {
    const editing = !!r;
    const d = r || { name: "", enabled: true, node_id: null, metric: "loss", threshold: 20, recover_threshold: 5, for_minutes: 5, recover_minutes: 5,
      notify_recovery: true, repeat_minutes: 0, flap_transitions: 4, flap_window_minutes: 60, channel_ids: channels.length ? [channels[0].id] : [] };
    const name = h("input", { type: "text", value: d.name, placeholder: "e.g. Core links: packet loss" });
    const scope = h("select", h("option", { value: "" }, "All hosts"),
      ...flatNodes().map(({ n, d: depth }) => h("option", { value: n.id }, "  ".repeat(depth) + (n.kind === "folder" ? "▸ " : "") + n.name)));
    scope.value = d.node_id || "";
    const metric = h("select", h("option", { value: "loss" }, "Packet loss (%)"), h("option", { value: "latency" }, "Median latency (ms)"));
    metric.value = d.metric;
    const num = (v, min, max, step = "any") => h("input", { type: "number", value: v, min, max, step });
    const thr = num(d.threshold, 1, 60000), rthr = num(d.recover_threshold, 0.1, 60000);
    const forM = num(d.for_minutes, 1, 1440, 1), recM = num(d.recover_minutes, 1, 1440, 1);
    const repeat = num(d.repeat_minutes, 0, 10080, 1);
    const flapN = num(d.flap_transitions, 0, 50, 1), flapW = num(d.flap_window_minutes, 10, 1440, 1);
    const [recRow, notifyRec] = check("Notify when it recovers", d.notify_recovery);
    const [enRow, enabled] = check("Enabled", d.enabled);
    const chBoxes = channels.map((c) => { const [row, i] = check(`${c.name} (${KINDS[c.kind]?.label || c.kind})`, d.channel_ids.includes(c.id)); i.dataset.id = c.id; return row; });
    const unitLbl = () => (metric.value === "loss" ? "%" : "ms");
    const thrField = field("Alert at or above", thr), rthrField = field("Recovered below", rthr);
    const preview = h("p.hint", { style: "margin-top:4px" });
    function sync() {
      thrField.querySelector(".lbl").textContent = `Alert at or above (${unitLbl()})`;
      rthrField.querySelector(".lbl").textContent = `Recovered below (${unitLbl()})`;
      preview.textContent = `Alert when ${metric.value === "loss" ? "packet loss" : "median latency"} stays at or above ${thr.value} ${unitLbl()} for ${forM.value} min; ` +
        `resolve after it stays below ${rthr.value} ${unitLbl()} for ${recM.value} min.` +
        (Number(flapN.value) ? ` If the state changes ${flapN.value} times within ${flapW.value} min, send one "flapping" notice and pause until it settles.` : "");
    }
    [metric, thr, rthr, forM, recM, flapN, flapW].forEach((i) => i.addEventListener("input", sync));
    sync();
    const err = h("p.error-text");
    const m = wideModal(editing ? "Edit alert rule" : "New alert rule", null, [
      h("div.row", field("Name", name), field("Hosts", scope, "A folder includes every host below it.")),
      h("div.row", field("Metric", metric), thrField, field("for (minutes)", forM)),
      h("div.row", rthrField, field("for (minutes)", recM), field("Reminder every (min, 0 = off)", repeat)),
      h("div.row", field("Flap guard: state changes (0 = off)", flapN), field("within (minutes)", flapW)),
      preview,
      h("p.lbl", { style: "margin:14px 0 6px;font-size:12.5px;font-weight:560;color:var(--text-dim)" }, "Send to"), ...chBoxes,
      recRow, enRow, err,
    ], [h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"), h("button.btn.primary", { onclick: save }, editing ? "Save" : "Create rule")]);
    async function save() {
      err.textContent = "";
      const payload = {
        name: name.value, enabled: enabled.checked, node_id: scope.value ? Number(scope.value) : null, metric: metric.value,
        threshold: Number(thr.value), recover_threshold: Number(rthr.value), for_minutes: Number(forM.value), recover_minutes: Number(recM.value),
        notify_recovery: notifyRec.checked, repeat_minutes: Number(repeat.value), flap_transitions: Number(flapN.value), flap_window_minutes: Number(flapW.value),
        channel_ids: [...m.back.querySelectorAll("input[data-id]")].filter((i) => i.checked).map((i) => Number(i.dataset.id)),
      };
      try {
        if (editing) await api.updateRule(r.id, payload); else await api.createRule(payload);
        m.close(); toast("Rule saved", "ok"); refresh();
      } catch (e) { err.textContent = e.message; }
    }
  }

  await refresh();
}
