import { api } from "../api.js";
import { h, clear, toast, modal, confirmDialog, fmtDateTime, fmtRelative, fmtUntil, icons, pager, avatar } from "../ui.js";
import { webauthnSupported, createCredential, webauthnError } from "../webauthn.js";
import { notificationsTab } from "./notifications.js";
import { usageTab } from "./usage.js";

const TABS = [
  { id: "account", label: "Account" },
  { id: "team", label: "Team" },
  { id: "profiles", label: "Probe profiles" },
  { id: "notifications", label: "Notifications" },
  { id: "import", label: "Import" },
  { id: "retention", label: "Data retention" },
  { id: "usage", label: "Usage" },
  { id: "audit", label: "Audit log" },
];

// Instance limits from /api/me (test instances are stricter).
let LIMITS = { min_interval: 5, max_packet: 1472, max_pings: 100 };
const LIMITS_STRICT = () => LIMITS.test_instance && !LIMITS.exempt;

export function renderSettings(mount, ctx) {
  clear(mount);
  LIMITS = { ...LIMITS, ...(ctx.me.limits || {}) };
  let tab = ctx.tab || "account";
  const canManage = ctx.me.role === "owner" || ctx.me.role === "admin";

  const tabsEl = h("div.tabs", ...TABS.map((t) =>
    h("button", { class: t.id === tab ? "active" : "", onclick: () => { tab = t.id; draw(); } }, t.label)));
  const body = h("div");
  mount.append(h("div.section-title", h("h2", "Settings")), tabsEl, body);

  function draw() {
    [...tabsEl.children].forEach((b, i) => b.className = TABS[i].id === tab ? "active" : "");
    clear(body);
    if (tab === "account") accountTab(body, ctx);
    else if (tab === "team") teamTab(body, ctx, canManage);
    else if (tab === "profiles") profilesTab(body, canManage);
    else if (tab === "notifications") notificationsTab(body, ctx, canManage);
    else if (tab === "import") importTab(body, canManage);
    else if (tab === "retention") retentionTab(body, ctx, canManage);
    else if (tab === "usage") usageTab(body);
    else if (tab === "audit") auditTab(body);
  }
  draw();
}

// The picture next to the email in the navigation bar follows the profile.
function refreshNavAvatar(me) {
  const old = document.querySelector(".nav-right .avatar");
  if (old) old.replaceWith(avatar(me, 26));
}

function field(label, input, hint) {
  return h("label.field", h("span.lbl", label), input, hint ? h("p.hint", hint) : null);
}

// ---------- Account ----------
function accountTab(body, ctx) {
  // profile name
  const fn = h("input", { type: "text", value: ctx.me.first_name || "", placeholder: "First name", autocomplete: "given-name" });
  const ln = h("input", { type: "text", value: ctx.me.last_name || "", placeholder: "Last name", autocomplete: "family-name" });
  // profile picture: checked here for a quick answer, and again (strictly)
  // by the server, which stores its own re-encoded 256 x 256 copy
  const AVATAR_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
  const AVATAR_MAX = 5 * 1024 * 1024;
  const picBox = h("div.avatar-edit");
  const picErr = h("p.error-text");
  const file = h("input", { type: "file", accept: AVATAR_TYPES.join(","), hidden: true, "aria-label": "Profile picture file" });
  function drawPic() {
    clear(picBox).append(
      avatar(ctx.me, 72),
      h("div",
        h("div.avatar-actions",
          h("button.btn.sm", { type: "button", onclick: () => file.click() }, ctx.me.avatar ? "Change picture" : "Upload picture"),
          ctx.me.avatar ? h("button.btn.sm.ghost", { type: "button", onclick: removePic }, "Remove") : null),
        h("p.hint", "JPEG, PNG, GIF or WebP, up to 5 MB and 4096 x 4096 pixels. It is cropped to a square and shown to your teammates.")),
    );
  }
  async function removePic() {
    picErr.textContent = "";
    try { await api.removeAvatar(); ctx.me.avatar = ""; drawPic(); refreshNavAvatar(ctx.me); toast("Picture removed", "ok"); }
    catch (e) { picErr.textContent = e.message; }
  }
  file.addEventListener("change", async () => {
    const f = file.files[0];
    file.value = "";
    picErr.textContent = "";
    if (!f) return;
    if (!AVATAR_TYPES.includes(f.type)) { picErr.textContent = "Only JPEG, PNG, GIF and WebP pictures are accepted."; return; }
    if (f.size > AVATAR_MAX) { picErr.textContent = "The picture is larger than 5 MB."; return; }
    try {
      const data = await new Promise((ok, fail) => {
        const rd = new FileReader();
        rd.onload = () => ok(String(rd.result).split(",")[1] || "");
        rd.onerror = () => fail(new Error("The file could not be read."));
        rd.readAsDataURL(f);
      });
      const r = await api.setAvatar(f.type, data);
      ctx.me.avatar = r.avatar; drawPic(); refreshNavAvatar(ctx.me); toast("Picture saved", "ok");
    } catch (e) { picErr.textContent = e.message; }
  });
  drawPic();

  const nameCard = h("div.card",
    h("h2", "Profile"), h("p.sub", "Your picture and name, shown to teammates in the members list."),
    picBox, file, picErr,
    h("div.row", field("First name", fn), field("Last name", ln)),
    h("button.btn.primary", { onclick: async () => {
      try {
        await api.changeName({ first_name: fn.value, last_name: ln.value });
        ctx.me.first_name = fn.value.trim(); ctx.me.last_name = ln.value.trim();
        drawPic(); refreshNavAvatar(ctx.me);
        toast("Profile saved", "ok");
      } catch (e) { toast(e.message, "err"); }
    } }, "Save"),
  );

  // change email
  const e1 = h("input", { type: "email", value: ctx.me.email });
  const ep = h("input", { type: "password", placeholder: "Current password" });
  const eErr = h("p.error-text");
  const emailCard = h("div.card",
    h("h2", "Email"), h("p.sub", "Change the email you sign in with."),
    field("Email", e1), field("Confirm with password", ep), eErr,
    h("button.btn.primary", { onclick: async () => {
      eErr.textContent = "";
      try { await api.changeEmail({ email: e1.value, password: ep.value }); toast("Email updated", "ok"); ctx.me.email = e1.value; ep.value = ""; }
      catch (e) { eErr.textContent = e.message; }
    } }, "Update email"),
  );

  // change password
  const cur = h("input", { type: "password", placeholder: "Current password", autocomplete: "current-password" });
  const nw = h("input", { type: "password", placeholder: "New password (8+ chars)", autocomplete: "new-password" });
  const nw2 = h("input", { type: "password", placeholder: "Repeat new password", autocomplete: "new-password" });
  const pErr = h("p.error-text");
  const pwCard = h("div.card",
    h("h2", "Password"), h("p.sub", "Other sessions are signed out after a change."),
    field("Current password", cur), field("New password", nw), field("Repeat new password", nw2), pErr,
    h("button.btn.primary", { onclick: async () => {
      pErr.textContent = "";
      if (nw.value !== nw2.value) { pErr.textContent = "New passwords do not match"; return; }
      try { await api.changePassword({ current: cur.value, new: nw.value, confirm: nw2.value }); toast("Password changed", "ok"); cur.value = nw.value = nw2.value = ""; }
      catch (e) { pErr.textContent = e.message; }
    } }, "Change password"),
  );

  // two-factor authentication: an authenticator app (TOTP), hardware
  // security keys and passkeys. Any enrolled method completes a sign-in.
  const tfaCard = h("div.card");
  let keys = { credentials: [], available: true, limit: 10 };

  // Asks for the password (plus optional fields) before a sensitive change.
  function confirmWithPassword(title, sub, extra, label, danger, action) {
    const pw = h("input", { type: "password", placeholder: "Current password", autocomplete: "current-password" });
    const mErr = h("p.error-text");
    const go = h("button.btn" + (danger ? ".danger" : ".primary"), { onclick: run }, label);
    const m = modal(title, sub, [...extra, field("Confirm with password", pw), mErr], [
      h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"), go]);
    pw.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
    async function run() {
      mErr.textContent = ""; go.disabled = true;
      try { await action(pw.value, m); }
      catch (e) { mErr.textContent = e.name && e.name.endsWith("Error") && !e.status ? webauthnError(e) : e.message; }
      go.disabled = false;
    }
    setTimeout(() => (extra.length ? extra[0].querySelector("input") || pw : pw).focus(), 0);
    return m;
  }

  function methodRow(title, desc, state, ...actions) {
    return h("div.tfa-method",
      h("div.tfa-method-text", h("div.tfa-method-title", title, state), h("p.hint", desc)),
      h("div.tfa-method-actions", ...actions));
  }

  function credRows(kind) {
    const list = keys.credentials.filter((c) => c.kind === kind);
    if (!list.length) return null;
    return h("table.tbl.tfa-keys", h("tbody", ...list.map((c) => h("tr",
      h("td", c.name),
      h("td", "added " + fmtDateTime(c.created_at).slice(0, 10)),
      h("td", c.last_used_at ? "last used " + fmtRelative(c.last_used_at) : "never used"),
      h("td", { style: "text-align:right" }, h("button.btn.sm.ghost", { "aria-label": `Remove ${c.name}`, onclick: () => removeCred(c) }, "Remove")),
    ))));
  }

  function addCred(kind) {
    const label = kind === "passkey" ? "passkey" : "security key";
    const name = h("input", { type: "text", maxlength: "60", placeholder: kind === "passkey" ? "e.g. MacBook, phone, 1Password" : "e.g. YubiKey 5 (desk)" });
    confirmWithPassword(kind === "passkey" ? "Add a passkey" : "Add a security key",
      kind === "passkey"
        ? "A passkey lives on this device, your phone or a password manager and asks for your fingerprint, face or PIN. After confirming, follow your browser's prompt."
        : "A hardware key such as a YubiKey (USB or NFC). After confirming, insert the key and touch it when your browser asks.",
      [field("Name", name, "So you can tell your keys apart later.")], "Continue", false,
      async (password, m) => {
        const begin = await api.webauthnBegin({ password, kind, name: name.value });
        const credential = await createCredential(begin.options);
        await api.webauthnFinish({ token: begin.token, credential });
        m.close(); toast(`The ${label} was added`, "ok"); await loadKeys();
      });
  }

  function removeCred(c) {
    const label = c.kind === "passkey" ? "passkey" : "security key";
    confirmWithPassword(`Remove this ${label}?`, `"${c.name}" will no longer be accepted when you sign in.`, [], "Remove", true,
      async (password, m) => { await api.webauthnRemove(c.id, password); m.close(); toast(`The ${label} was removed`, "ok"); await loadKeys(); });
  }

  async function loadKeys() {
    try { keys = await api.webauthnList(); } catch (e) { /* keep what is shown */ }
    ctx.me.two_factor = [...(ctx.me.totp_enabled ? ["totp"] : []), ...["key", "passkey"].filter((k) => keys.credentials.some((c) => c.kind === k))];
    drawTfa();
  }

  function drawTfa() {
    const on = ctx.me.totp_enabled || keys.credentials.length > 0;
    const canKeys = keys.available && webauthnSupported();
    const full = keys.credentials.length >= keys.limit;
    const why = !keys.available ? keys.reason : !webauthnSupported() ? "Security keys and passkeys need HTTPS and a browser that supports them." : full ? `The limit of ${keys.limit} keys and passkeys is reached.` : "";
    const count = (kind) => { const n = keys.credentials.filter((c) => c.kind === kind).length; return n ? h("span.badge.ok", String(n)) : h("span.badge.muted", "none"); };
    clear(tfaCard).append(...[
      h("div.spread",
        h("h2", "Two-factor authentication"),
        on ? h("span.badge.ok", "enabled") : h("span.badge.muted", "off")),
      h("p.sub", "Signing in asks for your password and then one of the methods below. Enroll more than one, so a lost phone or key does not lock you out."),
      methodRow("Authenticator app", "Time-based one-time codes (TOTP): Google Authenticator, Aegis, 1Password and hardware TOTP tokens.",
        ctx.me.totp_enabled ? h("span.badge.ok", "on") : h("span.badge.muted", "off"),
        ctx.me.totp_enabled
          ? h("button.btn.sm.danger", { onclick: () => confirmWithPassword("Turn off the authenticator app?", "Codes from your app will no longer be asked for or accepted.", [], "Disable two-factor", true,
              async (password, m) => { await api.totpDisable({ password }); ctx.me.totp_enabled = false; m.close(); toast("Two-factor disabled", "ok"); loadKeys(); }) }, "Turn off")
          : h("button.btn.sm.primary", { onclick: () => confirmWithPassword("Set up an authenticator app", "Confirm your password to get the QR code.", [], "Continue", false,
              async (password, m) => { const setup = await api.totpSetup({ password }); m.close(); showTfaEnroll(setup); }) }, "Set up two-factor")),
      methodRow("Security keys", "Hardware keys (FIDO2 / WebAuthn) such as YubiKey: insert and touch. Resistant to phishing.",
        count("key"),
        h("button.btn.sm.primary", { disabled: !canKeys || full, title: why, onclick: () => addCred("key") }, "Add security key")),
      credRows("key"),
      methodRow("Passkeys", "This device, your phone or a password manager, unlocked with a fingerprint, face or PIN. Resistant to phishing.",
        count("passkey"),
        h("button.btn.sm.primary", { disabled: !canKeys || full, title: why, onclick: () => addCred("passkey") }, "Add passkey")),
      credRows("passkey"),
      why && !full ? h("p.hint", why) : null,
    ].filter(Boolean));
  }
  function showTfaEnroll(setup) {
    // QR via the vendored qrcode-generator lib (global `qrcode`); type 0 = auto-size.
    const qr = qrcode(0, "M");
    qr.addData(setup.otpauth);
    qr.make();
    const img = h("img", { src: qr.createDataURL(5, 20), alt: "TOTP enrollment QR code", style: "display:block;margin:0 auto;border-radius:8px;width:220px;height:220px;image-rendering:pixelated" });
    const secret = h("input", { type: "text", value: setup.secret, readonly: true, style: "font-family:var(--mono)" });
    const code = h("input", { type: "text", inputmode: "numeric", maxlength: "6", placeholder: "123456", autocomplete: "one-time-code" });
    const mErr = h("p.error-text");
    const m = modal("Set up two-factor", "Scan the QR code with your authenticator app, or enter the secret into the app or your hardware TOTP key. Then confirm with a generated code.", [
      img,
      field("Secret (manual entry)", h("div.copyfield", secret,
        h("button.btn.sm.ghost", { onclick: () => navigator.clipboard.writeText(setup.secret).then(() => toast("Copied", "ok")) }, "Copy"))),
      field("Code from device", code),
      mErr,
    ], [
      h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"),
      h("button.btn.primary", { onclick: async () => {
        mErr.textContent = "";
        try { await api.totpEnable({ code: code.value }); ctx.me.totp_enabled = true; m.close(); toast("Two-factor enabled", "ok"); loadKeys(); }
        catch (e) { mErr.textContent = e.message; }
      } }, "Verify & enable"),
    ]);
  }
  drawTfa();
  loadKeys();

  body.append(h("div.stack", nameCard, emailCard, pwCard, tfaCard));
}

// ---------- Team ----------
async function teamTab(body, ctx, canManage) {
  const usersBox = h("div.card", h("h2", "Members"), h("p.sub", "People in your organization."), h("div", "Loading..."));
  const invitesBox = h("div.card", h("h2", "Invite links"),
    h("p.sub", "Links expire after 48 hours and can be used once."), h("div", "Loading..."));
  body.append(h("div.stack", usersBox, invitesBox));

  async function refreshUsers() {
    const users = await api.users();
    clear(usersBox); usersBox.append(h("h2", "Members"), h("p.sub", canManage
      ? "People in your organization, how they protect their sign-in and when they last signed in."
      : "People in your organization."));
    // Owners can remove anyone but themselves; admins can remove members only.
    // Owners and admins switch others between admin and member (not the owner, not themselves).
    const canChangeRole = (u) => canManage && !u.self && u.role !== "owner";
    const roleSelect = (u) => {
      const s = h("select", { style: "width:auto;padding:5px 8px;font-size:12.5px", "aria-label": "Role of " + u.email },
        h("option", { value: "admin" }, "admin"), h("option", { value: "member" }, "member"));
      s.value = u.role;
      s.addEventListener("change", async () => {
        try { await api.changeRole(u.id, s.value); toast(`${u.email} is now ${s.value}`, "ok"); await refreshUsers(); }
        catch (e) { toast(e.message, "err"); s.value = u.role; }
      });
      return s;
    };
    const canRemove = (u) => canManage && !u.self && u.role !== "owner" && !(ctx.me.role === "admin" && u.role !== "member");
    // Second factors and the last sign-in are sent only to owners and
    // admins (and to everyone about themselves).
    const FACTOR = { totp: "TOTP", key: "Security key", passkey: "Passkey" };
    const factors = (u) => !u.two_factor ? h("span.muted", "-")
      : u.two_factor.length ? h("span.tfa-badges", ...u.two_factor.map((f) => h("span.badge.ok", FACTOR[f] || f)))
      : h("span.badge.muted", "off");
    const lastLogin = (u) => u.last_login ? h("span", { title: fmtDateTime(u.last_login) }, fmtRelative(u.last_login)) : h("span.muted", u.two_factor ? "never" : "-");
    const tbl = h("table.tbl.team",
      h("thead", h("tr", h("th", "Name"), h("th", "Email"), h("th", "Role"),
        canManage ? h("th", "Two-factor") : null, canManage ? h("th", "Last sign-in") : null,
        h("th", "Joined"), canManage ? h("th", "") : null)),
      h("tbody", ...users.map((u) => h("tr",
        h("td", h("span.who", avatar(u, 28), [u.first_name, u.last_name].filter(Boolean).join(" ") || h("span.muted", "-"))),
        h("td.mono", u.email, u.self ? h("span.badge.muted", { style: "margin-left:8px" }, "you") : null),
        h("td", canChangeRole(u) ? roleSelect(u) : h("span.badge" + (u.role !== "member" ? ".accent" : ""), u.role)),
        canManage ? h("td", factors(u)) : null,
        canManage ? h("td", lastLogin(u)) : null,
        h("td", fmtDateTime(u.created_at)),
        canManage ? h("td", { style: "text-align:right" }, canRemove(u)
          ? h("button.btn.sm.ghost", { onclick: () => confirmDialog("Remove member?",
              `${u.email} will lose access immediately. Their account and sessions are deleted; monitoring data is not affected.`,
              async () => { try { await api.removeUser(u.id); toast("Member removed", "ok"); await refreshUsers(); } catch (e) { toast(e.message, "err"); } },
              "Remove") }, "Remove") : null) : null,
      ))));
    usersBox.append(tbl);
  }

  async function refreshInvites() {
    clear(invitesBox);
    invitesBox.append(h("h2", "Invite links"), h("p.sub", "Links expire after 48 hours and can be used once."));
    if (canManage) {
      const role = h("select", h("option", { value: "member" }, "Member"), h("option", { value: "admin" }, "Admin"));
      invitesBox.append(h("div.spread", { style: "margin-bottom:16px" },
        h("div.row", { style: "max-width:240px" }, role),
        h("button.btn.primary", { onclick: async () => {
          try { const inv = await api.createInvite(role.value); showInviteLink(inv); await refreshInvites(); }
          catch (e) { toast(e.message, "err"); }
        } }, h("span.ico", { html: icons.plus }), "Generate link"),
      ));
    }
    if (!canManage) { invitesBox.append(h("p.muted", "Only owners and admins can create and view invite links.")); return; }
    const invites = await api.invites();
    if (!invites.length) { invitesBox.append(h("p.muted", "No invite links yet.")); return; }
    const tbl = h("table.tbl",
      h("thead", h("tr", h("th", "Link"), h("th", "Role"), h("th", "Status"), canManage ? h("th", "") : null)),
      h("tbody", ...invites.map((inv) => {
        const url = inviteUrl(inv.token);
        const status = inv.used ? h("span.badge", "used") : inv.expired ? h("span.badge", "expired") : h("span.badge.ok", "active · " + fmtUntil(inv.expires_at));
        return h("tr",
          h("td", h("button.btn.sm.ghost", { onclick: () => copy(url), title: url }, "Copy link")),
          h("td", h("span.badge" + (inv.role !== "member" ? ".accent" : ""), inv.role)),
          h("td", status),
          canManage ? h("td", { style: "text-align:right" }, (!inv.used && !inv.expired)
            ? h("button.btn.sm.ghost", { onclick: async () => { try { await api.revokeInvite(inv.token); await refreshInvites(); } catch (e) { toast(e.message, "err"); } } }, "Revoke") : null) : null,
        );
      })));
    invitesBox.append(tbl);
  }

  function showInviteLink(inv) {
    const url = inviteUrl(inv.token);
    const input = h("input", { type: "text", value: url, readonly: true });
    modal("Invite link created", "Share this link. It expires in 48 hours and works once.",
      [h("div.copyfield", input, h("button.btn.primary", { onclick: () => copy(url) }, "Copy"))],
      [h("button.btn.primary", { onclick: () => document.querySelector(".modal-back").remove() }, "Done")]);
  }

  try { await refreshUsers(); await refreshInvites(); }
  catch (e) { toast(e.message, "err"); }
}

function inviteUrl(token) { return `${location.origin}/#/accept?token=${encodeURIComponent(token)}`; }
function copy(text) { navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard", "ok"), () => toast("Copy failed", "err")); }

// ---------- Profiles ----------
async function profilesTab(body, canManage) {
  const card = h("div.card", h("div.spread", h("div", h("h2", "Probe profiles"), h("p.sub", "Predefined sampling presets. Hosts use the default unless you pick another.")),
    canManage ? h("button.btn.primary", { onclick: () => openProfileModal({}, refresh) }, h("span.ico", { html: icons.plus }), "New profile") : null),
    h("div", "Loading..."));
  body.append(card);

  async function refresh() {
    const profiles = await api.profiles();
    clear(card);
    card.append(h("div.spread", h("div", h("h2", "Probe profiles"), h("p.sub", "Predefined sampling presets. Hosts use the default unless you pick another.")),
      canManage ? h("button.btn.primary", { onclick: () => openProfileModal({}, refresh) }, h("span.ico", { html: icons.plus }), "New profile") : null));
    card.append(h("table.tbl",
      h("thead", h("tr", h("th", "Name"), h("th", "Interval"), h("th", "Pings"), h("th", "Packet"), h("th", ""), canManage ? h("th", "") : null)),
      h("tbody", ...profiles.map((p) => h("tr",
        h("td", p.name), h("td", p.interval_s + " s"), h("td", p.ping_count), h("td", p.packet_size + " B"),
        h("td", p.is_default ? h("span.badge.accent", "default") : null),
        canManage ? h("td", { style: "text-align:right;white-space:nowrap" },
          h("button.btn.sm.ghost", { onclick: () => openProfileModal({ profile: p }, refresh) }, "Edit"),
          p.is_default ? null : h("button.btn.sm.ghost", { onclick: () => confirmDialog("Delete profile?", `"${p.name}" will be removed. Hosts using it fall back to the default.`, async () => { try { await api.deleteProfile(p.id); toast("Deleted", "ok"); refresh(); } catch (e) { toast(e.message, "err"); } }) }, "Delete")) : null,
      )))));
  }
  try { await refresh(); } catch (e) { toast(e.message, "err"); }
}

function openProfileModal({ profile = null }, onDone) {
  const editing = !!profile;
  const name = h("input", { type: "text", value: profile ? profile.name : "", placeholder: "e.g. Standard" });
  const interval = h("input", { type: "number", min: LIMITS.min_interval, max: 86400, value: profile ? profile.interval_s : 60 });
  const count = h("input", { type: "number", min: "1", max: LIMITS.max_pings, value: profile ? profile.ping_count : 20 });
  const size = h("input", { type: "number", min: "12", max: LIMITS.max_packet, value: profile ? profile.packet_size : 56 });
  const rules = h("p.hint", `Interval ${LIMITS.min_interval}-86400 s · pings 1-${LIMITS.max_pings} and not more than the interval in seconds · packet 12-${LIMITS.max_packet} B` +
    (LIMITS_STRICT() ? " (test instance limits)" : " (1500 MTU minus IPv4 and ICMP headers)") + ".");
  const def = h("input", { type: "checkbox" }); def.checked = profile ? profile.is_default : false;
  const err = h("p.error-text");
  const m = modal(editing ? "Edit profile" : "New profile", "Sampling preset for hosts.", [
    field("Name", name),
    h("div.row", field("Interval (s)", interval), field("Pings / cycle", count), field("Packet size (B)", size)),
    rules,
    h("label.field", { style: "display:flex;gap:8px;align-items:center;flex-direction:row" }, def, h("span.lbl", { style: "margin:0" }, "Use as default for new hosts")),
    err,
  ], [
    h("button.btn.ghost", { onclick: () => m.close() }, "Cancel"),
    h("button.btn.primary", { onclick: save }, editing ? "Save" : "Create"),
  ]);
  async function save() {
    err.textContent = "";
    const iv = Number(interval.value), pc = Number(count.value), ps = Number(size.value);
    if (iv < LIMITS.min_interval) { err.textContent = `Interval must be at least ${LIMITS.min_interval} s${LIMITS_STRICT() ? " on this test instance" : ""}.`; return; }
    if (pc > iv) { err.textContent = `Pings per cycle (${pc}) cannot exceed the interval in seconds (${iv}).`; return; }
    if (ps > LIMITS.max_packet) { err.textContent = `Packet size can be at most ${LIMITS.max_packet} B${LIMITS_STRICT() ? " on this test instance" : ""}.`; return; }
    const payload = { name: name.value, interval_s: Number(interval.value), ping_count: Number(count.value), packet_size: Number(size.value), is_default: def.checked };
    try {
      if (editing) await api.updateProfile(profile.id, payload); else await api.createProfile(payload);
      m.close(); toast("Saved", "ok"); onDone();
    } catch (e) { err.textContent = e.message; }
  }
}

// ---------- Import (SmokePing) ----------
function importTab(body, canManage) {
  const ta = h("textarea", { rows: 14, placeholder: "Paste your SmokePing Targets config here, or choose a file below...", style: "font-family:var(--mono);font-size:12px" });
  const file = h("input", { type: "file", accept: ".cfg,.conf,.txt,text/plain" });
  const err = h("p.error-text");
  const info = h("p.hint");
  // Check the file before showing it: plain UTF-8 text only (the server
  // checks again). Binary files never reach the text box.
  file.addEventListener("change", async () => {
    err.textContent = ""; info.textContent = "";
    const f = file.files && file.files[0]; if (!f) return;
    const reject = (msg) => { err.textContent = msg; file.value = ""; ta.value = ""; };
    if (f.size > IMPORT_MAX_BYTES) return reject(`The file is ${(f.size / 1048576).toFixed(1)} MB; the limit is 2 MB.`);
    const buf = new Uint8Array(await f.arrayBuffer());
    const kind = sniffBinary(buf);
    if (kind) return reject(`This looks like ${kind}, not a SmokePing config. Choose the plain-text config file (for example /etc/smokeping/config or config.d/Targets).`);
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(buf); }
    catch (e) { return reject("The file is not UTF-8 text. Choose the plain-text SmokePing config file."); }
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) return reject("The file contains binary data. Choose the plain-text SmokePing config file.");
    if (/^\s*#!/.test(text)) return reject("Scripts are not accepted. Choose the SmokePing config itself.");
    const lines = text.split("\n").length;
    if (lines > IMPORT_MAX_LINES) return reject(`The file has ${lines} lines; the limit is ${IMPORT_MAX_LINES}.`);
    if (!/^\s*\*{3}\s*targets\s*\*{3}\s*$/im.test(text)) return reject("No *** Targets *** section found. Is this a SmokePing config?");
    ta.value = text;
    info.textContent = `${f.name}: ${lines} lines, ${(text.match(/^\s*host\s*=/gim) || []).length} host entries.`;
  });
  const card = h("div.card",
    h("h2", "Import from SmokePing"),
    h("p.sub", "Paste your SmokePing config (or upload the file). Driftband reads the *** Targets *** section and recreates the folder/host tree; hosts get your default probe profile."),
    canManage ? h("label.field", h("span.lbl", "Config file"), file) : null,
    h("label.field", h("span.lbl", "Config text"), ta),
    info, err,
    canManage
      ? h("button.btn.primary", { onclick: doImport }, "Import")
      : h("p.hint", "Only owners and admins can import."),
    h("p.hint", { style: "margin-top:14px" }, "Plain-text SmokePing config only (up to 2 MB, 20 000 lines, 1 000 hosts per import); binary files and scripts are refused. Only targets are imported (probes and alerts are ignored). Branches deeper than 3 levels are flattened. Import adds to the existing tree; it does not remove anything."),
  );
  body.append(card);

  async function doImport() {
    err.textContent = "";
    if (!ta.value.trim()) { err.textContent = "Paste a config or choose a file first."; return; }
    try {
      const res = await api.importSmokeping(ta.value);
      toast(`Imported ${res.folders} folders and ${res.hosts} hosts`, "ok");
      ta.value = ""; file.value = "";
      info.textContent = (res.warnings || []).length ? "Note: " + res.warnings.join("; ") + "." : "";
    } catch (e) { err.textContent = e.message; }
  }
}

const IMPORT_MAX_BYTES = 2 * 1048576, IMPORT_MAX_LINES = 20000;
const SIGNATURES = [
  [[0x25, 0x50, 0x44, 0x46], "a PDF document"], [[0x50, 0x4b, 0x03, 0x04], "a ZIP archive or Office document"],
  [[0xd0, 0xcf, 0x11, 0xe0], "an Office document"], [[0x7b, 0x5c, 0x72, 0x74, 0x66], "an RTF document"],
  [[0x7f, 0x45, 0x4c, 0x46], "a program"], [[0x4d, 0x5a], "a Windows program"], [[0x1f, 0x8b], "a gzip archive"],
  [[0x42, 0x5a, 0x68], "a bzip2 archive"], [[0x37, 0x7a, 0xbc, 0xaf], "a 7-Zip archive"],
  [[0x89, 0x50, 0x4e, 0x47], "an image"], [[0x47, 0x49, 0x46, 0x38], "an image"], [[0xff, 0xd8, 0xff], "an image"],
];
function sniffBinary(buf) {
  for (const [sig, what] of SIGNATURES) if (sig.every((b, i) => buf[i] === b)) return what;
  if (buf.subarray(0, 8192).includes(0)) return "a binary file";
  return null;
}

// ---------- Retention ----------
function retentionTab(body, ctx, canManage) {
  const cur = ctx.me.org.retention_years || 1;
  const card = h("div.card", h("h2", "Data retention"),
    h("p.sub", "The housekeeper removes raw samples older than this window. Default is 1 year."));
  const opts = [1, 2, 3].map((y) => {
    const radio = h("input", { type: "radio", name: "ret", value: y }); radio.checked = y === cur; radio.disabled = !canManage;
    return h("label.field", { style: "display:flex;gap:10px;align-items:center;flex-direction:row" }, radio, h("span.lbl", { style: "margin:0" }, y + (y === 1 ? " year" : " years")));
  });
  card.append(...opts);
  if (canManage) {
    card.append(h("button.btn.primary", { onclick: async () => {
      const sel = card.querySelector('input[name=ret]:checked');
      try { await api.setRetention(Number(sel.value)); ctx.me.org.retention_years = Number(sel.value); toast("Retention updated", "ok"); }
      catch (e) { toast(e.message, "err"); }
    } }, "Save"));
  } else {
    card.append(h("p.hint", "Only owners and admins can change retention."));
  }
  body.append(card);
}

// ---------- Audit ----------
async function auditTab(body) {
  const tbody = h("tbody");
  const pg = pager("audit", load);
  const card = h("div.card", h("h2", "Audit log"), h("p.sub", "Actions in your organization, newest first."),
    h("div", { style: "overflow-x:auto" }, h("table.tbl",
      h("thead", h("tr", h("th", "When"), h("th", "User"), h("th", "Action"), h("th", "Detail"), h("th", "IP"))), tbody)),
    pg.el);
  body.append(card);
  async function load() {
    let page;
    try { page = await api.audit({ limit: pg.limit, offset: pg.offset }); } catch (e) { toast(e.message, "err"); return; }
    if (!pg.set(page.total)) return;
    clear(tbody);
    if (!page.items.length) { tbody.append(h("tr", h("td", { colspan: 5, class: "muted" }, "No activity yet."))); return; }
    for (const r of page.items) {
      tbody.append(h("tr",
        h("td", { title: fmtDateTime(r.created_at) }, fmtRelative(r.created_at)),
        h("td.mono", r.email || "-"),
        h("td", h(/^(denied\.|auth\.login_(failed|blocked))/.test(r.action) ? "span.badge.bad" : "span.badge", r.action)),
        h("td", r.detail || ""),
        h("td.mono", r.ip || ""),
      ));
    }
  }
  await load();
}
