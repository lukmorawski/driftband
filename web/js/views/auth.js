import { api } from "../api.js";
import { h, clear, toast, currentTheme, toggleTheme, icons } from "../ui.js";
import { webauthnSupported, getAssertion, webauthnError } from "../webauthn.js";
import { captcha, CAPTCHA_WAIT } from "../turnstile.js";

// What the server allows on these pages. If it cannot be asked, assume the
// defaults; the server enforces its settings either way.
async function authConfig() {
  try { return await api.authConfig(); }
  catch (e) { return { registration_open: true, turnstile_site_key: "", sso: [] }; }
}

function field(label, input) {
  return h("label.field", h("span.lbl", label), input);
}

function authShell(...kids) {
  return h("div.auth-wrap",
    h("div.auth-card.card",
      h("div.auth-brand", h("span.dot", { class: "dot", style: "width:12px;height:12px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 16%,transparent),0 0 16px 2px var(--accent)" }), "Driftband"),
      ...kids,
    ),
  );
}

export async function renderAuth(mount, { onAuthed }) {
  clear(mount);
  let mode = "login";
  const err = h("p.error-text");

  const wrap = authShell();
  const card = wrap.querySelector(".auth-card");
  mount.append(wrap);
  const cfg = await authConfig();
  // With organization creation turned off there is only the sign-in form:
  // new people join through an invitation link.
  const tabs = h("div.auth-tabs",
    h("button", { onclick: () => set("login") }, "Sign in"),
    cfg.registration_open ? h("button", { onclick: () => set("register") }, "Create organization") : null,
  );
  tabs.hidden = !cfg.registration_open;
  const formHost = h("div");
  card.append(tabs, formHost, err);

  function set(m) { mode = m; err.textContent = ""; draw(); }

  function draw() {
    [...tabs.children].forEach((b, i) => b.className = (mode === "login") === (i === 0) ? "active" : "");
    clear(formHost);
    const check = captcha(cfg.turnstile_site_key);
    if (mode === "login") {
      const email = h("input", { type: "email", autocomplete: "email", placeholder: "you@example.com" });
      const pw = h("input", { type: "password", autocomplete: "current-password", placeholder: "Password" });
      const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", placeholder: "123456" });
      // After the password is accepted the server says which second factors
      // the account has: a code (TOTP), a security key / passkey, or both.
      let challenge = null; // { token, options } for the key, single use
      // Issued with the request for a second factor: it stands in for the
      // verification on the request that brings the code or the key.
      let pass = "";
      const keyBtn = h("button.btn", { type: "button", hidden: true, onclick: () => useKey() }, "Use security key or passkey");
      keyBtn.classList.add("auth-key");
      const needSecond = (e) => {
        const d = e.data || {};
        const methods = d.methods || (d.totp_required ? ["totp"] : []);
        const first = codeField.hidden && keyBtn.hidden;
        challenge = d.webauthn || null;
        pass = d.captcha_pass || "";
        codeField.hidden = !methods.includes("totp");
        keyBtn.hidden = !challenge;
        if (!first) { err.textContent = e.message; }
        else if (challenge && !webauthnSupported()) err.textContent = "This browser or address cannot use security keys" + (codeField.hidden ? "." : "; enter the code from your authenticator app.");
        else if (challenge && !codeField.hidden) err.textContent = "Use your security key or passkey, or enter the 6-digit code from your authenticator app.";
        else if (challenge) err.textContent = "Use your security key or passkey to finish signing in.";
        else if (!codeField.hidden) err.textContent = "Enter the 6-digit code from your authenticator app or key.";
        else err.textContent = e.message;
        code.value = "";
        if (!codeField.hidden) code.focus();
        return first;
      };
      const send = async (extra) => {
        const proof = pass ? { captcha_pass: pass } : check.el ? { turnstile_token: check.token() } : {};
        if (check.el && !pass && !check.token()) return new Error(CAPTCHA_WAIT);
        try { await api.login({ email: email.value, password: pw.value, ...extra, ...proof }); onAuthed(); return null; }
        catch (e) {
          if (!pass) check.reset(); // the token went with this request
          if (e.data && e.data.captcha_failed) pass = "";
          return e;
        }
      };
      async function useKey() {
        if (!challenge) return;
        err.textContent = "Waiting for your security key or passkey: follow your browser's prompt.";
        const ch = challenge;
        let credential;
        keyBtn.disabled = true;
        try { credential = await getAssertion(ch.options); }
        catch (e) { err.textContent = webauthnError(e); keyBtn.disabled = false; return; }
        const e = await send({ webauthn_token: ch.token, credential });
        keyBtn.disabled = false;
        if (e && e.data && e.data.two_factor_required) needSecond(e);
        else if (e) err.textContent = e.message;
      }
      const submit = async () => {
        err.textContent = "";
        const e = await send({ code: code.value });
        if (!e) return;
        if (e.data && (e.data.two_factor_required || e.data.totp_required)) {
          // Password accepted. When a key is the only second factor, ask
          // for it right away; with a code as well, the user chooses.
          if (needSecond(e) && challenge && webauthnSupported() && codeField.hidden) useKey();
        } else {
          err.textContent = e.message;
        }
      };
      const codeField = field("Two-factor code", onEnter(code, submit));
      codeField.hidden = true;
      formHost.append(
        field("Email", email),
        field("Password", onEnter(pw, submit)),
        codeField,
        ...widget(check),
        h("button.btn.primary", { style: "width:100%", onclick: submit }, "Sign in"),
        keyBtn,
        ...ssoButtons(cfg.sso),
      );
    } else {
      const org = h("input", { type: "text", placeholder: "Acme Inc." });
      const email = h("input", { type: "email", autocomplete: "email", placeholder: "you@example.com" });
      const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "At least 8 characters" });
      const submit = async () => {
        err.textContent = "";
        if (check.el && !check.token()) { err.textContent = CAPTCHA_WAIT; return; }
        const proof = check.el ? { turnstile_token: check.token() } : {};
        try { await api.registerOrg({ org_name: org.value, email: email.value, password: pw.value, ...proof }); onAuthed(); }
        catch (e) { check.reset(); err.textContent = e.message; }
      };
      formHost.append(
        field("Organization name", org),
        field("Your email", email),
        field("Password", onEnter(pw, submit)),
        ...widget(check),
        h("button.btn.primary", { style: "width:100%", onclick: submit }, "Create organization"),
        h("p.hint", "You become the owner. Invite teammates afterwards from Settings."),
      );
    }
  }
  draw();
}

export async function renderAccept(mount, token, { onAuthed }) {
  clear(mount);
  const err = h("p.error-text");
  const wrap = authShell(h("p.sub", { style: "text-align:center" }, "Loading invite..."));
  mount.append(wrap);
  const card = wrap.querySelector(".auth-card");

  if (!token) { card.lastChild.textContent = "Missing invite token."; return; }
  let info;
  try { info = await api.inviteInfo(token); }
  catch (e) { clear(card); card.append(h("div.auth-brand", "Driftband"), h("p.sub", { style: "text-align:center" }, e.message), h("a", { href: "#/dashboard", style: "display:block;text-align:center;margin-top:10px" }, "Go to sign in")); return; }

  clear(card);
  const check = captcha((await authConfig()).turnstile_site_key);
  const email = h("input", { type: "email", autocomplete: "email", placeholder: "you@example.com" });
  const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "At least 8 characters" });
  const submit = async () => {
    err.textContent = "";
    if (check.el && !check.token()) { err.textContent = CAPTCHA_WAIT; return; }
    const proof = check.el ? { turnstile_token: check.token() } : {};
    try { await api.acceptInvite({ token, email: email.value, password: pw.value, ...proof }); onAuthed(); }
    catch (e) { check.reset(); err.textContent = e.message; }
  };
  card.append(
    h("div.auth-brand", h("span.dot", { style: "width:12px;height:12px;border-radius:50%;background:var(--accent)" }), "Driftband"),
    h("p.sub", { style: "text-align:center" }, `Join ${info.org} as ${info.role}`),
    field("Email", email),
    field("Password", onEnter(pw, submit)),
    ...widget(check),
    h("button.btn.primary", { style: "width:100%", onclick: submit }, "Join organization"),
    err,
  );
}

// The verification widget as form content: nothing when the check is off.
function widget(check) { return check.el ? [check.el] : []; }

// One button per single sign-on provider of this instance. They are plain
// links: the server sends the browser on to the provider.
function ssoButtons(list) {
  if (!list || !list.length) return [];
  return [
    h("div.auth-sep", h("span", "or")),
    ...list.map((p) => h("a.btn.auth-sso", { href: `/api/auth/sso/${encodeURIComponent(p.id)}/start` }, `Sign in with ${p.name}`)),
  ];
}

// The page the provider sends the browser back to (/sso?code=...&state=...).
// params is that query string; the address bar has been cleaned already.
// A sign-in is finished here, with the second factor when the account has
// one; a request to connect an account is stored. onAuthed runs after a
// sign-in, onDone(tab) leads back into the application.
export async function renderSsoReturn(mount, params, { onAuthed, onDone }) {
  clear(mount);
  const state = params.get("state") || "";
  const linking = state.startsWith("link.");
  const msg = h("p.sub", { style: "text-align:center" }, linking ? "Connecting the account..." : "Signing in...");
  const err = h("p.error-text");
  const formHost = h("div");
  const back = h("a", { href: "#/dashboard", hidden: true, style: "display:block;text-align:center;margin-top:10px",
    onclick: (e) => { e.preventDefault(); onDone(linking ? "/settings" : "/dashboard"); } }, linking ? "Back to settings" : "Back to sign in");
  const wrap = authShell(msg, formHost, err, back);
  mount.append(wrap);
  const fail = (text) => { msg.hidden = true; err.textContent = text; back.hidden = false; };

  if (params.get("error")) {
    fail(params.get("error") === "access_denied" ? "The sign-in was cancelled."
      : params.get("error") === "temporarily_unavailable" ? "This sign-in method cannot be reached right now. Try again in a moment."
      : "The sign-in provider reported an error. Try again.");
    return;
  }
  const answer = { state, authorization_code: params.get("code") || "" };

  if (linking) {
    try {
      const r = await api.ssoLinkFinish(answer);
      toast(`Your ${r.name} account is connected`, "ok");
      onDone("/settings");
    } catch (e) { fail(e.status === 401 ? "Sign in first, then connect the account under Settings, Account." : e.message); }
    return;
  }

  let challenge = null; // { token, options } for a security key or passkey
  const send = async (extra) => {
    try { await api.ssoFinish({ ...answer, ...extra }); onAuthed(); return null; }
    catch (e) { return e; }
  };
  const first = await send({});
  if (!first) return;
  if (!(first.data && first.data.two_factor_required)) { fail(first.message); return; }

  // The provider vouched for the first factor; the account's second one follows.
  const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", placeholder: "123456" });
  const codeField = field("Two-factor code", onEnter(code, () => submit()));
  const keyBtn = h("button.btn.auth-key", { type: "button", onclick: () => useKey() }, "Use security key or passkey");
  const go = h("button.btn.primary", { style: "width:100%", onclick: () => submit() }, "Sign in");
  const ask = (e) => {
    const d = e.data || {};
    if (!d.two_factor_required) { clear(formHost); fail(e.message); return false; }
    const methods = d.methods || [];
    challenge = d.webauthn || null;
    codeField.hidden = go.hidden = !methods.includes("totp");
    keyBtn.hidden = !challenge;
    return true;
  };
  async function submit() {
    err.textContent = "";
    const e = await send({ code: code.value });
    if (e && ask(e)) { err.textContent = e.message; code.value = ""; code.focus(); }
  }
  async function useKey() {
    if (!challenge) return;
    err.textContent = "Waiting for your security key or passkey: follow your browser's prompt.";
    const ch = challenge;
    let credential;
    keyBtn.disabled = true;
    try { credential = await getAssertion(ch.options); }
    catch (e) { err.textContent = webauthnError(e); keyBtn.disabled = false; return; }
    const e = await send({ webauthn_token: ch.token, credential });
    keyBtn.disabled = false;
    if (e && ask(e)) err.textContent = e.message;
  }
  formHost.append(codeField, go, keyBtn);
  if (!ask(first)) return;
  msg.textContent = "One more step: your second factor.";
  if (challenge && !webauthnSupported()) err.textContent = "This browser or address cannot use security keys" + (codeField.hidden ? "." : "; enter the code from your authenticator app.");
  else if (challenge && codeField.hidden) useKey();
  else if (!codeField.hidden) code.focus();
  else err.textContent = first.message;
}

function onEnter(input, fn) { input.addEventListener("keydown", (e) => { if (e.key === "Enter") fn(); }); return input; }
