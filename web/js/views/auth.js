import { api } from "../api.js";
import { h, clear, toast, currentTheme, toggleTheme, icons } from "../ui.js";
import { webauthnSupported, getAssertion, webauthnError } from "../webauthn.js";

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

export function renderAuth(mount, { onAuthed }) {
  clear(mount);
  let mode = "login";
  const err = h("p.error-text");

  const wrap = authShell();
  const card = wrap.querySelector(".auth-card");
  const tabs = h("div.auth-tabs",
    h("button", { onclick: () => set("login") }, "Sign in"),
    h("button", { onclick: () => set("register") }, "Create organization"),
  );
  const formHost = h("div");
  card.append(tabs, formHost, err);
  mount.append(wrap);

  function set(m) { mode = m; err.textContent = ""; draw(); }

  function draw() {
    tabs.children[0].className = mode === "login" ? "active" : "";
    tabs.children[1].className = mode === "register" ? "active" : "";
    clear(formHost);
    if (mode === "login") {
      const email = h("input", { type: "email", autocomplete: "email", placeholder: "you@example.com" });
      const pw = h("input", { type: "password", autocomplete: "current-password", placeholder: "Password" });
      const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", placeholder: "123456" });
      // After the password is accepted the server says which second factors
      // the account has: a code (TOTP), a security key / passkey, or both.
      let challenge = null; // { token, options } for the key, single use
      const keyBtn = h("button.btn", { type: "button", hidden: true, onclick: () => useKey() }, "Use security key or passkey");
      keyBtn.classList.add("auth-key");
      const needSecond = (e) => {
        const d = e.data || {};
        const methods = d.methods || (d.totp_required ? ["totp"] : []);
        const first = codeField.hidden && keyBtn.hidden;
        challenge = d.webauthn || null;
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
        try { await api.login({ email: email.value, password: pw.value, ...extra }); onAuthed(); return null; }
        catch (e) { return e; }
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
        h("button.btn.primary", { style: "width:100%", onclick: submit }, "Sign in"),
        keyBtn,
      );
    } else {
      const org = h("input", { type: "text", placeholder: "Acme Inc." });
      const email = h("input", { type: "email", autocomplete: "email", placeholder: "you@example.com" });
      const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "At least 8 characters" });
      const submit = async () => {
        err.textContent = "";
        try { await api.registerOrg({ org_name: org.value, email: email.value, password: pw.value }); onAuthed(); }
        catch (e) { err.textContent = e.message; }
      };
      formHost.append(
        field("Organization name", org),
        field("Your email", email),
        field("Password", onEnter(pw, submit)),
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
  const email = h("input", { type: "email", autocomplete: "email", placeholder: "you@example.com" });
  const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "At least 8 characters" });
  const submit = async () => {
    err.textContent = "";
    try { await api.acceptInvite({ token, email: email.value, password: pw.value }); onAuthed(); }
    catch (e) { err.textContent = e.message; }
  };
  card.append(
    h("div.auth-brand", h("span.dot", { style: "width:12px;height:12px;border-radius:50%;background:var(--accent)" }), "Driftband"),
    h("p.sub", { style: "text-align:center" }, `Join ${info.org} as ${info.role}`),
    field("Email", email),
    field("Password", onEnter(pw, submit)),
    h("button.btn.primary", { style: "width:100%", onclick: submit }, "Join organization"),
    err,
  );
}

function onEnter(input, fn) { input.addEventListener("keydown", (e) => { if (e.key === "Enter") fn(); }); return input; }
