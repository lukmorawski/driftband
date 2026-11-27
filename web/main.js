// Driftband SPA entry: routing, auth gate, nav + footer shell.
import { api } from "./js/api.js";
import { h, clear, applyTheme, currentTheme, toggleTheme, isWide, icons, toast, avatar } from "./js/ui.js";
import { renderAuth, renderAccept, renderSsoReturn } from "./js/views/auth.js";
import { renderDashboard } from "./js/views/dashboard.js";
import { renderSettings } from "./js/views/settings.js";
import { renderFaq } from "./js/views/faq.js";
import { renderAdmin } from "./js/views/admin.js";
import { renderAlerts } from "./js/views/alerts.js";

const root = document.getElementById("root");
let me = null;

// A single sign-on provider sends the browser back to /sso with its answer
// in the query string. The answer is taken out of the address bar (and the
// history) before anything else happens.
let ssoReturn = null;
if (location.pathname === "/sso") {
  ssoReturn = new URLSearchParams(location.search);
  history.replaceState(null, "", "/");
}

applyTheme(currentTheme());
window.addEventListener("hashchange", route);
route();

function parseHash() {
  const raw = location.hash.replace(/^#/, "") || "/dashboard";
  const [path, query] = raw.split("?");
  const params = new URLSearchParams(query || "");
  return { path, params };
}

function navigate(path) {
  if (location.hash === "#" + path) route();
  else location.hash = path;
}

async function route() {
  const { path, params } = parseHash();

  if (ssoReturn) {
    const answer = ssoReturn;
    ssoReturn = null;
    renderSsoReturn(root, answer, { onAuthed: afterAuth, onDone: (to) => { me = null; navigate(to); } });
    return;
  }

  // Invite acceptance works without a session.
  if (path === "/accept") {
    clear(root);
    renderAccept(root, params.get("token") || "", { onAuthed: afterAuth });
    return;
  }

  if (!me) {
    try { me = await api.me(); }
    catch (e) { me = null; }
  }
  if (!me) {
    clear(root);
    renderAuth(root, { onAuthed: afterAuth });
    return;
  }
  renderShell(path, params);
}

async function afterAuth() {
  me = await api.me();
  // navigate() routes once itself (directly, or via the hashchange event);
  // calling route() here as well rendered the whole dashboard twice.
  navigate("/dashboard");
}

function themeBtn() {
  const b = h("button.btn.icon.ghost", { title: "Toggle theme", onclick: () => { toggleTheme(); refreshThemeIcon(b); } });
  refreshThemeIcon(b);
  return b;
}
function refreshThemeIcon(b) { b.innerHTML = `<span class="ico">${currentTheme() === "dark" ? icons.sun : icons.moon}</span>`; }

function renderShell(path, params) {
  clear(root);
  const links = [
    { p: "/dashboard", label: "Dashboard" },
    { p: "/settings", label: "Settings" },
    { p: "/faq", label: "FAQ" },
  ];
  if (me.is_superadmin) links.push({ p: "/admin", label: "Admin" });
  const nav = h("nav.nav",
    h("div.nav-inner",
      h("div.brand", h("span.dot"), "Driftband"),
      h("div.nav-links", ...links.map((l) =>
        h("a", { href: "#" + l.p, class: path.startsWith(l.p) ? "active" : "" }, l.label))),
      h("div.nav-center", alertsLink(path)),
      h("div.nav-right",
        avatar(me, 26),
        h("span.nav-user", me.email),
        themeBtn(),
        h("button.btn.sm.ghost", { onclick: doLogout }, "Sign out"),
      ),
    ),
  );

  const main = h("main.app-main");
  const footer = h("footer.footer",
    h("div.footer-inner",
      h("div", "Driftband" + (me.version ? " " + me.version : "") + " · ICMP latency monitor"),
      h("div", { class: "muted", style: "display:flex;gap:16px;align-items:center;flex-wrap:wrap" },
        h("a", { href: "https://driftband.app", target: "_blank", rel: "noopener" }, "driftband.app"),
        h("a", { href: "https://driftband.app/whats-new/", target: "_blank", rel: "noopener" }, "What's new"),
        h("a", { href: "https://github.com/lukmorawski/driftband", target: "_blank", rel: "noopener" }, "Source"),
        h("a", { href: "https://buymeacoffee.com/lukmorawski", target: "_blank", rel: "noopener" }, "Buy me a coffee"),
        h("a", { href: "https://www.gnu.org/licenses/agpl-3.0.html", target: "_blank", rel: "noopener" }, "AGPL-3.0"),
      ),
    ),
  );

  root.append(h("div.app" + (isWide() ? ".wide" : ""), nav, main, footer));

  if (path.startsWith("/settings")) renderSettings(main, { me, tab: params.get("tab") || "account", navigate });
  else if (path.startsWith("/faq")) renderFaq(main);
  else if (path.startsWith("/alerts")) renderAlerts(main);
  else if (path.startsWith("/admin") && me.is_superadmin) renderAdmin(main, { me, tab: params.get("tab") });
  else renderDashboard(main, { me, navigate });
}

// "Active Alerts" in the middle of the navigation bar: a link to the alerts
// page with the number of alerting rule/host pairs, refreshed every minute
// while this shell is on screen.
let alertsTimer = null;
function alertsLink(path) {
  const count = h("span.nav-alerts-count", { hidden: true });
  const link = h("a.nav-alerts", { href: "#/alerts", class: path.startsWith("/alerts") ? "active" : "" }, "Active Alerts", count);
  async function refresh() {
    if (!link.isConnected) { clearInterval(alertsTimer); return; }
    try {
      const ev = await api.notifyEvents({ limit: 1 });
      const n = ev.active.length;
      count.textContent = n ? String(n) : "";
      count.hidden = n === 0;
      link.classList.toggle("alerting", n > 0);
      link.title = n ? `${n} active alert${n === 1 ? "" : "s"}` : "Nothing is alerting right now";
    } catch (e) { /* signed out or offline: leave the link as it is */ }
  }
  clearInterval(alertsTimer);
  alertsTimer = setInterval(refresh, 60000);
  setTimeout(refresh, 0); // after the shell is in the document
  return link;
}

async function doLogout() {
  try { await api.logout(); } catch (e) {}
  me = null;
  navigate("/dashboard");
  route();
}
