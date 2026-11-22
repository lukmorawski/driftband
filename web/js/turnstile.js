// Cloudflare Turnstile on the sign-in pages. The server says whether it is
// on (the site key from GET /api/auth/config); without a key nothing is
// loaded from Cloudflare and captcha() is a no-op.
import { h, currentTheme } from "./ui.js";

const SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
let loading = null;

function load() {
  if (!loading) {
    loading = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = SCRIPT;
      s.async = true;
      s.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error("Turnstile did not load")));
      s.onerror = () => { loading = null; reject(new Error("Turnstile did not load")); };
      document.head.append(s);
    });
  }
  return loading;
}

// captcha(siteKey) -> { el, token(), reset() }
// el is the widget's element (null when the check is off); token() is the
// current answer ("" until the visitor has passed); a token can be used for
// one request, so call reset() after every request that carried it.
export function captcha(siteKey) {
  if (!siteKey) return { el: null, token: () => "", reset() {} };
  const el = h("div.captcha");
  let token = "", id = null, api = null;
  load().then((ts) => {
    api = ts;
    id = ts.render(el, {
      sitekey: siteKey,
      theme: currentTheme() === "light" ? "light" : "dark",
      size: "flexible", // as wide as the form
      callback: (t) => { token = t; },
      "expired-callback": () => { token = ""; },
      "error-callback": () => { token = ""; },
    });
  }).catch(() => { el.textContent = "The verification could not be loaded. Check your connection and reload the page."; });
  return {
    el,
    token: () => token,
    reset() { token = ""; if (api && id !== null) api.reset(id); },
  };
}

// What to tell someone who submits before the check has finished.
export const CAPTCHA_WAIT = "Complete the verification below first.";
