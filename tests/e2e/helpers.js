// Shared helpers: throwaway accounts, sign-in through the API or the UI,
// TOTP codes, form fields by label, console watching.
const crypto = require("node:crypto");
const { expect } = require("@playwright/test");

let seq = 0;
const uniq = (tag) => `${tag}-${Date.now().toString(36)}${(++seq).toString(36)}-${process.pid.toString(36)}`;

// A fresh organization owner. Passwords are random so no two tests share one.
function account(tag) {
  return { org: `${tag} ${uniq("org")}`, email: `${uniq(tag)}@e2e.test`, password: `Pw-${crypto.randomBytes(6).toString("hex")}` };
}

// Registers through the API using the page's cookie jar: the page is signed
// in afterwards. Returns the /api/me document.
async function registerViaApi(page, acc) {
  const r = await page.request.post("/api/auth/register-org", { data: { org_name: acc.org, email: acc.email, password: acc.password } });
  expect(r.ok(), `register ${acc.email}: ${r.status()} ${await r.text()}`).toBeTruthy();
  return (await page.request.get("/api/me")).json();
}

async function loginViaApi(page, acc, code = "") {
  const r = await page.request.post("/api/auth/login", { data: { email: acc.email, password: acc.password, code } });
  expect(r.ok(), `login ${acc.email}: ${r.status()} ${await r.text()}`).toBeTruthy();
  return (await page.request.get("/api/me")).json();
}

// A signed-in page on the dashboard with its own new organization.
async function signedIn(page, tag) {
  const acc = account(tag);
  const me = await registerViaApi(page, acc);
  await page.goto("/#/dashboard");
  await expect(page.locator(".nav-user")).toHaveText(acc.email);
  return { ...acc, me };
}

async function registerViaUi(page, acc) {
  await page.goto("/");
  await page.locator(".auth-tabs button", { hasText: "Create organization" }).click();
  await page.getByPlaceholder("Acme Inc.").fill(acc.org);
  await page.getByPlaceholder("you@example.com").fill(acc.email);
  await page.getByPlaceholder("At least 8 characters").fill(acc.password);
  await page.locator(".auth-card button.primary", { hasText: "Create organization" }).click();
  await expect(page.locator(".nav-user")).toHaveText(acc.email);
}

async function loginViaUi(page, acc, code) {
  await page.goto("/");
  await expect(page.locator(".auth-tabs")).toBeVisible();
  await page.getByPlaceholder("you@example.com").fill(acc.email);
  await page.getByPlaceholder("Password").fill(acc.password);
  await page.locator(".auth-card button.primary", { hasText: "Sign in" }).click();
  if (code !== undefined) {
    await expect(page.getByPlaceholder("123456")).toBeVisible();
    await page.getByPlaceholder("123456").fill(code);
    await page.locator(".auth-card button.primary", { hasText: "Sign in" }).click();
  }
}

async function signOut(page) {
  await page.locator(".nav-right button", { hasText: "Sign out" }).click();
  await expect(page.locator(".auth-tabs")).toBeVisible();
}

// ----- TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30 s), base32 secret as the UI shows it -----
function base32Decode(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const out = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const v = alphabet.indexOf(c);
    if (v < 0) throw new Error("bad base32 secret");
    bits += v.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, offset = 0) {
  const step = BigInt(Math.floor(Date.now() / 1000 / 30) + offset);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(step);
  const h = crypto.createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const v = h.readUInt32BE(off) & 0x7fffffff;
  return String(v % 1_000_000).padStart(6, "0");
}

// A solid-colour PNG of w x h pixels, built by hand (signature, IHDR, one
// zlib-compressed IDAT, IEND) so the tests need no image library.
function pngBuffer(w, h, [r, g, b] = [220, 60, 60]) {
  const zlib = require("node:zlib");
  const table = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc = (buf) => { let c = 0xffffffff; for (const x of buf) c = table[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type), data]), len = Buffer.alloc(4), sum = Buffer.alloc(4);
    len.writeUInt32BE(data.length); sum.writeUInt32BE(crc(body));
    return Buffer.concat([len, body, sum]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2; // 8 bit RGB
  const row = Buffer.concat([Buffer.from([0]), Buffer.alloc(w * 3)]);
  for (let x = 0; x < w; x++) { row[1 + x * 3] = r; row[2 + x * 3] = g; row[3 + x * 3] = b; }
  const raw = Buffer.concat(Array.from({ length: h }, () => row));
  return Buffer.concat([Buffer.from("\x89PNG\r\n\x1a\n", "binary"), chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

// A virtual authenticator in the browser (Chrome DevTools protocol): it
// answers WebAuthn prompts by itself, like a key that is always touched.
// kind "key": a roaming USB key; "passkey": a built-in authenticator with a
// stored credential that verifies the user.
async function virtualAuthenticator(page, kind) {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable");
  const options = kind === "passkey"
    ? { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }
    : { protocol: "ctap2", transport: "usb", hasResidentKey: false, hasUserVerification: false, isUserVerified: false, automaticPresenceSimulation: true };
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", { options });
  return { client, authenticatorId, remove: () => client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }) };
}

// The input/select/textarea of a labelled field ("label.field > span.lbl").
// The inner locator of filter({ has }) must be page-rooted: it is resolved
// relative to each candidate label.
function field(scope, label) {
  const re = new RegExp(`^\\s*${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*$`);
  return scope.locator("label.field").filter({ has: scope.page().locator(".lbl", { hasText: re }) }).locator("input, select, textarea").first();
}

// Console errors and uncaught exceptions for the rest of the page's life
// (Chromium reports CSP violations as console errors). The throwaway stack
// is plain HTTP, so Chromium notes that it ignores the Cross-Origin-Opener-
// Policy header (it applies on HTTPS only); that note is not an error here.
const expectedOnHttp = /Cross-Origin-Opener-Policy header has been ignored, because the URL's origin was untrustworthy/;
function watchConsole(page) {
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error" && !expectedOnHttp.test(m.text())) errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  return errors;
}

// Accept the confirmation dialog (ui.js confirmDialog) with the given label.
async function confirm(page, label) {
  await page.locator(".modal-back .modal-actions button", { hasText: label }).last().click();
}

const settingsTab = async (page, name) => {
  await page.goto("/#/settings");
  await page.locator(".tabs button", { hasText: name }).click();
};

module.exports = { pngBuffer, virtualAuthenticator, account, registerViaApi, loginViaApi, signedIn, registerViaUi, loginViaUi, signOut, totp, field, watchConsole, confirm, settingsTab, uniq };
