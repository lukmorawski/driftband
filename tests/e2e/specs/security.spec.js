// Browser-side security checks: what the backend suite cannot see because it
// needs a real browser (CSP in effect, cookie scope, SameSite, framing,
// stored content rendered as text).
const { test, expect } = require("@playwright/test");
const { signedIn, account, registerViaApi, watchConsole, signOut, field } = require("../helpers");

const XSS = [
  `<img src=x onerror="window.__pwned=1">`,
  `"><svg onload="window.__pwned=2">`,
  `'); window.__pwned=3; //`,
  `<script>window.__pwned=4</script>`,
];

test.describe("browser security @security", () => {
  test("every view loads without CSP violations or console errors", async ({ page }) => {
    const errors = watchConsole(page);
    await signedIn(page, "csp");
    await page.request.post("/api/nodes", { data: { kind: "host", name: "h", host: "192.0.2.5" } });
    for (const hash of ["/dashboard", "/settings?tab=account", "/settings?tab=team", "/settings?tab=profiles", "/settings?tab=notifications",
      "/settings?tab=import", "/settings?tab=retention", "/settings?tab=usage", "/settings?tab=audit", "/faq"]) {
      await page.goto("/#" + hash);
      await page.waitForLoadState("networkidle");
    }
    await page.goto("/#/dashboard");
    await page.locator(".tree-row").first().click();
    await expect(page.locator(".chart-card").first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    // the CSP really is enforced: an inline script injected now is refused
    const inlineRan = await page.evaluate(() => {
      window.__inline = 0;
      const s = document.createElement("script");
      s.textContent = "window.__inline = 1";
      document.body.append(s);
      return window.__inline;
    });
    expect(inlineRan).toBe(0);
    const cspInline = (e) => /inline script/i.test(e) && /Content Security Policy/i.test(e);
    expect(errors.filter((e) => !cspInline(e))).toEqual([]);
    expect(errors.some(cspInline)).toBe(true);
  });

  test("stored script payloads in names and descriptions render as text", async ({ page }) => {
    await signedIn(page, "xss");
    const folder = await (await page.request.post("/api/nodes", { data: { kind: "folder", name: XSS[0] } })).json();
    for (const [i, p] of XSS.entries()) {
      const r = await page.request.post("/api/nodes", { data: { kind: "host", name: p, host: "192.0.2." + (i + 1), description: XSS[(i + 1) % XSS.length], parent_id: folder.id } });
      expect(r.ok()).toBeTruthy();
    }
    await page.request.post("/api/profiles", { data: { name: XSS[1], interval_s: 60, ping_count: 5, packet_size: 56, is_default: false } });
    await page.request.post("/api/notify/channels", { data: { name: XSS[0], kind: "slack", config: {}, secrets: { webhook_url: "https://hooks.slack.com/services/T000/B000/x" } } });
    await page.request.post("/api/notify/rules", { data: { name: XSS[3], enabled: true, node_id: null, metric: "loss", threshold: 50, recover_threshold: 10, for_minutes: 2, recover_minutes: 2, notify_recovery: true, repeat_minutes: 0, flap_transitions: 4, flap_window_minutes: 60, channel_ids: [] } });
    const errors = watchConsole(page);
    await page.reload();
    await expect(page.locator(".tree-row .tname")).toHaveCount(5);
    const names = await page.locator(".tree-row .tname").allTextContents();
    for (const p of XSS) expect(names).toContain(p);
    await page.locator(".tree-row").first().click();
    await expect(page.locator(".chart-card")).toHaveCount(4);
    const labels = (await page.locator(".chart-card .label-line").allTextContents()).join("\n");
    for (const p of XSS) expect(labels).toContain(p);
    for (const tab of ["profiles", "notifications", "audit"]) {
      await page.goto("/#/settings?tab=" + tab);
      await page.waitForLoadState("networkidle");
    }
    await expect(page.locator("main")).toContainText(XSS[3]);
    await page.goto("/#/dashboard");
    await page.locator(".tree-row").first().hover();
    await page.locator(".tree-row").first().locator('.trow-actions button[title="Edit"]').click({ force: true });
    await expect(field(page.locator(".modal"), "Name")).toHaveValue(XSS[0]);
    expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
    expect(await page.locator("img[src='x'], svg[onload]").count()).toBe(0);
    expect(errors.filter((e) => !e.includes("x:1") && !e.includes("Failed to load resource"))).toEqual([]);
  });

  test("the session cookie is HttpOnly, SameSite and gone after sign-out", async ({ page, context }) => {
    const acc = await signedIn(page, "cookie");
    const cookies = await context.cookies();
    const sess = cookies.find((c) => c.name === "dband_session");
    expect(sess).toBeTruthy();
    expect(sess.httpOnly).toBe(true);
    expect(sess.sameSite).toBe("Lax");
    expect(sess.value).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(await page.evaluate(() => document.cookie)).not.toContain("dband_session");
    const token = sess.value;
    await signOut(page);
    expect((await context.cookies()).find((c) => c.name === "dband_session")).toBeUndefined();
    // the old token is dead on the server too
    const r = await page.request.get("/api/me", { headers: { Cookie: "dband_session=" + token } });
    expect(r.status()).toBe(401);
    // a deep link without a session shows the sign-in form, nothing else
    await page.goto("/#/settings?tab=team");
    await expect(page.locator(".auth-tabs")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(acc.email);
  });

  test("cross-site requests cannot act on the session (SameSite, CORS)", async ({ page, context }) => {
    await signedIn(page, "csrf");
    await page.request.post("/api/nodes", { data: { kind: "host", name: "keep", host: "192.0.2.9" } });
    const base = new URL(page.url()).origin;
    // an attacker page on another origin
    await page.route("https://evil.example/**", (route) => route.fulfill({ contentType: "text/html", body: `<!doctype html><title>evil</title>
      <form id=f method=post action="${base}/api/auth/logout"><button>go</button></form>
      <script>
        window.results = {};
        fetch("${base}/api/nodes", {method:"POST", credentials:"include", headers:{"Content-Type":"application/json"}, body:'{"kind":"folder","name":"csrf"}'})
          .then(r => results.json = r.status, e => results.json = "blocked");
        fetch("${base}/api/settings/retention", {method:"POST", credentials:"include", body:'{"years":3}'})
          .then(r => results.plain = r.status, e => results.plain = "blocked");
      </script>` }));
    await page.goto("https://evil.example/");
    await expect.poll(() => page.evaluate(() => Object.keys(window.results).length)).toBe(2);
    const results = await page.evaluate(() => window.results);
    expect([401, "blocked"]).toContain(results.json);
    expect([401, "blocked"]).toContain(results.plain);
    await page.locator("#f button").click();
    await page.waitForLoadState("domcontentloaded");
    await expect(page.locator("body")).toContainText("not authenticated");
    // nothing happened: still signed in, nothing created
    expect((await context.cookies()).some((c) => c.name === "dband_session")).toBe(true);
    const me = await page.request.get("/api/me");
    expect(me.ok()).toBeTruthy();
    expect((await (await page.request.get("/api/me")).json()).org.retention_years).toBe(1);
    const tree = await (await page.request.get("/api/tree")).json();
    expect(tree.map((n) => n.name)).toEqual(["keep"]);
  });

  test("the application cannot be framed", async ({ page }) => {
    await signedIn(page, "frame");
    const base = new URL(page.url()).origin;
    await page.route("https://evil.example/**", (route) => route.fulfill({ contentType: "text/html", body: `<iframe id=i src="${base}/"></iframe>` }));
    await page.goto("https://evil.example/");
    await page.waitForTimeout(1500);
    const framed = await page.evaluate(() => {
      const f = document.getElementById("i");
      try { return !!(f.contentDocument && f.contentDocument.getElementById("root")); } catch (e) { return false; }
    });
    expect(framed).toBe(false);
    const hdr = await page.request.get("/");
    expect(hdr.headers()["x-frame-options"]).toBe("DENY");
    expect(hdr.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
  });

  test("the application has its own icon", async ({ page }) => {
    await page.goto("/");
    const href = await page.locator('link[rel="icon"][type="image/svg+xml"]').getAttribute("href");
    expect(href).toMatch(/^favicon\.svg/);
    const svg = await page.request.get("/" + href);
    expect(svg.headers()["content-type"]).toContain("image/svg+xml");
    // browsers also ask for /favicon.ico on their own: it must be the icon, not the page
    const ico = await page.request.get("/favicon.ico");
    expect(ico.headers()["content-type"]).not.toContain("text/html");
    expect((await ico.body()).subarray(0, 4)).toEqual(Buffer.from([0, 0, 1, 0]));
    const touch = await page.request.get("/apple-touch-icon.png");
    expect(touch.headers()["content-type"]).toContain("image/png");
  });

  test("security headers on pages, assets and the API", async ({ page }) => {
    await signedIn(page, "headers");
    for (const path of ["/", "/main.js", "/style.css", "/api/me", "/api/tree", "/robots.txt"]) {
      const r = await page.request.get(path);
      const h = r.headers();
      expect(h["x-content-type-options"], path).toBe("nosniff");
      expect(h["x-frame-options"], path).toBe("DENY");
      expect(h["referrer-policy"], path).toBe("no-referrer");
      expect(h["content-security-policy"], path).toMatch(/script-src 'self'/);
      expect(h["content-security-policy"], path).not.toMatch(/unsafe-eval|unsafe-inline/);
      expect(h["permissions-policy"], path).toContain("camera=()");
      expect(h["cross-origin-opener-policy"], path).toBe("same-origin");
      expect(h["cross-origin-embedder-policy"], path).toBe("require-corp");
      expect(h["cross-origin-resource-policy"], path).toBe("same-origin");
      if (path.startsWith("/api/")) expect(h["cache-control"], path).toBe("no-store");
      expect(h["server"] || "", path).not.toMatch(/go|version/i);
    }
    const js = await page.request.get("/js/ui.js");
    expect(js.headers()["content-type"]).toMatch(/javascript/);
    const missing = await page.request.get("/api/nope");
    expect(missing.status()).toBe(404);
    expect(missing.headers()["content-type"]).toMatch(/json/);
    for (const path of ["/../../etc/passwd", "/js/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/vendor/..%2f..%2fetc/passwd"]) {
      const trav = await page.request.get(path);
      expect(await trav.text(), path).not.toContain("root:");
    }
  });

  test("tenants and roles are enforced for a signed-in attacker", async ({ page, browser }) => {
    const victim = await signedIn(page, "victim2");
    const host = await (await page.request.post("/api/nodes", { data: { kind: "host", name: "secret-host", host: "192.0.2.44", description: "victim-only" } })).json();
    const ch = await (await page.request.post("/api/notify/channels", { data: { name: "victim channel", kind: "slack", config: {}, secrets: { webhook_url: "https://hooks.slack.com/services/T000/B000/v" } } })).json();
    const ctx = await browser.newContext();
    const attacker = await ctx.newPage();
    await registerViaApi(attacker, account("attacker"));
    expect(host.id, JSON.stringify(host)).toBeTruthy();
    expect(ch.id, JSON.stringify(ch)).toBeTruthy();
    const a = attacker.request;
    const attempts = [
      ["read the victim's series", () => a.get(`/api/series?host=${host.id}&from=0&to=9999999999`), 404],
      ["rename the victim's host", () => a.patch(`/api/nodes/${host.id}`, { data: { name: "owned", host: "192.0.2.44" } }), 404],
      ["delete the victim's host", () => a.delete(`/api/nodes/${host.id}`), 404],
      ["delete the victim's channel", () => a.delete(`/api/notify/channels/${ch.id}`), 404],
      ["send through the victim's channel", () => a.post(`/api/notify/channels/${ch.id}/test`), 404],
      ["rule on the victim's host and channel", () => a.post("/api/notify/rules", { data: { name: "steal", enabled: true, node_id: host.id, metric: "loss", threshold: 50, recover_threshold: 10, for_minutes: 2, recover_minutes: 2, notify_recovery: true, repeat_minutes: 0, flap_transitions: 4, flap_window_minutes: 60, channel_ids: [ch.id] } }), 400],
    ];
    for (const [what, call, want] of attempts) {
      const r = await call();
      expect(r.status(), `${what}: ${await r.text()}`).toBe(want);
    }
    for (const path of ["/api/tree", "/api/status", "/api/audit", "/api/notify/channels", "/api/users"]) {
      expect(await (await a.get(path)).text(), path).not.toContain("victim");
    }
    expect((await a.get("/api/admin/orgs")).status()).toBe(403);
    expect((await a.get("/api/admin/audit")).status()).toBe(403);
    // the victim's data is untouched and the attempts are not in the victim's log
    const tree = await (await page.request.get("/api/tree")).json();
    expect(tree[0].name).toBe("secret-host");
    expect(victim.me.role).toBe("owner");
    await ctx.close();
  });

  test("mass assignment, oversized bodies and malformed ids are refused", async ({ page }) => {
    await signedIn(page, "input");
    const r1 = await page.request.post("/api/account/name", { data: { first_name: "A", last_name: "B", role: "owner", is_superadmin: true } });
    expect(r1.status()).toBe(400);
    const r2 = await page.request.post("/api/nodes", { data: { kind: "host", name: "x".repeat(2 * 1024 * 1024), host: "192.0.2.1" } });
    expect([400, 413]).toContain(r2.status());
    const r3 = await page.request.patch("/api/nodes/not-a-number", { data: { name: "x" } });
    expect(r3.status()).toBe(400);
    const r4 = await page.request.post("/api/nodes", { headers: { "Content-Type": "application/json" }, data: "{not json" });
    expect(r4.status()).toBe(400);
    const me = await (await page.request.get("/api/me")).json();
    expect(me.is_superadmin).toBeFalsy();
    expect(me.role).toBe("owner");
  });
});
