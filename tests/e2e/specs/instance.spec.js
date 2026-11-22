// Settings of the whole instance: closing it to new organizations, the
// Turnstile check on the sign-in pages, the health endpoint. Runs after
// the other specs (see playwright.config.js), one test at a time.
const { test, expect } = require("@playwright/test");
const { account, registerViaApi, loginViaApi, watchConsole } = require("../helpers");

const SA = { email: process.env.SUPERADMIN_EMAIL, password: process.env.SUPERADMIN_PASSWORD };

test.describe.configure({ mode: "serial" });

test.describe("instance settings @e2e @security", () => {
  test("the health endpoint answers without a session", async ({ request }) => {
    const r = await request.get("/api/health");
    expect(r.status()).toBe(200);
    expect(await r.json()).toEqual({ status: "ok", database: "ok" });
    expect(r.headers()["cache-control"]).toBe("no-store");
    expect(r.headers()["set-cookie"]).toBeUndefined();
  });

  test("a platform administrator closes the instance to new organizations", async ({ page, browser }) => {
    test.skip(!SA.email, "SUPERADMIN_EMAIL not set (start the stack with scripts/test-stack.sh)");
    const errors = watchConsole(page);
    await loginViaApi(page, SA);
    const visitorCtx = await browser.newContext();
    const visitor = await visitorCtx.newPage();
    try {
      await page.goto("/#/admin");
      await page.locator(".tabs button", { hasText: "Settings" }).click();
      const box = page.locator("#reg-open");
      await expect(box).toBeChecked();
      await expect(page.locator(".card", { hasText: "Sign-in protection" })).toContainText("off");

      // a visitor sees both forms
      await visitor.goto("/");
      await expect(visitor.locator(".auth-tabs button", { hasText: "Create organization" })).toBeVisible();

      await box.uncheck();
      await expect(page.locator(".toast.ok", { hasText: "Creating organizations is off" })).toBeVisible();
      await expect(page.locator(".card", { hasText: "Registration" })).toContainText("only through an invitation link");

      // the sign-in page offers only signing in, and the API refuses as well
      await visitor.reload();
      await expect(visitor.getByPlaceholder("Password")).toBeVisible();
      await expect(visitor.locator(".auth-tabs")).toBeHidden();
      await expect(visitor.locator("button", { hasText: "Create organization" })).toHaveCount(0);
      const acc = account("closed");
      const refused = await visitor.request.post("/api/auth/register-org", { data: { org_name: acc.org, email: acc.email, password: acc.password } });
      expect(refused.status()).toBe(403);
      expect((await refused.json()).error).toContain("turned off");
      // existing accounts still sign in
      expect((await visitor.request.post("/api/auth/login", { data: { email: SA.email, password: SA.password } })).ok()).toBeTruthy();
      await visitor.request.post("/api/auth/logout");

      // the setting survives a reload and is recorded in the global audit log
      await page.reload();
      await page.locator(".tabs button", { hasText: "Settings" }).click();
      await expect(page.locator("#reg-open")).not.toBeChecked();
      await page.locator("#reg-open").check();
      await expect(page.locator(".toast.ok", { hasText: "Creating organizations is on" })).toBeVisible();
      const audit = await (await page.request.get("/api/admin/audit?action=admin.settings_change&limit=5")).json();
      expect(JSON.stringify(audit)).toContain("creating organizations turned off");

      await visitor.goto("/");
      await expect(visitor.locator(".auth-tabs button", { hasText: "Create organization" })).toBeVisible();
      await registerViaApi(visitor, account("reopened"));
      expect(errors).toEqual([]);
    } finally {
      // whatever happened above, leave the instance open for the next run
      await page.request.patch("/api/admin/settings", { data: { registration_open: true } });
      await visitorCtx.close();
    }
  });

  test("members and anonymous visitors cannot change instance settings", async ({ page }) => {
    expect((await page.request.patch("/api/admin/settings", { data: { registration_open: false } })).status()).toBe(401);
    await registerViaApi(page, account("nosettings"));
    expect((await page.request.patch("/api/admin/settings", { data: { registration_open: false } })).status()).toBe(403);
    expect((await page.request.get("/api/admin/settings")).status()).toBe(403);
    expect((await (await page.request.get("/api/auth/config")).json()).registration_open).toBe(true);
  });

  // The server of the throwaway stack runs without Turnstile, so the page is
  // told otherwise and Cloudflare's script is replaced by a stand-in: what is
  // tested here is the page's side (the widget is shown, nothing is sent
  // before it has an answer, the answer travels with the request and is
  // renewed after use). The server's side is in the backend suite.
  test("with Turnstile on, the forms wait for the check and send its answer", async ({ browser }) => {
    const acc = account("turnstile");
    const setup = await browser.newContext();
    await registerViaApi(await setup.newPage(), acc);
    await setup.close();

    // the stack's policy does not list Cloudflare (Turnstile is off there)
    const ctx = await browser.newContext({ bypassCSP: true });
    const page = await ctx.newPage();
    await page.route("**/api/auth/config", (route) => route.fulfill({ json: { registration_open: true, turnstile_site_key: "site-key-for-tests" } }));
    await page.route("https://challenges.cloudflare.com/**", (route) => route.fulfill({
      contentType: "application/javascript",
      body: `window.turnstile = {
        n: 0,
        render(el, o) { this.o = o; el.textContent = "check for " + o.sitekey; return "w1"; },
        reset() { window.__resets = (window.__resets || 0) + 1; },
        solve() { this.o.callback("answer-" + (++this.n)); },
      };`,
    }));
    const sent = [];
    page.on("request", (r) => { if (r.url().endsWith("/api/auth/login") || r.url().endsWith("/api/auth/register-org")) sent.push(r.postDataJSON()); });

    await page.goto("/");
    await expect(page.locator(".captcha")).toHaveText("check for site-key-for-tests");
    await page.getByPlaceholder("you@example.com").fill(acc.email);
    await page.getByPlaceholder("Password").fill("not-the-password");
    const signIn = page.locator(".auth-card button.primary", { hasText: "Sign in" });

    // before the check has an answer nothing leaves the page
    await signIn.click();
    await expect(page.locator(".error-text")).toHaveText("Complete the verification below first.");
    expect(sent).toEqual([]);

    // a wrong password: the answer went with the request and is renewed
    await page.evaluate(() => window.turnstile.solve());
    await signIn.click();
    await expect(page.locator(".error-text")).toHaveText("invalid email or password");
    expect(sent[0].turnstile_token).toBe("answer-1");
    expect(await page.evaluate(() => window.__resets)).toBe(1);
    await signIn.click();
    await expect(page.locator(".error-text")).toHaveText("Complete the verification below first.");
    expect(sent.length).toBe(1);

    await page.evaluate(() => window.turnstile.solve());
    await page.getByPlaceholder("Password").fill(acc.password);
    await signIn.click();
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
    expect(sent[1].turnstile_token).toBe("answer-2");

    // the organization form has its own check
    await page.locator(".nav-right button", { hasText: "Sign out" }).click();
    await page.locator(".auth-tabs button", { hasText: "Create organization" }).click();
    await expect(page.locator(".captcha")).toHaveText("check for site-key-for-tests");
    const next = account("turnstile-org");
    await page.getByPlaceholder("Acme Inc.").fill(next.org);
    await page.getByPlaceholder("you@example.com").fill(next.email);
    await page.getByPlaceholder("At least 8 characters").fill(next.password);
    const create = page.locator(".auth-card button.primary", { hasText: "Create organization" });
    await create.click();
    await expect(page.locator(".error-text")).toHaveText("Complete the verification below first.");
    await page.evaluate(() => window.turnstile.solve());
    await create.click();
    await expect(page.locator(".nav-user")).toHaveText(next.email);
    expect(sent[2].turnstile_token).toMatch(/^answer-/);
    await ctx.close();
  });

  test("without Turnstile nothing is loaded from Cloudflare", async ({ page }) => {
    const foreign = [];
    page.on("request", (r) => { if (!r.url().startsWith(new URL(page.url() === "about:blank" ? process.env.BASE_URL || "http://localhost:8080" : page.url()).origin)) foreign.push(r.url()); });
    await page.goto("/");
    await expect(page.getByPlaceholder("Password")).toBeVisible();
    await expect(page.locator(".captcha")).toHaveCount(0);
    expect(foreign).toEqual([]);
  });
});
