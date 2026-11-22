// Platform administration (superadmin seeded by scripts/test-stack.sh).
const { test, expect } = require("@playwright/test");
const { signedIn, loginViaApi, confirm, account, registerViaApi, field } = require("../helpers");

const SA = { email: process.env.SUPERADMIN_EMAIL, password: process.env.SUPERADMIN_PASSWORD };

test.describe("platform admin @e2e", () => {
  test.skip(!SA.email, "SUPERADMIN_EMAIL not set (start the stack with scripts/test-stack.sh)");

  test("only platform administrators see and reach the admin area", async ({ page, browser }) => {
    await signedIn(page, "notadmin");
    await expect(page.locator(".nav-links a", { hasText: "Admin" })).toHaveCount(0);
    await page.goto("/#/admin");
    await expect(page.locator(".tree-head h2")).toContainText("Hosts");
    expect((await page.request.get("/api/admin/orgs")).status()).toBe(403);

    const ctx = await browser.newContext();
    const admin = await ctx.newPage();
    await loginViaApi(admin, SA);
    await admin.goto("/#/admin");
    await expect(admin.locator(".nav-links a", { hasText: "Admin" })).toHaveClass(/active/);
    await expect(admin.locator(".section-title h2")).toHaveText("Platform admin");
    await expect(admin.locator(".card h2", { hasText: "Organizations" })).toBeVisible();
    await ctx.close();
  });

  test("organizations: users, blocking ends the session, limits", async ({ page, browser }) => {
    const victim = await signedIn(page, "victim");
    const ctx = await browser.newContext();
    const admin = await ctx.newPage();
    await loginViaApi(admin, SA);
    await admin.goto("/#/admin");
    const orgRow = admin.locator("table.tbl tbody tr", { hasText: victim.org });
    await expect(orgRow).toHaveCount(1);
    await expect(orgRow.locator(".badge.ok")).toHaveText("active");
    await orgRow.locator("button", { hasText: "Users" }).click();
    const users = admin.locator(".card", { hasText: `Users of ${victim.org}` });
    const userRow = users.locator("tbody tr", { hasText: victim.email });
    await expect(userRow).toContainText("owner");

    await userRow.locator("button", { hasText: "Block" }).click();
    await confirm(admin, "Block");
    await expect(admin.locator(".toast.ok", { hasText: "User blocked" }).last()).toBeVisible();
    await expect(users.locator("tbody tr", { hasText: victim.email }).locator(".badge.bad")).toHaveText("blocked");
    expect((await page.request.get("/api/me")).status()).toBe(401);
    const r = await page.request.post("/api/auth/login", { data: { email: victim.email, password: victim.password, code: "" } });
    expect(r.status()).toBe(403);
    await users.locator("tbody tr", { hasText: victim.email }).locator("button", { hasText: "Unblock" }).click();
    await confirm(admin, "Unblock");
    await expect(admin.locator(".toast.ok", { hasText: "User unblocked" }).last()).toBeVisible();
    await loginViaApi(page, victim);

    // host limit for the organization
    await orgRow.locator("button", { hasText: "edit" }).click();
    await admin.locator(".modal input[type=number]").fill("1");
    await admin.locator(".modal button", { hasText: "Save" }).click();
    await expect(admin.locator(".toast.ok", { hasText: "Limits saved" }).last()).toBeVisible();
    expect((await page.request.post("/api/nodes", { data: { kind: "host", name: "h1", host: "192.0.2.1" } })).ok()).toBeTruthy();
    expect((await page.request.post("/api/nodes", { data: { kind: "host", name: "h2", host: "192.0.2.2" } })).status()).toBe(403);
    await page.reload();
    await expect(page.locator(".tree-head .badge")).toHaveText("1 / 1");

    // the tenant sees the admin's actions in its own audit log
    await page.goto("/#/settings?tab=audit");
    await expect(page.locator("main")).toContainText("admin.org_limits");
    await ctx.close();
  });

  test("organizations: the hosts an organization monitors, with their parameters", async ({ page, browser }) => {
    const tenant = await signedIn(page, "hostsview");
    const prof = await (await page.request.post("/api/profiles", { data: { name: "Rapid", interval_s: 15, ping_count: 4, packet_size: 120, is_default: false } })).json();
    const folder = await (await page.request.post("/api/nodes", { data: { kind: "folder", name: "Core" } })).json();
    await page.request.post("/api/nodes", { data: { kind: "host", name: "gateway", host: "192.0.2.61", description: "edge router", parent_id: folder.id, profile_id: prof.id } });
    await page.request.post("/api/nodes", { data: { kind: "host", name: "plain", host: "192.0.2.62" } });
    const ctx = await browser.newContext();
    const admin = await ctx.newPage();
    await loginViaApi(admin, SA);
    await admin.goto("/#/admin");
    const orgRow = admin.locator("table.tbl tbody tr", { hasText: tenant.org });
    await orgRow.locator("button", { hasText: "Hosts" }).click();
    const hosts = admin.locator(".card", { hasText: `Hosts of ${tenant.org}` });
    await expect(hosts.locator(".sub")).toContainText("2 monitored hosts");
    const gw = hosts.locator("tbody tr", { hasText: "gateway" });
    await expect(gw.locator("td")).toContainText(["Core", "gateway", "192.0.2.61", "Rapid", "15 s", "4", "120 B"]);
    await expect(gw).toContainText("edge router");
    const plain = hosts.locator("tbody tr", { hasText: "plain" });
    await expect(plain.locator("td")).toContainText(["-", "plain", "192.0.2.62", "Standard", "60 s", "20", "56 B"]);
    await expect(plain.locator(".badge", { hasText: "default" })).toBeVisible();
    // the tenant itself has no such view
    expect((await page.request.get(`/api/admin/orgs/${tenant.me.org.id}/hosts`)).status()).toBe(403);
    await ctx.close();
  });

  test("organizations: deleting one removes its users, hosts and data", async ({ page, browser }) => {
    const victim = await signedIn(page, "delorg");
    const host = await (await page.request.post("/api/nodes", { data: { kind: "host", name: "doomed", host: "192.0.2.63" } })).json();
    expect(host.id).toBeTruthy();
    const ctx = await browser.newContext();
    const admin = await ctx.newPage();
    await loginViaApi(admin, SA);
    await admin.goto("/#/admin");
    const orgRow = admin.locator("table.tbl tbody tr", { hasText: victim.org });
    await expect(orgRow).toHaveCount(1);
    // the administrator's own organization cannot be deleted from here
    await expect(admin.locator("table.tbl tbody tr", { hasText: "yours" }).locator("button", { hasText: "Delete" })).toHaveCount(0);

    await orgRow.locator("button", { hasText: "Delete" }).click();
    const modal = admin.locator(".modal");
    await expect(modal).toContainText("It cannot be undone");
    await expect(modal).toContainText("1 user, 1 host");
    const go = modal.locator("button", { hasText: "Delete organization" });
    await expect(go).toBeDisabled();
    await field(modal, "Type the organization's name to confirm").fill(victim.org + " typo");
    await expect(go).toBeDisabled();
    await field(modal, "Type the organization's name to confirm").fill(victim.org);
    await field(modal, "Your password").fill("not-my-password");
    await go.click();
    await expect(modal.locator(".error-text")).toHaveText("password is incorrect");
    expect((await page.request.get("/api/me")).ok()).toBeTruthy(); // still there
    await field(modal, "Your password").fill(SA.password);
    await go.click();
    await expect(admin.locator(".toast.ok", { hasText: `${victim.org} deleted` }).last()).toBeVisible();
    await expect(admin.locator("table.tbl tbody tr", { hasText: victim.org })).toHaveCount(0);

    // the organization is gone for its people
    expect((await page.request.get("/api/me")).status()).toBe(401);
    expect((await page.request.post("/api/auth/login", { data: { email: victim.email, password: victim.password, code: "" } })).status()).toBe(401);
    await page.reload();
    await expect(page.locator(".auth-tabs")).toBeVisible();
    // and on record in the global audit log, under system events
    await admin.goto("/#/admin?tab=audit");
    const log = admin.locator(".card").filter({ has: admin.locator("h2", { hasText: /^Global audit log$/ }) });
    await admin.getByPlaceholder("Search email, action, detail, IP").fill(victim.org);
    const entry = log.locator("tbody tr").filter({ has: admin.locator(".badge", { hasText: /^admin\.org_delete$/ }) });
    await expect(entry).toContainText(victim.org);
    await expect(entry).toContainText(SA.email);
    await expect(entry).toContainText("1 users, 1 hosts");
    await expect(entry.locator(".badge", { hasText: "system" })).toBeVisible();
    await ctx.close();
  });

  test("global audit log and usage views", async ({ page }) => {
    const acc = account("globalaudit");
    await registerViaApi(page, acc);
    await page.request.post("/api/auth/logout");
    await loginViaApi(page, SA);
    await page.goto("/#/admin?tab=audit");
    const log = page.locator(".card").filter({ has: page.locator("h2", { hasText: /^Global audit log$/ }) });
    await expect(log.locator("tbody tr").first()).toBeVisible();
    // paged: 10 rows by default, filters narrow the total, the size is selectable
    await expect(log.locator("tbody tr")).toHaveCount(10);
    await expect(log.locator(".pager-info")).toHaveText(/^1-10 of \d+$/);
    await expect(log.locator(".pager-nav button", { hasText: "Previous" })).toBeDisabled();
    await log.locator(".pager-nav button", { hasText: "Next" }).click();
    await expect(log.locator(".pager-info")).toHaveText(/^11-20 of \d+$/);
    await page.getByPlaceholder("Search email, action, detail, IP").fill(acc.email);
    await expect(log.locator(".pager-info")).toHaveText(/^1-\d+ of \d+$/);
    await expect(log.locator("tbody tr", { hasText: "org.create" })).toContainText(acc.org);
    await log.locator(".pager-size select").selectOption("50");
    await expect(log.locator("tbody tr", { hasText: acc.email }).first()).toBeVisible();
    for (const n of ["10", "20", "50", "100", "200"]) await expect(log.locator(`.pager-size option[value="${n}"]`)).toHaveCount(1);
    await page.locator(".tabs button", { hasText: "Usage & forecast" }).click();
    await expect(page.locator(".kpi-lbl", { hasText: "Size now" })).toBeVisible();
    await expect(page.locator(".kpi-lbl", { hasText: "Organizations" })).toBeVisible();
    await expect(page.locator(".card h2", { hasText: "Tables" })).toBeVisible();
    const stats = await (await page.request.get("/api/admin/stats")).json();
    expect(stats.counts.orgs).toBeGreaterThan(1);
  });
});
