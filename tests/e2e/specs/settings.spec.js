// Settings: team and invites, probe profiles, notifications, retention,
// usage and the audit log.
const { test, expect } = require("@playwright/test");
const { signedIn, field, confirm, settingsTab, uniq, loginViaUi, pngBuffer } = require("../helpers");

const card = (page, title) => page.locator(".card").filter({ has: page.locator("h2", { hasText: new RegExp(`^${title}$`) }) });

test.describe("settings @e2e", () => {
  test("team: invite a member, change the role, remove", async ({ page, browser }) => {
    const owner = await signedIn(page, "team");
    await settingsTab(page, "Team");
    await expect(card(page, "Members").locator("tbody tr")).toHaveCount(1);
    await card(page, "Invite links").locator("button", { hasText: "Generate link" }).click();
    const url = await page.locator(".modal input[readonly]").inputValue();
    expect(url).toMatch(/\/#\/accept\?token=/);
    await page.locator(".modal button", { hasText: "Done" }).click();
    await expect(card(page, "Invite links").locator("tbody tr")).toHaveCount(1);
    await expect(card(page, "Invite links").locator("tbody .badge.ok")).toContainText("active");

    // the invitee joins from another browser
    const ctx = await browser.newContext();
    const other = await ctx.newPage();
    const member = { email: uniq("member") + "@e2e.test", password: "Member-pw-" + uniq("p") };
    await other.goto(url);
    await expect(other.locator(".auth-card")).toContainText(`Join ${owner.org} as member`);
    await other.getByPlaceholder("you@example.com").fill(member.email);
    await other.getByPlaceholder("At least 8 characters").fill(member.password);
    await other.locator("button", { hasText: "Join organization" }).click();
    await expect(other.locator(".nav-user")).toHaveText(member.email);
    // members see the team but cannot invite
    await other.goto("/#/settings?tab=team");
    await expect(card(other, "Invite links")).toContainText("Only owners and admins");
    // sign-in details of teammates are for owners and admins
    await expect(card(other, "Members").locator("thead th")).toHaveText(["Name", "Email", "Role", "Joined"]);
    await expect(card(other, "Invite links").locator("button", { hasText: "Generate link" })).toHaveCount(0);
    await expect(other.locator("main")).not.toContainText(url.split("token=")[1]);
    // the link is single use
    const again = await ctx.newPage();
    await again.goto(url);
    await expect(again.locator(".auth-card")).toContainText("invite invalid, used, or expired");

    await settingsTab(page, "Team");
    await expect(card(page, "Members").locator("tbody tr")).toHaveCount(2);
    // the owner sees how each member protects the sign-in and when they last signed in
    await expect(card(page, "Members").locator("thead th")).toHaveText(["Name", "Email", "Role", "Two-factor", "Last sign-in", "Joined", ""]);
    const joined = card(page, "Members").locator("tbody tr", { hasText: member.email });
    await expect(joined.locator("td").nth(3)).toHaveText("off");
    await expect(joined.locator("td").nth(4)).toHaveText(/^\d+[smh] ago$/);
    await expect(card(page, "Invite links").locator("tbody tr").first().locator("td").nth(2)).toHaveText("used");
    const sel = page.locator(`select[aria-label="Role of ${member.email}"]`);
    await sel.selectOption("admin");
    await expect(page.locator(".toast.ok", { hasText: "is now admin" }).last()).toBeVisible();
    await expect(page.locator(`select[aria-label="Role of ${member.email}"]`)).toHaveValue("admin");
    const memberRow = card(page, "Members").locator("tbody tr", { hasText: member.email });
    await memberRow.locator("button", { hasText: "Remove" }).click();
    await confirm(page, "Remove");
    await expect(page.locator(".toast.ok", { hasText: "Member removed" }).last()).toBeVisible();
    await expect(card(page, "Members").locator("tbody tr")).toHaveCount(1);
    // the removed member's session is gone
    await other.reload();
    await expect(other.locator(".auth-tabs")).toBeVisible();
    await ctx.close();
  });

  test("profile picture: upload, refusals, shown to the team, remove", async ({ page }) => {
    const acc = await signedIn(page, "avatar");
    await settingsTab(page, "Account");
    const profile = card(page, "Profile");
    const file = profile.locator("input[type=file]");
    // without a picture: initials
    await expect(page.locator(".nav-right .avatar img")).toHaveCount(0);
    await expect(page.locator(".nav-right .avatar")).not.toBeEmpty();

    await file.setInputFiles({ name: "me.png", mimeType: "image/png", buffer: pngBuffer(320, 200) });
    await expect(page.locator(".toast.ok", { hasText: "Picture saved" }).last()).toBeVisible();
    const img = page.locator(".nav-right .avatar img");
    await expect(img).toHaveAttribute("src", new RegExp(`^/api/users/${acc.me.id}/avatar\\?v=[0-9a-f]{16}$`));
    // what is served is the server's own 256 x 256 copy, privately cacheable
    const res = await page.request.get(await img.getAttribute("src"));
    expect(res.headers()["content-type"]).toBe("image/jpeg");
    expect(res.headers()["cache-control"]).toContain("private");
    expect(await img.evaluate((el) => el.decode().then(() => [el.naturalWidth, el.naturalHeight]))).toEqual([256, 256]);

    // not a picture, whatever the name and type say
    await file.setInputFiles({ name: "evil.png", mimeType: "image/png", buffer: Buffer.from("<script>alert(1)</script>") });
    await expect(profile.locator(".error-text")).toHaveText("only JPEG, PNG, GIF and WebP pictures are accepted");
    // a type the form does not take, and a file over 5 MB, are stopped before the upload
    await file.setInputFiles({ name: "doc.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.7") });
    await expect(profile.locator(".error-text")).toHaveText("Only JPEG, PNG, GIF and WebP pictures are accepted.");
    await file.setInputFiles({ name: "huge.png", mimeType: "image/png", buffer: Buffer.concat([pngBuffer(64, 64), Buffer.alloc(5 * 1024 * 1024)]) });
    await expect(profile.locator(".error-text")).toHaveText("The picture is larger than 5 MB.");
    // a header that claims 30000 x 30000 pixels (decompression bomb)
    const bomb = pngBuffer(64, 64); bomb.writeUInt32BE(30000, 16); bomb.writeUInt32BE(30000, 20);
    await file.setInputFiles({ name: "bomb.png", mimeType: "image/png", buffer: bomb });
    await expect(profile.locator(".error-text")).not.toBeEmpty();
    await expect(page.locator(".nav-right .avatar img")).toHaveCount(1); // the earlier picture stays

    await page.locator(".tabs button", { hasText: "Team" }).click();
    await expect(card(page, "Members").locator("tbody tr .avatar img")).toHaveCount(1);
    await page.locator(".tabs button", { hasText: "Account" }).click();
    await card(page, "Profile").locator("button", { hasText: "Remove" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Picture removed" }).last()).toBeVisible();
    await expect(page.locator(".nav-right .avatar img")).toHaveCount(0);
    expect((await page.request.get(`/api/users/${acc.me.id}/avatar`)).status()).toBe(404);
  });

  test("probe profiles: create with validation, edit, delete", async ({ page }) => {
    await signedIn(page, "profiles");
    await settingsTab(page, "Probe profiles");
    await expect(card(page, "Probe profiles").locator("tbody tr")).toHaveCount(4);
    await expect(card(page, "Probe profiles").locator("tbody tr", { hasText: "Standard" }).locator(".badge")).toHaveText("default");
    await card(page, "Probe profiles").locator("button", { hasText: "New profile" }).click();
    const modal = page.locator(".modal");
    await page.getByPlaceholder("e.g. Standard").fill("Tight");
    await field(modal, "Interval (s)").fill("10");
    await field(modal, "Pings / cycle").fill("20");
    await modal.locator("button", { hasText: "Create" }).click();
    await expect(modal.locator(".error-text")).toContainText("cannot exceed the interval");
    await field(modal, "Pings / cycle").fill("5");
    await field(modal, "Packet size (B)").fill("2000");
    await modal.locator("button", { hasText: "Create" }).click();
    await expect(modal.locator(".error-text")).toContainText("at most 1472");
    await field(modal, "Packet size (B)").fill("100");
    await modal.locator("button", { hasText: "Create" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Saved" }).last()).toBeVisible();
    const rowT = card(page, "Probe profiles").locator("tbody tr", { hasText: "Tight" });
    await expect(rowT).toContainText("10 s");
    await rowT.locator("button", { hasText: "Edit" }).click();
    await page.getByPlaceholder("e.g. Standard").fill("Tighter");
    await page.locator(".modal button", { hasText: "Save" }).click();
    await expect(card(page, "Probe profiles").locator("tbody tr", { hasText: "Tighter" })).toHaveCount(1);
    await card(page, "Probe profiles").locator("tbody tr", { hasText: "Tighter" }).locator("button", { hasText: "Delete" }).click();
    await confirm(page, "Delete");
    await expect(card(page, "Probe profiles").locator("tbody tr")).toHaveCount(4);
  });

  test("notifications: a channel keeps its secret, rules reference it", async ({ page }) => {
    await signedIn(page, "notify");
    await page.request.post("/api/nodes", { data: { kind: "folder", name: "Edge" } });
    await settingsTab(page, "Notifications");
    await expect(card(page, "Active alerts")).toContainText("Nothing is alerting");
    await expect(card(page, "Alert rules").locator("button", { hasText: "New rule" })).toBeDisabled();
    await card(page, "Channels").locator("button", { hasText: "Add channel" }).click();
    const modal = page.locator(".modal");
    await field(modal, "Type").selectOption("telegram");
    await page.getByPlaceholder("e.g. NOC on-call").fill("NOC bot");
    const token = "123456789:AAEhBP0av28AbCdEfGhIjKlMnOpQrStUvWx";
    await page.getByPlaceholder("123456789:AA...").fill(token);
    await field(modal, "Chat id").fill("-100123456");
    await modal.locator("button", { hasText: "Add channel" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Channel saved" }).last()).toBeVisible();
    const chRow = card(page, "Channels").locator("tbody tr", { hasText: "NOC bot" });
    await expect(chRow).toContainText("chat -100123456");
    await expect(chRow.locator(".badge.ok")).toHaveText("enabled");
    // the token is never shown again, in the UI or the API
    await chRow.locator("button", { hasText: "Edit" }).click();
    await expect(page.getByPlaceholder("stored - leave empty to keep")).toHaveValue("");
    await page.locator(".modal button", { hasText: "Cancel" }).click();
    expect(await (await page.request.get("/api/notify/channels")).text()).not.toContain(token);

    await card(page, "Alert rules").locator("button", { hasText: "New rule" }).click();
    await page.getByPlaceholder("e.g. Core links: packet loss").fill("Edge loss");
    await field(page.locator(".modal"), "Hosts").selectOption({ label: "▸ Edge" });
    await expect(page.locator(".modal .hint", { hasText: "Alert when packet loss" })).toBeVisible();
    await page.locator(".modal button", { hasText: "Create rule" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Rule saved" }).last()).toBeVisible();
    const ruleRow = card(page, "Alert rules").locator("tbody tr", { hasText: "Edge loss" });
    await expect(ruleRow).toContainText("Edge");
    await expect(ruleRow).toContainText("NOC bot");
    await expect(ruleRow).toContainText("Packet loss ≥ 20% for 5 min");

    await ruleRow.locator("button", { hasText: "Delete" }).click();
    await confirm(page, "Delete");
    await expect(page.locator(".toast.ok", { hasText: "Rule deleted" }).last()).toBeVisible();
    await chRow.locator("button", { hasText: "Delete" }).click();
    await confirm(page, "Delete");
    await expect(page.locator(".toast.ok", { hasText: "Channel deleted" }).last()).toBeVisible();
    await expect(card(page, "Channels")).toContainText("No channels yet");
  });

  test("retention, usage and the audit log", async ({ page }) => {
    const acc = await signedIn(page, "misc");
    await page.request.post("/api/nodes", { data: { kind: "host", name: "audited", host: "192.0.2.77" } });
    await settingsTab(page, "Data retention");
    await page.locator("input[name=ret][value='2']").check();
    await card(page, "Data retention").locator("button", { hasText: "Save" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Retention updated" }).last()).toBeVisible();
    expect((await (await page.request.get("/api/me")).json()).org.retention_years).toBe(2);
    await page.reload();
    await page.locator(".tabs button", { hasText: "Data retention" }).click();
    await expect(page.locator("input[name=ret][value='2']")).toBeChecked();

    await page.locator(".tabs button", { hasText: "Usage" }).click();
    await expect(page.locator(".ukpi")).toHaveCount(4);
    await expect(page.locator(".ukpi-lbl").first()).toHaveText("Measurements stored");
    const forecast = card(page, "Storage forecast");
    await expect(forecast).toContainText("Yours is 2 years");
    await expect(forecast.locator(".ulegend")).toContainText("Your retention: 2 years");
    await expect(forecast.locator(".uchart canvas")).toBeVisible();
    // every chart has the same numbers as a table
    await forecast.locator("button", { hasText: "Table" }).click();
    await expect(forecast.locator(".uchart")).toBeHidden();
    await expect(forecast.locator("thead th")).toHaveText(["When", "1 year", "2 years (yours)", "3 years"]);
    await expect(forecast.locator("tbody tr")).toHaveCount(7);
    await forecast.locator("button", { hasText: "Chart" }).click();
    await expect(forecast.locator(".uchart")).toBeVisible();
    await expect(card(page, "Measurements per day").locator(".uchart canvas")).toBeVisible();

    await page.locator(".tabs button", { hasText: "Audit log" }).click();
    const audit = card(page, "Audit log");
    await expect(audit.locator("tbody tr").first()).toBeVisible();
    await expect(audit).toContainText("org.retention");
    await expect(audit).toContainText("host.create");
    await expect(audit.locator("tbody tr", { hasText: "host.create" })).toContainText(acc.email);
  });

  test("audit log: paged, 10 rows by default, sizes up to 200", async ({ page }) => {
    await signedIn(page, "auditpages");
    for (let i = 0; i < 27; i++) {
      const r = await page.request.post("/api/account/name", { data: { first_name: "n" + i, last_name: "x" } });
      expect(r.ok()).toBeTruthy();
    }
    const total = (await (await page.request.get("/api/audit")).json()).total;
    expect(total).toBeGreaterThanOrEqual(28);
    await settingsTab(page, "Audit log");
    const audit = card(page, "Audit log");
    await expect(audit.locator("tbody tr")).toHaveCount(10);
    await expect(audit.locator(".pager-info")).toHaveText(`1-10 of ${total}`);
    await expect(audit.locator(".pager-size select")).toHaveValue("10");
    await expect(audit.locator(".pager-size option")).toHaveText(["10", "20", "50", "100", "200"]);
    const prev = audit.locator(".pager-nav button", { hasText: "Previous" }), next = audit.locator(".pager-nav button", { hasText: "Next" });
    await expect(prev).toBeDisabled();
    // newest first: the last name change is on top
    await expect(audit.locator("tbody tr").first()).toContainText("account.name_change");
    await next.click();
    await expect(audit.locator(".pager-info")).toHaveText(`11-20 of ${total}`);
    await expect(prev).toBeEnabled();
    await next.click();
    await expect(audit.locator(".pager-info")).toHaveText(`21-${Math.min(30, total)} of ${total}`);
    await expect(audit.locator("tbody tr")).toHaveCount(Math.min(10, total - 20));
    if (total <= 30) await expect(next).toBeDisabled();
    await prev.click();
    await expect(audit.locator(".pager-info")).toHaveText(`11-20 of ${total}`);
    // a bigger page starts again at the top and shows everything
    await audit.locator(".pager-size select").selectOption("50");
    await expect(audit.locator(".pager-info")).toHaveText(`1-${total} of ${total}`);
    await expect(audit.locator("tbody tr")).toHaveCount(total);
    await expect(audit.locator("tbody tr").last()).toContainText("org.create");
    await expect(next).toBeDisabled();
    // the chosen size is remembered
    await page.reload();
    await page.locator(".tabs button", { hasText: "Audit log" }).click();
    await expect(card(page, "Audit log").locator(".pager-size select")).toHaveValue("50");
    await expect(card(page, "Audit log").locator("tbody tr")).toHaveCount(total);
  });

  test("a member only reads: no management buttons, API refuses changes", async ({ page, browser }) => {
    await signedIn(page, "roles");
    const inv = await (await page.request.post("/api/invites", { data: { role: "member" } })).json();
    const ctx = await browser.newContext();
    const m = await ctx.newPage();
    const member = { email: uniq("ro") + "@e2e.test", password: "Ro-pw-" + uniq("p") };
    const join = await m.request.post("/api/auth/accept-invite", { data: { token: inv.token, email: member.email, password: member.password } });
    expect(join.ok()).toBeTruthy();
    await m.goto("/#/settings?tab=profiles");
    await expect(m.locator(".nav-user")).toHaveText(member.email);
    await expect(card(m, "Probe profiles").locator("button", { hasText: "New profile" })).toHaveCount(0);
    await m.locator(".tabs button", { hasText: "Notifications" }).click();
    await expect(card(m, "Channels").locator("button", { hasText: "Add channel" })).toHaveCount(0);
    await m.locator(".tabs button", { hasText: "Import" }).click();
    await expect(m.locator("main")).toContainText("Only owners and admins can import");
    await m.locator(".tabs button", { hasText: "Data retention" }).click();
    await expect(m.locator("input[name=ret]").first()).toBeDisabled();
    for (const [method, path, data] of [
      ["post", "/api/invites", { role: "member" }],
      ["get", "/api/invites", undefined],
      ["post", "/api/settings/retention", { years: 3 }],
      ["post", "/api/notify/channels", { name: "x", kind: "slack", config: {}, secrets: { webhook_url: "https://hooks.slack.com/services/T000/B000/h" } }],
    ]) {
      const r = await m.request[method](path, data ? { data } : {});
      expect(r.status(), `${method} ${path}`).toBe(403);
    }
    await ctx.close();
  });
});
