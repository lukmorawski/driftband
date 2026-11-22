// "Active Alerts" in the navigation bar and its page: what is alerting now
// and the paged delivery history. The second test raises a real alert: an
// address that never answers, probed every 5 seconds, with a one-minute rule.
const { test, expect } = require("@playwright/test");
const { signedIn, watchConsole } = require("../helpers");

const card = (page, title) => page.locator(".card").filter({ has: page.locator("h2", { hasText: new RegExp(`^${title}$`) }) });

test.describe("active alerts @e2e", () => {
  test("the navigation link opens a page with active alerts and the history only", async ({ page }) => {
    await signedIn(page, "alertsnav");
    const errors = watchConsole(page);
    const link = page.locator(".nav-center a.nav-alerts");
    await expect(link).toHaveText("Active Alerts");
    await expect(link.locator(".nav-alerts-count")).toBeHidden();
    await link.click();
    await expect(page).toHaveURL(/#\/alerts$/);
    await expect(link).toHaveClass(/active/);
    await expect(page.locator(".nav-links a.active")).toHaveCount(0);
    await expect(page.locator(".section-title h2")).toHaveText("Active Alerts");
    // exactly the two cards, nothing to configure here
    await expect(page.locator("main .card h2")).toHaveText(["Active alerts", "Recent notifications"]);
    await expect(card(page, "Active alerts")).toContainText("Nothing is alerting right now");
    const history = card(page, "Recent notifications");
    await expect(history).toContainText("No notifications sent yet");
    await expect(history.locator(".pager-info")).toHaveText("0 of 0");
    await expect(history.locator(".pager-size option")).toHaveText(["10", "20", "50", "100", "200"]);
    await expect(page.locator("main button", { hasText: /Add channel|New rule/ })).toHaveCount(0);
    // the same history, paged, is still part of Settings > Notifications
    await page.goto("/#/settings?tab=notifications");
    await expect(card(page, "Recent notifications").locator(".pager")).toBeVisible();
    await expect(card(page, "Channels")).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("an unreachable host raises an alert: badge, active list, history", async ({ page }) => {
    test.setTimeout(300_000);
    await signedIn(page, "alertfire");
    const prof = await (await page.request.post("/api/profiles", { data: { name: "Rapid", interval_s: 5, ping_count: 3, packet_size: 56, is_default: false } })).json();
    // example.com is the documentation domain: a public HTTPS address that takes no deliveries
    const ch = await (await page.request.post("/api/notify/channels", { data: { name: "hook", kind: "slack", config: {}, secrets: { webhook_url: "https://example.com/driftband-e2e-hook" } } })).json();
    expect(ch.id, JSON.stringify(ch)).toBeTruthy();
    const host = await (await page.request.post("/api/nodes", { data: { kind: "host", name: "blackhole", host: "192.0.2.199", profile_id: prof.id } })).json();
    const rule = await page.request.post("/api/notify/rules", { data: { name: "Down fast", enabled: true, node_id: host.id, metric: "loss", threshold: 50, recover_threshold: 10,
      for_minutes: 1, recover_minutes: 1, notify_recovery: true, repeat_minutes: 0, flap_transitions: 0, flap_window_minutes: 60, channel_ids: [ch.id] } });
    expect(rule.ok(), await rule.text()).toBeTruthy();

    await expect.poll(async () => (await (await page.request.get("/api/notify/events")).json()).active.length,
      { timeout: 240_000, intervals: [5000], message: "the rule never fired" }).toBe(1);
    await expect.poll(async () => (await (await page.request.get("/api/notify/events")).json()).log_total,
      { timeout: 60_000, intervals: [3000], message: "no delivery was logged" }).toBeGreaterThan(0);

    // The page is already on the dashboard, where the badge refreshes once a
    // minute; a reload shows the current count at once.
    await page.reload();
    const link = page.locator(".nav-center a.nav-alerts");
    await expect(link.locator(".nav-alerts-count")).toHaveText("1");
    await expect(link).toHaveClass(/alerting/);
    await link.click();
    const active = card(page, "Active alerts").locator("tbody tr");
    await expect(active).toHaveCount(1);
    await expect(active.locator("td")).toContainText(["blackhole", "Down fast", "alerting", "100.0%"]);
    const history = card(page, "Recent notifications");
    const fired = history.locator("tbody tr", { hasText: "firing" }).first();
    await expect(fired).toContainText("blackhole");
    await expect(fired).toContainText("hook");
    await expect(history.locator(".pager-info")).toHaveText(/^1-\d+ of \d+$/);

    // removing the host clears the alert
    expect((await page.request.delete(`/api/nodes/${host.id}`)).ok()).toBeTruthy();
    await page.reload();
    await expect(card(page, "Active alerts")).toContainText("Nothing is alerting right now");
    await expect(page.locator(".nav-center .nav-alerts-count")).toBeHidden();
  });
});
