// Frontend module tests, run inside the real browser against the served
// files (no bundler, no DOM emulation): web/js/ui.js, api.js, chart.js and
// the formatting helpers of the views.
const { test, expect } = require("@playwright/test");

test.describe("frontend modules @unit", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".auth-tabs")).toBeVisible();
  });

  test("ui.js: h() builds elements and never interprets text as HTML", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const { h } = await import("/js/ui.js");
      let clicked = 0;
      const el = h("button.btn.primary#go", { title: "T", "data-x": "1", onclick: () => clicked++ }, "a <b>bold</b> ", h("span", "kid"), null, false, 42);
      el.click();
      return { tag: el.tagName, cls: el.className, id: el.id, title: el.title, data: el.dataset.x, html: el.innerHTML, clicked, kids: el.children.length };
    });
    expect(r).toMatchObject({ tag: "BUTTON", cls: "btn primary", id: "go", title: "T", data: "1", clicked: 1, kids: 1 });
    expect(r.html).toContain("a &lt;b&gt;bold&lt;/b&gt;");
    expect(r.html).toContain("42");
    expect(r.html).not.toContain("<b>");
  });

  test("ui.js: time formatting", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const m = await import("/js/ui.js");
      const now = Math.floor(Date.now() / 1000);
      return {
        dt: m.fmtDateTime(now),
        until2m: m.fmtUntil(now + 150), untilH: m.fmtUntil(now + 7260), untilD: m.fmtUntil(now + 3 * 86400 + 60), expired: m.fmtUntil(now - 1),
        agoS: m.fmtRelative(now - 5), agoM: m.fmtRelative(now - 150), agoH: m.fmtRelative(now - 3700), agoD: m.fmtRelative(now - 2 * 86400 - 60),
      };
    });
    expect(r.dt).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    expect(r).toMatchObject({ until2m: "2m left", untilH: "2h left", untilD: "3d left", expired: "expired", agoM: "2m ago", agoH: "1h ago", agoD: "2d ago" });
    expect(r.agoS).toMatch(/^[5-9]s ago$/);
  });

  test("ui.js: theme and local storage helpers", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const m = await import("/js/ui.js");
      m.applyTheme("light");
      const light = document.documentElement.getAttribute("data-theme");
      m.toggleTheme();
      const dark = document.documentElement.getAttribute("data-theme");
      m.saveJSON("e2e-key", { a: [1, 2], b: "x" });
      const back = m.loadJSON("e2e-key", null);
      const fallback = m.loadJSON("e2e-missing", "fb");
      localStorage.setItem("e2e-bad", "{not json");
      const bad = m.loadJSON("e2e-bad", "fb2");
      return { light, dark, back, fallback, bad, current: m.currentTheme() };
    });
    expect(r).toEqual({ light: "light", dark: "dark", back: { a: [1, 2], b: "x" }, fallback: "fb", bad: "fb2", current: "dark" });
  });

  test("ui.js: modal and confirmDialog", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const m = await import("/js/ui.js");
      let yes = 0;
      m.confirmDialog("Delete?", "really", async () => { yes++; }, "Zap");
      const open = !!document.querySelector(".modal-back .modal");
      const title = document.querySelector(".modal h3").textContent;
      const btn = [...document.querySelectorAll(".modal-actions button")].find((b) => b.textContent === "Zap");
      btn.click();
      await new Promise((r) => setTimeout(r, 20));
      const closed = !document.querySelector(".modal-back");
      // Escape closes a modal
      const mm = m.modal("T", null, [], []);
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
      const escClosed = !document.querySelector(".modal-back");
      mm.close();
      return { open, title, yes, closed, escClosed };
    });
    expect(r).toEqual({ open: true, title: "Delete?", yes: 1, closed: true, escClosed: true });
  });

  test("ui.js: pager keeps offset, size and bounds", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const { pager, PAGE_SIZES } = await import("/js/ui.js");
      localStorage.removeItem("driftband-page-unit");
      let total = 35, calls = [];
      const pg = pager("unit", () => { calls.push([pg.limit, pg.offset]); pg.set(total); });
      document.body.append(pg.el);
      const info = () => pg.el.querySelector(".pager-info").textContent;
      const [prev, next] = pg.el.querySelectorAll(".pager-nav button");
      const sel = pg.el.querySelector("select");
      const out = { sizes: PAGE_SIZES, initial: [pg.limit, pg.offset, info()] };
      pg.set(total);
      out.first = [info(), prev.disabled, next.disabled];
      next.click(); next.click(); next.click();
      out.last = [info(), prev.disabled, next.disabled, pg.offset];
      next.click(); // disabled: no call
      out.callsAfterNext = calls.length;
      total = 12; pg.set(total); // rows vanished: back to the last page that exists
      out.shrunk = [info(), pg.offset];
      sel.value = "200"; sel.dispatchEvent(new Event("change"));
      out.resized = [pg.limit, pg.offset, info(), localStorage.getItem("driftband-page-unit")];
      const again = pager("unit", () => {});
      out.remembered = again.limit;
      localStorage.setItem("driftband-page-unit", "7"); // not an offered size
      out.invalid = pager("unit", () => {}).limit;
      total = 0; pg.set(0);
      out.empty = [info(), prev.disabled, next.disabled];
      pg.el.remove();
      return out;
    });
    expect(r.sizes).toEqual([10, 20, 50, 100, 200]);
    expect(r.initial).toEqual([10, 0, "0 of 0"]);
    expect(r.first).toEqual(["1-10 of 35", true, false]);
    expect(r.last).toEqual(["31-35 of 35", false, true, 30]);
    expect(r.callsAfterNext).toBe(3);
    expect(r.shrunk).toEqual(["11-12 of 12", 10]);
    expect(r.resized).toEqual([200, 0, "1-12 of 12", "200"]);
    expect(r.remembered).toBe(200);
    expect(r.invalid).toBe(10);
    expect(r.empty).toEqual(["0 of 0", true, true]);
  });

  test("api.js: errors carry the status and the server message", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const { api } = await import("/js/api.js");
      const out = {};
      try { await api.me(); } catch (e) { out.me = { status: e.status, msg: e.message }; }
      try { await api.login({ email: "nobody@e2e.test", password: "wrong-wrong" }); } catch (e) { out.login = { status: e.status, msg: e.message }; }
      try { await api.get("/api/does-not-exist"); } catch (e) { out.unknown = { status: e.status }; }
      return out;
    });
    expect(r.me).toEqual({ status: 401, msg: "not authenticated" });
    expect(r.login).toEqual({ status: 401, msg: "invalid email or password" });
    expect(r.unknown.status).toBe(404);
  });

  test("ui.js avatar() and the webauthn.js helpers", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const ui = await import("/js/ui.js");
      const wa = await import("/js/webauthn.js");
      const a = ui.avatar({ id: 7, email: "ada.nowak@example.com", first_name: "", last_name: "" }, 40);
      const b = ui.avatar({ id: 7, email: "x@example.com", first_name: "Jan", last_name: "Kowalski", avatar: "abc123" }, 32);
      const c = ui.avatar({ id: 1, email: "x@example.com", first_name: "<img src=x onerror=alert(1)>", last_name: "" });
      const same = ui.avatar({ id: 9, email: "ada.nowak@example.com" }, 40);
      return {
        aText: a.textContent, aWidth: a.style.width, aImg: !!a.querySelector("img"), aBg: a.style.background, sameBg: same.style.background,
        bSrc: b.querySelector("img").getAttribute("src"), bText: b.textContent, cHtml: c.innerHTML, cKids: c.children.length,
        errs: ["NotAllowedError", "InvalidStateError", "SecurityError"].map((n) => wa.webauthnError({ name: n })),
        other: wa.webauthnError(new Error("boom")), supported: typeof wa.webauthnSupported(),
      };
    });
    // initials from the email when there is no name, a stable colour per person
    expect(r).toMatchObject({ aText: "AN", aWidth: "40px", aImg: false, bSrc: "/api/users/7/avatar?v=abc123", bText: "", cHtml: "&lt;O", cKids: 0, supported: "boolean", other: "boom" });
    expect(r.aBg).not.toBe("");
    expect(r.sameBg).toBe(r.aBg);
    expect(r.errs[0]).toContain("cancelled");
    expect(r.errs[1]).toContain("already enrolled");
    expect(r.errs[2]).toContain("HTTPS");
  });

  test("formatting helpers of the views", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const a = await import("/js/views/admin.js");
      const u = await import("/js/views/usage.js");
      return {
        b0: a.fmtBytes(0), b1: a.fmtBytes(1536), b2: a.fmtBytes(10 * 1024 * 1024), b3: a.fmtBytes(3.5 * 1024 ** 3), bNull: a.fmtBytes(null),
        s0: u.fmtSize(0), s1: u.fmtSize(2048), sInf: u.fmtSize(Infinity),
      };
    });
    expect(r).toMatchObject({ b0: "0 B", b1: "1.50 KB", b2: "10.0 MB", b3: "3.50 GB", bNull: "-", sInf: "-" });
    expect(r.s0).toMatch(/^0(\.0+)? B$/);
    expect(r.s1).toMatch(/^2(\.0+)? KB$/);
  });

  test("chart.js: a chart card renders points and legend statistics", async ({ page }) => {
    const r = await page.evaluate(async () => {
      const { buildChartCard } = await import("/js/chart.js");
      const now = Math.floor(Date.now() / 1000);
      const points = [];
      for (let i = 0; i < 60; i++) {
        const ts = now - (60 - i) * 60, base = 10 + (i % 7);
        points.push({ ts, p0: base - 1, p2_5: base - 0.8, p10: base - 0.5, p25: base - 0.2, p50: base, p75: base + 0.2, p90: base + 0.5, p97_5: base + 0.8, p100: base + 1, loss: i === 30 ? 5 : 0, sent: 20, recv: i === 30 ? 15 : 20 });
      }
      const stats = { cycles: 60, loss_cycles: 1, sent: 1200, recv: 1195, loss_max: 0.25, loss_min: 0, med_avg: 13, med_sd: 2, rtt_min: 9, rtt_max: 17, now: 12, now_loss: 0, now_sent: 20, last: now - 60 };
      let calls = 0;
      const c = buildChartCard({ title: "unit host", ip: "192.0.2.9", interval: 60, pings: 20, packet: 56, height: 220,
        fetch: async () => { calls++; return { step: 0, since: 0, points, stats }; } });
      document.body.append(c.el);
      await c.load(now - 3600, now, false);
      const canvas = !!c.el.querySelector(".chart canvas");
      const rtt = c.el.querySelector(".lg-rtt").textContent;
      const loss = c.el.querySelector(".lg-loss-stats").textContent;
      const placeholder = !!c.el.querySelector(".chart .placeholder");
      c.destroy();
      return { calls, canvas, rtt, loss, placeholder, title: c.el.querySelector(".label").textContent };
    });
    expect(r.calls).toBe(1);
    expect(r.canvas).toBe(true);
    expect(r.placeholder).toBe(false);
    expect(r.title).toBe("unit host");
    expect(r.rtt).toContain("avg 13.0");
    expect(r.rtt).toContain("max 17.0");
    expect(r.loss).toContain("0.42%");
    expect(r.loss).toContain("cycles with loss 1/60");
  });
});
