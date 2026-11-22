// Security keys and passkeys as second factors, through the UI, with the
// browser's virtual authenticators (Chrome DevTools protocol). WebAuthn
// needs a secure context, so these tests use the stack's WebAuthn address
// (WEBAUTHN_URL, see scripts/test-stack.sh and playwright.config.js).
const { test, expect } = require("@playwright/test");
const { account, registerViaApi, signOut, field, virtualAuthenticator, watchConsole } = require("../helpers");

test.use({ baseURL: process.env.WEBAUTHN_URL });

const tfaCard = (page) => page.locator(".card").filter({ has: page.locator("h2", { hasText: "Two-factor authentication" }) });
const method = (page, title) => tfaCard(page).locator(".tfa-method").filter({ has: page.locator(".tfa-method-title", { hasText: title }) });

async function signInWithPassword(page, acc) {
  await page.goto("/");
  await expect(page.locator(".auth-tabs")).toBeVisible();
  await page.getByPlaceholder("you@example.com").fill(acc.email);
  await page.getByPlaceholder("Password").fill(acc.password);
  await page.locator(".auth-card button.primary", { hasText: "Sign in" }).click();
}

async function addCredential(page, acc, button, name) {
  await tfaCard(page).locator("button", { hasText: button }).click();
  const modal = page.locator(".modal");
  await field(modal, "Name").fill(name);
  await field(modal, "Confirm with password").fill(acc.password);
  await modal.locator("button", { hasText: "Continue" }).click();
}

test.describe("security keys and passkeys @e2e @security", () => {
  test.skip(!process.env.WEBAUTHN_URL, "the stack has no WebAuthn address");

  test("security key: enrol, sign in with it, the password alone is not enough, remove", async ({ page }) => {
    const errors = watchConsole(page);
    const acc = account("fido");
    await registerViaApi(page, acc);
    const key = await virtualAuthenticator(page, "key");
    await page.goto("/#/settings?tab=account");
    await expect(tfaCard(page).locator(".spread > .badge")).toHaveText("off");

    // a wrong password stops the enrollment before the key is asked
    await tfaCard(page).locator("button", { hasText: "Add security key" }).click();
    const modal = page.locator(".modal");
    await field(modal, "Name").fill("Desk YubiKey");
    await field(modal, "Confirm with password").fill("wrong-" + acc.password);
    await modal.locator("button", { hasText: "Continue" }).click();
    await expect(modal.locator(".error-text")).toHaveText("password is incorrect");
    await field(modal, "Confirm with password").fill(acc.password);
    await modal.locator("button", { hasText: "Continue" }).click();
    await expect(page.locator(".toast.ok", { hasText: "The security key was added" }).last()).toBeVisible();
    await expect(tfaCard(page).locator(".spread > .badge")).toHaveText("enabled");
    await expect(method(page, "Security keys").locator(".badge")).toHaveText("1");
    await expect(tfaCard(page).locator(".tfa-keys tr", { hasText: "Desk YubiKey" })).toContainText("never used");
    // the same key cannot be enrolled twice
    await addCredential(page, acc, "Add security key", "Again");
    await expect(modal.locator(".error-text")).toHaveText("This key or device is already enrolled for your account.");
    await modal.locator("button", { hasText: "Cancel" }).click();

    // the team list names the factor
    await page.locator(".tabs button", { hasText: "Team" }).click();
    await expect(page.locator("table.team tbody tr").first().locator("td").nth(3)).toHaveText("Security key");

    // sign in: password, then the key answers the prompt by itself
    await signOut(page);
    await signInWithPassword(page, acc);
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
    const audit = await (await page.request.get("/api/audit?limit=5")).json();
    expect(audit.items.find((e) => e.action === "auth.login").detail).toBe("with two-factor (security key)");

    // without the key the password does not sign in
    await signOut(page);
    await key.remove();
    await signInWithPassword(page, acc);
    await expect(page.locator("button.auth-key")).toBeVisible();
    await expect(page.getByPlaceholder("123456")).toBeHidden(); // no authenticator app on this account
    await expect(page.locator(".nav-user")).toHaveCount(0);
    expect((await page.request.get("/api/me")).status()).toBe(401);
    const api = await page.request.post("/api/auth/login", { data: { email: acc.email, password: acc.password } });
    expect(api.status()).toBe(401);
    expect((await api.json()).methods).toEqual(["webauthn"]);

    // refused requests (wrong password, the password alone) are expected;
    // script errors and Content Security Policy violations are not
    expect(errors.filter((e) => !e.startsWith("Failed to load resource"))).toEqual([]);
  });

  test("passkey: enrol on this device, sign in, remove with the password", async ({ page }) => {
    const acc = account("passkey");
    await registerViaApi(page, acc);
    await virtualAuthenticator(page, "passkey");
    await page.goto("/#/settings?tab=account");
    await addCredential(page, acc, "Add passkey", "This laptop");
    await expect(page.locator(".toast.ok", { hasText: "The passkey was added" }).last()).toBeVisible();
    await expect(method(page, "Passkeys").locator(".badge")).toHaveText("1");
    await expect(method(page, "Security keys").locator(".badge")).toHaveText("none");

    await signOut(page);
    await signInWithPassword(page, acc);
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
    const audit = await (await page.request.get("/api/audit?limit=5")).json();
    expect(audit.items.find((e) => e.action === "auth.login").detail).toBe("with two-factor (passkey)");
    expect((await (await page.request.get("/api/me")).json()).two_factor).toEqual(["passkey"]);

    await page.goto("/#/settings?tab=account");
    await expect(tfaCard(page).locator(".tfa-keys tr", { hasText: "This laptop" })).toContainText("last used");
    await tfaCard(page).locator("button[aria-label='Remove This laptop']").click();
    const modal = page.locator(".modal");
    await field(modal, "Confirm with password").fill("wrong-" + acc.password);
    await modal.locator("button", { hasText: "Remove" }).click();
    await expect(modal.locator(".error-text")).toHaveText("password is incorrect");
    await field(modal, "Confirm with password").fill(acc.password);
    await modal.locator("button", { hasText: "Remove" }).click();
    await expect(page.locator(".toast.ok", { hasText: "The passkey was removed" }).last()).toBeVisible();
    await expect(tfaCard(page).locator(".spread > .badge")).toHaveText("off");

    // the password alone is enough again
    await signOut(page);
    await signInWithPassword(page, acc);
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
  });
});
