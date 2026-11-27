// Single sign-on through the UI, against the stack's stand-in provider
// (tests/e2e/idp, in the role of Microsoft Entra ID): connecting an account,
// signing in with it, the second factor, an identity nobody connected, and
// disconnecting. The provider sends the browser back to the address the
// application knows as its own, so these tests use that address
// (WEBAUTHN_URL, see scripts/test-stack.sh).
const { test, expect } = require("@playwright/test");
const { account, registerViaApi, signOut, field, totp, watchConsole } = require("../helpers");

test.use({ baseURL: process.env.WEBAUTHN_URL, ignoreHTTPSErrors: true });

const provider = process.env.SSO_PROVIDER_URL || "";
const ssoCard = (page) => page.locator(".card").filter({ has: page.locator("h2", { hasText: "Single sign-on" }) });
const row = (page, name) => ssoCard(page).locator(".tfa-method").filter({ has: page.locator(".tfa-method-title", { hasText: name }) });
const subject = (tag) => `${tag}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

// The provider's page: who is signing in.
async function atProvider(page, sub, email, decision = "Continue") {
  await expect(page).toHaveURL(new RegExp("^" + provider.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  await page.locator("input[name=sub]").fill(sub);
  await page.locator("input[name=email]").fill(email);
  await page.locator("button", { hasText: decision }).click();
}

async function connect(page, acc, sub) {
  await page.goto("/#/settings?tab=account");
  await expect(row(page, "Microsoft").locator(".badge")).toHaveText("not connected");
  await row(page, "Microsoft").locator("button", { hasText: "Connect" }).click();
  const modal = page.locator(".modal");
  await field(modal, "Confirm with password").fill(acc.password);
  await modal.locator("button", { hasText: "Continue" }).click();
  await atProvider(page, sub, "ada@contoso.example");
  await expect(page.locator(".toast")).toContainText("Your Microsoft account is connected");
  await expect(row(page, "Microsoft").locator(".badge")).toHaveText("connected");
}

test.describe("single sign-on @e2e @security", () => {
  test.skip(!process.env.WEBAUTHN_URL || !provider, "the stack has no single sign-on provider");

  test("the sign-in page offers the providers of the instance", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".auth-sso")).toHaveText(["Sign in with Google", "Sign in with Microsoft"]);
    await expect(page.locator(".auth-sso").nth(1)).toHaveAttribute("href", "/api/auth/sso/entra/start");
    // creating an organization goes by password
    await page.locator(".auth-tabs button", { hasText: "Create organization" }).click();
    await expect(page.locator(".auth-sso")).toHaveCount(0);
  });

  test("connect an account, sign in with it, disconnect", async ({ page }) => {
    const errors = watchConsole(page);
    const acc = account("sso");
    await registerViaApi(page, acc);
    const sub = subject("ada");

    // connecting asks for the password first
    await page.goto("/#/settings?tab=account");
    await row(page, "Microsoft").locator("button", { hasText: "Connect" }).click();
    const modal = page.locator(".modal");
    await field(modal, "Confirm with password").fill("wrong-" + acc.password);
    await modal.locator("button", { hasText: "Continue" }).click();
    await expect(modal.locator(".error-text")).toHaveText("password is incorrect");
    await modal.locator("button", { hasText: "Cancel" }).click();

    await connect(page, acc, sub);
    await expect(row(page, "Microsoft")).toContainText("Connected as ada@contoso.example");
    await expect(row(page, "Google").locator(".badge")).toHaveText("not connected");

    await signOut(page);
    await page.locator(".auth-sso", { hasText: "Sign in with Microsoft" }).click();
    await atProvider(page, sub, "ada@contoso.example");
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
    // the provider's answer does not stay in the address bar
    expect(new URL(page.url()).search).toBe("");
    expect(new URL(page.url()).pathname).toBe("/");
    await page.reload();
    await expect(page.locator(".nav-user")).toHaveText(acc.email);

    // the audit log names the way in
    await page.goto("/#/settings?tab=audit");
    await expect(page.locator("main table")).toContainText("with Microsoft");

    // disconnect, and the same identity opens nothing any more
    await page.goto("/#/settings?tab=account");
    await row(page, "Microsoft").locator("button", { hasText: "Disconnect" }).click();
    await field(page.locator(".modal"), "Confirm with password").fill(acc.password);
    await page.locator(".modal button", { hasText: "Disconnect" }).click();
    await expect(row(page, "Microsoft").locator(".badge")).toHaveText("not connected");
    await signOut(page);
    await page.locator(".auth-sso", { hasText: "Sign in with Microsoft" }).click();
    await atProvider(page, sub, "ada@contoso.example");
    await expect(page.locator(".error-text")).toContainText("No account here is connected to this Microsoft account");
    await page.locator("a", { hasText: "Back to sign in" }).click();
    await expect(page.locator(".auth-tabs")).toBeVisible();
    expect(errors.filter((e) => !/40[13]/.test(e))).toEqual([]);
  });

  test("an identity is never matched by its email address", async ({ page }) => {
    const acc = account("ssomail");
    await registerViaApi(page, acc);
    await page.goto("/#/dashboard");
    await signOut(page);
    await page.locator(".auth-sso", { hasText: "Sign in with Microsoft" }).click();
    await atProvider(page, subject("stranger"), acc.email);
    await expect(page.locator(".error-text")).toContainText("No account here is connected");
    expect((await page.request.get("/api/me")).status()).toBe(401);
  });

  test("cancelling at the provider leads back to the sign-in page", async ({ page }) => {
    await page.goto("/");
    await page.locator(".auth-sso", { hasText: "Sign in with Microsoft" }).click();
    await atProvider(page, "", "", "Cancel");
    await expect(page.locator(".error-text")).toHaveText("The sign-in was cancelled.");
    await page.locator("a", { hasText: "Back to sign in" }).click();
    await expect(page.locator(".auth-tabs")).toBeVisible();
  });

  test("with two-factor on, single sign-on still asks for the code", async ({ page }) => {
    const acc = account("sso2fa");
    await registerViaApi(page, acc);
    const sub = subject("grace");
    await connect(page, acc, sub);
    const setup = await (await page.request.post("/api/account/2fa/setup", { data: { password: acc.password } })).json();
    expect((await page.request.post("/api/account/2fa/enable", { data: { code: totp(setup.secret) } })).ok()).toBeTruthy();
    await page.reload();
    await signOut(page);

    await page.locator(".auth-sso", { hasText: "Sign in with Microsoft" }).click();
    await atProvider(page, sub, "");
    await expect(page.locator(".auth-card")).toContainText("One more step: your second factor.");
    expect((await page.request.get("/api/me")).status()).toBe(401);
    await page.getByPlaceholder("123456").fill("000000");
    await page.locator(".auth-card button.primary", { hasText: "Sign in" }).click();
    await expect(page.locator(".error-text")).toHaveText("invalid two-factor code");
    await page.getByPlaceholder("123456").fill(totp(setup.secret, 1));
    await page.locator(".auth-card button.primary", { hasText: "Sign in" }).click();
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
  });
});
