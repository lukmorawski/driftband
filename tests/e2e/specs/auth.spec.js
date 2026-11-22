// Accounts through the UI: registration, sign-in, sign-out, errors,
// two-factor authentication, lockout.
const { test, expect } = require("@playwright/test");
const { account, registerViaUi, loginViaUi, signOut, totp, field, loginViaApi } = require("../helpers");

test.describe("authentication @e2e", () => {
  test("create an organization, sign out, sign in again", async ({ page }) => {
    const acc = account("signup");
    await registerViaUi(page, acc);
    await expect(page.locator(".nav-links a", { hasText: "Dashboard" })).toHaveClass(/active/);
    await expect(page.locator(".tree-empty")).toContainText("No hosts yet");
    await signOut(page);
    await loginViaUi(page, acc);
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
    // the session survives a reload
    await page.reload();
    await expect(page.locator(".nav-user")).toHaveText(acc.email);
  });

  test("registration rejects weak input", async ({ page }) => {
    await page.goto("/");
    await page.locator(".auth-tabs button", { hasText: "Create organization" }).click();
    await page.getByPlaceholder("Acme Inc.").fill("Weak");
    await page.getByPlaceholder("you@example.com").fill("not-an-email");
    await page.getByPlaceholder("At least 8 characters").fill("short");
    await page.locator(".auth-card button.primary", { hasText: "Create organization" }).click();
    await expect(page.locator(".error-text")).toContainText("8+ char password");
    await expect(page.locator(".auth-tabs")).toBeVisible();
  });

  test("a wrong password shows one generic error", async ({ page }) => {
    const acc = account("wrongpw");
    await registerViaUi(page, acc);
    await signOut(page);
    await loginViaUi(page, { ...acc, password: acc.password + "x" });
    await expect(page.locator(".error-text")).toHaveText("invalid email or password");
    await loginViaUi(page, { ...acc, email: "unknown-" + acc.email });
    await expect(page.locator(".error-text")).toHaveText("invalid email or password");
  });

  test("two-factor: enrol, sign in with a code, refuse a wrong one, disable", async ({ page }) => {
    const acc = account("tfa");
    await registerViaUi(page, acc);
    await page.goto("/#/settings?tab=account");
    const card = page.locator(".card").filter({ has: page.locator("h2", { hasText: "Two-factor authentication" }) });
    const state = card.locator(".spread > .badge");
    await expect(state).toHaveText("off");
    await card.locator("button", { hasText: "Set up two-factor" }).click();
    const modal = page.locator(".modal");
    // the password is asked for first
    await field(modal, "Confirm with password").fill("wrong-" + acc.password);
    await modal.locator("button", { hasText: "Continue" }).click();
    await expect(modal.locator(".error-text")).toHaveText("password is incorrect");
    await field(modal, "Confirm with password").fill(acc.password);
    await modal.locator("button", { hasText: "Continue" }).click();
    await expect(modal.locator("img[alt='TOTP enrollment QR code']")).toBeVisible();
    const secret = await field(modal, "Secret (manual entry)").inputValue();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    await field(modal, "Code from device").fill("000000");
    await modal.locator("button", { hasText: "Verify & enable" }).click();
    await expect(modal.locator(".error-text")).not.toBeEmpty();
    await field(modal, "Code from device").fill(totp(secret));
    await modal.locator("button", { hasText: "Verify & enable" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Two-factor enabled" }).last()).toBeVisible();
    await expect(state).toHaveText("enabled");

    await signOut(page);
    // password alone: the code field appears; wrong code refused; right code works
    await loginViaUi(page, acc, "123456");
    await expect(page.locator(".error-text")).not.toBeEmpty();
    await expect(page.locator(".auth-tabs")).toBeVisible();
    // an account with a code only is not offered a security key
    await expect(page.locator("button.auth-key")).toBeHidden();
    // the code used for enrolment cannot be replayed: take the next step
    // (accepted within the drift window)
    await page.getByPlaceholder("123456").fill(totp(secret, 1));
    await page.locator(".auth-card button.primary", { hasText: "Sign in" }).click();
    await expect(page.locator(".nav-user")).toHaveText(acc.email);

    await page.goto("/#/settings?tab=account");
    await card.locator("button", { hasText: "Turn off" }).click();
    await field(modal, "Confirm with password").fill(acc.password);
    await modal.locator("button", { hasText: "Disable two-factor" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Two-factor disabled" }).last()).toBeVisible();
    await expect(state).toHaveText("off");
  });

  test("ten wrong passwords lock the account and the UI says so", async ({ page }) => {
    const acc = account("lockout");
    await registerViaUi(page, acc);
    await signOut(page);
    for (let i = 0; i < 10; i++) {
      const r = await page.request.post("/api/auth/login", { data: { email: acc.email, password: "Guess-" + i, code: "" } });
      expect(r.status()).toBe(401);
    }
    await loginViaUi(page, acc);
    await expect(page.locator(".error-text")).toContainText("too many failed attempts");
    await expect(page.locator(".auth-tabs")).toBeVisible();
  });

  test("account settings: name, email and password changes", async ({ page }) => {
    const acc = account("account");
    await registerViaUi(page, acc);
    await page.goto("/#/settings?tab=account");
    const profile = page.locator(".card").filter({ has: page.locator("h2", { hasText: /^Profile$/ }) });
    await page.getByPlaceholder("First name").fill("Ada");
    await page.getByPlaceholder("Last name").fill("Lovelace");
    await profile.locator("button", { hasText: "Save" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Profile saved" }).last()).toBeVisible();

    const pw = page.locator(".card").filter({ has: page.locator("h2", { hasText: /^Password$/ }) });
    const newPw = acc.password + "-new";
    await pw.getByPlaceholder("Current password").fill(acc.password);
    await page.getByPlaceholder("New password (8+ chars)").fill(newPw);
    await page.getByPlaceholder("Repeat new password").fill(newPw + "typo");
    await pw.locator("button", { hasText: "Change password" }).click();
    await expect(pw.locator(".error-text")).toContainText("do not match");
    await page.getByPlaceholder("Repeat new password").fill(newPw);
    await pw.locator("button", { hasText: "Change password" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Password changed" }).last()).toBeVisible();

    const email = page.locator(".card").filter({ has: page.locator("h2", { hasText: /^Email$/ }) });
    const newEmail = "renamed-" + acc.email;
    await field(email, "Email").fill(newEmail);
    await field(email, "Confirm with password").fill(newPw);
    await email.locator("button", { hasText: "Update email" }).click();
    await expect(page.locator(".toast.ok", { hasText: "Email updated" }).last()).toBeVisible();

    await signOut(page);
    await loginViaUi(page, { email: newEmail, password: newPw });
    await expect(page.locator(".nav-user")).toHaveText(newEmail);
    await page.goto("/#/settings?tab=team");
    await expect(page.locator("table.tbl tbody tr").first()).toContainText("Ada Lovelace");
  });

  test("a signed-in user is sent to the dashboard; unknown routes fall back to it", async ({ page }) => {
    const acc = account("routes");
    await loginViaApi(page, acc).catch(() => {});
    await page.request.post("/api/auth/register-org", { data: { org_name: acc.org, email: acc.email, password: acc.password } });
    await page.goto("/#/nowhere");
    await expect(page.locator(".tree-head h2")).toContainText("Hosts");
    await page.goto("/#/faq");
    await expect(page.locator(".nav-links a", { hasText: "FAQ" })).toHaveClass(/active/);
    await expect(page.locator("main")).toContainText("smoke");
    // how to set up each kind of notification channel
    const guide = page.locator(".card").filter({ has: page.locator("h2", { hasText: "Setting up notification channels" }) });
    await expect(guide.locator(".howto h3")).toHaveText(["Telegram", "Slack", "Microsoft Teams", "Email with a username and password", "Email through Microsoft 365 with OAuth 2.0"]);
    await expect(guide).toContainText("@BotFather");
    await expect(guide).toContainText("SMTP.SendAsApp");
  });
});
