package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// systemAuditHas reports whether the system log (no organization) has the
// action for email since t0.
func systemAuditHas(t *testing.T, email, action string, since time.Time) bool {
	t.Helper()
	var n int
	_ = testDB.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log
		WHERE org_id IS NULL AND action = $1 AND user_email = $2 AND created_at >= $3`,
		action, email, since).Scan(&n)
	return n > 0
}

// A platform administrator can close the instance to new organizations.
// People then join only through invitations; everything else keeps working.
func TestRegistrationCanBeClosed(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("closed")
	sa := e.superadmin()
	t.Cleanup(func() {
		_, _ = testDB.Exec(context.Background(), `DELETE FROM app_settings WHERE key = $1`, settingRegistration)
	})

	if r := e.must(e.req(anon, "GET", "/api/auth/config", nil), 200, "config"); r.JSON["registration_open"] != true || r.JSON["turnstile_site_key"] != "" {
		t.Fatalf("default config: %s", r.Body)
	}
	if r := e.req(sa, "PATCH", "/api/admin/settings", map[string]any{}); r.Status != 400 {
		t.Errorf("settings without a value: %d", r.Status)
	}
	if r := e.req(sa, "PATCH", "/api/admin/settings", map[string]any{"registration_open": false, "is_superadmin": true}); r.Status != 400 {
		t.Errorf("unknown field accepted: %d", r.Status)
	}
	t0 := dbNow(t)
	e.must(e.req(sa, "PATCH", "/api/admin/settings", map[string]any{"registration_open": false}), 200, "close")
	if !systemAuditHas(t, sa.Email, "admin.settings_change", t0) {
		t.Error("closing registration is not in the system log")
	}
	if r := e.must(e.req(sa, "GET", "/api/admin/settings", nil), 200, "settings"); r.JSON["registration_open"] != false {
		t.Errorf("settings after closing: %s", r.Body)
	}
	if r := e.must(e.req(anon, "GET", "/api/auth/config", nil), 200, "config"); r.JSON["registration_open"] != false {
		t.Errorf("the sign-in page is not told: %s", r.Body)
	}

	// No organization and no account come out of a refused registration.
	email := uniqueEmail("refused")
	var orgs int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM organizations`).Scan(&orgs)
	r := e.req(anon, "POST", "/api/auth/register-org", map[string]any{"org_name": "Refused", "email": email, "password": "Refused-pass-123"})
	if r.Status != 403 || r.cookie(sessionCookie) != nil {
		t.Fatalf("registration while closed: %d %s", r.Status, r.Body)
	}
	var after, users int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM organizations`).Scan(&after)
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email = $1`, email).Scan(&users)
	if after != orgs || users != 0 {
		t.Errorf("a refused registration left data behind: organizations %d -> %d, users %d", orgs, after, users)
	}
	if !systemAuditHas(t, email, "denied.org.create", t0) {
		t.Error("the refused registration is not audited")
	}

	// Existing accounts sign in and invitations still bring people in.
	e.must(e.login(o.Owner.Email, o.Owner.Password, ""), 200, "sign-in while closed")
	if joined := e.invite(o.Owner, "member", "closed-join"); joined.OrgID != o.Owner.OrgID {
		t.Error("an invitation did not work while registration is closed")
	}

	// Tenants cannot change the setting, whatever their role.
	for _, a := range []*actor{o.Owner, o.Admin, o.Member, anon} {
		if r := e.req(a, "PATCH", "/api/admin/settings", map[string]any{"registration_open": true}); r.Status != 403 && r.Status != 401 {
			t.Errorf("%s changed an instance setting: %d", a.Role, r.Status)
		}
	}
	if r := e.must(e.req(anon, "GET", "/api/auth/config", nil), 200, "config"); r.JSON["registration_open"] != false {
		t.Error("the setting changed without a platform administrator")
	}

	e.must(e.req(sa, "PATCH", "/api/admin/settings", map[string]any{"registration_open": true}), 200, "reopen")
	e.registerOrg("reopened")
}

// The health endpoint answers without a session, says only whether the
// application can serve, and turns 503 when the database is gone.
func TestHealth(t *testing.T) {
	e := newEnv(t)
	r := e.must(e.req(anon, "GET", "/api/health", nil), 200, "health")
	if r.JSON["status"] != "ok" || r.JSON["database"] != "ok" || len(r.JSON) != 2 {
		t.Errorf("health body: %s", r.Body)
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("health may be cached: %q", r.Header.Get("Cache-Control"))
	}
	if r := e.req(anon, "POST", "/api/health", nil); r.Status == 200 {
		t.Error("health answers POST")
	}

	// A pool that cannot reach its database (it is closed).
	pool, err := pgxpool.New(context.Background(), testDB.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	rec := httptest.NewRecorder()
	(&App{db: pool}).handleHealth(rec, httptest.NewRequest("GET", "/api/health", nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 503 || body["status"] != "unavailable" {
		t.Errorf("health without a database: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "postgres") || strings.Contains(rec.Body.String(), "closed pool") {
		t.Errorf("health leaks the database error: %s", rec.Body)
	}
}

// fakeTurnstile stands in for Cloudflare's siteverify: tokens starting with
// "good" are accepted once (a second use is a duplicate, as with the real
// service), "down" breaks the service, anything else is refused.
type fakeTurnstile struct {
	*httptest.Server
	mu    sync.Mutex
	used  map[string]bool
	calls []map[string]string
}

func newFakeTurnstile(t *testing.T, secret string) *fakeTurnstile {
	f := &fakeTurnstile{used: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		token := r.PostForm.Get("response")
		f.mu.Lock()
		f.calls = append(f.calls, map[string]string{"response": token, "secret": r.PostForm.Get("secret"), "remoteip": r.PostForm.Get("remoteip")})
		dup := f.used[token]
		f.used[token] = true
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case token == "down":
			http.Error(w, "upstream error", http.StatusBadGateway)
		case r.PostForm.Get("secret") != secret:
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-secret"]}`))
		case dup:
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["timeout-or-duplicate"]}`))
		case strings.HasPrefix(token, "good"):
			_, _ = w.Write([]byte(`{"success":true,"error-codes":[]}`))
		default:
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeTurnstile) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// With Turnstile on, the public forms need a solved challenge before
// anything else is looked at.
func TestTurnstile(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("captcha") // created before the check is switched on
	invite := func() string {
		return e.must(e.req(o.Owner, "POST", "/api/invites", map[string]any{"role": "member"}), 200, "invite").JSON["token"].(string)
	}
	plainCSP := e.req(anon, "GET", "/", nil).Header.Get("Content-Security-Policy")
	if strings.Contains(plainCSP, "cloudflare") {
		t.Errorf("without Turnstile the policy must not name Cloudflare: %s", plainCSP)
	}

	fake := newFakeTurnstile(t, "test-secret")
	ts := newTurnstile("test-site-key", "test-secret")
	ts.verifyURL = fake.URL
	e.app.captcha = ts
	t.Cleanup(func() { e.app.captcha = nil })

	// The sign-in page learns the site key (never the secret) and the
	// policy lets Cloudflare's script and frame in, nothing more.
	cfg := e.must(e.req(anon, "GET", "/api/auth/config", nil), 200, "config")
	if cfg.JSON["turnstile_site_key"] != "test-site-key" || strings.Contains(string(cfg.Body), "test-secret") {
		t.Errorf("config: %s", cfg.Body)
	}
	csp := e.req(anon, "GET", "/", nil).Header.Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self' https://challenges.cloudflare.com;", "frame-src https://challenges.cloudflare.com;", "style-src 'self';", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy with Turnstile lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe") {
		t.Errorf("policy with Turnstile is weaker than needed: %s", csp)
	}
	if site := e.req(anon, "GET", "/main/", nil).Header.Get("Content-Security-Policy"); strings.Contains(site, "cloudflare") {
		t.Errorf("the website's policy changed: %s", site)
	}

	login := func(email, password string, extra map[string]any) *resp {
		body := map[string]any{"email": email, "password": password}
		for k, v := range extra {
			body[k] = v
		}
		return e.req(anon, "POST", "/api/auth/login", body, "X-Forwarded-For: 203.0.113.50")
	}

	// Without a token nothing is checked: not Cloudflare, and above all not
	// the password (the answer does not depend on it, no failure is counted).
	t0 := dbNow(t)
	for _, pw := range []string{o.Owner.Password, "Wrong-pass-123"} {
		if r := login(o.Owner.Email, pw, nil); r.Status != 403 || r.JSON["captcha_failed"] != true || r.cookie(sessionCookie) != nil {
			t.Fatalf("sign-in without a token: %d %s", r.Status, r.Body)
		}
	}
	if fake.count() != 0 {
		t.Error("Cloudflare was asked about a request without a token")
	}
	if auditHas(t, o.Owner.OrgID, o.Owner.Email, "auth.login_failed", t0) {
		t.Error("the password was checked although the challenge was not passed")
	}

	// A token Cloudflare refuses: no sign-in, recorded in the system log.
	if r := login(o.Owner.Email, o.Owner.Password, map[string]any{"turnstile_token": "forged"}); r.Status != 403 || r.cookie(sessionCookie) != nil {
		t.Fatalf("refused token: %d %s", r.Status, r.Body)
	}
	if !systemAuditHas(t, o.Owner.Email, "auth.captcha_failed", t0) {
		t.Error("a refused token is not audited")
	}
	// Cloudflare unreachable: refused as well, with a different answer.
	if r := login(o.Owner.Email, o.Owner.Password, map[string]any{"turnstile_token": "down"}); r.Status != 503 || r.cookie(sessionCookie) != nil {
		t.Fatalf("verification service down: %d %s", r.Status, r.Body)
	}

	// A good token signs in; Cloudflare got our secret and the client address.
	e.must(login(o.Owner.Email, o.Owner.Password, map[string]any{"turnstile_token": "good-1"}), 200, "sign-in with a token")
	fake.mu.Lock()
	last := fake.calls[len(fake.calls)-1]
	fake.mu.Unlock()
	if last["secret"] != "test-secret" || last["remoteip"] != "203.0.113.50" {
		t.Errorf("verification request: %v", last)
	}
	// A token works once.
	if r := login(o.Owner.Email, o.Owner.Password, map[string]any{"turnstile_token": "good-1"}); r.Status != 403 {
		t.Errorf("a token was accepted twice: %d", r.Status)
	}
	// With a good token a wrong password is an ordinary failed sign-in.
	if r := login(o.Owner.Email, "Wrong-pass-123", map[string]any{"turnstile_token": "good-2"}); r.Status != 401 {
		t.Errorf("wrong password with a good token: %d", r.Status)
	}

	// Creating an organization and accepting an invitation need it too.
	reg := map[string]any{"org_name": "Captcha org", "email": uniqueEmail("cap-reg"), "password": "Register-pass-123"}
	if r := e.req(anon, "POST", "/api/auth/register-org", reg); r.Status != 403 {
		t.Errorf("registration without a token: %d", r.Status)
	}
	reg["turnstile_token"] = "good-3"
	e.must(e.req(anon, "POST", "/api/auth/register-org", reg), 200, "registration with a token")
	join := map[string]any{"token": invite(), "email": uniqueEmail("cap-join"), "password": "Joiner-pass-1234"}
	if r := e.req(anon, "POST", "/api/auth/accept-invite", join); r.Status != 403 {
		t.Errorf("invitation without a token: %d", r.Status)
	}
	join["turnstile_token"] = "good-4"
	e.must(e.req(anon, "POST", "/api/auth/accept-invite", join), 200, "invitation with a token")

	// Two-factor sign-in: the first answer carries a pass for the second
	// request, so the challenge is not solved twice.
	a := o.Member
	secret := e.must(e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": a.Password}), 200, "setup").JSON["secret"].(string)
	e.must(e.req(a, "POST", "/api/account/2fa/enable", map[string]any{"code": currentTotp(t, secret, 0)}), 200, "enable")
	if r := login(a.Email, "Wrong-pass-123", map[string]any{"turnstile_token": "good-5"}); r.Status != 401 || r.JSON["captcha_pass"] != nil {
		t.Fatalf("a pass was issued without the right password: %d %s", r.Status, r.Body)
	}
	r := login(a.Email, a.Password, map[string]any{"turnstile_token": "good-6"})
	pass, _ := r.JSON["captcha_pass"].(string)
	if r.Status != 401 || r.JSON["two_factor_required"] != true || len(pass) < 32 {
		t.Fatalf("first step of a two-factor sign-in: %d %s", r.Status, r.Body)
	}
	// The pass belongs to this account only.
	if r := login(o.Owner.Email, o.Owner.Password, map[string]any{"captcha_pass": pass}); r.Status != 403 {
		t.Errorf("a pass was accepted for another account: %d", r.Status)
	}
	if r := login(a.Email, a.Password, map[string]any{"captcha_pass": "0123456789abcdef0123456789abcdef0123456789abcdef", "code": currentTotp(t, secret, 1)}); r.Status != 403 {
		t.Errorf("a made-up pass was accepted: %d", r.Status)
	}
	// A wrong code with the pass keeps the pass; the right code signs in.
	if r := login(a.Email, a.Password, map[string]any{"captcha_pass": pass, "code": "000000"}); r.Status != 401 || r.JSON["captcha_pass"] != pass {
		if currentTotp(t, secret, 1) != "000000" {
			t.Errorf("wrong code with a pass: %d %s", r.Status, r.Body)
		}
	}
	before := fake.count()
	e.must(login(a.Email, a.Password, map[string]any{"captcha_pass": pass, "code": currentTotp(t, secret, 1)}), 200, "second step with the pass")
	if fake.count() != before {
		t.Error("Cloudflare was asked although a pass was presented")
	}
	// A pass expires.
	r = login(a.Email, a.Password, map[string]any{"turnstile_token": "good-7"})
	pass, _ = r.JSON["captcha_pass"].(string)
	ts.now = func() time.Time { return time.Now().Add(captchaPassTTL + time.Minute) }
	if r := login(a.Email, a.Password, map[string]any{"captcha_pass": pass, "code": currentTotp(t, secret, 2)}); r.Status != 403 {
		t.Errorf("an expired pass was accepted: %d", r.Status)
	}
	ts.now = time.Now
}
