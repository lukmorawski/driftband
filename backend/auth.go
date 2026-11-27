package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

// ----- password hashing (Argon2id) -----

const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

func hashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var mem uint32
	var t, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, mem, uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when the email is unknown, so failed logins
// take the same time whether or not the account exists.
var dummyHash, _ = hashPassword("driftband-timing-equaliser")

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ----- validation -----

func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\n")
}

func validPassword(s string) bool { return len(s) >= 8 && len(s) <= 200 }

// ----- session creation -----

func (a *App) createSession(ctx context.Context, w http.ResponseWriter, r *http.Request, userID int64) error {
	token := randomToken()
	expires := time.Now().Add(30 * 24 * time.Hour)
	_, err := a.db.Exec(ctx,
		`INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2,$3)`,
		token, userID, expires)
	if err != nil {
		return err
	}
	_, _ = a.db.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID)
	setSessionCookie(w, token, expires, a.isHTTPS(r))
	return nil
}

// ----- handlers -----

func (a *App) handleRegisterOrg(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OrgName        string `json:"org_name"`
		Email          string `json:"email"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstile_token"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.OrgName = strings.TrimSpace(in.OrgName)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	// A platform administrator can close the instance to new organizations;
	// people then join only through invitations.
	if !a.registrationOpen(r.Context()) {
		a.auditSystem(r.Context(), in.Email, clientIP(r), "denied.org.create", "creating organizations is turned off")
		writeErr(w, http.StatusForbidden, "creating organizations is turned off on this instance")
		return
	}
	if !a.checkCaptcha(w, r, in.TurnstileToken, "", in.Email) {
		return
	}
	if in.OrgName == "" || !validEmail(in.Email) || !validPassword(in.Password) {
		writeErr(w, http.StatusBadRequest, "organization name, valid email and 8+ char password required")
		return
	}
	ph, err := hashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash failed")
		return
	}

	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	var orgID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO organizations (name) VALUES ($1) RETURNING id`, in.OrgName).Scan(&orgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create organization")
		return
	}
	var userID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO users (org_id, email, password_hash, role) VALUES ($1,$2,$3,'owner') RETURNING id`,
		orgID, in.Email, ph).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "email already in use")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not create user")
		return
	}
	for _, p := range defaultProfiles {
		// On a test instance, presets outside its limits are left out.
		if validateProfile(profile{Name: p.Name, IntervalS: p.IntervalS, PingCount: p.PingCount, PacketSize: p.PacketSize}, a.testMode) != nil {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO probe_profiles (org_id, name, interval_s, ping_count, packet_size, is_default)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			orgID, p.Name, p.IntervalS, p.PingCount, p.PacketSize, p.Default); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not seed profiles")
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "commit failed")
		return
	}

	a.auditAnon(ctx, orgID, in.Email, clientIP(r), "org.create", "organization "+in.OrgName)
	if err := a.createSession(ctx, w, r, userID); err != nil {
		writeErr(w, http.StatusInternalServerError, "session failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		secondFactorInput
		// Turnstile (when enabled): the widget's token, or on the request
		// that brings the second factor the pass issued with the first answer.
		TurnstileToken string `json:"turnstile_token"`
		CaptchaPass    string `json:"captcha_pass"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))

	ctx := r.Context()
	ip := clientIP(r)
	ipKey, acctKey := "login-ip:"+ip, "login-email:"+in.Email
	if a.limiter.blocked(ipKey, maxFailsPerIP) || a.limiter.blocked(acctKey, maxFailsPerAccount) {
		log.Printf("auth: login rate-limited for %q from %s", in.Email, ip)
		var orgID int64
		if a.db.QueryRow(ctx, `SELECT org_id FROM users WHERE email = $1`, in.Email).Scan(&orgID) == nil {
			a.auditAnon(ctx, orgID, in.Email, ip, "auth.login_blocked", "too many failed attempts")
		}
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	// No password is checked for a request that did not pass the challenge.
	if !a.checkCaptcha(w, r, in.TurnstileToken, in.CaptchaPass, in.Email) {
		return
	}

	acct := account{email: in.Email}
	var ph string
	var blocked bool
	err := a.db.QueryRow(ctx,
		`SELECT u.id, u.org_id, u.password_hash, u.totp_enabled, u.totp_secret, u.totp_last_step,
		        u.disabled OR o.disabled
		 FROM users u JOIN organizations o ON o.id = u.org_id WHERE u.email = $1`, in.Email).
		Scan(&acct.userID, &acct.orgID, &ph, &acct.totpEnabled, &acct.totpSecret, &acct.totpLastStep, &blocked)
	if err != nil {
		// Unknown email: still pay for one hash so response time does not
		// reveal which emails have accounts. No org to file it under, so it
		// goes to the server log only.
		verifyPassword(in.Password, dummyHash)
		a.limiter.fail(ipKey, acctKey)
		a.auditSystem(ctx, in.Email, ip, "auth.login_failed", "unknown email")
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	userID, orgID := acct.userID, acct.orgID
	if !verifyPassword(in.Password, ph) {
		a.limiter.fail(ipKey, acctKey)
		a.auditAnon(ctx, orgID, in.Email, ip, "auth.login_failed", "wrong password")
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	// Checked only after the password, so guessers learn nothing about it.
	if blocked {
		a.auditAnon(ctx, orgID, in.Email, ip, "auth.login_disabled", "account or organization is blocked")
		writeErr(w, http.StatusForbidden, "this account is blocked; contact the administrator")
		return
	}
	used, ok := a.secondFactor(w, r, acct, in.secondFactorInput, func(out map[string]any) {
		if a.captcha != nil {
			// The password was right: the request with the second factor
			// presents this instead of solving the challenge again.
			if a.captcha.passValid(in.CaptchaPass, in.Email) {
				out["captcha_pass"] = in.CaptchaPass
			} else {
				out["captcha_pass"] = a.captcha.issue(in.Email)
			}
		}
	})
	if !ok {
		return
	}
	if err := a.createSession(ctx, w, r, userID); err != nil {
		writeErr(w, http.StatusInternalServerError, "session failed")
		return
	}
	a.limiter.clear(acctKey)
	detail := ""
	if used != "" {
		detail = "with two-factor (" + used + ")"
	}
	a.auditAnon(ctx, orgID, in.Email, ip, "auth.login", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// account is what a sign-in needs to know about a user once the first
// factor (the password, or single sign-on) was accepted.
type account struct {
	userID, orgID int64
	email         string
	totpEnabled   bool
	totpSecret    *string
	totpLastStep  int64
}

// secondFactorInput is the part of a sign-in request that answers the
// second factor.
type secondFactorInput struct {
	Code string `json:"code"` // TOTP code, when that is the second factor used
	// Answer of a security key or passkey to the challenge issued after
	// the first factor was accepted (see webauthn.go).
	WebauthnToken string          `json:"webauthn_token"`
	Credential    json.RawMessage `json:"credential"`
}

// secondFactor checks the account's second factor: a TOTP code, or a
// security key / passkey. An account without one passes. With none supplied
// the answer lists what the account accepts (and a fresh challenge for its
// keys); the frontend then retries with one of them. It returns what was
// used; when ok is false the response has been written. decorate may add
// to the answer that asks for the factor.
func (a *App) secondFactor(w http.ResponseWriter, r *http.Request, acct account, in secondFactorInput, decorate func(map[string]any)) (used string, ok bool) {
	ctx := r.Context()
	ip := clientIP(r)
	ipKey, acctKey := "login-ip:"+ip, "login-email:"+acct.email
	wu, err := a.webauthnUser(ctx, acct.userID, acct.email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return "", false
	}
	hasTotp := acct.totpEnabled && acct.totpSecret != nil
	if !hasTotp && len(wu.creds) == 0 && wu.broken == 0 {
		return "", true
	}
	need := func(msg string) {
		out := map[string]any{"error": msg, "two_factor_required": true, "totp_required": hasTotp}
		methods := []string{}
		if hasTotp {
			methods = append(methods, "totp")
		}
		if len(wu.creds) > 0 {
			if opts, err := a.webauthnLoginOptions(r, wu); err == nil {
				methods = append(methods, "webauthn")
				out["webauthn"] = opts
			} else if !hasTotp {
				out["error"] = err.Error()
			}
		}
		if len(methods) == 0 && wu.broken > 0 {
			// The account is protected by keys this server can no longer
			// read. The first factor alone must not be enough: an
			// administrator resets the two-factor instead.
			out["error"] = "your security keys cannot be used on this server; ask an administrator to reset your two-factor authentication"
		}
		out["methods"] = methods
		if decorate != nil {
			decorate(out)
		}
		writeJSON(w, http.StatusUnauthorized, out)
	}
	code := strings.TrimSpace(in.Code)
	switch {
	case len(in.Credential) > 0 && len(wu.creds) > 0:
		c, err := a.webauthnLogin(r, wu, in.WebauthnToken, in.Credential)
		if err != nil {
			a.limiter.fail(ipKey, acctKey)
			a.auditAnon(ctx, acct.orgID, acct.email, ip, "auth.login_failed", "security key or passkey not accepted: "+err.Error())
			need("the security key or passkey was not accepted")
			return "", false
		}
		return kindLabel(c.Kind), true
	case code != "" && hasTotp:
		// A stored secret that does not open accepts no code at all.
		var step int64
		valid := false
		if secret, err := a.openTotp(acct.userID, *acct.totpSecret); err == nil {
			step, valid = verifyTotp(secret, code, acct.totpLastStep)
		}
		if !valid {
			a.limiter.fail(ipKey, acctKey)
			a.auditAnon(ctx, acct.orgID, acct.email, ip, "auth.login_failed", "wrong two-factor code")
			need("invalid two-factor code")
			return "", false
		}
		_, _ = a.db.Exec(ctx, `UPDATE users SET totp_last_step = $1 WHERE id = $2`, step, acct.userID)
		return "TOTP code", true
	}
	// The first factor was correct; the frontend asks for the second.
	need("two-factor authentication required")
	return "", false
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_, _ = a.db.Exec(r.Context(), `DELETE FROM sessions WHERE token = $1`, c.Value)
	}
	a.audit(r.Context(), userFrom(r), clientIP(r), "auth.logout", "")
	clearSessionCookie(w, a.isHTTPS(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var orgName string
	var retention int
	_ = a.db.QueryRow(r.Context(),
		`SELECT name, retention_years FROM organizations WHERE id = $1`, u.OrgID).
		Scan(&orgName, &retention)
	var firstName, lastName, avatar string
	var totpEnabled bool
	var kinds []string
	_ = a.db.QueryRow(r.Context(), `
		SELECT u.first_name, u.last_name, u.totp_enabled,
		       COALESCE((SELECT array_agg(DISTINCT c.kind) FROM webauthn_credentials c WHERE c.user_id = u.id), '{}'),
		       COALESCE((SELECT av.etag FROM user_avatars av WHERE av.user_id = u.id), '')
		FROM users u WHERE u.id = $1`, u.ID).
		Scan(&firstName, &lastName, &totpEnabled, &kinds, &avatar)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "email": u.Email, "role": u.Role, "is_superadmin": u.Superadmin, "version": version,
		"first_name": firstName, "last_name": lastName, "totp_enabled": totpEnabled,
		"two_factor": twoFactorList(totpEnabled, kinds), "avatar": avatar,
		"org":    map[string]any{"id": u.OrgID, "name": orgName, "retention_years": retention},
		"limits": a.instanceInfo(r.Context(), u.OrgID),
	})
}

func (a *App) handleAcceptInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token          string `json:"token"`
		Email          string `json:"email"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstile_token"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !a.checkCaptcha(w, r, in.TurnstileToken, "", in.Email) {
		return
	}
	if !validEmail(in.Email) || !validPassword(in.Password) {
		writeErr(w, http.StatusBadRequest, "valid email and 8+ char password required")
		return
	}

	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	var orgID int64
	var role string
	err = tx.QueryRow(ctx, `
		SELECT org_id, role FROM invites
		WHERE token = $1 AND used_at IS NULL AND expires_at > now()
		FOR UPDATE`, in.Token).Scan(&orgID, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		log.Printf("auth: rejected invite token from %s", clientIP(r))
		writeErr(w, http.StatusGone, "invite invalid, used, or expired")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}

	ph, err := hashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash failed")
		return
	}
	var userID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO users (org_id, email, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING id`,
		orgID, in.Email, ph, role).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "email already in use")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not create user")
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE invites SET used_at = now() WHERE token = $1`, in.Token); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "commit failed")
		return
	}

	a.auditAnon(ctx, orgID, in.Email, clientIP(r), "user.join", "accepted invite, role="+role)
	if err := a.createSession(ctx, w, r, userID); err != nil {
		writeErr(w, http.StatusInternalServerError, "session failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// inviteInfo lets the accept page show which org/role an invite is for.
func (a *App) handleInviteInfo(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	var orgName, role string
	err := a.db.QueryRow(r.Context(), `
		SELECT o.name, i.role FROM invites i JOIN organizations o ON o.id = i.org_id
		WHERE i.token = $1 AND i.used_at IS NULL AND i.expires_at > now()`, token).
		Scan(&orgName, &role)
	if err != nil {
		writeErr(w, http.StatusGone, "invite invalid, used, or expired")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": orgName, "role": role})
}
