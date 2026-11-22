package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Cloudflare Turnstile on the public forms (sign-in, creating an
// organization, accepting an invitation). Off unless TURNSTILE_ENABLE is
// set; then every one of those requests must carry a token from the widget,
// which is verified with Cloudflare before anything else is looked at: no
// password is checked for a request that did not pass.
//
// Signing in with a second factor takes two requests. The token of the
// widget can be used once, so the answer that asks for the second factor
// carries a pass (issued only after the password was accepted, bound to the
// account, valid for a few minutes) that the next request presents instead.
type turnstile struct {
	siteKey   string
	secret    string
	verifyURL string
	client    *http.Client

	mu     sync.Mutex
	passes map[string]captchaPass
	now    func() time.Time
}

type captchaPass struct {
	email   string
	expires time.Time
}

const (
	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	// The origin the widget's script and frame are loaded from (see appCSP).
	turnstileOrigin = "https://challenges.cloudflare.com"
	captchaPassTTL  = 5 * time.Minute
)

// errCaptchaUnavailable: Cloudflare could not be asked. The request is
// refused (a check that cannot be made is not a check that passed).
var errCaptchaUnavailable = errors.New("verification service unavailable")

// turnstileFromEnv returns nil when the check is off. Turning it on without
// both keys is a configuration error: starting without the protection the
// operator asked for would be worse than not starting.
func turnstileFromEnv() *turnstile {
	if !parseBoolEnv(os.Getenv("TURNSTILE_ENABLE")) {
		return nil
	}
	site, secret := strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY")), strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY"))
	if site == "" || secret == "" {
		log.Fatal("TURNSTILE_ENABLE is on, but TURNSTILE_SITE_KEY or TURNSTILE_SECRET_KEY is empty")
	}
	return newTurnstile(site, secret)
}

func newTurnstile(siteKey, secret string) *turnstile {
	return &turnstile{siteKey: siteKey, secret: secret, verifyURL: turnstileVerifyURL,
		client: &http.Client{Timeout: 8 * time.Second}, passes: map[string]captchaPass{}, now: time.Now}
}

// verify asks Cloudflare whether token is a solved challenge for this site.
// It returns nil, errCaptchaUnavailable, or an error naming Cloudflare's
// reason for refusing the token.
func (t *turnstile) verify(ctx context.Context, token, ip string) error {
	form := url.Values{"secret": {t.secret}, "response": {token}}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errCaptchaUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := t.client.Do(req)
	if err != nil {
		return errCaptchaUnavailable
	}
	defer res.Body.Close()
	var out struct {
		Success bool     `json:"success"`
		Codes   []string `json:"error-codes"`
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil || json.Unmarshal(body, &out) != nil {
		return errCaptchaUnavailable
	}
	if out.Success {
		return nil
	}
	for _, c := range out.Codes {
		// Our own request was wrong or Cloudflare failed: not the visitor's doing.
		if c == "internal-error" || c == "missing-input-secret" || c == "invalid-input-secret" || c == "bad-request" {
			log.Printf("turnstile: verification failed on our side: %s", strings.Join(out.Codes, ", "))
			return errCaptchaUnavailable
		}
	}
	if len(out.Codes) == 0 {
		return errors.New("not accepted")
	}
	return errors.New(strings.Join(out.Codes, ", "))
}

// issue returns a pass for email, valid for captchaPassTTL.
func (t *turnstile) issue(email string) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	p := hex.EncodeToString(b)
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.passes {
		if now.After(v.expires) {
			delete(t.passes, k)
		}
	}
	t.passes[p] = captchaPass{email: email, expires: now.Add(captchaPassTTL)}
	return p
}

// passValid reports whether pass was issued for email and has not expired.
func (t *turnstile) passValid(pass, email string) bool {
	if pass == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.passes[pass]
	return ok && v.email == email && !t.now().After(v.expires)
}

// checkCaptcha lets a public request through when the check is off, when it
// presents a valid pass, or when its widget token verifies. Otherwise it
// writes the refusal and returns false. email is what the request claims
// (for the audit log); it is not trusted for anything else.
func (a *App) checkCaptcha(w http.ResponseWriter, r *http.Request, token, pass, email string) bool {
	if a.captcha == nil || a.captcha.passValid(pass, email) {
		return true
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 4096 {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "complete the verification first", "captcha_failed": true})
		return false
	}
	ip := clientIP(r)
	err := a.captcha.verify(r.Context(), token, ip)
	switch {
	case err == nil:
		return true
	case errors.Is(err, errCaptchaUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "the verification service could not be reached; try again in a moment", "captcha_failed": true})
	default:
		a.auditSystem(r.Context(), email, ip, "auth.captcha_failed", err.Error())
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "the verification was not accepted; try again", "captcha_failed": true})
	}
	return false
}
