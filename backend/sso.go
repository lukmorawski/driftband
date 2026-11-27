package main

// Single sign-on with OpenID Connect: Google and Microsoft Entra ID.
//
// A provider is turned on in the environment (client ID and secret of an
// application registered with it). Signing in this way replaces the
// password only: an account's second factor is still asked for.
//
// An account and a provider identity are connected explicitly, by the
// signed-in user, who confirms with the password. Nothing is matched by
// email address: addresses are not verified here and not every provider
// verifies them, so a match by address would let whoever controls an
// address at a provider take over the account that uses it. A sign-in
// finds its account by the provider's issuer and subject alone.
//
// The flow is the authorization code flow with PKCE, state and nonce. The
// state is bound to the browser that started it by a cookie, the provider
// answers to the web application (APP_URL + ssoCallbackPath), and the
// application hands the code to the API, which redeems it and verifies the
// ID token: signature against the provider's published keys, issuer,
// audience, expiry and nonce, and the provider-specific claims (tenant,
// hosted domain).

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ssoCallbackPath = "/sso"
	ssoCookie       = "dband_sso"
	ssoFlowTTL      = 10 * time.Minute
	ssoMaxFlows     = 5000
	ssoMaxFlowsIP   = 20 // flows in progress per client address
	ssoMetaTTL      = 24 * time.Hour
	ssoKeysTTL      = 6 * time.Hour
	ssoKeysRefresh  = time.Minute // an unknown key ID refetches the keys at most this often
)

type ssoProvider struct {
	id           string // google | entra
	name         string // shown to people
	issuer       string
	clientID     string
	clientSecret string
	tenant       string // entra: the directory (tenant) ID
	domain       string // google: restrict to one Workspace domain ("" = any account)
	insecure     bool   // tests only: the provider may be reached over http
	client       *http.Client

	mu      sync.Mutex
	meta    *oidcMeta
	metaAt  time.Time
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time
	keysTry time.Time
}

// oidcMeta is the part of the provider's discovery document that is used.
type oidcMeta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// ssoIdentity is what a verified ID token says about who signed in. email
// is shown to the account's owner and in the audit log; it identifies nothing.
type ssoIdentity struct {
	issuer  string
	subject string
	email   string
}

// ssoFlow is one sign-in or connection in progress.
type ssoFlow struct {
	provider *ssoProvider
	binder   string // value of the cookie of the browser that started it
	nonce    string
	verifier string
	intent   string // login | link
	userID   int64  // link: the user who started it
	ip       string
	expires  time.Time
	mu       sync.Mutex // one request at a time continues a flow
	// Set once the provider's answer was verified: a sign-in that waits
	// for the second factor does not redeem the code again.
	identity *ssoIdentity
}

type sso struct {
	providers []*ssoProvider
	mu        sync.Mutex
	flows     map[string]*ssoFlow
	now       func() time.Time
}

var entraTenantRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ssoFromEnv returns nil when no provider is configured. A provider that is
// configured only in part is a configuration error: the application does
// not start with a sign-in method the operator asked for missing.
func ssoFromEnv(appURL string) *sso {
	env := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	s := &sso{flows: map[string]*ssoFlow{}, now: time.Now}
	if id := env("SSO_GOOGLE_CLIENT_ID"); id != "" {
		secret := env("SSO_GOOGLE_CLIENT_SECRET")
		if secret == "" {
			log.Fatal("SSO_GOOGLE_CLIENT_ID is set, but SSO_GOOGLE_CLIENT_SECRET is empty")
		}
		s.providers = append(s.providers, newGoogleProvider(id, secret, strings.ToLower(env("SSO_GOOGLE_DOMAIN"))))
	}
	if id := env("SSO_ENTRA_CLIENT_ID"); id != "" {
		secret, tenant := env("SSO_ENTRA_CLIENT_SECRET"), strings.ToLower(env("SSO_ENTRA_TENANT_ID"))
		if secret == "" {
			log.Fatal("SSO_ENTRA_CLIENT_ID is set, but SSO_ENTRA_CLIENT_SECRET is empty")
		}
		if !entraTenantRe.MatchString(tenant) {
			log.Fatal("SSO_ENTRA_TENANT_ID must be the directory (tenant) ID of your organization, a GUID")
		}
		authority := strings.TrimRight(envOr("SSO_ENTRA_AUTHORITY", "https://login.microsoftonline.com"), "/")
		if u, err := url.Parse(authority); err != nil || u.Scheme != "https" || u.Host == "" {
			log.Fatal("SSO_ENTRA_AUTHORITY must be an https URL")
		}
		s.providers = append(s.providers, newEntraProvider(authority, tenant, id, secret))
	}
	if len(s.providers) == 0 {
		return nil
	}
	if appURL == "" {
		log.Fatal("single sign-on needs APP_URL: the provider sends people back to " + ssoCallbackPath + " under it")
	}
	return s
}

func newSSOClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") }}
}

func newGoogleProvider(clientID, secret, domain string) *ssoProvider {
	return &ssoProvider{id: "google", name: "Google", issuer: "https://accounts.google.com",
		clientID: clientID, clientSecret: secret, domain: domain, client: newSSOClient()}
}

func newEntraProvider(authority, tenant, clientID, secret string) *ssoProvider {
	return &ssoProvider{id: "entra", name: "Microsoft", issuer: authority + "/" + tenant + "/v2.0",
		clientID: clientID, clientSecret: secret, tenant: tenant, client: newSSOClient()}
}

func (s *sso) provider(id string) *ssoProvider {
	if s == nil {
		return nil
	}
	for _, p := range s.providers {
		if p.id == id {
			return p
		}
	}
	return nil
}

// list is what the sign-in page shows: one button per provider.
func (s *sso) list() []map[string]string {
	out := []map[string]string{}
	if s != nil {
		for _, p := range s.providers {
			out = append(out, map[string]string{"id": p.id, "name": p.name})
		}
	}
	return out
}

// ----- provider: discovery, keys, code exchange, token verification -----

func (p *ssoProvider) allowed(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && u.User == nil && (u.Scheme == "https" || (p.insecure && u.Scheme == "http"))
}

func (p *ssoProvider) getJSON(ctx context.Context, target string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(dst)
}

// metadata returns the provider's endpoints from its discovery document,
// read once a day. A document that names another issuer, or an endpoint
// that is not https, is refused. When the provider cannot be asked, the
// last good document stays in use.
func (p *ssoProvider) metadata(ctx context.Context) (*oidcMeta, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meta != nil && time.Since(p.metaAt) < ssoMetaTTL {
		return p.meta, nil
	}
	var m oidcMeta
	err := p.getJSON(ctx, p.issuer+"/.well-known/openid-configuration", &m)
	if err == nil {
		switch {
		case m.Issuer != p.issuer:
			err = fmt.Errorf("the discovery document names the issuer %q, expected %q", m.Issuer, p.issuer)
		case !p.allowed(m.AuthorizationEndpoint) || !p.allowed(m.TokenEndpoint) || !p.allowed(m.JWKSURI):
			err = errors.New("the discovery document lists an endpoint that is not an https URL")
		}
	}
	if err != nil {
		if p.meta != nil {
			log.Printf("sso: %s: discovery failed, keeping the last document: %v", p.id, err)
			return p.meta, nil
		}
		return nil, fmt.Errorf("discovery: %w", err)
	}
	p.meta, p.metaAt = &m, time.Now()
	return p.meta, nil
}

// key returns the provider's signing key with the given ID. Providers rotate
// their keys, so an unknown ID refetches them (not more often than
// ssoKeysRefresh, whatever tokens are presented).
func (p *ssoProvider) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	meta, err := p.metadata(ctx)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, known := p.keys[kid]
	if known && time.Since(p.keysAt) < ssoKeysTTL {
		return k, nil
	}
	if time.Since(p.keysTry) < ssoKeysRefresh {
		if known {
			return k, nil
		}
		return nil, errors.New("the token is signed with a key the provider does not publish")
	}
	p.keysTry = time.Now()
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := p.getJSON(ctx, meta.JWKSURI, &set); err != nil {
		if known {
			return k, nil
		}
		return nil, fmt.Errorf("signing keys: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || (j.Use != "" && j.Use != "sig") || j.Kid == "" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(j.N)
		e, err2 := base64.RawURLEncoding.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 {
			continue
		}
		keys[j.Kid] = pub
	}
	if len(keys) == 0 {
		if known {
			return k, nil
		}
		return nil, errors.New("signing keys: the provider published none that can be used")
	}
	p.keys, p.keysAt = keys, time.Now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("the token is signed with a key the provider does not publish")
}

// exchange redeems an authorization code for the ID token.
func (p *ssoProvider) exchange(ctx context.Context, code, verifier, redirectURI string) (string, error) {
	meta, err := p.metadata(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {p.clientID}, "client_secret": {p.clientSecret}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := p.client.Do(req)
	if err != nil {
		return "", errors.New("the token endpoint could not be reached")
	}
	defer res.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out)
	if res.StatusCode != http.StatusOK || out.IDToken == "" {
		if out.Error != "" {
			return "", fmt.Errorf("the token endpoint refused the code: %s", firstLine(out.Error))
		}
		return "", fmt.Errorf("the token endpoint answered HTTP %d", res.StatusCode)
	}
	return out.IDToken, nil
}

type idTokenClaims struct {
	jwt.RegisteredClaims
	Nonce             string `json:"nonce"`
	AuthorizedParty   string `json:"azp"`
	Email             string `json:"email"`
	EmailVerified     any    `json:"email_verified"`
	HostedDomain      string `json:"hd"`
	TenantID          string `json:"tid"`
	PreferredUsername string `json:"preferred_username"`
}

// verify checks an ID token and returns who it is about.
func (p *ssoProvider) verify(ctx context.Context, raw, nonce string) (*ssoIdentity, error) {
	var c idTokenClaims
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(p.clientID),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(time.Minute))
	_, err := parser.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("the token names no signing key")
		}
		return p.key(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("ID token: %w", err)
	}
	// Google documents both spellings of its issuer.
	if c.Issuer != p.issuer && !(p.id == "google" && c.Issuer == "accounts.google.com") {
		return nil, errors.New("ID token: issued by someone else")
	}
	if c.AuthorizedParty != "" && c.AuthorizedParty != p.clientID {
		return nil, errors.New("ID token: issued to another application")
	}
	if len(c.Audience) != 1 && c.AuthorizedParty != p.clientID {
		return nil, errors.New("ID token: issued to several applications")
	}
	if c.IssuedAt == nil {
		return nil, errors.New("ID token: no issue time")
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("ID token: it does not answer this sign-in request")
	}
	if c.Subject == "" || len(c.Subject) > 255 {
		return nil, errors.New("ID token: no usable subject")
	}
	id := &ssoIdentity{issuer: p.issuer, subject: c.Subject}
	switch p.id {
	case "google":
		if p.domain != "" && !strings.EqualFold(c.HostedDomain, p.domain) {
			return nil, errors.New("the account does not belong to the allowed Google Workspace domain")
		}
		if v, _ := c.EmailVerified.(bool); v || c.EmailVerified == "true" {
			id.email = c.Email
		}
	case "entra":
		if !strings.EqualFold(c.TenantID, p.tenant) {
			return nil, errors.New("the account belongs to another Microsoft Entra tenant")
		}
		id.email = c.Email
		if id.email == "" {
			id.email = c.PreferredUsername
		}
	}
	id.email = strings.ToLower(strings.TrimSpace(id.email))
	if len(id.email) > 254 || strings.ContainsAny(id.email, "\r\n\t") {
		id.email = ""
	}
	return id, nil
}

// ----- flows -----

// begin opens a flow for the browser behind w and returns the address at
// the provider to send it to.
func (a *App) ssoBegin(w http.ResponseWriter, r *http.Request, p *ssoProvider, intent string, userID int64) (string, error) {
	meta, err := p.metadata(r.Context())
	if err != nil {
		return "", err
	}
	target, err := url.Parse(meta.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	f := &ssoFlow{provider: p, binder: randomToken(), nonce: randomToken(), verifier: randomToken(),
		intent: intent, userID: userID, ip: clientIP(r)}
	state := intent + "." + randomToken()
	s := a.sso
	s.mu.Lock()
	now := s.now()
	same := 0
	for k, v := range s.flows {
		if now.After(v.expires) {
			delete(s.flows, k)
		} else if v.ip == f.ip {
			same++
		}
	}
	if len(s.flows) >= ssoMaxFlows || same >= ssoMaxFlowsIP {
		s.mu.Unlock()
		return "", errors.New("too many sign-ins in progress")
	}
	f.expires = now.Add(ssoFlowTTL)
	s.flows[state] = f
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: f.binder, Path: "/api/", MaxAge: int(ssoFlowTTL.Seconds()),
		HttpOnly: true, Secure: a.isHTTPS(r), SameSite: http.SameSiteLaxMode})
	challenge := sha256.Sum256([]byte(f.verifier))
	q := target.Query()
	for k, v := range map[string]string{
		"response_type": "code", "client_id": p.clientID, "redirect_uri": a.appURL + ssoCallbackPath,
		"scope": "openid email profile", "state": state, "nonce": f.nonce, "prompt": "select_account",
		"code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256",
	} {
		q.Set(k, v)
	}
	if p.domain != "" {
		q.Set("hd", p.domain) // a hint for the account chooser; the token's claim is what is checked
	}
	target.RawQuery = q.Encode()
	return target.String(), nil
}

// ssoFlowFor returns the flow a request continues: the state must be known
// and not expired, of the given intent, and the request must come from the
// browser that started it.
func (a *App) ssoFlowFor(r *http.Request, state, intent string) *ssoFlow {
	if a.sso == nil || state == "" {
		return nil
	}
	c, err := r.Cookie(ssoCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	s := a.sso
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flows[state]
	if f == nil || s.now().After(f.expires) || f.intent != intent ||
		subtle.ConstantTimeCompare([]byte(f.binder), []byte(c.Value)) != 1 {
		return nil
	}
	return f
}

func (a *App) ssoEnd(w http.ResponseWriter, r *http.Request, state string) {
	a.sso.mu.Lock()
	delete(a.sso.flows, state)
	a.sso.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/api/", MaxAge: -1,
		HttpOnly: true, Secure: a.isHTTPS(r), SameSite: http.SameSiteLaxMode})
}

// ssoRedeem turns the provider's answer into a verified identity, once per flow.
func (a *App) ssoRedeem(ctx context.Context, f *ssoFlow, code string) (*ssoIdentity, error) {
	if code == "" || len(code) > 4096 {
		return nil, errors.New("no authorization code")
	}
	raw, err := f.provider.exchange(ctx, code, f.verifier, a.appURL+ssoCallbackPath)
	if err != nil {
		return nil, err
	}
	return f.provider.verify(ctx, raw, f.nonce)
}

// ----- handlers: signing in -----

// handleSSOStart sends the browser to the provider. It is opened as a link
// from the sign-in page, so failures go back to the application as well.
func (a *App) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	p := a.sso.provider(r.PathValue("provider"))
	if p == nil {
		writeErr(w, http.StatusNotFound, "this sign-in method is not available")
		return
	}
	target, err := a.ssoBegin(w, r, p, "login", 0)
	if err != nil {
		log.Printf("sso: %s: cannot start a sign-in: %v", p.id, err)
		http.Redirect(w, r, ssoCallbackPath+"?error=temporarily_unavailable", http.StatusFound)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// handleSSOFinish completes a sign-in: the web application passes on what
// the provider answered. With a second factor on the account it is called
// again with that factor; the provider's answer is redeemed only once.
func (a *App) handleSSOFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		State             string `json:"state"`
		AuthorizationCode string `json:"authorization_code"`
		secondFactorInput
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	ipKey := "login-ip:" + ip
	if a.limiter.blocked(ipKey, maxFailsPerIP) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	f := a.ssoFlowFor(r, in.State, "login")
	if f == nil {
		a.limiter.fail(ipKey)
		a.auditSystem(ctx, "", ip, "auth.sso_failed", "unknown or expired sign-in request")
		writeErr(w, http.StatusBadRequest, "this sign-in request has expired; start again")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.provider
	if f.identity == nil {
		id, err := a.ssoRedeem(ctx, f, in.AuthorizationCode)
		if err != nil {
			a.ssoEnd(w, r, in.State)
			a.limiter.fail(ipKey)
			a.auditSystem(ctx, "", ip, "auth.sso_failed", p.name+": "+err.Error())
			writeErr(w, http.StatusUnauthorized, "signing in with "+p.name+" failed; try again")
			return
		}
		f.identity = id
	}
	id := f.identity

	var acct account
	var blocked bool
	err := a.db.QueryRow(ctx, `
		SELECT u.id, u.org_id, u.email, u.totp_enabled, u.totp_secret, u.totp_last_step, u.disabled OR o.disabled
		FROM user_identities i JOIN users u ON u.id = i.user_id JOIN organizations o ON o.id = u.org_id
		WHERE i.provider = $1 AND i.issuer = $2 AND i.subject = $3`, p.id, id.issuer, id.subject).
		Scan(&acct.userID, &acct.orgID, &acct.email, &acct.totpEnabled, &acct.totpSecret, &acct.totpLastStep, &blocked)
	if err != nil {
		a.ssoEnd(w, r, in.State)
		a.auditSystem(ctx, id.email, ip, "auth.sso_failed", "no account is connected to this "+p.name+" account")
		writeJSON(w, http.StatusForbidden, map[string]any{"sso_not_connected": true,
			"error": "No account here is connected to this " + p.name + " account. Sign in with your password and connect it under Settings, Account."})
		return
	}
	if blocked {
		a.ssoEnd(w, r, in.State)
		a.auditAnon(ctx, acct.orgID, acct.email, ip, "auth.login_disabled", "account or organization is blocked")
		writeErr(w, http.StatusForbidden, "this account is blocked; contact the administrator")
		return
	}
	acctKey := "login-email:" + acct.email
	if a.limiter.blocked(acctKey, maxFailsPerAccount) {
		a.auditAnon(ctx, acct.orgID, acct.email, ip, "auth.login_blocked", "too many failed attempts")
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	used, ok := a.secondFactor(w, r, acct, in.secondFactorInput, nil)
	if !ok {
		return
	}
	a.ssoEnd(w, r, in.State)
	if err := a.createSession(ctx, w, r, acct.userID); err != nil {
		writeErr(w, http.StatusInternalServerError, "session failed")
		return
	}
	a.limiter.clear(acctKey)
	_, _ = a.db.Exec(ctx, `UPDATE user_identities SET last_used_at = now(), email = $4
		WHERE provider = $1 AND issuer = $2 AND subject = $3`, p.id, id.issuer, id.subject, id.email)
	detail := "with " + p.name
	if used != "" {
		detail += " and two-factor (" + used + ")"
	}
	a.auditAnon(ctx, acct.orgID, acct.email, ip, "auth.login", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ----- handlers: connecting an account -----

// handleSSOList lists the providers of this instance and which of them the
// account is connected to (a connection to a provider that was turned off
// since is listed too, so it can be removed).
func (a *App) handleSSOList(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	type row struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Available   bool   `json:"available"`
		Connected   bool   `json:"connected"`
		Email       string `json:"email"`
		ConnectedAt int64  `json:"connected_at"`
		LastUsedAt  int64  `json:"last_used_at"`
	}
	out := []*row{}
	byID := map[string]*row{}
	if a.sso != nil {
		for _, p := range a.sso.providers {
			x := &row{ID: p.id, Name: p.name, Available: true}
			out, byID[p.id] = append(out, x), x
		}
	}
	rows, err := a.db.Query(r.Context(), `SELECT provider, email, created_at, last_used_at FROM user_identities WHERE user_id = $1 ORDER BY provider`, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var provider, email string
		var created time.Time
		var used *time.Time
		if rows.Scan(&provider, &email, &created, &used) != nil {
			continue
		}
		x := byID[provider]
		if x == nil {
			x = &row{ID: provider, Name: ssoProviderName(provider)}
			out = append(out, x)
		}
		x.Connected, x.Email, x.ConnectedAt = true, email, created.Unix()
		if used != nil {
			x.LastUsedAt = used.Unix()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func ssoProviderName(id string) string {
	switch id {
	case "google":
		return "Google"
	case "entra":
		return "Microsoft"
	}
	return id
}

// handleSSOLink starts connecting the signed-in account to a provider
// identity. The password is asked for, as for every change of how an
// account is signed in to.
func (a *App) handleSSOLink(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Provider string `json:"provider"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	p := a.sso.provider(in.Provider)
	if p == nil {
		writeErr(w, http.StatusBadRequest, "this sign-in method is not available")
		return
	}
	if !a.checkPassword(w, r, u, in.Password, "account.sso_setup", "password is incorrect") {
		return
	}
	ctx := r.Context()
	var n int
	_ = a.db.QueryRow(ctx, `SELECT count(*) FROM user_identities WHERE user_id = $1 AND provider = $2`, u.ID, p.id).Scan(&n)
	if n > 0 {
		writeErr(w, http.StatusConflict, "this account is already connected to a "+p.name+" account; disconnect it first")
		return
	}
	target, err := a.ssoBegin(w, r, p, "link", u.ID)
	if err != nil {
		log.Printf("sso: %s: cannot start a connection: %v", p.id, err)
		writeErr(w, http.StatusBadGateway, p.name+" could not be reached; try again in a moment")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.sso_setup", p.name)
	writeJSON(w, http.StatusOK, map[string]any{"url": target})
}

// handleSSOLinkFinish stores the connection once the provider has answered.
func (a *App) handleSSOLinkFinish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		State             string `json:"state"`
		AuthorizationCode string `json:"authorization_code"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	f := a.ssoFlowFor(r, in.State, "link")
	if f == nil || f.userID != u.ID {
		a.deny(w, r, "account.sso_add", "this request to connect an account has expired; start again")
		return
	}
	p := f.provider
	a.ssoEnd(w, r, in.State) // one attempt per request to connect
	id, err := a.ssoRedeem(ctx, f, in.AuthorizationCode)
	if err != nil {
		a.audit(ctx, u, clientIP(r), "denied.account.sso_add", p.name+": "+err.Error())
		writeErr(w, http.StatusBadGateway, "connecting the "+p.name+" account failed; try again")
		return
	}
	if _, err := a.db.Exec(ctx, `INSERT INTO user_identities (user_id, provider, issuer, subject, email) VALUES ($1,$2,$3,$4,$5)`,
		u.ID, p.id, id.issuer, id.subject, id.email); err != nil {
		if isUniqueViolation(err) {
			a.audit(ctx, u, clientIP(r), "denied.account.sso_add", p.name+": the identity is already connected")
			writeErr(w, http.StatusConflict, "this "+p.name+" account is already connected to an account here")
			return
		}
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	detail := p.name
	if id.email != "" {
		detail += " (" + id.email + ")"
	}
	a.audit(ctx, u, clientIP(r), "account.sso_add", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider": p.id, "name": p.name, "email": id.email})
}

// handleSSOUnlink removes the connection to a provider.
func (a *App) handleSSOUnlink(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	provider := r.PathValue("provider")
	if !a.checkPassword(w, r, u, in.Password, "account.sso_remove", "password is incorrect") {
		return
	}
	ctx := r.Context()
	var email string
	if err := a.db.QueryRow(ctx, `DELETE FROM user_identities WHERE user_id = $1 AND provider = $2 RETURNING email`, u.ID, provider).Scan(&email); err != nil {
		writeErr(w, http.StatusNotFound, "this account is not connected to that sign-in method")
		return
	}
	detail := ssoProviderName(provider)
	if email != "" {
		detail += " (" + email + ")"
	}
	a.audit(ctx, u, clientIP(r), "account.sso_remove", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
