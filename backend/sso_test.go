package main

// Single sign-on: a fake OpenID Connect provider and the security rules of
// the flow (SECURITY-TESTING.md).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testTenant       = "11111111-2222-3333-4444-555555555555"
	testSSOClient    = "driftband-test-client"
	testSSOSecret    = "driftband-test-secret"
	testGoogleIssuer = "/google"
)

// mockIdP plays Google and Microsoft Entra ID: discovery, the authorization
// endpoint (the "person" always agrees and is whoever person says), the
// token endpoint (it checks the client secret and PKCE) and the keys.
type mockIdP struct {
	*httptest.Server
	t   *testing.T
	key *rsa.PrivateKey
	kid string

	mu     sync.Mutex
	person mockPerson
	grants map[string]mockGrant
	tokens int // codes redeemed
	// tamper may change the claims, the signing method, the key or the
	// header of the next ID token.
	tamper func(claims jwt.MapClaims, tok *mockToken)
	// discovery, when set, replaces the discovery document.
	discovery func(issuer string) map[string]any
	// published in addition to the signing key
	extraKeys map[string]*rsa.PublicKey
}

type mockPerson struct {
	Sub, Email string
	Claims     map[string]any // added to the ID token
}

type mockGrant struct {
	issuer, nonce, challenge, redirect string
	person                             mockPerson
}

type mockToken struct {
	method jwt.SigningMethod
	key    any
	kid    string
}

func newMockIdP(t *testing.T) *mockIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{t: t, key: key, kid: "test-key-1", grants: map[string]mockGrant{}}
	m.Server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.Close)
	return m
}

// sso returns the application's provider configuration pointing at the mock.
func (m *mockIdP) sso() *sso {
	g := newGoogleProvider(testSSOClient, testSSOSecret, "")
	g.issuer = m.URL + testGoogleIssuer
	e := newEntraProvider(m.URL, testTenant, testSSOClient, testSSOSecret)
	g.insecure, e.insecure = true, true
	return &sso{flows: map[string]*ssoFlow{}, now: time.Now, providers: []*ssoProvider{g, e}}
}

func (m *mockIdP) as(sub, email string, claims map[string]any) {
	m.mu.Lock()
	m.person = mockPerson{Sub: sub, Email: email, Claims: claims}
	m.mu.Unlock()
}

func (m *mockIdP) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	cut := func(suffix string) (string, bool) {
		if strings.HasSuffix(path, suffix) {
			return m.URL + strings.TrimSuffix(path, suffix), true
		}
		return "", false
	}
	if issuer, ok := cut("/.well-known/openid-configuration"); ok {
		doc := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"}
		m.mu.Lock()
		if m.discovery != nil {
			doc = m.discovery(issuer)
		}
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(doc)
		return
	}
	if _, ok := cut("/keys"); ok {
		jwk := func(kid string, pub *rsa.PublicKey) map[string]any {
			return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
		}
		keys := []any{jwk(m.kid, &m.key.PublicKey)}
		for kid, pub := range m.extraKeys {
			keys = append(keys, jwk(kid, pub))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		return
	}
	if issuer, ok := cut("/authorize"); ok {
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("client_id") != testSSOClient || q.Get("code_challenge_method") != "S256" ||
			q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" || !strings.Contains(q.Get("scope"), "openid") {
			http.Error(w, "bad authorization request", http.StatusBadRequest)
			return
		}
		code := randomToken()
		m.mu.Lock()
		m.grants[code] = mockGrant{issuer: issuer, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
			redirect: q.Get("redirect_uri"), person: m.person}
		m.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
		return
	}
	if issuer, ok := cut("/token"); ok {
		_ = r.ParseForm()
		m.mu.Lock()
		g, known := m.grants[r.PostForm.Get("code")]
		delete(m.grants, r.PostForm.Get("code")) // a code is redeemed once
		tamper := m.tamper
		m.tamper = nil
		m.tokens++
		m.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !known || g.issuer != issuer || r.PostForm.Get("grant_type") != "authorization_code" ||
			r.PostForm.Get("client_id") != testSSOClient || r.PostForm.Get("client_secret") != testSSOSecret ||
			r.PostForm.Get("redirect_uri") != g.redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		now := time.Now()
		claims := jwt.MapClaims{"iss": issuer, "aud": testSSOClient, "sub": g.person.Sub, "nonce": g.nonce,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "email": g.person.Email}
		if strings.HasSuffix(issuer, testGoogleIssuer) {
			claims["email_verified"] = true
		} else {
			claims["tid"] = testTenant
		}
		for k, v := range g.person.Claims {
			claims[k] = v
		}
		mt := &mockToken{method: jwt.SigningMethodRS256, key: m.key, kid: m.kid}
		if tamper != nil {
			tamper(claims, mt)
		}
		tok := jwt.NewWithClaims(mt.method, claims)
		if mt.kid != "" {
			tok.Header["kid"] = mt.kid
		}
		raw, err := tok.SignedString(mt.key)
		if err != nil {
			m.t.Errorf("mock provider: sign: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": raw, "access_token": "x", "token_type": "Bearer"})
		return
	}
	http.NotFound(w, r)
}

// ssoAnswer is what comes back from the provider to the web application,
// with the cookie of the browser that started the flow.
type ssoAnswer struct {
	State, Code string
	Cookie      *http.Cookie
}

func (s ssoAnswer) body() map[string]any {
	return map[string]any{"state": s.State, "authorization_code": s.Code}
}

// visit follows the redirect to the provider and back, like a browser.
func (e *env) visit(target string, cookie *http.Cookie) ssoAnswer {
	e.t.Helper()
	res, err := http.DefaultTransport.RoundTrip(must(http.NewRequest("GET", target, nil)))
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound || !strings.HasPrefix(back.String(), testOrigin+ssoCallbackPath+"?") {
		e.t.Fatalf("the provider did not send the browser back to the application: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	return ssoAnswer{State: back.Query().Get("state"), Code: back.Query().Get("code"), Cookie: cookie}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// ssoStart begins a sign-in with provider and returns the provider's answer.
func (e *env) ssoStart(provider string) ssoAnswer {
	e.t.Helper()
	r := e.req(anon, "GET", "/api/auth/sso/"+provider+"/start", nil)
	if r.Status != http.StatusFound || r.cookie(ssoCookie) == nil {
		e.t.Fatalf("start: %d %s", r.Status, r.Body)
	}
	return e.visit(r.Header.Get("Location"), r.cookie(ssoCookie))
}

// ssoFinish presents the provider's answer from the browser that owns the cookie.
func (e *env) ssoFinish(a ssoAnswer, extra map[string]any) *resp {
	body := a.body()
	for k, v := range extra {
		body[k] = v
	}
	browser := &actor{}
	if a.Cookie != nil {
		browser.Extra = []*http.Cookie{a.Cookie}
	}
	return e.req(browser, "POST", "/api/auth/sso/finish", body)
}

// ssoLinkStart begins connecting a's account and returns the provider's answer.
func (e *env) ssoLinkStart(a *actor, provider string) ssoAnswer {
	e.t.Helper()
	r := e.must(e.req(a, "POST", "/api/account/sso/link", map[string]any{"provider": provider, "password": a.Password}), 200, "link")
	return e.visit(r.JSON["url"].(string), r.cookie(ssoCookie))
}

// ssoConnect connects a's account to the identity sub at provider.
func (e *env) ssoConnect(a *actor, provider, sub, email string) {
	e.t.Helper()
	e.idp.as(sub, email, nil)
	ans := e.ssoLinkStart(a, provider)
	browser := &actor{Token: a.Token, Extra: []*http.Cookie{ans.Cookie}}
	e.must(e.req(browser, "POST", "/api/account/sso/finish", ans.body()), 200, "connect "+provider)
}

func newSub(tag string) string { return fmt.Sprintf("%s-%d", tag, seq.Add(1)) }

func identities(t *testing.T, userID int64) int {
	t.Helper()
	var n int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM user_identities WHERE user_id = $1`, userID).Scan(&n)
	return n
}

func systemAuditLike(t *testing.T, action, like string, since time.Time) bool {
	t.Helper()
	var n int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM audit_log
		WHERE org_id IS NULL AND action = $1 AND detail LIKE '%' || $2 || '%' AND created_at >= $3`, action, like, since).Scan(&n)
	return n > 0
}

func TestSSOConfigIsPublished(t *testing.T) {
	e := newEnv(t)
	r := e.must(e.req(anon, "GET", "/api/auth/config", nil), 200, "config")
	list, _ := r.JSON["sso"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["id"] != "google" || list[1].(map[string]any)["id"] != "entra" {
		t.Errorf("providers on the sign-in page: %s", r.Body)
	}
	if strings.Contains(string(r.Body), testSSOSecret) || strings.Contains(string(r.Body), testSSOClient) {
		t.Error("the sign-in page configuration gives away the client credentials")
	}
	e.app.sso = nil
	r = e.must(e.req(anon, "GET", "/api/auth/config", nil), 200, "config without providers")
	if list, _ := r.JSON["sso"].([]any); len(list) != 0 {
		t.Errorf("no provider configured, yet listed: %s", r.Body)
	}
	if r := e.req(anon, "GET", "/api/auth/sso/google/start", nil); r.Status != 404 {
		t.Errorf("start without providers: %d", r.Status)
	}
	if r := e.req(anon, "POST", "/api/auth/sso/finish", map[string]any{"state": "login.x", "authorization_code": "y"}); r.Status != 400 {
		t.Errorf("finish without providers: %d", r.Status)
	}
}

func TestSSOAuthorizationRequest(t *testing.T) {
	e := newEnv(t)
	r := e.req(anon, "GET", "/api/auth/sso/entra/start", nil, "X-Forwarded-Proto: https")
	if r.Status != http.StatusFound {
		t.Fatalf("start: %d", r.Status)
	}
	u, _ := url.Parse(r.Header.Get("Location"))
	q := u.Query()
	if !strings.HasPrefix(u.String(), e.idp.URL+"/"+testTenant+"/v2.0/authorize?") {
		t.Errorf("sent to %s", u)
	}
	for k, want := range map[string]string{"response_type": "code", "client_id": testSSOClient,
		"redirect_uri": testOrigin + ssoCallbackPath, "code_challenge_method": "S256"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if len(q.Get(k)) < 40 {
			t.Errorf("%s is missing or short: %q", k, q.Get(k))
		}
	}
	if strings.Contains(u.String(), testSSOSecret) {
		t.Error("the client secret travels through the browser")
	}
	c := r.cookie(ssoCookie)
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/api/" || c.MaxAge <= 0 {
		t.Errorf("flow cookie flags: %+v", c)
	}
	r2 := e.req(anon, "GET", "/api/auth/sso/entra/start", nil)
	q2 := must(url.Parse(r2.Header.Get("Location"))).Query()
	if q2.Get("state") == q.Get("state") || q2.Get("nonce") == q.Get("nonce") || q2.Get("code_challenge") == q.Get("code_challenge") ||
		r2.cookie(ssoCookie).Value == c.Value {
		t.Error("two sign-ins share state, nonce, PKCE challenge or cookie")
	}
	if r := e.req(anon, "GET", "/api/auth/sso/github/start", nil); r.Status != 404 {
		t.Errorf("unknown provider: %d", r.Status)
	}
}

func TestSSOConnectAndSignIn(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("sso")
	a := o.Member
	sub := newSub("g")

	// connecting asks for the password
	t0 := dbNow(t)
	if r := e.req(a, "POST", "/api/account/sso/link", map[string]any{"provider": "google", "password": "Wrong-pass-123"}); r.Status != 403 {
		t.Fatalf("connect with a wrong password: %d", r.Status)
	}
	if !auditHas(t, a.OrgID, a.Email, "denied.account.sso_setup", t0) {
		t.Error("refused connection not audited")
	}
	if r := e.req(a, "POST", "/api/account/sso/link", map[string]any{"provider": "github", "password": a.Password}); r.Status != 400 {
		t.Errorf("unknown provider: %d", r.Status)
	}
	e.ssoConnect(a, "google", sub, "ada@example.org")
	if !auditHas(t, a.OrgID, a.Email, "account.sso_add", t0) {
		t.Error("connection not audited")
	}
	r := e.must(e.req(a, "GET", "/api/account/sso", nil), 200, "list")
	g := r.List[0].(map[string]any)
	if g["id"] != "google" || g["connected"] != true || g["email"] != "ada@example.org" || r.List[1].(map[string]any)["connected"] != false {
		t.Errorf("list: %s", r.Body)
	}
	if strings.Contains(string(r.Body), sub) {
		t.Error("the list gives away the provider's subject")
	}
	if r := e.req(a, "POST", "/api/account/sso/link", map[string]any{"provider": "google", "password": a.Password}); r.Status != 409 {
		t.Errorf("second connection to the same provider: %d", r.Status)
	}

	// signing in
	t0 = dbNow(t)
	ans := e.ssoStart("google")
	fin := e.must(e.ssoFinish(ans, nil), 200, "sign in")
	c := fin.cookie(sessionCookie)
	if c == nil || !c.HttpOnly {
		t.Fatal("no session after signing in")
	}
	me := e.must(e.req(&actor{Token: c.Value}, "GET", "/api/me", nil), 200, "me")
	if me.JSON["email"] != a.Email {
		t.Errorf("signed in as %v, want %s", me.JSON["email"], a.Email)
	}
	if !auditHas(t, a.OrgID, a.Email, "auth.login", t0) {
		t.Error("sign-in not audited")
	}
	// the answer of the provider works once
	if r := e.ssoFinish(ans, nil); r.Status != 400 || r.cookie(sessionCookie) != nil {
		t.Errorf("replayed answer: %d", r.Status)
	}

	// another account cannot take the same identity
	other := o.Admin
	e.idp.as(sub, "ada@example.org", nil)
	la := e.ssoLinkStart(other, "google")
	if r := e.req(&actor{Token: other.Token, Extra: []*http.Cookie{la.Cookie}}, "POST", "/api/account/sso/finish", la.body()); r.Status != 409 {
		t.Errorf("identity connected twice: %d %s", r.Status, r.Body)
	}
	if identities(t, other.ID) != 0 {
		t.Error("identity stored for a second account")
	}

	// disconnecting asks for the password; afterwards the identity opens nothing
	if r := e.req(a, "POST", "/api/account/sso/google/unlink", map[string]any{"password": "Wrong-pass-123"}); r.Status != 403 || identities(t, a.ID) != 1 {
		t.Errorf("disconnect with a wrong password: %d", r.Status)
	}
	e.must(e.req(a, "POST", "/api/account/sso/google/unlink", map[string]any{"password": a.Password}), 200, "disconnect")
	if r := e.req(a, "POST", "/api/account/sso/google/unlink", map[string]any{"password": a.Password}); r.Status != 404 {
		t.Errorf("disconnect twice: %d", r.Status)
	}
	e.idp.as(sub, "ada@example.org", nil)
	if r := e.ssoFinish(e.ssoStart("google"), nil); r.Status != 403 || r.cookie(sessionCookie) != nil {
		t.Errorf("sign-in after disconnecting: %d", r.Status)
	}
}

// An account is found by the provider's subject only. An identity that
// merely carries the email address of an account opens nothing, whatever
// the provider says about that address.
func TestSSONeverMatchesByEmail(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("ssomail")
	for _, provider := range []string{"google", "entra"} {
		t0 := dbNow(t)
		e.idp.as(newSub("stranger"), o.Owner.Email, map[string]any{"email_verified": true, "preferred_username": o.Owner.Email})
		r := e.ssoFinish(e.ssoStart(provider), nil)
		if r.Status != 403 || r.JSON["sso_not_connected"] != true || r.cookie(sessionCookie) != nil {
			t.Errorf("%s: an identity with the owner's address: %d %s", provider, r.Status, r.Body)
		}
		if !systemAuditLike(t, "auth.sso_failed", "no account is connected", t0) {
			t.Errorf("%s: refused sign-in not audited", provider)
		}
	}
	if identities(t, o.Owner.ID) != 0 {
		t.Error("a sign-in connected an identity by itself")
	}
}

func TestSSOFlowIsBoundToItsBrowser(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("ssobind")
	sub := newSub("g")
	e.ssoConnect(o.Owner, "google", sub, "")
	e.idp.as(sub, "", nil)

	refused := func(what string, a ssoAnswer) {
		t.Helper()
		if r := e.ssoFinish(a, nil); r.Status != 400 || r.cookie(sessionCookie) != nil {
			t.Errorf("%s: %d %s", what, r.Status, r.Body)
		}
	}
	ans := e.ssoStart("google")
	refused("without the cookie", ssoAnswer{State: ans.State, Code: ans.Code})
	other := e.ssoStart("google")
	refused("with another browser's cookie", ssoAnswer{State: ans.State, Code: ans.Code, Cookie: other.Cookie})
	refused("unknown state", ssoAnswer{State: "login." + randomToken(), Code: ans.Code, Cookie: ans.Cookie})
	refused("empty state", ssoAnswer{Code: ans.Code, Cookie: ans.Cookie})

	// a request to connect an account cannot be finished as a sign-in, and
	// the other way round
	link := e.ssoLinkStart(o.Admin, "google")
	refused("state of a connection", link)
	if r := e.req(&actor{Token: o.Admin.Token, Extra: []*http.Cookie{ans.Cookie}}, "POST", "/api/account/sso/finish", ans.body()); r.Status != 403 {
		t.Errorf("state of a sign-in used to connect: %d", r.Status)
	}
	// someone else's request to connect
	link = e.ssoLinkStart(o.Admin, "google")
	t0 := dbNow(t)
	if r := e.req(&actor{Token: o.Member.Token, Extra: []*http.Cookie{link.Cookie}}, "POST", "/api/account/sso/finish", link.body()); r.Status != 403 {
		t.Errorf("another user finishing the connection: %d", r.Status)
	}
	if !auditHas(t, o.Member.OrgID, o.Member.Email, "denied.account.sso_add", t0) || identities(t, o.Member.ID) != 0 {
		t.Error("refused connection not audited, or stored")
	}

	// an expired flow
	ans = e.ssoStart("google")
	e.app.sso.now = func() time.Time { return time.Now().Add(ssoFlowTTL + time.Second) }
	refused("expired", ans)
	e.app.sso.now = time.Now

	// the original answer still signs in from its own browser
	ans = e.ssoStart("google")
	e.must(e.ssoFinish(ans, nil), 200, "own browser")
}

func TestSSOTokenIsVerified(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("ssotok")
	gsub, esub := newSub("g"), newSub("e")
	e.ssoConnect(o.Owner, "google", gsub, "")
	e.ssoConnect(o.Owner, "entra", esub, "")
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	smallKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM := []byte(base64.StdEncoding.EncodeToString(e.idp.key.PublicKey.N.Bytes()))
	// a key the provider publishes, but too short to be trusted
	e.idp.extraKeys = map[string]*rsa.PublicKey{"small": &smallKey.PublicKey}

	cases := []struct {
		name     string
		provider string
		tamper   func(c jwt.MapClaims, tok *mockToken)
	}{
		{"another audience", "google", func(c jwt.MapClaims, _ *mockToken) { c["aud"] = "someone-else" }},
		{"several audiences without azp", "google", func(c jwt.MapClaims, _ *mockToken) { c["aud"] = []string{testSSOClient, "someone-else"} }},
		{"authorized party is another application", "google", func(c jwt.MapClaims, _ *mockToken) { c["azp"] = "someone-else" }},
		{"another issuer", "google", func(c jwt.MapClaims, _ *mockToken) { c["iss"] = "https://evil.example" }},
		{"the other provider's issuer", "entra", func(c jwt.MapClaims, _ *mockToken) { c["iss"] = e.idp.URL + testGoogleIssuer }},
		{"expired", "google", func(c jwt.MapClaims, _ *mockToken) { c["exp"] = time.Now().Add(-10 * time.Minute).Unix() }},
		{"no expiry", "google", func(c jwt.MapClaims, _ *mockToken) { delete(c, "exp") }},
		{"issued in the future", "google", func(c jwt.MapClaims, _ *mockToken) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"no issue time", "google", func(c jwt.MapClaims, _ *mockToken) { delete(c, "iat") }},
		{"another nonce", "google", func(c jwt.MapClaims, _ *mockToken) { c["nonce"] = randomToken() }},
		{"no nonce", "google", func(c jwt.MapClaims, _ *mockToken) { delete(c, "nonce") }},
		{"no subject", "google", func(c jwt.MapClaims, _ *mockToken) { c["sub"] = "" }},
		{"unsigned", "google", func(_ jwt.MapClaims, tok *mockToken) {
			tok.method, tok.key = jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType
		}},
		{"HMAC with the public key", "google", func(_ jwt.MapClaims, tok *mockToken) { tok.method, tok.key = jwt.SigningMethodHS256, pubPEM }},
		{"signed with another key", "google", func(_ jwt.MapClaims, tok *mockToken) { tok.key = otherKey }},
		{"unknown key ID", "google", func(_ jwt.MapClaims, tok *mockToken) { tok.key, tok.kid = otherKey, "other" }},
		{"no key ID", "google", func(_ jwt.MapClaims, tok *mockToken) { tok.kid = "" }},
		{"published key that is too short", "google", func(_ jwt.MapClaims, tok *mockToken) { tok.key, tok.kid = smallKey, "small" }},
		{"another tenant", "entra", func(c jwt.MapClaims, _ *mockToken) { c["tid"] = "99999999-2222-3333-4444-555555555555" }},
		{"no tenant", "entra", func(c jwt.MapClaims, _ *mockToken) { delete(c, "tid") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.app.limiter = newRateLimiter()
			sub := map[string]string{"google": gsub, "entra": esub}[tc.provider]
			e.idp.as(sub, "", nil)
			ans := e.ssoStart(tc.provider)
			e.idp.mu.Lock()
			e.idp.tamper = tc.tamper
			e.idp.mu.Unlock()
			t0 := dbNow(t)
			r := e.ssoFinish(ans, nil)
			if r.Status != 401 || r.cookie(sessionCookie) != nil {
				t.Fatalf("status %d (%s), session %v", r.Status, r.Body, r.cookie(sessionCookie) != nil)
			}
			if !systemAuditLike(t, "auth.sso_failed", "", t0) {
				t.Error("refused token not audited")
			}
			// the failed flow is over: the same answer does not get a second look
			if r := e.ssoFinish(ans, nil); r.Status != 400 {
				t.Errorf("flow still open after a refused token: %d", r.Status)
			}
		})
	}
	// untampered tokens still sign in with both providers
	e.app.limiter = newRateLimiter()
	for provider, sub := range map[string]string{"google": gsub, "entra": esub} {
		e.idp.as(sub, "", nil)
		e.must(e.ssoFinish(e.ssoStart(provider), nil), 200, provider)
	}
}

func TestSSOCodeIsProtected(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("ssocode")
	sub := newSub("g")
	e.ssoConnect(o.Owner, "google", sub, "")
	e.idp.as(sub, "", nil)

	// a code belongs to the flow whose PKCE verifier it was issued for
	first, second := e.ssoStart("google"), e.ssoStart("google")
	if r := e.ssoFinish(ssoAnswer{State: second.State, Code: first.Code, Cookie: second.Cookie}, nil); r.Status != 401 || r.cookie(sessionCookie) != nil {
		t.Errorf("code of another flow: %d", r.Status)
	}
	for name, code := range map[string]string{"made up": randomToken(), "empty": "", "oversized": strings.Repeat("a", 5000)} {
		e.app.limiter = newRateLimiter()
		if r := e.ssoFinish(ssoAnswer{State: e.ssoStart("google").State, Code: code, Cookie: nil}, nil); r.Status != 400 {
			t.Errorf("%s code without cookie: %d", name, r.Status)
		}
		ans := e.ssoStart("google")
		ans.Code = code
		if r := e.ssoFinish(ans, nil); r.Status != 401 || r.cookie(sessionCookie) != nil {
			t.Errorf("%s code: %d", name, r.Status)
		}
	}
	// failures count against the client address
	e.app.limiter = newRateLimiter()
	for i := 0; i < maxFailsPerIP; i++ {
		e.ssoFinish(ssoAnswer{State: "login.guess", Code: "x"}, nil)
	}
	if r := e.ssoFinish(e.ssoStart("google"), nil); r.Status != 429 {
		t.Errorf("after %d failures from one address: %d", maxFailsPerIP, r.Status)
	}
}

func TestSSOKeepsTheSecondFactor(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("sso2fa")
	a := o.Member
	sub := newSub("e")
	e.ssoConnect(a, "entra", sub, "")
	secret := e.must(e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": a.Password}), 200, "setup").JSON["secret"].(string)
	e.must(e.req(a, "POST", "/api/account/2fa/enable", map[string]any{"code": currentTotp(t, secret, 0)}), 200, "enable")

	e.idp.as(sub, "", nil)
	e.idp.mu.Lock()
	e.idp.tokens = 0
	e.idp.mu.Unlock()
	ans := e.ssoStart("entra")
	r := e.ssoFinish(ans, nil)
	if r.Status != 401 || r.JSON["two_factor_required"] != true || r.cookie(sessionCookie) != nil {
		t.Fatalf("single sign-on alone must not sign in with 2FA on: %d %s", r.Status, r.Body)
	}
	t0 := dbNow(t)
	if r := e.ssoFinish(ans, map[string]any{"code": "000000"}); (r.Status != 401 || r.cookie(sessionCookie) != nil) && currentTotp(t, secret, 1) != "000000" {
		t.Errorf("wrong code: %d", r.Status)
	}
	if !auditHas(t, a.OrgID, a.Email, "auth.login_failed", t0) {
		t.Error("wrong code not audited")
	}
	// the code goes with the browser that signed in at the provider
	if r := e.ssoFinish(ssoAnswer{State: ans.State}, map[string]any{"code": currentTotp(t, secret, 1)}); r.Status != 400 {
		t.Errorf("second factor from another browser: %d", r.Status)
	}
	fin := e.must(e.ssoFinish(ans, map[string]any{"code": currentTotp(t, secret, 1)}), 200, "with the code")
	if fin.cookie(sessionCookie) == nil {
		t.Fatal("no session")
	}
	e.idp.mu.Lock()
	redeemed := e.idp.tokens
	e.idp.mu.Unlock()
	if redeemed != 1 {
		t.Errorf("the authorization code was redeemed %d times, want once", redeemed)
	}
	if !auditHas(t, a.OrgID, a.Email, "auth.login", t0) {
		t.Error("sign-in not audited")
	}

	// guessing the code is limited like at the password sign-in
	e.app.limiter = newRateLimiter()
	ans = e.ssoStart("entra")
	for i := 0; i < maxFailsPerAccount; i++ {
		e.ssoFinish(ans, map[string]any{"code": "000000"})
	}
	if r := e.ssoFinish(ans, map[string]any{"code": currentTotp(t, secret, 2)}); r.Status != 429 {
		t.Errorf("after %d wrong codes: %d", maxFailsPerAccount, r.Status)
	}
}

func TestSSOBlockedAccountsAndResets(t *testing.T) {
	e := newEnv(t)
	sa, o := e.superadmin(), e.newOrg("ssoblock")
	a := o.Member
	sub := newSub("g")
	e.ssoConnect(a, "google", sub, "")
	e.idp.as(sub, "", nil)

	e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/block", a.ID), map[string]any{"blocked": true}), 200, "block")
	if r := e.ssoFinish(e.ssoStart("google"), nil); r.Status != 403 || r.cookie(sessionCookie) != nil {
		t.Errorf("blocked account signed in: %d", r.Status)
	}
	e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/block", a.ID), map[string]any{"blocked": false}), 200, "unblock")
	e.must(e.ssoFinish(e.ssoStart("google"), nil), 200, "after unblocking")

	// a password reset by an administrator takes the account back: the
	// connections go with the old password
	e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/reset-password", a.ID), map[string]any{}), 200, "reset")
	if identities(t, a.ID) != 0 {
		t.Error("connections survive an administrator's password reset")
	}
	if r := e.ssoFinish(e.ssoStart("google"), nil); r.Status != 403 || r.cookie(sessionCookie) != nil {
		t.Errorf("sign-in after the reset: %d", r.Status)
	}
}

func TestSSODomainRestriction(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("ssohd")
	sub := newSub("g")
	e.ssoConnect(o.Owner, "google", sub, "")
	e.app.sso.provider("google").domain = "example.org"
	for name, claims := range map[string]map[string]any{"no domain": nil, "another domain": {"hd": "evil.example"}} {
		e.idp.as(sub, "", claims)
		if r := e.ssoFinish(e.ssoStart("google"), nil); r.Status != 401 || r.cookie(sessionCookie) != nil {
			t.Errorf("%s: %d", name, r.Status)
		}
	}
	e.idp.as(sub, "", map[string]any{"hd": "Example.org"})
	e.must(e.ssoFinish(e.ssoStart("google"), nil), 200, "allowed domain")
}

func TestSSODiscoveryIsChecked(t *testing.T) {
	idp := newMockIdP(t)
	for name, doc := range map[string]func(issuer string) map[string]any{
		"another issuer": func(issuer string) map[string]any {
			return map[string]any{"issuer": "https://evil.example", "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"}
		},
		"endpoint without a scheme": func(issuer string) map[string]any {
			return map[string]any{"issuer": issuer, "authorization_endpoint": "javascript:alert(1)", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"}
		},
		"endpoint with credentials": func(issuer string) map[string]any {
			return map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": strings.Replace(issuer, "://", "://u:p@", 1) + "/token", "jwks_uri": issuer + "/keys"}
		},
	} {
		idp.discovery = doc
		p := idp.sso().provider("entra")
		if _, err := p.metadata(context.Background()); err == nil {
			t.Errorf("%s: discovery document accepted", name)
		}
	}
	// outside the tests the provider must be reached over https
	idp.discovery = nil
	p := idp.sso().provider("entra")
	p.insecure = false
	if _, err := p.metadata(context.Background()); err == nil {
		t.Error("endpoints over plain http accepted")
	}
}

func TestSSOStartIsBounded(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < ssoMaxFlowsIP; i++ {
		if r := e.req(anon, "GET", "/api/auth/sso/google/start", nil); !strings.HasPrefix(r.Header.Get("Location"), e.idp.URL) {
			t.Fatalf("start %d: %d %s", i, r.Status, r.Header.Get("Location"))
		}
	}
	r := e.req(anon, "GET", "/api/auth/sso/google/start", nil)
	if r.Status != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), ssoCallbackPath+"?error=") || r.cookie(ssoCookie) != nil {
		t.Errorf("start beyond the limit: %d %s", r.Status, r.Header.Get("Location"))
	}
	// other addresses are not affected
	if r := e.req(anon, "GET", "/api/auth/sso/google/start", nil, "X-Forwarded-For: 203.0.113.9"); !strings.HasPrefix(r.Header.Get("Location"), e.idp.URL) {
		t.Errorf("another address: %s", r.Header.Get("Location"))
	}
}

func TestSSOSecretsStayOutOfLogsAndAnswers(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("ssoleak")
	sub := newSub("g")
	e.ssoConnect(o.Owner, "google", sub, "ada@example.org")
	e.idp.as(sub, "ada@example.org", nil)
	ans := e.ssoStart("google")
	fin := e.must(e.ssoFinish(ans, nil), 200, "sign in")
	for _, secret := range []string{testSSOSecret, ans.Code, sub} {
		if strings.Contains(string(fin.Body), secret) {
			t.Errorf("the answer contains %q", secret)
		}
		var n int
		_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE detail LIKE '%' || $1 || '%'`, secret).Scan(&n)
		if n > 0 {
			t.Errorf("the audit log contains %q", secret)
		}
	}
}
