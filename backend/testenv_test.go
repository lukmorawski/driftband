package main

// Test harness for the security suite: a throwaway Postgres database, the real
// HTTP router behind httptest, and helpers to act as different users.
//
// Integration tests need TEST_DATABASE_URL pointing at a Postgres server the
// tests may create databases on (scripts/security-tests.sh starts one in
// Docker). Without it they are skipped; route-coverage checks still run.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	testDB    *pgxpool.Pool
	testDBErr string
	seq       atomic.Int64
)

func TestMain(m *testing.M) {
	flag.Parse()
	if !testing.Verbose() {
		log.SetOutput(io.Discard) // request logging drowns the failures
	}
	admin := os.Getenv("TEST_DATABASE_URL")
	if admin == "" {
		testDBErr = "TEST_DATABASE_URL not set (run scripts/security-tests.sh)"
		os.Exit(m.Run())
	}
	ctx := context.Background()
	name := fmt.Sprintf("driftband_test_%d_%d", os.Getpid(), time.Now().Unix())
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect admin db:", err)
		os.Exit(1)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		fmt.Fprintln(os.Stderr, "create test db:", err)
		os.Exit(1)
	}
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	testDB, err = openDB(ctx, u.String())
	if err != nil {
		fmt.Fprintln(os.Stderr, "open test db:", err)
		os.Exit(1)
	}
	code := m.Run()
	testDB.Close()
	_, _ = conn.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
	conn.Close(ctx)
	os.Exit(code)
}

func needDB(t *testing.T) {
	t.Helper()
	if testDB == nil {
		t.Skip(testDBErr)
	}
}

// env is one running server with its own rate limiter.
type env struct {
	t    *testing.T
	app  *App
	srv  *httptest.Server
	web  string
	sink *sink // fake Telegram API / webhook receiver
}

// sink records every HTTP request sent to it (webhooks, Telegram API).
type sink struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []sinkReq
}

type sinkReq struct {
	Path string
	Body string
}

func newSink(t *testing.T) *sink {
	s := &sink{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, sinkReq{Path: r.URL.Path, Body: string(b)})
		s.mu.Unlock()
		if strings.Contains(r.URL.Path, "fail") {
			http.Error(w, "nope", 500)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *sink) all() []sinkReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sinkReq(nil), s.reqs...)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	needDB(t)
	web := t.TempDir()
	_ = os.WriteFile(web+"/index.html", []byte("<!doctype html><title>spa</title>"), 0o644)
	_ = os.WriteFile(web+"/app.js", []byte("console.log(1)"), 0o644)
	app := newApp(testDB, newProberMgr(testDB)) // prober not started: no pings
	sk := newSink(t)
	app.telegramAPI = sk.URL
	app.allowPrivateTargets = true // deliveries go to the local sink
	app.retryDelay = 5 * time.Millisecond
	app.appURL = testOrigin // the address security keys and passkeys are bound to
	landing := t.TempDir()
	_ = os.MkdirAll(landing+"/about", 0o755)
	_ = os.MkdirAll(landing+"/assets/img", 0o755)
	_ = os.WriteFile(landing+"/index.html", []byte(`<!doctype html><link rel="canonical" href="https://example.org/"><title>landing</title>`), 0o644)
	_ = os.WriteFile(landing+"/about/index.html", []byte("<!doctype html><title>about</title>"), 0o644)
	_ = os.WriteFile(landing+"/assets/img/x.svg", []byte("<svg/>"), 0o644)
	_ = os.WriteFile(landing+"/404.html", []byte("<!doctype html><title>landing 404</title>"), 0o644)
	srv := httptest.NewServer(app.routes(web, landing))
	t.Cleanup(srv.Close)
	return &env{t: t, app: app, srv: srv, web: web, sink: sk}
}

// actor is a signed-in (or anonymous) user.
type actor struct {
	ID       int64
	OrgID    int64
	Email    string
	Password string
	Role     string
	Token    string // session cookie value
}

var anon = &actor{}

type resp struct {
	Status int
	Body   []byte
	Header http.Header
	JSON   map[string]any
	List   []any
}

// req performs an API call as a, with optional extra headers ("K: V").
func (e *env) req(a *actor, method, path string, body any, hdrs ...string) *resp {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if a != nil && a.Token != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: a.Token})
	}
	seen := map[string]bool{}
	for _, h := range hdrs {
		k, v, _ := strings.Cut(h, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if seen[k] {
			r.Header.Add(k, v) // repeated header: sent as another line
		} else {
			r.Header.Set(k, v)
		}
		seen[k] = true
	}
	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	out := &resp{Status: res.StatusCode, Header: res.Header}
	out.Body, _ = io.ReadAll(res.Body)
	_ = json.Unmarshal(out.Body, &out.JSON)
	_ = json.Unmarshal(out.Body, &out.List)
	return out
}

func (r *resp) cookie(name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (e *env) must(r *resp, want int, what string) *resp {
	e.t.Helper()
	if r.Status != want {
		e.t.Fatalf("%s: status %d, want %d (%s)", what, r.Status, want, r.Body)
	}
	return r
}

func uniqueEmail(tag string) string {
	return fmt.Sprintf("%s-%d-%d@sec.test", tag, os.Getpid(), seq.Add(1))
}

// registerOrg creates a new organization and returns its signed-in owner.
func (e *env) registerOrg(tag string) *actor {
	e.t.Helper()
	a := &actor{Email: uniqueEmail(tag), Password: "Owner-pass-1234", Role: "owner"}
	r := e.must(e.req(anon, "POST", "/api/auth/register-org",
		map[string]any{"org_name": "Org " + tag, "email": a.Email, "password": a.Password}), 200, "register org")
	a.Token = r.cookie(sessionCookie).Value
	e.fillIDs(a)
	return a
}

// invite creates a user with role in inviter's org through the invite flow.
func (e *env) invite(inviter *actor, role, tag string) *actor {
	e.t.Helper()
	r := e.must(e.req(inviter, "POST", "/api/invites", map[string]any{"role": role}), 200, "create invite")
	a := &actor{Email: uniqueEmail(tag), Password: "Member-pass-1234", Role: role}
	r = e.must(e.req(anon, "POST", "/api/auth/accept-invite",
		map[string]any{"token": r.JSON["token"], "email": a.Email, "password": a.Password}), 200, "accept invite")
	a.Token = r.cookie(sessionCookie).Value
	e.fillIDs(a)
	return a
}

func (e *env) fillIDs(a *actor) {
	e.t.Helper()
	if err := testDB.QueryRow(context.Background(),
		`SELECT id, org_id FROM users WHERE email = $1`, a.Email).Scan(&a.ID, &a.OrgID); err != nil {
		e.t.Fatalf("lookup %s: %v", a.Email, err)
	}
}

// superadmin returns a new platform administrator (own organization; the
// flag can only be set in the database).
func (e *env) superadmin() *actor {
	e.t.Helper()
	a := e.registerOrg("super")
	if _, err := testDB.Exec(context.Background(), `UPDATE users SET is_superadmin = true WHERE id = $1`, a.ID); err != nil {
		e.t.Fatal(err)
	}
	a.Role = "superadmin"
	return a
}

// login signs in with password (+ optional TOTP code) and returns the response.
func (e *env) login(email, password, code string, hdrs ...string) *resp {
	body := map[string]any{"email": email, "password": password}
	if code != "" {
		body["code"] = code
	}
	return e.req(anon, "POST", "/api/auth/login", body, hdrs...)
}

// org is a fully populated tenant: owner, admin, member, and some objects.
type org struct {
	Owner, Admin, Member *actor
	FolderID, HostID     int64
	ProfileID            int64 // non-default profile
	InviteToken          string
	ChannelID, RuleID    int64 // a Telegram channel and a loss rule on the folder
}

func (e *env) newOrg(tag string) *org {
	e.t.Helper()
	o := &org{Owner: e.registerOrg(tag)}
	o.Admin = e.invite(o.Owner, "admin", tag+"-admin")
	o.Member = e.invite(o.Owner, "member", tag+"-member")
	r := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "folder", "name": tag + " folder"}), 200, "folder")
	o.FolderID = int64(r.JSON["id"].(float64))
	r = e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{
		"kind": "host", "name": tag + " host", "host": "192.0.2.1", "parent_id": o.FolderID}), 200, "host")
	o.HostID = int64(r.JSON["id"].(float64))
	r = e.must(e.req(o.Owner, "POST", "/api/profiles", map[string]any{
		"name": tag + " profile", "interval_s": 60, "ping_count": 5, "packet_size": 56}), 200, "profile")
	o.ProfileID = int64(r.JSON["id"].(float64))
	r = e.must(e.req(o.Owner, "POST", "/api/invites", map[string]any{"role": "member"}), 200, "pending invite")
	o.InviteToken = r.JSON["token"].(string)
	r = e.must(e.req(o.Owner, "POST", "/api/notify/channels", map[string]any{
		"name": tag + " channel", "kind": "telegram", "config": map[string]any{"chat_id": "-100123456"},
		"secrets": map[string]any{"bot_token": testBotToken}}), 200, "channel")
	o.ChannelID = int64(r.JSON["id"].(float64))
	r = e.must(e.req(o.Owner, "POST", "/api/notify/rules", ruleBody(tag+" rule", o.FolderID, o.ChannelID)), 200, "rule")
	o.RuleID = int64(r.JSON["id"].(float64))
	// a little probe data so series/status have something to return
	_, err := testDB.Exec(context.Background(), `
		INSERT INTO samples (host_id, ts, sent, recv, rtts)
		SELECT $1, now() - make_interval(mins => g), 5, 5, ARRAY[1.0, 1.1, 1.2, 1.3, 1.4]
		FROM generate_series(1, 30) g`, o.HostID)
	if err != nil {
		e.t.Fatalf("seed samples: %v", err)
	}
	return o
}

const testBotToken = "123456789:AAEhBP0av28AbCdEfGhIjKlMnOpQrStUvWx"

func ruleBody(name string, nodeID, channelID int64) map[string]any {
	return map[string]any{"name": name, "enabled": true, "node_id": nodeID, "metric": "loss", "threshold": 50,
		"recover_threshold": 10, "for_minutes": 2, "recover_minutes": 2, "notify_recovery": true,
		"repeat_minutes": 0, "flap_transitions": 4, "flap_window_minutes": 60, "channel_ids": []int64{channelID}}
}

// items returns the rows of a paged list response ({"items": [...], "total": n}).
func items(r *resp) []any {
	l, _ := r.JSON["items"].([]any)
	return l
}

// orgName reads an organization's name (the admin delete route asks for it).
func orgName(t *testing.T, orgID int64) string {
	t.Helper()
	var name string
	if err := testDB.QueryRow(context.Background(), `SELECT name FROM organizations WHERE id = $1`, orgID).Scan(&name); err != nil {
		t.Fatalf("org %d: %v", orgID, err)
	}
	return name
}

// auditHas reports whether orgID's audit log has action by email since t0.
func auditHas(t *testing.T, orgID int64, email, action string, since time.Time) bool {
	t.Helper()
	var n int
	_ = testDB.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log
		WHERE org_id = $1 AND action = $2 AND ($3 = '' OR user_email = $3) AND created_at >= $4`,
		orgID, action, email, since).Scan(&n)
	return n > 0
}

// currentTotp returns the code for the current step of a secret.
func currentTotp(t *testing.T, secret string, offset int64) string {
	t.Helper()
	c, err := totpCode(secret, time.Now().Unix()/totpStep+offset)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
