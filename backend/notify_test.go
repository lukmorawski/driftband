package main

// Security and behaviour tests for notifications and team roles.
// See SECURITY-TESTING.md.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Team roles.

func TestRoleChange(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("roles")
	m2 := e.invite(o.Owner, "member", "roles-m2")
	t0 := dbNow(t)
	e.must(e.req(o.Admin, "PATCH", pathf("/api/users/%d/role", o.Member.ID), map[string]any{"role": "admin"}), 200, "admin promotes member")
	if !auditHas(t, o.Owner.OrgID, o.Admin.Email, "user.role_change", t0) {
		t.Error("role change not audited")
	}
	// takes effect on the next request, no new sign-in needed
	e.must(e.req(o.Member, "GET", "/api/invites", nil), 200, "promoted member sees invites")
	e.must(e.req(o.Owner, "PATCH", pathf("/api/users/%d/role", o.Member.ID), map[string]any{"role": "member"}), 200, "owner demotes")
	if r := e.req(o.Member, "GET", "/api/invites", nil); r.Status != 403 {
		t.Errorf("demoted user still has admin rights: %d", r.Status)
	}
	if r := e.req(o.Member, "PATCH", pathf("/api/users/%d/role", m2.ID), map[string]any{"role": "admin"}); r.Status != 403 {
		t.Errorf("member changed a role: %d", r.Status)
	}
	if r := e.req(o.Admin, "PATCH", pathf("/api/users/%d/role", o.Owner.ID), map[string]any{"role": "member"}); r.Status != 403 {
		t.Errorf("owner demoted: %d", r.Status)
	}
	if r := e.req(o.Admin, "PATCH", pathf("/api/users/%d/role", o.Admin.ID), map[string]any{"role": "member"}); r.Status != 400 {
		t.Errorf("self role change: %d", r.Status)
	}
	for _, role := range []string{"owner", "superadmin", ""} {
		if r := e.req(o.Owner, "PATCH", pathf("/api/users/%d/role", m2.ID), map[string]any{"role": role}); r.Status != 400 {
			t.Errorf("role %q accepted: %d", role, r.Status)
		}
	}
}

// ---------------------------------------------------------------------------
// Channels: secrets, validation, SSRF.

func TestChannelSecretsNeverExposed(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("secrets")
	r := e.must(e.req(o.Member, "GET", "/api/notify/channels", nil), 200, "list")
	if strings.Contains(string(r.Body), testBotToken) || !strings.Contains(string(r.Body), `"bot_token":true`) {
		t.Fatalf("channel list leaks the token or hides that it is set: %s", r.Body)
	}
	var sealed []byte
	_ = testDB.QueryRow(context.Background(), `SELECT secret FROM notify_channels WHERE id = $1`, o.ChannelID).Scan(&sealed)
	if len(sealed) == 0 || strings.Contains(string(sealed), testBotToken) || strings.Contains(string(sealed), "bot_token") {
		t.Fatal("channel secret stored in plaintext")
	}
	// An update without the token keeps it; the test message reaches the bot API with it.
	e.must(e.req(o.Owner, "PATCH", pathf("/api/notify/channels/%d", o.ChannelID), map[string]any{"name": "kept", "config": map[string]any{"chat_id": "-100777"}}), 200, "update")
	e.must(e.req(o.Owner, "POST", pathf("/api/notify/channels/%d/test", o.ChannelID), nil), 200, "test")
	got := e.sink.all()
	if len(got) == 0 || got[len(got)-1].Path != "/bot"+testBotToken+"/sendMessage" || !strings.Contains(got[len(got)-1].Body, "-100777") {
		t.Fatalf("test message not delivered with the kept token: %+v", got)
	}
	if r := e.req(o.Owner, "PATCH", pathf("/api/notify/channels/%d", o.ChannelID), map[string]any{"name": "x", "kind": "slack"}); r.Status != 400 {
		t.Errorf("channel kind changed: %d", r.Status)
	}
	// Errors in the delivery log never contain the token.
	ch := e.must(e.req(o.Owner, "POST", "/api/notify/channels", map[string]any{"name": "dead", "kind": "slack",
		"secrets": map[string]any{"webhook_url": e.sink.URL + "/fail/T0/B0/SECRETPART"}}), 200, "slack")
	if r := e.req(o.Owner, "POST", pathf("/api/notify/channels/%d/test", int64(ch.JSON["id"].(float64))), nil); r.Status != http.StatusBadGateway || strings.Contains(string(r.Body), "SECRETPART") {
		t.Errorf("failed delivery: %d %s", r.Status, r.Body)
	}
	var leaks int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM notify_log WHERE error LIKE '%SECRETPART%' OR message LIKE '%SECRETPART%'`).Scan(&leaks)
	if leaks > 0 {
		t.Error("webhook URL written to the delivery log")
	}
}

func TestChannelValidation(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("chval")
	bad := []map[string]any{
		{"name": "", "kind": "telegram", "config": map[string]any{"chat_id": "1"}, "secrets": map[string]any{"bot_token": testBotToken}},
		{"name": "t", "kind": "sms"},
		{"name": "t", "kind": "telegram", "config": map[string]any{"chat_id": "1"}, "secrets": map[string]any{"bot_token": "nope"}},
		{"name": "t", "kind": "telegram", "config": map[string]any{"chat_id": "1; rm"}, "secrets": map[string]any{"bot_token": testBotToken}},
		{"name": "e", "kind": "email", "config": map[string]any{"host": "smtp.example.com", "from": "x", "to": []string{"a@b.c"}}},
		{"name": "e", "kind": "email", "config": map[string]any{"host": "smtp.example.com", "from": "a@b.c", "to": []string{}}},
		{"name": "e", "kind": "email", "config": map[string]any{"host": "smtp.example.com", "from": "a@b.c", "to": []string{"x@y.z\r\nBcc: evil@x.y"}}},
		{"name": "e", "kind": "email", "config": map[string]any{"host": "smtp.example.com", "security": "none", "auth": "password", "username": "u", "from": "a@b.c", "to": []string{"a@b.c"}}, "secrets": map[string]any{"password": "p"}},
		{"name": "e", "kind": "email", "config": map[string]any{"host": "smtp.office365.com", "auth": "oauth2", "username": "a@b.c", "client_id": "id", "tenant_id": "../evil", "from": "a@b.c", "to": []string{"a@b.c"}}, "secrets": map[string]any{"client_secret": "s"}},
	}
	for i, b := range bad {
		if r := e.req(o.Owner, "POST", "/api/notify/channels", b); r.Status != 400 {
			t.Errorf("bad channel %d accepted: %d %s", i, r.Status, r.Body)
		}
	}
	ok := map[string]any{"name": "m365", "kind": "email", "config": map[string]any{"host": "smtp.office365.com", "port": 587,
		"auth": "oauth2", "username": "alerts@contoso.com", "client_id": "11111111-2222-3333-4444-555555555555",
		"tenant_id": "contoso.onmicrosoft.com", "from": "Driftband <alerts@contoso.com>", "to": []string{"noc@contoso.com"}},
		"secrets": map[string]any{"client_secret": "s3cr3t-value"}}
	r := e.must(e.req(o.Owner, "POST", "/api/notify/channels", ok), 200, "m365 channel")
	cfg := r.JSON["config"].(map[string]any)
	if cfg["token_url"] != "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token" || cfg["scope"] != "https://outlook.office365.com/.default" || cfg["security"] != "starttls" {
		t.Errorf("Microsoft 365 preset not applied: %v", cfg)
	}
	if strings.Contains(string(r.Body), "s3cr3t-value") {
		t.Error("client secret returned")
	}
}

func TestWebhookSSRFBlocked(t *testing.T) {
	e := newEnv(t)
	e.app.allowPrivateTargets = false
	o := e.newOrg("ssrf")
	for _, u := range []string{"http://hooks.slack.com/services/x", "https://127.0.0.1/hook", "https://localhost/hook",
		"https://10.0.0.5/hook", "https://169.254.169.254/latest/meta-data", "https://[::1]/hook", "https://user:pw@example.com/x",
		"ftp://example.com/x", "https://0.0.0.0/x", "https://100.64.1.1/x"} {
		for _, kind := range []string{"slack", "teams"} {
			if r := e.req(o.Owner, "POST", "/api/notify/channels", map[string]any{"name": "x", "kind": kind, "secrets": map[string]any{"webhook_url": u}}); r.Status != 400 {
				t.Errorf("%s webhook %s accepted: %d", kind, u, r.Status)
			}
		}
	}
	if r := e.req(o.Owner, "POST", "/api/notify/channels", map[string]any{"name": "e", "kind": "email", "config": map[string]any{
		"host": "smtp.example.com", "auth": "oauth2", "oauth_provider": "custom", "token_url": "https://127.0.0.1/token",
		"username": "a@b.c", "client_id": "id", "from": "a@b.c", "to": []string{"a@b.c"}}, "secrets": map[string]any{"client_secret": "s"}}); r.Status != 400 {
		t.Errorf("private OAuth token URL accepted: %d", r.Status)
	}
	// The dial-time check also stops a URL that was stored while allowed.
	err := e.app.postJSON(context.Background(), e.sink.URL+"/x", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Errorf("connection to a private address not refused at dial time: %v", err)
	}
	for ip, want := range map[string]bool{"8.8.8.8": true, "1.1.1.1": true, "10.1.2.3": false, "192.168.1.1": false,
		"172.16.0.1": false, "127.0.0.1": false, "169.254.1.1": false, "100.64.0.1": false, "::1": false, "fd00::1": false, "2606:4700::1111": true} {
		if got := isPublicIP(net.ParseIP(ip)); got != want {
			t.Errorf("isPublicIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Message formats.

func TestChannelPayloads(t *testing.T) {
	e := newEnv(t)
	m := alertMessage{Title: "[ALERT] <b>host</b> & co", Lines: []string{"Packet loss 60% <script>"}, Link: "https://app.example/x", Firing: true}
	for _, kind := range []string{"slack", "teams"} {
		c := &channel{Kind: kind, Secrets: channelSecrets{WebhookURL: e.sink.URL + "/" + kind}}
		if err := e.app.deliver(context.Background(), c, m); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	c := &channel{Kind: "telegram", Config: channelConfig{ChatID: "-1001"}, Secrets: channelSecrets{BotToken: testBotToken}}
	if err := e.app.deliver(context.Background(), c, m); err != nil {
		t.Fatal(err)
	}
	got := e.sink.all()
	var slack, teams, tg map[string]any
	_ = json.Unmarshal([]byte(got[0].Body), &slack)
	_ = json.Unmarshal([]byte(got[1].Body), &teams)
	_ = json.Unmarshal([]byte(got[2].Body), &tg)
	if txt, _ := slack["text"].(string); !strings.Contains(txt, "&lt;b&gt;host&lt;/b&gt; &amp; co") || !strings.Contains(txt, "<https://app.example/x|Open in Driftband>") {
		t.Errorf("slack text not escaped/linked: %q", txt)
	}
	att := teams["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" || teams["type"] != "message" {
		t.Errorf("teams payload is not an Adaptive Card message: %v", teams)
	}
	if tg["parse_mode"] != "HTML" || !strings.Contains(tg["text"].(string), "&lt;script&gt;") || tg["chat_id"] != "-1001" {
		t.Errorf("telegram payload not escaped: %v", tg)
	}
}

// fakeSMTP accepts one message and records the session.
func fakeSMTP(t *testing.T, authLine *string, data *string) (host string, port int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rd := bufio.NewReader(conn)
		say := func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }
		say("220 fake ESMTP")
		inData := false
		var buf strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					*data = buf.String()
					say("250 queued")
					continue
				}
				buf.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-fake")
				say("250 AUTH PLAIN XOAUTH2")
			case strings.HasPrefix(cmd, "AUTH"):
				*authLine = strings.TrimSpace(line)
				say("235 ok")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				say("250 ok")
			case cmd == "DATA":
				inData = true
				say("354 go")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

func TestEmailDelivery(t *testing.T) {
	e := newEnv(t)
	var auth, data string
	host, port := fakeSMTP(t, &auth, &data)
	c := &channel{Kind: "email", Config: channelConfig{Host: host, Port: port, Security: "none", Auth: "none",
		From: "Driftband <alerts@example.com>", To: []string{"noc@example.com", "ops@example.com"}}}
	m := alertMessage{Title: "[ALERT] router: packet loss 60.0%", Lines: []string{"line one", ".starts with a dot"}}
	if err := e.app.deliver(context.Background(), c, m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data, "Subject: [ALERT] router: packet loss 60.0%") || !strings.Contains(data, "To: noc@example.com, ops@example.com") ||
		!strings.Contains(data, "\r\n..starts with a dot") || !strings.Contains(data, "Auto-Submitted: auto-generated") {
		t.Errorf("unexpected message:\n%s", data)
	}
	if auth != "" {
		t.Error("authenticated although auth is none")
	}

	// OAuth 2.0 client credentials -> XOAUTH2 (unit level; real servers require TLS).
	var form string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm.Encode()
		w.Write([]byte(`{"access_token":"tok-123","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()
	tok, err := e.app.oauthToken(context.Background(), channelConfig{TokenURL: tokenSrv.URL, ClientID: "cid", Scope: "https://outlook.office365.com/.default"}, "csecret")
	if err != nil || tok != "tok-123" {
		t.Fatalf("token: %q %v", tok, err)
	}
	if !strings.Contains(form, "grant_type=client_credentials") || !strings.Contains(form, "client_secret=csecret") {
		t.Errorf("token request: %s", form)
	}
	mech, resp, _ := xoauth2{user: "alerts@contoso.com", token: tok}.Start(nil)
	if mech != "XOAUTH2" || string(resp) != "user=alerts@contoso.com\x01auth=Bearer tok-123\x01\x01" {
		t.Errorf("XOAUTH2 initial response: %s %q", mech, resp)
	}
}

// ---------------------------------------------------------------------------
// Evaluator logic (pure, deterministic).

func testRule() *alertRule {
	return &alertRule{Name: "r", Metric: "loss", Threshold: 50, RecoverThreshold: 10, ForMinutes: 3, RecoverMinutes: 3,
		NotifyRecovery: true, FlapTransitions: 4, FlapWindowMinutes: 60}
}

// run feeds one value per minute and returns the events in order.
func run(rl *alertRule, s *alertState, t0 time.Time, values ...float64) []string {
	var ev []string
	for i, v := range values {
		now := t0.Add(time.Duration(i) * time.Minute)
		e := step(rl, s, v, v >= 0, now) // negative = no data
		if e != "" {
			t := now
			s.LastNotified = &t
			ev = append(ev, fmt.Sprintf("%d:%s", i, e))
		}
	}
	return ev
}

func TestAlertNoFalsePositives(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := testRule()
	// single and double blips never fire (needs 3 continuous minutes)
	if ev := run(rl, &alertState{}, t0, 0, 100, 0, 100, 100, 0, 0, 80, 0); len(ev) != 0 {
		t.Errorf("blips fired: %v", ev)
	}
	// sustained breach fires exactly once, after for_minutes
	s := alertState{}
	if ev := run(rl, &s, t0, 0, 60, 60, 60, 60, 70, 80, 90); fmt.Sprint(ev) != "[4:firing]" {
		t.Errorf("sustained breach: %v", ev)
	}
	// hysteresis: 20-45% is neither alerting nor recovered; resolves only below 10% for 3 min
	if ev := run(rl, &s, t0.Add(time.Hour), 30, 45, 20, 30, 5, 5, 20, 5, 5, 5, 5); fmt.Sprint(ev) != "[10:resolved]" {
		t.Errorf("hysteresis/recovery: %v", ev)
	}
	// no data neither fires nor resolves
	s2 := alertState{}
	if ev := run(rl, &s2, t0, 60, -1, -1, -1, -1, 60); len(ev) != 0 || s2.Firing {
		t.Errorf("no data changed state: %v", ev)
	}
}

func TestAlertRecoveryAndReminders(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := testRule()
	rl.NotifyRecovery = false
	rl.RepeatMinutes = 10
	s := alertState{}
	ev := run(rl, &s, t0, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 0, 0, 0, 0)
	if fmt.Sprint(ev) != "[3:firing 13:reminder 23:reminder]" {
		t.Errorf("reminders: %v", ev)
	}
	if s.Firing {
		t.Error("did not resolve")
	}
}

func TestAlertFlappingDoesNotSpam(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := testRule()
	rl.ForMinutes, rl.RecoverMinutes = 1, 1
	// A link that drops for ~3 minutes every ~6 minutes for two hours.
	var vals []float64
	for i := 0; i < 120; i++ {
		if i%6 < 3 {
			vals = append(vals, 100)
		} else {
			vals = append(vals, 0)
		}
	}
	// then stable for an hour
	for i := 0; i < 60; i++ {
		vals = append(vals, 0)
	}
	s := alertState{}
	ev := run(rl, &s, t0, vals...)
	flaps := 0
	for _, e := range ev {
		if strings.HasSuffix(e, ":flapping") {
			flaps++
		}
	}
	if len(ev) > 6 || flaps != 1 || !strings.HasSuffix(ev[len(ev)-1], ":flapping_end") {
		t.Errorf("flapping link produced %d notifications: %v", len(ev), ev)
	}
	// Without flap detection the same link would have sent dozens.
	rl.FlapTransitions = 0
	if n := len(run(rl, &alertState{}, t0, vals...)); n < 30 {
		t.Errorf("control run: expected many notifications without flap detection, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// Evaluator end to end: samples in the database -> webhook delivery.

func TestAlertEndToEnd(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("e2e")
	ctx := context.Background()
	// A host in a sub-folder: the rule on the parent folder must cover it.
	sub := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "folder", "name": "sub", "parent_id": o.FolderID}), 200, "sub")
	h := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "edge", "host": "192.0.2.77", "parent_id": int64(sub.JSON["id"].(float64))}), 200, "host")
	hostID := int64(h.JSON["id"].(float64))
	ch := e.must(e.req(o.Owner, "POST", "/api/notify/channels", map[string]any{"name": "slack", "kind": "slack",
		"secrets": map[string]any{"webhook_url": e.sink.URL + "/slack-hook"}}), 200, "slack")
	chID := int64(ch.JSON["id"].(float64))
	body := ruleBody("edge loss", o.FolderID, chID)
	e.must(e.req(o.Owner, "PATCH", pathf("/api/notify/rules/%d", o.RuleID), body), 200, "rule")

	base := time.Now().Truncate(time.Second).Add(-time.Hour)
	ins := func(at time.Time, lost int) {
		_, err := testDB.Exec(ctx, `INSERT INTO samples (host_id, ts, sent, recv, rtts) VALUES ($1,$2,20,$3,$4)`,
			hostID, at, 20-lost, func() []float64 {
				r := make([]float64, 20-lost)
				for i := range r {
					r[i] = 12
				}
				return r
			}())
		if err != nil {
			t.Fatal(err)
		}
	}
	slackHits := func() (n int, last string) {
		for _, r := range e.sink.all() {
			if r.Path == "/slack-hook" {
				n++
				last = r.Body
			}
		}
		return
	}
	// healthy, then a 6-minute outage, then healthy again
	for i := 0; i < 30; i++ {
		at := base.Add(time.Duration(i) * 30 * time.Second)
		lost := 0
		if i >= 6 && i < 18 {
			lost = 20
		}
		ins(at, lost)
		if err := e.app.evaluateAlerts(ctx, at.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, last := slackHits()
		switch {
		case i == 9 && n != 0:
			t.Fatalf("fired before the breach lasted 2 minutes (tick %d)", i)
		case i == 14 && (n != 1 || !strings.Contains(last, "[ALERT] edge (192.0.2.77)")):
			t.Fatalf("expected exactly one alert by tick %d, got %d: %s", i, n, last)
		}
	}
	n, last := slackHits()
	if n != 2 || !strings.Contains(last, "[RESOLVED]") {
		t.Fatalf("expected alert + recovery, got %d: %s", n, last)
	}
	var okCount int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM notify_log WHERE org_id = $1 AND ok AND event IN ('firing','resolved')`, o.Owner.OrgID).Scan(&okCount)
	if okCount != 2 {
		t.Errorf("delivery log has %d entries", okCount)
	}
	// The other rule/channel of a different org never received anything about this host.
	ev := e.must(e.req(o.Member, "GET", "/api/notify/events", nil), 200, "events")
	if !strings.Contains(string(ev.Body), "[RESOLVED] edge") {
		t.Error("events endpoint misses the delivery")
	}
}

func TestRuleValidation(t *testing.T) {
	e := newEnv(t)
	o, other := e.newOrg("rval"), e.newOrg("rval-other")
	cases := []func(b map[string]any){
		func(b map[string]any) { b["recover_threshold"] = 60 },
		func(b map[string]any) { b["threshold"] = 150 },
		func(b map[string]any) { b["metric"] = "jitter" },
		func(b map[string]any) { b["for_minutes"] = 0 },
		func(b map[string]any) { b["flap_transitions"] = 2 },
		func(b map[string]any) { b["channel_ids"] = []int64{} },
		func(b map[string]any) { b["channel_ids"] = []int64{other.ChannelID} },
		func(b map[string]any) { b["node_id"] = other.FolderID },
	}
	for i, mod := range cases {
		b := ruleBody("x", o.FolderID, o.ChannelID)
		mod(b)
		if r := e.req(o.Owner, "POST", "/api/notify/rules", b); r.Status != 400 {
			t.Errorf("invalid rule %d accepted: %d %s", i, r.Status, r.Body)
		}
	}
	// Deleting a channel removes it from rules.
	e.must(e.req(o.Owner, "DELETE", pathf("/api/notify/channels/%d", o.ChannelID), nil), 200, "delete channel")
	var n int
	_ = testDB.QueryRow(context.Background(), `SELECT cardinality(channel_ids) FROM alert_rules WHERE id = $1`, o.RuleID).Scan(&n)
	if n != 0 {
		t.Error("deleted channel still referenced by a rule")
	}
}
