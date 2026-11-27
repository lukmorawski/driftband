package main

// The Zabbix notification channel (SECURITY-TESTING.md): what is sent to
// the Zabbix API, how its answers are read, and that Zabbix follows the
// state of an alert.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testZabbixToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeZabbix answers history.push like the Zabbix API and records the calls.
type fakeZabbix struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []zabbixCall
	answer string // "" = success
}

type zabbixCall struct {
	Path, Auth, ContentType, Method string
	Host, Key                       string
	Clock, NS                       float64
	Value                           zabbixValue
	RawValue                        string
}

func newFakeZabbix(t *testing.T) *fakeZabbix {
	z := &fakeZabbix{}
	z.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var in struct {
			Method string `json:"method"`
			Params []struct {
				Host  string  `json:"host"`
				Key   string  `json:"key"`
				Value string  `json:"value"`
				Clock float64 `json:"clock"`
				NS    float64 `json:"ns"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &in)
		c := zabbixCall{Path: r.URL.Path, Auth: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type"), Method: in.Method}
		if len(in.Params) == 1 {
			c.Host, c.Key, c.Clock, c.NS, c.RawValue = in.Params[0].Host, in.Params[0].Key, in.Params[0].Clock, in.Params[0].NS, in.Params[0].Value
			_ = json.Unmarshal([]byte(in.Params[0].Value), &c.Value)
		}
		z.mu.Lock()
		z.calls = append(z.calls, c)
		answer := z.answer
		z.mu.Unlock()
		if answer == "" {
			answer = `{"jsonrpc":"2.0","result":{"response":"success","data":[{"itemid":"10600"}]},"id":1}`
		}
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(z.Close)
	return z
}

func (z *fakeZabbix) all() []zabbixCall {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]zabbixCall(nil), z.calls...)
}

func (z *fakeZabbix) answerWith(s string) {
	z.mu.Lock()
	z.answer = s
	z.mu.Unlock()
}

func (e *env) zabbixChannel(a *actor, z *fakeZabbix) int64 {
	e.t.Helper()
	r := e.must(e.req(a, "POST", "/api/notify/channels", map[string]any{"name": "zabbix", "kind": "zabbix",
		"config":  map[string]any{"zabbix_url": z.URL + "/zabbix/", "zabbix_host": "Driftband"},
		"secrets": map[string]any{"api_token": testZabbixToken}}), 200, "zabbix channel")
	return int64(r.JSON["id"].(float64))
}

func TestZabbixChannel(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("zbx")
	z := newFakeZabbix(t)

	bad := []map[string]any{
		{"config": map[string]any{"zabbix_url": "", "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": testZabbixToken}},
		{"config": map[string]any{"zabbix_url": "ftp://zabbix.example.com", "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": testZabbixToken}},
		{"config": map[string]any{"zabbix_url": "https://user:pw@zabbix.example.com", "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": testZabbixToken}},
		{"config": map[string]any{"zabbix_url": "https://zabbix.example.com/?x=1", "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": testZabbixToken}},
		{"config": map[string]any{"zabbix_url": z.URL, "zabbix_host": ""}, "secrets": map[string]any{"api_token": testZabbixToken}},
		{"config": map[string]any{"zabbix_url": z.URL, "zabbix_host": "bad\"host"}, "secrets": map[string]any{"api_token": testZabbixToken}},
		{"config": map[string]any{"zabbix_url": z.URL, "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": ""}},
		{"config": map[string]any{"zabbix_url": z.URL, "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": "short"}},
		{"config": map[string]any{"zabbix_url": z.URL, "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": "with space " + testZabbixToken}},
	}
	for i, b := range bad {
		b["name"], b["kind"] = "z", "zabbix"
		if r := e.req(o.Owner, "POST", "/api/notify/channels", b); r.Status != 400 {
			t.Errorf("bad channel %d accepted: %d %s", i, r.Status, r.Body)
		}
	}

	id := e.zabbixChannel(o.Owner, z)
	r := e.must(e.req(o.Member, "GET", "/api/notify/channels", nil), 200, "list")
	if strings.Contains(string(r.Body), testZabbixToken) || !strings.Contains(string(r.Body), `"api_token":true`) ||
		!strings.Contains(string(r.Body), z.URL+"/zabbix/api_jsonrpc.php") {
		t.Errorf("list leaks the token, hides that it is set, or the URL was not completed: %s", r.Body)
	}
	var sealed []byte
	_ = testDB.QueryRow(context.Background(), `SELECT secret FROM notify_channels WHERE id = $1`, id).Scan(&sealed)
	if len(sealed) == 0 || strings.Contains(string(sealed), testZabbixToken) || strings.Contains(string(sealed), "Driftband") {
		t.Error("channel settings stored in plaintext")
	}

	// the test value, sent with the stored token after an update that does not repeat it
	e.must(e.req(o.Owner, "PATCH", pathf("/api/notify/channels/%d", id), map[string]any{"name": "zabbix 2",
		"config": map[string]any{"zabbix_url": z.URL + "/zabbix/api_jsonrpc.php", "zabbix_host": "Driftband"}}), 200, "update")
	before := time.Now().Unix()
	e.must(e.req(o.Owner, "POST", pathf("/api/notify/channels/%d/test", id), nil), 200, "test")
	calls := z.all()
	if len(calls) != 1 {
		t.Fatalf("%d calls to Zabbix, want 1", len(calls))
	}
	c := calls[0]
	if c.Path != "/zabbix/api_jsonrpc.php" || c.Method != "history.push" || c.Auth != "Bearer "+testZabbixToken ||
		c.ContentType != "application/json-rpc" || c.Host != "Driftband" || c.Key != zabbixItemKey || int64(c.Clock) < before {
		t.Errorf("request to Zabbix: %+v", c)
	}
	if c.Value.Event != "test" || c.Value.Alert != "test" || c.Value.Summary == "" {
		t.Errorf("test value: %s", c.RawValue)
	}

	// answers of the API that mean the value was not taken
	for name, answer := range map[string]string{
		"API error":       `{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params.","data":"Not authorized. ` + testZabbixToken + `"},"id":1}`,
		"refused value":   `{"jsonrpc":"2.0","result":{"response":"success","data":[{"error":"No permissions to referred object or it does not exist."}]},"id":1}`,
		"not a Zabbix":    `<html>welcome</html>`,
		"empty result":    `{"jsonrpc":"2.0","result":{"response":"success","data":[]},"id":1}`,
		"another service": `{"ok":true}`,
	} {
		z.answerWith(answer)
		r := e.req(o.Owner, "POST", pathf("/api/notify/channels/%d/test", id), nil)
		if r.Status != http.StatusBadGateway || strings.Contains(string(r.Body), testZabbixToken) {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	var leaks int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM notify_log WHERE error LIKE '%' || $1 || '%'`, testZabbixToken).Scan(&leaks)
	if leaks > 0 {
		t.Error("API token written to the delivery log")
	}
}

// The values are read by the template with regular expressions: whatever a
// host or a rule is called, the fields it reads stay intact.
func TestZabbixValueIsSafeForTheTemplate(t *testing.T) {
	m := alertMessage{Event: "firing", Link: "https://driftband.example", Alert: &alertData{RuleID: 7, HostID: 42,
		Rule: `loss "wan"`, Host: `edge "a" \ <b>` + "\n" + `","event":"resolved`, Address: "192.0.2.7", Org: "Acme", Metric: "loss", Value: 61.26, Threshold: 50}}
	v, ok := zabbixEvent(m)
	if !ok || v.Event != "problem" || v.Alert != "r7-h42" || v.Metric != "loss" {
		t.Fatalf("value: %+v", v)
	}
	if strings.ContainsAny(v.Summary, "\"\\\n") || !strings.Contains(v.Summary, "packet loss 61.3 %") {
		t.Errorf("summary: %q", v.Summary)
	}
	j, _ := json.Marshal(v)
	if n := strings.Count(string(j), `"event":"`); n != 1 {
		t.Errorf("the value names %d events: %s", n, j)
	}
	m.Event = "resolved"
	if r, ok := zabbixEvent(m); !ok || r.Event != "resolved" || r.Alert != v.Alert {
		t.Errorf("recovery does not match its problem: %+v", r)
	}
	for _, ev := range []string{"reminder", "flapping", "flapping_end"} {
		m.Event = ev
		if _, ok := zabbixEvent(m); ok {
			t.Errorf("%s was turned into a value", ev)
		}
	}
	for in, want := range map[string]string{"https://zabbix.example.com": "https://zabbix.example.com/api_jsonrpc.php",
		"https://example.com/zabbix/": "https://example.com/zabbix/api_jsonrpc.php", "https://example.com/zabbix/api_jsonrpc.php": "https://example.com/zabbix/api_jsonrpc.php"} {
		if got, err := zabbixAPIURL(in); err != nil || got != want {
			t.Errorf("zabbixAPIURL(%s) = %s, %v", in, got, err)
		}
	}
}

// Zabbix gets every change of state exactly once: also from a rule without
// recovery notices, and no reminders.
func TestZabbixFollowsAlertState(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("zbxstate")
	ctx := context.Background()
	z := newFakeZabbix(t)
	zid := e.zabbixChannel(o.Owner, z)
	slack := e.must(e.req(o.Owner, "POST", "/api/notify/channels", map[string]any{"name": "slack", "kind": "slack",
		"secrets": map[string]any{"webhook_url": e.sink.URL + "/zbx-slack"}}), 200, "slack")
	body := ruleBody("wan loss", o.FolderID, zid)
	body["channel_ids"] = []int64{zid, int64(slack.JSON["id"].(float64))}
	body["notify_recovery"] = false
	body["repeat_minutes"] = 1
	body["flap_transitions"] = 0
	e.must(e.req(o.Owner, "PATCH", pathf("/api/notify/rules/%d", o.RuleID), body), 200, "rule")
	_, _ = testDB.Exec(ctx, `DELETE FROM samples WHERE host_id = $1`, o.HostID)

	base := time.Now().Truncate(time.Second).Add(-time.Hour)
	for i := 0; i < 34; i++ {
		at := base.Add(time.Duration(i) * 30 * time.Second)
		recv := 20
		if i >= 4 && i < 20 {
			recv = 0
		}
		if _, err := testDB.Exec(ctx, `INSERT INTO samples (host_id, ts, sent, recv, rtts) VALUES ($1,$2,20,$3,$4)`,
			o.HostID, at, recv, make([]float64, recv)); err != nil {
			t.Fatal(err)
		}
		if err := e.app.evaluateAlerts(ctx, at.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	calls := z.all()
	if len(calls) != 2 {
		t.Fatalf("Zabbix got %d values, want a problem and its recovery: %+v", len(calls), calls)
	}
	p, r := calls[0].Value, calls[1].Value
	if p.Event != "problem" || r.Event != "resolved" || p.Alert == "" || p.Alert != r.Alert || p.Rule != "wan loss" ||
		p.Organization == "" || p.Address != "192.0.2.1" || p.Value == nil || *p.Value != 100 || p.Threshold == nil || *p.Threshold != 50 {
		t.Errorf("problem %s\nrecovery %s", calls[0].RawValue, calls[1].RawValue)
	}
	if calls[0].Clock == calls[1].Clock && calls[0].NS == calls[1].NS {
		t.Error("two values carry the same timestamp (Zabbix drops the second)")
	}
	// the message channel behaved as configured: an alert, reminders, no recovery notice
	var reminders, recoveries int
	for _, s := range e.sink.all() {
		if s.Path == "/zbx-slack" {
			if strings.Contains(s.Body, "[STILL FIRING]") {
				reminders++
			}
			if strings.Contains(s.Body, "[RESOLVED]") {
				recoveries++
			}
		}
	}
	if reminders == 0 || recoveries != 0 {
		t.Errorf("slack: %d reminders, %d recovery notices", reminders, recoveries)
	}
	var logged int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM notify_log WHERE channel_id = $1 AND ok AND event IN ('firing','resolved')`, zid).Scan(&logged)
	if logged != 2 {
		t.Errorf("delivery log has %d Zabbix entries, want 2", logged)
	}
}

// Private addresses stay refused unless the operator allows them, and then
// https is still required.
func TestZabbixPrivateTargets(t *testing.T) {
	e := newEnv(t)
	e.app.allowPrivateTargets = false
	o := e.newOrg("zbxssrf")
	ch := func(u string) int {
		return e.req(o.Owner, "POST", "/api/notify/channels", map[string]any{"name": "z", "kind": "zabbix",
			"config": map[string]any{"zabbix_url": u, "zabbix_host": "Driftband"}, "secrets": map[string]any{"api_token": testZabbixToken}}).Status
	}
	for _, u := range []string{"https://127.0.0.1/zabbix", "https://10.0.0.5", "https://192.168.1.10/zabbix", "https://[::1]/", "http://zabbix.example.com"} {
		if s := ch(u); s != 400 {
			t.Errorf("%s accepted: %d", u, s)
		}
	}
	e.app.privateTargets = true
	if s := ch("https://10.0.0.5/zabbix"); s != 200 {
		t.Errorf("private address with NOTIFY_PRIVATE_TARGETS: %d", s)
	}
	for _, u := range []string{"http://10.0.0.5/zabbix", "http://zabbix.example.com"} {
		if s := ch(u); s != 400 {
			t.Errorf("%s accepted over plain http: %d", u, s)
		}
	}
}
