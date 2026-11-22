package main

// Paged lists (audit logs, notification history) and the platform
// administrator's organization tools: the hosts an organization monitors
// and deleting an organization with everything it owns.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPagedLists(t *testing.T) {
	e := newEnv(t)
	o, other := e.newOrg("page"), e.newOrg("page-other")
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		e.must(e.req(o.Owner, "POST", "/api/account/name", map[string]any{"first_name": pathf("n%d", i), "last_name": "x"}), 200, "activity")
	}
	var want int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE org_id = $1`, o.Owner.OrgID).Scan(&want)
	ids := func(r *resp) []int64 {
		var out []int64
		for _, it := range items(r) {
			out = append(out, int64(it.(map[string]any)["id"].(float64)))
		}
		return out
	}

	// Default page: 10 rows, newest first, with the organization's total.
	first := e.must(e.req(o.Member, "GET", "/api/audit", nil), 200, "audit")
	if got := ids(first); len(got) != pageSizeDefault || int(first.JSON["total"].(float64)) != want {
		t.Fatalf("default page: %d rows, total %v, want 10 of %d", len(got), first.JSON["total"], want)
	}
	seen := map[int64]bool{}
	var prev int64
	for off := 0; off < want; off += 20 {
		page := ids(e.must(e.req(o.Member, "GET", pathf("/api/audit?limit=20&offset=%d", off), nil), 200, "page"))
		if len(page) != min(20, want-off) {
			t.Errorf("offset %d: %d rows, want %d", off, len(page), min(20, want-off))
		}
		for _, id := range page {
			if seen[id] || (prev != 0 && id >= prev) {
				t.Fatalf("offset %d: entry %d repeated or out of order", off, id)
			}
			seen[id], prev = true, id
		}
	}
	if len(seen) != want {
		t.Errorf("paging covered %d of %d entries", len(seen), want)
	}
	// Bounds: the limit is clamped to 1-200, junk falls back to the default,
	// an offset past the end is an empty page with the same total.
	for q, rows := range map[string]int{
		"limit=100000": min(want, pageSizeMax), "limit=0": 1, "limit=-5": 1, "limit=abc": pageSizeDefault,
		"limit=50&offset=-9": min(want, 50), "limit=10&offset=999999": 0, "limit=10&offset=99999999999999": 0,
	} {
		r := e.must(e.req(o.Member, "GET", "/api/audit?"+q, nil), 200, q)
		if len(items(r)) != rows || int(r.JSON["total"].(float64)) != want {
			t.Errorf("%s: %d rows (want %d), total %v (want %d)", q, len(items(r)), rows, r.JSON["total"], want)
		}
	}
	// Paging never crosses the tenant boundary.
	all := e.must(e.req(o.Member, "GET", "/api/audit?limit=200", nil), 200, "all")
	for _, em := range []string{other.Owner.Email, other.Admin.Email, other.Member.Email} {
		if strings.Contains(string(all.Body), em) {
			t.Errorf("audit page shows another organization's user %s", em)
		}
	}

	// Global audit log: the same paging on top of its filters.
	sa := e.superadmin()
	g := e.must(e.req(sa, "GET", pathf("/api/admin/audit?org=%d", o.Owner.OrgID), nil), 200, "global")
	if len(items(g)) != pageSizeDefault || int(g.JSON["total"].(float64)) != want {
		t.Errorf("global audit, org filter: %d rows, total %v, want 10 of %d", len(items(g)), g.JSON["total"], want)
	}
	g2 := e.must(e.req(sa, "GET", pathf("/api/admin/audit?org=%d&limit=20&offset=%d", o.Owner.OrgID, want-3), nil), 200, "global tail")
	if len(items(g2)) != 3 {
		t.Errorf("global audit tail: %d rows, want 3", len(items(g2)))
	}
	if r := e.must(e.req(sa, "GET", pathf("/api/admin/audit?org=%d&action=account.name&limit=200", o.Owner.OrgID), nil), 200, "filtered"); int(r.JSON["total"].(float64)) != 25 || len(items(r)) != 25 {
		t.Errorf("global audit, action filter: %d rows, total %v, want 25", len(items(r)), r.JSON["total"])
	}

	// Notification history.
	for i := 0; i < 15; i++ {
		if _, err := testDB.Exec(ctx, `INSERT INTO notify_log (org_id, rule_id, host_id, channel_id, event, message, ok)
			VALUES ($1, $2, $3, $4, 'firing', $5, true)`, o.Owner.OrgID, o.RuleID, o.HostID, o.ChannelID, pathf("msg %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = testDB.Exec(ctx, `INSERT INTO notify_log (org_id, event, message, ok) VALUES ($1, 'firing', 'foreign message', true)`, other.Owner.OrgID)
	ev := e.must(e.req(o.Member, "GET", "/api/notify/events", nil), 200, "events")
	log, _ := ev.JSON["log"].([]any)
	if len(log) != pageSizeDefault || int(ev.JSON["log_total"].(float64)) != 15 {
		t.Fatalf("events default page: %d rows, total %v, want 10 of 15", len(log), ev.JSON["log_total"])
	}
	if log[0].(map[string]any)["message"] != "msg 14" {
		t.Errorf("history is not newest first: %v", log[0])
	}
	ev = e.must(e.req(o.Member, "GET", "/api/notify/events?limit=10&offset=10", nil), 200, "events page 2")
	if log, _ = ev.JSON["log"].([]any); len(log) != 5 || log[4].(map[string]any)["message"] != "msg 0" {
		t.Errorf("events second page: %d rows", len(log))
	}
	if strings.Contains(string(e.must(e.req(o.Member, "GET", "/api/notify/events?limit=200", nil), 200, "events all").Body), "foreign message") {
		t.Error("notification history shows another organization's delivery")
	}
}

func TestAdminOrgHosts(t *testing.T) {
	e := newEnv(t)
	sa, o, other := e.superadmin(), e.newOrg("ohosts"), e.newOrg("ohosts-other")
	h := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{
		"kind": "host", "name": "top level", "host": "198.51.100.7", "description": "edge", "profile_id": o.ProfileID}), 200, "host")
	topID := int64(h.JSON["id"].(float64))
	r := e.must(e.req(sa, "GET", pathf("/api/admin/orgs/%d/hosts", o.Owner.OrgID), nil), 200, "hosts")
	if len(r.List) != 2 {
		t.Fatalf("want the organization's 2 hosts, got %d: %s", len(r.List), r.Body)
	}
	byID := map[int64]map[string]any{}
	for _, it := range r.List {
		m := it.(map[string]any)
		byID[int64(m["id"].(float64))] = m
	}
	top, nested := byID[topID], byID[o.HostID]
	if top == nil || nested == nil {
		t.Fatalf("hosts missing: %s", r.Body)
	}
	if top["path"] != "" || top["host"] != "198.51.100.7" || top["description"] != "edge" || top["profile"] != "ohosts profile" ||
		top["default_profile"] != false || top["interval_s"].(float64) != 60 || top["ping_count"].(float64) != 5 || top["packet_size"].(float64) != 56 ||
		top["last_ts"].(float64) != 0 {
		t.Errorf("top-level host: %v", top)
	}
	// The seeded host sits in a folder, uses the default profile and has samples.
	if nested["path"] != "ohosts folder" || nested["default_profile"] != true || nested["profile"] != "Standard" ||
		nested["interval_s"].(float64) != 60 || nested["ping_count"].(float64) != 20 ||
		nested["last_ts"].(float64) == 0 || nested["last_sent"].(float64) != 5 || nested["last_recv"].(float64) != 5 {
		t.Errorf("nested host: %v", nested)
	}
	if strings.Contains(string(r.Body), "192.0.2.1\",\"description\":\"\",\"path\":\"ohosts-other") || strings.Contains(string(r.Body), "ohosts-other") {
		t.Error("another organization's hosts are listed")
	}
	// The parameters are the ones the prober uses: on a test instance a
	// 30 s / 1400 B profile runs at 60 s / 56 B unless the org is exempt.
	e.must(e.req(o.Owner, "PATCH", pathf("/api/profiles/%d", o.ProfileID), map[string]any{"name": "ohosts profile", "interval_s": 30, "ping_count": 30, "packet_size": 1400, "is_default": false}), 200, "profile")
	e.app.testMode = true
	r = e.must(e.req(sa, "GET", pathf("/api/admin/orgs/%d/hosts", o.Owner.OrgID), nil), 200, "hosts, test instance")
	for _, it := range r.List {
		if m := it.(map[string]any); int64(m["id"].(float64)) == topID && (m["interval_s"].(float64) != 60 || m["packet_size"].(float64) != 56 || m["ping_count"].(float64) != 30) {
			t.Errorf("test-instance limits not reflected: %v", m)
		}
	}
	e.app.testMode = false
	if spec := mustHost(t, e, topID); spec.intervalS != 30 || spec.packetSize != 1400 {
		t.Errorf("prober spec differs from the test's assumption: %+v", spec)
	}
	if r := e.req(sa, "GET", "/api/admin/orgs/999999999/hosts", nil); r.Status != 404 {
		t.Errorf("unknown organization: %d", r.Status)
	}
	if r := e.req(sa, "GET", "/api/admin/orgs/abc/hosts", nil); r.Status != 400 {
		t.Errorf("bad id: %d", r.Status)
	}
	_ = other
}

func TestAdminDeleteOrg(t *testing.T) {
	e := newEnv(t)
	sa, o, other := e.superadmin(), e.newOrg("delorg"), e.newOrg("delorg-other")
	ctx := context.Background()
	orgID := o.Owner.OrgID
	name := orgName(t, orgID)
	// Everything an organization can own: rollups, alert state, deliveries.
	hour := time.Now().Truncate(time.Hour).Unix()
	if err := newRollupWorker(testDB).rollRange(ctx, o.HostID, hour-3600, hour+3600); err != nil {
		t.Fatal(err)
	}
	e.app.saveState(ctx, o.RuleID, o.HostID, alertState{Since: time.Now(), Firing: true})
	if _, err := testDB.Exec(ctx, `INSERT INTO notify_log (org_id, rule_id, host_id, channel_id, event, message, ok)
		VALUES ($1, $2, $3, $4, 'firing', 'm', true)`, orgID, o.RuleID, o.HostID, o.ChannelID); err != nil {
		t.Fatal(err)
	}
	userIDs := []int64{o.Owner.ID, o.Admin.ID, o.Member.ID}
	// a passkey, a pending key enrollment and a profile picture
	e.enroll(o.Member, "passkey", true)
	e.must(e.req(o.Admin, "POST", "/api/account/webauthn/register/begin", map[string]any{"password": o.Admin.Password, "kind": "key"}), 200, "pending enrollment")
	e.must(e.req(o.Owner, "POST", "/api/account/avatar", avatarBody("image/png", testPNG(t, 64, 64, false))), 200, "picture")
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := testDB.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// what belongs to the organization, by table
	owned := map[string]func() int{
		"organizations":   func() int { return count(`SELECT count(*) FROM organizations WHERE id = $1`, orgID) },
		"users":           func() int { return count(`SELECT count(*) FROM users WHERE org_id = $1`, orgID) },
		"sessions":        func() int { return count(`SELECT count(*) FROM sessions WHERE user_id = ANY($1)`, userIDs) },
		"invites":         func() int { return count(`SELECT count(*) FROM invites WHERE org_id = $1`, orgID) },
		"probe_profiles":  func() int { return count(`SELECT count(*) FROM probe_profiles WHERE org_id = $1`, orgID) },
		"nodes":           func() int { return count(`SELECT count(*) FROM nodes WHERE org_id = $1`, orgID) },
		"samples":         func() int { return count(`SELECT count(*) FROM samples WHERE host_id = $1`, o.HostID) },
		"sample_rollups":  func() int { return count(`SELECT count(*) FROM sample_rollups WHERE host_id = $1`, o.HostID) },
		"rollup_state":    func() int { return count(`SELECT count(*) FROM rollup_state WHERE host_id = $1`, o.HostID) },
		"notify_channels": func() int { return count(`SELECT count(*) FROM notify_channels WHERE org_id = $1`, orgID) },
		"alert_rules":     func() int { return count(`SELECT count(*) FROM alert_rules WHERE org_id = $1`, orgID) },
		"alert_state":     func() int { return count(`SELECT count(*) FROM alert_state WHERE host_id = $1`, o.HostID) },
		"notify_log":      func() int { return count(`SELECT count(*) FROM notify_log WHERE org_id = $1`, orgID) },
		"audit_log":       func() int { return count(`SELECT count(*) FROM audit_log WHERE org_id = $1`, orgID) },
		"webauthn_credentials": func() int {
			return count(`SELECT count(*) FROM webauthn_credentials WHERE user_id = ANY($1)`, userIDs)
		},
		"webauthn_challenges": func() int {
			return count(`SELECT count(*) FROM webauthn_challenges WHERE user_id = ANY($1)`, userIDs)
		},
		"user_avatars": func() int { return count(`SELECT count(*) FROM user_avatars WHERE user_id = ANY($1)`, userIDs) },
	}
	for table, n := range owned {
		if n() == 0 {
			t.Fatalf("setup: the organization has no %s rows", table)
		}
	}
	path := pathf("/api/admin/orgs/%d/delete", orgID)
	intact := func(why string) {
		t.Helper()
		if owned["organizations"]() != 1 || owned["users"]() != 3 || owned["samples"]() == 0 {
			t.Fatalf("%s: the organization was touched", why)
		}
	}

	// Refusals: wrong password (audited), wrong or missing name, unknown id,
	// the administrator's own organization, one with a platform administrator.
	t0 := dbNow(t)
	if r := e.req(sa, "POST", path, map[string]any{"password": "not-the-password", "name": name}); r.Status != 403 {
		t.Errorf("wrong password: %d", r.Status)
	}
	if !auditHas(t, sa.OrgID, sa.Email, "denied.admin.org_delete", t0) {
		t.Error("refused delete (wrong password) not audited")
	}
	intact("wrong password")
	for _, wrong := range []string{"", name + "x", strings.ToUpper(name), "Org delorg-other"} {
		if r := e.req(sa, "POST", path, map[string]any{"password": sa.Password, "name": wrong}); r.Status != 400 {
			t.Errorf("name %q: %d, want 400", wrong, r.Status)
		}
	}
	intact("wrong name")
	if r := e.req(sa, "POST", path, map[string]any{"password": sa.Password}); r.Status != 400 {
		t.Errorf("no name: %d", r.Status)
	}
	if r := e.req(sa, "POST", "/api/admin/orgs/999999999/delete", map[string]any{"password": sa.Password, "name": name}); r.Status != 404 {
		t.Errorf("unknown organization: %d", r.Status)
	}
	if r := e.req(sa, "POST", pathf("/api/admin/orgs/%d/delete", sa.OrgID), map[string]any{"password": sa.Password, "name": orgName(t, sa.OrgID)}); r.Status != 400 {
		t.Errorf("own organization: %d", r.Status)
	}
	sa2 := e.superadmin()
	if r := e.req(sa, "POST", pathf("/api/admin/orgs/%d/delete", sa2.OrgID), map[string]any{"password": sa.Password, "name": orgName(t, sa2.OrgID)}); r.Status != 403 {
		t.Errorf("organization of another platform administrator: %d", r.Status)
	}
	if count(`SELECT count(*) FROM organizations WHERE id = ANY($1)`, []int64{sa.OrgID, sa2.OrgID}) != 2 {
		t.Fatal("a protected organization was deleted")
	}
	// A tenant owner cannot delete anything, not even their own organization.
	if r := e.req(o.Owner, "POST", path, map[string]any{"password": o.Owner.Password, "name": name}); r.Status != 403 {
		t.Errorf("tenant owner: %d", r.Status)
	}
	intact("tenant owner")

	// The real thing.
	if spec := mustHost(t, e, o.HostID); spec.id != o.HostID {
		t.Fatal("setup: host not probed")
	}
	t0 = dbNow(t)
	r := e.must(e.req(sa, "POST", path, map[string]any{"password": sa.Password, "name": name}, "X-Forwarded-For: 203.0.113.50"), 200, "delete organization")
	if r.JSON["users"].(float64) != 3 || r.JSON["hosts"].(float64) != 1 {
		t.Errorf("reported counts: %s", r.Body)
	}
	for table, n := range owned {
		if left := n(); left != 0 {
			t.Errorf("%s: %d rows left after deleting the organization", table, left)
		}
	}
	if count(`SELECT count(*) FROM samples s WHERE NOT EXISTS (SELECT 1 FROM nodes n WHERE n.id = s.host_id)`) != 0 {
		t.Error("orphan samples left behind")
	}
	// Its people are gone: no sign-in, old sessions dead, the email is free again.
	if s := e.login(o.Owner.Email, o.Owner.Password, "").Status; s != 401 {
		t.Errorf("deleted owner signs in: %d", s)
	}
	for _, a := range []*actor{o.Owner, o.Admin, o.Member} {
		if s := e.req(a, "GET", "/api/me", nil).Status; s != 401 {
			t.Errorf("%s session survived: %d", a.Role, s)
		}
	}
	e.must(e.req(anon, "POST", "/api/auth/register-org", map[string]any{"org_name": "Reborn", "email": o.Owner.Email, "password": "Reborn-pass-123"}), 200, "re-register the freed email")
	if _, probed := func() (hostSpec, bool) { h, _ := e.app.pm.loadHosts(ctx); s, ok := h[o.HostID]; return s, ok }(); probed {
		t.Error("the deleted organization's host is still probed")
	}
	// The bystander is untouched.
	if count(`SELECT count(*) FROM users WHERE org_id = $1`, other.Owner.OrgID) != 3 || count(`SELECT count(*) FROM samples WHERE host_id = $1`, other.HostID) == 0 {
		t.Error("another organization lost data")
	}
	e.must(e.req(other.Member, "GET", "/api/tree", nil), 200, "bystander still works")

	// The deletion is on record in the system log, with who did it and from
	// where; platform administrators see it, tenants do not.
	var email, detail, ip string
	if err := testDB.QueryRow(ctx, `SELECT user_email, detail, ip FROM audit_log
		WHERE org_id IS NULL AND action = 'admin.org_delete' AND created_at >= $1 ORDER BY id DESC LIMIT 1`, t0).Scan(&email, &detail, &ip); err != nil {
		t.Fatalf("deletion not in the system log: %v", err)
	}
	if email != sa.Email || ip != "203.0.113.50" || !strings.Contains(detail, name) || !strings.Contains(detail, "3 users, 1 hosts") {
		t.Errorf("system log entry: %s | %s | %s", email, detail, ip)
	}
	if g := e.must(e.req(sa, "GET", "/api/admin/audit?org=system&action=admin.org_delete", nil), 200, "global audit"); !strings.Contains(string(g.Body), name) {
		t.Error("global audit log does not show the deletion")
	}
	if a := e.must(e.req(other.Owner, "GET", "/api/audit?limit=200", nil), 200, "tenant audit"); strings.Contains(string(a.Body), "admin.org_delete") {
		t.Error("a tenant sees the deletion of another organization")
	}
	// Deleting twice is a clean 404.
	if r := e.req(sa, "POST", path, map[string]any{"password": sa.Password, "name": name}); r.Status != 404 {
		t.Errorf("second delete: %d", r.Status)
	}
}
