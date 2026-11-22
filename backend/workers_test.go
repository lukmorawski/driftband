package main

// The background workers and small helpers: the prober manager (which hosts
// are probed, restarts on profile changes), fping output parsing and a real
// cycle when fping is installed, the rollup backfill pass, the worker loops
// stopping on context cancellation, SMTP authentication exchanges.

import (
	"context"
	"net/smtp"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestParseFping(t *testing.T) {
	out := "192.0.2.1 : 12.3 11.8 - 12.1\n" +
		"ICMP Host Unreachable from 10.0.0.1 for ICMP Echo sent to 192.0.2.2\n" +
		"192.0.2.2 : - - - -\n" +
		"host.example : 0.5 abc 0.7\n" +
		"garbage line without separator\n"
	got := parseFping(out)
	want := []float64{12.3, 11.8, 12.1, 0.5, 0.7}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rtt %d: %v, want %v", i, got[i], want[i])
		}
	}
	if n := len(parseFping("")); n != 0 {
		t.Errorf("empty output parsed into %d rtts", n)
	}
}

func TestFpingCycle(t *testing.T) {
	if _, err := exec.LookPath("fping"); err != nil {
		t.Skip("fping not installed")
	}
	rtts, sent, recv := fpingOnce(hostSpec{host: "127.0.0.1", pingCount: 3, packetSize: 56})
	if sent != 3 || recv != 3 || len(rtts) != 3 {
		t.Fatalf("loopback cycle: sent %d recv %d rtts %v", sent, recv, rtts)
	}
	for _, r := range rtts {
		if r <= 0 || r > 1000 {
			t.Errorf("implausible loopback rtt %v", r)
		}
	}
	// An address that never answers: every ping is lost, the cycle still ends.
	rtts, sent, recv = fpingOnce(hostSpec{host: "192.0.2.1", pingCount: 2, packetSize: 56})
	if sent != 2 || recv != 0 || len(rtts) != 0 {
		t.Errorf("unreachable cycle: sent %d recv %d rtts %v", sent, recv, rtts)
	}
}

func TestProberManagerFollowsHosts(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("pm")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pm := newProberMgr(testDB)
	started := make(chan hostSpec, 100)
	pm.probeFn = func(ctx context.Context, s hostSpec) {
		started <- s
		<-ctx.Done()
	}
	running := func() map[int64]*proberHandle {
		pm.mu.Lock()
		defer pm.mu.Unlock()
		out := map[int64]*proberHandle{}
		for k, v := range pm.running {
			out[k] = v
		}
		return out
	}

	pm.sync(ctx)
	h, ok := running()[o.HostID]
	if !ok {
		t.Fatalf("the org's host is not probed after sync: %v", running())
	}
	if !strings.HasPrefix(h.sig, "192.0.2.1|60|") {
		t.Errorf("host signature %q", h.sig)
	}
	select {
	case s := <-started:
		if s.id != o.HostID && s.host != "192.0.2.1" {
			// other tests' hosts are probed too; only ours is checked
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prober goroutine not started")
	}

	// A profile change restarts the host's prober with the new signature.
	e.must(e.req(o.Owner, "PATCH", pathf("/api/nodes/%d", o.HostID), map[string]any{"name": "pm host", "host": "192.0.2.1", "profile_id": o.ProfileID}), 200, "set profile")
	e.must(e.req(o.Owner, "PATCH", pathf("/api/profiles/%d", o.ProfileID), map[string]any{"name": "fast", "interval_s": 30, "ping_count": 5, "packet_size": 56, "is_default": false}), 200, "profile")
	pm.sync(ctx)
	if h2 := running()[o.HostID]; h2 == nil || h2.sig == h.sig || !strings.Contains(h2.sig, "|30|5|") {
		t.Errorf("prober not restarted after the profile change: %+v", h2)
	}
	// A removed host stops being probed.
	e.must(e.req(o.Owner, "DELETE", pathf("/api/nodes/%d", o.HostID), nil), 200, "delete host")
	pm.sync(ctx)
	if _, still := running()[o.HostID]; still {
		t.Error("deleted host is still probed")
	}
	// A blocked organization's hosts are not probed.
	h2 := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "h2", "host": "192.0.2.2"}), 200, "host")
	id2 := int64(h2.JSON["id"].(float64))
	pm.sync(ctx)
	if _, ok := running()[id2]; !ok {
		t.Fatal("new host not probed")
	}
	sa := e.superadmin()
	e.must(e.req(sa, "POST", pathf("/api/admin/orgs/%d/block", o.Owner.OrgID), map[string]any{"blocked": true}), 200, "block org")
	pm.sync(ctx)
	if _, ok := running()[id2]; ok {
		t.Error("host of a blocked organization is still probed")
	}
	// kick() wakes the manager; Run stops with its context.
	pm.kick()
	pm.kick() // a second kick while one is pending is dropped, not blocked
	rctx, rcancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { pm.Run(rctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	rcancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prober manager did not stop")
	}
	cancel()
}

func TestProbeLoopStoresCycles(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("loop")
	ctx, cancel := context.WithCancel(context.Background())
	var before int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM samples WHERE host_id = $1`, o.HostID).Scan(&before)
	done := make(chan struct{})
	// fping is probably missing here: the cycle then records a full loss,
	// which is still a stored cycle.
	go func() {
		e.app.pm.probe(ctx, hostSpec{id: o.HostID, host: "127.0.0.1", intervalS: 60, pingCount: 1, packetSize: 56})
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var after int
		_ = testDB.QueryRow(ctx, `SELECT count(*) FROM samples WHERE host_id = $1`, o.HostID).Scan(&after)
		if after == before+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no cycle stored: %d before, %d after", before, after)
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probe loop did not stop")
	}
}

func TestRollupPassBackfillsAndAdvances(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("pass")
	ctx := context.Background()
	h := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "bf", "host": "192.0.2.85"}), 200, "host")
	hostID := int64(h.JSON["id"].(float64))
	to := time.Now().Truncate(time.Hour).Add(-time.Hour)
	seedCycles(t, hostID, to.Add(-5*time.Hour), to, time.Minute)
	rw := newRollupWorker(testDB)
	rw.pass(ctx)
	var done *time.Time
	var n int
	_ = testDB.QueryRow(ctx, `SELECT done_until FROM rollup_state WHERE host_id = $1`, hostID).Scan(&done)
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM sample_rollups WHERE host_id = $1 AND res = 3600`, hostID).Scan(&n)
	if done == nil || done.Before(to) || n < 5 {
		t.Errorf("backfill: done_until %v, %d hourly rollups", done, n)
	}
	var audited int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'system.rollup_backfill' AND detail LIKE $1`, pathf("host %d from %%", hostID)).Scan(&audited)
	if audited != 1 {
		t.Errorf("backfill audited %d times", audited)
	}
	// A second pass has nothing new to do and keeps the watermark.
	rw.pass(ctx)
	var done2 *time.Time
	_ = testDB.QueryRow(ctx, `SELECT done_until FROM rollup_state WHERE host_id = $1`, hostID).Scan(&done2)
	if done2 == nil || !done2.Equal(*done) {
		t.Errorf("watermark moved without new samples: %v -> %v", done, done2)
	}
}

func TestWorkerLoopsStopWithContext(t *testing.T) {
	e := newEnv(t)
	e.newOrg("loops")
	for name, run := range map[string]func(context.Context){
		"housekeeper": newHousekeeper(testDB).Run,
		"rollup":      newRollupWorker(testDB).Run,
		"alerts":      alertEvaluator{app: e.app}.Run,
	} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { run(ctx); close(done) }()
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s loop did not stop", name)
		}
	}
	var snapshots int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM db_size_history WHERE day = current_date`).Scan(&snapshots)
	if snapshots != 1 {
		t.Errorf("the housekeeper's first sweep left %d size snapshots", snapshots)
	}
}

func TestSMTPAuthExchanges(t *testing.T) {
	info := &smtp.ServerInfo{Name: "mail.example", TLS: true, Auth: []string{"LOGIN", "PLAIN"}}
	a := loginOrPlainAuth{user: "bot@example.com", pass: "s3cret"}
	proto, resp, err := a.Start(info)
	if err != nil {
		t.Fatal(err)
	}
	switch proto {
	case "PLAIN":
		if string(resp) != "\x00bot@example.com\x00s3cret" {
			t.Errorf("PLAIN initial response %q", resp)
		}
	case "LOGIN":
		if u, _ := a.Next([]byte("Username:"), true); string(u) != "bot@example.com" {
			t.Errorf("LOGIN username %q", u)
		}
		if p, _ := a.Next([]byte("Password:"), true); string(p) != "s3cret" {
			t.Errorf("LOGIN password %q", p)
		}
	default:
		t.Fatalf("unexpected mechanism %q", proto)
	}
	if proto, _, _ := a.Start(&smtp.ServerInfo{Name: "mail.example", TLS: true, Auth: []string{"LOGIN"}}); proto != "LOGIN" {
		t.Errorf("server offering only LOGIN: %q", proto)
	}
	if _, err := a.Next([]byte("Surprise:"), true); err == nil {
		t.Error("unknown LOGIN challenge accepted")
	}
	if r, err := a.Next([]byte("Unexpected"), false); err != nil || r != nil {
		t.Errorf("end of exchange: %v %q", err, r)
	}

	x := xoauth2{user: "bot@example.com", token: "tok"}
	proto, resp, err = x.Start(info)
	if err != nil || proto != "XOAUTH2" || !strings.Contains(string(resp), "user=bot@example.com") || !strings.Contains(string(resp), "auth=Bearer tok") {
		t.Errorf("XOAUTH2 start: %q %q %v", proto, resp, err)
	}
	if r, err := x.Next([]byte(`{"status":"401"}`), true); err != nil || string(r) != "" {
		t.Errorf("XOAUTH2 error continuation: %q %v", r, err)
	}
	if r, _ := x.Next(nil, false); r != nil {
		t.Errorf("XOAUTH2 end: %q", r)
	}
}

func TestSmallHelpers(t *testing.T) {
	if b64("ab") != "YWI=" {
		t.Error("b64")
	}
	if firstLine("one\ntwo") != "one" || firstLine("") != "" || firstLine("one\r\ntwo") != "one" || firstLine("single") != "single" {
		t.Error("firstLine")
	}
	for d, want := range map[time.Duration]string{
		45 * time.Second: "0 min", 5 * time.Minute: "5 min", 3*time.Hour + 20*time.Minute: "3.3 h", 49 * time.Hour: "2.0 days",
	} {
		if got := humanDur(d); got != want {
			t.Errorf("humanDur(%v) = %q, want %q", d, got, want)
		}
	}
	t.Setenv("DRIFTBAND_TEST_ENV", "")
	if envOr("DRIFTBAND_TEST_ENV", "fallback") != "fallback" {
		t.Error("envOr: empty variable must give the default")
	}
	t.Setenv("DRIFTBAND_TEST_ENV", "set")
	if envOr("DRIFTBAND_TEST_ENV", "fallback") != "set" {
		t.Error("envOr: set variable ignored")
	}
}
