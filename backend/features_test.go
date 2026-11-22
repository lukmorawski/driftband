package main

// Functional tests of the measurement pipeline and the tree: the series
// endpoint (raw and rollup-backed, incremental refreshes), the rollup
// worker, the status endpoint, moving nodes, profile fallback and the
// housekeeper. The security suite covers who may call what; these cover
// that the answers are right.

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"
)

// seedCycles stores one probe cycle per interval over [from, to) for a host:
// 20 pings around a base RTT that drifts slowly, with a burst of loss in the
// middle of the range. Returns the number of cycles written.
func seedCycles(t *testing.T, hostID int64, from, to time.Time, interval time.Duration) int {
	t.Helper()
	ctx := context.Background()
	n := 0
	mid := from.Add(to.Sub(from) / 2)
	for ts := from; ts.Before(to); ts = ts.Add(interval) {
		base := 10 + 5*math.Sin(float64(n)/50)
		rtts := make([]float64, 0, 20)
		lost := 0
		if !ts.Before(mid) && ts.Before(mid.Add(10*interval)) {
			lost = 5
		}
		for i := 0; i < 20-lost; i++ {
			rtts = append(rtts, base+float64(i%5)*0.3)
		}
		if _, err := testDB.Exec(ctx, `INSERT INTO samples (host_id, ts, sent, recv, rtts) VALUES ($1,$2,20,$3,$4)`,
			hostID, ts, 20-lost, rtts); err != nil {
			t.Fatal(err)
		}
		n++
	}
	return n
}

func jsonInto(body []byte, v any) error { return json.Unmarshal(body, v) }

func seriesOf(t *testing.T, e *env, a *actor, hostID int64, from, to int64, extra string) seriesResp {
	t.Helper()
	r := e.must(e.req(a, "GET", pathf("/api/series?host=%d&from=%d&to=%d%s", hostID, from, to, extra), nil), 200, "series")
	var out seriesResp
	if err := jsonInto(r.Body, &out); err != nil {
		t.Fatalf("series: %v", err)
	}
	return out
}

func TestSeriesRawAndRollupsAgree(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("series")
	ctx := context.Background()
	h := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "agree", "host": "192.0.2.80"}), 200, "host")
	hostID := int64(h.JSON["id"].(float64))
	// Two days of cycles, aligned to the hour so the rollups cover them whole.
	to := time.Now().Truncate(time.Hour).Add(-2 * time.Hour)
	from := to.Add(-48 * time.Hour)
	cycles := seedCycles(t, hostID, from, to, time.Minute)

	raw := seriesOf(t, e, o.Owner, hostID, from.Unix(), to.Unix(), "&points=200")
	if raw.Step == 0 || len(raw.Points) < 150 || len(raw.Points) > 200 {
		t.Fatalf("raw: step %d, %d points for 200 columns", raw.Step, len(raw.Points))
	}
	if raw.Stats.Cycles != cycles || raw.Stats.Sent != 20*cycles || raw.Stats.LossCycles != 10 {
		t.Errorf("raw stats: %+v (want %d cycles, 10 with loss)", raw.Stats, cycles)
	}
	if raw.Stats.MedAvg == nil || *raw.Stats.MedAvg < 5 || *raw.Stats.MedAvg > 15 || *raw.Stats.RttMin < 4.9 {
		t.Errorf("raw stats medians: %+v", raw.Stats)
	}

	// Roll the whole range up; the series is now served from the rollups.
	rw := newRollupWorker(testDB)
	if err := rw.rollRange(ctx, hostID, from.Unix(), to.Unix()); err != nil {
		t.Fatal(err)
	}
	var nRoll int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM sample_rollups WHERE host_id = $1 AND res = 3600`, hostID).Scan(&nRoll)
	if nRoll != 48 {
		t.Errorf("hourly rollups: %d, want 48", nRoll)
	}
	rolled := seriesOf(t, e, o.Owner, hostID, from.Unix(), to.Unix(), "&points=200")
	if rolled.Step != raw.Step {
		t.Errorf("step changed: raw %d, rolled %d", raw.Step, rolled.Step)
	}
	rs, ss := raw.Stats, rolled.Stats
	if rs.Cycles != ss.Cycles || rs.Sent != ss.Sent || rs.Recv != ss.Recv || rs.LossCycles != ss.LossCycles || rs.LossMax != ss.LossMax {
		t.Errorf("counts differ: raw %+v, rolled %+v", rs, ss)
	}
	closeEnough := func(a, b *float64) bool {
		return a != nil && b != nil && math.Abs(*a-*b) < 0.05
	}
	if !closeEnough(rs.MedAvg, ss.MedAvg) || !closeEnough(rs.RttMin, ss.RttMin) || !closeEnough(rs.RttMax, ss.RttMax) || !closeEnough(rs.Now, ss.Now) {
		t.Errorf("statistics differ: raw %+v, rolled %+v", rs, ss)
	}
	if len(rolled.Points) != len(raw.Points) {
		t.Fatalf("columns: raw %d, rolled %d", len(raw.Points), len(rolled.Points))
	}
	for i := range raw.Points {
		a, b := raw.Points[i], rolled.Points[i]
		if a.TS != b.TS || a.Sent != b.Sent || a.Loss != b.Loss {
			t.Fatalf("column %d: raw %+v, rolled %+v", i, a, b)
		}
		if a.P50 != nil && (b.P50 == nil || math.Abs(*a.P50-*b.P50) > 1) {
			t.Errorf("column %d median: raw %v, rolled %v", i, *a.P50, *b.P50)
		}
	}

	// A short window is served raw, one column per cycle.
	fine := seriesOf(t, e, o.Owner, hostID, to.Add(-30*time.Minute).Unix(), to.Unix(), "&points=1000")
	if fine.Step != 0 || len(fine.Points) != 30 {
		t.Errorf("short window: step %d, %d points", fine.Step, len(fine.Points))
	}
	// "max" (from=0) starts at the first sample.
	all := seriesOf(t, e, o.Owner, hostID, 0, to.Unix(), "&points=100")
	if len(all.Points) == 0 || all.Points[0].TS < from.Unix() || all.Stats.Cycles != cycles {
		t.Errorf("max window: first %d (from %d), %d cycles", all.Points[0].TS, from.Unix(), all.Stats.Cycles)
	}
}

func TestSeriesIncrementalRefresh(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("live")
	h := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "live", "host": "192.0.2.81"}), 200, "host")
	hostID := int64(h.JSON["id"].(float64))
	to := time.Now().Truncate(time.Minute)
	from := to.Add(-6 * time.Hour)
	seedCycles(t, hostID, from, to, time.Minute)
	full := seriesOf(t, e, o.Owner, hostID, from.Unix(), to.Unix(), "&points=100")
	if full.Step == 0 {
		t.Fatal("expected bucketed columns")
	}
	last := full.Points[len(full.Points)-1].TS
	inc := seriesOf(t, e, o.Owner, hostID, from.Unix(), to.Unix(), pathf("&step=%d&since=%d", full.Step, last))
	if inc.Step != full.Step || inc.Since != last {
		t.Errorf("incremental: step %d since %d, want %d / %d", inc.Step, inc.Since, full.Step, last)
	}
	if len(inc.Points) != 1 || inc.Points[0].TS != last {
		t.Errorf("incremental points: %d (first ts %d, want only %d)", len(inc.Points), inc.Points[0].TS, last)
	}
	if inc.Stats.Cycles != full.Stats.Cycles {
		t.Errorf("stats must cover the whole window: %d vs %d cycles", inc.Stats.Cycles, full.Stats.Cycles)
	}
	// Clamps: points is bounded, to never exceeds now, from > to is empty.
	if r := seriesOf(t, e, o.Owner, hostID, from.Unix(), to.Unix(), "&points=999999"); len(r.Points) > maxPoints {
		t.Errorf("points clamp: %d columns", len(r.Points))
	}
	if r := seriesOf(t, e, o.Owner, hostID, to.Unix(), from.Unix(), ""); len(r.Points) != 0 {
		t.Errorf("from > to returned %d points", len(r.Points))
	}
	if r := e.req(o.Owner, "GET", "/api/series?host=abc", nil); r.Status != 400 {
		t.Errorf("bad host id: %d", r.Status)
	}
}

func TestStatusReportsNewestCycle(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("status")
	ctx := context.Background()
	h := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "st", "host": "192.0.2.82"}), 200, "host")
	hostID := int64(h.JSON["id"].(float64))
	now := time.Now().Truncate(time.Second)
	for i, lost := range []int{0, 2, 7} {
		ts := now.Add(time.Duration(i-3) * time.Minute)
		if _, err := testDB.Exec(ctx, `INSERT INTO samples (host_id, ts, sent, recv, rtts) VALUES ($1,$2,20,$3,'{1,2,3}')`, hostID, ts, 20-lost); err != nil {
			t.Fatal(err)
		}
	}
	r := e.must(e.req(o.Owner, "GET", "/api/status", nil), 200, "status")
	var found bool
	for _, it := range r.List {
		m := it.(map[string]any)
		if int64(m["host_id"].(float64)) != hostID {
			continue
		}
		found = true
		if m["loss"].(float64) != 7 || m["sent"].(float64) != 20 || int64(m["ts"].(float64)) != now.Add(-time.Minute).Unix() {
			t.Errorf("status of the newest cycle: %v", m)
		}
	}
	if !found {
		t.Fatalf("host missing from status: %s", r.Body)
	}
	// hosts without samples are absent, folders never appear
	e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "silent", "host": "192.0.2.83"}), 200, "host")
	r = e.must(e.req(o.Owner, "GET", "/api/status", nil), 200, "status")
	if len(r.List) != 2 { // the org's seeded host and "st"
		t.Errorf("status lists %d hosts, want 2: %s", len(r.List), r.Body)
	}
}

func TestNodeMoveRules(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("move")
	mk := func(kind, name string, parent any) int64 {
		body := map[string]any{"kind": kind, "name": name, "parent_id": parent}
		if kind == "host" {
			body["host"] = "192.0.2.90"
		}
		return int64(e.must(e.req(o.Owner, "POST", "/api/nodes", body), 200, name).JSON["id"].(float64))
	}
	top := mk("folder", "top", nil)
	mid := mk("folder", "mid", top)
	leaf := mk("host", "leaf", mid)
	other := mk("folder", "other", nil)
	deep := mk("folder", "deep", other)
	move := func(id int64, parent any, pos int) int {
		return e.req(o.Owner, "POST", pathf("/api/nodes/%d/move", id), map[string]any{"parent_id": parent, "position": pos}).Status
	}
	if s := move(top, top, 0); s != 400 {
		t.Errorf("into itself: %d", s)
	}
	if s := move(top, mid, 0); s != 400 {
		t.Errorf("into own descendant: %d", s)
	}
	if s := move(mid, leaf, 0); s != 400 {
		t.Errorf("host as parent: %d", s)
	}
	if s := move(top, deep, 0); s != 400 { // top (height 3) under level 2
		t.Errorf("beyond 3 levels: %d", s)
	}
	if s := move(leaf, deep, 0); s != 200 { // host under level 2 is level 3: fine
		t.Errorf("valid move: %d", s)
	}
	// reorder at the top level: "other" first
	if s := move(other, nil, 0); s != 200 {
		t.Errorf("reorder: %d", s)
	}
	tree := e.must(e.req(o.Owner, "GET", "/api/tree", nil), 200, "tree").List
	names := []string{}
	for _, n := range tree {
		names = append(names, n.(map[string]any)["name"].(string))
	}
	if len(names) != 3 || names[0] != "other" {
		t.Errorf("top level order: %v", names)
	}
	var parent int64
	_ = testDB.QueryRow(context.Background(), `SELECT parent_id FROM nodes WHERE id = $1`, leaf).Scan(&parent)
	if parent != deep {
		t.Errorf("leaf parent %d, want %d", parent, deep)
	}
	if !auditHas(t, o.Owner.OrgID, o.Owner.Email, "host.move", dbNow(t).Add(-time.Minute)) {
		t.Error("move not audited")
	}
}

func TestProfileFallbackAndDefault(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("prof")
	ctx := context.Background()
	p := e.must(e.req(o.Owner, "POST", "/api/profiles", map[string]any{"name": "temp", "interval_s": 15, "ping_count": 5, "packet_size": 56, "is_default": false}), 200, "profile")
	pid := int64(p.JSON["id"].(float64))
	h := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "ph", "host": "192.0.2.91", "profile_id": pid}), 200, "host")
	hostID := int64(h.JSON["id"].(float64))
	if spec := mustHost(t, e, hostID); spec.intervalS != 15 {
		t.Errorf("host does not use its profile: %+v", spec)
	}
	// making another profile the default demotes the old default
	e.must(e.req(o.Owner, "PATCH", pathf("/api/profiles/%d", pid), map[string]any{"name": "temp", "interval_s": 15, "ping_count": 5, "packet_size": 56, "is_default": true}), 200, "set default")
	var defaults int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM probe_profiles WHERE org_id = $1 AND is_default`, o.Owner.OrgID).Scan(&defaults)
	if defaults != 1 {
		t.Errorf("%d default profiles", defaults)
	}
	if r := e.req(o.Owner, "DELETE", pathf("/api/profiles/%d", pid), nil); r.Status != 409 {
		t.Errorf("deleting the default profile: %d", r.Status)
	}
	e.must(e.req(o.Owner, "PATCH", pathf("/api/profiles/%d", o.ProfileID), map[string]any{"name": "back", "interval_s": 60, "ping_count": 5, "packet_size": 56, "is_default": true}), 200, "restore default")
	e.must(e.req(o.Owner, "DELETE", pathf("/api/profiles/%d", pid), nil), 200, "delete profile")
	if spec := mustHost(t, e, hostID); spec.intervalS != 60 {
		t.Errorf("host did not fall back to the default: %+v", spec)
	}
	var profile *int64
	_ = testDB.QueryRow(ctx, `SELECT profile_id FROM nodes WHERE id = $1`, hostID).Scan(&profile)
	if profile != nil {
		t.Errorf("host still references the deleted profile: %d", *profile)
	}
}

func TestHousekeeperRetention(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("sweep")
	ctx := context.Background()
	e.must(e.req(o.Owner, "POST", "/api/settings/retention", map[string]any{"years": 1}), 200, "retention")
	now := time.Now()
	for _, age := range []time.Duration{400 * 24 * time.Hour, 370 * 24 * time.Hour, 360 * 24 * time.Hour, 24 * time.Hour} {
		if _, err := testDB.Exec(ctx, `INSERT INTO samples (host_id, ts, sent, recv, rtts) VALUES ($1,$2,5,5,'{1,2,3,4,5}')`, o.HostID, now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		if _, err := testDB.Exec(ctx, `INSERT INTO sample_rollups (host_id, res, ts, cycles, sent, recv, pct, med_n, med_sum, med_sq, loss_cycles, loss_max, loss_min)
			VALUES ($1, 3600, $2, 1, 5, 5, NULL, 1, 1, 1, 0, 0, 0)`, o.HostID, now.Add(-age).Truncate(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testDB.Exec(ctx, `INSERT INTO sessions (token, user_id, expires_at) VALUES ('expired-token', $1, now() - interval '1 day')`, o.Member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(ctx, `UPDATE invites SET expires_at = now() - interval '1 hour' WHERE token = $1`, o.InviteToken); err != nil {
		t.Fatal(err)
	}
	newHousekeeper(testDB).sweep(ctx)

	var old, recent, oldRoll, sess, inv, snapshots int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM samples WHERE host_id = $1 AND ts < now() - interval '1 year'`, o.HostID).Scan(&old)
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM samples WHERE host_id = $1 AND ts >= now() - interval '1 year'`, o.HostID).Scan(&recent)
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM sample_rollups WHERE host_id = $1 AND ts < now() - interval '1 year'`, o.HostID).Scan(&oldRoll)
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE token = 'expired-token'`).Scan(&sess)
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM invites WHERE token = $1`, o.InviteToken).Scan(&inv)
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM db_size_history WHERE day = current_date`).Scan(&snapshots)
	if old != 0 || oldRoll != 0 {
		t.Errorf("%d samples and %d rollups older than the retention survived", old, oldRoll)
	}
	if recent < 32 { // 30 seeded by newOrg + 2 within a year
		t.Errorf("recent samples swept: %d left", recent)
	}
	if sess != 0 || inv != 0 {
		t.Errorf("expired session (%d) or invite (%d) survived", sess, inv)
	}
	if snapshots != 1 {
		t.Errorf("size snapshot rows for today: %d", snapshots)
	}
	var audited int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'system.retention_sweep' AND created_at >= $1`, now.Add(-time.Minute)).Scan(&audited)
	if audited == 0 {
		t.Error("retention sweep not audited")
	}
	// a longer retention keeps the same data
	e.must(e.req(o.Owner, "POST", "/api/settings/retention", map[string]any{"years": 3}), 200, "retention")
	if _, err := testDB.Exec(ctx, `INSERT INTO samples (host_id, ts, sent, recv, rtts) VALUES ($1, now() - interval '400 days', 5, 5, '{1}')`, o.HostID); err != nil {
		t.Fatal(err)
	}
	newHousekeeper(testDB).sweep(ctx)
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM samples WHERE host_id = $1 AND ts < now() - interval '1 year'`, o.HostID).Scan(&old)
	if old != 1 {
		t.Errorf("3-year retention removed a 400-day-old sample")
	}
}
