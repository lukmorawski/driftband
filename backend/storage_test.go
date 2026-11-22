package main

import (
	"bytes"
	"context"
	"log"
	"slices"
	"testing"
	"time"
)

// A host deleted while its prober, the alert evaluator or the rollup worker
// is mid-cycle: the late writes are refused by the foreign keys, nothing of
// the host stays in the database and nothing is logged as an error.
func TestHostDeletedMidCycle(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("midcycle")
	ctx := context.Background()
	rows := func(query string, id int64) int {
		t.Helper()
		var n int
		if err := testDB.QueryRow(ctx, query, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	tables := []string{"samples", "sample_rollups", "rollup_state", "alert_state"}
	live := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{
		"kind": "host", "name": "live", "host": "192.0.2.90", "parent_id": o.FolderID}), 200, "host")
	liveID := int64(live.JSON["id"].(float64))

	// The host has rollups and alert state, as in production.
	rw := newRollupWorker(testDB)
	hour := time.Now().Truncate(time.Hour).Unix()
	if err := rw.rollRange(ctx, o.HostID, hour-3600, hour+3600); err != nil {
		t.Fatal(err)
	}
	e.app.saveState(ctx, o.RuleID, o.HostID, alertState{Since: time.Now()})
	for _, table := range tables {
		if rows("SELECT count(*) FROM "+table+" WHERE host_id = $1", o.HostID) == 0 {
			t.Fatalf("setup: no %s rows for the host", table)
		}
	}
	e.must(e.req(o.Owner, "DELETE", pathf("/api/nodes/%d", o.HostID), nil), 200, "delete host")

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	// Work for the host that was already running finishes after the delete.
	e.app.pm.store(ctx, o.HostID, 5, 5, []float64{1, 2, 3, 4, 5})
	e.app.saveState(ctx, o.RuleID, o.HostID, alertState{Since: time.Now()})
	if err := rw.rollRange(ctx, o.HostID, hour-3600, hour); !isForeignKeyViolation(err) {
		t.Errorf("rollup of a deleted host: %v, want a foreign-key error", err)
	}
	// A stopped prober drops its last cycle; a running one stores it.
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	e.app.pm.store(stopped, liveID, 5, 5, []float64{1, 2, 3, 4, 5})
	if n := rows(`SELECT count(*) FROM samples WHERE host_id = $1`, liveID); n != 0 {
		t.Errorf("stopped prober stored %d samples", n)
	}
	e.app.pm.store(ctx, liveID, 5, 4, []float64{1, 2, 3, 4})
	if n := rows(`SELECT count(*) FROM samples WHERE host_id = $1`, liveID); n != 1 {
		t.Errorf("running prober stored %d samples, want 1", n)
	}

	log.SetOutput(prev)
	if logs.Len() > 0 {
		t.Errorf("errors logged for a deleted host:\n%s", logs.String())
	}
	for _, table := range tables {
		if n := rows("SELECT count(*) FROM "+table+" WHERE host_id = $1", o.HostID); n != 0 {
			t.Errorf("%s keeps %d rows of the deleted host", table, n)
		}
	}
}

// samples carries only its primary key: a second index over the same columns
// would double the index space and the work of every insert and vacuum.
func TestSamplesSingleIndex(t *testing.T) {
	needDB(t)
	var names []string
	if err := testDB.QueryRow(context.Background(),
		`SELECT array_agg(indexname::text ORDER BY indexname) FROM pg_indexes WHERE tablename = 'samples'`).Scan(&names); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"samples_pkey"}) {
		t.Errorf("samples indexes: %v, want only samples_pkey", names)
	}
}

// The bulk tables are vacuumed after a fixed number of dead rows, not the
// default 20 % of the table, so a deleted host's samples are reclaimed soon.
func TestBulkTablesAutovacuum(t *testing.T) {
	needDB(t)
	for _, table := range []string{"samples", "sample_rollups"} {
		var opts []string
		if err := testDB.QueryRow(context.Background(),
			`SELECT COALESCE(reloptions, '{}') FROM pg_class WHERE oid = $1::regclass`, table).Scan(&opts); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"autovacuum_vacuum_scale_factor=0", "autovacuum_vacuum_threshold=1000", "autovacuum_vacuum_cost_limit=2000"} {
			if !slices.Contains(opts, want) {
				t.Errorf("%s: %s not set (have %v)", table, want, opts)
			}
		}
	}
}
