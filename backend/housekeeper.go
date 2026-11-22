package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// housekeeper periodically deletes samples older than each organization's
// configured retention window (1-3 years, default 1), and clears expired
// sessions and invites. Runs once at startup, then daily.
type housekeeper struct {
	db *pgxpool.Pool
}

func newHousekeeper(db *pgxpool.Pool) *housekeeper { return &housekeeper{db: db} }

func (h *housekeeper) Run(ctx context.Context) {
	h.sweep(ctx)
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.sweep(ctx)
		}
	}
}

func (h *housekeeper) sweep(ctx context.Context) {
	// Delete samples beyond each org's retention window.
	ct, err := h.db.Exec(ctx, `
		DELETE FROM samples s
		USING nodes n, organizations o
		WHERE s.host_id = n.id
		  AND n.org_id = o.id
		  AND s.ts < now() - make_interval(years => o.retention_years)`)
	if err != nil {
		log.Printf("housekeeper: samples sweep: %v", err)
	} else if n := ct.RowsAffected(); n > 0 {
		log.Printf("housekeeper: removed %d expired sample rows", n)
		auditSystemDB(ctx, h.db, "", "", "system.retention_sweep", fmt.Sprintf("removed %d expired sample rows", n))
	}

	// Rollups follow the same retention as the samples they summarise.
	if _, err := h.db.Exec(ctx, `
		DELETE FROM sample_rollups r
		USING nodes n, organizations o
		WHERE r.host_id = n.id
		  AND n.org_id = o.id
		  AND r.ts < now() - make_interval(years => o.retention_years)`); err != nil {
		log.Printf("housekeeper: rollups sweep: %v", err)
	}

	// Safety net against orphans: remove any sample whose host node no longer
	// exists. The samples.host_id foreign key (ON DELETE CASCADE) already
	// prevents this, so it normally deletes nothing, but it guards against
	// future schema changes or out-of-band bulk operations.
	if ct, err := h.db.Exec(ctx,
		`DELETE FROM samples s WHERE NOT EXISTS (SELECT 1 FROM nodes n WHERE n.id = s.host_id)`); err != nil {
		log.Printf("housekeeper: orphan sweep: %v", err)
	} else if n := ct.RowsAffected(); n > 0 {
		log.Printf("housekeeper: removed %d orphan sample rows", n)
		auditSystemDB(ctx, h.db, "", "", "system.orphan_sweep", fmt.Sprintf("removed %d orphan sample rows", n))
	}

	if _, err := h.db.Exec(ctx, `DELETE FROM notify_log WHERE created_at < now() - interval '90 days'`); err != nil {
		log.Printf("housekeeper: notify log sweep: %v", err)
	}
	if _, err := h.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`); err != nil {
		log.Printf("housekeeper: sessions sweep: %v", err)
	}
	if _, err := h.db.Exec(ctx, `DELETE FROM invites WHERE expires_at < now() AND used_at IS NULL`); err != nil {
		log.Printf("housekeeper: invites sweep: %v", err)
	}

	// Daily size snapshot for the admin usage trend / forecast.
	if _, err := h.db.Exec(ctx, `
		INSERT INTO db_size_history (day, total_bytes, samples_bytes, rollups_bytes, samples_rows)
		SELECT current_date, pg_database_size(current_database()),
		       pg_total_relation_size('samples'), pg_total_relation_size('sample_rollups'),
		       GREATEST((SELECT reltuples FROM pg_class WHERE oid = 'samples'::regclass), 0)::bigint
		ON CONFLICT (day) DO UPDATE SET total_bytes = EXCLUDED.total_bytes,
		  samples_bytes = EXCLUDED.samples_bytes, rollups_bytes = EXCLUDED.rollups_bytes,
		  samples_rows = EXCLUDED.samples_rows`); err != nil {
		log.Printf("housekeeper: size snapshot: %v", err)
	}
}
