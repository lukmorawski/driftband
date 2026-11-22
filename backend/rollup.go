package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Rollup tiers, in seconds. Long windows are served from these instead of raw
// samples, the way SmokePing serves its week/month/year graphs from RRAs.
var rollupTiers = []int64{300, 3600}

// pctQs are the percentiles stored per bucket, in Point field order.
var pctQs = [9]float64{0, 2.5, 10, 25, 50, 75, 90, 97.5, 100}

// part is one aggregated slice of samples: a single probe cycle, a pooled
// bucket of raw cycles, or a rollup row. Parts merge into display buckets and
// into window statistics.
type part struct {
	TS         int64
	Cycles     int
	Sent, Recv int
	Pct        []float64 // len 9, or nil when nothing replied
	MedN       int
	MedSum     float64
	MedSq      float64
	LossCycles int
	LossMax    float64
	LossMin    float64
}

// pooler pools the RTTs of consecutive raw cycles into one part, so bucket
// percentiles describe every ping in the bucket, not an average of cycles.
type pooler struct {
	p    part
	rtts []float64
	tmp  []float64
}

func (pl *pooler) reset(ts int64) {
	pl.p = part{TS: ts}
	pl.rtts = pl.rtts[:0]
}

func (pl *pooler) add(sent, recv int, rtts []float64) {
	p := &pl.p
	lossF := 0.0
	if sent > 0 && recv < sent { // duplicate replies can make recv > sent
		lossF = float64(sent-recv) / float64(sent)
	}
	if p.Cycles == 0 || lossF > p.LossMax {
		p.LossMax = lossF
	}
	if p.Cycles == 0 || lossF < p.LossMin {
		p.LossMin = lossF
	}
	if sent-recv > 0 {
		p.LossCycles++
	}
	p.Cycles++
	p.Sent += sent
	p.Recv += recv
	if len(rtts) > 0 {
		pl.tmp = append(pl.tmp[:0], rtts...)
		sort.Float64s(pl.tmp)
		m := pctlVal(pl.tmp, 50)
		p.MedN++
		p.MedSum += m
		p.MedSq += m * m
		pl.rtts = append(pl.rtts, rtts...)
	}
}

func (pl *pooler) part() part {
	p := pl.p
	if len(pl.rtts) > 0 {
		sort.Float64s(pl.rtts)
		p.Pct = make([]float64, len(pctQs))
		for i, q := range pctQs {
			p.Pct[i] = pctlVal(pl.rtts, q)
		}
	}
	return p
}

// pctlVal is the q-th percentile (0-100) of a sorted, non-empty slice, with
// linear interpolation (same definition as Postgres percentile_cont).
func pctlVal(s []float64, q float64) float64 {
	n := len(s)
	if n == 1 {
		return s[0]
	}
	rank := q / 100 * float64(n-1)
	lo := int(rank)
	if lo+1 >= n {
		return s[n-1]
	}
	return s[lo] + (s[lo+1]-s[lo])*(rank-float64(lo))
}

func alignDown(ts, w int64) int64 {
	if w <= 0 {
		return ts
	}
	return int64(math.Floor(float64(ts)/float64(w))) * w
}

// ----- background worker -----

// rollupWorker keeps sample_rollups up to date: every few minutes it rolls up
// each host's completed hours. On first start it backfills all history.
type rollupWorker struct {
	db *pgxpool.Pool
}

func newRollupWorker(db *pgxpool.Pool) *rollupWorker { return &rollupWorker{db: db} }

// rollupLag keeps the worker clear of cycles still being written.
const rollupLag = 3 * time.Minute

func (rw *rollupWorker) Run(ctx context.Context) {
	rw.pass(ctx)
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rw.pass(ctx)
		}
	}
}

func (rw *rollupWorker) pass(ctx context.Context) {
	rows, err := rw.db.Query(ctx, `
		SELECT n.id, rs.done_until
		FROM nodes n LEFT JOIN rollup_state rs ON rs.host_id = n.id
		WHERE n.kind = 'host'`)
	if err != nil {
		log.Printf("rollup: list hosts: %v", err)
		return
	}
	type hs struct {
		id   int64
		done *time.Time
	}
	var hosts []hs
	for rows.Next() {
		var h hs
		if err := rows.Scan(&h.id, &h.done); err == nil {
			hosts = append(hosts, h)
		}
	}
	rows.Close()

	top := rollupTiers[len(rollupTiers)-1]
	target := alignDown(time.Now().Add(-rollupLag).Unix(), top)
	for _, h := range hosts {
		var cur int64
		if h.done != nil {
			cur = h.done.Unix()
		} else {
			var first *time.Time
			if err := rw.db.QueryRow(ctx, `SELECT min(ts) FROM samples WHERE host_id = $1`, h.id).Scan(&first); err != nil || first == nil {
				continue
			}
			cur = alignDown(first.Unix(), top)
			log.Printf("rollup: backfilling host %d from %s", h.id, first.UTC().Format(time.DateOnly))
			auditSystemDB(ctx, rw.db, "", "", "system.rollup_backfill", fmt.Sprintf("host %d from %s", h.id, first.UTC().Format(time.DateOnly)))
		}
		// One day per transaction keeps backfill transactions short.
		for cur < target && ctx.Err() == nil {
			end := min(cur+86400, target)
			if err := rw.rollRange(ctx, h.id, cur, end); err != nil {
				// A host deleted during the pass has nothing left to roll up.
				if ctx.Err() == nil && !isForeignKeyViolation(err) {
					log.Printf("rollup: host %d: %v", h.id, err)
					auditSystemDB(ctx, rw.db, "", "", "system.rollup_error", fmt.Sprintf("host %d: %v", h.id, err))
				}
				break
			}
			cur = end
		}
	}
}

// rollRange (re)builds every tier for [from, to), both aligned to the top tier,
// and advances the host's watermark to `to`.
func (rw *rollupWorker) rollRange(ctx context.Context, hostID, from, to int64) error {
	rows, err := rw.db.Query(ctx, `
		SELECT ts, sent, recv, rtts FROM samples
		WHERE host_id = $1 AND ts >= to_timestamp($2) AND ts < to_timestamp($3)
		ORDER BY ts`, hostID, from, to)
	if err != nil {
		return err
	}
	pools := make([]pooler, len(rollupTiers))
	open := make([]bool, len(rollupTiers))
	var out [][]any
	flush := func(i int) {
		if !open[i] {
			return
		}
		p := pools[i].part()
		var pct any
		if p.Pct != nil {
			pct = p.Pct
		}
		out = append(out, []any{hostID, int32(rollupTiers[i]), time.Unix(p.TS, 0), p.Cycles, p.Sent, p.Recv,
			pct, p.MedN, p.MedSum, p.MedSq, p.LossCycles, p.LossMax, p.LossMin})
		open[i] = false
	}
	for rows.Next() {
		var ts time.Time
		var sent, recv int
		var rtts []float64
		if err := rows.Scan(&ts, &sent, &recv, &rtts); err != nil {
			rows.Close()
			return err
		}
		for i, res := range rollupTiers {
			b := alignDown(ts.Unix(), res)
			if open[i] && pools[i].p.TS != b {
				flush(i)
			}
			if !open[i] {
				pools[i].reset(b)
				open[i] = true
			}
			pools[i].add(sent, recv, rtts)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range rollupTiers {
		flush(i)
	}

	tx, err := rw.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM sample_rollups
		WHERE host_id = $1 AND ts >= to_timestamp($2) AND ts < to_timestamp($3)`, hostID, from, to); err != nil {
		return err
	}
	if len(out) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"sample_rollups"},
			[]string{"host_id", "res", "ts", "cycles", "sent", "recv", "pct", "med_n", "med_sum", "med_sq", "loss_cycles", "loss_max", "loss_min"},
			pgx.CopyFromRows(out)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rollup_state (host_id, done_until) VALUES ($1, to_timestamp($2))
		ON CONFLICT (host_id) DO UPDATE SET done_until = EXCLUDED.done_until`, hostID, to); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
