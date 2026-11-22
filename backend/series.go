package main

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Point is one chart column: a single probe cycle, or a bucket of cycles when
// the window holds more cycles than the chart has pixels.
type Point struct {
	TS    int64    `json:"ts"`
	P0    *float64 `json:"p0"`
	P2_5  *float64 `json:"p2_5"`
	P10   *float64 `json:"p10"`
	P25   *float64 `json:"p25"`
	P50   *float64 `json:"p50"`
	P75   *float64 `json:"p75"`
	P90   *float64 `json:"p90"`
	P97_5 *float64 `json:"p97_5"`
	P100  *float64 `json:"p100"`
	Loss  int      `json:"loss"`
	Sent  int      `json:"sent"`
	Recv  int      `json:"recv"`
}

// seriesStats summarises the whole requested window, computed over every
// cycle (not over the downsampled points), for the chart legend.
type seriesStats struct {
	Cycles     int      `json:"cycles"`
	LossCycles int      `json:"loss_cycles"`
	Sent       int      `json:"sent"`
	Recv       int      `json:"recv"`
	LossMax    float64  `json:"loss_max"` // worst single-cycle loss fraction
	LossMin    float64  `json:"loss_min"`
	MedAvg     *float64 `json:"med_avg"` // mean / stddev of per-cycle medians
	MedSD      *float64 `json:"med_sd"`
	RttMin     *float64 `json:"rtt_min"`
	RttMax     *float64 `json:"rtt_max"`
	Now        *float64 `json:"now"` // median of the newest cycle
	NowLoss    int      `json:"now_loss"`
	NowSent    int      `json:"now_sent"`
	Last       int64    `json:"last"` // ts of the newest cycle, 0 if none
}

type seriesResp struct {
	Step   int64       `json:"step"`  // bucket width in seconds; 0 = raw cycles
	Since  int64       `json:"since"` // points cover ts >= since (incremental requests)
	Points []Point     `json:"points"`
	Stats  seriesStats `json:"stats"`
}

const (
	defaultPoints = 1000
	maxPoints     = 4000
)

// handleSeries serves a chart-ready series for one host:
//
//	from, to  window (unix seconds)
//	points    target column count, normally the chart width in pixels
//	step      force a bucket width (0 = raw), used by incremental refreshes
//	since     only return points from this ts on (stats still cover the window)
//
// Windows with more cycles than columns are bucketed: from raw samples for
// short windows, from the 5 min / 1 h rollups for long ones, plus a raw tail
// for the period the rollups don't cover yet.
func (a *App) handleSeries(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	q := r.URL.Query()
	hostID, err := strconv.ParseInt(q.Get("host"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad host id")
		return
	}
	now := time.Now().Unix()
	from := parseUnix(q.Get("from"), now-86400)
	to := min(parseUnix(q.Get("to"), now), now)
	points := min(max(parseUnix(q.Get("points"), defaultPoints), 50), maxPoints)
	ctx := r.Context()

	// Confirm the host belongs to the caller's org; fetch its probe interval
	// (resolved the same way the prober does).
	var interval int64
	err = a.db.QueryRow(ctx, `
		SELECT COALESCE(p.interval_s, dp.interval_s, 60)
		FROM nodes n
		LEFT JOIN probe_profiles p ON p.id = n.profile_id
		LEFT JOIN LATERAL (
		    SELECT interval_s FROM probe_profiles d
		    WHERE d.org_id = n.org_id ORDER BY is_default DESC, id LIMIT 1
		) dp ON true
		WHERE n.id = $1 AND n.org_id = $2 AND n.kind = 'host'`, hostID, u.OrgID).Scan(&interval)
	if err != nil {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}

	resp := seriesResp{Points: []Point{}}
	// "max" sends from=0: size buckets by the data actually present.
	var first *time.Time
	_ = a.db.QueryRow(ctx, `SELECT min(ts) FROM samples WHERE host_id = $1`, hostID).Scan(&first)
	if first == nil || from > to {
		writeJSONGz(w, r, resp)
		return
	}
	from = max(from, first.Unix())

	var step, res int64
	if s := q.Get("step"); s != "" {
		step = max(parseUnix(s, 0), 0)
		for _, t := range rollupTiers {
			if step >= t && step%t == 0 {
				res = t
			}
		}
	} else {
		step, res = pickStep(to-from, points, interval)
	}
	key := func(ts int64) int64 { return alignDown(ts, step) }
	since := key(max(parseUnix(q.Get("since"), from), from))
	resp.Step, resp.Since = step, since

	var st statAcc
	var disp dispAcc
	emit := func(p part) {
		st.add(p)
		if k := key(p.TS); k >= since {
			disp.add(k, p)
		}
	}

	// Rollups cover [.., done); raw samples cover the rest.
	rawFrom := from
	if res > 0 {
		var done *time.Time
		_ = a.db.QueryRow(ctx, `SELECT done_until FROM rollup_state WHERE host_id = $1`, hostID).Scan(&done)
		if done != nil && done.Unix() > from {
			end := min(done.Unix(), to+1)
			if err := a.scanRollups(ctx, hostID, res, alignDown(from, res), end, emit); err != nil {
				writeErr(w, http.StatusInternalServerError, "query failed")
				return
			}
			rawFrom = end
		}
	}
	if rawFrom <= to {
		if err := a.scanRaw(ctx, hostID, rawFrom, to, step, emit); err != nil {
			writeErr(w, http.StatusInternalServerError, "query failed")
			return
		}
	}

	// Newest cycle, for the legend's "now" values and the freshness dot.
	var lts time.Time
	var lsent, lrecv int
	var lrtts []float64
	if a.db.QueryRow(ctx, `
		SELECT ts, sent, recv, rtts FROM samples
		WHERE host_id = $1 AND ts >= to_timestamp($2) AND ts <= to_timestamp($3)
		ORDER BY ts DESC LIMIT 1`, hostID, from, to).Scan(&lts, &lsent, &lrecv, &lrtts) == nil {
		var pl pooler
		pl.reset(lts.Unix())
		pl.add(lsent, lrecv, lrtts)
		if lp := pl.part(); lp.Pct != nil {
			v := lp.Pct[4]
			st.s.Now = &v
		}
		st.s.NowLoss, st.s.NowSent, st.s.Last = lsent-lrecv, lsent, lts.Unix()
	}

	resp.Points = disp.points()
	resp.Stats = st.result()
	writeJSONGz(w, r, resp)
}

// pickStep chooses the bucket width for a window: raw cycles when they fit
// into `points` columns, otherwise the smallest whole multiple of the probe
// interval (short windows) or of a rollup tier (long windows) that does.
func pickStep(span, points, interval int64) (step, res int64) {
	need := (span + points - 1) / points
	if need <= interval {
		return 0, 0
	}
	unit := interval
	for _, t := range rollupTiers {
		if need >= t {
			unit, res = t, t
		}
	}
	return (need + unit - 1) / unit * unit, res
}

func (a *App) scanRollups(ctx context.Context, hostID, res, from, to int64, emit func(part)) error {
	rows, err := a.db.Query(ctx, `
		SELECT extract(epoch FROM ts)::bigint, cycles, sent, recv, pct, med_n, med_sum, med_sq,
		       loss_cycles, loss_max, loss_min
		FROM sample_rollups
		WHERE host_id = $1 AND res = $2 AND ts >= to_timestamp($3) AND ts < to_timestamp($4)
		ORDER BY ts`, hostID, res, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p part
		if err := rows.Scan(&p.TS, &p.Cycles, &p.Sent, &p.Recv, &p.Pct, &p.MedN, &p.MedSum, &p.MedSq,
			&p.LossCycles, &p.LossMax, &p.LossMin); err != nil {
			return err
		}
		emit(p)
	}
	return rows.Err()
}

// scanRaw streams raw cycles in [from, to], pooled into step-wide buckets
// (step 0: one part per cycle, keeping its own timestamp).
func (a *App) scanRaw(ctx context.Context, hostID, from, to, step int64, emit func(part)) error {
	rows, err := a.db.Query(ctx, `
		SELECT ts, sent, recv, rtts FROM samples
		WHERE host_id = $1 AND ts >= to_timestamp($2) AND ts <= to_timestamp($3)
		ORDER BY ts`, hostID, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	var pl pooler
	open := false
	for rows.Next() {
		var ts time.Time
		var sent, recv int
		var rtts []float64
		if err := rows.Scan(&ts, &sent, &recv, &rtts); err != nil {
			return err
		}
		b := ts.Unix()
		if step > 0 {
			b = alignDown(b, step)
		}
		if open && (step == 0 || pl.p.TS != b) {
			emit(pl.part())
			open = false
		}
		if !open {
			pl.reset(b)
			open = true
		}
		pl.add(sent, recv, rtts)
	}
	if open {
		emit(pl.part())
	}
	return rows.Err()
}

// dispAcc merges parts into chart columns. Percentiles of parts sharing a
// column are averaged, weighted by replying cycles (RRD AVERAGE style).
type dispAcc struct {
	out    []Point
	key    int64
	open   bool
	sent   int
	recv   int
	pctSum [9]float64
	pctW   int
}

func (d *dispAcc) add(k int64, p part) {
	if d.open && k != d.key {
		d.flush()
	}
	if !d.open {
		*d = dispAcc{out: d.out, key: k, open: true}
	}
	d.sent += p.Sent
	d.recv += p.Recv
	if p.Pct != nil && p.MedN > 0 {
		for i, v := range p.Pct {
			d.pctSum[i] += v * float64(p.MedN)
		}
		d.pctW += p.MedN
	}
}

func (d *dispAcc) flush() {
	pt := Point{TS: d.key, Sent: d.sent, Recv: d.recv, Loss: d.sent - d.recv}
	if d.pctW > 0 {
		var v [9]float64
		for i := range v {
			v[i] = d.pctSum[i] / float64(d.pctW)
		}
		pt.P0, pt.P2_5, pt.P10, pt.P25, pt.P50, pt.P75, pt.P90, pt.P97_5, pt.P100 =
			&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8]
	}
	d.out = append(d.out, pt)
	d.open = false
}

func (d *dispAcc) points() []Point {
	if d.open {
		d.flush()
	}
	if d.out == nil {
		return []Point{}
	}
	return d.out
}

// statAcc sums parts into window statistics.
type statAcc struct {
	s      seriesStats
	medN   int
	medSum float64
	medSq  float64
	rttMin float64
	rttMax float64
	hasRtt bool
}

func (a *statAcc) add(p part) {
	if p.Cycles == 0 {
		return
	}
	if a.s.Cycles == 0 || p.LossMax > a.s.LossMax {
		a.s.LossMax = p.LossMax
	}
	if a.s.Cycles == 0 || p.LossMin < a.s.LossMin {
		a.s.LossMin = p.LossMin
	}
	a.s.Cycles += p.Cycles
	a.s.LossCycles += p.LossCycles
	a.s.Sent += p.Sent
	a.s.Recv += p.Recv
	a.medN += p.MedN
	a.medSum += p.MedSum
	a.medSq += p.MedSq
	if p.Pct != nil {
		if !a.hasRtt || p.Pct[0] < a.rttMin {
			a.rttMin = p.Pct[0]
		}
		if !a.hasRtt || p.Pct[8] > a.rttMax {
			a.rttMax = p.Pct[8]
		}
		a.hasRtt = true
	}
}

func (a *statAcc) result() seriesStats {
	s := a.s
	if a.medN > 0 {
		avg := a.medSum / float64(a.medN)
		sd := math.Sqrt(max(a.medSq/float64(a.medN)-avg*avg, 0))
		s.MedAvg, s.MedSD = &avg, &sd
	}
	if a.hasRtt {
		lo, hi := a.rttMin, a.rttMax
		s.RttMin, s.RttMax = &lo, &hi
	}
	return s
}

// handleStatus returns the latest sample per host (for the tree health dots).
func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	// Lateral join: one index-backed lookup of the newest sample per host,
	// instead of DISTINCT ON sorting the whole samples table.
	rows, err := a.db.Query(r.Context(), `
		SELECT n.id, s.ts, s.sent, s.recv
		FROM nodes n
		CROSS JOIN LATERAL (
			SELECT ts, sent, recv FROM samples
			WHERE host_id = n.id ORDER BY ts DESC LIMIT 1
		) s
		WHERE n.org_id = $1 AND n.kind = 'host'`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type st struct {
		HostID int64 `json:"host_id"`
		TS     int64 `json:"ts"`
		Sent   int   `json:"sent"`
		Recv   int   `json:"recv"`
		Loss   int   `json:"loss"`
	}
	out := []st{}
	for rows.Next() {
		var s st
		var ts time.Time
		if err := rows.Scan(&s.HostID, &ts, &s.Sent, &s.Recv); err != nil {
			continue
		}
		s.TS = ts.Unix()
		s.Loss = s.Sent - s.Recv
		out = append(out, s)
	}
	writeJSON(w, http.StatusOK, out)
}

func parseUnix(s string, def int64) int64 {
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v
	}
	return def
}
