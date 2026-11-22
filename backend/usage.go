package main

// Organization usage for the Usage tab: how many measurements are stored,
// roughly how much space they take, how fast that grows and where it ends
// up once the retention window is full. Table names are not exposed.

import (
	"math"
	"net/http"
	"time"
)

// usageTopHosts is how many hosts the per-day chart shows on their own.
const usageTopHosts = 6

func (a *App) handleUsage(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	ctx := r.Context()
	bpr, rawShare := a.sampleStorage(ctx)

	var retention int
	_ = a.db.QueryRow(ctx, `SELECT retention_years FROM organizations WHERE id = $1`, u.OrgID).Scan(&retention)

	// Per host: stored cycles (rollups up to the watermark + raw tail) and
	// the configured cycles per day.
	type hostUse struct {
		ID      int64   `json:"id"`
		Name    string  `json:"name"`
		Records int64   `json:"records"`
		PerDay  float64 `json:"per_day"`
	}
	rows, err := a.db.Query(ctx, `
		SELECT n.id, n.name,
		       COALESCE((SELECT sum(r.cycles) FROM sample_rollups r WHERE r.host_id = n.id AND r.res = 3600), 0)
		     + (SELECT count(*) FROM samples s WHERE s.host_id = n.id
		          AND s.ts >= COALESCE((SELECT done_until FROM rollup_state rs WHERE rs.host_id = n.id), '-infinity')),
		       86400.0 / COALESCE(p.interval_s, dp.interval_s, 60)
		FROM nodes n
		LEFT JOIN probe_profiles p ON p.id = n.profile_id
		LEFT JOIN LATERAL (SELECT interval_s FROM probe_profiles d WHERE d.org_id = n.org_id ORDER BY is_default DESC, id LIMIT 1) dp ON true
		WHERE n.org_id = $1 AND n.kind = 'host'
		ORDER BY 3 DESC`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	strict := a.strict(ctx, u.OrgID)
	hosts := []hostUse{}
	var records int64
	var perDay float64
	for rows.Next() {
		var h hostUse
		if rows.Scan(&h.ID, &h.Name, &h.Records, &h.PerDay) == nil {
			if strict {
				h.PerDay = math.Min(h.PerDay, 86400.0/testMinInterval)
			}
			hosts = append(hosts, h)
			records += h.Records
			perDay += h.PerDay
		}
	}
	rows.Close()

	// Measurements stored per day, last 30 days.
	type day struct {
		Day     int64 `json:"day"`
		Records int64 `json:"records"`
	}
	daily := []day{}
	if drows, err := a.db.Query(ctx, `
		SELECT extract(epoch FROM date_trunc('day', r.ts))::bigint, sum(r.cycles)
		FROM sample_rollups r JOIN nodes n ON n.id = r.host_id
		WHERE n.org_id = $1 AND r.res = 3600 AND r.ts >= date_trunc('day', now()) - interval '29 days'
		GROUP BY 1 ORDER BY 1`, u.OrgID); err == nil {
		for drows.Next() {
			var d day
			if drows.Scan(&d.Day, &d.Records) == nil {
				daily = append(daily, d)
			}
		}
		drows.Close()
	}

	// The same 30 days split by host, for the hosts that store the most
	// (the chart stacks them and folds the rest into "other").
	type hostDay struct {
		Day     int64 `json:"day"`
		ID      int64 `json:"id"`
		Records int64 `json:"records"`
	}
	dailyByHost := []hostDay{}
	var topIDs []int64
	for i := 0; i < len(hosts) && i < usageTopHosts; i++ {
		topIDs = append(topIDs, hosts[i].ID)
	}
	if hrows, err := a.db.Query(ctx, `
		SELECT extract(epoch FROM date_trunc('day', r.ts))::bigint, r.host_id, sum(r.cycles)
		FROM sample_rollups r JOIN nodes n ON n.id = r.host_id
		WHERE n.org_id = $1 AND r.host_id = ANY($2) AND r.res = 3600 AND r.ts >= date_trunc('day', now()) - interval '29 days'
		GROUP BY 1, 2 ORDER BY 1, 2`, u.OrgID, topIDs); err == nil {
		for hrows.Next() {
			var d hostDay
			if hrows.Scan(&d.Day, &d.ID, &d.Records) == nil {
				dailyByHost = append(dailyByHost, d)
			}
		}
		hrows.Close()
	}

	// Forecast: grow at the configured rate until the oldest data reaches the
	// retention age, then stay flat (the housekeeper removes older data).
	capRecords := perDay * 365 * float64(retention)
	at := func(days float64) float64 {
		return math.Min(float64(records)+perDay*days, math.Max(capRecords, float64(records)))
	}
	type point struct {
		Day     int     `json:"day"`
		Records float64 `json:"records"`
		Bytes   float64 `json:"bytes"`
	}
	horizon := 365 * max(retention, 1)
	points := []point{}
	for d := 0; d <= horizon; d += 7 {
		v := at(float64(d))
		points = append(points, point{d, v, v * bpr})
	}
	steadyDay := -1
	if perDay > 0 && capRecords > float64(records) {
		steadyDay = int(math.Ceil((capRecords - float64(records)) / perDay))
	}

	// The same projection for each retention the organization could choose
	// (1, 2 or 3 years), over three years, so the options can be compared.
	type option struct {
		Years        int     `json:"years"`
		SteadyBytes  int64   `json:"steady_bytes"`
		SteadyInDays int     `json:"steady_in_days"`
		Points       []point `json:"points"`
	}
	options := []option{}
	for years := 1; years <= 3; years++ {
		capR := math.Max(perDay*365*float64(years), float64(records))
		o := option{Years: years, SteadyBytes: int64(capR * bpr), SteadyInDays: -1, Points: []point{}}
		if perDay > 0 && capR > float64(records) {
			o.SteadyInDays = int(math.Ceil((capR - float64(records)) / perDay))
		}
		for d := 0; d <= 3*365; d += 15 {
			v := math.Min(float64(records)+perDay*float64(d), capR)
			o.Points = append(o.Points, point{d, v, v * bpr})
		}
		options = append(options, o)
	}

	limit, count := a.hostQuota(ctx, u.OrgID)
	if len(hosts) > 12 {
		hosts = hosts[:12]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records":           records,
		"bytes":             int64(float64(records) * bpr),
		"raw_bytes":         int64(float64(records) * bpr * rawShare),
		"summary_bytes":     int64(float64(records) * bpr * (1 - rawShare)),
		"records_per_day":   perDay,
		"bytes_per_day":     int64(perDay * bpr),
		"retention_years":   retention,
		"steady_records":    int64(math.Max(capRecords, float64(records))),
		"steady_bytes":      int64(math.Max(capRecords, float64(records)) * bpr),
		"steady_in_days":    steadyDay,
		"in_30_days":        int64(at(30) * bpr),
		"in_365_days":       int64(at(365) * bpr),
		"forecast":          points,
		"daily":             daily,
		"daily_by_host":     dailyByHost,
		"retention_options": options,
		"top_hosts":         hosts,
		"host_limit":        limit,
		"host_count":        count,
		"generated_at":      time.Now().Unix(),
	})
}
