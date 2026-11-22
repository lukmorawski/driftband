package main

// Alert rules and their evaluator.
//
// Every tick the evaluator measures each host in a rule's scope over a short
// lookback (a few probe cycles, so one bad cycle is smoothed out) and keeps
// two timers per rule and host:
//
//	breach_since  value >= threshold continuously since
//	clear_since   value <  recover_threshold continuously since
//
// A rule fires only after the breach has lasted for_minutes and resolves only
// after recovery has lasted recover_minutes, with a lower recovery threshold
// (hysteresis). If the firing state changes flap_transitions times within
// flap_window_minutes the pair is marked flapping: one notification is sent
// and further fire/resolve messages are held back until the state has been
// stable for half the window. A lookback without samples keeps the firing
// state but restarts both timers (no data is neither an outage nor a
// recovery).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type alertRule struct {
	ID                int64   `json:"id"`
	Name              string  `json:"name"`
	Enabled           bool    `json:"enabled"`
	NodeID            *int64  `json:"node_id"`
	Metric            string  `json:"metric"`
	Threshold         float64 `json:"threshold"`
	RecoverThreshold  float64 `json:"recover_threshold"`
	ForMinutes        int     `json:"for_minutes"`
	RecoverMinutes    int     `json:"recover_minutes"`
	NotifyRecovery    bool    `json:"notify_recovery"`
	RepeatMinutes     int     `json:"repeat_minutes"`
	FlapTransitions   int     `json:"flap_transitions"`
	FlapWindowMinutes int     `json:"flap_window_minutes"`
	ChannelIDs        []int64 `json:"channel_ids"`
	orgID             int64
}

func (rl *alertRule) validate() error {
	rl.Name = strings.TrimSpace(rl.Name)
	if rl.Name == "" || len(rl.Name) > 100 {
		return errors.New("name is required (max 100 characters)")
	}
	switch rl.Metric {
	case "loss":
		if rl.Threshold < 1 || rl.Threshold > 100 {
			return errors.New("loss threshold must be 1-100 %")
		}
	case "latency":
		if rl.Threshold < 1 || rl.Threshold > 60000 {
			return errors.New("latency threshold must be 1-60000 ms")
		}
	default:
		return errors.New("metric must be loss or latency")
	}
	if rl.RecoverThreshold <= 0 || rl.RecoverThreshold > rl.Threshold {
		return errors.New("recovery threshold must be above 0 and not above the alert threshold")
	}
	if rl.ForMinutes < 1 || rl.ForMinutes > 1440 || rl.RecoverMinutes < 1 || rl.RecoverMinutes > 1440 {
		return errors.New("durations must be 1-1440 minutes")
	}
	if rl.RepeatMinutes < 0 || rl.RepeatMinutes > 10080 {
		return errors.New("reminder interval must be 0 (off) to 10080 minutes")
	}
	if rl.FlapTransitions != 0 && (rl.FlapTransitions < 3 || rl.FlapTransitions > 50) {
		return errors.New("flap detection needs 3-50 state changes, or 0 to disable")
	}
	if rl.FlapWindowMinutes < 10 || rl.FlapWindowMinutes > 1440 {
		return errors.New("flap window must be 10-1440 minutes")
	}
	if len(rl.ChannelIDs) == 0 || len(rl.ChannelIDs) > 20 {
		return errors.New("choose 1 to 20 channels")
	}
	return nil
}

// checkRefs ensures the scope node and channels belong to the org.
func (a *App) checkRuleRefs(ctx context.Context, orgID int64, rl *alertRule) error {
	if rl.NodeID != nil {
		var ok bool
		_ = a.db.QueryRow(ctx, `SELECT true FROM nodes WHERE id = $1 AND org_id = $2`, *rl.NodeID, orgID).Scan(&ok)
		if !ok {
			return errors.New("scope must be a folder or host of your organization")
		}
	}
	seen := map[int64]bool{}
	var ids []int64
	for _, id := range rl.ChannelIDs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	var n int
	_ = a.db.QueryRow(ctx, `SELECT count(*) FROM notify_channels WHERE org_id = $1 AND id = ANY($2)`, orgID, ids).Scan(&n)
	if n != len(ids) {
		return errors.New("unknown notification channel")
	}
	rl.ChannelIDs = ids
	return nil
}

const ruleCols = `id, name, enabled, node_id, metric, threshold, recover_threshold, for_minutes, recover_minutes,
	notify_recovery, repeat_minutes, flap_transitions, flap_window_minutes, channel_ids, org_id`

type scanner interface{ Scan(...any) error }

func scanRule(s scanner) (*alertRule, error) {
	var rl alertRule
	err := s.Scan(&rl.ID, &rl.Name, &rl.Enabled, &rl.NodeID, &rl.Metric, &rl.Threshold, &rl.RecoverThreshold,
		&rl.ForMinutes, &rl.RecoverMinutes, &rl.NotifyRecovery, &rl.RepeatMinutes, &rl.FlapTransitions,
		&rl.FlapWindowMinutes, &rl.ChannelIDs, &rl.orgID)
	if rl.ChannelIDs == nil {
		rl.ChannelIDs = []int64{}
	}
	return &rl, err
}

// ----- handlers -----

func (a *App) handleListRules(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	rows, err := a.db.Query(r.Context(), `SELECT `+ruleCols+` FROM alert_rules WHERE org_id = $1 ORDER BY name, id`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := []*alertRule{}
	for rows.Next() {
		if rl, err := scanRule(rows); err == nil {
			out = append(out, rl)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r, "notify.rule_create") {
		return
	}
	u := userFrom(r)
	var in alertRule
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.checkRuleRefs(ctx, u.OrgID, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := a.db.QueryRow(ctx, `
		INSERT INTO alert_rules (org_id, name, enabled, node_id, metric, threshold, recover_threshold, for_minutes,
		  recover_minutes, notify_recovery, repeat_minutes, flap_transitions, flap_window_minutes, channel_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
		u.OrgID, in.Name, in.Enabled, in.NodeID, in.Metric, in.Threshold, in.RecoverThreshold, in.ForMinutes,
		in.RecoverMinutes, in.NotifyRecovery, in.RepeatMinutes, in.FlapTransitions, in.FlapWindowMinutes, in.ChannelIDs).Scan(&in.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "notify.rule_create", ruleSummary(&in))
	writeJSON(w, http.StatusOK, in)
}

func (a *App) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r, "notify.rule_update") {
		return
	}
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in alertRule
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	var exists bool
	_ = a.db.QueryRow(ctx, `SELECT true FROM alert_rules WHERE id = $1 AND org_id = $2`, id, u.OrgID).Scan(&exists)
	if !exists {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.checkRuleRefs(ctx, u.OrgID, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in.ID = id
	if _, err := a.db.Exec(ctx, `
		UPDATE alert_rules SET name=$1, enabled=$2, node_id=$3, metric=$4, threshold=$5, recover_threshold=$6,
		  for_minutes=$7, recover_minutes=$8, notify_recovery=$9, repeat_minutes=$10, flap_transitions=$11,
		  flap_window_minutes=$12, channel_ids=$13
		WHERE id=$14 AND org_id=$15`,
		in.Name, in.Enabled, in.NodeID, in.Metric, in.Threshold, in.RecoverThreshold, in.ForMinutes, in.RecoverMinutes,
		in.NotifyRecovery, in.RepeatMinutes, in.FlapTransitions, in.FlapWindowMinutes, in.ChannelIDs, id, u.OrgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	// A changed rule starts from a clean slate: old timers no longer apply.
	_, _ = a.db.Exec(ctx, `DELETE FROM alert_state WHERE rule_id = $1`, id)
	a.audit(ctx, u, clientIP(r), "notify.rule_update", ruleSummary(&in))
	writeJSON(w, http.StatusOK, in)
}

func (a *App) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r, "notify.rule_delete") {
		return
	}
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var name string
	if err := a.db.QueryRow(r.Context(), `DELETE FROM alert_rules WHERE id=$1 AND org_id=$2 RETURNING name`, id, u.OrgID).Scan(&name); err != nil {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	a.audit(r.Context(), u, clientIP(r), "notify.rule_delete", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleNotifyEvents returns active alerts and recent deliveries.
func (a *App) handleNotifyEvents(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	ctx := r.Context()
	type active struct {
		RuleID   int64    `json:"rule_id"`
		Rule     string   `json:"rule"`
		HostID   int64    `json:"host_id"`
		Host     string   `json:"host"`
		Flapping bool     `json:"flapping"`
		Since    int64    `json:"since"`
		Value    *float64 `json:"value"`
		Metric   string   `json:"metric"`
	}
	act := []active{}
	if rows, err := a.db.Query(ctx, `
		SELECT s.rule_id, r.name, s.host_id, n.name, s.flapping, s.since, s.last_value, r.metric
		FROM alert_state s JOIN alert_rules r ON r.id = s.rule_id JOIN nodes n ON n.id = s.host_id
		WHERE r.org_id = $1 AND (s.firing OR s.flapping) ORDER BY s.since DESC`, u.OrgID); err == nil {
		for rows.Next() {
			var v active
			var since time.Time
			if rows.Scan(&v.RuleID, &v.Rule, &v.HostID, &v.Host, &v.Flapping, &since, &v.Value, &v.Metric) == nil {
				v.Since = since.Unix()
				act = append(act, v)
			}
		}
		rows.Close()
	}
	type entry struct {
		ID      int64   `json:"id"`
		Event   string  `json:"event"`
		Message string  `json:"message"`
		OK      bool    `json:"ok"`
		Error   *string `json:"error"`
		Channel string  `json:"channel"`
		Kind    string  `json:"kind"`
		At      int64   `json:"at"`
	}
	// Delivery history: one page (limit and offset: pageParams) and the total.
	limit, offset := pageParams(r)
	var logTotal int
	_ = a.db.QueryRow(ctx, `SELECT count(*) FROM notify_log WHERE org_id = $1`, u.OrgID).Scan(&logTotal)
	log := []entry{}
	if rows, err := a.db.Query(ctx, `
		SELECT l.id, l.event, l.message, l.ok, l.error, COALESCE(c.name, ''), COALESCE(c.kind, ''), l.created_at
		FROM notify_log l LEFT JOIN notify_channels c ON c.id = l.channel_id
		WHERE l.org_id = $1 ORDER BY l.id DESC LIMIT $2 OFFSET $3`, u.OrgID, limit, offset); err == nil {
		for rows.Next() {
			var e entry
			var at time.Time
			if rows.Scan(&e.ID, &e.Event, &e.Message, &e.OK, &e.Error, &e.Channel, &e.Kind, &at) == nil {
				e.At = at.Unix()
				log = append(log, e)
			}
		}
		rows.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": act, "log": log, "log_total": logTotal})
}

func ruleSummary(rl *alertRule) string {
	unit := map[string]string{"loss": "% loss", "latency": " ms median"}[rl.Metric]
	return fmt.Sprintf("%s: >= %s%s for %d min, recover < %s for %d min", rl.Name,
		fmtNum(rl.Threshold), unit, rl.ForMinutes, fmtNum(rl.RecoverThreshold), rl.RecoverMinutes)
}

func fmtNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// ----- evaluator -----

type alertEvaluator struct{ app *App }

func (ev alertEvaluator) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := ev.app.evaluateAlerts(ctx, time.Now()); err != nil {
				log.Printf("alerts: %v", err)
			}
		}
	}
}

type alertState struct {
	Firing, Flapping        bool
	Since                   time.Time
	BreachSince, ClearSince *time.Time
	Transitions             []time.Time
	LastNotified            *time.Time
	LastValue               *float64
}

type hostInfo struct {
	id       int64
	name     string
	addr     string
	interval int
}

// evaluateAlerts runs one evaluation pass at time now and waits for the
// resulting deliveries.
func (a *App) evaluateAlerts(ctx context.Context, now time.Time) error {
	rows, err := a.db.Query(ctx, `
		SELECT `+ruleCols+` FROM alert_rules r
		WHERE enabled AND EXISTS (SELECT 1 FROM organizations o WHERE o.id = r.org_id AND NOT o.disabled)`)
	if err != nil {
		return err
	}
	var rules []*alertRule
	for rows.Next() {
		if rl, err := scanRule(rows); err == nil {
			rules = append(rules, rl)
		}
	}
	rows.Close()
	var wg sync.WaitGroup
	for _, rl := range rules {
		if err := a.evaluateRule(ctx, rl, now, &wg); err != nil {
			log.Printf("alerts: rule %d: %v", rl.ID, err)
		}
	}
	wg.Wait()
	return nil
}

func (a *App) scopeHosts(ctx context.Context, rl *alertRule) ([]hostInfo, error) {
	rows, err := a.db.Query(ctx, `
		WITH RECURSIVE scope AS (
			SELECT id FROM nodes WHERE org_id = $1 AND ($2::bigint IS NULL AND parent_id IS NULL OR id = $2)
			UNION ALL SELECT n.id FROM nodes n JOIN scope s ON n.parent_id = s.id
		)
		SELECT n.id, n.name, COALESCE(n.host, ''), COALESCE(p.interval_s, dp.interval_s, 60)
		FROM nodes n
		LEFT JOIN probe_profiles p ON p.id = n.profile_id
		LEFT JOIN LATERAL (SELECT interval_s FROM probe_profiles d WHERE d.org_id = n.org_id ORDER BY is_default DESC, id LIMIT 1) dp ON true
		WHERE n.kind = 'host' AND n.org_id = $1 AND n.id IN (SELECT id FROM scope)`, rl.orgID, rl.NodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hostInfo
	for rows.Next() {
		var h hostInfo
		if rows.Scan(&h.id, &h.name, &h.addr, &h.interval) == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

// lookback is how far back one evaluation looks: a few cycles of the host's
// probe interval, at least two minutes.
func lookback(interval int) time.Duration {
	return time.Duration(max(120, interval*5/2)) * time.Second
}

// measure returns the rule's metric for a host over [now-lookback, now].
func (a *App) measure(ctx context.Context, rl *alertRule, h hostInfo, now time.Time) (float64, bool) {
	from := now.Add(-lookback(h.interval))
	if rl.Metric == "loss" {
		var sent, recv int64
		var n int
		_ = a.db.QueryRow(ctx, `SELECT count(*), COALESCE(sum(sent),0), COALESCE(sum(recv),0) FROM samples
			WHERE host_id = $1 AND ts > $2 AND ts <= $3`, h.id, from, now).Scan(&n, &sent, &recv)
		if n == 0 || sent == 0 {
			return 0, false
		}
		return math.Max(0, float64(sent-recv)) / float64(sent) * 100, true
	}
	var med *float64
	_ = a.db.QueryRow(ctx, `SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY r) FROM samples s, unnest(s.rtts) r
		WHERE s.host_id = $1 AND s.ts > $2 AND s.ts <= $3`, h.id, from, now).Scan(&med)
	if med == nil {
		return 0, false // no replies at all: a loss rule covers outages
	}
	return *med, true
}

func (a *App) loadState(ctx context.Context, ruleID, hostID int64) (alertState, bool) {
	var s alertState
	err := a.db.QueryRow(ctx, `SELECT firing, flapping, since, breach_since, clear_since, transitions, last_notified, last_value
		FROM alert_state WHERE rule_id = $1 AND host_id = $2`, ruleID, hostID).
		Scan(&s.Firing, &s.Flapping, &s.Since, &s.BreachSince, &s.ClearSince, &s.Transitions, &s.LastNotified, &s.LastValue)
	return s, err == nil
}

func (a *App) saveState(ctx context.Context, ruleID, hostID int64, s alertState) {
	if s.Transitions == nil {
		s.Transitions = []time.Time{} // column is NOT NULL
	}
	_, err := a.db.Exec(ctx, `
		INSERT INTO alert_state (rule_id, host_id, firing, flapping, since, breach_since, clear_since, transitions, last_notified, last_value)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (rule_id, host_id) DO UPDATE SET firing=$3, flapping=$4, since=$5, breach_since=$6, clear_since=$7,
		  transitions=$8, last_notified=$9, last_value=$10`,
		ruleID, hostID, s.Firing, s.Flapping, s.Since, s.BreachSince, s.ClearSince, s.Transitions, s.LastNotified, s.LastValue)
	// A foreign-key error means the host or rule was deleted during this pass.
	if err != nil && ctx.Err() == nil && !isForeignKeyViolation(err) {
		log.Printf("alerts: save state: %v", err)
	}
}

// step advances one rule/host state at time now given the measured value and
// returns the notification event to send ("" for none). Pure: no I/O.
func step(rl *alertRule, s *alertState, v float64, ok bool, now time.Time) string {
	if s.Since.IsZero() {
		s.Since = now
	}
	if !ok {
		// No data is neither a breach nor a recovery: restart both timers so a
		// gap can never complete a "for N minutes" condition.
		s.BreachSince, s.ClearSince = nil, nil
		return ""
	}
	val := v
	s.LastValue = &val
	if v >= rl.Threshold {
		if s.BreachSince == nil {
			t := now
			s.BreachSince = &t
		}
	} else {
		s.BreachSince = nil
	}
	if v < rl.RecoverThreshold {
		if s.ClearSince == nil {
			t := now
			s.ClearSince = &t
		}
	} else {
		s.ClearSince = nil
	}

	event := ""
	forD := time.Duration(rl.ForMinutes) * time.Minute
	recD := time.Duration(rl.RecoverMinutes) * time.Minute
	if !s.Firing && s.BreachSince != nil && now.Sub(*s.BreachSince) >= forD {
		s.Firing, s.Since = true, now
		s.Transitions = append(s.Transitions, now)
		event = "firing"
	} else if s.Firing && s.ClearSince != nil && now.Sub(*s.ClearSince) >= recD {
		s.Firing, s.Since = false, now
		s.Transitions = append(s.Transitions, now)
		event = "resolved"
		if !rl.NotifyRecovery {
			event = ""
		}
	}

	// Flap detection over the transitions inside the window.
	win := time.Duration(rl.FlapWindowMinutes) * time.Minute
	kept := s.Transitions[:0]
	for _, t := range s.Transitions {
		if now.Sub(t) <= win {
			kept = append(kept, t)
		}
	}
	s.Transitions = kept
	if rl.FlapTransitions > 0 {
		if !s.Flapping && len(s.Transitions) >= rl.FlapTransitions {
			s.Flapping = true
			return "flapping"
		}
		if s.Flapping {
			if len(s.Transitions) == 0 || now.Sub(s.Transitions[len(s.Transitions)-1]) >= win/2 {
				s.Flapping = false
				s.Transitions = s.Transitions[:0] // start counting afresh
				return "flapping_end"
			}
			return "" // hold back fire/resolve/reminders while flapping
		}
	}

	if event == "" && s.Firing && rl.RepeatMinutes > 0 && s.LastNotified != nil &&
		now.Sub(*s.LastNotified) >= time.Duration(rl.RepeatMinutes)*time.Minute {
		event = "reminder"
	}
	return event
}

func (a *App) evaluateRule(ctx context.Context, rl *alertRule, now time.Time, wg *sync.WaitGroup) error {
	hosts, err := a.scopeHosts(ctx, rl)
	if err != nil {
		return err
	}
	var orgName string
	_ = a.db.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, rl.orgID).Scan(&orgName)
	var chans []*channel
	for _, id := range rl.ChannelIDs {
		if c, err := a.loadChannel(ctx, rl.orgID, id); err == nil && c.Enabled {
			chans = append(chans, c)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].id < hosts[j].id })
	for _, h := range hosts {
		s, _ := a.loadState(ctx, rl.ID, h.id)
		v, ok := a.measure(ctx, rl, h, now)
		event := step(rl, &s, v, ok, now)
		if event != "" {
			t := now
			s.LastNotified = &t
		}
		a.saveState(ctx, rl.ID, h.id, s)
		if event == "" {
			continue
		}
		m := a.buildMessage(rl, h, orgName, event, s, v)
		for _, c := range chans {
			wg.Add(1)
			go func(c *channel) {
				defer wg.Done()
				err := a.deliverWithRetry(ctx, c, m)
				a.logDelivery(context.Background(), rl.orgID, rl.ID, h.id, c.ID, event, m, err)
			}(c)
		}
	}
	return nil
}

func (a *App) deliverWithRetry(ctx context.Context, c *channel, m alertMessage) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = a.deliver(ctx, c, m); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(a.retryDelay * time.Duration(attempt+1)):
		}
	}
	return err
}

func (a *App) buildMessage(rl *alertRule, h hostInfo, org, event string, s alertState, v float64) alertMessage {
	what, unit := "Packet loss", "%"
	if rl.Metric == "latency" {
		what, unit = "Median latency", " ms"
	}
	host := h.name
	if h.addr != "" && h.addr != h.name {
		host += " (" + h.addr + ")"
	}
	val := strconv.FormatFloat(v, 'f', 1, 64) + unit
	thr := fmtNum(rl.Threshold) + unit
	m := alertMessage{Event: event, Link: a.appURL}
	switch event {
	case "firing":
		m.Firing = true
		m.Title = fmt.Sprintf("[ALERT] %s: %s %s", host, strings.ToLower(what), val)
		m.Lines = []string{fmt.Sprintf("%s has been at or above %s for %d min.", what, thr, rl.ForMinutes)}
	case "reminder":
		m.Firing = true
		m.Title = fmt.Sprintf("[STILL FIRING] %s: %s %s", host, strings.ToLower(what), val)
		m.Lines = []string{fmt.Sprintf("Alerting since %s (%s).", s.Since.UTC().Format("2006-01-02 15:04 UTC"), humanDur(time.Since(s.Since)))}
	case "resolved":
		m.Title = fmt.Sprintf("[RESOLVED] %s: %s %s", host, strings.ToLower(what), val)
		m.Lines = []string{fmt.Sprintf("Back below %s%s for %d min.", fmtNum(rl.RecoverThreshold), unit, rl.RecoverMinutes)}
	case "flapping":
		m.Neutral = true
		m.Title = fmt.Sprintf("[FLAPPING] %s: %s keeps crossing %s", host, strings.ToLower(what), thr)
		m.Lines = []string{fmt.Sprintf("%d state changes in %d min. Further alerts for this host are paused until it is stable.", len(s.Transitions), rl.FlapWindowMinutes)}
	case "flapping_end":
		state := "recovered"
		if s.Firing {
			state, m.Firing = "still alerting", true
		}
		m.Title = fmt.Sprintf("[STABLE] %s: no longer flapping, %s", host, state)
		m.Lines = []string{fmt.Sprintf("%s now %s (threshold %s).", what, val, thr)}
	}
	m.Lines = append(m.Lines, "Rule: "+rl.Name+" · Organization: "+org)
	return m
}

func humanDur(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f h", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}
