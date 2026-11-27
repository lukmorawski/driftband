package main

// Platform administration: cross-tenant views and actions for superadmins
// (users.is_superadmin, granted only in the database). Every route here is
// wrapped by App.superadmin; every change is audited into the affected
// organization's log, so tenants can see what an administrator did.

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ----- organizations and users -----

func (a *App) handleAdminOrgs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bpr := a.bytesPerSampleRow(ctx)
	rows, err := a.db.Query(ctx, `
		SELECT o.id, o.name, o.disabled, o.retention_years, o.created_at, o.host_limit, o.exempt_limits,
		       (SELECT count(*) FROM users u WHERE u.org_id = o.id),
		       (SELECT count(*) FROM nodes n WHERE n.org_id = o.id AND n.kind = 'host'),
		       COALESCE((SELECT sum(r.cycles) FROM sample_rollups r JOIN nodes n ON n.id = r.host_id
		                 WHERE n.org_id = o.id AND r.res = 3600), 0),
		       (SELECT max(created_at) FROM audit_log al WHERE al.org_id = o.id AND al.action = 'auth.login')
		FROM organizations o ORDER BY o.id`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type org struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Disabled  bool   `json:"disabled"`
		Retention int    `json:"retention_years"`
		Created   int64  `json:"created_at"`
		Users     int    `json:"users"`
		Hosts     int    `json:"hosts"`
		HostLimit *int   `json:"host_limit"`           // explicit limit, null = instance default
		Exempt    bool   `json:"exempt_limits"`        // test-instance limits do not apply
		Effective int    `json:"effective_host_limit"` // 0 = unlimited
		Samples   int64  `json:"samples"`              // probe cycles stored (from rollups)
		EstBytes  int64  `json:"est_bytes"`            // estimated storage for those cycles
		LastLogin int64  `json:"last_login"`           // 0 = never
	}
	out := []org{}
	for rows.Next() {
		var o org
		var created time.Time
		var last *time.Time
		if err := rows.Scan(&o.ID, &o.Name, &o.Disabled, &o.Retention, &created, &o.HostLimit, &o.Exempt, &o.Users, &o.Hosts, &o.Samples, &last); err != nil {
			continue
		}
		o.Effective = a.effectiveHostLimit(o.HostLimit, o.Exempt)
		o.Created = created.Unix()
		if last != nil {
			o.LastLogin = last.Unix()
		}
		o.EstBytes = int64(float64(o.Samples) * bpr)
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleAdminOrgUsers(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	rows, err := a.db.Query(r.Context(), `
		SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.disabled, u.totp_enabled,
		       COALESCE((SELECT array_agg(DISTINCT c.kind) FROM webauthn_credentials c WHERE c.user_id = u.id), '{}'),
		       u.is_superadmin, u.created_at,
		       (SELECT max(created_at) FROM audit_log al WHERE al.user_email = u.email AND al.action = 'auth.login'),
		       (SELECT count(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > now())
		FROM users u WHERE u.org_id = $1 ORDER BY u.created_at`, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type usr struct {
		ID         int64    `json:"id"`
		Email      string   `json:"email"`
		FirstName  string   `json:"first_name"`
		LastName   string   `json:"last_name"`
		Role       string   `json:"role"`
		Disabled   bool     `json:"disabled"`
		TOTP       bool     `json:"totp_enabled"`
		TwoFactor  []string `json:"two_factor"`
		Superadmin bool     `json:"is_superadmin"`
		Created    int64    `json:"created_at"`
		LastLogin  int64    `json:"last_login"`
		Sessions   int      `json:"sessions"`
	}
	out := []usr{}
	for rows.Next() {
		var v usr
		var created time.Time
		var last *time.Time
		var kinds []string
		if err := rows.Scan(&v.ID, &v.Email, &v.FirstName, &v.LastName, &v.Role, &v.Disabled, &v.TOTP, &kinds,
			&v.Superadmin, &created, &last, &v.Sessions); err != nil {
			continue
		}
		v.TwoFactor = twoFactorList(v.TOTP, kinds)
		v.Created = created.Unix()
		if last != nil {
			v.LastLogin = last.Unix()
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleAdminBlockOrg(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Blocked bool `json:"blocked"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if id == u.OrgID && in.Blocked {
		writeErr(w, http.StatusBadRequest, "you cannot block your own organization")
		return
	}
	ctx := r.Context()
	var name string
	if err := a.db.QueryRow(ctx, `UPDATE organizations SET disabled = $1 WHERE id = $2 RETURNING name`, in.Blocked, id).Scan(&name); err != nil {
		writeErr(w, http.StatusNotFound, "organization not found")
		return
	}
	ended := int64(0)
	if in.Blocked {
		ct, _ := a.db.Exec(ctx, `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE org_id = $1)`, id)
		ended = ct.RowsAffected()
	}
	action := map[bool]string{true: "admin.org_block", false: "admin.org_unblock"}[in.Blocked]
	a.auditFor(ctx, id, u, clientIP(r), action, name+", sessions ended: "+strconv.FormatInt(ended, 10))
	a.pm.kick() // blocked organizations are not probed
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdminSetLimits sets an organization's host limit (null restores the
// instance default). Existing hosts are kept even above the limit; only
// adding more is refused.
func (a *App) handleAdminSetLimits(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		HostLimit *int  `json:"host_limit"`
		Exempt    *bool `json:"exempt_limits"`
	}
	if err := readJSON(r, &in); err != nil || (in.HostLimit != nil && (*in.HostLimit < 0 || *in.HostLimit > 100000)) {
		writeErr(w, http.StatusBadRequest, "host_limit must be 0 (unlimited) to 100000, or null for the default")
		return
	}
	ctx := r.Context()
	var name string
	var exempt bool
	if err := a.db.QueryRow(ctx, `UPDATE organizations SET host_limit = $1, exempt_limits = COALESCE($3, exempt_limits)
		WHERE id = $2 RETURNING name, exempt_limits`, in.HostLimit, id, in.Exempt).Scan(&name, &exempt); err != nil {
		writeErr(w, http.StatusNotFound, "organization not found")
		return
	}
	detail := name + ": host limit = default"
	if in.HostLimit != nil {
		detail = name + ": host limit = " + strconv.Itoa(*in.HostLimit)
		if *in.HostLimit == 0 {
			detail += " (unlimited)"
		}
	}
	if exempt {
		detail += ", exempt from test-instance limits"
	}
	a.auditFor(ctx, id, userFrom(r), clientIP(r), "admin.org_limits", detail)
	a.pm.kick() // exemption changes the prober's clamping
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "effective_host_limit": a.effectiveHostLimit(in.HostLimit, exempt)})
}

// adminTarget loads a user an administrator wants to act on and enforces the
// common rules: not yourself, not another platform administrator.
func (a *App) adminTarget(w http.ResponseWriter, r *http.Request, action string) (id, orgID int64, email, role string, ok bool) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if id == u.ID {
		writeErr(w, http.StatusBadRequest, "use your own account settings for yourself")
		return
	}
	var super bool
	if err := a.db.QueryRow(r.Context(), `SELECT org_id, email, role, is_superadmin FROM users WHERE id = $1`, id).
		Scan(&orgID, &email, &role, &super); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if super {
		a.deny(w, r, action, "platform administrators cannot be changed here")
		return
	}
	return id, orgID, email, role, true
}

func (a *App) handleAdminBlockUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Blocked bool `json:"blocked"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	action := map[bool]string{true: "admin.user_block", false: "admin.user_unblock"}[in.Blocked]
	id, orgID, email, _, ok := a.adminTarget(w, r, action)
	if !ok {
		return
	}
	ctx := r.Context()
	if _, err := a.db.Exec(ctx, `UPDATE users SET disabled = $1 WHERE id = $2`, in.Blocked, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if in.Blocked {
		_, _ = a.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
	}
	a.auditFor(ctx, orgID, userFrom(r), clientIP(r), action, email)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdminResetPassword sets a random temporary password, returned once to
// the administrator (never logged), and signs the user out everywhere.
// Optionally turns off 2FA for users who lost their device.
func (a *App) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reset2FA bool `json:"reset_2fa"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	id, orgID, email, _, ok := a.adminTarget(w, r, "admin.user_password_reset")
	if !ok {
		return
	}
	pw := randomPassword(20)
	ph, err := hashPassword(pw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash failed")
		return
	}
	ctx := r.Context()
	q := `UPDATE users SET password_hash = $1 WHERE id = $2`
	if in.Reset2FA {
		q = `UPDATE users SET password_hash = $1, totp_enabled = false, totp_secret = NULL, totp_last_step = 0 WHERE id = $2`
	}
	if _, err := a.db.Exec(ctx, q, ph, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if in.Reset2FA {
		_, _ = a.db.Exec(ctx, `DELETE FROM webauthn_credentials WHERE user_id = $1`, id)
	}
	// A reset takes back the account: whoever connected a single sign-on
	// identity to it must not keep that way in.
	_, _ = a.db.Exec(ctx, `DELETE FROM user_identities WHERE user_id = $1`, id)
	_, _ = a.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
	a.limiter.clear("login-email:"+email, "pw-user:"+strconv.FormatInt(id, 10))
	detail := email
	if in.Reset2FA {
		detail += ", two-factor reset"
	}
	a.auditFor(ctx, orgID, userFrom(r), clientIP(r), "admin.user_password_reset", detail)
	writeJSON(w, http.StatusOK, map[string]any{"password": pw})
}

func (a *App) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, orgID, email, role, ok := a.adminTarget(w, r, "admin.user_delete")
	if !ok {
		return
	}
	if role == "owner" {
		a.deny(w, r, "admin.user_delete", "an organization owner cannot be deleted; block the organization instead")
		return
	}
	ctx := r.Context()
	if _, err := a.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	a.auditFor(ctx, orgID, userFrom(r), clientIP(r), "admin.user_delete", email+" ("+role+")")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdminOrgHosts lists the hosts an organization monitors, with the
// probe parameters the prober really uses (profile or the organization's
// default, with the instance limits applied) and each host's newest cycle.
func (a *App) handleAdminOrgHosts(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	var exempt bool
	if err := a.db.QueryRow(ctx, `SELECT exempt_limits FROM organizations WHERE id = $1`, id).Scan(&exempt); err != nil {
		writeErr(w, http.StatusNotFound, "organization not found")
		return
	}
	rows, err := a.db.Query(ctx, `
		WITH RECURSIVE tree AS (
			SELECT id, name, ''::text AS path FROM nodes WHERE org_id = $1 AND parent_id IS NULL
			UNION ALL
			SELECT n.id, n.name, CASE WHEN t.path = '' THEN t.name ELSE t.path || ' / ' || t.name END
			FROM nodes n JOIN tree t ON n.parent_id = t.id
		)
		SELECT n.id, n.name, COALESCE(n.host, ''), COALESCE(n.description, ''), t.path,
		       COALESCE(p.name, dp.name, ''), COALESCE(p.is_default, true),
		       COALESCE(p.interval_s, dp.interval_s, 60),
		       COALESCE(p.ping_count, dp.ping_count, 20),
		       COALESCE(p.packet_size, dp.packet_size, 56),
		       n.created_at, s.ts, s.sent, s.recv
		FROM nodes n
		JOIN tree t ON t.id = n.id
		LEFT JOIN probe_profiles p ON p.id = n.profile_id
		LEFT JOIN LATERAL (
		    SELECT name, interval_s, ping_count, packet_size FROM probe_profiles d
		    WHERE d.org_id = n.org_id ORDER BY is_default DESC, id LIMIT 1
		) dp ON true
		LEFT JOIN LATERAL (
		    SELECT ts, sent, recv FROM samples WHERE host_id = n.id ORDER BY ts DESC LIMIT 1
		) s ON true
		WHERE n.org_id = $1 AND n.kind = 'host'
		ORDER BY t.path, n.position, n.name`, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type host struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Host        string `json:"host"`
		Description string `json:"description"`
		Path        string `json:"path"` // folders above the host, "" at the top level
		Profile     string `json:"profile"`
		DefaultProf bool   `json:"default_profile"` // the organization's default profile applies
		IntervalS   int    `json:"interval_s"`
		PingCount   int    `json:"ping_count"`
		PacketSize  int    `json:"packet_size"`
		Created     int64  `json:"created_at"`
		LastTS      int64  `json:"last_ts"` // newest cycle, 0 = never probed
		LastSent    int    `json:"last_sent"`
		LastRecv    int    `json:"last_recv"`
	}
	out := []host{}
	for rows.Next() {
		var h host
		var created time.Time
		var last *time.Time
		var sent, recv *int
		if err := rows.Scan(&h.ID, &h.Name, &h.Host, &h.Description, &h.Path, &h.Profile, &h.DefaultProf,
			&h.IntervalS, &h.PingCount, &h.PacketSize, &created, &last, &sent, &recv); err != nil {
			continue
		}
		// The same clamps as the prober (loadHosts), so this is what runs.
		h.PacketSize = min(h.PacketSize, maxPacketSize)
		h.PingCount = min(h.PingCount, h.IntervalS)
		if a.testMode && !exempt {
			h.IntervalS = max(h.IntervalS, testMinInterval)
			h.PacketSize = min(h.PacketSize, testMaxPacket)
		}
		h.Created = created.Unix()
		if last != nil {
			h.LastTS, h.LastSent, h.LastRecv = last.Unix(), *sent, *recv
		}
		out = append(out, h)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAdminDeleteOrg removes an organization with everything it owns:
// users and their sessions, hosts with all samples and rollups, profiles,
// notification channels, rules and history, invites and its audit log (the
// schema cascades from organizations). The administrator confirms with
// their password and the organization's name. Their own organization and
// one that holds a platform administrator cannot be deleted. The deletion
// itself is recorded in the system log, which outlives the organization.
func (a *App) handleAdminDeleteOrg(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if id == u.OrgID {
		writeErr(w, http.StatusBadRequest, "you cannot delete your own organization")
		return
	}
	ctx := r.Context()
	var name string
	var users, supers, hosts int
	var cycles int64
	if err := a.db.QueryRow(ctx, `
		SELECT o.name,
		       (SELECT count(*) FROM users u WHERE u.org_id = o.id),
		       (SELECT count(*) FROM users u WHERE u.org_id = o.id AND u.is_superadmin),
		       (SELECT count(*) FROM nodes n WHERE n.org_id = o.id AND n.kind = 'host'),
		       COALESCE((SELECT sum(r.cycles) FROM sample_rollups r JOIN nodes n ON n.id = r.host_id
		                 WHERE n.org_id = o.id AND r.res = 3600), 0)
		FROM organizations o WHERE o.id = $1`, id).Scan(&name, &users, &supers, &hosts, &cycles); err != nil {
		writeErr(w, http.StatusNotFound, "organization not found")
		return
	}
	if supers > 0 {
		a.deny(w, r, "admin.org_delete", "an organization with a platform administrator cannot be deleted")
		return
	}
	if strings.TrimSpace(in.Name) != name {
		writeErr(w, http.StatusBadRequest, "type the organization's name exactly to confirm")
		return
	}
	if !a.checkPassword(w, r, u, in.Password, "admin.org_delete", "password is incorrect") {
		return
	}
	// Months of samples can take a while to delete: finish even if the
	// client goes away, so an organization is never left half removed (the
	// delete is one statement, all or nothing).
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
	defer cancel()
	ct, err := a.db.Exec(dctx, `DELETE FROM organizations WHERE id = $1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	a.auditSystemBy(dctx, u, clientIP(r), "admin.org_delete",
		name+" (id "+strconv.FormatInt(id, 10)+"): "+strconv.Itoa(users)+" users, "+strconv.Itoa(hosts)+
			" hosts, about "+strconv.FormatInt(cycles, 10)+" stored cycles removed")
	a.pm.kick() // its hosts stop being probed
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": users, "hosts": hosts})
}

// randomPassword returns n characters from an unambiguous alphabet.
func randomPassword(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	var sb strings.Builder
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		sb.WriteByte(alphabet[k.Int64()])
	}
	return sb.String()
}

// ----- usage statistics and forecast -----

// bytesPerSampleRow is the on-disk cost of one stored probe cycle, including
// indexes and its share of the rollups.
func (a *App) bytesPerSampleRow(ctx context.Context) float64 {
	bpr, _ := a.sampleStorage(ctx)
	return bpr
}

// sampleStorage estimates the stored bytes per probe cycle (measurements
// and their summaries, with indexes) and the share of it that is the
// full-resolution measurements.
func (a *App) sampleStorage(ctx context.Context) (bytesPerRow, rawShare float64) {
	var bytes, rollups, rows float64
	_ = a.db.QueryRow(ctx, `
		SELECT pg_total_relation_size('samples'), pg_total_relation_size('sample_rollups'),
		       GREATEST((SELECT reltuples FROM pg_class WHERE oid = 'samples'::regclass), 0)`).Scan(&bytes, &rollups, &rows)
	if rows < 1 || bytes+rollups <= 0 {
		return 400, 0.9 // empty database: typical size of a 20-ping row with indexes
	}
	return (bytes + rollups) / rows, bytes / (bytes + rollups)
}

type tableStat struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Rows  int64  `json:"rows"` // planner estimate
}

type forecastPoint struct {
	Day   int   `json:"day"` // days from today
	Bytes int64 `json:"bytes"`
}

func (a *App) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{}

	var dbBytes int64
	_ = a.db.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&dbBytes)
	out["db_bytes"] = dbBytes

	tables := []tableStat{}
	if rows, err := a.db.Query(ctx, `
		SELECT c.relname, pg_total_relation_size(c.oid),
		       GREATEST(c.reltuples, COALESCE(st.n_live_tup, 0), 0)::bigint
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
		WHERE c.relkind = 'r' AND n.nspname = 'public'
		ORDER BY 2 DESC`); err == nil {
		for rows.Next() {
			var t tableStat
			if rows.Scan(&t.Name, &t.Bytes, &t.Rows) == nil {
				tables = append(tables, t)
			}
		}
		rows.Close()
	}
	out["tables"] = tables

	counts := map[string]int64{}
	for k, q := range map[string]string{
		"orgs":              `SELECT count(*) FROM organizations`,
		"orgs_blocked":      `SELECT count(*) FROM organizations WHERE disabled`,
		"users":             `SELECT count(*) FROM users`,
		"users_blocked":     `SELECT count(*) FROM users WHERE disabled`,
		"users_2fa":         `SELECT count(*) FROM users u WHERE u.totp_enabled OR EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.user_id = u.id)`,
		"hosts":             `SELECT count(*) FROM nodes WHERE kind = 'host'`,
		"sessions":          `SELECT count(*) FROM sessions WHERE expires_at > now()`,
		"audit_entries":     `SELECT GREATEST(reltuples, 0)::bigint FROM pg_class WHERE oid = 'audit_log'::regclass`,
		"failed_logins_24h": `SELECT count(*) FROM audit_log WHERE action IN ('auth.login_failed','auth.login_blocked') AND created_at > now() - interval '1 day'`,
	} {
		var n int64
		_ = a.db.QueryRow(ctx, q).Scan(&n)
		counts[k] = n
	}
	out["counts"] = counts

	// Ingestion: stored probe cycles per day over the last 30 days (rollups).
	type day struct {
		Day    int64 `json:"day"` // unix, start of day (UTC)
		Cycles int64 `json:"cycles"`
	}
	daily := []day{}
	if rows, err := a.db.Query(ctx, `
		SELECT extract(epoch FROM date_trunc('day', ts))::bigint, sum(cycles)
		FROM sample_rollups WHERE res = 3600 AND ts >= date_trunc('day', now()) - interval '30 days'
		GROUP BY 1 ORDER BY 1`); err == nil {
		for rows.Next() {
			var d day
			if rows.Scan(&d.Day, &d.Cycles) == nil {
				daily = append(daily, d)
			}
		}
		rows.Close()
	}
	out["daily_cycles"] = daily

	// Size history snapshots (one per day, from the housekeeper).
	type snap struct {
		Day   int64 `json:"day"`
		Bytes int64 `json:"bytes"`
	}
	hist := []snap{}
	if rows, err := a.db.Query(ctx, `
		SELECT extract(epoch FROM day::timestamptz)::bigint, total_bytes
		FROM db_size_history ORDER BY day DESC LIMIT 400`); err == nil {
		for rows.Next() {
			var s snap
			if rows.Scan(&s.Day, &s.Bytes) == nil {
				hist = append([]snap{s}, hist...)
			}
		}
		rows.Close()
	}
	out["history"] = hist

	fc, err := a.forecast(ctx, dbBytes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "forecast failed")
		return
	}
	out["forecast"] = fc
	writeJSON(w, http.StatusOK, out)
}

// forecast projects database size from each active organization's configured
// probe rate and retention: an org grows by (cycles/day x bytes/cycle) until
// its oldest data reaches the retention age, then stays flat (housekeeper).
func (a *App) forecast(ctx context.Context, dbBytes int64) (map[string]any, error) {
	bpr := a.bytesPerSampleRow(ctx)
	rows, err := a.db.Query(ctx, `
		SELECT o.id, o.retention_years,
		       COALESCE(sum(86400.0 / COALESCE(p.interval_s, dp.interval_s, 60)), 0),
		       COALESCE((SELECT sum(r.cycles) FROM sample_rollups r JOIN nodes nn ON nn.id = r.host_id
		                 WHERE nn.org_id = o.id AND r.res = 3600), 0)
		FROM organizations o
		LEFT JOIN nodes n ON n.org_id = o.id AND n.kind = 'host'
		LEFT JOIN probe_profiles p ON p.id = n.profile_id
		LEFT JOIN LATERAL (
		    SELECT interval_s FROM probe_profiles d WHERE d.org_id = o.id ORDER BY is_default DESC, id LIMIT 1
		) dp ON true
		WHERE NOT o.disabled
		GROUP BY o.id, o.retention_years`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type orgRate struct {
		cyclesPerDay, stored, cap float64
	}
	var orgs []orgRate
	var totalRate, storedNow float64
	for rows.Next() {
		var id int64
		var years int
		var o orgRate
		if err := rows.Scan(&id, &years, &o.cyclesPerDay, &o.stored); err != nil {
			continue
		}
		o.cap = o.cyclesPerDay * 365 * float64(years)
		orgs = append(orgs, o)
		totalRate += o.cyclesPerDay
		storedNow += o.stored
	}
	base := float64(dbBytes) - storedNow*bpr // everything that is not probe data
	if base < 0 {
		base = 0
	}
	at := func(days float64) int64 {
		sum := 0.0
		for _, o := range orgs {
			sum += math.Min(o.stored+o.cyclesPerDay*days, math.Max(o.cap, o.stored))
		}
		return int64(base + sum*bpr)
	}
	points := []forecastPoint{}
	for d := 0; d <= 365*3; d += 7 {
		points = append(points, forecastPoint{Day: d, Bytes: at(float64(d))})
	}
	steady := 0.0
	for _, o := range orgs {
		steady += math.Max(o.cap, o.stored)
	}
	return map[string]any{
		"bytes_per_cycle": bpr,
		"cycles_per_day":  totalRate,
		"bytes_per_day":   int64(totalRate * bpr),
		"in_30_days":      at(30),
		"in_90_days":      at(90),
		"in_365_days":     at(365),
		"steady_state":    int64(base + steady*bpr),
		"points":          points,
	}, nil
}

// ----- global audit log -----

// handleAdminAudit lists audit entries across all organizations plus system
// events (org NULL). Filters: org (id or "system"), q (text), action prefix.
// Newest first, one page at a time (limit and offset: pageParams), with the
// total number of matching entries.
func (a *App) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	where := []string{"true"}
	args := []any{}
	arg := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }
	switch org := q.Get("org"); {
	case org == "system":
		where = append(where, "al.org_id IS NULL")
	case org != "":
		id, err := strconv.ParseInt(org, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad org")
			return
		}
		where = append(where, "al.org_id = "+arg(id))
	}
	if s := strings.TrimSpace(q.Get("q")); s != "" {
		p := arg("%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s) + "%")
		where = append(where, "(al.user_email ILIKE "+p+" OR al.action ILIKE "+p+" OR al.detail ILIKE "+p+" OR al.ip ILIKE "+p+")")
	}
	if s := strings.TrimSpace(q.Get("action")); s != "" {
		where = append(where, "al.action LIKE "+arg(strings.ReplaceAll(s, "%", "")+"%"))
	}
	limit, offset := pageParams(r)
	cond := strings.Join(where, " AND ")
	var total int
	if err := a.db.QueryRow(r.Context(), `SELECT count(*) FROM audit_log al WHERE `+cond, args...).Scan(&total); err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	rows, err := a.db.Query(r.Context(), `
		SELECT al.id, al.org_id, COALESCE(o.name, ''), COALESCE(al.user_email, ''), al.action,
		       COALESCE(al.detail, ''), COALESCE(al.ip, ''), al.created_at
		FROM audit_log al LEFT JOIN organizations o ON o.id = al.org_id
		WHERE `+cond+`
		ORDER BY al.id DESC LIMIT `+arg(limit)+` OFFSET `+arg(offset), args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type entry struct {
		ID        int64  `json:"id"`
		OrgID     *int64 `json:"org_id"`
		Org       string `json:"org"`
		Email     string `json:"email"`
		Action    string `json:"action"`
		Detail    string `json:"detail"`
		IP        string `json:"ip"`
		CreatedAt int64  `json:"created_at"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		var created time.Time
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Org, &e.Email, &e.Action, &e.Detail, &e.IP, &created); err != nil {
			continue
		}
		e.CreatedAt = created.Unix()
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "total": total})
}
