package main

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// audit records an action performed by a user. Best-effort: logging failures
// never block the request.
func (a *App) audit(ctx context.Context, u *currentUser, ip, action, detail string) {
	if u == nil {
		return
	}
	_, _ = a.db.Exec(ctx, `
		INSERT INTO audit_log (org_id, user_id, user_email, action, detail, ip)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		u.OrgID, u.ID, u.Email, action, detail, ip)
}

// auditAnon records an action where there is no authenticated user yet
// (registration, invite acceptance).
func (a *App) auditAnon(ctx context.Context, orgID int64, email, ip, action, detail string) {
	_, _ = a.db.Exec(ctx, `
		INSERT INTO audit_log (org_id, user_email, action, detail, ip)
		VALUES ($1,$2,$3,$4,$5)`,
		orgID, email, action, detail, ip)
}

// auditFor records an action by u that concerns another organization (a
// platform administrator acting on a tenant): it lands in that org's log.
func (a *App) auditFor(ctx context.Context, orgID int64, u *currentUser, ip, action, detail string) {
	_, _ = a.db.Exec(ctx, `
		INSERT INTO audit_log (org_id, user_id, user_email, action, detail, ip)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		orgID, u.ID, u.Email, action, detail, ip)
}

// auditSystem records an event that belongs to no organization: background
// jobs, startup, sign-in attempts for unknown emails. Visible only in the
// platform administrators' global audit log.
func (a *App) auditSystem(ctx context.Context, email, ip, action, detail string) {
	auditSystemDB(ctx, a.db, email, ip, action, detail)
}

func auditSystemDB(ctx context.Context, db *pgxpool.Pool, email, ip, action, detail string) {
	_, _ = db.Exec(ctx, `
		INSERT INTO audit_log (org_id, user_email, action, detail, ip)
		VALUES (NULL, NULLIF($1,''), $2, $3, NULLIF($4,''))`,
		email, action, detail, ip)
}

// auditSystemBy records an action by u that leaves no organization to file
// it under (a platform administrator deleting one): it lands in the system
// log, with the administrator's identity.
func (a *App) auditSystemBy(ctx context.Context, u *currentUser, ip, action, detail string) {
	_, _ = a.db.Exec(ctx, `
		INSERT INTO audit_log (org_id, user_id, user_email, action, detail, ip)
		VALUES (NULL, $1, $2, $3, $4, $5)`,
		u.ID, u.Email, action, detail, ip)
}

// handleAuditList returns one page of the organization's audit log, newest
// first, with the total number of entries (limit and offset: pageParams).
func (a *App) handleAuditList(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	limit, offset := pageParams(r)
	ctx := r.Context()
	var total int
	if err := a.db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE org_id = $1`, u.OrgID).Scan(&total); err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	rows, err := a.db.Query(ctx, `
		SELECT id, COALESCE(user_email,''), action, COALESCE(detail,''), COALESCE(ip,''), created_at
		FROM audit_log WHERE org_id = $1
		ORDER BY id DESC LIMIT $2 OFFSET $3`, u.OrgID, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type entry struct {
		ID        int64  `json:"id"`
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
		if err := rows.Scan(&e.ID, &e.Email, &e.Action, &e.Detail, &e.IP, &created); err != nil {
			continue
		}
		e.CreatedAt = created.Unix()
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "total": total})
}
