package main

import (
	"net/http"
	"time"
)

const inviteTTL = 48 * time.Hour

func (a *App) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Role == "member" {
		a.deny(w, r, "invite.create", "only owners and admins can invite")
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	_ = readJSON(r, &in)
	if in.Role != "admin" && in.Role != "member" {
		in.Role = "member"
	}

	token := randomToken()
	expires := time.Now().Add(inviteTTL)
	_, err := a.db.Exec(r.Context(),
		`INSERT INTO invites (token, org_id, role, created_by, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		token, u.OrgID, in.Role, u.ID, expires)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create invite")
		return
	}
	a.audit(r.Context(), u, clientIP(r), "invite.create", "role="+in.Role+", token "+tokenHint(token))

	// The frontend turns this token into a full URL it can display/copy.
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"role":       in.Role,
		"expires_at": expires.Unix(),
		"ttl_hours":  48,
	})
}

func (a *App) handleListInvites(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	// Pending tokens are credentials (an admin invite grants admin), so
	// members must not see them.
	if u.Role == "member" {
		a.deny(w, r, "invite.list", "only owners and admins can view invites")
		return
	}
	rows, err := a.db.Query(r.Context(), `
		SELECT token, role, expires_at, used_at IS NOT NULL, expires_at < now()
		FROM invites WHERE org_id = $1 ORDER BY created_at DESC LIMIT 100`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type inv struct {
		Token   string `json:"token"`
		Role    string `json:"role"`
		Expires int64  `json:"expires_at"`
		Used    bool   `json:"used"`
		Expired bool   `json:"expired"`
	}
	out := []inv{}
	for rows.Next() {
		var v inv
		var exp time.Time
		if err := rows.Scan(&v.Token, &v.Role, &exp, &v.Used, &v.Expired); err != nil {
			continue
		}
		v.Expires = exp.Unix()
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Role == "member" {
		a.deny(w, r, "invite.revoke", "only owners and admins can revoke invites")
		return
	}
	token := r.PathValue("token")
	ct, err := a.db.Exec(r.Context(),
		`DELETE FROM invites WHERE token = $1 AND org_id = $2 AND used_at IS NULL`, token, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if ct.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "invite not found")
		return
	}
	a.audit(r.Context(), u, clientIP(r), "invite.revoke", "token "+tokenHint(token))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// tokenHint identifies an invite in the audit log without storing the
// usable token.
func tokenHint(t string) string {
	if len(t) > 6 {
		return t[:6] + "..."
	}
	return t
}

func (a *App) handleListUsers(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	rows, err := a.db.Query(r.Context(), `
		SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.created_at, u.last_login_at, u.totp_enabled,
		       COALESCE((SELECT array_agg(DISTINCT c.kind) FROM webauthn_credentials c WHERE c.user_id = u.id), '{}'),
		       COALESCE((SELECT av.etag FROM user_avatars av WHERE av.user_id = u.id), '')
		FROM users u WHERE u.org_id = $1 ORDER BY u.created_at`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	// Sign-in details (last sign-in, second factors) are for the people who
	// manage the team, and for everyone about their own account.
	manages := u.Role != "member"
	type usr struct {
		ID        int64     `json:"id"`
		Email     string    `json:"email"`
		FirstName string    `json:"first_name"`
		LastName  string    `json:"last_name"`
		Role      string    `json:"role"`
		Created   int64     `json:"created_at"`
		Self      bool      `json:"self"`
		Avatar    string    `json:"avatar"`
		LastLogin *int64    `json:"last_login,omitempty"`
		TwoFactor *[]string `json:"two_factor,omitempty"`
	}
	out := []usr{}
	for rows.Next() {
		var v usr
		var created time.Time
		var last *time.Time
		var totp bool
		var kinds []string
		if err := rows.Scan(&v.ID, &v.Email, &v.FirstName, &v.LastName, &v.Role, &created, &last, &totp, &kinds, &v.Avatar); err != nil {
			continue
		}
		v.Created = created.Unix()
		v.Self = v.ID == u.ID
		if manages || v.Self {
			if last != nil {
				t := last.Unix()
				v.LastLogin = &t
			}
			tf := twoFactorList(totp, kinds)
			v.TwoFactor = &tf
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRemoveUser removes a member from the organization. Owners can remove
// anyone but themselves; admins can remove members only. Sessions cascade.
func (a *App) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Role == "member" {
		a.deny(w, r, "user.remove", "only owners and admins can remove members")
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if id == u.ID {
		writeErr(w, http.StatusBadRequest, "you cannot remove yourself")
		return
	}
	ctx := r.Context()
	var role, email string
	err = a.db.QueryRow(ctx,
		`SELECT role, email FROM users WHERE id = $1 AND org_id = $2`, id, u.OrgID).Scan(&role, &email)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if role == "owner" {
		a.deny(w, r, "user.remove", "the owner cannot be removed")
		return
	}
	if u.Role == "admin" && role != "member" {
		a.deny(w, r, "user.remove", "only the owner can remove admins")
		return
	}
	if _, err := a.db.Exec(ctx, `DELETE FROM users WHERE id = $1 AND org_id = $2`, id, u.OrgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "user.remove", "removed "+email+" ("+role+")")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleChangeRole switches a teammate between admin and member. Owners and
// admins may do it for anyone except the owner and themselves (so nobody
// locks themselves out by accident). Ownership is never transferred here.
func (a *App) handleChangeRole(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Role == "member" {
		a.deny(w, r, "user.role_change", "only owners and admins can change roles")
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if err := readJSON(r, &in); err != nil || (in.Role != "admin" && in.Role != "member") {
		writeErr(w, http.StatusBadRequest, "role must be admin or member")
		return
	}
	if id == u.ID {
		writeErr(w, http.StatusBadRequest, "you cannot change your own role")
		return
	}
	ctx := r.Context()
	var role, email string
	if err := a.db.QueryRow(ctx, `SELECT role, email FROM users WHERE id = $1 AND org_id = $2`, id, u.OrgID).Scan(&role, &email); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if role == "owner" {
		a.deny(w, r, "user.role_change", "the owner's role cannot be changed")
		return
	}
	if role != in.Role {
		if _, err := a.db.Exec(ctx, `UPDATE users SET role = $1 WHERE id = $2 AND org_id = $3`, in.Role, id, u.OrgID); err != nil {
			writeErr(w, http.StatusInternalServerError, "update failed")
			return
		}
	}
	a.audit(ctx, u, clientIP(r), "user.role_change", email+": "+role+" -> "+in.Role)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "role": in.Role})
}
