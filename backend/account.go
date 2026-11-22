package main

import (
	"net/http"
	"strconv"
	"strings"
)

// handleUpdateName sets the user's display name shown to teammates.
func (a *App) handleUpdateName(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.FirstName = strings.TrimSpace(in.FirstName)
	in.LastName = strings.TrimSpace(in.LastName)
	if len(in.FirstName) > 100 || len(in.LastName) > 100 {
		writeErr(w, http.StatusBadRequest, "name too long")
		return
	}
	if _, err := a.db.Exec(r.Context(),
		`UPDATE users SET first_name = $1, last_name = $2 WHERE id = $3`,
		in.FirstName, in.LastName, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(r.Context(), u, clientIP(r), "account.name_change", strings.TrimSpace(in.FirstName+" "+in.LastName))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
		Confirm string `json:"confirm"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !validPassword(in.New) {
		writeErr(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if in.New != in.Confirm {
		writeErr(w, http.StatusBadRequest, "new passwords do not match")
		return
	}

	ctx := r.Context()
	if !a.checkPassword(w, r, u, in.Current, "account.password_change", "current password is incorrect") {
		return
	}
	nph, err := hashPassword(in.New)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash failed")
		return
	}
	if _, err := a.db.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, nph, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	// Invalidate other sessions for safety; keep the current one.
	if c, err := r.Cookie(sessionCookie); err == nil {
		_, _ = a.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token <> $2`, u.ID, c.Value)
	}
	a.audit(ctx, u, clientIP(r), "account.password_change", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleChangeEmail(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(in.Email) {
		writeErr(w, http.StatusBadRequest, "invalid email")
		return
	}

	ctx := r.Context()
	if !a.checkPassword(w, r, u, in.Password, "account.email_change", "password is incorrect") {
		return
	}
	if _, err := a.db.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, in.Email, u.ID); err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "email already in use")
			return
		}
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "account.email_change", u.Email+" -> "+in.Email)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// checkPassword re-verifies the signed-in user's password before a sensitive
// change, with the same guessing limit as login. On failure it has already
// written the response (and audited the refusal).
func (a *App) checkPassword(w http.ResponseWriter, r *http.Request, u *currentUser, pw, action, msg string) bool {
	key := "pw-user:" + strconv.FormatInt(u.ID, 10)
	if a.limiter.blocked(key, maxFailsPerAccount) {
		a.audit(r.Context(), u, clientIP(r), "denied."+action, "too many failed password attempts")
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return false
	}
	var ph string
	if err := a.db.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id = $1`, u.ID).Scan(&ph); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return false
	}
	if !verifyPassword(pw, ph) {
		a.limiter.fail(key)
		a.deny(w, r, action, msg)
		return false
	}
	a.limiter.clear(key)
	return true
}

// handleSetRetention sets how many years of history the housekeeper keeps.
func (a *App) handleSetRetention(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Role == "member" {
		a.deny(w, r, "org.retention_change", "only owners and admins can change retention")
		return
	}
	var in struct {
		Years int `json:"years"`
	}
	if err := readJSON(r, &in); err != nil || in.Years < 1 || in.Years > 3 {
		writeErr(w, http.StatusBadRequest, "years must be 1, 2 or 3")
		return
	}
	if _, err := a.db.Exec(r.Context(),
		`UPDATE organizations SET retention_years = $1 WHERE id = $2`, in.Years, u.OrgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(r.Context(), u, clientIP(r), "org.retention_change", strconv.Itoa(in.Years)+" years")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
