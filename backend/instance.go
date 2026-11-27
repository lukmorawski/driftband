package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// Instance-wide settings a platform administrator changes in the web
// interface (kept in app_settings), what the sign-in page needs to know
// about them, and the health endpoint for monitoring.

const settingRegistration = "registration_open"

// registrationOpen reports whether new organizations may be created. Open
// unless a platform administrator closed it; when the setting cannot be
// read, closed.
func (a *App) registrationOpen(ctx context.Context) bool {
	var v string
	err := a.db.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = $1`, settingRegistration).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return true
	}
	return err == nil && v != "false"
}

// handleAuthConfig tells the sign-in page, before anyone has signed in,
// whether organizations can be created, which Turnstile site key to use
// (empty when the check is off) and which single sign-on providers there
// are. Nothing here is secret.
func (a *App) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"registration_open": a.registrationOpen(r.Context()), "turnstile_site_key": "", "sso": a.sso.list()}
	if a.captcha != nil {
		out["turnstile_site_key"] = a.captcha.siteKey
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleAdminGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"registration_open": a.registrationOpen(r.Context()),
		// set in the environment, shown for information
		"turnstile_enabled": a.captcha != nil,
		"sso":               a.sso.list(),
	})
}

func (a *App) handleAdminSetSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RegistrationOpen *bool `json:"registration_open"`
	}
	if err := readJSON(r, &in); err != nil || in.RegistrationOpen == nil {
		writeErr(w, http.StatusBadRequest, "registration_open (true or false) is required")
		return
	}
	ctx := r.Context()
	v, detail := "true", "creating organizations turned on"
	if !*in.RegistrationOpen {
		v, detail = "false", "creating organizations turned off"
	}
	if _, err := a.db.Exec(ctx, `INSERT INTO app_settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, settingRegistration, v); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	a.auditSystemBy(ctx, userFrom(r), clientIP(r), "admin.settings_change", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "registration_open": *in.RegistrationOpen})
}

// handleHealth is the endpoint for load balancers, container health checks
// and monitoring: 200 when the application can serve requests, which means
// the database answers; 503 otherwise. It needs no session and says nothing
// about the instance beyond that.
func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var one int
	if err := a.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "database": "unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "database": "ok"})
}
