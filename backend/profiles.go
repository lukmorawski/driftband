package main

import (
	"fmt"
	"net/http"
)

type profile struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	IntervalS  int    `json:"interval_s"`
	PingCount  int    `json:"ping_count"`
	PacketSize int    `json:"packet_size"`
	Default    bool   `json:"is_default"`
}

func (a *App) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	rows, err := a.db.Query(r.Context(), `
		SELECT id, name, interval_s, ping_count, packet_size, is_default
		FROM probe_profiles WHERE org_id = $1 ORDER BY is_default DESC, name`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	out := []profile{}
	for rows.Next() {
		var p profile
		if err := rows.Scan(&p.ID, &p.Name, &p.IntervalS, &p.PingCount, &p.PacketSize, &p.Default); err != nil {
			continue
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in profile
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := validateProfile(in, a.strict(r.Context(), userFrom(r).OrgID)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	if in.Default {
		_, _ = tx.Exec(ctx, `UPDATE probe_profiles SET is_default = false WHERE org_id = $1`, u.OrgID)
	}
	var id int64
	err = tx.QueryRow(ctx, `
		INSERT INTO probe_profiles (org_id, name, interval_s, ping_count, packet_size, is_default)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		u.OrgID, in.Name, in.IntervalS, in.PingCount, in.PacketSize, in.Default).Scan(&id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "commit failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "profile.create", profileDetail(in))
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (a *App) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in profile
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := validateProfile(in, a.strict(r.Context(), userFrom(r).OrgID)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	if in.Default {
		_, _ = tx.Exec(ctx, `UPDATE probe_profiles SET is_default = false WHERE org_id = $1`, u.OrgID)
	}
	ct, err := tx.Exec(ctx, `
		UPDATE probe_profiles SET name=$1, interval_s=$2, ping_count=$3, packet_size=$4, is_default=$5
		WHERE id=$6 AND org_id=$7`,
		in.Name, in.IntervalS, in.PingCount, in.PacketSize, in.Default, id, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if ct.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "profile not found")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "commit failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "profile.update", profileDetail(in))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	var isDefault bool
	var name string
	if err := a.db.QueryRow(ctx,
		`SELECT is_default, name FROM probe_profiles WHERE id=$1 AND org_id=$2`, id, u.OrgID).Scan(&isDefault, &name); err != nil {
		writeErr(w, http.StatusNotFound, "profile not found")
		return
	}
	if isDefault {
		writeErr(w, http.StatusConflict, "cannot delete the default profile")
		return
	}
	// Hosts using this profile fall back to the default (profile_id -> NULL).
	if _, err := a.db.Exec(ctx, `DELETE FROM probe_profiles WHERE id=$1 AND org_id=$2`, id, u.OrgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "profile.delete", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func profileDetail(p profile) string {
	return fmt.Sprintf("%s (%d pings / %ds, %d B%s)", p.Name, p.PingCount, p.IntervalS, p.PacketSize,
		map[bool]string{true: ", default", false: ""}[p.Default])
}
