package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

const maxTreeDepth = 3

type node struct {
	ID          int64   `json:"id"`
	ParentID    *int64  `json:"parent_id"`
	Kind        string  `json:"kind"` // folder | host
	Name        string  `json:"name"`
	Host        string  `json:"host,omitempty"`
	Description string  `json:"description,omitempty"`
	ProfileID   *int64  `json:"profile_id"`
	Position    int     `json:"position"`
	Children    []*node `json:"children,omitempty"`
}

// handleTree returns the org's full node tree, nested.
func (a *App) handleTree(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	rows, err := a.db.Query(r.Context(), `
		SELECT id, parent_id, kind, name, COALESCE(host,''), COALESCE(description,''), profile_id, position
		FROM nodes WHERE org_id = $1 ORDER BY position, name`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	byID := map[int64]*node{}
	var all []*node
	for rows.Next() {
		n := &node{}
		if err := rows.Scan(&n.ID, &n.ParentID, &n.Kind, &n.Name, &n.Host, &n.Description, &n.ProfileID, &n.Position); err != nil {
			continue
		}
		byID[n.ID] = n
		all = append(all, n)
	}

	roots := []*node{}
	for _, n := range all {
		if n.ParentID == nil {
			roots = append(roots, n)
		} else if p, ok := byID[*n.ParentID]; ok {
			p.Children = append(p.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	writeJSON(w, http.StatusOK, roots)
}

func (a *App) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in node
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if in.Kind != "folder" && in.Kind != "host" {
		writeErr(w, http.StatusBadRequest, "kind must be folder or host")
		return
	}
	if in.Kind == "host" && !validHostAddr(in.Host) {
		writeErr(w, http.StatusBadRequest, "host address must be an IP address or a host name")
		return
	}
	if len(in.Name) > 200 || len(in.Description) > 500 {
		writeErr(w, http.StatusBadRequest, "name or description too long")
		return
	}
	if in.Kind == "host" && !a.checkHostQuota(w, r, 1) {
		return
	}

	ctx := r.Context()
	if !a.parentValid(ctx, u.OrgID, in.ParentID) {
		writeErr(w, http.StatusBadRequest, "invalid parent")
		return
	}
	if in.ParentID != nil && a.nodeDepth(ctx, u.OrgID, *in.ParentID) >= maxTreeDepth {
		writeErr(w, http.StatusBadRequest, "maximum nesting depth is 3")
		return
	}
	profileID := a.resolveProfile(ctx, u.OrgID, in.Kind, in.ProfileID)

	var id int64
	err := a.db.QueryRow(ctx, `
		INSERT INTO nodes (org_id, parent_id, kind, name, host, description, profile_id, position)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,
		        COALESCE((SELECT MAX(position)+1 FROM nodes WHERE org_id=$1 AND parent_id IS NOT DISTINCT FROM $2),0))
		RETURNING id`,
		u.OrgID, in.ParentID, in.Kind, in.Name, in.Host, in.Description, profileID).Scan(&id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	a.audit(ctx, u, clientIP(r), in.Kind+".create", in.Name+kvHost(in.Host))
	a.pm.kick()
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (a *App) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in node
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}

	ctx := r.Context()
	var kind string
	if err := a.db.QueryRow(ctx, `SELECT kind FROM nodes WHERE id=$1 AND org_id=$2`, id, u.OrgID).Scan(&kind); err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	if kind == "host" && !validHostAddr(in.Host) {
		writeErr(w, http.StatusBadRequest, "host address must be an IP address or a host name")
		return
	}
	if len(in.Name) > 200 || len(in.Description) > 500 {
		writeErr(w, http.StatusBadRequest, "name or description too long")
		return
	}
	profileID := a.resolveProfile(ctx, u.OrgID, kind, in.ProfileID)

	ct, err := a.db.Exec(ctx, `
		UPDATE nodes SET name=$1, host=NULLIF($2,''), description=NULLIF($3,''), profile_id=$4
		WHERE id=$5 AND org_id=$6`,
		in.Name, in.Host, in.Description, profileID, id, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if ct.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	a.audit(ctx, u, clientIP(r), kind+".update", in.Name+kvHost(in.Host))
	a.pm.kick()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	var name, kind string
	if err := a.db.QueryRow(ctx, `SELECT name, kind FROM nodes WHERE id=$1 AND org_id=$2`, id, u.OrgID).
		Scan(&name, &kind); err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	// ON DELETE CASCADE removes descendants and their samples.
	if _, err := a.db.Exec(ctx, `DELETE FROM nodes WHERE id=$1 AND org_id=$2`, id, u.OrgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	a.audit(ctx, u, clientIP(r), kind+".delete", name)
	a.pm.kick()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMoveNode reparents/reorders a node (drag-and-drop), validating that the
// move does not create a cycle and keeps the tree within maxTreeDepth levels.
func (a *App) handleMoveNode(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		ParentID *int64 `json:"parent_id"`
		Position int    `json:"position"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()

	var kind, name string
	if err := a.db.QueryRow(ctx, `SELECT kind, name FROM nodes WHERE id=$1 AND org_id=$2`, id, u.OrgID).Scan(&kind, &name); err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	dest := "top level"
	if in.ParentID != nil {
		if *in.ParentID == id {
			writeErr(w, http.StatusBadRequest, "cannot move into itself")
			return
		}
		var pkind string
		if err := a.db.QueryRow(ctx, `SELECT kind FROM nodes WHERE id=$1 AND org_id=$2`, *in.ParentID, u.OrgID).Scan(&pkind); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid parent")
			return
		}
		dest = "folder " + strconv.FormatInt(*in.ParentID, 10)
		if pkind != "folder" {
			writeErr(w, http.StatusBadRequest, "parent must be a folder")
			return
		}
		// cycle: the new parent must not be a descendant of the node
		var cyc bool
		_ = a.db.QueryRow(ctx, `
			WITH RECURSIVE d AS (
				SELECT id FROM nodes WHERE id=$1
				UNION ALL SELECT n.id FROM nodes n JOIN d ON n.parent_id=d.id
			) SELECT true FROM d WHERE id=$2`, id, *in.ParentID).Scan(&cyc)
		if cyc {
			writeErr(w, http.StatusBadRequest, "cannot move a node into its own descendant")
			return
		}
		// depth: parentDepth + subtree height must stay within the limit
		var height int
		_ = a.db.QueryRow(ctx, `
			WITH RECURSIVE d AS (
				SELECT id, 1 AS lvl FROM nodes WHERE id=$1
				UNION ALL SELECT n.id, d.lvl+1 FROM nodes n JOIN d ON n.parent_id=d.id
			) SELECT COALESCE(MAX(lvl),1) FROM d`, id).Scan(&height)
		if a.nodeDepth(ctx, u.OrgID, *in.ParentID)+height > maxTreeDepth {
			writeErr(w, http.StatusBadRequest, "move would exceed 3 levels")
			return
		}
	}

	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `UPDATE nodes SET parent_id=$1 WHERE id=$2 AND org_id=$3`, in.ParentID, id, u.OrgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	// collect siblings in order, move the node to the requested index, renumber
	rows, err := tx.Query(ctx,
		`SELECT id FROM nodes WHERE org_id=$1 AND parent_id IS NOT DISTINCT FROM $2 ORDER BY position, id`, u.OrgID, in.ParentID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	var ids []int64
	for rows.Next() {
		var sid int64
		if rows.Scan(&sid) == nil {
			ids = append(ids, sid)
		}
	}
	rows.Close()

	ordered := make([]int64, 0, len(ids))
	for _, sid := range ids {
		if sid != id {
			ordered = append(ordered, sid)
		}
	}
	pos := in.Position
	if pos < 0 {
		pos = 0
	}
	if pos > len(ordered) {
		pos = len(ordered)
	}
	ordered = append(ordered[:pos], append([]int64{id}, ordered[pos:]...)...)
	for i, sid := range ordered {
		if _, err := tx.Exec(ctx, `UPDATE nodes SET position=$1 WHERE id=$2`, i, sid); err != nil {
			writeErr(w, http.StatusInternalServerError, "reorder failed")
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "commit failed")
		return
	}
	a.audit(ctx, u, clientIP(r), kind+".move", name+" -> "+dest+", position "+strconv.Itoa(in.Position))
	a.pm.kick()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// nodeDepth returns the depth of a node (root = 1) by walking ancestors.
func (a *App) nodeDepth(ctx context.Context, orgID, id int64) int {
	var d int
	_ = a.db.QueryRow(ctx, `
		WITH RECURSIVE anc AS (
			SELECT id, parent_id, 1 AS d FROM nodes WHERE id = $1 AND org_id = $2
			UNION ALL
			SELECT n.id, n.parent_id, a.d + 1 FROM nodes n JOIN anc a ON n.id = a.parent_id
		) SELECT COALESCE(MAX(d), 0) FROM anc`, id, orgID).Scan(&d)
	return d
}

func (a *App) parentValid(ctx context.Context, orgID int64, parentID *int64) bool {
	if parentID == nil {
		return true
	}
	var kind string
	if err := a.db.QueryRow(ctx, `SELECT kind FROM nodes WHERE id=$1 AND org_id=$2`, *parentID, orgID).Scan(&kind); err != nil {
		return false
	}
	return kind == "folder" // hosts cannot contain children
}

// resolveProfile picks the host's profile: explicit if valid, else org default.
func (a *App) resolveProfile(ctx context.Context, orgID int64, kind string, want *int64) *int64 {
	if kind != "host" {
		return nil
	}
	if want != nil {
		var ok bool
		_ = a.db.QueryRow(ctx, `SELECT true FROM probe_profiles WHERE id=$1 AND org_id=$2`, *want, orgID).Scan(&ok)
		if ok {
			return want
		}
	}
	var id int64
	if err := a.db.QueryRow(ctx,
		`SELECT id FROM probe_profiles WHERE org_id=$1 ORDER BY is_default DESC, id LIMIT 1`, orgID).Scan(&id); err != nil {
		return nil
	}
	return &id
}

func kvHost(h string) string {
	if h == "" {
		return ""
	}
	return " (" + h + ")"
}
