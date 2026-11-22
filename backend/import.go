package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// A parsed SmokePing target-tree node.
type spNode struct {
	id       string
	props    map[string]string
	children []*spNode
}

var spHeader = regexp.MustCompile(`^(\++)\s*(.*)$`)

// parseSmokeping extracts the tree from the *** Targets *** section of a
// SmokePing config. Header lines are "+ id" / "++ id" (depth = number of +),
// followed by "key = value" property lines.
func parseSmokeping(text string) []*spNode {
	var roots []*spNode
	stack := map[int]*spNode{}
	inTargets := false
	var cur *spNode

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") && strings.HasSuffix(line, "*") {
			sec := strings.ToLower(strings.TrimSpace(strings.Trim(line, "* ")))
			inTargets = sec == "targets"
			cur = nil
			continue
		}
		if !inTargets {
			continue
		}
		if strings.HasPrefix(line, "+") {
			m := spHeader.FindStringSubmatch(line)
			depth := len(m[1])
			n := &spNode{id: strings.TrimSpace(m[2]), props: map[string]string{}}
			if p := stack[depth-1]; p != nil {
				p.children = append(p.children, n)
			} else {
				roots = append(roots, n)
			}
			stack[depth] = n
			for d := range stack {
				if d > depth {
					delete(stack, d)
				}
			}
			cur = n
			continue
		}
		if cur != nil {
			if eq := strings.Index(line, "="); eq > 0 {
				key := strings.ToLower(strings.TrimSpace(line[:eq]))
				if key != "" && !strings.ContainsAny(key, " \t") {
					cur.props[key] = strings.TrimSpace(line[eq+1:])
				}
			}
		}
	}
	return roots
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Import limits. A large SmokePing installation has a few thousand lines
// (3-6 per host); these caps leave plenty of room while bounding the work.
const (
	maxImportBytes = 2 << 20
	maxImportLines = 20000
	maxImportHosts = 1000
)

var binarySignatures = []struct{ sig, what string }{
	{"%PDF", "a PDF document"}, {"PK\x03\x04", "a ZIP archive or Office document"},
	{"\xd0\xcf\x11\xe0", "an Office document"}, {"{\\rtf", "an RTF document"},
	{"\x7fELF", "a program"}, {"MZ", "a Windows program"},
	{"\x1f\x8b", "a gzip archive"}, {"BZh", "a bzip2 archive"}, {"7z\xbc\xaf", "a 7-Zip archive"},
	{"\x89PNG", "an image"}, {"GIF8", "an image"}, {"\xff\xd8\xff", "an image"},
}

var targetsHeaderRe = regexp.MustCompile(`(?mi)^\s*\*{3}\s*targets\s*\*{3}\s*$`)

// checkImportText accepts only a plain-text SmokePing configuration: no
// binary files, no scripts, bounded size, and a Targets section.
func checkImportText(s string) error {
	if len(s) > maxImportBytes {
		return fmt.Errorf("the file is larger than %d MB", maxImportBytes>>20)
	}
	for _, b := range binarySignatures {
		if strings.HasPrefix(s, b.sig) {
			return fmt.Errorf("this looks like %s, not a SmokePing config; upload the plain-text config file", b.what)
		}
	}
	// U+FFFD appears when a binary file was decoded as text (browsers and
	// JSON encoders substitute it for undecodable bytes).
	if !utf8.ValidString(s) || strings.ContainsRune(s, utf8.RuneError) {
		return errors.New("the file is not UTF-8 text; upload the plain-text config file")
	}
	for _, r := range s {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return errors.New("the file contains binary data; upload the plain-text config file")
		}
	}
	first := strings.TrimSpace(strings.SplitN(strings.TrimLeft(s, " \t\r\n"), "\n", 2)[0])
	if strings.HasPrefix(first, "#!") {
		return errors.New("scripts are not accepted; upload the SmokePing config itself")
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "<?php") || strings.Contains(low, "<script") {
		return errors.New("the file contains script code; upload the SmokePing config itself")
	}
	if n := strings.Count(s, "\n") + 1; n > maxImportLines {
		return fmt.Errorf("the file has %d lines; the limit is %d", n, maxImportLines)
	}
	if !targetsHeaderRe.MatchString(s) {
		return errors.New("no *** Targets *** section found - is this a SmokePing config?")
	}
	return nil
}

// cleanText removes control characters and bounds a display string.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

func (a *App) handleImportSmokeping(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Role == "member" {
		a.deny(w, r, "import.smokeping", "only owners and admins can import")
		return
	}
	var in struct {
		Config string `json:"config"`
	}
	if err := readJSONLimit(r, &in, maxImportBytes+(1<<20)); err != nil || strings.TrimSpace(in.Config) == "" {
		writeErr(w, http.StatusBadRequest, "empty or oversized config")
		return
	}
	cfg := strings.TrimPrefix(in.Config, "\ufeff")
	if err := checkImportText(cfg); err != nil {
		a.audit(r.Context(), u, clientIP(r), "import.rejected", err.Error())
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	roots := parseSmokeping(cfg)
	if len(roots) == 0 {
		writeErr(w, http.StatusBadRequest, "the *** Targets *** section contains no targets")
		return
	}

	// Plan first: count hosts and validate every address before writing.
	var hostCount, dynamic int
	var invalid []string
	var walk func(n *spNode)
	walk = func(n *spNode) {
		host := ""
		if fs := strings.Fields(n.props["host"]); len(fs) > 0 {
			host = fs[0]
		}
		if host != "" && len(n.children) == 0 {
			switch {
			case strings.EqualFold(host, "DYNAMIC"):
				dynamic++
			case !validHostAddr(host):
				if len(invalid) < 5 {
					invalid = append(invalid, cleanText(n.id, 60)+" (host = "+cleanText(host, 60)+")")
				}
			default:
				hostCount++
			}
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	for _, n := range roots {
		walk(n)
	}
	if len(invalid) > 0 {
		msg := "invalid host addresses (must be an IP address or host name): " + strings.Join(invalid, ", ")
		a.audit(r.Context(), u, clientIP(r), "import.rejected", msg)
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if hostCount > maxImportHosts {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("the config has %d hosts; one import can add at most %d", hostCount, maxImportHosts))
		return
	}
	if !a.checkHostQuota(w, r, hostCount) {
		return
	}
	var warnings []string
	if dynamic > 0 {
		warnings = append(warnings, fmt.Sprintf("%d DYNAMIC hosts were skipped", dynamic))
	}
	if regexp.MustCompile(`(?m)^\s*@include`).MatchString(cfg) {
		warnings = append(warnings, "@include lines are not followed; paste included Targets files separately")
	}

	ctx := r.Context()
	var defProf *int64
	var pid int64
	if err := a.db.QueryRow(ctx,
		`SELECT id FROM probe_profiles WHERE org_id=$1 ORDER BY is_default DESC, id LIMIT 1`, u.OrgID).Scan(&pid); err == nil {
		defProf = &pid
	}

	tx, err := a.db.Begin(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	var folders, hosts int
	var ins func(n *spNode, parentID *int64, parentDepth int) error
	ins = func(n *spNode, parentID *int64, parentDepth int) error {
		name := cleanText(firstNonEmpty(n.props["menu"], n.props["title"], n.id), 200)
		if name == "" {
			return nil
		}
		desc := ""
		if t := cleanText(n.props["title"], 500); t != "" && t != name {
			desc = t
		}
		host := ""
		if fs := strings.Fields(n.props["host"]); len(fs) > 0 {
			host = fs[0]
		}
		if host != "" && len(n.children) == 0 {
			if strings.EqualFold(host, "DYNAMIC") {
				return nil
			}
			var id int64
			if err := insertNode(ctx, tx, u.OrgID, parentID, "host", name, host, desc, defProf, &id); err != nil {
				return err
			}
			hosts++
			return nil
		}
		// folder: only nest deeper while its children can still fit within 3 levels
		if parentDepth+1 <= 2 {
			var id int64
			if err := insertNode(ctx, tx, u.OrgID, parentID, "folder", name, "", desc, nil, &id); err != nil {
				return err
			}
			folders++
			for _, c := range n.children {
				if err := ins(c, &id, parentDepth+1); err != nil {
					return err
				}
			}
		} else {
			// too deep to nest: flatten children into the current parent
			for _, c := range n.children {
				if err := ins(c, parentID, parentDepth); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, n := range roots {
		if err := ins(n, nil, 0); err != nil {
			writeErr(w, http.StatusInternalServerError, "insert failed")
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "commit failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "import.smokeping", strconv.Itoa(folders)+" folders, "+strconv.Itoa(hosts)+" hosts")
	a.pm.kick()
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"folders": folders, "hosts": hosts, "warnings": warnings})
}

func insertNode(ctx context.Context, tx pgx.Tx, org int64, parent *int64, kind, name, host, desc string, profile *int64, out *int64) error {
	return tx.QueryRow(ctx, `
		INSERT INTO nodes (org_id, parent_id, kind, name, host, description, profile_id, position)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,
		        COALESCE((SELECT MAX(position)+1 FROM nodes WHERE org_id=$1 AND parent_id IS NOT DISTINCT FROM $2),0))
		RETURNING id`,
		org, parent, kind, name, host, desc, profile).Scan(out)
}
