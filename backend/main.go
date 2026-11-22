// Driftband - modern smoke-graph latency monitor.
// Copyright (C) 2026 Łukasz Morawski
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Backend: Postgres-backed multi-tenant API (organizations, users, invites,
// audit log), a host tree with probe profiles, an fping scheduler, a retention
// housekeeper, and the static SPA.
package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// version is set at build time (-ldflags "-X main.version=1.2.3").
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println("driftband", version)
		return
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	listen := envOr("LISTEN", ":8080")
	webDir := envOr("WEB_DIR", "web")
	// A static website can be served next to the application, under /main:
	// LANDING_DIR names its directory. Without it /main does not exist.
	landingDir := os.Getenv("LANDING_DIR")
	if landingDir != "" {
		if st, err := os.Stat(landingDir); err != nil || !st.IsDir() {
			log.Printf("LANDING_DIR %q is not a directory; /main is disabled", landingDir)
			landingDir = ""
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := openDB(ctx, dsn)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	app := newApp(db, newProberMgr(db))
	app.pm.testMode = app.testMode
	app.migrateChannelSecrets(ctx)
	app.migrateTotpSecrets(ctx)
	if app.testMode {
		log.Printf("TEST_INSTANCE: test-instance limits are on (hosts %d/org by default, interval >= %ds, packet <= %d B)", testHostLimit, testMinInterval, testMaxPacket)
	}

	auditSystemDB(ctx, db, "", "", "system.start", "listening on "+listen)
	go app.pm.Run(ctx)
	go newHousekeeper(db).Run(ctx)
	go newRollupWorker(db).Run(ctx)
	go alertEvaluator{app}.Run(ctx)

	srv := &http.Server{
		Addr:              listen,
		Handler:           app.routes(webDir, landingDir),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	log.Printf("driftband %s listening on %s (web=%s)", version, listen, webDir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// apiRoute is one API endpoint. public routes skip the session check; super
// routes are for platform administrators only. Every route must have an entry
// in the security test suite (securityMatrix in security_test.go);
// TestEveryRouteIsCovered enforces it.
type apiRoute struct {
	pattern string
	public  bool
	handler http.HandlerFunc
	super   bool
}

func (a *App) apiRoutes() []apiRoute {
	return []apiRoute{
		{"POST /api/auth/register-org", true, a.handleRegisterOrg, false},
		{"POST /api/auth/login", true, a.handleLogin, false},
		{"POST /api/auth/accept-invite", true, a.handleAcceptInvite, false},
		{"GET /api/auth/invite-info", true, a.handleInviteInfo, false},
		{"POST /api/auth/logout", false, a.handleLogout, false},
		{"GET /api/me", false, a.handleMe, false},
		{"POST /api/account/password", false, a.handleChangePassword, false},
		{"POST /api/account/email", false, a.handleChangeEmail, false},
		{"POST /api/account/name", false, a.handleUpdateName, false},
		{"POST /api/account/2fa/setup", false, a.handleTotpSetup, false},
		{"POST /api/account/2fa/enable", false, a.handleTotpEnable, false},
		{"POST /api/account/2fa/disable", false, a.handleTotpDisable, false},
		{"GET /api/account/webauthn", false, a.handleWebauthnList, false},
		{"POST /api/account/webauthn/register/begin", false, a.handleWebauthnRegisterBegin, false},
		{"POST /api/account/webauthn/register/finish", false, a.handleWebauthnRegisterFinish, false},
		{"POST /api/account/webauthn/{id}/delete", false, a.handleWebauthnDelete, false},
		{"POST /api/account/avatar", false, a.handleAvatarSet, false},
		{"DELETE /api/account/avatar", false, a.handleAvatarRemove, false},
		{"GET /api/users/{id}/avatar", false, a.handleAvatarGet, false},
		{"GET /api/users", false, a.handleListUsers, false},
		{"DELETE /api/users/{id}", false, a.handleRemoveUser, false},
		{"POST /api/invites", false, a.handleCreateInvite, false},
		{"GET /api/invites", false, a.handleListInvites, false},
		{"DELETE /api/invites/{token}", false, a.handleRevokeInvite, false},
		{"GET /api/profiles", false, a.handleListProfiles, false},
		{"POST /api/profiles", false, a.handleCreateProfile, false},
		{"PATCH /api/profiles/{id}", false, a.handleUpdateProfile, false},
		{"DELETE /api/profiles/{id}", false, a.handleDeleteProfile, false},
		{"GET /api/tree", false, a.handleTree, false},
		{"POST /api/nodes", false, a.handleCreateNode, false},
		{"PATCH /api/nodes/{id}", false, a.handleUpdateNode, false},
		{"POST /api/nodes/{id}/move", false, a.handleMoveNode, false},
		{"DELETE /api/nodes/{id}", false, a.handleDeleteNode, false},
		{"POST /api/import/smokeping", false, a.handleImportSmokeping, false},
		{"GET /api/series", false, a.handleSeries, false},
		{"GET /api/status", false, a.handleStatus, false},
		{"GET /api/usage", false, a.handleUsage, false},
		{"GET /api/audit", false, a.handleAuditList, false},
		{"POST /api/settings/retention", false, a.handleSetRetention, false},
		{"PATCH /api/users/{id}/role", false, a.handleChangeRole, false},

		// notifications (reading: any member; changes: owners and admins)
		{"GET /api/notify/channels", false, a.handleListChannels, false},
		{"POST /api/notify/channels", false, a.handleCreateChannel, false},
		{"PATCH /api/notify/channels/{id}", false, a.handleUpdateChannel, false},
		{"DELETE /api/notify/channels/{id}", false, a.handleDeleteChannel, false},
		{"POST /api/notify/channels/{id}/test", false, a.handleTestChannel, false},
		{"GET /api/notify/rules", false, a.handleListRules, false},
		{"POST /api/notify/rules", false, a.handleCreateRule, false},
		{"PATCH /api/notify/rules/{id}", false, a.handleUpdateRule, false},
		{"DELETE /api/notify/rules/{id}", false, a.handleDeleteRule, false},
		{"GET /api/notify/events", false, a.handleNotifyEvents, false},

		// platform administration
		{"GET /api/admin/orgs", false, a.handleAdminOrgs, true},
		{"GET /api/admin/orgs/{id}/users", false, a.handleAdminOrgUsers, true},
		{"POST /api/admin/orgs/{id}/block", false, a.handleAdminBlockOrg, true},
		{"PATCH /api/admin/orgs/{id}/limits", false, a.handleAdminSetLimits, true},
		{"GET /api/admin/orgs/{id}/hosts", false, a.handleAdminOrgHosts, true},
		{"POST /api/admin/orgs/{id}/delete", false, a.handleAdminDeleteOrg, true},
		{"POST /api/admin/users/{id}/block", false, a.handleAdminBlockUser, true},
		{"POST /api/admin/users/{id}/reset-password", false, a.handleAdminResetPassword, true},
		{"DELETE /api/admin/users/{id}", false, a.handleAdminDeleteUser, true},
		{"GET /api/admin/stats", false, a.handleAdminStats, true},
		{"GET /api/admin/audit", false, a.handleAdminAudit, true},
	}
}

func (a *App) routes(webDir, landingDir string) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range a.apiRoutes() {
		h := rt.handler
		if rt.super {
			h = a.superadmin(h)
		}
		if !rt.public {
			h = a.authed(h)
		}
		mux.HandleFunc(rt.pattern, h)
	}

	// --- static website (only when LANDING_DIR is set) ---
	if landingDir != "" {
		mux.Handle("/main/", http.StripPrefix("/main", landingHandler(landingDir)))
		mux.Handle("/main", http.RedirectHandler("/main/", http.StatusMovedPermanently))
	}

	// --- static SPA ---
	mux.HandleFunc("/", spaHandler(webDir))
	return a.withClientIP(securityHeaders(logRequests(mux)))
}

// landingHandler serves the static website. Directories are served only
// through their index.html (no listings); assets may be cached for a day;
// unknown paths get the site's own 404.html with a 404 status.
func landingHandler(dir string) http.Handler {
	root := indexOnlyFS{http.Dir(dir)}
	fs := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if f, err := root.Open(path.Clean("/" + r.URL.Path)); err != nil {
			serveLanding404(w, dir)
			return
		} else {
			f.Close()
		}
		if compressible(r.URL.Path) && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			r.Header.Del("Range") // byte ranges of the uncompressed file would be wrong
			gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
			defer gz.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Add("Vary", "Accept-Encoding")
			w = gzipResponseWriter{ResponseWriter: w, gz: gz}
		}
		fs.ServeHTTP(w, r)
	})
}

func serveLanding404(w http.ResponseWriter, dir string) {
	page, err := os.ReadFile(filepath.Join(dir, "404.html")) // #nosec G304 -- dir is the configured LANDING_DIR, not request input
	if err != nil {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(page)
}

// compressible reports whether a landing file is text worth gzipping
// (images and fonts are already compressed).
func compressible(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case "", ".html", ".css", ".js", ".svg", ".xml", ".txt", ".json", ".webmanifest", ".ico":
		return true
	}
	return false
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g gzipResponseWriter) WriteHeader(code int) {
	g.Header().Del("Content-Length")
	g.ResponseWriter.WriteHeader(code)
}

func (g gzipResponseWriter) Write(b []byte) (int, error) {
	g.Header().Del("Content-Length")
	return g.gz.Write(b)
}

// indexOnlyFS refuses to open directories that have no index.html, so the
// file server never renders a directory listing.
type indexOnlyFS struct{ fs http.FileSystem }

func (f indexOnlyFS) Open(name string) (http.File, error) {
	file, err := f.fs.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := file.Stat(); err == nil && st.IsDir() {
		idx, err := f.fs.Open(strings.TrimSuffix(name, "/") + "/index.html")
		if err != nil {
			file.Close()
			return nil, os.ErrNotExist
		}
		idx.Close()
	}
	return file, nil
}

// spaHandler serves static files and falls back to index.html for client routes.
func spaHandler(dir string) http.HandlerFunc {
	fs := http.FileServer(http.Dir(dir))
	index := filepath.Join(dir, "index.html")
	return func(w http.ResponseWriter, r *http.Request) {
		// Unknown API paths (or wrong methods on known ones) must not fall
		// through to the SPA with a 200.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// The image build references every asset with ?v=<content hash>
		// (scripts/web-version.sh): such URLs change with the content, so they
		// are cached for a year. Everything else (the page itself, unstamped
		// files during development) is cached for a minute.
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=60")
		}
		if r.URL.Path != "/" {
			p := filepath.Join(dir, filepath.Clean(r.URL.Path))
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				fs.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFile(w, r, index)
	}
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			log.Printf("%s %s", r.Method, r.URL.RequestURI())
		}
		h.ServeHTTP(w, r)
	})
}
