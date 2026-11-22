package main

// Security test suite. See SECURITY-TESTING.md for the procedure.
//
// Every API route must have an entry in securityMatrix; the generic tests then
// check, for every route: authentication, role enforcement, tenant isolation
// and the audit trail. Route-specific and general security properties
// (passwords, sessions, 2FA, invites, rate limits, headers, input handling)
// have their own tests below.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// routeSpec describes how to exercise one route and what security rules apply.
type routeSpec struct {
	// minRole: "public" (no session), "member" (any signed-in user),
	// "admin" (owners and admins only) or "superadmin" (platform
	// administrators; the generic tests then act as one, against org o).
	minRole string
	// call returns the path (with query) and JSON body for a successful
	// request by actor a against org o. It may perform setup requests.
	call func(e *env, o *org, a *actor) (path string, body any)
	// audit is the audit_log action a successful call must record ("" for
	// read-only routes).
	audit string
	// idor: the path addresses an object of org o; another tenant must get
	// 404 and the object must survive.
	idor bool
}

func pathf(f string, v ...any) string { return fmt.Sprintf(f, v...) }

var securityMatrix = map[string]routeSpec{
	"POST /api/auth/register-org": {minRole: "public", audit: "org.create",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/auth/register-org", map[string]any{"org_name": "New org", "email": uniqueEmail("reg"), "password": "Register-pass-123"}
		}},
	"POST /api/auth/login": {minRole: "public", audit: "auth.login",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/auth/login", map[string]any{"email": o.Owner.Email, "password": o.Owner.Password}
		}},
	"POST /api/auth/accept-invite": {minRole: "public", audit: "user.join",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/auth/accept-invite", map[string]any{"token": o.InviteToken, "email": uniqueEmail("join"), "password": "Joiner-pass-1234"}
		}},
	"GET /api/auth/invite-info": {minRole: "public",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/auth/invite-info?token=" + o.InviteToken, nil
		}},
	"GET /api/auth/config": {minRole: "public",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/auth/config", nil }},
	"GET /api/health": {minRole: "public",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/health", nil }},
	"POST /api/auth/logout": {minRole: "member", audit: "auth.logout",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/auth/logout", nil }},
	"GET /api/me": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/me", nil }},
	"POST /api/account/password": {minRole: "member", audit: "account.password_change",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/account/password", map[string]any{"current": a.Password, "new": "Changed-pass-123", "confirm": "Changed-pass-123"}
		}},
	"POST /api/account/email": {minRole: "member", audit: "account.email_change",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/account/email", map[string]any{"email": uniqueEmail("newmail"), "password": a.Password}
		}},
	"POST /api/account/name": {minRole: "member", audit: "account.name_change",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/account/name", map[string]any{"first_name": "Ada", "last_name": "Lovelace"}
		}},
	"POST /api/account/2fa/setup": {minRole: "member", audit: "account.2fa_setup",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/account/2fa/setup", map[string]any{"password": a.Password}
		}},
	"POST /api/account/2fa/enable": {minRole: "member", audit: "account.2fa_enable",
		call: func(e *env, o *org, a *actor) (string, any) {
			r := e.must(e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": a.Password}), 200, "2fa setup")
			return "/api/account/2fa/enable", map[string]any{"code": currentTotp(e.t, r.JSON["secret"].(string), 0)}
		}},
	"POST /api/account/2fa/disable": {minRole: "member", audit: "account.2fa_disable",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/account/2fa/disable", map[string]any{"password": a.Password}
		}},
	"GET /api/account/webauthn": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/account/webauthn", nil }},
	"POST /api/account/webauthn/register/begin": {minRole: "member", audit: "account.webauthn_setup",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/account/webauthn/register/begin", map[string]any{"password": a.Password, "kind": "key", "name": "Desk key"}
		}},
	"POST /api/account/webauthn/register/finish": {minRole: "member", audit: "account.webauthn_add",
		call: func(e *env, o *org, a *actor) (string, any) {
			r := e.must(e.req(a, "POST", "/api/account/webauthn/register/begin",
				map[string]any{"password": a.Password, "kind": "key", "name": "Desk key"}), 200, "webauthn begin")
			return "/api/account/webauthn/register/finish", map[string]any{"token": r.JSON["token"], "credential": newSoftKey(e.t, false).register(r)}
		}},
	// The key belongs to the caller when the caller is in org o; otherwise
	// (tenant isolation) it is the owner's key that the outsider addresses.
	"POST /api/account/webauthn/{id}/delete": {minRole: "member", audit: "account.webauthn_remove", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			holder := a
			if a.OrgID != o.Owner.OrgID {
				holder = o.Owner
			}
			_, id := e.enroll(holder, "key", false)
			return pathf("/api/account/webauthn/%d/delete", id), map[string]any{"password": a.Password}
		}},
	"POST /api/account/avatar": {minRole: "member", audit: "account.avatar_set",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/account/avatar", avatarBody("image/png", testPNG(e.t, 64, 64, false))
		}},
	"DELETE /api/account/avatar": {minRole: "member", audit: "account.avatar_remove",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/account/avatar", nil }},
	"GET /api/users/{id}/avatar": {minRole: "member", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			e.must(e.req(o.Owner, "POST", "/api/account/avatar", avatarBody("image/png", testPNG(e.t, 64, 64, false))), 200, "set avatar")
			return pathf("/api/users/%d/avatar", o.Owner.ID), nil
		}},
	"GET /api/users": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/users", nil }},
	"DELETE /api/users/{id}": {minRole: "admin", audit: "user.remove", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) { return pathf("/api/users/%d", o.Member.ID), nil }},
	"POST /api/invites": {minRole: "admin", audit: "invite.create",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/invites", map[string]any{"role": "member"} }},
	"GET /api/invites": {minRole: "admin",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/invites", nil }},
	"DELETE /api/invites/{token}": {minRole: "admin", audit: "invite.revoke", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/invites/" + o.InviteToken, nil }},
	"GET /api/profiles": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/profiles", nil }},
	"POST /api/profiles": {minRole: "member", audit: "profile.create",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/profiles", map[string]any{"name": "p2", "interval_s": 30, "ping_count": 10, "packet_size": 64}
		}},
	"PATCH /api/profiles/{id}": {minRole: "member", audit: "profile.update", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/profiles/%d", o.ProfileID), map[string]any{"name": "renamed", "interval_s": 30, "ping_count": 10, "packet_size": 64}
		}},
	"DELETE /api/profiles/{id}": {minRole: "member", audit: "profile.delete", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) { return pathf("/api/profiles/%d", o.ProfileID), nil }},
	"GET /api/tree": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/tree", nil }},
	"POST /api/nodes": {minRole: "member", audit: "host.create",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/nodes", map[string]any{"kind": "host", "name": "h2", "host": "192.0.2.2", "parent_id": o.FolderID}
		}},
	"PATCH /api/nodes/{id}": {minRole: "member", audit: "host.update", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/nodes/%d", o.HostID), map[string]any{"name": "renamed", "host": "192.0.2.3"}
		}},
	"POST /api/nodes/{id}/move": {minRole: "member", audit: "host.move", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/nodes/%d/move", o.HostID), map[string]any{"parent_id": nil, "position": 0}
		}},
	"DELETE /api/nodes/{id}": {minRole: "member", audit: "host.delete", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) { return pathf("/api/nodes/%d", o.HostID), nil }},
	"POST /api/import/smokeping": {minRole: "admin", audit: "import.smokeping",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/import/smokeping", map[string]any{"config": "*** Targets ***\n+ Grp\nmenu = Grp\n++ h\nhost = 192.0.2.9\n"}
		}},
	"GET /api/series": {minRole: "member", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			now := time.Now().Unix()
			return pathf("/api/series?host=%d&from=%d&to=%d", o.HostID, now-3600, now), nil
		}},
	"GET /api/status": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/status", nil }},
	"GET /api/audit": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/audit", nil }},
	"POST /api/settings/retention": {minRole: "admin", audit: "org.retention_change",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/settings/retention", map[string]any{"years": 2}
		}},

	"PATCH /api/users/{id}/role": {minRole: "admin", audit: "user.role_change", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/users/%d/role", o.Member.ID), map[string]any{"role": "admin"}
		}},

	// notifications
	"GET /api/notify/channels": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/notify/channels", nil }},
	"POST /api/notify/channels": {minRole: "admin", audit: "notify.channel_create",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/notify/channels", map[string]any{"name": "ops", "kind": "telegram",
				"config": map[string]any{"chat_id": "@driftband_ops"}, "secrets": map[string]any{"bot_token": testBotToken}}
		}},
	"PATCH /api/notify/channels/{id}": {minRole: "admin", audit: "notify.channel_update", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/notify/channels/%d", o.ChannelID), map[string]any{"name": "renamed", "config": map[string]any{"chat_id": "-100999"}}
		}},
	"DELETE /api/notify/channels/{id}": {minRole: "admin", audit: "notify.channel_delete", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/notify/channels/%d", o.ChannelID), nil
		}},
	"POST /api/notify/channels/{id}/test": {minRole: "admin", audit: "notify.channel_test", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/notify/channels/%d/test", o.ChannelID), nil
		}},
	"GET /api/notify/rules": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/notify/rules", nil }},
	"POST /api/notify/rules": {minRole: "admin", audit: "notify.rule_create",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/notify/rules", ruleBody("new rule", o.HostID, o.ChannelID)
		}},
	"PATCH /api/notify/rules/{id}": {minRole: "admin", audit: "notify.rule_update", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/notify/rules/%d", o.RuleID), ruleBody("changed rule", o.FolderID, o.ChannelID)
		}},
	"DELETE /api/notify/rules/{id}": {minRole: "admin", audit: "notify.rule_delete", idor: true,
		call: func(e *env, o *org, a *actor) (string, any) { return pathf("/api/notify/rules/%d", o.RuleID), nil }},
	"GET /api/notify/events": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/notify/events", nil }},

	// platform administration
	"GET /api/admin/orgs": {minRole: "superadmin",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/admin/orgs", nil
		}},
	"GET /api/admin/orgs/{id}/users": {minRole: "superadmin",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/orgs/%d/users", o.Owner.OrgID), nil
		}},
	"POST /api/admin/orgs/{id}/block": {minRole: "superadmin", audit: "admin.org_block",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/orgs/%d/block", o.Owner.OrgID), map[string]any{"blocked": true}
		}},
	"POST /api/admin/users/{id}/block": {minRole: "superadmin", audit: "admin.user_block",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/users/%d/block", o.Member.ID), map[string]any{"blocked": true}
		}},
	"POST /api/admin/users/{id}/reset-password": {minRole: "superadmin", audit: "admin.user_password_reset",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/users/%d/reset-password", o.Member.ID), map[string]any{}
		}},
	"DELETE /api/admin/users/{id}": {minRole: "superadmin", audit: "admin.user_delete",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/users/%d", o.Member.ID), nil
		}},
	"PATCH /api/admin/orgs/{id}/limits": {minRole: "superadmin", audit: "admin.org_limits",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/orgs/%d/limits", o.Owner.OrgID), map[string]any{"host_limit": 25}
		}},
	"GET /api/admin/orgs/{id}/hosts": {minRole: "superadmin",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/orgs/%d/hosts", o.Owner.OrgID), nil
		}},
	"POST /api/admin/orgs/{id}/delete": {minRole: "superadmin", audit: "admin.org_delete",
		call: func(e *env, o *org, a *actor) (string, any) {
			return pathf("/api/admin/orgs/%d/delete", o.Owner.OrgID), map[string]any{"password": a.Password, "name": orgName(e.t, o.Owner.OrgID)}
		}},
	"GET /api/usage": {minRole: "member",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/usage", nil }},
	"GET /api/admin/settings": {minRole: "superadmin",
		call: func(e *env, o *org, a *actor) (string, any) { return "/api/admin/settings", nil }},
	// The generic tests keep the instance open (its default): closing it
	// would refuse the organizations other tests create. TestRegistrationCanBeClosed
	// covers the closed state.
	"PATCH /api/admin/settings": {minRole: "superadmin", audit: "admin.settings_change",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/admin/settings", map[string]any{"registration_open": true}
		}},
	"GET /api/admin/stats": {minRole: "superadmin",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/admin/stats", nil
		}},
	"GET /api/admin/audit": {minRole: "superadmin",
		call: func(e *env, o *org, a *actor) (string, any) {
			return "/api/admin/audit?q=a", nil
		}},
}

func method(pattern string) string { m, _, _ := strings.Cut(pattern, " "); return m }

func sortedPatterns() []string {
	var ps []string
	for p := range securityMatrix {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

func dbNow(t *testing.T) time.Time {
	t.Helper()
	var ts time.Time
	_ = testDB.QueryRow(context.Background(), `SELECT now()`).Scan(&ts)
	return ts
}

// ---------------------------------------------------------------------------
// Coverage: the procedure's enforcement point.

// TestEveryRouteIsCovered fails when a route is added without a matrix entry
// (or an entry outlives its route). Runs without a database.
func TestEveryRouteIsCovered(t *testing.T) {
	app := &App{}
	seen := map[string]bool{}
	for _, rt := range app.apiRoutes() {
		seen[rt.pattern] = true
		spec, ok := securityMatrix[rt.pattern]
		if !ok {
			t.Errorf("route %q has no securityMatrix entry: add one (see SECURITY-TESTING.md)", rt.pattern)
			continue
		}
		if rt.public != (spec.minRole == "public") {
			t.Errorf("route %q: public=%v in apiRoutes but minRole=%q in securityMatrix", rt.pattern, rt.public, spec.minRole)
		}
		if rt.super != (spec.minRole == "superadmin") {
			t.Errorf("route %q: super=%v in apiRoutes but minRole=%q in securityMatrix", rt.pattern, rt.super, spec.minRole)
		}
		if strings.HasPrefix(rt.pattern, method(rt.pattern)+" /api/admin/") != rt.super {
			t.Errorf("route %q: /api/admin/ routes, and only they, must be superadmin-only", rt.pattern)
		}
		if method(rt.pattern) == "GET" && spec.audit != "" {
			t.Errorf("route %q: GET must not change state (it declares audit %q)", rt.pattern, spec.audit)
		}
		if method(rt.pattern) != "GET" && spec.audit == "" {
			t.Errorf("route %q changes state but declares no audit action", rt.pattern)
		}
	}
	for p := range securityMatrix {
		if !seen[p] {
			t.Errorf("securityMatrix entry %q has no route", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Generic per-route checks.

func TestUnauthenticatedRequestsRejected(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("unauth")
	expired := &actor{Token: randomToken()}
	_, _ = testDB.Exec(context.Background(),
		`INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, now() - interval '1 minute')`, expired.Token, o.Owner.ID)
	forged := &actor{Token: "forged-" + randomToken()}
	for _, p := range sortedPatterns() {
		spec := securityMatrix[p]
		if spec.minRole == "public" {
			continue
		}
		path, body := spec.call(e, o, o.Owner)
		for name, a := range map[string]*actor{"no session": anon, "forged token": forged, "expired session": expired} {
			if r := e.req(a, method(p), path, body); r.Status != http.StatusUnauthorized {
				t.Errorf("%s with %s: status %d, want 401", p, name, r.Status)
			}
		}
	}
}

func TestRoleEnforcement(t *testing.T) {
	e := newEnv(t)
	for _, p := range sortedPatterns() {
		spec := securityMatrix[p]
		if spec.minRole != "admin" {
			continue
		}
		t.Run(p, func(t *testing.T) {
			o := e.newOrg("role")
			t0 := dbNow(t)
			path, body := spec.call(e, o, o.Member)
			r := e.req(o.Member, method(p), path, body)
			if r.Status != http.StatusForbidden {
				t.Fatalf("member: status %d, want 403 (%s)", r.Status, r.Body)
			}
			if !auditHasPrefix(t, o.Owner.OrgID, o.Member.Email, "denied.", t0) {
				t.Errorf("member: refused attempt not recorded in audit log")
			}
			for _, role := range []string{"admin", "owner"} {
				o := e.newOrg("role") // fresh fixture per role
				a := map[string]*actor{"admin": o.Admin, "owner": o.Owner}[role]
				path, body := spec.call(e, o, a)
				if r := e.req(a, method(p), path, body); r.Status >= 400 {
					t.Errorf("%s: status %d, want success (%s)", role, r.Status, r.Body)
				}
			}
		})
	}
	// Platform routes refuse every tenant role and work for superadmins.
	for _, p := range sortedPatterns() {
		spec := securityMatrix[p]
		if spec.minRole != "superadmin" {
			continue
		}
		t.Run(p, func(t *testing.T) {
			o := e.newOrg("plat")
			for _, a := range []*actor{o.Member, o.Admin, o.Owner} {
				t0 := dbNow(t)
				path, body := spec.call(e, o, a)
				if r := e.req(a, method(p), path, body); r.Status != http.StatusForbidden {
					t.Errorf("%s: status %d, want 403 (%s)", a.Role, r.Status, r.Body)
				}
				if !auditHasPrefix(t, o.Owner.OrgID, a.Email, "denied.", t0) {
					t.Errorf("%s: refused attempt not audited", a.Role)
				}
			}
			o = e.newOrg("plat")
			sa := e.superadmin()
			path, body := spec.call(e, o, sa)
			if r := e.req(sa, method(p), path, body); r.Status >= 400 {
				t.Errorf("superadmin: status %d (%s)", r.Status, r.Body)
			}
		})
	}
	// Member-level routes must work for members (no accidental lock-out).
	for _, p := range sortedPatterns() {
		spec := securityMatrix[p]
		if spec.minRole != "member" {
			continue
		}
		o := e.newOrg("memberok")
		path, body := spec.call(e, o, o.Member)
		if r := e.req(o.Member, method(p), path, body); r.Status >= 400 {
			t.Errorf("%s as member: status %d (%s)", p, r.Status, r.Body)
		}
	}
}

func auditHasPrefix(t *testing.T, orgID int64, email, prefix string, since time.Time) bool {
	var n int
	_ = testDB.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE org_id = $1 AND user_email = $2 AND action LIKE $3 AND created_at >= $4`,
		orgID, email, prefix+"%", since).Scan(&n)
	return n > 0
}

func TestTenantIsolation(t *testing.T) {
	e := newEnv(t)
	for _, p := range sortedPatterns() {
		spec := securityMatrix[p]
		if !spec.idor {
			continue
		}
		t.Run(p, func(t *testing.T) {
			victim := e.newOrg("victim")
			attacker := e.newOrg("attacker")
			path, body := spec.call(e, victim, attacker.Owner)
			r := e.req(attacker.Owner, method(p), path, body)
			if r.Status != http.StatusNotFound {
				t.Fatalf("other tenant: status %d, want 404 (%s)", r.Status, r.Body)
			}
			assertVictimIntact(t, victim)
		})
	}
	// Collections are scoped: another tenant's objects never show up.
	victim, attacker := e.newOrg("victim"), e.newOrg("attacker")
	for _, path := range []string{"/api/tree", "/api/profiles", "/api/users", "/api/invites", "/api/status", "/api/audit",
		"/api/notify/channels", "/api/notify/rules", "/api/notify/events", "/api/usage"} {
		r := e.must(e.req(attacker.Owner, "GET", path, nil), 200, path)
		for _, leak := range []string{victim.Owner.Email, "victim folder", "victim profile", "victim channel", "victim rule", victim.InviteToken, fmt.Sprintf(`"host_id":%d`, victim.HostID)} {
			if strings.Contains(string(r.Body), leak) {
				t.Errorf("%s leaks other tenant data %q", path, leak)
			}
		}
	}
}

func assertVictimIntact(t *testing.T, o *org) {
	t.Helper()
	ctx := context.Background()
	var n int
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE id = $1 AND name LIKE 'victim%' AND parent_id = $2`, o.HostID, o.FolderID).Scan(&n)
	if n != 1 {
		t.Errorf("victim host was modified or deleted")
	}
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM probe_profiles WHERE id = $1 AND name LIKE 'victim%'`, o.ProfileID).Scan(&n)
	if n != 1 {
		t.Errorf("victim profile was modified or deleted")
	}
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, o.Member.ID).Scan(&n)
	if n != 1 {
		t.Errorf("victim member was removed")
	}
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM invites WHERE token = $1`, o.InviteToken).Scan(&n)
	if n != 1 {
		t.Errorf("victim invite was revoked")
	}
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM notify_channels WHERE id = $1 AND name LIKE 'victim%'`, o.ChannelID).Scan(&n)
	if n != 1 {
		t.Errorf("victim channel was modified or deleted")
	}
	_ = testDB.QueryRow(ctx, `SELECT count(*) FROM alert_rules WHERE id = $1 AND name LIKE 'victim%'`, o.RuleID).Scan(&n)
	if n != 1 {
		t.Errorf("victim rule was modified or deleted")
	}
	var role string
	_ = testDB.QueryRow(ctx, `SELECT role FROM users WHERE id = $1`, o.Member.ID).Scan(&role)
	if role != "member" {
		t.Errorf("victim member's role was changed to %s", role)
	}
}

func TestEveryChangeIsAudited(t *testing.T) {
	e := newEnv(t)
	for _, p := range sortedPatterns() {
		spec := securityMatrix[p]
		if spec.audit == "" {
			continue
		}
		t.Run(p, func(t *testing.T) {
			o := e.newOrg("audit")
			a := o.Owner
			if spec.minRole == "superadmin" {
				a = e.superadmin()
			}
			path, body := spec.call(e, o, a)
			t0 := dbNow(t)
			r := e.req(a, method(p), path, body, "X-Forwarded-For: 203.0.113.77")
			if r.Status >= 400 {
				t.Fatalf("status %d (%s)", r.Status, r.Body)
			}
			// Platform actions are filed under the affected organization;
			// deleting one is filed in the system log (no organization),
			// because its own log goes with it.
			var org int64 = o.Owner.OrgID
			orgID := &org
			if p == "POST /api/auth/register-org" {
				_ = testDB.QueryRow(context.Background(), `SELECT org_id FROM users WHERE email = $1`, body.(map[string]any)["email"]).Scan(orgID)
			}
			if p == "POST /api/admin/orgs/{id}/delete" || p == "PATCH /api/admin/settings" {
				orgID = nil // instance-wide: the system log
			}
			var n int
			_ = testDB.QueryRow(context.Background(), `
				SELECT count(*) FROM audit_log WHERE org_id IS NOT DISTINCT FROM $1 AND action = $2 AND created_at >= $3
				  AND ip = '203.0.113.77' AND user_email IS NOT NULL AND user_email <> ''`,
				orgID, spec.audit, t0).Scan(&n)
			if n == 0 {
				t.Errorf("no audit entry %q (with user and client IP) after %s", spec.audit, p)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Passwords and login.

func TestPasswordsStoredAsArgon2id(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("hash")
	var h1, h2 string
	_ = testDB.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE id = $1`, o.Admin.ID).Scan(&h1)
	_ = testDB.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE id = $1`, o.Member.ID).Scan(&h2)
	if !regexp.MustCompile(`^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`).MatchString(h1) {
		t.Fatalf("hash is not argon2id: %q", h1)
	}
	if strings.Contains(h1, o.Admin.Password) {
		t.Fatal("hash contains the plaintext password")
	}
	if h1 == h2 {
		t.Error("identical hashes for different users: salts are not unique")
	}
}

func TestRegistrationValidation(t *testing.T) {
	e := newEnv(t)
	for name, body := range map[string]map[string]any{
		"short password": {"org_name": "x", "email": uniqueEmail("v"), "password": "short"},
		"bad email":      {"org_name": "x", "email": "not-an-email", "password": "Long-enough-1"},
		"no org name":    {"org_name": " ", "email": uniqueEmail("v"), "password": "Long-enough-1"},
	} {
		if r := e.req(anon, "POST", "/api/auth/register-org", body); r.Status != 400 {
			t.Errorf("%s: status %d, want 400", name, r.Status)
		}
	}
	o := e.newOrg("dup")
	if r := e.req(anon, "POST", "/api/auth/register-org",
		map[string]any{"org_name": "x", "email": strings.ToUpper(o.Owner.Email), "password": "Long-enough-1"}); r.Status != 409 {
		t.Errorf("duplicate email (case-insensitive): status %d, want 409", r.Status)
	}
}

func TestLoginDoesNotRevealAccounts(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("enum")
	unknown := e.login(uniqueEmail("nobody"), "Whatever-123", "")
	wrong := e.login(o.Owner.Email, "Wrong-password-1", "")
	if unknown.Status != 401 || wrong.Status != 401 {
		t.Fatalf("statuses %d / %d, want 401", unknown.Status, wrong.Status)
	}
	if string(unknown.Body) != string(wrong.Body) {
		t.Errorf("different errors for unknown email vs wrong password: %s vs %s", unknown.Body, wrong.Body)
	}
	// Timing: an unknown email must still cost a password hash.
	measure := func(email string) time.Duration {
		var best time.Duration
		for i := 0; i < 3; i++ {
			t0 := time.Now()
			e.login(email, "Wrong-password-1", "")
			if d := time.Since(t0); best == 0 || d < best {
				best = d
			}
		}
		return best
	}
	tu, tw := measure(uniqueEmail("nobody")), measure(o.Admin.Email)
	if tu < tw/3 {
		t.Errorf("unknown-email login is much faster (%v vs %v): account existence leaks via timing", tu, tw)
	}
}

func TestLoginRateLimited(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("brute")
	t0 := dbNow(t)
	for i := 0; i < maxFailsPerAccount; i++ {
		if r := e.login(o.Member.Email, fmt.Sprintf("Guess-%d-xx", i), ""); r.Status != 401 {
			t.Fatalf("guess %d: status %d", i, r.Status)
		}
	}
	if r := e.login(o.Member.Email, o.Member.Password, ""); r.Status != http.StatusTooManyRequests {
		t.Fatalf("after %d failures even the right password must be refused: status %d", maxFailsPerAccount, r.Status)
	}
	if !auditHas(t, o.Owner.OrgID, o.Member.Email, "auth.login_failed", t0) {
		t.Error("failed logins not audited")
	}
	if !auditHas(t, o.Owner.OrgID, o.Member.Email, "auth.login_blocked", t0) {
		t.Error("blocked login not audited")
	}
	// Other accounts are unaffected by one account's lock-out.
	e.must(e.login(o.Admin.Email, o.Admin.Password, ""), 200, "other account")

	// Per-IP budget across many accounts.
	e2 := newEnv(t)
	for i := 0; i < maxFailsPerIP; i++ {
		e2.login(uniqueEmail("spray"), "Spray-pass-123", "")
	}
	if r := e2.login(o.Admin.Email, o.Admin.Password, ""); r.Status != http.StatusTooManyRequests {
		t.Errorf("password spraying from one IP not limited: status %d", r.Status)
	}
}

// ---------------------------------------------------------------------------
// Sessions.

func TestSessionCookieFlags(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("cookie")
	c := e.must(e.login(o.Owner.Email, o.Owner.Password, ""), 200, "login").cookie(sessionCookie)
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("session cookie must be HttpOnly, SameSite=Lax, Path=/: %+v", c)
	}
	if c.Secure {
		t.Error("plain-HTTP login set a Secure cookie (would break local use)")
	}
	c = e.login(o.Owner.Email, o.Owner.Password, "", "X-Forwarded-Proto: https").cookie(sessionCookie)
	if c == nil || !c.Secure {
		t.Error("HTTPS (via trusted proxy) login must set a Secure cookie")
	}
	// The cookie that ends a session (sign-out, or a request with a dead
	// session) carries the same attributes, so browsers match and drop it.
	for name, r := range map[string]*resp{
		"logout":       e.req(o.Admin, "POST", "/api/auth/logout", nil, "X-Forwarded-Proto: https"),
		"dead session": e.req(&actor{Token: "no-such-session"}, "GET", "/api/me", nil, "X-Forwarded-Proto: https"),
	} {
		c := r.cookie(sessionCookie)
		if c == nil || c.Value != "" || c.MaxAge >= 0 || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || !c.Secure || c.Path != "/" {
			t.Errorf("%s: clearing cookie must be empty, expired, HttpOnly, SameSite=Lax, Secure over HTTPS: %+v", name, c)
		}
	}
	e.app.trusted = parseTrustedProxies("198.51.100.0/24")
	c = e.login(o.Owner.Email, o.Owner.Password, "", "X-Forwarded-Proto: https").cookie(sessionCookie)
	if c == nil || c.Secure {
		t.Error("X-Forwarded-Proto from an untrusted client must be ignored")
	}
}

func TestSessionTokens(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("token")
	t1 := e.must(e.login(o.Owner.Email, o.Owner.Password, ""), 200, "login 1").cookie(sessionCookie).Value
	t2 := e.must(e.login(o.Owner.Email, o.Owner.Password, ""), 200, "login 2").cookie(sessionCookie).Value
	if t1 == t2 {
		t.Fatal("each login must issue a new session token")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43,}$`).MatchString(t1) {
		t.Errorf("session token too short or odd alphabet: %q", t1)
	}
	var exp time.Time
	_ = testDB.QueryRow(context.Background(), `SELECT expires_at FROM sessions WHERE token = $1`, t1).Scan(&exp)
	if d := time.Until(exp); d <= 0 || d > 31*24*time.Hour {
		t.Errorf("session lifetime %v outside (0, 31d]", d)
	}
	s1 := &actor{Token: t1}
	e.must(e.req(s1, "POST", "/api/auth/logout", nil), 200, "logout")
	if r := e.req(s1, "GET", "/api/me", nil); r.Status != 401 {
		t.Errorf("token still valid after logout: %d", r.Status)
	}
	if r := e.req(&actor{Token: t2}, "GET", "/api/me", nil); r.Status != 200 {
		t.Errorf("logout of one session must not end the others: %d", r.Status)
	}
}

// ---------------------------------------------------------------------------
// Account changes.

func TestPasswordChange(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("pwchange")
	a := o.Member
	other := &actor{Token: e.must(e.login(a.Email, a.Password, ""), 200, "2nd session").cookie(sessionCookie).Value}

	if r := e.req(a, "POST", "/api/account/password", map[string]any{"current": a.Password, "new": "Brand-new-pass1", "confirm": "Brand-new-pass2"}); r.Status != 400 {
		t.Errorf("mismatched confirmation: status %d, want 400", r.Status)
	}
	if r := e.req(a, "POST", "/api/account/password", map[string]any{"current": a.Password, "new": "short", "confirm": "short"}); r.Status != 400 {
		t.Errorf("weak password: status %d, want 400", r.Status)
	}
	if r := e.req(a, "POST", "/api/account/password", map[string]any{"current": a.Password, "new": "Brand-new-pass1"}); r.Status != 400 {
		t.Errorf("missing confirmation: status %d, want 400", r.Status)
	}
	t0 := dbNow(t)
	if r := e.req(a, "POST", "/api/account/password", map[string]any{"current": "Wrong-current-1", "new": "Brand-new-pass1", "confirm": "Brand-new-pass1"}); r.Status != 403 {
		t.Errorf("wrong current password: status %d, want 403", r.Status)
	}
	if !auditHas(t, a.OrgID, a.Email, "denied.account.password_change", t0) {
		t.Error("wrong current password not audited")
	}
	e.must(e.req(a, "POST", "/api/account/password", map[string]any{"current": a.Password, "new": "Brand-new-pass1", "confirm": "Brand-new-pass1"}), 200, "change")
	if r := e.req(other, "GET", "/api/me", nil); r.Status != 401 {
		t.Error("other sessions must be signed out after a password change")
	}
	if r := e.req(a, "GET", "/api/me", nil); r.Status != 200 {
		t.Error("the session that changed the password must stay signed in")
	}
	if r := e.login(a.Email, a.Password, ""); r.Status != 401 {
		t.Error("old password still works")
	}
	e.must(e.login(a.Email, "Brand-new-pass1", ""), 200, "new password")
}

func TestPasswordConfirmationRateLimited(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("pwguess")
	for i := 0; i < maxFailsPerAccount; i++ {
		e.req(o.Member, "POST", "/api/account/email", map[string]any{"email": uniqueEmail("x"), "password": fmt.Sprintf("Guess-%d-xx", i)})
	}
	if r := e.req(o.Member, "POST", "/api/account/2fa/setup", map[string]any{"password": o.Member.Password}); r.Status != http.StatusTooManyRequests {
		t.Errorf("password guessing through a signed-in session not limited: status %d", r.Status)
	}
}

func TestEmailChange(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("email")
	if r := e.req(o.Member, "POST", "/api/account/email", map[string]any{"email": uniqueEmail("n"), "password": "Wrong-pass-123"}); r.Status != 403 {
		t.Errorf("wrong password: status %d, want 403", r.Status)
	}
	if r := e.req(o.Member, "POST", "/api/account/email", map[string]any{"email": o.Owner.Email, "password": o.Member.Password}); r.Status != 409 {
		t.Errorf("taking another user's email: status %d, want 409", r.Status)
	}
	if r := e.req(o.Member, "POST", "/api/account/email", map[string]any{"email": "bogus", "password": o.Member.Password}); r.Status != 400 {
		t.Errorf("invalid email: status %d, want 400", r.Status)
	}
}

// ---------------------------------------------------------------------------
// Two-factor authentication.

func TestTwoFactor(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("tfa")
	a := o.Member
	if r := e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": "Wrong-pass-123"}); r.Status != 403 {
		t.Fatalf("setup with wrong password: %d", r.Status)
	}
	secret := e.must(e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": a.Password}), 200, "setup").JSON["secret"].(string)
	if r := e.req(a, "POST", "/api/account/2fa/enable", map[string]any{"code": "000000"}); r.Status != 403 && currentTotp(t, secret, 0) != "000000" {
		t.Errorf("enable with wrong code: %d", r.Status)
	}
	e.must(e.req(a, "POST", "/api/account/2fa/enable", map[string]any{"code": currentTotp(t, secret, 0)}), 200, "enable")
	if r := e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": a.Password}); r.Status != 409 {
		t.Errorf("re-setup while enabled must be refused (would swap the secret): %d", r.Status)
	}

	r := e.login(a.Email, a.Password, "")
	if r.Status != 401 || r.JSON["totp_required"] != true || r.cookie(sessionCookie) != nil {
		t.Fatalf("password alone must not sign in with 2FA on: %d %s", r.Status, r.Body)
	}
	t0 := dbNow(t)
	if r := e.login(a.Email, a.Password, "123456"); r.Status != 401 && currentTotp(t, secret, 0) != "123456" {
		t.Errorf("wrong code: %d", r.Status)
	}
	if !auditHas(t, a.OrgID, a.Email, "auth.login_failed", t0) {
		t.Error("wrong 2FA code not audited")
	}
	if r := e.login(a.Email, "Wrong-pass-123", currentTotp(t, secret, 1)); r.Status != 401 {
		t.Errorf("right code with wrong password: %d", r.Status)
	}
	code := currentTotp(t, secret, 1)
	e.must(e.login(a.Email, a.Password, code), 200, "login with code")
	if r := e.login(a.Email, a.Password, code); r.Status != 401 {
		t.Error("a TOTP code must not be accepted twice (replay)")
	}
	if r := e.req(a, "POST", "/api/account/2fa/disable", map[string]any{"password": "Wrong-pass-123"}); r.Status != 403 {
		t.Errorf("disable with wrong password: %d", r.Status)
	}
	e.must(e.req(a, "POST", "/api/account/2fa/disable", map[string]any{"password": a.Password}), 200, "disable")
	e.must(e.login(a.Email, a.Password, ""), 200, "login after disable")
}

// ---------------------------------------------------------------------------
// Invites and team management.

func TestInvites(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("inv")
	r := e.req(o.Member, "GET", "/api/invites", nil)
	if r.Status != 403 || strings.Contains(string(r.Body), o.InviteToken) {
		t.Errorf("members must not see pending invite tokens: %d %s", r.Status, r.Body)
	}
	if len(o.InviteToken) < 43 {
		t.Errorf("invite token too short: %q", o.InviteToken)
	}
	e.must(e.req(anon, "GET", "/api/auth/invite-info?token="+o.InviteToken, nil), 200, "invite info")
	if r := e.req(anon, "GET", "/api/auth/invite-info?token=nope", nil); r.Status != 410 {
		t.Errorf("unknown token info: %d", r.Status)
	}

	// Role escalation through the invite role is impossible.
	r = e.must(e.req(o.Admin, "POST", "/api/invites", map[string]any{"role": "owner"}), 200, "owner invite")
	if r.JSON["role"] != "member" {
		t.Errorf("invite role 'owner' must be downgraded, got %v", r.JSON["role"])
	}

	// Single use.
	join := map[string]any{"token": o.InviteToken, "email": uniqueEmail("j1"), "password": "Joiner-pass-1234"}
	e.must(e.req(anon, "POST", "/api/auth/accept-invite", join), 200, "accept")
	join["email"] = uniqueEmail("j2")
	if r := e.req(anon, "POST", "/api/auth/accept-invite", join); r.Status != 410 {
		t.Errorf("invite reused: %d", r.Status)
	}

	// Expired.
	r = e.must(e.req(o.Owner, "POST", "/api/invites", map[string]any{"role": "member"}), 200, "invite")
	tok := r.JSON["token"].(string)
	_, _ = testDB.Exec(context.Background(), `UPDATE invites SET expires_at = now() - interval '1 second' WHERE token = $1`, tok)
	if r := e.req(anon, "POST", "/api/auth/accept-invite", map[string]any{"token": tok, "email": uniqueEmail("j3"), "password": "Joiner-pass-1234"}); r.Status != 410 {
		t.Errorf("expired invite accepted: %d", r.Status)
	}

	// Revoked.
	r = e.must(e.req(o.Owner, "POST", "/api/invites", map[string]any{"role": "admin"}), 200, "invite")
	tok = r.JSON["token"].(string)
	e.must(e.req(o.Admin, "DELETE", "/api/invites/"+tok, nil), 200, "revoke")
	if r := e.req(anon, "POST", "/api/auth/accept-invite", map[string]any{"token": tok, "email": uniqueEmail("j4"), "password": "Joiner-pass-1234"}); r.Status != 410 {
		t.Errorf("revoked invite accepted: %d", r.Status)
	}
}

func TestUserRemovalRules(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("rm")
	admin2 := e.invite(o.Owner, "admin", "rm-admin2")
	if r := e.req(o.Admin, "DELETE", pathf("/api/users/%d", admin2.ID), nil); r.Status != 403 {
		t.Errorf("admin removing admin: %d", r.Status)
	}
	if r := e.req(o.Admin, "DELETE", pathf("/api/users/%d", o.Owner.ID), nil); r.Status != 403 {
		t.Errorf("admin removing owner: %d", r.Status)
	}
	if r := e.req(o.Owner, "DELETE", pathf("/api/users/%d", o.Owner.ID), nil); r.Status != 400 {
		t.Errorf("owner removing self: %d", r.Status)
	}
	e.must(e.req(o.Owner, "DELETE", pathf("/api/users/%d", o.Member.ID), nil), 200, "remove member")
	if r := e.req(o.Member, "GET", "/api/me", nil); r.Status != 401 {
		t.Error("removed user's session still works")
	}
}

// ---------------------------------------------------------------------------
// Input handling.

func TestMassAssignmentRejected(t *testing.T) {
	e := newEnv(t)
	o, other := e.newOrg("mass"), e.newOrg("mass-other")
	cases := []struct {
		method, path string
		body         map[string]any
	}{
		{"POST", "/api/nodes", map[string]any{"kind": "folder", "name": "x", "org_id": other.Owner.OrgID}},
		{"PATCH", pathf("/api/profiles/%d", o.ProfileID), map[string]any{"name": "x", "interval_s": 30, "ping_count": 1, "packet_size": 56, "org_id": other.Owner.OrgID}},
		{"POST", "/api/account/name", map[string]any{"first_name": "x", "role": "owner"}},
	}
	for _, c := range cases {
		if r := e.req(o.Member, c.method, c.path, c.body); r.Status != 400 {
			t.Errorf("%s %s with extra privileged field: %d, want 400", c.method, c.path, r.Status)
		}
	}
	if r := e.req(anon, "POST", "/api/auth/accept-invite", map[string]any{"token": o.InviteToken, "email": uniqueEmail("m"), "password": "Joiner-pass-1234", "role": "owner"}); r.Status != 400 {
		t.Errorf("accept-invite with role: %d, want 400", r.Status)
	}
}

func TestCrossTenantReferences(t *testing.T) {
	e := newEnv(t)
	o, other := e.newOrg("ref"), e.newOrg("ref-other")
	if r := e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "x", "host": "192.0.2.5", "parent_id": other.FolderID}); r.Status != 400 {
		t.Errorf("creating a node under another tenant's folder: %d", r.Status)
	}
	if r := e.req(o.Owner, "POST", pathf("/api/nodes/%d/move", o.HostID), map[string]any{"parent_id": other.FolderID, "position": 0}); r.Status != 400 {
		t.Errorf("moving a node into another tenant's folder: %d", r.Status)
	}
	r := e.must(e.req(o.Owner, "POST", "/api/nodes", map[string]any{"kind": "host", "name": "x", "host": "192.0.2.6", "profile_id": other.ProfileID}), 200, "host")
	var porg int64
	_ = testDB.QueryRow(context.Background(), `SELECT p.org_id FROM nodes n JOIN probe_profiles p ON p.id = n.profile_id WHERE n.id = $1`, int64(r.JSON["id"].(float64))).Scan(&porg)
	if porg != o.Owner.OrgID {
		t.Error("a host was linked to another tenant's probe profile")
	}
}

func TestInjectionAndMalformedInput(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("inj")
	evil := `x'); DROP TABLE users; -- <img src=x onerror=alert(1)>`
	r := e.must(e.req(o.Member, "POST", "/api/nodes", map[string]any{"kind": "folder", "name": evil}), 200, "evil name")
	id := int64(r.JSON["id"].(float64))
	var name string
	_ = testDB.QueryRow(context.Background(), `SELECT name FROM nodes WHERE id = $1`, id).Scan(&name)
	if name != evil {
		t.Errorf("name not stored verbatim: %q", name)
	}
	// A NUL character in any JSON string is refused as bad input (PostgreSQL
	// would reject it in a text column, which must not become a 500).
	before := countHosts(t, o.Owner.OrgID)
	for _, c := range []struct {
		method, path string
		body         string
	}{
		{"POST", "/api/nodes", `{"kind":"host","name":"a\u0000b","host":"192.0.2.9"}`},
		{"POST", "/api/account/name", `{"first_name":"a\u0000","last_name":"b"}`},
		{"POST", "/api/profiles", `{"name":"p\u0000","interval_s":60,"ping_count":5,"packet_size":56,"is_default":false}`},
		{"PATCH", pathf("/api/profiles/%d", o.ProfileID), `{"name":"p\u0000","interval_s":60,"ping_count":5,"packet_size":56,"is_default":false}`},
		{"POST", "/api/notify/channels", `{"name":"c\u0000","kind":"slack","config":{},"secrets":{"webhook_url":"https://hooks.slack.com/services/T0/B0/x"}}`},
	} {
		if r := e.req(o.Owner, c.method, c.path, c.body); r.Status != 400 {
			t.Errorf("%s %s with a NUL character: status %d, want 400 (%s)", c.method, c.path, r.Status, r.Body)
		}
	}
	if countHosts(t, o.Owner.OrgID) != before {
		t.Error("a host with a NUL character was stored")
	}
	tree := e.must(e.req(o.Member, "GET", "/api/tree", nil), 200, "tree")
	if strings.Contains(string(tree.Body), "<img") {
		t.Error("API returned unescaped HTML in JSON")
	}
	if ct := tree.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("API content type %q", ct)
	}
	for _, q := range []string{"1%20OR%201=1", "1;DROP%20TABLE%20users", "-1", "abc"} {
		if r := e.req(o.Member, "GET", "/api/series?host="+q, nil); r.Status != 400 && r.Status != 404 {
			t.Errorf("series host=%s: %d", q, r.Status)
		}
	}
	if r := e.req(o.Member, "DELETE", "/api/nodes/1%20OR%201=1", nil); r.Status != 400 {
		t.Errorf("non-numeric path id: %d", r.Status)
	}
	if r := e.req(o.Member, "POST", "/api/nodes", `{"kind":"folder",`); r.Status != 400 {
		t.Errorf("malformed JSON: %d", r.Status)
	}
	big := `{"config":"` + strings.Repeat("A", 2<<20) + `"}`
	if r := e.req(o.Owner, "POST", "/api/import/smokeping", big); r.Status != 400 {
		t.Errorf("2 MB body: %d, want 400", r.Status)
	}
	// Huge point counts are clamped server-side.
	now := time.Now().Unix()
	r = e.must(e.req(o.Member, "GET", pathf("/api/series?host=%d&from=0&to=%d&points=99999999", o.HostID, now), nil), 200, "series")
	if pts, _ := r.JSON["points"].([]any); len(pts) > maxPoints {
		t.Errorf("points not clamped: %d", len(pts))
	}
	var users int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users)
	if users == 0 {
		t.Fatal("users table emptied")
	}
}

// ---------------------------------------------------------------------------
// HTTP layer.

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("hdr")
	for _, path := range []string{"/api/me", "/", "/app.js", "/some/client/route", "/main/", "/main/assets/img/x.svg"} {
		r := e.req(o.Member, "GET", path, nil)
		for h, want := range map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Embedder-Policy": "require-corp",
			"Cross-Origin-Resource-Policy": "same-origin",
		} {
			if got := r.Header.Get(h); got != want {
				t.Errorf("%s: %s = %q, want %q", path, h, got, want)
			}
		}
		csp := r.Header.Get("Content-Security-Policy")
		for _, d := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'"} {
			if !strings.Contains(csp, d) {
				t.Errorf("%s: CSP lacks %q", path, d)
			}
		}
		if strings.Contains(csp, "unsafe-eval") || regexp.MustCompile(`script-src[^;]*unsafe-inline`).MatchString(csp) {
			t.Errorf("%s: CSP allows inline/eval scripts", path)
		}
		// The application sets styles through the CSSOM only; the static
		// website under /main is the one place inline style attributes exist.
		inlineStyles := regexp.MustCompile(`style-src[^;]*unsafe-inline`).MatchString(csp)
		if site := strings.HasPrefix(path, "/main"); inlineStyles != site {
			t.Errorf("%s: style-src allows inline styles = %v, want %v", path, inlineStyles, site)
		}
	}
	if cc := e.req(o.Member, "GET", "/api/me", nil).Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("API responses must not be cached: %q", cc)
	}
}

// Stamped asset URLs (?v=<content hash>, set by the image build) are
// immutable for a year; the page and unstamped files are cached briefly;
// the API is never cached.
func TestStaticCaching(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("cache")
	for path, want := range map[string]string{
		"/app.js?v=0123456789": "public, max-age=31536000, immutable",
		"/app.js":              "public, max-age=60",
		"/":                    "public, max-age=60",
		"/some/client/route":   "public, max-age=60",
		"/api/me":              "no-store",
	} {
		if got := e.must(e.req(o.Member, "GET", path, nil), 200, path).Header.Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control %q, want %q", path, got, want)
		}
	}
	// a stamp must not be a way to cache a missing file or an API path
	if r := e.req(o.Member, "GET", "/api/nope?v=1", nil); r.Status != 404 || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("stamped API path: %d %q", r.Status, r.Header.Get("Cache-Control"))
	}
}

func TestStaticFilesConfined(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/../../../../etc/passwd", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2f..%2fetc%2fpasswd", "/.%2e/.%2e/etc/passwd"} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", p)
		buf := make([]byte, 1<<16)
		n, _ := conn.Read(buf)
		conn.Close()
		if strings.Contains(string(buf[:n]), "root:") {
			t.Errorf("path traversal served a system file for %s", p)
		}
	}
}

func TestClientIPNotSpoofable(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("ip")
	lastIP := func() string {
		var ip string
		_ = testDB.QueryRow(context.Background(),
			`SELECT ip FROM audit_log WHERE user_email = $1 ORDER BY id DESC LIMIT 1`, o.Member.Email).Scan(&ip)
		return ip
	}
	// Test client is on loopback = a trusted proxy by default: header honoured.
	e.req(o.Member, "POST", "/api/account/name", map[string]any{"first_name": "a"}, "X-Forwarded-For: 203.0.113.5")
	if ip := lastIP(); ip != "203.0.113.5" {
		t.Errorf("trusted proxy X-Forwarded-For ignored: %q", ip)
	}
	// Each proxy appends the address it saw, so the chain is read from the
	// right: whatever the client itself put further left is ignored.
	e.app.trusted = parseTrustedProxies("127.0.0.0/8,::1/128,198.51.100.0/24")
	peer, _, _ := net.SplitHostPort(e.srv.Listener.Addr().String())
	for i, c := range []struct {
		hdrs []string
		want string
	}{
		{[]string{"X-Forwarded-For: 192.0.2.66, 203.0.113.7"}, "203.0.113.7"},
		{[]string{"X-Forwarded-For: 192.0.2.66", "X-Forwarded-For: 203.0.113.8"}, "203.0.113.8"},
		{[]string{"X-Forwarded-For: 192.0.2.66, 203.0.113.9, 198.51.100.20"}, "203.0.113.9"},
		{[]string{"X-Forwarded-For: 198.51.100.21, 198.51.100.20"}, "198.51.100.21"},
		{[]string{"X-Forwarded-For: 192.0.2.66, not-an-address"}, peer},
	} {
		e.req(o.Member, "POST", "/api/account/name", map[string]any{"first_name": fmt.Sprintf("c%d", i)}, c.hdrs...)
		if ip := lastIP(); ip != c.want {
			t.Errorf("%q: client IP %q, want %q", c.hdrs, ip, c.want)
		}
	}
	// Rotating the client-supplied part of the chain does not escape the
	// per-IP login limit.
	for i := 0; i < maxFailsPerIP; i++ {
		e.login(fmt.Sprintf("nobody%d@example.test", i), "Wrong-pass-123", "",
			fmt.Sprintf("X-Forwarded-For: 192.0.2.%d, 203.0.113.99", i))
	}
	if r := e.login(o.Owner.Email, o.Owner.Password, "", "X-Forwarded-For: 192.0.2.250, 203.0.113.99"); r.Status != http.StatusTooManyRequests {
		t.Errorf("rotating spoofed X-Forwarded-For entries bypassed the per-IP limit: %d", r.Status)
	}
	// From an untrusted peer the header is ignored.
	e.app.trusted = parseTrustedProxies("198.51.100.0/24")
	e.req(o.Member, "POST", "/api/account/name", map[string]any{"first_name": "b"}, "X-Forwarded-For: 203.0.113.6")
	if ip := lastIP(); ip == "203.0.113.6" {
		t.Error("client spoofed its audit-log IP with X-Forwarded-For")
	}
	// The spoofed IP must not dodge the login rate limit either.
	for i := 0; i < maxFailsPerAccount; i++ {
		e.login(o.Admin.Email, "Wrong-pass-123", "", fmt.Sprintf("X-Forwarded-For: 203.0.113.%d", i+10))
	}
	if r := e.login(o.Admin.Email, o.Admin.Password, ""); r.Status != http.StatusTooManyRequests {
		t.Errorf("rotating X-Forwarded-For bypassed the account lock: %d", r.Status)
	}
}

func TestAuditLogIsReadOnlyAndScoped(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("auditro")
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if r := e.req(o.Owner, m, "/api/audit", map[string]any{}); r.Status != http.StatusMethodNotAllowed && r.Status != http.StatusNotFound {
			t.Errorf("%s /api/audit: %d, want 404/405", m, r.Status)
		}
	}
	r := e.must(e.req(o.Member, "GET", "/api/audit?limit=200", nil), 200, "audit")
	if len(items(r)) == 0 {
		t.Error("audit log empty for an org with activity")
	}
	for _, it := range items(r) {
		em, _ := it.(map[string]any)["email"].(string)
		if em != "" && em != o.Owner.Email && em != o.Admin.Email && em != o.Member.Email {
			t.Errorf("audit log shows a foreign user: %s", em)
		}
	}
}

// ---------------------------------------------------------------------------
// Platform administration.

func TestSuperadminFlagNotSelfAssignable(t *testing.T) {
	e := newEnv(t)
	o := e.newOrg("noflag")
	if r := e.must(e.req(o.Owner, "GET", "/api/me", nil), 200, "me"); r.JSON["is_superadmin"] != false {
		t.Errorf("owner reported as superadmin: %v", r.JSON["is_superadmin"])
	}
	for _, c := range []struct {
		path string
		body map[string]any
	}{
		{"/api/account/name", map[string]any{"first_name": "x", "is_superadmin": true}},
		{"/api/auth/register-org", map[string]any{"org_name": "x", "email": uniqueEmail("f"), "password": "Long-enough-12", "is_superadmin": true}},
	} {
		if r := e.req(o.Owner, "POST", c.path, c.body); r.Status != 400 {
			t.Errorf("%s accepted is_superadmin: %d", c.path, r.Status)
		}
	}
}

func TestAdminBlockUser(t *testing.T) {
	e := newEnv(t)
	sa, o := e.superadmin(), e.newOrg("blk")
	e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/block", o.Member.ID), map[string]any{"blocked": true}), 200, "block")
	if r := e.req(o.Member, "GET", "/api/me", nil); r.Status != 401 {
		t.Error("blocked user's session still works")
	}
	t0 := dbNow(t)
	if r := e.login(o.Member.Email, o.Member.Password, ""); r.Status != 403 || r.cookie(sessionCookie) != nil {
		t.Errorf("blocked user signed in: %d", r.Status)
	}
	if !auditHas(t, o.Owner.OrgID, o.Member.Email, "auth.login_disabled", t0) {
		t.Error("blocked sign-in attempt not audited")
	}
	if r := e.login(o.Member.Email, "Wrong-pass-123", ""); r.Status != 401 {
		t.Error("blocked status must not be revealed to someone without the password")
	}
	e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/block", o.Member.ID), map[string]any{"blocked": false}), 200, "unblock")
	e.must(e.login(o.Member.Email, o.Member.Password, ""), 200, "login after unblock")

	if r := e.req(sa, "POST", pathf("/api/admin/users/%d/block", sa.ID), map[string]any{"blocked": true}); r.Status != 400 {
		t.Errorf("superadmin blocked itself: %d", r.Status)
	}
	sa2 := e.superadmin()
	if r := e.req(sa, "POST", pathf("/api/admin/users/%d/block", sa2.ID), map[string]any{"blocked": true}); r.Status != 403 {
		t.Errorf("superadmin blocked another superadmin: %d", r.Status)
	}
	if r := e.req(sa, "POST", "/api/admin/users/999999999/block", map[string]any{"blocked": true}); r.Status != 404 {
		t.Errorf("unknown user: %d", r.Status)
	}
}

func TestAdminBlockOrg(t *testing.T) {
	e := newEnv(t)
	sa, o, other := e.superadmin(), e.newOrg("blkorg"), e.newOrg("blkorg-other")
	e.must(e.req(sa, "POST", pathf("/api/admin/orgs/%d/block", o.Owner.OrgID), map[string]any{"blocked": true}), 200, "block org")
	for _, a := range []*actor{o.Owner, o.Admin, o.Member} {
		if r := e.req(a, "GET", "/api/me", nil); r.Status != 401 {
			t.Errorf("%s of a blocked org still has a session", a.Role)
		}
		if r := e.login(a.Email, a.Password, ""); r.Status != 403 {
			t.Errorf("%s of a blocked org signed in: %d", a.Role, r.Status)
		}
	}
	if r := e.req(other.Owner, "GET", "/api/me", nil); r.Status != 200 {
		t.Error("blocking one org affected another")
	}
	hosts, err := e.app.pm.loadHosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, probed := hosts[o.HostID]; probed {
		t.Error("hosts of a blocked organization are still probed")
	}
	if _, probed := hosts[other.HostID]; !probed {
		t.Error("hosts of an active organization are not probed")
	}
	if r := e.req(sa, "POST", pathf("/api/admin/orgs/%d/block", sa.OrgID), map[string]any{"blocked": true}); r.Status != 400 {
		t.Errorf("superadmin blocked its own organization: %d", r.Status)
	}
	e.must(e.req(sa, "POST", pathf("/api/admin/orgs/%d/block", o.Owner.OrgID), map[string]any{"blocked": false}), 200, "unblock org")
	e.must(e.login(o.Member.Email, o.Member.Password, ""), 200, "login after org unblock")
}

func TestAdminResetPassword(t *testing.T) {
	e := newEnv(t)
	sa, o := e.superadmin(), e.newOrg("reset")
	a := o.Member
	secret := e.must(e.req(a, "POST", "/api/account/2fa/setup", map[string]any{"password": a.Password}), 200, "setup").JSON["secret"].(string)
	e.must(e.req(a, "POST", "/api/account/2fa/enable", map[string]any{"code": currentTotp(t, secret, 0)}), 200, "enable")

	r := e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/reset-password", a.ID), map[string]any{"reset_2fa": true}), 200, "reset")
	pw, _ := r.JSON["password"].(string)
	if len(pw) < 16 {
		t.Fatalf("temporary password too short: %q", pw)
	}
	if e.req(a, "GET", "/api/me", nil).Status != 401 {
		t.Error("sessions survive a password reset")
	}
	if e.login(a.Email, a.Password, "").Status != 401 {
		t.Error("old password still works")
	}
	e.must(e.login(a.Email, pw, ""), 200, "login with temporary password (2FA reset)")
	var leaked int
	_ = testDB.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE detail LIKE '%' || $1 || '%'`, pw).Scan(&leaked)
	if leaked > 0 {
		t.Error("temporary password written to the audit log")
	}
	r2 := e.must(e.req(sa, "POST", pathf("/api/admin/users/%d/reset-password", o.Admin.ID), map[string]any{}), 200, "reset 2")
	if r2.JSON["password"] == pw {
		t.Error("temporary passwords repeat")
	}
}

func TestAdminDeleteUser(t *testing.T) {
	e := newEnv(t)
	sa, o := e.superadmin(), e.newOrg("del")
	if r := e.req(sa, "DELETE", pathf("/api/admin/users/%d", o.Owner.ID), nil); r.Status != 403 {
		t.Errorf("deleting an org owner: %d, want 403", r.Status)
	}
	if r := e.req(sa, "DELETE", pathf("/api/admin/users/%d", sa.ID), nil); r.Status != 400 {
		t.Errorf("superadmin deleting itself: %d", r.Status)
	}
	e.must(e.req(sa, "DELETE", pathf("/api/admin/users/%d", o.Admin.ID), nil), 200, "delete admin")
	if e.login(o.Admin.Email, o.Admin.Password, "").Status != 401 {
		t.Error("deleted user can still sign in")
	}
	r := e.must(e.req(o.Owner, "GET", "/api/audit", nil), 200, "org audit")
	if !strings.Contains(string(r.Body), "admin.user_delete") {
		t.Error("the tenant cannot see what the platform administrator did")
	}
}

func TestAdminViewsAndGlobalAudit(t *testing.T) {
	e := newEnv(t)
	sa, o1, o2 := e.superadmin(), e.newOrg("view1"), e.newOrg("view2")
	orgs := e.must(e.req(sa, "GET", "/api/admin/orgs", nil), 200, "orgs")
	for _, o := range []*org{o1, o2} {
		if !strings.Contains(string(orgs.Body), fmt.Sprintf(`"id":%d,`, o.Owner.OrgID)) {
			t.Errorf("org %d missing from admin list", o.Owner.OrgID)
		}
	}
	users := e.must(e.req(sa, "GET", pathf("/api/admin/orgs/%d/users", o1.Owner.OrgID), nil), 200, "users")
	if len(users.List) != 3 || strings.Contains(string(users.Body), "password") || strings.Contains(string(users.Body), "totp_secret") {
		t.Errorf("org users: want 3 users and no secrets: %s", users.Body)
	}

	e.login(uniqueEmail("ghost"), "Whatever-123", "") // system-level event (unknown email)
	all := e.must(e.req(sa, "GET", "/api/admin/audit?limit=200", nil), 200, "global audit")
	body := string(all.Body)
	for _, want := range []string{o1.Owner.Email, o2.Owner.Email, `"org_id":null`} {
		if !strings.Contains(body, want) {
			t.Errorf("global audit lacks %s", want)
		}
	}
	only := e.must(e.req(sa, "GET", pathf("/api/admin/audit?org=%d", o1.Owner.OrgID), nil), 200, "filtered")
	if strings.Contains(string(only.Body), o2.Owner.Email) {
		t.Error("org filter leaks other orgs")
	}
	sys := e.must(e.req(sa, "GET", "/api/admin/audit?org=system&limit=200", nil), 200, "system")
	if len(items(sys)) == 0 {
		t.Error("system filter returned nothing")
	}
	for _, it := range items(sys) {
		if it.(map[string]any)["org_id"] != nil {
			t.Error("system filter returned tenant entries")
		}
	}
	if r := e.req(sa, "GET", "/api/admin/audit?q=%25'%20OR%201=1--&org=abc", nil); r.Status != 400 {
		t.Errorf("bad org filter: %d", r.Status)
	}
	if r := e.must(e.req(sa, "GET", "/api/admin/audit?q=%25%27%20OR%201%3D1--", nil), 200, "injection probe"); len(items(r)) != 0 || r.JSON["total"].(float64) != 0 {
		t.Errorf("search text was not treated literally: %d hits", len(items(r)))
	}
	// Tenants never see system events.
	org := e.must(e.req(o1.Owner, "GET", "/api/audit", nil), 200, "org audit")
	if strings.Contains(string(org.Body), "system.") || strings.Contains(string(org.Body), "unknown email") {
		t.Error("tenant audit log shows system events")
	}
}

func TestAdminStats(t *testing.T) {
	e := newEnv(t)
	sa := e.superadmin()
	e.newOrg("stats")
	r := e.must(e.req(sa, "GET", "/api/admin/stats", nil), 200, "stats")
	if n, _ := r.JSON["db_bytes"].(float64); n <= 0 {
		t.Error("db_bytes missing")
	}
	fc, _ := r.JSON["forecast"].(map[string]any)
	pts, _ := fc["points"].([]any)
	if len(pts) < 10 {
		t.Fatalf("forecast has %d points", len(pts))
	}
	prev := 0.0
	for _, p := range pts {
		b := p.(map[string]any)["bytes"].(float64)
		if b < prev {
			t.Fatal("forecast decreases over time")
		}
		prev = b
	}
	if fc["steady_state"].(float64) < fc["in_30_days"].(float64)-1 && fc["cycles_per_day"].(float64) > 0 {
		t.Error("steady state below the 30-day projection")
	}
}

// ---------------------------------------------------------------------------
// Static website under /main/ (LANDING_DIR).

func TestLandingSite(t *testing.T) {
	e := newEnv(t)
	r := e.must(e.req(anon, "GET", "/main/", nil), 200, "landing")
	if !strings.Contains(string(r.Body), "canonical") {
		t.Error("landing index not served")
	}
	if r.Header.Get("Content-Security-Policy") == "" || r.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("landing lacks security headers")
	}
	if r := e.req(anon, "GET", "/main", nil); r.Status != 200 && r.Status != http.StatusMovedPermanently {
		t.Errorf("/main: %d", r.Status)
	}
	e.must(e.req(anon, "GET", "/main/about/", nil), 200, "about")
	if r := e.req(anon, "GET", "/main/", nil, "Accept-Encoding: gzip"); r.Header.Get("Content-Encoding") != "gzip" || r.Status != 200 {
		t.Errorf("landing HTML not gzipped: %d %q", r.Status, r.Header.Get("Content-Encoding"))
	}
	if r := e.must(e.req(anon, "GET", "/main/assets/img/x.svg", nil), 200, "asset"); !strings.Contains(r.Header.Get("Cache-Control"), "max-age") {
		t.Error("assets not cacheable")
	}
	// Unknown paths get the site's own 404 page with a 404 status.
	if r := e.req(anon, "GET", "/main/no/such/page", nil); r.Status != 404 || !strings.Contains(string(r.Body), "landing 404") {
		t.Errorf("unknown landing path: %d %s", r.Status, r.Body)
	}
	// No directory listings, no writes, no escaping the directory.
	if r := e.req(anon, "GET", "/main/assets/img/", nil); r.Status != 404 || strings.Contains(string(r.Body), "x.svg") || !strings.Contains(string(r.Body), "landing 404") {
		t.Errorf("directory listing exposed: %d %s", r.Status, r.Body)
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if r := e.req(anon, m, "/main/", "x"); r.Status != http.StatusMethodNotAllowed {
			t.Errorf("%s /main/: %d", m, r.Status)
		}
	}
	for _, p := range []string{"/main/../../../../etc/passwd", "/main/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/main/..%2f..%2f..%2fetc/passwd"} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", p)
		buf := make([]byte, 1<<16)
		n, _ := conn.Read(buf)
		conn.Close()
		if strings.Contains(string(buf[:n]), "root:") {
			t.Errorf("path traversal via %s", p)
		}
	}
	// Without LANDING_DIR (the default) the site is not mounted at all.
	plain := httptest.NewServer(e.app.routes(e.web, ""))
	defer plain.Close()
	if res, err := http.Get(plain.URL + "/main/"); err == nil {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if strings.Contains(string(body), "canonical") {
			t.Error("website served without LANDING_DIR")
		}
	}
	// The SPA must not swallow the landing path, and the landing must not
	// expose the SPA or the API.
	if r := e.req(anon, "GET", "/main/api/me", nil); r.Status == 200 {
		t.Error("API reachable under /main/")
	}
}
