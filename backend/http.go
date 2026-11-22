package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// App holds shared dependencies for HTTP handlers and background workers.
type App struct {
	db      *pgxpool.Pool
	pm      *proberMgr
	limiter *rateLimiter
	trusted []*net.IPNet // proxies whose X-Forwarded-* headers are believed

	// notifications
	sealer              *sealer
	appURL              string        // public URL linked from notifications (APP_URL)
	telegramAPI         string        // Telegram Bot API base URL
	allowPrivateTargets bool          // tests only: allow webhooks on private addresses
	retryDelay          time.Duration // base delay between delivery retries

	testMode bool // TEST_INSTANCE: public test-instance limits (see limits.go)
}

func newApp(db *pgxpool.Pool, pm *proberMgr) *App {
	s, err := newSealer(context.Background(), db)
	if err != nil {
		log.Fatalf("secrets: %v", err)
	}
	return &App{db: db, pm: pm, limiter: newRateLimiter(), trusted: parseTrustedProxies(os.Getenv("TRUSTED_PROXIES")),
		sealer: s, appURL: strings.TrimRight(os.Getenv("APP_URL"), "/"), telegramAPI: "https://api.telegram.org",
		retryDelay: 5 * time.Second, testMode: parseBoolEnv(os.Getenv("TEST_INSTANCE"))}
}

// parseTrustedProxies reads a comma-separated list of CIDRs or addresses.
// Default: loopback and private ranges, i.e. a reverse proxy / tunnel on the
// same host or LAN. A client connecting directly from the internet can then
// not spoof its IP. Every trusted proxy must append the address it received
// the request from to X-Forwarded-For (nginx $proxy_add_x_forwarded_for,
// HAProxy "option forwardfor", CDNs such as Cloudflare); behind a CDN, list
// its ranges as well.
func parseTrustedProxies(s string) []*net.IPNet {
	if strings.TrimSpace(s) == "" {
		s = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
	}
	var out []*net.IPNet
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			bits := 8 * len(ip)
			if ip4 := ip.To4(); ip4 != nil {
				ip, bits = ip4, 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		} else if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		} else {
			log.Printf("TRUSTED_PROXIES: ignoring %q (not an address or CIDR)", c)
		}
	}
	return out
}

func (a *App) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return a.trustedIP(net.ParseIP(host))
}

func (a *App) trustedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range a.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isHTTPS reports whether the client reached us over TLS (directly or via a
// trusted proxy), which decides the session cookie's Secure flag.
func (a *App) isHTTPS(r *http.Request) bool {
	return r.TLS != nil || (a.fromTrustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

// Current user resolved from the session cookie.
type currentUser struct {
	ID         int64
	OrgID      int64
	Email      string
	Role       string
	Superadmin bool
}

type ctxKey int

const userKey ctxKey = 1

const sessionCookie = "dband_session"

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONGz is writeJSON with gzip when the client accepts it; used for the
// larger chart payloads (JSON floats compress ~4x).
func writeJSONGz(w http.ResponseWriter, r *http.Request, v any) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		writeJSON(w, http.StatusOK, v)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Add("Vary", "Accept-Encoding")
	gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	_ = json.NewEncoder(gz).Encode(v)
	_ = gz.Close()
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, dst any) error { return readJSONLimit(r, dst, 1<<20) }

// readJSONLimit decodes a JSON body of at most limit bytes, rejecting
// unknown fields. A NUL character (the JSON escape \u0000) is refused up
// front: it is never meaningful in a name or address, and PostgreSQL
// rejects it in text columns, which would turn into a server error.
func readJSONLimit(r *http.Request, dst any, limit int64) error {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, limit))
	if err != nil {
		return err
	}
	if bytes.Contains(body, []byte(`\u0000`)) {
		return errors.New("NUL characters are not allowed")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// pageSizeDefault and pageSizeMax bound the paged lists (audit logs,
// notification history): the UI offers 10, 20, 50, 100 and 200 rows.
const (
	pageSizeDefault = 10
	pageSizeMax     = 200
)

// pageParams reads limit (1-200, default 10) and offset (>= 0) of a paged
// list from the query string; anything else falls back to the bounds.
func pageParams(r *http.Request) (limit, offset int) {
	q := r.URL.Query()
	limit = int(min(max(parseUnix(q.Get("limit"), pageSizeDefault), 1), pageSizeMax))
	offset = int(min(max(parseUnix(q.Get("offset"), 0), 0), 1<<31-1))
	return limit, offset
}

// clientIPKey carries the resolved client IP through the request context.
const clientIPKey ctxKey = 2

// clientIP is the address recorded in the audit log and used for rate limits.
// X-Forwarded-For is honoured only from trusted proxies (see withClientIP).
func clientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// withClientIP resolves the client address once per request. X-Forwarded-For
// is read only on connections from a trusted proxy, and from the right: each
// proxy appends the address it received the request from, so the rightmost
// entry that is not a trusted proxy is the client. Entries further left were
// sent by the client itself and are ignored.
func (a *App) withClientIP(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if a.fromTrustedProxy(r) {
			if v := a.forwardedClient(r.Header.Values("X-Forwarded-For")); v != "" {
				ip = v
			}
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey, ip)))
	})
}

// forwardedClient walks the X-Forwarded-For chain (all header lines, in
// order) from the right and returns the first address that is not a trusted
// proxy, or the leftmost one when every hop is trusted. It stops at an entry
// that is not an address; "" means the chain gave nothing usable.
func (a *App) forwardedClient(lines []string) string {
	var hops []string
	for _, l := range lines {
		hops = append(hops, strings.Split(l, ",")...)
	}
	client := ""
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			break
		}
		client = ip.String()
		if !a.trustedIP(ip) {
			break
		}
	}
	return client
}

// Content Security Policy. The application never uses inline scripts or
// inline styles (styles are set through the CSSOM), so both are refused.
// The website under /main is static HTML with inline style attributes, so
// it keeps 'unsafe-inline' for styles only.
const (
	cspApp = "default-src 'self'; script-src 'self'; style-src 'self'; " +
		"img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; " +
		"form-action 'self'; frame-ancestors 'none'"
	cspSite = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; " +
		"form-action 'self'; frame-ancestors 'none'"
)

// securityHeaders sets defensive headers on every response.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		if r.URL.Path == "/main" || strings.HasPrefix(r.URL.Path, "/main/") {
			hd.Set("Content-Security-Policy", cspSite)
		} else {
			hd.Set("Content-Security-Policy", cspApp)
		}
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// Cross-origin isolation: no other origin may open, embed or read
		// this origin's documents and resources.
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Cross-Origin-Embedder-Policy", "require-corp")
		hd.Set("Cross-Origin-Resource-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

func userFrom(r *http.Request) *currentUser {
	u, _ := r.Context().Value(userKey).(*currentUser)
	return u
}

// authed wraps a handler so only requests with a valid session reach it.
func (a *App) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		var u currentUser
		// Blocked users and users of blocked organizations have no valid
		// session (blocking also deletes their sessions; this is the backstop).
		err = a.db.QueryRow(r.Context(), `
			SELECT u.id, u.org_id, u.email, u.role, u.is_superadmin
			FROM sessions s
			JOIN users u ON u.id = s.user_id
			JOIN organizations o ON o.id = u.org_id
			WHERE s.token = $1 AND s.expires_at > now() AND NOT u.disabled AND NOT o.disabled`, c.Value).
			Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.Superadmin)
		if err != nil {
			clearSessionCookie(w, a.isHTTPS(r))
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		ctx := context.WithValue(r.Context(), userKey, &u)
		h(w, r.WithContext(ctx))
	}
}

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie expires the session cookie with the same attributes it
// was set with, so browsers match and remove it.
func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// superadmin wraps an authed handler so only platform administrators reach it.
func (a *App) superadmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r); u == nil || !u.Superadmin {
			a.deny(w, r, "admin", "platform administrators only")
			return
		}
		h(w, r)
	}
}

// deny answers 403 and records the refused attempt in the audit log.
func (a *App) deny(w http.ResponseWriter, r *http.Request, action, msg string) {
	a.audit(r.Context(), userFrom(r), clientIP(r), "denied."+action, msg)
	writeErr(w, http.StatusForbidden, msg)
}

func pathID(r *http.Request, name string) (int64, error) {
	return strconv.ParseInt(r.PathValue(name), 10, 64)
}
