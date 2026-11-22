package main

// Instance limits and input rules shared by hosts, probe profiles and the
// SmokePing import.
//
// TEST_INSTANCE=yes turns on the public test-instance limits (10 hosts per
// organization unless a platform admin sets another number, probe interval
// of at least 60 s, packets of at most 56 bytes). Any other value, or none,
// leaves them off.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

const (
	// Largest ICMP payload that fits a 1500-byte Ethernet MTU without
	// fragmentation: 1500 - 20 (IPv4 header) - 8 (ICMP header).
	maxPacketSize = 1472
	minPacketSize = 12
	maxPingCount  = 100
	minIntervalS  = 5
	maxIntervalS  = 86400

	testHostLimit   = 10
	testMinInterval = 60
	testMaxPacket   = 56
)

func parseBoolEnv(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "yes", "y", "true", "on", "enable", "enabled":
		return true
	}
	return false
}

// strict reports whether the test-instance limits apply to an organization:
// only on a test instance, and not for organizations a platform admin has
// exempted.
func (a *App) strict(ctx context.Context, orgID int64) bool {
	if !a.testMode {
		return false
	}
	var exempt bool
	_ = a.db.QueryRow(ctx, `SELECT exempt_limits FROM organizations WHERE id = $1`, orgID).Scan(&exempt)
	return !exempt
}

func minIntervalFor(strict bool) int {
	if strict {
		return testMinInterval
	}
	return minIntervalS
}

func maxPacketFor(strict bool) int {
	if strict {
		return testMaxPacket
	}
	return maxPacketSize
}

// hostQuota returns the organization's host limit (0 = unlimited) and how
// many hosts it has. An explicit organizations.host_limit wins; otherwise
// the test instance default applies (unless the org is exempt).
func (a *App) hostQuota(ctx context.Context, orgID int64) (limit, count int) {
	var explicit *int
	var exempt bool
	_ = a.db.QueryRow(ctx, `
		SELECT o.host_limit, o.exempt_limits, (SELECT count(*) FROM nodes n WHERE n.org_id = o.id AND n.kind = 'host')
		FROM organizations o WHERE o.id = $1`, orgID).Scan(&explicit, &exempt, &count)
	return a.effectiveHostLimit(explicit, exempt), count
}

func (a *App) effectiveHostLimit(explicit *int, exempt bool) int {
	if explicit != nil {
		return *explicit
	}
	if a.testMode && !exempt {
		return testHostLimit
	}
	return 0
}

// checkHostQuota writes a 403 when adding n hosts would exceed the limit.
func (a *App) checkHostQuota(w http.ResponseWriter, r *http.Request, n int) bool {
	u := userFrom(r)
	limit, count := a.hostQuota(r.Context(), u.OrgID)
	if limit > 0 && count+n > limit {
		msg := fmt.Sprintf("host limit reached: your organization can have %d hosts and has %d", limit, count)
		if n > 1 {
			msg = fmt.Sprintf("this adds %d hosts, but your organization can have %d and already has %d", n, limit, count)
		}
		a.deny(w, r, "host.limit", msg)
		return false
	}
	return true
}

// ----- host addresses -----

var hostnameLabelRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

// validHostAddr accepts an IPv4/IPv6 address or a DNS name. It never accepts
// anything starting with "-": the address is passed to fping as an argument
// and must not be read as an option.
func validHostAddr(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, "-") {
		return false
	}
	if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if !hostnameLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// ----- probe profiles -----

func validateProfile(p profile, strict bool) error {
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 100 {
		return errors.New("name is required (max 100 characters)")
	}
	if p.IntervalS < minIntervalFor(strict) || p.IntervalS > maxIntervalS {
		if strict {
			return fmt.Errorf("interval must be %d-%d seconds on this test instance", minIntervalFor(strict), maxIntervalS)
		}
		return fmt.Errorf("interval must be %d-%d seconds", minIntervalFor(strict), maxIntervalS)
	}
	if p.PingCount < 1 || p.PingCount > maxPingCount {
		return fmt.Errorf("pings per cycle must be 1-%d", maxPingCount)
	}
	// fping sends one ping every 200 ms and waits for the last reply; with
	// at most one ping per second of interval a cycle always finishes in time.
	if p.PingCount > p.IntervalS {
		return fmt.Errorf("pings per cycle (%d) cannot exceed the interval in seconds (%d)", p.PingCount, p.IntervalS)
	}
	if p.PacketSize < minPacketSize || p.PacketSize > maxPacketFor(strict) {
		if strict {
			return fmt.Errorf("packet size must be %d-%d bytes on this test instance", minPacketSize, maxPacketFor(strict))
		}
		return fmt.Errorf("packet size must be %d-%d bytes (1500 MTU minus 20 B IPv4 and 8 B ICMP headers)", minPacketSize, maxPacketFor(strict))
	}
	return nil
}

// instanceInfo is what /api/me reports so the UI can show the limits.
func (a *App) instanceInfo(ctx context.Context, orgID int64) map[string]any {
	limit, count := a.hostQuota(ctx, orgID)
	strict := a.strict(ctx, orgID)
	return map[string]any{
		"test_instance": a.testMode,
		"exempt":        a.testMode && !strict,
		"host_limit":    limit,
		"hosts":         count,
		"min_interval":  minIntervalFor(strict),
		"max_packet":    maxPacketFor(strict),
		"max_pings":     maxPingCount,
	}
}
