package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// proberMgr keeps one probing goroutine per host in sync with the DB. It
// reconciles on a timer and whenever kick() is called (after host/profile edits).
type proberMgr struct {
	db       *pgxpool.Pool
	testMode bool // enforce test-instance limits on stored profiles too
	kickCh   chan struct{}
	mu       sync.Mutex
	running  map[int64]*proberHandle
	probeFn  func(ctx context.Context, s hostSpec) // nil: probe (tests replace it)
}

type proberHandle struct {
	cancel context.CancelFunc
	sig    string // host|interval|count|size; a change forces a restart
}

type hostSpec struct {
	id         int64
	host       string
	intervalS  int
	pingCount  int
	packetSize int
}

func (h hostSpec) sig() string {
	return fmt.Sprintf("%s|%d|%d|%d", h.host, h.intervalS, h.pingCount, h.packetSize)
}

func newProberMgr(db *pgxpool.Pool) *proberMgr {
	return &proberMgr{db: db, kickCh: make(chan struct{}, 1), running: map[int64]*proberHandle{}}
}

func (m *proberMgr) kick() {
	if m == nil {
		return
	}
	select {
	case m.kickCh <- struct{}{}:
	default:
	}
}

func (m *proberMgr) Run(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	m.sync(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kickCh:
			m.sync(ctx)
		case <-t.C:
			m.sync(ctx)
		}
	}
}

func (m *proberMgr) loadHosts(ctx context.Context) (map[int64]hostSpec, error) {
	rows, err := m.db.Query(ctx, `
		SELECT n.id, n.host,
		       COALESCE(p.interval_s,  dp.interval_s,  60),
		       COALESCE(p.ping_count,  dp.ping_count,  20),
		       COALESCE(p.packet_size, dp.packet_size, 56),
		       o.exempt_limits
		FROM nodes n
		LEFT JOIN probe_profiles p ON p.id = n.profile_id
		LEFT JOIN LATERAL (
		    SELECT interval_s, ping_count, packet_size FROM probe_profiles d
		    WHERE d.org_id = n.org_id ORDER BY is_default DESC, id LIMIT 1
		) dp ON true
		JOIN organizations o ON o.id = n.org_id
		WHERE n.kind = 'host' AND n.host IS NOT NULL AND n.host <> ''
		  AND NOT o.disabled -- blocked organizations are not probed`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[int64]hostSpec{}
	for rows.Next() {
		var s hostSpec
		var exempt bool
		if err := rows.Scan(&s.id, &s.host, &s.intervalS, &s.pingCount, &s.packetSize, &exempt); err != nil {
			continue
		}
		// Never hand fping something that could be read as an option.
		if !validHostAddr(s.host) {
			log.Printf("prober: skipping host %d: invalid address %q", s.id, s.host)
			continue
		}
		// Profiles saved before a limit existed must not bypass it.
		s.packetSize = min(s.packetSize, maxPacketSize)
		s.pingCount = min(s.pingCount, s.intervalS)
		if m.testMode && !exempt {
			s.intervalS = max(s.intervalS, testMinInterval)
			s.packetSize = min(s.packetSize, testMaxPacket)
		}
		out[s.id] = s
	}
	return out, rows.Err()
}

func (m *proberMgr) sync(ctx context.Context) {
	desired, err := m.loadHosts(ctx)
	if err != nil {
		log.Printf("prober: load hosts: %v", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop probers that were removed or whose profile changed.
	for id, h := range m.running {
		d, ok := desired[id]
		if !ok || d.sig() != h.sig {
			h.cancel()
			delete(m.running, id)
		}
	}
	// Start probers for new or changed hosts.
	for id, d := range desired {
		if _, ok := m.running[id]; ok {
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		m.running[id] = &proberHandle{cancel: cancel, sig: d.sig()}
		run := m.probe
		if m.probeFn != nil {
			run = m.probeFn
		}
		go run(cctx, d)
	}
}

func (m *proberMgr) probe(ctx context.Context, s hostSpec) {
	m.runCycle(ctx, s)
	t := time.NewTicker(time.Duration(s.intervalS) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.runCycle(ctx, s)
		}
	}
}

func (m *proberMgr) runCycle(ctx context.Context, s hostSpec) {
	rtts, sent, recv := fpingOnce(s)
	m.store(ctx, s.id, sent, recv, rtts)
}

// store saves one cycle. A prober stopped while fping ran (host deleted,
// profile changed, shutdown) drops its last cycle, and a host deleted between
// the check and the insert is refused by the foreign key: neither is an error.
func (m *proberMgr) store(ctx context.Context, hostID int64, sent, recv int, rtts []float64) {
	if ctx.Err() != nil {
		return
	}
	_, err := m.db.Exec(ctx, `
		INSERT INTO samples (host_id, ts, sent, recv, rtts)
		VALUES ($1, now(), $2, $3, $4) ON CONFLICT DO NOTHING`,
		hostID, sent, recv, rtts)
	if err != nil && ctx.Err() == nil && !isForeignKeyViolation(err) {
		log.Printf("prober: insert host %d: %v", hostID, err)
	}
}

// fpingOnce runs a single count-mode fping cycle and parses the per-ping RTTs.
// In count mode fping prints to stderr as:  <host> : 12.3 11.8 - 12.1 ...
// where "-" marks a lost packet.
func fpingOnce(s hostSpec) (rtts []float64, sent, recv int) {
	// #nosec G204 -- the only variable argument is the host address, validated
	// by validHostAddr (an IP or host name that never starts with "-").
	cmd := exec.Command("fping",
		"-C", strconv.Itoa(s.pingCount),
		"-b", strconv.Itoa(s.packetSize),
		"-p", "200",
		"-q", s.host)
	out, _ := cmd.CombinedOutput() // non-zero exit on loss; parse output anyway
	rtts = parseFping(string(out))
	return rtts, s.pingCount, len(rtts)
}

// parseFping extracts the RTTs from fping's count-mode output; lost packets
// ("-") and anything that is not a number are skipped.
func parseFping(out string) []float64 {
	rtts := []float64{}
	for _, line := range strings.Split(out, "\n") {
		idx := strings.LastIndex(line, " : ")
		if idx < 0 {
			continue
		}
		for _, f := range strings.Fields(line[idx+3:]) {
			if f == "-" {
				continue
			}
			if v, err := strconv.ParseFloat(f, 64); err == nil {
				rtts = append(rtts, v)
			}
		}
	}
	return rtts
}
