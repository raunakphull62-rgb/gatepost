package waffailopen

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
)

// WAFStats holds the fail-open counters shared between the handler module
// and the admin API stats endpoint. A single instance is created at package
// init time and referenced by all FailOpenHandler instances — there is only
// one Caddy process, so one set of counters is correct.
type WAFStats struct {
	panics    atomic.Uint64
	timeouts  atomic.Uint64
	saturated atomic.Uint64

	mu       sync.RWMutex
	mode     string
	hostModes map[string]string
}

var globalStats = &WAFStats{}

// getStats returns the singleton stats instance.
func getStats() *WAFStats { return globalStats }

func (s *WAFStats) setConfig(mode string, hostModes map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.hostModes = hostModes
}

// snap returns a point-in-time copy safe for JSON encoding.
func (s *WAFStats) snap() statsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]string, len(s.hostModes))
	for k, v := range s.hostModes {
		cp[k] = v
	}
	return statsSnapshot{
		Mode:      s.mode,
		HostModes: cp,
		Panics:    s.panics.Load(),
		Timeouts:  s.timeouts.Load(),
		Saturated: s.saturated.Load(),
	}
}

type statsSnapshot struct {
	Mode      string            `json:"mode"`
	HostModes map[string]string `json:"host_modes,omitempty"`
	Panics    uint64            `json:"panics"`
	Timeouts  uint64            `json:"timeouts"`
	Saturated uint64            `json:"saturated"`
}

// --- admin API module ---

// StatsAPI is a Caddy admin API module that exposes WAF fail-open counters
// at /waffailopen/stats. It is compiled into the edge image alongside the
// handler module.
type StatsAPI struct{}

func (StatsAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.waffailopen",
		New: func() caddy.Module { return new(StatsAPI) },
	}
}

func (s *StatsAPI) Provision(ctx caddy.Context) error { return nil }

// Routes implements caddy.AdminRouter, registering the /waffailopen/stats
// endpoint on the Caddy admin API.
func (s *StatsAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{
		Pattern: "/waffailopen/stats",
		Handler: caddy.AdminHandlerFunc(s.serveStats),
	}}
}

func (s *StatsAPI) serveStats(w http.ResponseWriter, r *http.Request) error {
	snap := getStats().snap()
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(snap)
}

// Interface guard
var _ caddy.AdminRouter = (*StatsAPI)(nil)
