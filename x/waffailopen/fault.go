package waffailopen

import (
	"context"
	"log"
	"os"
	"time"
)

// FaultConfig is always available so the "fault" JSON field parses in
// both fault and production images. The production image just never sets
// the env var that enables fault injection.
type FaultConfig struct {
	Panic any    `json:"panic,omitempty"`
	Sleep string `json:"sleep,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h *FailOpenHandler) faultInjected() *FaultConfig {
	return h.Fault
}

func (h *FailOpenHandler) injectFaults() bool {
	// Fault injection is enabled by an env var at runtime, not a build tag.
	// This works with xcaddy (which doesn't support custom build tags).
	// The production image simply never sets GP_EDGE_FAULT_WAF_ENABLED.
	return os.Getenv("GP_EDGE_FAULT_WAF_ENABLED") == "true"
}

func (h *FailOpenHandler) injectFault(ctx context.Context) {
	fc := h.faultInjected()
	if fc == nil {
		return
	}
	if fc.Panic != nil {
		log.Printf("waffailopen: INJECTED PANIC: %v", fc.Panic)
		panic(fc.Panic)
	}
	if fc.Sleep != "" {
		if d, err := time.ParseDuration(fc.Sleep); err == nil {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		}
	}
}