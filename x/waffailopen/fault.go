//go:build waffailopen_fault

package waffailopen

import (
	"context"
	"log"
	"os"
	"time"
)

// FaultConfig is only compiled with waffailopen_fault build tag.
// The production image has no fault hook at all.
type FaultConfig struct {
	Panic any    `json:"panic,omitempty"`
	Sleep string `json:"sleep,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h *FailOpenHandler) faultInjected() *FaultConfig {
	return h.Fault
}

func (h *FailOpenHandler) injectFaults() bool {
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