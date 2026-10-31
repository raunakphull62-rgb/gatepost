//go:build waffailopen_fault

package waffailopen

import (
	"log"
	"time"
)

type FaultConfig struct {
	Panic  any           `json:"panic,omitempty"`
	Sleep  time.Duration `json:"sleep,omitempty"`
	Error  string        `json:"error,omitempty"`
}

// faultInjected returns the active fault config, or nil.
func (h *FailOpenHandler) faultInjected() *FaultConfig {
	return h.Fault
}

// injectFaults checks for configured fault injection. If a fault is active,
// it applies the sleep/panic and returns true (the caller should NOT proceed
// to the real WAF handler). Returns false if no fault is configured.
// The panic is caught by the goroutine's deferred recover above.
func (h *FailOpenHandler) injectFaults() bool {
	fc := h.faultInjected()
	if fc == nil {
		return false
	}
	if fc.Sleep > 0 {
		time.Sleep(fc.Sleep)
	}
	if fc.Panic != nil {
		log.Printf("waffailopen: INJECTED PANIC: %v", fc.Panic)
		panic(fc.Panic)
	}
	return false
}
