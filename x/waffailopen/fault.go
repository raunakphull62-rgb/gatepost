//go:build waffailopen_fault

package waffailopen

import (
	"log"
	"time"
)

type FaultConfig struct {
	Panic any    `json:"panic,omitempty"`
	Sleep string `json:"sleep,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h *FailOpenHandler) faultInjected() *FaultConfig {
	return h.Fault
}

func (h *FailOpenHandler) injectFaults() bool {
	fc := h.faultInjected()
	if fc == nil {
		return false
	}
	if fc.Sleep != "" {
		if d, err := time.ParseDuration(fc.Sleep); err == nil {
			time.Sleep(d)
		}
	}
	if fc.Panic != nil {
		log.Printf("waffailopen: INJECTED PANIC: %v", fc.Panic)
		panic(fc.Panic)
	}
	return false
}
