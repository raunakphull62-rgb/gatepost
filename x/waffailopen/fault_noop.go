//go:build !waffailopen_fault

package waffailopen

import "context"

// FaultConfig is a no-op without the waffailopen_fault build tag.
// The JSON field "fault" is still parsed for config compatibility, but
// injectFaults always returns false so the hooks are never triggered.
type FaultConfig struct{}

func (h *FailOpenHandler) faultInjected() *FaultConfig { return nil }
func (h *FailOpenHandler) injectFaults() bool { return false }
func (h *FailOpenHandler) injectFault(ctx context.Context) {}